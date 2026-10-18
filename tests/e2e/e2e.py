#!/usr/bin/env python3
"""
End-to-end tests for the sfcc CLI.

Covers what the ctest suite cannot: the actual bytes on the wire. The unit
tests assert on encoding functions and return values; this drives the real
binary against a mock Salesforce endpoint and inspects what came back. That is
the only reason the missing "Authorization: " prefix was ever caught -- a unit
test on the string constant would have passed while every request went out
unauthenticated.

Python rather than shell on purpose: bash is not on Windows by default, and this
project targets three platforms. Runs anywhere Python does, needs nothing
installed (stdlib only), and needs no Salesforce org or credentials.

    python3 tests/e2e/e2e.py build/release/bin/sfcc
    python3 tests/e2e/e2e.py --verbose build/debug/bin/sfcc

Exit status is 0 when everything passed and 1 otherwise.
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mock_server import (BLOB, MOCK_CLIENT_ID, MOCK_SECRET, MockSalesforce,
                         RETRIEVE_ZIP, STATE)

# The SOAP envelopes the mock has received, read live: most of the
# assertions here are about what the client sent, and the only way to see
# that is from here. The mock clears the list in place on start, so this
# alias stays valid.
SOAP_BODIES = STATE.soap_bodies
MOCK = STATE

IS_WINDOWS = os.name == "nt"


class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.group = ""
        self.failures = []

    def section(self, name):
        self.group = name
        print("\n== %s" % name)

    def ok(self, what):
        self.passed += 1
        print("  ok   %s" % what)

    def bad(self, what, detail=""):
        self.failed += 1
        self.failures.append((self.group, what, detail))
        print("  FAIL %s" % what)
        if detail:
            for line in str(detail).splitlines():
                print("         %s" % line[:200])

    def check(self, cond, what, detail=""):
        (self.ok if cond else self.bad)(what) if cond else self.bad(what, detail)

    def contains(self, haystack, needle, what):
        if needle in haystack:
            self.ok(what)
        else:
            self.bad(what, "expected to contain: %r\nin: %r"
                     % (needle, haystack[:400]))

    def lacks(self, haystack, needle, what):
        if needle not in haystack:
            self.ok(what)
        else:
            self.bad(what, "should NOT contain: %r\nin: %r"
                     % (needle, haystack[:400]))


class Client:
    """Thin wrapper around the sfcc binary under test."""

    def __init__(self, path, login_url, workdir):
        self.path = path
        self.login_url = login_url
        self.workdir = workdir
        self.env = dict(os.environ)
        # Cleared so a developer's own exported variables cannot change the
        # outcome of a run, and the mock's fake credentials are used instead.
        for var in ("SFCC_CLIENT_ID", "SFCC_CLIENT_SECRET",
                    "SFCC_ACCESS_TOKEN", "SFCC_INSTANCE_URL",
                    "SFCC_TOKEN_CACHE"):
            self.env.pop(var, None)
        self.env["SFCC_CLIENT_ID"] = MOCK_CLIENT_ID
        self.env["SFCC_CLIENT_SECRET"] = MOCK_SECRET

    def run(self, *args, stdin=None, no_cache=True):
        """Run sfcc against the mock. Returns (returncode, stdout, stderr).

        no_cache is on by default so no test is at the mercy of a token cache
        left behind by an earlier one. The cache tests turn it off.
        """
        cmd = [self.path, "--login-url", self.login_url]
        if no_cache:
            cmd.append("--no-cache")
        cmd += list(args)
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              input=stdin, env=self.env, cwd=self.workdir,
                              timeout=120)
        return proc.returncode, proc.stdout, proc.stderr

    def path_in(self, name):
        return os.path.join(self.workdir, name)

    def write(self, name, text):
        """Put a file in the workdir and return its path.

        The tests needing a manifest on disk rather than on the command line go
        through here, so it is cleaned up along with everything else.
        Destinations come from path_in() -- returning both from here once made an
        output path collide with the manifest it was meant to sit beside.
        """
        p = self.path_in(name)
        with open(p, "w") as fh:
            fh.write(text)
        return p


def make_package(workdir):
    """Build a real metadata zip, the way a user's would be made.

    Uses Python's zipfile rather than shelling out to `zip`, so this works on a
    machine without it -- and so the test does not depend on the platform's
    archiver producing a byte-identical archive.
    """
    import zipfile
    pkg = os.path.join(workdir, "pkg", "classes")
    os.makedirs(pkg, exist_ok=True)
    with open(os.path.join(workdir, "pkg", "package.xml"), "w") as fh:
        fh.write(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Package xmlns="http://soap.sforce.com/2006/04/metadata">\n'
            '  <types><members>Good</members><members>Bad</members>'
            '<name>ApexClass</name></types>\n'
            '  <version>64.0</version>\n</Package>\n')
    with open(os.path.join(pkg, "Good.cls"), "w") as fh:
        fh.write("public class Good {}\n")
    with open(os.path.join(pkg, "Bad.cls"), "w") as fh:
        fh.write("public class Bad { oops }\n")

    zpath = os.path.join(workdir, "deploy.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(os.path.join(workdir, "pkg", "package.xml"), "package.xml")
        zf.write(os.path.join(pkg, "Good.cls"), "classes/Good.cls")
        zf.write(os.path.join(pkg, "Bad.cls"), "classes/Bad.cls")
    return zpath


# --------------------------------------------------------------------------
# The tests
# --------------------------------------------------------------------------

def test_auth(c, r):
    r.section("auth: form-encoded token request")
    rc, out, err = c.run("auth")
    if rc == 0:
        r.ok("auth exits 0")
    else:
        r.bad("auth exits 0", "rc=%d out=%s err=%s" % (rc, out, err))
    r.contains(out, c.login_url, "instance url reported")
    # The secret must never be echoed, not even into an error path.
    r.lacks(out + err, MOCK_SECRET, "secret never printed")

    r.section("auth: bad client id surfaces the OAuth error shape")
    rc, out, err = c.run("auth")
    bad_env = dict(c.env)
    bad_env["SFCC_CLIENT_ID"] = "wrong-key"
    proc = subprocess.run(
        [c.path, "--login-url", c.login_url, "--no-cache", "auth"],
        capture_output=True, text=True, env=bad_env, timeout=60)
    blob = proc.stdout + proc.stderr
    if proc.returncode != 0:
        r.ok("bad creds exits nonzero")
    else:
        r.bad("bad creds exits nonzero", blob)
    r.contains(blob, "invalid_client", "reports invalid_client")
    r.contains(blob, "client identifier invalid", "reports the description")
    r.lacks(blob, '{"error"', "not printed as a raw json blob")


def test_query(c, r):
    r.section("query: SOQL arrives percent-encoded and decodes identically")
    soql = ("SELECT Id, Name FROM Account WHERE Name = 'O''Brien & Co' "
            "LIMIT 2")
    rc, out, err = c.run("query", soql)
    if rc == 0:
        r.ok("query exits 0")
    else:
        r.bad("query exits 0", "rc=%d err=%s" % (rc, err))
    r.contains(out, "001000000000000AAA", "first record returned")
    r.contains(out, "O'Brien", "apostrophe record returned")
    r.contains(out, '"records"', "records array returned")

    r.section("query: the server error shape is unpacked, not dumped")
    rc, out, err = c.run("query", "SELECT Bogus FROM Account FAIL_ME")
    blob = out + err
    if rc != 0:
        r.ok("bad query exits nonzero")
    else:
        r.bad("bad query exits nonzero", blob)
    r.contains(blob, "INVALID_FIELD", "errorCode extracted")
    r.contains(blob, "No such column", "message extracted")
    r.lacks(blob, '[{"message"', "not printed as a raw json blob")


def _tables(out):
    """Split describe output into {section: [lines]} keyed by table.

    Indexing the output by line number is fragile -- the first heading is
    preceded by a blank line, and --no-header removes a line entirely -- so the
    headings are used as the anchors instead.
    """
    names = {"fields (": "fields",
             "child relationships (": "children",
             "record types (": "recordtypes"}
    out_tables = {}
    cur = None
    for ln in out.splitlines():
        matched = None
        for prefix, key in names.items():
            if ln.startswith(prefix):
                matched = key
                break
        if matched is not None:
            cur = matched
            out_tables[cur] = []
        elif cur is not None and ln.strip():
            out_tables[cur].append(ln)
    return out_tables


def _rows(section_lines):
    """Drop a header line if the first row looks like one."""
    if section_lines and section_lines[0].split()[:1] == ["NAME"]:
        return section_lines[1:]
    if section_lines and section_lines[0].split()[:1] == ["FIELD"]:
        return section_lines[1:]
    if section_lines and section_lines[0].split()[:1] == ["ID"]:
        return section_lines[1:]
    return section_lines


PACKAGE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Package xmlns="http://soap.sforce.com/2006/04/metadata">
    <types>
        <members>*</members>
        <name>ApexClass</name>
    </types>
    <version>64.0</version>
</Package>
"""

# The realistic version of the same mistake: the root carries a prefix.
PACKAGE_XML_PREFIXED = """<?xml version="1.0" encoding="UTF-8"?>
<md:Package xmlns:md="http://soap.sforce.com/2006/04/metadata">
    <md:types><md:members>*</md:members><md:name>ApexClass</md:name></md:types>
</md:Package>
"""


def test_retrieve(c, r):
    """Metadata retrieve over SOAP.

    The org-facing behaviour here is the request, so the mock records every SOAP
    envelope it receives and the assertions are mostly about what went out. The
    archive is checked byte-exact, because the payload is binary and contains a
    NUL early on: a client that treats it as a C string writes a truncated file
    and reports success.
    """
    r.section("retrieve: the archive is written byte-exact")
    before = len(SOAP_BODIES)
    path = c.write("package.xml", PACKAGE_XML)
    out = c.path_in("out.zip")
    rc, so, se = c.run("retrieve", path, "--out", out,
                       "--retrieve-poll-interval", "1")
    if rc == 0:
        r.ok("retrieve exits 0")
    else:
        r.bad("retrieve exits 0", "rc=%d err=%s" % (rc, se))
    r.contains(so, "Succeeded", "reports the org's status")
    r.check(os.path.exists(out), "the archive file exists", out)
    if os.path.exists(out):
        got = open(out, "rb").read()
        r.check(got == RETRIEVE_ZIP,
                "the archive matches byte for byte (%d bytes)" % len(got),
                "got %r" % got[:80])

    r.section("retrieve: it polls rather than assuming the first answer is final")
    r.contains(se, "Pending", "the first status was Pending, so it polled again")
    # Only the POST has a body, so the request log is where the exchanges are
    # counted -- SOAP_BODIES would only ever show the one that was sent a body.
    soap_calls = [q for q in MOCK.requests[before:] if q[1].startswith("/services/Soap/")]
    r.check(len(soap_calls) >= 2, "more than one SOAP exchange happened",
            "%d" % len(soap_calls))

    r.section("retrieve: the envelope carries what the SOAP binding requires")
    env = SOAP_BODIES[before] if SOAP_BODIES[before:] else ""
    r.contains(env, 'xmlns="http://soap.sforce.com/2006/04/metadata"',
               "the metadata namespace is the default")
    r.contains(env, "SessionHeader", "the session header is present")
    r.contains(env, "<apiVersion>64.0</apiVersion>",
               "the API version is bare, with no v prefix")
    r.lacks(env, "<apiVersion>v64.0</apiVersion>",
            "and not in the REST spelling")
    r.contains(env, "<unpackaged>", "the request wraps the manifest")

    r.section("retrieve: the manifest is copied across, not reparsed")
    r.contains(env, "<name>ApexClass</name>", "the manifest's types survived")
    r.contains(env, "<members>*</members>", "including the wildcard member")
    # The session id must not be percent-encoded: sfcc_buf_append_encoded is the
    # URL encoder and using it here produced ...%21...%3D%3D, which the org
    # cannot match against a real session id.
    r.lacks(env, "%3D", "the session id is not percent-encoded")

    r.section("retrieve: both calls go to the SOAP endpoint")
    actions = [q for q in MOCK.requests if q[1].startswith("/services/Soap/")]
    r.check(len(actions) >= 2, "both calls hit the SOAP endpoint",
            repr(actions))
    r.check(all(q[1].startswith("/services/Soap/m/")
                for q in actions),
            "on the versioned metadata SOAP path", repr(actions))

    r.section("retrieve: a failed retrieve names the org's own reason")
    path = c.write("package.xml",
                   PACKAGE_XML.replace("ApexClass", "FailMe"))
    out2 = c.path_in("failed.zip")
    rc, so, se = c.run("retrieve", path, "--out", out2,
                       "--retrieve-poll-interval", "1")
    r.check(rc != 0, "a failed retrieve exits nonzero", "rc=%d" % rc)
    r.contains(se, "No component retrieved",
               "the org's problem text is reported, not just 'Failed'")
    r.contains(se, "&", "and its XML entity was unescaped")
    r.check(not os.path.exists(out2),
            "and no empty archive is left behind", out2)

    r.section("retrieve: a bad manifest never reaches the network")
    for label, text, needle in (
            ("truncated", PACKAGE_XML[:PACKAGE_XML.index("<version")],
             "truncated"),
            ("prefixed", PACKAGE_XML_PREFIXED, "namespace prefix"),
            ("not a manifest", "<html>nope</html>", "no <Package>")):
        n = len(SOAP_BODIES)
        path = c.write("package.xml", text)
        rc, so, se = c.run("retrieve", path, "--out",
                           os.path.join(c.workdir, "never.zip"),
                           "--retrieve-poll-interval", "1")
        r.check(rc != 0, "%s manifest exits nonzero" % label, "rc=%d" % rc)
        r.contains(se, needle, "%s manifest explains itself" % label)
        r.check(len(SOAP_BODIES) == n,
                "%s manifest sends no SOAP at all" % label,
                "%d new envelopes" % (len(SOAP_BODIES) - n))

    r.section("retrieve: a missing manifest is reported, not crashed on")
    rc, so, se = c.run("retrieve",
                       os.path.join(c.workdir, "nope.xml"),
                       "--out", os.path.join(c.workdir, "never2.zip"))
    r.check(rc != 0, "a missing manifest exits nonzero", "rc=%d" % rc)
    r.contains(se, "cannot read", "and says it could not be read")

    r.section("retrieve: arguments")
    rc, so, se = c.run("retrieve")
    r.check(rc != 0, "no arguments exits nonzero", "rc=%d" % rc)
    r.contains(se, "package.xml", "and says what it wanted")

    rc, so, se = c.run("retrieve", path, path)
    r.check(rc != 0, "two manifests exits nonzero", "rc=%d" % rc)

    rc, so, se = c.run("retrieve", path, "--retrieve-timeout", "0")
    r.check(rc != 0, "--retrieve-timeout 0 is rejected", "rc=%d" % rc)
    r.contains(se, "positive", "with a clear reason")


def test_describe(c, r):
    """The three describe tables.

    The fixture is built from the shapes Salesforce actually sends: an empty
    referenceTo, a one-element one, a polymorphic two-element one, precision and
    scale that are zero because they do not apply, a null relationshipName, and
    a record type that is false in every flag column. Each is a way a renderer
    can be quietly wrong without crashing.
    """
    r.section("describe: three tables, each with a heading and a count")
    rc, out, err = c.run("describe", "Account")
    if rc == 0:
        r.ok("describe exits 0")
    else:
        r.bad("describe exits 0", "rc=%d err=%s" % (rc, err))

    for title in ("fields (6)", "child relationships (3)", "record types (3)"):
        r.contains(out, title, "section heading %r with its count" % title)

    t = _tables(out)
    r.check(len(t.get("fields", [])) == 7,
            "the fields table has a header and six rows",
            repr(t.get("fields")))
    r.check(len(t.get("children", [])) == 4,
            "the child table has a header and three rows",
            repr(t.get("children")))
    r.check(len(t.get("recordtypes", [])) == 4,
            "the record types table has a header and three rows",
            repr(t.get("recordtypes")))

    r.section("describe: the fields table")
    for col in ("NAME", "LABEL", "TYPE", "LEN", "SIZE", "REL NAME",
                "REFERENCE TO"):
        r.contains(t["fields"][0], col, "fields header %s" % col)

    fields = _rows(t["fields"])
    by_name = {ln.split()[0]: ln for ln in fields}
    r.contains(out, "AnnualRevenue", "field API name listed")
    r.contains(out, "Annual Revenue", "field label listed")
    r.contains(out, "currency", "datatype listed")

    # Matched with a regex rather than by splitting on whitespace and counting
    # fields: labels contain spaces ("SLA Expiration Date"), so a positional
    # index is only meaningful relative to the start of the row, not from zero.
    # These patterns assert the whole cell run, which is the actual property
    # being checked -- that each value landed in its own column.
    r.section("describe: numeric columns distinguish zero from not-applicable")
    def cellrun(row, tail):
        return re.search(tail + r"\s*$", row) is not None

    r.check(cellrun(by_name.get("AnnualRevenue", ""),
                    r"currency\s+18\s+18,0\s+-\s+-\s*$"),
            "a currency field shows precision,scale then dashes",
            repr(by_name.get("AnnualRevenue")))
    r.check(cellrun(by_name.get("SLAExpirationDate__c", ""),
                    r"datetime\s+-\s+-\s+-\s+-"),
            "a type with no length and no size shows -, not 0",
            repr(by_name.get("SLAExpirationDate__c")))
    r.check(cellrun(by_name.get("Name", ""),
                    r"string\s+255\s+-\s+-\s+-"),
            "a text field has a length but no size",
            repr(by_name.get("Name")))

    r.section("describe: referenceTo renders every shape")
    r.check(cellrun(by_name.get("ParentId", ""),
                    r"reference\s+18\s+-\s+Account\s+Account$"),
            "a single reference: relationship name and reference are separate "
            "columns", repr(by_name.get("ParentId")))
    r.check(cellrun(by_name.get("OwnerId", ""),
                    r"reference\s+18\s+-\s+-\s+User, Group$"),
            "a polymorphic reference lists both, comma separated",
            repr(by_name.get("OwnerId")))
    r.check(cellrun(by_name.get("Id", ""), r"id\s+18\s+-\s+-\s+-$"),
            "a non-relationship field shows - for both",
            repr(by_name.get("Id")))

    r.section("describe: child relationships")
    r.contains(out, "Contacts", "relationship name listed")
    r.contains(out, "AccountShare", "a child with no relationship name listed")
    kids = _rows(t["children"])
    r.check(any(ln.rstrip().endswith("-") for ln in kids),
            "and its missing relationship name shows -", repr(kids))
    r.check(any("Contact" in ln and "Opportunity" not in ln for ln in kids),
            "each row names its own child object", repr(kids))

    r.section("describe: record types")
    r.contains(out, "DEVELOPER NAME", "developer name is a column")
    rts = {ln.split()[0]: ln for ln in _rows(t["recordtypes"])}
    master = rts.get("012000000000000AAA", "")
    partner = rts.get("012000000000000CCC", "")
    r.check(len(master.split()) == 7, "a record type row has seven fields",
            repr(master))
    r.check(master.split()[3:] == ["yes", "yes", "yes", "yes"],
            "the master type is yes in all four flag columns", repr(master))
    r.check(partner.split()[3:] == ["no", "no", "no", "no"],
            "an inactive, unavailable type is no in all four", repr(partner))
    r.check(rts.get("012000000000000BBB", "").split()[4] == "no",
            "a non-master available type has master=no", repr(rts))

    r.section("describe: --field narrows the fields table only")
    rc, out, err = c.run("describe", "Account", "--field", "Revenue")
    r.check(rc == 0, "--field exits 0", err)
    r.contains(out, "fields (1)", "only one field row")
    r.contains(out, "AnnualRevenue", "the matching field is there")
    r.contains(out, "child relationships (3)", "the other tables are untouched")

    rc, out, err = c.run("describe", "Account", "--field", "annual revenue")
    r.contains(out, "AnnualRevenue", "matched case-insensitively on the label")

    rc, out, err = c.run("describe", "Account", "--field", "zzzznomatch")
    r.contains(out, "fields (0)", "a filter matching nothing gives an empty table")
    r.contains(out, "record types (3)", "and leaves the other tables alone")

    r.section("describe: --no-header drops every header line")
    rc, out, err = c.run("describe", "Account", "--no-header")
    r.check(rc == 0, "--no-header exits 0", err)
    r.lacks(out, "REFERENCE TO", "the fields header is gone")
    r.lacks(out, "DEVELOPER NAME", "the record types header is gone")
    r.contains(out, "AnnualRevenue", "the rows are still there")
    r.check(len(_rows(_tables(out)["fields"])) == 6,
            "and all six of them", repr(_tables(out)["fields"]))

    r.section("describe: --raw and --json both give the response")
    rc, out, err = c.run("describe", "Account", "--raw")
    r.check(rc == 0, "--raw exits 0", err)
    r.check(out.count("\n") == 1, "--raw is a single line",
            "%d newlines" % out.count("\n"))
    r.contains(out, '"referenceTo"', "the raw response is verbatim")

    rc, out, err = c.run("describe", "Account", "--json")
    r.check(rc == 0, "--json exits 0", err)
    r.check(out.count("\n") > 1, "--json is indented",
            "%d newlines" % out.count("\n"))
    r.lacks(out, "REFERENCE TO", "and is not the table")
    r.contains(out, '"recordTypeInfos"', "with the arrays intact")

    r.section("describe: an unknown object is still reported")
    rc, out, err = c.run("describe", "NoSuchObject")
    r.check(rc != 0, "an unknown object exits nonzero", "rc=%d" % rc)


def test_sobjects(c, r):
    """The sobjects table.

    The renderer is the part worth asserting: a flag that arrives absent, an
    object with no key prefix, and a label long enough to stretch the columns.
    All three are in the fixture precisely because a table can get each wrong
    quietly -- blank cells, a column shift, a header sized to nothing.
    """
    r.section("sobjects: the table has headers and one row per object")
    rc, out, err = c.run("sobjects")
    if rc == 0:
        r.ok("sobjects exits 0")
    else:
        r.bad("sobjects exits 0", "rc=%d err=%s" % (rc, err))

    first = out.splitlines()[0] if out else ""
    for col in ("NAME", "LABEL", "PREFIX", "CUST", "CRE", "UPD", "DEL",
                "UNDEL", "QRY", "RET", "SRCH", "LAY", "MRG", "TRIG"):
        r.contains(first, col, "header names %s" % col)

    body = [ln for ln in out.splitlines()[1:]
            if ln and not ln.endswith("objects")]
    r.check(len(body) == 4, "one row per object",
            "got %d rows: %r" % (len(body), out))
    r.contains(out, "4 of 4 objects", "the summary counts what was printed")

    r.section("sobjects: identity columns come from the right fields")
    r.contains(out, "Account", "platform object listed by API name")
    r.contains(out, "Invoice__c", "custom object listed by API name")
    r.contains(out, "Customer Invoice", "label shown, not the API name")
    r.contains(out, "001", "key prefix shown")

    r.section("sobjects: capability flags render yes and no")
    # Account is queryable and createable; ContentNote carries no flags at all,
    # so every one of its cells must read "no" rather than being guessed at.
    account = next((ln for ln in body if ln.startswith("Account ")), "")
    notenote = next((ln for ln in body if ln.startswith("ContentNote")), "")
    a = account.split()
    n = notenote.split()
    # 14 columns: name, label, prefix, and eleven flags. A label may contain
    # spaces, so only rows whose label is one word can be counted this way --
    # which is why these two are the ones asserted on.
    r.check(len(a) == 14, "a fully-populated row has all 14 columns",
            "got %d: %r" % (len(a), account))
    r.check(a[3:5] == ["no", "yes"],
            "Account is not custom and is createable", repr(account))
    r.check(a[-3:] == ["yes", "yes", "yes"],
            "and the last three flags line up at the right end", repr(account))

    # ContentNote has no keyPrefix, so that column is empty and collapses under
    # whitespace splitting: 13 fields, not 14. That it is 13 rather than 14 or
    # 12 is the alignment assertion -- a renderer that skipped or duplicated the
    # empty cell would show up here.
    r.check(len(n) == 13, "the row with no key prefix has one fewer field",
            "got %d: %r" % (len(n), notenote))
    r.check(n[2:] == ["no"] * 11,
            "an object with no flags at all reads no for all eleven",
            repr(notenote))
    r.check(n[:2] == ["ContentNote", "Note"],
            "and its identity columns are not displaced by the missing prefix",
            repr(notenote))

    r.section("sobjects: --custom keeps only custom objects")
    rc, out, err = c.run("sobjects", "--custom")
    r.check(rc == 0, "--custom exits 0", err)
    r.contains(out, "Invoice__c", "the custom object is kept")
    r.lacks(out, "Account ", "a platform object is dropped")
    r.contains(out, "1 of 4 objects", "the summary reflects the filter")

    r.section("sobjects: --filter matches name or label, ignoring case")
    rc, out, err = c.run("sobjects", "--filter", "invoice")
    r.check(rc == 0, "--filter exits 0", err)
    r.contains(out, "Invoice__c", "matched on the API name")

    rc, out, err = c.run("sobjects", "--filter", "INVOICE")
    r.contains(out, "Invoice__c", "the match is case-insensitive")

    rc, out, err = c.run("sobjects", "--filter", "Customer Invoice")
    r.contains(out, "Invoice__c", "matched on the label")

    rc, out, err = c.run("sobjects", "--filter", "zzzznomatch")
    r.check(rc != 0, "no match exits nonzero", "rc=%d out=%s" % (rc, out))
    r.contains(err, "no objects matched",
               "and says so rather than printing nothing")

    r.section("sobjects: --limit and --no-header")
    rc, out, err = c.run("sobjects", "--limit", "2")
    r.check(rc == 0, "--limit exits 0", err)
    rows = [ln for ln in out.splitlines()[1:]
            if ln and not ln.endswith("objects")]
    r.check(len(rows) == 2, "--limit caps the row count", "got %d" % len(rows))
    r.contains(out, "2 of 4 objects", "the summary shows the cap and the total")

    rc, out, err = c.run("sobjects", "--no-header")
    r.check(rc == 0, "--no-header exits 0", err)
    r.lacks(out, "PREFIX", "the header line is gone")
    r.contains(out, "Account", "the rows are still there")

    r.section("sobjects: --raw prints the response instead of the table")
    rc, out, err = c.run("sobjects", "--raw")
    r.check(rc == 0, "--raw exits 0", err)
    r.contains(out, '"sobjects"', "the wrapper object is present")
    r.contains(out, '"customSetting"', "flags the table omits are still there")
    r.lacks(out, "NAME", "no table header in raw mode")

    r.section("sobjects: arguments are rejected")
    rc, out, err = c.run("sobjects", "Account")
    r.check(rc != 0, "a stray argument exits nonzero", "rc=%d" % rc)
    r.contains(err, "describe", "and points at the command that does take one")


def test_records(c, r):
    r.section("get / create / update / delete")
    rc, out, err = c.run("get", "Account", "001000000000000AAA")
    if rc == 0:
        r.ok("get exits 0")
    else:
        r.bad("get exits 0", "rc=%d err=%s" % (rc, err))
    r.contains(out, "Acme Corporation", "record returned")

    rc, out, err = c.run("create", "Account", '{"Name":"New Co"}')
    if rc == 0:
        r.ok("create exits 0")
    else:
        r.bad("create exits 0", "rc=%d err=%s" % (rc, err))
    r.contains(out, "001000000000000CCC", "new id returned")

    rc, out, err = c.run("update", "Account", "001000000000000AAA",
                         '{"Phone":"555-0100"}')
    if rc == 0:
        r.ok("update exits 0 (204 with no body)")
    else:
        r.bad("update exits 0 (204 with no body)", "rc=%d err=%s" % (rc, err))

    rc, out, err = c.run("delete", "Account", "001000000000000AAA")
    if rc == 0:
        r.ok("delete exits 0 (204 with no body)")
    else:
        r.bad("delete exits 0 (204 with no body)", "rc=%d err=%s" % (rc, err))


def test_validation(c, r):
    """Bad arguments must be caught locally, costing no request."""
    r.section("local validation: no request is made")
    cases = [
        (("get", "Account", "not-an-id"), "15 or 18",
         "bad record id explained"),
        (("get", "../User", "001000000000000AAA"), "invalid sObject",
         "path traversal in an object name rejected"),
        (("create", "Account", '{"Name": broken}'), "not valid JSON",
         "malformed json body rejected"),
    ]
    for args, needle, what in cases:
        rc, out, err = c.run(*args)
        if rc != 0:
            r.ok(what + " (exits nonzero)")
        else:
            r.bad(what + " (exits nonzero)", out + err)
        r.contains(out + err, needle, what)

    rc, out, err = c.run("get", "Account", "001000000000000AAA")
    r.check(rc == 0, "a well-formed call still succeeds afterwards", out + err)


def test_rest(c, r):
    r.section("rest: relative path gets the versioned prefix")
    rc, out, err = c.run("rest", "limits")
    if rc == 0:
        r.ok("rest exits 0")
    else:
        r.bad("rest exits 0", "rc=%d err=%s" % (rc, err))
    r.contains(out, "DailyApiRequests", "body returned")

    r.section("rest: {version} is substituted in an absolute path")
    rc, out, err = c.run("rest", "/services/data/{version}/limits")
    r.contains(out, "DailyApiRequests", "versioned absolute path works")

    r.section("rest: -i shows the response head")
    rc, out, err = c.run("rest", "limits", "-i")
    r.contains(out, "HTTP/1.1 200", "status line shown")
    r.contains(out, "Sforce-Limit-Info", "custom response header shown")

    r.section("rest: custom headers and body are delivered")
    rc, out, err = c.run("rest", "echo", "-X", "POST",
                         "-H", "X-Custom-Thing: hello", "-d", '{"Name":"Acme"}')
    r.contains(out, "hello", "custom header arrived")
    r.contains(out, "Acme", "body arrived")
    r.contains(out, "00Dxx0000000001", "our own auth was sent")

    r.section("rest: a caller-supplied Authorization replaces ours")
    rc, out, err = c.run("rest", "echo", "-H", "Authorization: Bearer mine")
    r.contains(out, "Bearer mine", "replacement token used")
    r.lacks(out, "00Dxx0000000001", "our token was not sent alongside")

    r.section("rest: a 4xx prints the body on stdout and exits 1")
    rc, out, err = c.run("rest", "echo", "-H", "Authorization: Bearer wrong-token")
    if rc == 1:
        r.ok("4xx exits 1")
    else:
        r.bad("4xx exits 1", "rc=%d out=%s" % (rc, out))
    r.contains(out, "INSUFFICIENT_ACCESS", "error body on stdout, parseable")
    r.contains(err, "HTTP 403", "status noted on stderr")

    r.section("rest: a rejected token is not reported as missing credentials")
    # The bug this guards: a stale token used to be discarded and replaced with
    # a vague "no credentials", hiding the 401 that actually explained it.
    rc, out, err = c.run("rest", "/id/x/y")
    r.lacks(out + err, "no credentials",
            "rejected token is not misreported as no credentials")


def test_binary_output(c, r):
    r.section("rest: a binary body is not truncated at the first NUL")
    dest = c.path_in("blob.bin")
    rc, out, err = c.run("rest",
                         "sobjects/ContentVersion/068xx000000000AAA/VersionData",
                         "-o", dest)
    if os.path.exists(dest):
        with open(dest, "rb") as fh:
            got = fh.read()
        if got == BLOB:
            r.ok("body written byte-exact (%d bytes, NULs intact)" % len(got))
        else:
            r.bad("body written byte-exact",
                  "expected %r got %r" % (BLOB, got))
    else:
        r.bad("output file was written", "rc=%d err=%s" % (rc, err))

    # And to stdout, where a C-string write would also truncate.
    rc, out_bytes, err = subprocess_run_bytes(
        c, ["rest", "sobjects/ContentVersion/068xx000000000AAA/VersionData"])
    if out_bytes == BLOB:
        r.ok("body to stdout byte-exact")
    else:
        r.bad("body to stdout byte-exact", "got %r" % out_bytes[:64])


def subprocess_run_bytes(c, args):
    cmd = [c.path, "--login-url", c.login_url, "--no-cache"] + args
    proc = subprocess.run(cmd, capture_output=True, env=c.env,
                          cwd=c.workdir, timeout=120)
    return proc.returncode, proc.stdout, proc.stderr


def test_stdio(c, r):
    r.section("stdin and stdout composability")
    rc, out, err = c.run("rest", "echo", "-X", "POST", "-d", "@-",
                         stdin='{"Name":"From Pipe"}')
    r.contains(out, "From Pipe", "-d @- reads stdin")

    rc, out, err = c.run("rest", "echo", "-X", "POST", "--data-file", "-",
                         stdin='{"Name":"ViaDataFile"}')
    r.contains(out, "ViaDataFile", "--data-file - reads stdin")

    body_file = c.path_in("body.json")
    with open(body_file, "w") as fh:
        fh.write('{"Name":"AtFile"}')
    rc, out, err = c.run("rest", "echo", "-X", "POST", "-d", "@" + body_file)
    r.contains(out, "AtFile", "-d @path reads a file")

    rc, out, err = c.run("rest", "echo", "-X", "POST", "-d", "@-", stdin="")
    if rc != 0:
        r.ok("empty stdin is refused")
    else:
        r.bad("empty stdin is refused", "rc=%d out=%s" % (rc, out))
    r.contains(out + err, "standard input was empty", "empty stdin explained")

    r.section("stdout is the default sink")
    rc, out, err = c.run("rest", "limits", "--raw")
    r.contains(out, '"Max":100000', "stdout usable in a pipeline")

    dest = c.path_in("lim.json")
    rc, out, err = c.run("rest", "limits", "-o", dest)
    with open(dest) as fh:
        r.contains(fh.read(), "DailyApiRequests", "-o file writes the body")
    r.check(out == "", "stdout is empty when -o names a file",
            "got %d bytes on stdout" % len(out))


def test_deploy(c, r):
    zip_path = make_package(c.workdir)
    r.section("deploy: multipart upload, async poll, failure report")
    rc, out, err = c.run("deploy", "--zip", zip_path,
                         "--test-level", "local", "--poll-interval", "1")
    blob = out + err
    # The org reported failures, so a deploy that "worked" must not exit 0.
    if rc == 1:
        r.ok("failed deploy exits 1 (not 0, not a crash)")
    else:
        r.bad("failed deploy exits 1", "rc=%d out=%s" % (rc, blob))
    r.contains(out, "Deploy failed", "reports the failure")
    r.contains(out, "Bad", "names the failing component")
    r.contains(out, "classes/Bad.cls", "shows the failing file")
    r.contains(out, "Good", "lists the successful component")
    r.contains(out, "tests: 2 passed", "test counts parsed")
    r.lacks(out, '"componentFailures"', "not printed as a raw json blob")

    r.section("deploy: options reach the wire correctly")
    cache = c.path_in("unused")
    rc, out, err = c.run("deploy", "--zip", zip_path, "--validate-only",
                         "--test-level", "specified", "--tests", "MyTest",
                         "--single-package", "--poll-interval", "1")
    opts = STATE.deploys.get("0Af1B000000DeployAAA", {}).get("options", "")
    for needle, what in [
        ('"deployOptions":"validateOnly"', "validateOnly sent"),
        ('"testLevel":"RunSpecifiedTests"', "RunSpecifiedTests sent"),
        ('"tests":"MyTest"', "tests list sent"),
        ('"singlePackage":true', "singlePackage sent"),
    ]:
        r.contains(opts, needle, what)
    del cache

    r.section("deploy: a non-zip never reaches the network")
    junk = c.path_in("junk.bin")
    with open(junk, "w") as fh:
        fh.write("not a zip\n")
    rc, out, err = c.run("deploy", "--zip", junk)
    blob = out + err
    if rc != 0:
        r.ok("non-zip exits nonzero")
    else:
        r.bad("non-zip exits nonzero", blob)
    r.contains(blob, "zip signature", "explains the signature problem")

    r.section("deploy: the token cache is not world readable")
    if IS_WINDOWS:
        r.ok("skipped on Windows: POSIX mode bits are not consulted there")
    else:
        cache = c.path_in("token.json")
        # no_cache must be off, or there is nothing to write.
        rc, out, err = c.run("--token-cache", cache, "auth", no_cache=False)
        if os.path.exists(cache):
            mode = stat.S_IMODE(os.stat(cache).st_mode)
            if mode == 0o600:
                r.ok("cache is mode 0600 (got %o)" % mode)
            else:
                r.bad("cache is mode 0600", "got %o" % mode)
        else:
            r.bad("cache file written", "no file at %s" % cache)


def test_transport_errors(c, r):
    r.section("transport failures are named")
    env = dict(c.env)
    proc = subprocess.run(
        [c.path, "--login-url", "https://no-such-host.invalid", "--no-cache",
         "auth"],
        capture_output=True, text=True, env=env, timeout=90)
    blob = proc.stdout + proc.stderr
    if proc.returncode != 0:
        r.ok("dns failure exits nonzero")
    else:
        r.bad("dns failure exits nonzero", blob)
    r.contains(blob, "could not reach", "names the transport problem")

    rc, out, err = c.run("--insecure-skip-verify", "auth")
    r.contains(out + err, "verification is disabled",
            "--insecure-skip-verify warns loudly")


# --------------------------------------------------------------------------

ALL = [test_auth, test_query, test_sobjects, test_describe, test_retrieve,
       test_records,
       test_validation, test_rest,
       test_binary_output, test_stdio, test_deploy, test_transport_errors]


def main(argv):
    verbose = "--verbose" in argv
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print(__doc__.strip())
        return 2
    binary = os.path.abspath(args[0])
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        print("not an executable: %s" % binary, file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="sfcc-e2e-")
    r = Results()
    try:
        with MockSalesforce() as base_url:
            print("mock Salesforce: %s" % base_url)
            c = Client(binary, base_url, workdir)
            for fn in ALL:
                try:
                    fn(c, r)
                except Exception as exc:      # a crash in one group is a failure
                    import traceback
                    r.bad("%s raised" % fn.__name__, traceback.format_exc())
                    del exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n" + "-" * 44)
    if r.failed:
        print("%d passed, %d FAILED" % (r.passed, r.failed))
        for grp, what, detail in r.failures:
            print("  [%s] %s" % (grp, what))
        return 1
    print("%d passed, 0 failed" % r.passed)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))