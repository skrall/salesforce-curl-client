#!/usr/bin/env python3
"""
A stand-in for the two Salesforce endpoints this client talks to.

Exists to verify the wire format, which unit tests cannot: that the token
request is form-encoded rather than JSON, that SOQL arrives percent-encoded and
decodes byte-identically, that the bearer header and API version are where they
should be, and that the two different error shapes are both handled.

Deliberately stdlib-only -- json, http.server, urllib.parse -- so it runs on a
CI runner with nothing installed, and on any Python the project already assumes.

Run directly to poke at it by hand:

    python3 tests/e2e/mock_server.py

which prints the base URL it bound and serves until interrupted. The test runner
imports ``MockSalesforce`` instead, running the server on a thread.
"""

import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# The API version the mock claims to speak. The client passes its own version in
# the path, so most routes match on a pattern rather than this constant -- the
# one place it is used is the catch-all "asked for something we do not model".
VERSION = "v64.0"

# A recognisable token, so a test can assert *which* token was sent.
MOCK_TOKEN = "00Dxx0000000001!AQEAQFmocktokenvalue=="
MOCK_SECRET = "test-secret"
MOCK_CLIENT_ID = "test-consumer-key"

DEPLOY_ID = "0Af1B000000DeployAAA"

# A binary blob with NUL bytes in it, to catch a client that treats a response
# body as a C string. The length is asserted, not just the prefix.
BLOB = b"\x89PNG\r\n\x1a\n\x00\x01\x02binary-blob"

# The global SObject listing, shaped like the real one: a wrapper object with
# "sobjects" inside it, not a bare array.
#
# Deliberately awkward in four places, because each one is a way a table
# renderer can quietly get something wrong:
#
#   * Invoice__c is custom, so --custom has something to select.
#   * ContentNote has no keyPrefix at all, and no capability flags either --
#     Salesforce omits fields freely, so "absent" must render rather than crash
#     or be mistaken for true.
#   * PlatformEvent__e is long-named with a long label, so column widths are
#     driven by content rather than by the header.
#   * Account has keyPrefix out of alphabetical order, so a renderer that sorts
#     by the wrong column or drops a field shows up immediately.
# A zip is binary and must survive the round trip byte-exact, so the fixture is
# deliberately not a real archive -- only a payload that includes NULs and high
# bytes, which is what catches a client treating it as a C string. The PK\x03\x04
# at the front is a genuine zip local-file header, so `file` recognises it.
RETRIEVE_ZIP = b"PK\x03\x04\x00\x00binary-retrieve-payload\x00\xff\xfe\x80\x01"

# The encoding of RETRIEVE_ZIP, wrapped at a line break inside the XML because
# Salesforce does that and a strict base64 decoder would reject it -- so the
# wrap here is what keeps the decoder's whitespace tolerance exercised rather
# than merely claimed. Regenerate with base64.b64encode(RETRIEVE_ZIP).
RETRIEVE_ZIP_B64 = (
    "UEsDBAAAYmluYXJ5LXJldHJp"
    "\n"
    "ZXZlLXBheWxvYWQA//6AAQ=="
)

SOBJECTS = {
    "encoding": "UTF-8",
    "maxBatchSize": 200,
    "sobjects": [
        {"name": "Account", "label": "Account", "labelPlural": "Accounts",
         "keyPrefix": "001", "createable": True, "custom": False,
         "deletable": True, "layoutable": True, "mergeable": True,
         "queryable": True, "retrieveable": True, "searchable": True,
         "triggerable": True, "undeletable": True, "updateable": True},
        {"name": "Invoice__c", "label": "Customer Invoice",
         "labelPlural": "Customer Invoices", "keyPrefix": "inv",
         "createable": True, "custom": True, "customSetting": False,
         "deletable": True, "layoutable": True, "mergeable": False,
         "queryable": True, "retrieveable": True, "searchable": True,
         "triggerable": True, "undeletable": True, "updateable": True},
        # No keyPrefix, and no flags: every capability must read as "no" and
        # the prefix as empty, without a crash or a stray blank column.
        {"name": "ContentNote", "label": "Note", "labelPlural": "Notes"},
        {"name": "PlatformEvent__e",
         "label": "Platform Event for the Long Column Test",
         "labelPlural": "Platform Events", "keyPrefix": "evt",
         "createable": True, "custom": False, "deletable": True,
         "queryable": True, "retrieveable": True, "undeletable": True},
    ],
}


# A describe response, with the parts that vary chosen to be awkward:
#
#   * referenceTo as an empty list (a text field), a one-element list (an
#     ordinary lookup) and a two-element list (a polymorphic reference such as
#     OwnerId, which may be a User or a Queue).
#   * precision and scale both 0 on the text fields, and non-zero on the
#     currency ones, so a renderer has to cope with "not applicable" rather than
#     printing 0,0 on every row.
#   * a relationshipName of null, which is what every non-relationship field
#     carries.
#   * a child relationship with no relationshipName, which happens when the
#     relationship has never been named.
#   * a record type that is not active and not available, so the table shows a
#     row that is entirely false apart from its identity.
DESCRIBE_ACCOUNT = {
    "name": "Account",
    "label": "Account",
    "labelPlural": "Accounts",
    "keyPrefix": "001",
    "custom": False,
    "createable": True,
    "deletable": True,
    "queryable": True,
    "retrieveable": True,
    "searchable": True,
    "triggerable": True,
    "undeletable": True,
    "updateable": True,
    "fields": [
        {"name": "Id", "label": "Account ID", "type": "id", "length": 18,
         "precision": 0, "scale": 0, "relationshipName": None,
         "referenceTo": [], "custom": False, "filterable": True,
         "nillable": False, "createable": False, "updateable": False,
         "unique": False, "idLookup": False, "nameField": True,
         "label": "Account ID"},
        {"name": "Name", "label": "Account Name", "type": "string",
         "length": 255, "precision": 0, "scale": 0, "relationshipName": None,
         "referenceTo": [], "custom": False, "filterable": True,
         "nillable": False, "createable": True, "updateable": True,
         "unique": False, "nameField": False},
        {"name": "ParentId", "label": "Parent Account ID", "type": "reference",
         "length": 18, "precision": 0, "scale": 0,
         "relationshipName": "Account", "referenceTo": ["Account"],
         "custom": False, "filterable": True, "nillable": False,
         "createable": True, "updateable": True, "unique": False},
        {"name": "OwnerId", "label": "Owner ID", "type": "reference",
         "length": 18, "precision": 0, "scale": 0, "relationshipName": None,
         "referenceTo": ["User", "Group"], "custom": False,
         "filterable": True, "nillable": False, "createable": True,
         "updateable": True, "unique": False},
        {"name": "AnnualRevenue", "label": "Annual Revenue",
         "type": "currency", "length": 18, "precision": 18, "scale": 0,
         "relationshipName": None, "referenceTo": [], "custom": False,
         "filterable": True, "nillable": True, "createable": True,
         "updateable": True, "unique": False},
        {"name": "SLAExpirationDate__c", "label": "SLA Expiration Date",
         "type": "datetime", "length": 0, "precision": 0, "scale": 0,
         "relationshipName": None, "referenceTo": [], "custom": True,
         "filterable": True, "nillable": True, "createable": True,
         "updateable": True, "unique": False},
    ],
    "childRelationships": [
        {"childSObject": "Contact", "field": "AccountId",
         "relationshipName": "Contacts", "fieldRequiredToCreate": False,
         "cascadeDelete": True},
        {"childSObject": "Opportunity", "field": "AccountId",
         "relationshipName": "Opportunities", "fieldRequiredToCreate": False,
         "cascadeDelete": False},
        # No relationshipName: a child that has never been given one.
        {"childSObject": "AccountShare", "field": "AccountId",
         "relationshipName": None, "fieldRequiredToCreate": False,
         "cascadeDelete": True},
    ],
    "recordTypeInfos": [
        {"recordTypeId": "012000000000000AAA", "name": "Master",
         "developerName": "Master", "active": True, "available": True,
         "master": True, "defaultRecordTypeMapping": True},
        {"recordTypeId": "012000000000000BBB", "name": "Customer",
         "developerName": "Customer", "active": True, "available": True,
         "master": False, "defaultRecordTypeMapping": False},
        {"recordTypeId": "012000000000000CCC", "name": "Partner",
         "developerName": "Partner", "active": False, "available": False,
         "master": False, "defaultRecordTypeMapping": False},
    ],
}


class _State:
    """Per-server state, kept off the handler so tests can inspect it."""

    def __init__(self):
        self.base_url = ""
        self.deploys = {}
        self.requests = []      # (method, path, authorization, content_type)
        # Raw SOAP envelopes, so a test can assert on what the client actually
        # sent. The SOAP path has no other observable: the org-facing behaviour
        # is the request, and asserting on it is what makes the envelope
        # construction testable at all.
        self.soap_bodies = []
        self.soap_polls = {}    # retrieve id -> number of checkStatus calls
        self.lock = threading.Lock()

    def record(self, method, path, auth, ctype):
        with self.lock:
            self.requests.append((method, path, auth, ctype))

    def last_auth(self, path_suffix):
        with self.lock:
            for m, p, a, c in reversed(self.requests):
                if path_suffix in p:
                    return a
        return None


STATE = _State()


RETRIEVE_SOAP = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Body>
    <retrieveResponse>
      <result>
        <id>%(id)s</id>
        <done>true</done>
        <status>Succeeded</status>
        <success>true</success>
        <fileProperties>
          <contentType>application/json</contentType>
          <fileName>package.xml</fileName>
          <fullName>package.xml</fullName>
        </fileProperties>
        <zipFile>%(zip)s</zipFile>
      </result>
    </retrieveResponse>
  </soapenv:Body>
</soapenv:Envelope>"""

RETRIEVE_PENDING_SOAP = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Body>
    <retrieveResponse>
      <result>
        <id>%s</id>
        <done>false</done>
        <status>Pending</status>
      </result>
    </retrieveResponse>
  </soapenv:Body>
</soapenv:Envelope>"""

RETRIEVE_FAILED_SOAP = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns="http://soap.sforce.com/2006/04/metadata">
  <soapenv:Body>
    <retrieveResponse>
      <result>
        <id>%s</id>
        <done>true</done>
        <status>Failed</status>
        <success>false</success>
        <messages>
          <message>
            <problem>No component retrieved: nothing matched the manifest &amp; nothing else.</problem>
          </message>
        </messages>
      </result>
    </retrieveResponse>
  </soapenv:Body>
</soapenv:Envelope>"""

SOAP_FAULT = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>sf:INVALID_SESSION_ID</faultcode>
      <faultstring>Invalid Session ID found in SessionHeader: expired or invalid</faultstring>
      <detail><stackTrace>A very long Java stack trace nobody can act on.</stackTrace></detail>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass    # the runner prints its own report; keep stderr clean

    # -- helpers ------------------------------------------------------------

    def _send_json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, code, body, ctype="application/octet-stream", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_salesforce_error(self, code, message, error_code, fields=None):
        """The REST shape: an array of {message, errorCode} objects."""
        self._send_json(code, [{
            "message": message,
            "errorCode": error_code,
            "fields": fields or [],
        }])

    def _send_oauth_error(self, code, error, description):
        """The OAuth shape: an object with error / error_description."""
        self._send_json(code, {"error": error,
                               "error_description": description})

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _note(self):
        STATE.record(self.command, self.path,
                     self.headers.get("Authorization"),
                     self.headers.get("Content-Type"))

    def _path_is(self, pattern):
        """True if the request path matches, with {version} standing for any
        API version and a '*' segment for "anything here".

        Assembled by hand rather than by escaping the whole pattern and then
        substituting: re.escape() turns '{' into '\\{' and '*' into '\\*', so
        escaping first puts both of the placeholders we rely on out of reach of
        the substitution. Split on the placeholder first, escape the literal
        pieces, then join.
        """
        u = urlparse(self.path)
        pieces = [re.escape(p) for p in pattern.split("{version}")]
        regex = "v[0-9.]+".join(pieces)
        # A '*' that re.escape turned into '\*' was meant as "any single
        # segment", which is what it has to become back.
        regex = regex.replace(re.escape("*"), "[^/]+")
        return re.match("^" + regex + "$", u.path) is not None

    def _soap_action(self):
        """The SOAPAction header, unquoted. Absent entirely is a real failure
        mode: SOAP 1.1 requires it, so a client that omits it is broken."""
        raw = self.headers.get("SOAPAction") or ""
        return raw.strip().strip('"')

    def _soap(self):
        """True when this is a Metadata SOAP endpoint, whatever the operation.

        The version is matched WITHOUT an optional "v" prefix, deliberately: a
        real org answers /services/Soap/m/v64.0 with "Invalid Api version
        specified on URL". A permissive regex here would let that ship, and did.
        """
        if not re.match(r"^/services/Soap/m/v?[0-9.]+$", urlparse(self.path).path):
            return False
        if re.match(r"^/services/Soap/m/v[0-9.]+$", urlparse(self.path).path):
            self._soap_fault("soapenv:Client",
                             "Invalid Api version specified on URL : %s"
                             % urlparse(self.path).path)
            return False
        return True

    def _soap_fault(self, code, text):
        return self._send_raw(500, SOAP_FAULT.replace("sf:INVALID_SESSION_ID", code)
                              .encode("utf-8"), "text/xml")

    # -- GET ----------------------------------------------------------------

    def do_GET(self):
        self._note()
        if self._deploy_status():
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if self._soap() and self._soap_action() == "checkRetrieveStatus":
            rid = "0Af1B000000RetrieveAAA"
            if rid == "unknown":
                return self._soap_fault("sf:INVALID_ID", "no such retrieve")
            with STATE.lock:
                n = STATE.soap_polls.get(rid, 0)
                STATE.soap_polls[rid] = n + 1
            # Pending once, then Succeeded. Polling is the thing worth forcing:
            # a client that treats the first response as final would never see
            # the archive and would fail here for the right reason.
            if n < 1:
                return self._send_raw(
                    200, (RETRIEVE_PENDING_SOAP % rid).encode("utf-8"),
                    "text/xml")
            return self._send_raw(
                200, (RETRIEVE_SOAP % {"id": rid, "zip": RETRIEVE_ZIP_B64})
                .encode("utf-8"), "text/xml")

        if self._path_is("/services/data/{version}/query"):
            # The statement must arrive fully decoded and identical to what we
            # were asked for. If the client's encoding were wrong this
            # comparison would fail rather than merely return odd records.
            soql = (q.get("q") or [""])[0]
            if not soql:
                return self._send_salesforce_error(
                    400, "no query supplied", "MALFORMED_QUERY")
            # A session id, not a REST token: the shape that must be reported as
            # a rejected token rather than as missing credentials.
            if self.headers.get("Authorization") == "Bearer session-id":
                return self._send_salesforce_error(
                    401, "\n  INVALID_SESSION_ID: Session expired or invalid\n",
                    "INVALID_SESSION_ID")
            if "FAIL_ME" in soql:
                return self._send_salesforce_error(
                    400, "\n  No such column 'Bogus' on entity 'Account'.\n",
                    "INVALID_FIELD", ["Bogus"])
            return self._send_json(200, {
                "totalSize": 2,
                "done": True,
                "records": [
                    {"attributes": {"type": "Account",
                                    "url": "/services/data/%s/sobjects/Account/001000000000000AAA" % u.path.split("/")[3]},
                     "Id": "001000000000000AAA", "Name": "Acme Corporation"},
                    {"attributes": {"type": "Account",
                                    "url": "/services/data/%s/sobjects/Account/001000000000000AAB" % u.path.split("/")[3]},
                     "Id": "001000000000000AAB", "Name": "O'Brien & Co"},
                ],
            })

        if self._path_is("/services/data/{version}/sobjects"):
            return self._send_json(200, SOBJECTS)

        if self._path_is("/services/data/{version}/sobjects/Account/describe"):
            return self._send_json(200, DESCRIBE_ACCOUNT)

        if self._path_is("/services/data/{version}/sobjects/Account/001000000000000AAA"):
            return self._send_json(200, {"Id": "001000000000000AAA",
                                         "Name": "Acme Corporation",
                                         "Industry": "Technology"})

        if self._path_is("/services/data/{version}/sobjects/ContentVersion/068xx000000000AAA/VersionData"):
            return self._send_raw(200, BLOB)

        # Any single-record read that is not the one above: 404 in the REST
        # shape, which the client has to unpack.
        if self._path_is("/services/data/{version}/sobjects/*"):
            return self._send_salesforce_error(
                404, "The requested resource does not exist", "NOT_FOUND")

        if self._path_is("/services/data/{version}/limits"):
            return self._send_raw(
                200,
                b'{"DailyApiRequests":{"Max":100000,"Remaining":99997}}',
                "application/json",
                extra=[("Sforce-Limit-Info", "api-usage=1/100000")])

        if self._path_is("/services/data/{version}/echo"):
            return self._send_echo(u, q)

        if self._path_is("/services/data/"):
            return self._send_json(
                200, [{"version": VERSION, "url": "/services/data/%s" % VERSION}])

        if u.path.startswith("/id/"):
            return self._send_json(200, {
                "id": "%s%s" % (STATE.base_url, u.path),
                "asserted_user": True,
                "user_id": u.path.rsplit("/", 1)[-1],
                "username": "integration@example.com",
                "display_name": "Integration User",
                "email": "integration@example.com",
                "organization_id": u.path.strip("/").split("/")[1],
            })

        return self._send_salesforce_error(
            404, "The requested resource does not exist (%s)" % u.path,
            "NOT_FOUND")

    def _send_echo(self, u, q, body=None):
        auth = self.headers.get("Authorization")
        if auth is None:
            return self._send_salesforce_error(
                401, "Session expired or invalid", "INVALID_SESSION_ID")
        if auth == "Bearer wrong-token":
            return self._send_salesforce_error(
                403, "insufficient access", "INSUFFICIENT_ACCESS")
        echoed = {
            "path": u.path,
            "authorization": auth,
            "customHeader": self.headers.get("X-Custom-Thing"),
        }
        if q:
            echoed["query"] = q
        if body is not None:
            echoed["contentType"] = self.headers.get("Content-Type")
            echoed["body"] = body
        self._send_json(200, {"echoed": echoed})

    def _deploy_status(self):
        """GET on .../metadata/deployRequest/<id>.

        Returns True when this request was the deploy status poll, so the
        caller stops looking for another route.
        """
        m = re.match(r"^/services/data/v[0-9.]+/metadata/deployRequest/([^/]+)$",
                     urlparse(self.path).path)
        if not m:
            return False
        st = STATE.deploys.get(m.group(1))
        if st is None:
            self._send_salesforce_error(404, "no such deploy", "NOT_FOUND")
            return True
        st["polls"] += 1
        # Pending once, then the final answer, so the client is forced to
        # actually poll rather than assuming the POST was the whole story.
        if st["polls"] < 2:
            self._send_json(200, {"id": m.group(1), "state": "InProgress",
                                  "status": "InProgress", "done": False})
        else:
            self._send_json(200, DEPLOY_FINAL_STATUS)
        return True

    # -- POST ---------------------------------------------------------------

    def do_POST(self):
        self._note()
        raw = self._body()
        u = urlparse(self.path)

        if self._soap() and self._soap_action() == "retrieve":
            body = raw.decode("utf-8", "replace")
            with STATE.lock:
                STATE.soap_bodies.append(body)

            # The session id is the only credential a retrieve carries, so a
            # wrong one must be a fault rather than a successful retrieve.
            if MOCK_TOKEN not in body:
                return self._soap_fault(
                    "sf:INVALID_SESSION_ID",
                    "Invalid Session ID found in SessionHeader: expired")

            # A manifest naming a FailMe type asks for the failure shape, so the
            # error path is exercised without a second endpoint.
            if "FailMe" in body:
                with STATE.lock:
                    STATE.soap_polls["fail"] = 0
                return self._send_raw(
                    200, (RETRIEVE_FAILED_SOAP % ("0AfRETRIEVEFAIL"))
                    .encode("utf-8"), "text/xml")

            rid = "0Af1B000000RetrieveAAA"
            with STATE.lock:
                STATE.soap_polls[rid] = 0
            # Pending, as a real org answers: retrieve is asynchronous, and a
            # mock that returned the archive here would mean the poll loop is
            # never executed by any test.
            return self._send_raw(
                200, (RETRIEVE_PENDING_SOAP % rid).encode("utf-8"), "text/xml")

        if u.path == "/services/oauth2/token":
            # The assertion that matters most: this endpoint must be form
            # encoded. A JSON content-type here would be a silent bug, because
            # the client sends JSON for every other call in the project.
            ctype = self.headers.get("Content-Type") or ""
            if "x-www-form-urlencoded" not in ctype:
                return self._send_oauth_error(
                    400, "invalid_request",
                    "expected form encoding, got %r" % ctype)
            form = parse_qs(raw.decode())
            if form.get("grant_type", [""])[0] != "client_credentials":
                return self._send_oauth_error(400, "unsupported_grant_type", None)
            if form.get("client_id", [""])[0] != MOCK_CLIENT_ID:
                return self._send_oauth_error(
                    401, "invalid_client", "client identifier invalid")
            return self._send_json(200, {
                "access_token": MOCK_TOKEN,
                "instance_url": STATE.base_url,
                "id": "%s/id/00Dxx0000000001/005xx000001SvogAAC" % STATE.base_url,
                "token_type": "Bearer",
                "issued_at": "1700000000000",
                "signature": "0abc=",
            })

        if self._path_is("/services/data/{version}/metadata/deployRequest"):
            return self._deploy(raw)

        if self._path_is("/services/data/{version}/echo"):
            return self._send_echo(u, None, body=raw.decode("utf-8", "replace"))

        if self._path_is("/services/data/{version}/sobjects/Account"):
            if self.headers.get("Content-Type") != "application/json":
                return self._send_salesforce_error(
                    400, "expected application/json", "INVALIDFIELD")
            try:
                obj = json.loads(raw)
            except ValueError as exc:
                return self._send_salesforce_error(
                    400, str(exc), "MALFORMED_QUERY")
            if not isinstance(obj, dict):
                return self._send_salesforce_error(
                    400, "expected a single JSON object", "MALFORMED_QUERY")
            return self._send_json(201, {"id": "001000000000000CCC",
                                         "success": True, "errors": []})

        return self._send_salesforce_error(404, "not found", "NOT_FOUND")

    def _deploy(self, raw):
        ctype = self.headers.get("Content-Type") or ""
        if "multipart/form-data" not in ctype:
            return self._send_salesforce_error(
                400, "expected multipart/form-data", "NOT_SUPPORTED")
        head = raw[:200000].decode("latin1")
        if 'name="json"' not in head:
            return self._send_salesforce_error(
                400, 'missing the "json" part', "NOT_SUPPORTED")
        if 'name="file"' not in head:
            return self._send_salesforce_error(
                400, 'missing the "file" part', "NOT_SUPPORTED")
        # The file part must be a binary zip. Base64 belongs to the SOAP
        # deploy() call; base64-ing it here is a common and unhelpful failure.
        if b"PK\x03\x04" not in raw:
            return self._send_salesforce_error(
                400, "file part is not a binary zip (did you base64 it?)",
                "NOT_SUPPORTED")
        options = ""
        marker = '{"deployOptions"'
        if marker in head:
            options = head[head.index(marker):head.index(marker) + 400]
        STATE.deploys[DEPLOY_ID] = {"polls": 0, "options": options}
        return self._send_json(201, {"id": DEPLOY_ID, "success": True,
                                     "state": "Pending"})

    # -- DELETE / PATCH -----------------------------------------------------

    def do_DELETE(self):
        self._note()
        # sobjects/<name>/<id> -- two segments after sobjects, hence two '*'.
        if self._path_is("/services/data/{version}/sobjects/*/*"):
            # 204 with no body is the delete-success shape, and must not be
            # mistaken for a parse failure.
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_salesforce_error(404, "not found", "NOT_FOUND")

    def do_PATCH(self):
        self._note()
        self._body()
        if self._path_is("/services/data/{version}/sobjects/*/*"):
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_salesforce_error(404, "not found", "NOT_FOUND")


# The deploy status document, shaped like the real thing: mixed successes and
# failures, with the line and column that tell you where in the file the problem
# is. That detail is the whole reason the client formats this.
DEPLOY_FINAL_STATUS = {
    "checkOnly": False,
    "createdDate": "2026-10-17T10:00:00.000Z",
    "done": True,
    "id": DEPLOY_ID,
    "status": "Failed",
    "statusDate": "2026-10-17T10:00:12.000Z",
    "numberComponentsDeployed": 1,
    "numberComponentsError": 1,
    "numberComponentsSkipped": 1,
    "numberComponentsTotal": 3,
    "details": {
        "componentSuccesses": [
            {"componentType": "ApexClass", "created": True,
             "fileName": "classes/Good.cls", "fullName": "Good",
             "problem": "", "success": True},
        ],
        "componentFailures": [
            {"componentType": "ApexClass", "created": True,
             "fileName": "classes/Bad.cls", "fullName": "Bad",
             "problem": "\n  Unexpected token: 'class' at line 3, column 1\n",
             "success": False, "lineNumber": 3, "columnNumber": 1},
            {"componentType": "CustomObject", "created": False,
             "fileName": "objects/Bogus/Bogus.object", "fullName": "Bogus",
             "problem": "In field: name - no CustomObject named Bogus found",
             "success": False, "lineNumber": 0, "columnNumber": 0},
        ],
        "runTestResult": {"numberErrors": 0, "numberFailures": 0,
                          "numberPassed": 2, "numberSkipped": 1,
                          "numberTestsRun": 2},
    },
}


def _deploy_status(self, path, query):
    """GET on .../metadata/deployRequest/<id>.

    Mixed into Handler after the class body because it is one route and reading
    it inline would bury the rest.
    """
    m = re.match(r"^/services/data/v[0-9.]+/metadata/deployRequest/([^/]+)$",
                 urlparse(path).path)
    if not m:
        return None
    loc = m.group(1)
    st = STATE.deploys.get(loc)
    if st is None:
        self._send_salesforce_error(404, "no such deploy", "NOT_FOUND")
        return True
    st["polls"] += 1
    # Pending once, then the final answer, so the client is forced to actually
    # poll rather than assuming the POST was the whole story.
    if st["polls"] < 2:
        self._send_json(200, {"id": loc, "state": "InProgress",
                              "status": "InProgress", "done": False})
        return True
    self._send_json(200, DEPLOY_FINAL_STATUS)
    return True


class MockSalesforce:
    """Context manager: start the mock on an ephemeral port, stop it on exit.

        with MockSalesforce() as base_url:
            ...  # base_url is the org root, e.g. http://127.0.0.1:34567
    """

    def __init__(self, host="127.0.0.1"):
        self.host = host
        self._server = None
        self._thread = None
        self.base_url = ""

    def __enter__(self):
        # Port 0 lets the kernel pick, so parallel runs cannot collide.
        self._server = HTTPServer((self.host, 0), Handler)
        self.base_url = "http://%s:%d" % (self.host, self._server.server_port)
        STATE.base_url = self.base_url
        STATE.deploys.clear()
        STATE.requests.clear()
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self.base_url

    def __exit__(self, *exc):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        return False

    @staticmethod
    def state():
        return STATE


def main():
    with MockSalesforce() as url:
        print("mock Salesforce listening at %s" % url, flush=True)
        print("point sfcc at it with: --login-url %s" % url, flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    sys.exit(main() or 0)