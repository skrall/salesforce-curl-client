# salesforce-curl-client

A small Salesforce REST client in C, built on libcurl.

Salesforce ships official SDKs for Java, .NET, PHP, Ruby, Node, Swift, Kotlin
and Go. There is no C or C++ SDK — not from Salesforce, and not from the
community either (GitHub's API returns zero C repositories for
`salesforce api client`). So this is the alternative: libcurl for transport and
a vendored cJSON for parsing, with OAuth and the handful of sObject calls a
command-line tool actually needs.

Builds and runs on Linux, macOS and Windows.

```
$ sfcc query "SELECT Id, Name FROM Account LIMIT 5"
{
  "totalSize": 2,
  "done": true,
  "records": [
    {
      "attributes": { "type": "Account", "url": "/services/data/v64.0/sobjects/Account/001000000000000AAA" },
      "Id": "001000000000000AAA",
      "Name": "Acme Corporation"
    }
  ]
}
```

## Building

libcurl is the only dependency you need to have installed; cJSON is vendored.

### Linux

```sh
# Arch
pacman -S libcurl
# Debian / Ubuntu
apt install libcurl4-openssl-dev build-essential cmake
```

### macOS

libcurl is present but headers often are not:

```sh
brew install curl cmake
cmake -S . -B build -DCMAKE_PREFIX_PATH="$(brew --prefix curl)"
```

### Windows

Nothing is bundled. Use vcpkg, which supplies libcurl and its dependencies:

```powershell
vcpkg install curl:x64-windows-static-md
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

Prefer the `static-md` triplet over a DLL one. It links libcurl statically
while still using the shared CRT, which avoids shipping a libcurl DLL next to
your executable and sidesteps the `CURL_STATICLIB` mismatch that produces
`__imp_curl_easy_init is unresolved` at link time. CMake handles that define
for you — see the `CURL_STATICLIB` block in `CMakeLists.txt`.

### All platforms

```sh
cmake --preset release && cmake --build --preset release
./build/release/bin/sfcc --help
```

Presets: `debug`, `release`, and `asan` (AddressSanitizer + UBSan).

## Setting up Salesforce

You need a **connected app** with the **OAuth 2.0 Client Credentials flow**
enabled. In Setup → App Manager → New Connected App → External App Options:

- enable OAuth Settings
- check **Enable Client Credentials Flow**
- add an **API Integration User** — this is the account whose permissions the
  client inherits, so it should be a least-privilege integration user, not an
  admin

Then put the consumer key and secret in the environment:

```sh
export SFCC_CLIENT_ID='3MVG9...'      # consumer key
export SFCC_CLIENT_SECRET='ABC123...'  # consumer secret
sfcc auth
```

```
instance: https://acme.my.salesforce.com
token:    obtained (not shown) and cached
cache:    /home/you/.sfcc-token.json
```

The secret is read from the environment only. There is deliberately no
`--client-secret` flag: command lines are visible to every process on the
machine through `ps` and `/proc`, so a secret passed that way is readable by
anything running as the same user.

Sandboxes use `--login-url https://test.salesforce.com`.

## Commands

| Command | Description |
| --- | --- |
| `auth` | Fetch a token and print the instance URL |
| `whoami` | The identity the token belongs to |
| `query <soql>` | Run a SOQL query |
| `get <object> <id>` | Fetch one record |
| `create <object> <json>` | Insert a record |
| `update <object> <id> <json>` | Update a record |
| `delete <object> <id>` | Delete a record |
| `describe <object>` | Object metadata as three tables: fields, children, record types |
| `sobjects` | Every object in the org, as a table |
| `versions` | API versions this org supports |
| `rest <path>` | One raw REST call, with auth applied |
| `deploy --zip <file>` | Deploy a prebuilt metadata package |
| `retrieve <package.xml>` | Fetch metadata named by a manifest into a `.zip` |

| Option | Description |
| --- | --- |
| `--instance <url>` | Org base URL |
| `--token <token>` | Use this token instead of authenticating |
| `--api-version <v64.0>` | API version |
| `--login-url <url>` | Token endpoint (default `https://login.salesforce.com`) |
| `--token-cache <path>` | Where to memoise the token |
| `--no-cache` | Do not read or write the cache |
| `--timeout <seconds>` | Whole-transfer timeout |
| `--raw` | One-line JSON instead of indented |
| `--quiet` | Suppress the trailing status line |
| `--insecure-skip-verify` | **Dangerous.** Disable TLS certificate checks |

| Environment variable | Description |
| --- | --- |
| `SFCC_CLIENT_ID` | Connected app consumer key (required) |
| `SFCC_CLIENT_SECRET` | Connected app consumer secret (required) |
| `SFCC_LOGIN_URL` | Token endpoint base |
| `SFCC_INSTANCE_URL` | Org base URL |
| `SFCC_ACCESS_TOKEN` | Pre-minted access token |
| `SFCC_API_VERSION` | API version |
| `SFCC_TOKEN_CACHE` | Token cache path |

### Listing what is in the org

`sobjects` fetches the global object listing — API name, label, key prefix, and
the capability flags — and prints it as a table:

```console
$ sfcc sobjects --custom --filter invoice
NAME        LABEL             PREFIX  CUST  CRE  UPD  DEL  UNDEL  QRY  RET  SRCH  LAY  MRG  TRIG
Invoice__c  Customer Invoice  inv     yes   yes  yes  yes  yes    yes  yes  yes   yes  no   yes
1 of 214 objects
```

Without `--raw` you get that table; with `--raw` you get the API response, which
includes the flags the table leaves out (`customSetting`, `feedEnabled`,
`deprecatedAndHidden`, `hasSubtypes`, `isSubtype`, `mruEnabled`). Nothing is
unavailable — it is only unlisted, and the table keeps to the flags worth
reading at a glance.

| Option | Description |
| --- | --- |
| `--raw` | Print the API response instead of the table |
| `--custom` | Only custom objects, skipping the platform ones |
| `--filter <text>` | Keep objects whose name or label contains `<text>`, ignoring case |
| `--limit <n>` | Show at most `<n>` objects |
| `--no-header` | Omit the column header line |

Column widths are measured over the rows actually printed, so `--filter` gives
a table sized to its results rather than padded to fit objects it dropped. A
flag Salesforce omits renders as `no` rather than as a blank, because a
capability table with holes in it is harder to read than one that is
pessimistic.

### Describing one object

`describe <object>` prints three tables — fields, child relationships and
record types — rather than one wall of JSON:

```console
$ sfcc describe Account --field Revenue

fields (1)
NAME           LABEL           TYPE      LEN  SIZE  REL NAME  REFERENCE TO
AnnualRevenue  Annual Revenue  currency  18   18,0  -         -

child relationships (3)
FIELD      CHILD OBJECT  REL NAME
AccountId  Contact       Contacts
AccountId  Opportunity   Opportunities
AccountId  AccountShare  -

record types (3)
ID                  NAME      DEVELOPER NAME  ACTIVE  MASTER  AVAILABLE  DEFAULT
012000000000000AAA  Master    Master          yes     yes     yes        yes
012000000000000BBB  Customer  Customer        yes     no      yes        no
012000000000000CCC  Partner   Partner         no      no      no         no
```

| Option | Description |
| --- | --- |
| `--json` | The whole response as indented JSON |
| `--field <text>` | Only fields whose name or label contains `<text>` |
| `--no-header` | Omit the column header line of each table |

`--field` is the practical one: a wide object like Account has around ninety
fields, and scanning for the one you care about is the reason to reach for
`describe` in the first place. `--filter` narrows only the fields table; the
other two always print in full, since they are short.

A few things the tables make explicit that the raw JSON leaves to be inferred:

- **`SIZE` is `precision,scale`**, and is `-` for the many types that have
  neither. `LEN` is `-` for those too — a `datetime` or a `boolean` reports a
  length of zero, and printing that `0` invites the reader to believe it.
- **`REFERENCE TO` lists several entries for a polymorphic reference.** `OwnerId`
  can be a `User` or a `Group`, and both are shown, comma separated.
- **`REL NAME` and `REFERENCE TO` are different columns.** A lookup provides
  both a relationship name and a target object; only one of the two is present
  for most fields, and the other shows `-`.

Note that `--json` exists because `describe` used to print indented JSON by
default. Piping it into `jq` still works, without `--raw`.

### Retrieving metadata

```console
$ sfcc retrieve package.xml --out build/metadata.zip
retrieve 0Af1B000000XXXX: Pending... (this can take minutes)
retrieved build/metadata.zip (Succeeded, 2401931 bytes)
```

Then unpack it with anything, and deploy it straight back:

```sh
unzip -q build/metadata.zip -d metadata
sfcc deploy --zip build/metadata.zip
```

| Option | Description |
| --- | --- |
| `--out <file.zip>` | Where to write the archive (default `metadata.zip`) |
| `--retrieve-poll-interval <s>` | Status poll interval (default 5) |
| `--retrieve-timeout <s>` | Give up waiting after this long (default 900) |

Both `retrieve` and `deploy` report while they wait, with the elapsed time and
what is left of the budget:

```
  retrieve 0Af1B000000XXXX: Pending... 3s elapsed, 897s left of 900s
```

On a terminal that is one line rewritten in place, so it shows movement rather
than filling the scrollback. Redirected — a CI log, a file — the same text is
written as standalone lines, throttled to one per poll interval.

**This is the one command that is not REST.** The Metadata API has a REST
resource for deploy but not for retrieve — Salesforce's own CLI and jsforce both
use SOAP for this, `performRetrieve` is documented as "Reserved for future use",
and a search of public code turns up nobody retrieving over REST. So this is the
client's only non-REST transport, kept as small as the operation allows.

**The archive is written as received and is not unpacked.** The Metadata API
returns one base64 `zipFile` and no per-file content, so there is nothing else to
write. That is not only a shortcut: no path inside the archive is ever used, so
the zip-slip class of problem — a hostile org returning `../../../.ssh/…` —
cannot arise here at all.

**The manifest is not parsed either.** Its `<Package>` element has the same shape
and the same default namespace as the `<unpackaged>` element the SOAP request
wants, so the contents are copied across verbatim. A manifest that writes
`<Package>` with a namespace prefix is refused with an explanation rather than
sent in the wrong namespace, where the org would answer with an opaque fault.

The API version comes from `--api-version`, like every other command, rather than
from the manifest. Note that Salesforce still lets a `<version>` inside the
manifest govern the shape of the components returned, so it is not fully
authoritative either way.

### The `rest` escape hatch

Salesforce adds REST resources faster than any client wraps them, so rather
than growing a command per endpoint there is one generic one:

```sh
sfcc rest limits                                  # -> /services/data/v64.0/limits
sfcc rest /services/data/{version}/limits         # absolute, {version} substituted
sfcc rest "query?q=SELECT Id FROM Account LIMIT 5"
sfcc rest sobjects/Account -X POST -d '{"Name":"Acme"}'
sfcc rest sobjects/ContentVersion/068.../VersionData -o blob.bin
```

A path beginning with `/` is absolute; anything else is relative to
`/services/data/<version>/`. The literal `{version}` is replaced with the
configured API version anywhere in the path, so scripts need not hardcode a
number that eventually goes out of support.

| Option | Description |
| --- | --- |
| `-X, --method <verb>` | `GET` `POST` `PATCH` `PUT` `DELETE` (default: POST with a body, else GET) |
| `-d, --data <text>` | Request body. `@-` reads stdin, `@path` reads a file, verbatim |
| `--data-file <path>` | Read the body from a file; `-` means stdin |
| `-H, --header 'Name: value'` | Add a header (repeatable) |
| `-i, --include` | Show the response headers |
| `-o, --output <path>` | Write the body to a file; `-` means stdout |

#### Piping

Input comes from stdin and output goes to stdout, so both ends compose:

```sh
# build a record with jq, send it, keep the id
jq -n '{Name:"Acme", Industry:"Tech"}' \
  | sfcc rest sobjects/Account -X POST -d @- \
  | jq -r .id

# a large export goes to a file, not through a shell argument
sfcc rest sobjects/Contact -o contacts.json

# and straight into another tool
sfcc rest "query?q=SELECT Id,Name FROM Account LIMIT 100" | jq '.records[]'
```

Details that matter in a pipeline:

* **`-d @-` reads stdin, and so does `--data-file -`.** A bare `@` or an empty
  pipe is reported as a mistake rather than sent as an empty body — an empty
  POST is almost always a broken pipeline, and sending it would look like a
  server-side problem.

* **`@` reads bytes unchanged, unlike curl.** curl's `-d @file` *form-encodes*
  the content unless you ask for `--data-raw`. Copying that here would quietly
  corrupt every JSON body anyone piped in, which is the common case.

* **stdin on a terminal is refused, not read.** `sfcc … -d @-` with nothing
  piped would otherwise block forever and look like a hang.

* **`-o <file>` leaves stdout empty** and puts its "wrote N bytes" status on
  stderr, so switching between a file and the pipeline via `-o -` cannot
  contaminate either.

* **stdin is read in binary mode** on Windows, so the CRT cannot rewrite the
  body's LF as CRLF behind your back.

Three deliberate choices:

* **The path is not percent-encoded.** SOQL, composite batches and report
  filters all live in the query string, and re-encoding a path that already
  carries a working query string would corrupt it. This matches `curl`: you own
  the encoding. A raw space is refused up front rather than sent, because the
  org's reply to one is a 400 that never mentions the missing `%20`.

* **No retry.** Every other call funnels through a path that re-authenticates
  once on an invalid session. That is right for a known endpoint and wrong
  here, where the request may be something new and not idempotent.

* **A 4xx is not an error.** The request worked and the server's answer is what
  you asked for, so the body always goes to stdout and the exit status reports
  only whether the exchange happened. Use it in a pipeline like:

```sh
sfcc rest "query?q=SELECT Id FROM Account WHERE Name LIKE 'A%'" \
  | jq '.records[].Id'
```

Response bodies are handled as bytes, not strings: a `VersionData` fetch or a
CSV export contains NULs, and `body_len` is authoritative for that reason.

Flags beat environment variables, which beat the built-in defaults. Options
may appear anywhere on the command line — before the command, after it, or
straddling it:

```sh
sfcc --instance https://acme.my.salesforce.com --token "$T" query "SELECT Id FROM Account"
sfcc query "SELECT Id FROM Account" --instance https://acme.my.salesforce.com --token "$T"
```

A bare `--` ends option processing, for the rare argument that must begin with
a dash.

## Using it as a library

The CLI is a thin shell over `libsfcc`, which is a normal static library with a
plain C header.

```c
#include <sfcc.h>

sfcc_config cfg;
sfcc_config_defaults(&cfg);
sfcc_config_apply_env(&cfg);          /* reads the SFCC_* variables */

sfcc_client* c = sfcc_client_new(&cfg);
if(c == NULL){
  return 1;
}

char* body = NULL;
sfcc_status rc = sfcc_query(c, "SELECT Id, Name FROM Account LIMIT 10", &body);
if(rc == SFCC_OK){
  puts(body);
}
free(body);

if(rc != SFCC_OK){
  fprintf(stderr, "%s\n", sfcc_last_error(c));   /* specific, not generic */
}
sfcc_client_free(c);
```

Every operation returns a status code and, on success, allocates the decoded
response body for you to free. Nothing prints unless you ask it to.

## Running it in a container

```sh
docker build -t sfcc .
docker run --rm sfcc rest limits          # with credentials from the environment
```

The image name is just `sfcc`, which Docker records as `sfcc:latest`. The `-t
sfcc` matters in practice: a build with no tag yields an unnamed `<none>` image
that is awkward to run and awkward to find again.

| Tag | For |
| --- | --- |
| `sfcc:latest` | Local development -- what `docker build -t sfcc .` produces |
| `sfcc:<version>` | A release, matching `project(VERSION)` in `CMakeLists.txt` |

Prefer a version tag over `latest` in anything scripted, so a rebuild cannot
silently change what CI runs.

A ~23 MB Alpine image: a 98 KB binary, `libcurl`, and a CA trust store. The
build stage is a full toolchain; the runtime image carries neither the compiler
nor the sources.

Why Alpine: musl's resolver works in a static build, whereas glibc's needs NSS,
so a statically linked glibc HTTP client fails DNS at runtime in a way that only
shows up when you try it. That is the reason to prefer Alpine here even though
the shipped image is not itself fully static — Alpine publishes
`openssl-libs-static` but has no `libcurl.a`, so a `scratch` build would mean
compiling curl from source in the build stage. Not worth it for a CLI.

Three things that bite in containers:

* **`-i` is required to pipe a request body in.** Without it the container's
  stdin is closed and `-d @-` reads nothing:

  ```sh
  jq -n '{Name:"Acme"}' | docker run -i --rm --env-file .env sfcc \
      rest sobjects/Account -X POST -d @- | jq -r .id
  ```

* **The token cache does not survive.** It lives at `~/.sfcc-token.json` and a
  container's HOME is ephemeral, so every `docker run` re-authenticates.
  Mounting the host's cache into the container puts a live bearer token on the
  host filesystem, which is a poor trade for one saved token request. Use
  `--no-cache` and let it re-authenticate.

* **Pass the secret with `--env-file`, never `--build-arg`.** A build argument
  is recorded in image history and is readable by anyone who can pull the
  intermediate layer.

## Things worth knowing

A few behaviours that are easy to get wrong, and that this client handles
deliberately. Each is covered by a test.

* **Record Ids never touch a numeric type.** An 18-character Salesforce Id
  does not survive a round trip through a `double` — the low bits are lost and
  you end up querying a record that does not exist. Ids stay strings
  everywhere, and are validated as 15 or 18 base-62 characters before a
  request is built.

* **SOQL is percent-encoded as a whole.** A query almost always contains
  spaces, which end the `q` parameter if left alone. `'+'` is escaped too,
  which matters more than it sounds: many decoders turn `+` back into a space,
  so leaving it raw silently changes the meaning of any filter containing one.
  Apostrophes (`'O''Brien'`) are escaped as well.

* **`.` is never percent-encoded.** It is an RFC 3986 unreserved character.
  Encoding it would break every record Id and field name. Traversal
  protection comes from escaping `/` instead — `../../etc` becomes
  `..%2F..%2Fetc`, which does not resolve.

* **The OAuth token endpoint is form-encoded, not JSON.** Every other call
  here sends `application/json`, and using that for the token request produces
  a 400 with a body that explains nothing. `sfcc_http_request` therefore takes
  the content type as a parameter.

* **The platform uses two different error shapes.** The REST sObject
  endpoints answer with a JSON *array* of `{message, errorCode}`; the token
  endpoint uses OAuth's `{error, error_description}`. Handle only the first
  and every authentication failure prints as a raw JSON blob.

* **A 204 with no body is success.** `delete` and `update` legitimately return
  nothing. Treating an empty body as a parse failure makes every delete look
  broken.

* **Text from the server is sanitised before printing.** Salesforce error
  messages embed user-supplied field values, so an escape sequence in a record
  name would otherwise be written to your terminal verbatim — and these
  messages are often captured into logs and CI annotations.

* **A cached token can go stale at any moment.** Salesforce does not say when
  an access token expires, and one can be revoked server-side between runs. The
  cache records an `expires_at` when the token is written, and a cache that has
  passed it is discarded and replaced before the request goes out — so an expired
  cache is not something you have to notice. If the org rejects a token that
  looked current anyway, the client drops it, fetches a new one, and retries
  exactly once, over REST and SOAP alike. Without either, long-running scripts
  need a manual `rm ~/.sfcc-token.json`.

* **A token cache counts as credentials.** A run with `SFCC_CLIENT_ID` and
  `SFCC_CLIENT_SECRET` unset is not refused for having none while a current cache
  is sitting on disk. Previously it was, and the advice it gave — set the two
  environment variables — was a plausible thing to do and entirely beside the
  point. The failure message names the cache path it looked at.

* **The token cache is created mode 0600.** It holds a bearer token granting
  whatever the integration user can do. Created normally it lands at 0644,
  which means any other local account can read it and use the org. There is no
  equivalent on Windows, where access is governed by the file's ACL instead.

* **Redirects are not followed.** Following one would replay the
  `Authorization` header at whatever host the `Location` points to.

* **A response body is bytes, not a C string.** Salesforce serves binary
  (`VersionData`) and CSV (Bulk exports) from the same REST API. Both contain
  NUL bytes, and `strlen()` on such a buffer truncates at the first one — which
  silently produced an 8-byte "file" out of a 22-byte response before this was
  caught by testing. `sfcc_rest_result` therefore carries `body_len`, and it is
  authoritative wherever the body is written out.

* **A caller-supplied `Authorization` header replaces this client's token**
  rather than being sent alongside it. curl emits duplicate header lines rather
  than replacing, so the client has to suppress its own default for an override
  to mean anything.

* **A `CURLOPT_HTTPHEADER` entry must contain a colon.** libcurl parses each
  string on its first colon and *silently discards* any entry without one.
  Writing `"Bearer <token>"` instead of `"Authorization: Bearer <token>"`
  produces no header, no error, and no warning — every request just goes out
  unauthenticated and the server replies 401. There is a test that binds a
  loopback listener and inspects the actual bytes, because asserting on the
  string constant would not catch it: the constant is not what curl does.

* **A rejected token is reported as such, not as missing credentials.** The
  client re-authenticates and retries once when a *cached* token goes stale —
  the platform can revoke one at any moment. That retry is only ever correct
  for a token the client obtained itself. With `--token` there is nothing to
  re-mint, so discarding the caller's token and failing to replace it turned a
  precise "this token was rejected" into a vague "no credentials".

* **A Salesforce *session* id is not a REST access token.** What Setup >
  Session Settings > View Session shows, and what the `sid` cookie holds, looks
  similar but is always rejected by the REST API. Since the resulting error is
  unhelpfully terse, a 401 says so explicitly.

* **sObject names and Ids are validated before they go near a URL**, which
  turns a typo into a clear message instead of a confusing 404.

* **`--instance` and `--token` are useless alone.** The instance says which
  org, the token says you may act on it, and a request missing either is
  rejected in a way that reads like bad credentials. Supplying just one gets a
  message naming the missing half rather than a generic complaint.

* **Argument parsing is hand-rolled**, since `getopt` is not on Windows
  without a POSIX shim. It follows getopt's convention of permuting options
  rather than requiring them first, because the alternative is a flag silently
  becoming a command argument — which produced a "no credentials" error that
  sent you looking in entirely the wrong place.

## Testing

```sh
cmake --preset debug && cmake --build --preset debug
ctest --test-dir build/debug --output-on-failure
```

29 tests, none of which need a Salesforce org or any credential:

- 104 unit checks covering percent-encoding, the growable buffer, input
  validation, both server error shapes, and the binary-body length — the parts
  that fail *silently* when wrong, as a bad encoder still returns HTTP 200 and
  the wrong records
- 28 CLI tests for argument handling and exit codes
- an end-to-end suite that drives the real binary against a mock endpoint and
  inspects the bytes on the wire (`tests/e2e/` — its README explains why that
  layer is not redundant with the unit tests)

The ASan preset adds AddressSanitizer and UBSan:

```sh
cmake --preset asan && cmake --build --preset asan
ctest --preset asan
```

Continuous integration runs on every push and pull request: Linux with both gcc
and clang at `-Werror` across all three presets, the end-to-end suite against a
*release* binary, macOS against Homebrew's libcurl, and Windows via MSVC and
vcpkg. No secrets are configured, because no test needs any.

## Limitations

Worth knowing before you build something on this:

- **REST only.** No Bulk API 2.0, Composite API, Metadata API, Tooling API,
  Streaming API or Pub/Sub API.
- **No field-level typing.** Everything is JSON, so `Account.Name` and
  `Account.NumberOfEmployees` come back as whatever the server sends, not as a
  declared struct. That is the usual trade-off in C; generating typed accessors
  from an org's metadata is the natural next step.
- **Client credentials only.** No interactive flow, so no per-user consent
  screen. This suits a CLI or a service account and does not suit a
  user-facing app.
- **`whoami` needs the client to authenticate itself.** It reads the identity
  URL from the token response, which a caller-supplied `--token` does not
  carry.
- **SOQL is not checked client-side.** A malformed query produces a server
  error rather than a local one.

## Layout

```
include/sfcc.h        public API
src/sfcc_internal.h   shared internals
src/sfcc_util.c       buffers, strings, percent-encoding, paths
src/sfcc_json.c       JSON helpers and error unpacking
src/sfcc_http.c       libcurl: build, send, collect, report
src/sfcc_auth.c       OAuth and token caching
src/sfcc_client.c     config, URL building, the sObject operations
src/main.c            command-line front end
third_party/cjson/    vendored, pinned at v1.7.19 (MIT)
tests/                unit tests plus CLI smoke tests
```