# End-to-end tests

These drive the real `sfcc` binary against a mock Salesforce endpoint and
check what actually goes over the wire.

They exist because of a specific bug. The `Authorization` header was once built
as `"Bearer <token>"` instead of `"Authorization: Bearer <token>"`. libcurl
parses each `CURLOPT_HTTPHEADER` entry on its first colon and **silently
discards** any entry without one, so every request went out unauthenticated --
no error, no warning, just a 401 from the server. The unit tests all passed,
because the constant they asserted on was not the string curl acts on. Only a
test that reads back what the server received could see it.

## Running them

```sh
python3 tests/e2e/e2e.py build/release/bin/sfcc
```

Or as part of the normal suite, where they run automatically when Python is
present:

```sh
ctest --test-dir build/release --output-on-failure
```

Exit status is 0 when everything passed, 1 otherwise.

**Run them against a release build.** An optimised binary is where latent memory
bugs become actual crashes, and one was hiding exactly here: a stack array of
request headers was never NULL-terminated, so the walk over it ran off the end
and dereferenced whatever was there. That is harmless at `-O0`, where the slot
happens to be zero, and a segfault at `-O2`.

## What they cover

| Group | What it pins down |
|---|---|
| auth | The token request is form-encoded, not JSON |
| query | SOQL is percent-encoded and decodes byte-identically |
| query | Both server error shapes are unpacked, not dumped as JSON |
| records | get / create / update / delete, including 204-with-no-body |
| validation | Bad arguments are caught before any request is made |
| rest | Path forms, `{version}` substitution, headers, method inference |
| rest | A caller-supplied `Authorization` replaces ours, not alongside it |
| rest | A rejected token is not misreported as missing credentials |
| binary | A body with NUL bytes survives, to file and to stdout |
| stdio | `-d @-`, `--data-file -`, `-d @path`, `-o`, `-o -` |
| deploy | Multipart shape, async polling, per-component failure reporting |
| deploy | The token cache is created mode 0600 |
| transport | DNS and TLS failures are named, not called "network error" |

## Files

- `mock_server.py` -- the mock. Stdlib only (`http.server`, `json`,
  `urllib.parse`), so it needs nothing installed. Also runnable on its own if you
  want to poke at the binary by hand.
- `e2e.py` -- the runner. Starts the mock on an ephemeral port, drives the
  binary through `subprocess`, and reports.

Python rather than shell, because bash is not on Windows by default and this
project targets three platforms. Everything here runs on any Python 3.7+.

## No credentials needed

The mock supplies its own `client_id` and `secret`, and the runner clears any
`SFCC_*` variables from the environment before each call. Nothing here talks to
a real Salesforce org, so there are no secrets to configure and nothing to leak
into CI logs.