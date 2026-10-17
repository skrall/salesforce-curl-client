/*
 * sfcc -- a small Salesforce REST client built on libcurl.
 *
 * The scope here is deliberate: authenticate, then the handful of sObject
 * calls a command-line tool actually needs. Every operation hands back the
 * decoded response body as a JSON string and leaves presentation (pretty
 * printing, table formatting) to the caller, so the library stays free of
 * opinions and is reusable from something other than a terminal.
 *
 * Thread safety: a single sfcc_client is not thread-safe. Distinct clients are
 * independent and may be used concurrently, since libcurl's global init is
 * reference-counted here rather than being an atexit teardown.
 */
#ifndef SFCC_H
#define SFCC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward declaration. Two functions below take a client before the typedef
 * appears, and in C an undeclared "struct sfcc_client" in a parameter list
 * declares a *new* type scoped to that prototype -- which then fails to match
 * the real definition and warns under -Werror.
 */
struct sfcc_client;

/* ------------------------------------------------------------------------ */
/* Status codes                                                             */
/* ------------------------------------------------------------------------ */

/*
 * Everything returns one of these. SFCC_OK is 0 so `if (rc)` reads correctly.
 * Anything transport- or protocol-level is negative; the enum is deliberately
 * sparse so the CLI can map a subset onto distinct exit codes.
 */
typedef enum {
  SFCC_OK           =  0,  /* success                                        */
  SFCC_ERR_ARG      = -1,  /* caller passed something unusable                */
  SFCC_ERR_MEM      = -2,  /* out of memory                                  */
  SFCC_ERR_NET      = -3,  /* transport failure; curl_easy_strerror applies   */
  SFCC_ERR_HTTP     = -4,  /* server answered, but with a non-2xx status     */
  SFCC_ERR_AUTH     = -5,  /* authentication failed or no usable credentials  */
  SFCC_ERR_JSON     = -6,  /* response was not the JSON we expected          */
  SFCC_ERR_IO       = -7,  /* local file i/o failed (e.g. the token cache)   */
} sfcc_status;

/*
 * A human-readable description of a status. For SFCC_ERR_NET the text is the
 * underlying curl message when one is available, since "network error" on its
 * own is never enough to diagnose anything. Never NULL, never needs freeing.
 */
const char* sfcc_strerror(sfcc_status rc);

/*
 * Details of the most recent failure, or NULL if there was none. Points into
 * the client and stays valid until the next call on that client. For HTTP
 * errors this holds a Salesforce-provided message when one was parseable --
 * things like "INVALID_FIELD: No such column 'Foo' on entity 'Account'" --
 * otherwise it holds the raw response body (truncated).
 */
const char* sfcc_last_error(const struct sfcc_client* c);

/* The HTTP status code of the last response, or 0 if no request completed. */
long sfcc_last_status(const struct sfcc_client* c);

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

typedef struct sfcc_config {
  /*
   * OAuth token endpoint base. Defaults to "https://login.salesforce.com";
   * sandboxes use "https://test.salesforce.com". A trailing slash is
   * tolerated and stripped.
   */
  const char* login_url;

  const char* client_id;      /* connected app consumer key                    */
  const char* client_secret;  /* connected app consumer secret                 */

  /*
   * Bypasses OAuth entirely when both are set, which is what you want in CI
   * where the token is minted elsewhere. If only one is set, authentication
   * is attempted and will fail with SFCC_ERR_AUTH rather than silently
   * sending a half-configured request.
   */
  const char* instance_url;
  const char* access_token;

  const char* api_version;    /* e.g. "v64.0". Defaults to the compile-time
                                 SFCC_DEFAULT_API_VERSION.                     */

  /* Where to memoise the access token between runs. NULL means the default
   * path under the user's home directory. Ignored when no_cache is set. */
  const char* cache_path;
  int no_cache;

  long timeout_s;             /* whole-transfer timeout; 0 uses the default   */
  long connect_timeout_s;

  /*
   * Disables TLS certificate and hostname verification. Off by default and
   * there is a good reason: it silently accepts any certificate, so traffic
   * carrying a bearer token can be intercepted. The CLI exposes this as
   * --insecure-skip-verify and prints a warning when it is used.
   */
  int insecure;
} sfcc_config;

/* Fill cfg with defaults. Call before overriding individual fields. */
void sfcc_config_defaults(sfcc_config* cfg);

/*
 * Read configuration from the environment (SFCC_LOGIN_URL, SFCC_CLIENT_ID,
 * SFCC_CLIENT_SECRET, SFCC_INSTANCE_URL, SFCC_ACCESS_TOKEN,
 * SFCC_API_VERSION, SFCC_TOKEN_CACHE). Unset variables are left untouched, so
 * this composes with explicit overrides in any order.
 */
void sfcc_config_apply_env(sfcc_config* cfg);

/* ------------------------------------------------------------------------ */
/* Client                                                                   */
/* ------------------------------------------------------------------------ */

typedef struct sfcc_client sfcc_client;

/*
 * Create a client. Does not perform any network I/O -- authentication is
 * deferred to the first API call, so constructing a client with bad
 * credentials succeeds and only fails once you ask for data.
 *
 * The config is copied; the client does not retain any pointer into it, and
 * the strings may be freed or go out of scope immediately afterwards.
 * Returns NULL only if memory is unavailable.
 */
sfcc_client* sfcc_client_new(const sfcc_config* cfg);

/* Free a client. Safe on NULL. Does not log out or revoke the token. */
void sfcc_client_free(sfcc_client* c);

/*
 * Authenticate if needed and return the instance URL in use. With cached
 * credentials this may touch no network at all. Useful for `whoami` and for
 * confirming that credentials work before doing real work.
 */
sfcc_status sfcc_authenticate(sfcc_client* c, char** instance_url);

/* ------------------------------------------------------------------------ */
/* API operations                                                           */
/* ------------------------------------------------------------------------ */

/*
 * Each of these allocates the response body into *out on success and returns
 * SFCC_ERR_ARG with *out untouched on a bad argument. The caller frees *out.
 * None of them print anything.
 */

/* Run a SOQL query. The statement is percent-encoded for you. */
sfcc_status sfcc_query(sfcc_client* c, const char* soql, char** out);

/* Fetch one record: GET /sobjects/<sobject>/<id>. */
sfcc_status sfcc_get_record(sfcc_client* c, const char* sobject,
                            const char* id, char** out);

/*
 * Insert a record. json_body must be a JSON object, e.g.
 * {"Name":"Acme","NumberOfEmployees":42}. Returns the new record's Id and
 * whether it was created (the latter is only meaningful for a partial insert).
 */
sfcc_status sfcc_create(sfcc_client* c, const char* sobject,
                        const char* json_body, char** out);

/* Update a record by Id. json_body must be a JSON object. */
sfcc_status sfcc_update(sfcc_client* c, const char* sobject,
                        const char* id, const char* json_body, char** out);

/* Delete a record by Id. Salesforce answers 204 with an empty body. */
sfcc_status sfcc_delete(sfcc_client* c, const char* sobject,
                        const char* id);

/*
 * The identity that owns the current token: user id, username, display name,
 * email, and the org id. Obtained from the token's identity endpoint, which is
 * recorded at authentication time.
 *
 * Requires that the client authenticated itself. When credentials were supplied
 * via --instance/--token there is no identity URL to ask, and this returns
 * SFCC_ERR_AUTH with an explanation rather than guessing.
 */
sfcc_status sfcc_whoami(sfcc_client* c, char** out);

/* Object metadata: field names, types, picklist values. */
sfcc_status sfcc_describe(sfcc_client* c, const char* sobject, char** out);

/* API versions this org supports. Needs no object, but does need auth. */
sfcc_status sfcc_list_versions(sfcc_client* c, char** out);

/* ------------------------------------------------------------------------ */
/* Metadata deploy                                                          */
/* ------------------------------------------------------------------------ */

/*
 * How much test execution a deploy asks for.
 *
 * SFCC_TEST_NONE is NoTestRun, valid for metadata that triggers nothing.
 * SFCC_TEST_LOCAL runs the org's local tests and is what you almost always
 * want in production. SFCC_TEST_SPECIFIED runs only the tests named in
 * options->tests, which is the only mode that can target a subset -- there is
 * no "these three classes" option on any other setting.
 */
typedef enum {
  SFCC_TEST_NONE = 0,
  SFCC_TEST_LOCAL,
  SFCC_TEST_SPECIFIED,
} sfcc_test_level;

typedef struct {
  /*
   * Validate without writing anything. Cheap, safe, and the right default when
   * you are iterating on a package: it exercises compilation and tests but
   * leaves the org untouched.
   */
  int validate_only;

  sfcc_test_level test_level;

  /* Comma-separated test class names. Required for, and only consulted by,
   * SFCC_TEST_SPECIFIED. */
  const char* tests;

  /* Treat the zip as a single managed package. Leave off for unpackaged
   * content, which is the common case. */
  int single_package;

  /* Poll interval and overall deadline in seconds. Defaults are used for
   * anything <= 0. Deploys are asynchronous and a test-heavy one can run for
   * many minutes, so the deadline is deliberately generous. */
  long poll_interval_s;
  long timeout_s;
} sfcc_deploy_options;

/* Fill opts with defaults: NoTestRun, unpackaged, 5s polls, 900s deadline. */
void sfcc_deploy_options_defaults(sfcc_deploy_options* opts);

/*
 * The outcome of a deploy, after polling has finished.
 *
 * The raw status document is kept in raw_json for anything this does not model;
 * sfcc_deploy_report() renders the useful summary. A failed deploy is a
 * *successful* function call describing a failure, so check succeeded rather
 * than the return value to decide whether the org changed.
 */
typedef struct {
  char* id;               /* async process id, for looking it up later       */
  char* status;           /* Succeeded | Failed | Canceled | Pending | ...   */
  char* raw_json;         /* the final status document, verbatim             */
  /*
   * A rendered summary: the outcome line, then one line per component with
   * file and line where the org supplied them. This is the useful view of
   * raw_json, which is complete but unreadable. Filled in even when polling
   * times out, since the partial state is still worth showing.
   */
  char* report;
  int   succeeded;        /* 1 when status is "Succeeded"                    */
  int   done;
  int   total;            /* numberComponentsTotal                          */
  int   deployed;         /* numberComponentsDeployed                       */
  int   errors;           /* numberComponentsError                          */
  int   skipped;          /* numberComponentsSkipped                        */
  int   was_cancelled;
} sfcc_deploy_result;

/*
 * Deploy a prebuilt metadata zip.
 *
 * zip_path must be a file on disk; this stage deliberately does not build zips
 * from a directory yet. The file is read and validated locally first, so an
 * unreadable path or something that is not a zip fails before consuming an API
 * call.
 *
 * The request is asynchronous: this uploads the package, then polls until the
 * org finishes or the deadline passes. On a timeout the partial result is
 * still stored in *out -- the deploy may well still finish server-side, so the
 * id is included precisely so you can check on it later.
 *
 * Returns SFCC_OK when the deploy *ran*, whatever its outcome. Consult
 * result->succeeded. SFCC_ERR_ARG for a bad path, SFCC_ERR_AUTH/HTTP for a
 * rejected request.
 */
sfcc_status sfcc_deploy_zip(sfcc_client* c, const char* zip_path,
                            const sfcc_deploy_options* opts,
                            sfcc_deploy_result* out);

void sfcc_deploy_result_free(sfcc_deploy_result* r);

/* ------------------------------------------------------------------------ */
/* Generic REST passthrough                                                 */
/* ------------------------------------------------------------------------ */

/*
 * An escape hatch: one request against any Salesforce REST path, with the
 * instance URL, API version and bearer token already applied.
 *
 * Intended for endpoints this library does not wrap -- which is always some of
 * them, since Salesforce keeps adding resources. It is deliberately thin: the
 * path is passed through verbatim and nothing is inferred about it beyond
 * where the instance URL goes.
 */
typedef struct {
  /* "GET", "POST", "PATCH", "PUT" or "DELETE", case-insensitive. NULL infers
   * POST when a body is present and GET when it is not. */
  const char* method;

  /* Request body. Read verbatim; the library does not validate or reformat it.
   * Passing NULL with a method that needs a body is a usage error. */
  const char* body;

  /* Defaults to application/json. Ignored if extra_headers names Content-Type. */
  const char* content_type;

  /* NULL-terminated array of "Name: value" strings. A caller-supplied
   * Authorization header replaces this client's token rather than being sent
   * alongside it. */
  const char* const* extra_headers;
} sfcc_rest_options;

typedef struct {
  long   status;      /* HTTP status, or 0 if the transfer never completed     */
  /*
   * Byte count of the body. The body is *not* a C string: a VersionData fetch
   * or a CSV export contains embedded NULs, and strlen() on it silently
   * truncates at the first one. This field is authoritative.
   */
  size_t body_len;
  char*  body;        /* response body; NULL when there was none               */
  char*  headers;     /* raw response head, for status and rate-limit info     */
} sfcc_rest_result;

/*
 * Perform one request against `path`.
 *
 * The path may be:
 *
 *   "/services/data/v64.0/limits"   absolute -- used as-is on the instance
 *   "sobjects/Account"               relative to /services/data/<version>/
 *
 * and the literal token "{version}" is replaced with the configured API
 * version anywhere in it, so a script need not hardcode the number.
 *
 * The path is *not* percent-encoded. That is deliberate and matches curl: the
 * caller owns the encoding, and silently re-encoding would corrupt the query
 * strings that make SOQL and composite calls work. A path containing a raw
 * space is reported as a usage error rather than sent, because the failure
 * mode otherwise is an opaque 400.
 *
 * Returns SFCC_OK for any completed exchange, including a 404: the request
 * succeeded and the server's answer is the interesting part. Check
 * result->status. Transport failures and usage errors return non-OK with no
 * result.
 */
sfcc_status sfcc_rest(sfcc_client* c, const char* path,
                      const sfcc_rest_options* opts, sfcc_rest_result* out);

void sfcc_rest_result_free(sfcc_rest_result* r);

/* --------------------------------------------------------------------- */

/* Library version, e.g. "1.0.0". */
const char* sfcc_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SFCC_H */