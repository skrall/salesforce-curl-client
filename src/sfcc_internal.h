/*
 * Internal declarations shared by the sfcc translation units. Nothing here is
 * part of the public API; include/sfcc.h is the contract.
 *
 * Layout note: this is a single flat library rather than a shared object, so
 * symbols that are not part of the public API are still externally visible by
 * default. Every internal symbol is therefore prefixed sfcc_ and any that are
 * not static are declared here, which keeps them out of the installed header
 * and gives a single place to check for collisions.
 */
#ifndef SFCC_INTERNAL_H
#define SFCC_INTERNAL_H

#include "sfcc.h"

/* The JSON accessors below take and return cJSON nodes, so anything including
 * this header needs the type whether or not it reads JSON itself. */
#include "cJSON.h"

#include <stddef.h>
#include <time.h>

#ifndef SFCC_DEFAULT_API_VERSION
#define SFCC_DEFAULT_API_VERSION "v64.0"
#endif

/* Marks a variadic wrapper as printf-like. gcc and clang then check the format
 * string and arguments at every call site, which is the whole reason to bother:
 * sfcc_buf_printf() and sfcc_fail() take format strings from all over the
 * library, and nothing else verifies them.
 *
 * It also clears -Wformat-nonliteral, which is what an unannotated wrapper
 * trips on when it forwards to vsnprintf(). That warning exists to catch exactly
 * the case we are annotating, so satisfying it this way is the point rather
 * than a way around it. MSVC has no equivalent and does not need one.
 *
 * Indices are 1-based and count the named parameters, so a wrapper taking
 * (ctx, fmt, ...) is format(printf, 2, 3). */
#if defined(__GNUC__) || defined(__clang__)
#  define SFCC_PRINTF_LIKE(fmt_idx, arg_idx) \
    __attribute__((format(printf, fmt_idx, arg_idx)))
#else
#  define SFCC_PRINTF_LIKE(fmt_idx, arg_idx)
#endif

/* Longest request body or error string we will accept from the server. A
 * Salesforce response is never near this; the cap exists so a runaway or
 * hostile endpoint cannot make us allocate without bound. */
#define SFCC_MAX_BODY (32u * 1024u * 1024u)

/* How much detail to keep for an error message before truncating. */
#define SFCC_ERRLEN_MAX 2048

/* ------------------------------------------------------------------------ */
/* Growable byte buffer                                                      */
/* ------------------------------------------------------------------------ */

typedef struct {
  char*  data;
  size_t len;
  size_t cap;
} sfcc_buf;

void  sfcc_buf_init(sfcc_buf* b);
int   sfcc_buf_reserve(sfcc_buf* b, size_t extra);
int   sfcc_buf_append(sfcc_buf* b, const char* data, size_t n);
int   sfcc_buf_puts(sfcc_buf* b, const char* s);
int   sfcc_buf_printf(sfcc_buf* b, const char* fmt, ...) SFCC_PRINTF_LIKE(2, 3);
/* Appends src with every byte outside the RFC 3986 unreserved set percent
 * encoded. SOQL in particular contains spaces, quotes and '+', all of which
 * will corrupt a query if they reach the URL verbatim. */
int   sfcc_buf_append_encoded(sfcc_buf* b, const char* src);
/* XML entity escaping, for the SOAP envelope. */
int   sfcc_buf_append_xml(sfcc_buf* b, const char* src);
void  sfcc_buf_free(sfcc_buf* b);

/* ------------------------------------------------------------------------ */
/* One-line progress feedback for an asynchronous operation.
 *
 * Both metadata deploy and retrieve are long-running polls, and a single
 * "this can take minutes" line is no use to someone deciding whether the process
 * has hung. This reports the elapsed time and the remaining budget, rewriting one
 * line in place on a terminal and writing throttled lines otherwise.
 *
 * Nothing here is thread-safe and nothing needs to be: the caller is the single
 * polling loop.
 */
typedef struct {
  int  tty;        /* stderr is a terminal: rewrite in place rather than append */
  int  width;      /* columns the previous line occupied, to erase it        */
  long last_emit;  /* elapsed seconds when the last line was written        */
} sfcc_progress;

void sfcc_progress_init(sfcc_progress* p);
void sfcc_progress_report(sfcc_progress* p, const char* op, const char* id,
                          const char* status, long elapsed_s, long budget_s,
                          long interval_s);
void sfcc_progress_finish(sfcc_progress* p);

/* ------------------------------------------------------------------------ */
/* Encrypted token-cache frame                                               */
/* ------------------------------------------------------------------------ */

/*
 * When SFCC_CACHE_PASSPHRASE is set, the cache file is written as an
 * SFCCENC1 frame instead of JSON: AES-256-GCM over the record, with the key
 * from PBKDF2-HMAC-SHA256. See src/sfcc_cache_crypto.c for the byte layout
 * and the reasoning about which threat this answers; sfcc_auth.c decides
 * when to wrap and what an unwrap failure means for the run.
 *
 * Every failure leaves the *out buffer empty and allocated-free -- never
 * with a partial frame in it -- so a caller can treat both functions as
 * all-or-nothing.
 */
#define SFCC_CACHE_MAGIC "SFCCENC1"
#define SFCC_CACHE_MAGIC_LEN 8
#define SFCC_CACHE_FORMAT_VERSION 1
#define SFCC_CACHE_SALT_LEN 16
#define SFCC_CACHE_NONCE_LEN 12
#define SFCC_CACHE_TAG_LEN 16
#define SFCC_CACHE_KEY_LEN 32          /* AES-256                            */

/* The KDF is where passphrase strength is bought, so the default tracks
 * published guidance rather than a round number. It can be lowered per
 * machine with SFCC_CACHE_KDF_ITERS -- the file records the count that
 * produced it, so a lowered one is visible, not secret. Both writers and
 * readers bound the value; a reader refuses a header outside this range
 * outright, which turns the field from a compute-scale attack into plain
 * corruption. */
#define SFCC_CACHE_KDF_DEFAULT 600000UL
#define SFCC_CACHE_KDF_MINIMUM 1000UL
#define SFCC_CACHE_KDF_MAXIMUM 100000000UL

typedef enum {
  SFCC_CACHE_OK = 0,
  SFCC_CACHE_ERR_ARG = -1,             /* caller bug                      */
  SFCC_CACHE_ERR_CRYPTO_UNAVAILABLE = -2,  /* built without a backend     */
  SFCC_CACHE_ERR_NO_PASSPHRASE = -3,   /* set SFCC_CACHE_PASSPHRASE       */
  SFCC_CACHE_ERR_OUT_OF_MEMORY = -4,
  SFCC_CACHE_ERR_KDF_RANGE = -5,       /* clamp before calling            */
  SFCC_CACHE_ERR_NOT_OURS = -6,        /* no SFCCENC1 magic               */
  SFCC_CACHE_ERR_BAD_HEADER = -7,      /* ours, but corrupted or newer    */
  SFCC_CACHE_ERR_KEY_MISMATCH = -8,    /* tag check failed                */
  SFCC_CACHE_ERR_BACKEND = -9,         /* a primitive failed; see stderr  */
} sfcc_cache_rc;

const char* sfcc_cache_passphrase(void);
int sfcc_cache_crypto_available(void);

/* Wrap `pt_len` bytes into an SFCCENC1 frame appended to `out`, or fail with
 * one of the codes above. `iters` must already be inside
 * [SFCC_CACHE_KDF_MINIMUM, SFCC_CACHE_KDF_MAXIMUM]. */
int sfcc_cache_wrap(const char* passphrase, const unsigned char* plaintext,
                    size_t pt_len, unsigned long iters, sfcc_buf* out);

/* Reverse. Header rejects are distinct from decrypt rejects: they are
 * decided before the KDF runs and cost microseconds, where a KEY_MISMATCH
 * has paid the full derivation first. */
int sfcc_cache_unwrap(const char* passphrase, const unsigned char* frame,
                      size_t frame_len, sfcc_buf* out);

/* Zero memory that held key material or the plaintext, before it is freed. */
void sfcc_cache_zero(void* p, size_t n);

/* Strings and paths                                                        */
/* ------------------------------------------------------------------------ */

char* sfcc_strdup(const char* s);          /* NULL in, NULL out              */

/* Case-insensitive comparison over at most n bytes, for header names.
 *
 * POSIX calls this strncasecmp and declares it in <strings.h>. Windows has
 * neither the header nor, despite _CRT_DECLARE_NONSTDC_NAMES, the POSIX
 * spelling in <string.h>: the call compiles to an implicit extern declaration
 * and MSVC reports C4013. _strnicmp is its documented equivalent. Wrapping it
 * is the difference between a build and not. */
int sfcc_strncasecmp(const char* a, const char* b, size_t n);
void  sfcc_strfree(char** s);              /* NULL-safe free + null out       */
void  sfcc_strset(char** slot, const char* value);
int   sfcc_str_eq(const char* a, const char* b);
/* Trims trailing slashes in place. */
void  sfcc_strip_trailing_slashes(char* s);

/* The user's home directory: $HOME, %USERPROFILE%, then HOMEDRIVE+HOMEPATH. */
const char* sfcc_home_dir(void);
/* Default token-cache location: <home>/.sfcc-token.json, or NULL if the home
 * directory cannot be determined. */
const char* sfcc_default_cache_path(void);

/* Whether a readable file exists at `path`. */
int sfcc_file_readable(const char* path);

/* ------------------------------------------------------------------------ */
/* HTTP                                                                     */
/* ------------------------------------------------------------------------ */

typedef enum {
  SFCC_HTTP_GET,
  SFCC_HTTP_POST,
  SFCC_HTTP_PATCH,
  SFCC_HTTP_PUT,
  SFCC_HTTP_DELETE,
} sfcc_method;

typedef struct {
  long        status;      /* HTTP status, or 0 if the transfer failed       */
  sfcc_buf    body;
  sfcc_buf    headers;     /* raw response head, for `rest`'s --include     */
  sfcc_method method;
} sfcc_response;

/*
 * Perform one request. auth_token may be NULL for the unauthenticated token
 * endpoint. body may be NULL, in which case no Content-Type is sent.
 * content_type may be NULL, which means application/json -- the right answer
 * for every sObject call, but not for the OAuth token endpoint, which is form
 * encoded. Passing it explicitly is why this is a parameter and not a constant.
 * On SFCC_ERR_NET or SFCC_ERR_MEM the response is left zeroed; on an HTTP
 * error the body is still populated, since that is where Salesforce puts the
 * reason.
 */
sfcc_status sfcc_http_request(sfcc_client* c, sfcc_method method,
                              const char* url, const char* auth_token,
                              const char* body, const char* content_type,
                              sfcc_response* resp);

/*
 * As above, plus caller-supplied request headers.
 *
 * extra_headers is a NULL-terminated array of "Name: value" strings, added
 * after the defaults so a caller can override Content-Type. Passing NULL gives
 * exactly sfcc_http_request's behaviour, which is why the plain function exists
 * rather than every caller passing NULL.
 */
sfcc_status sfcc_http_request_ex(sfcc_client* c, sfcc_method method,
                                 const char* url, const char* auth_token,
                                 const char* body, const char* content_type,
                                 const char* const* extra_headers,
                                 sfcc_response* resp);

/*
 * A multipart/form-data POST, for endpoints that take a binary file part
 * (metadata deploy is the only one today). Takes ownership of *mime and sets
 * it to NULL. Declared here with curl_mime only forward-declared, so this
 * header stays free of curl.h.
 */
struct curl_mime;
sfcc_status sfcc_http_request_mime(sfcc_client* c, const char* url,
                                   const char* auth_token, struct curl_mime** mime,
                                   sfcc_response* resp);

void sfcc_response_free(sfcc_response* r);

/* One-time libcurl global initialisation, reference-counted. Safe to call
 * from every entry point; the matching cleanup is atexit-registered once. */
sfcc_status sfcc_http_global_init(void);

/* ------------------------------------------------------------------------ */
/* JSON                                                                     */
/* ------------------------------------------------------------------------ */

/*
 * Turn a Salesforce error response into something worth printing. Understands
 * both shapes the platform uses: a bare array of {message,errorCode} objects
 * from the REST sObject endpoints, and an {error,error_description} object
 * from the OAuth token endpoint. Falls back to a truncated raw body.
 */
void sfcc_json_describe_error(const char* body, long status, char* out,
                              size_t outsz);

/* Validate that a response body parses as JSON. */
int sfcc_json_valid(const char* body);

/* Typed field accessors, shared by every caller that reads a response.
 *
 * Each looks a key up case-sensitively and type-checks what it finds, because
 * Salesforce omits fields freely: a capability flag can arrive as false, be
 * absent entirely, or be null depending on the object and the API version. An
 * accessor that assumed presence would report an absent field as true, which
 * for a capability listing is worse than saying nothing.
 *
 * The returned string points into the cJSON tree and is owned by it; it is
 * valid only while that tree is. */
const char* sfcc_json_str(const cJSON* o, const char* key, const char* dflt);
int sfcc_json_bool(const cJSON* o, const char* key);
int sfcc_json_int(const cJSON* o, const char* key, int fallback);

/* ------------------------------------------------------------------------ */
/* Client internals                                                         */
/* ------------------------------------------------------------------------ */

struct sfcc_client {
  char* login_url;
  char* client_id;
  char* client_secret;
  char* instance_url;
  char* access_token;
  char* api_version;
  char* cache_path;
  /*
   * The token response's "id" field: the URL of the identity that owns this
   * token. It is the only supported way to answer "who am I", because the REST
   * API has no /me endpoint -- there is no self-record filter that can be
   * written without already knowing the id, which is the thing being asked.
   */
  char* identity_url;
  int   no_cache;
  long  timeout_s;
  long  connect_timeout_s;
  int   insecure;

  time_t token_expiry;      /* absolute unix time; 0 when unknown           */
  char*  last_error;
  long   last_status;

  /* CURL* for this client, created on first use and reused. Typed void* so
   * that curl.h stays out of this header, which the rest of the library
   * includes. See sfcc_http.c. */
  void*  curl;
};

/* Record a failure for sfcc_last_error() and return rc, so call sites can
 * `return sfcc_fail(c, rc, fmt, ...)`. */
sfcc_status sfcc_fail(sfcc_client* c, sfcc_status rc, const char* fmt, ...)
  SFCC_PRINTF_LIKE(3, 4);

/* True when a cached token is still usable. Applies a margin so a token that
 * would expire mid-flight is treated as already expired. */
int sfcc_token_is_fresh(const sfcc_client* c);

/* OAuth client-credentials grant, then populate instance_url/access_token and
 * the cache. Returns immediately when the client already holds a token, so
 * callers that mean to replace one must discard it first. */
sfcc_status sfcc_auth_fetch_token(sfcc_client* c);

/* Drop the held token and delete the cache file naming the same one. */
void sfcc_auth_discard_token(sfcc_client* c);

/* Replace a token the server has rejected with a freshly minted one: discard,
 * then grant. Fails with SFCC_ERR_AUTH when the client holds no credentials to
 * mint with, since a caller-supplied token is not ours to renew.
 *
 * Shared by every request path, because every one of them meets a dead session
 * and a dead token is not a reason for one transport to give up and another to
 * carry on. */
sfcc_status sfcc_auth_reauthenticate(sfcc_client* c);

/* Salesforce's own code for a dead session, across REST and SOAP. */
int sfcc_is_invalid_session(long status, const char* body);

/* Load a cached token if one exists and is still fresh. */
sfcc_status sfcc_auth_load_cache(sfcc_client* c);

/* Write the current token to the cache file, best effort. A failure here is
 * never fatal -- the token is simply not persisted. */
void sfcc_auth_save_cache(sfcc_client* c);

/*
 * Build "<instance>/services/data/<version>/<path>".
 *
 * The path is appended verbatim rather than percent-encoded. That is
 * deliberate: the slashes are structural, and the only value that needs
 * encoding in an API path is the SOQL statement, which sfcc_query() encodes
 * itself before it ever gets here. Encoding the whole path would escape those
 * slashes and produce a URL that addresses nothing.
 *
 * Every path segment is validated or escaped by the caller before it reaches
 * this point -- object names by sfcc_check_sobject(), ids by sfcc_check_id(),
 * and query text by sfcc_buf_append_encoded().
 */
sfcc_status sfcc_api_url(sfcc_client* c, const char* path, char** out);

/* Sanity-check an sObject name and an 18/15-character Id before they go near
 * a URL. Returns SFCC_OK or SFCC_ERR_ARG with the reason recorded. */
sfcc_status sfcc_check_sobject(sfcc_client* c, const char* sobject);
sfcc_status sfcc_check_id(sfcc_client* c, const char* id);

/* Authenticate on first use, then dispatch. All API operations funnel here so
 * there is exactly one place that can trigger a token fetch. */
sfcc_status sfcc_ensure_auth(sfcc_client* c);

/* Shared response handling: turns a completed HTTP exchange into a status
 * plus an allocated body for the caller. */
sfcc_status sfcc_finish(sfcc_client* c, sfcc_response* resp, char** out);

#endif /* SFCC_INTERNAL_H */
