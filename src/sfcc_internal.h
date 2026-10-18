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
 * the cache. */
sfcc_status sfcc_auth_fetch_token(sfcc_client* c);

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
