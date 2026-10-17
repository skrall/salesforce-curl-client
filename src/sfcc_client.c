/*
 * Client lifecycle and the sObject API surface.
 *
 * Every API call funnels through sfcc_api_call(), which owns the three things
 * that are easy to get subtly wrong when spread across individual functions:
 *
 *   1. ensuring a token exists,
 *   2. building a correctly versioned URL,
 *   3. deciding what counts as success, including the one retry that a stale
 *      cached token warrants.
 *
 * The one piece of Salesforce-specific knowledge encoded here is that record
 * Ids are strings. They are 15 or 18 characters of base-62 and an 18-character
 * Id does not survive a round trip through a double, so Ids never pass through
 * a numeric type anywhere in this client.
 */
#include "sfcc_internal.h"

#include <curl/curl.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SFCC_VERSION_STR "1.0.0"

/* How long to wait for a whole transfer, and for the connection phase. */
#define SFCC_TIMEOUT_DEFAULT 60L
#define SFCC_CONNECT_TIMEOUT_DEFAULT 15L

const char* sfcc_version(void){
  return SFCC_VERSION_STR;
}

/* ------------------------------------------------------------------------ */
/* Errors                                                                   */
/* ------------------------------------------------------------------------ */

sfcc_status sfcc_fail(sfcc_client* c, sfcc_status rc, const char* fmt, ...){
  if(c != NULL){
    char* msg = NULL;
    va_list va;
    va_start(va, fmt);
    int need = vsnprintf(NULL, 0, fmt, va);
    va_end(va);
    if(need >= 0){
      msg = malloc((size_t)need + 1);
      if(msg != NULL){
        va_start(va, fmt);
        vsnprintf(msg, (size_t)need + 1, fmt, va);
        va_end(va);
        /* Keep only the most recent failure. Chaining them would grow without
         * bound across a retry and bury the reason that actually mattered. */
        sfcc_strset(&c->last_error, msg);
        free(msg);
      }
    }
  }
  return rc;
}

const char* sfcc_last_error(const sfcc_client* c){
  return (c != NULL) ? c->last_error : NULL;
}

long sfcc_last_status(const sfcc_client* c){
  return (c != NULL) ? c->last_status : 0;
}

const char* sfcc_strerror(sfcc_status rc){
  switch(rc){
    case SFCC_OK:       return "success";
    case SFCC_ERR_ARG:  return "invalid argument";
    case SFCC_ERR_MEM:  return "out of memory";
    case SFCC_ERR_NET:  return "network error";
    case SFCC_ERR_HTTP: return "the server returned an error";
    case SFCC_ERR_AUTH: return "authentication failed";
    case SFCC_ERR_JSON: return "the response was not the expected JSON";
    case SFCC_ERR_IO:   return "local file error";
    default:            return "unknown error";
  }
}

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

void sfcc_config_defaults(sfcc_config* cfg){
  if(cfg == NULL){
    return;
  }
  memset(cfg, 0, sizeof(*cfg));
  cfg->login_url = "https://login.salesforce.com";
  cfg->api_version = SFCC_DEFAULT_API_VERSION;
  cfg->timeout_s = SFCC_TIMEOUT_DEFAULT;
  cfg->connect_timeout_s = SFCC_CONNECT_TIMEOUT_DEFAULT;
  cfg->no_cache = 0;
  cfg->insecure = 0;
}

/* Environment variables are only consulted when set, so an explicit override
 * applied either side of this call wins. */
void sfcc_config_apply_env(sfcc_config* cfg){
  if(cfg == NULL){
    return;
  }
  static const struct { const char* var; size_t off; } MAP[] = {
    { "SFCC_LOGIN_URL",      offsetof(sfcc_config, login_url) },
    { "SFCC_CLIENT_ID",      offsetof(sfcc_config, client_id) },
    { "SFCC_CLIENT_SECRET",  offsetof(sfcc_config, client_secret) },
    { "SFCC_INSTANCE_URL",   offsetof(sfcc_config, instance_url) },
    { "SFCC_ACCESS_TOKEN",   offsetof(sfcc_config, access_token) },
    { "SFCC_API_VERSION",    offsetof(sfcc_config, api_version) },
    { "SFCC_TOKEN_CACHE",    offsetof(sfcc_config, cache_path) },
  };
  for(size_t i = 0 ; i < sizeof(MAP) / sizeof(MAP[0]) ; ++i){
    const char* v = getenv(MAP[i].var);
    if(v != NULL && *v){
      /* The map stores an offset into sfcc_config; assigning through it keeps
       * this table declarative instead of a dozen near-identical ifs. */
      *(const char**)((char*)cfg + MAP[i].off) = v;
    }
  }
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

sfcc_client* sfcc_client_new(const sfcc_config* cfg){
  if(sfcc_http_global_init() != SFCC_OK){
    return NULL;
  }
  sfcc_client* c = calloc(1, sizeof(*c));
  if(c == NULL){
    return NULL;
  }

  /* Defaults first, so an entirely zeroed config is still usable. A caller
   * that passes NULL gets a client that is merely unconfigured. */
  sfcc_config d;
  sfcc_config_defaults(&d);
  if(cfg != NULL){
    d = *cfg;
  }

  sfcc_strset(&c->login_url, d.login_url ? d.login_url
                                         : "https://login.salesforce.com");
  sfcc_strset(&c->client_id, d.client_id);
  sfcc_strset(&c->client_secret, d.client_secret);
  sfcc_strset(&c->api_version, d.api_version ? d.api_version
                                             : SFCC_DEFAULT_API_VERSION);
  sfcc_strip_trailing_slashes(c->login_url);

  if(d.cache_path != NULL){
    sfcc_strset(&c->cache_path, d.cache_path);
  }else{
    const char* dflt = sfcc_default_cache_path();
    sfcc_strset(&c->cache_path, dflt);
  }
  c->no_cache = d.no_cache;
  c->insecure = d.insecure;
  c->timeout_s = d.timeout_s > 0 ? d.timeout_s : SFCC_TIMEOUT_DEFAULT;
  c->connect_timeout_s = d.connect_timeout_s > 0
                       ? d.connect_timeout_s : SFCC_CONNECT_TIMEOUT_DEFAULT;

  /*
   * A caller-supplied instance URL is authoritative: it identifies a specific
   * org, and it comes with a token minted for exactly that org. Mixing in a
   * cached token from a different instance would produce confusing 401s, so
   * when both are supplied the cache is bypassed entirely.
   */
  if(d.instance_url != NULL && d.access_token != NULL){
    sfcc_strset(&c->instance_url, d.instance_url);
    sfcc_strip_trailing_slashes(c->instance_url);
    sfcc_strset(&c->access_token, d.access_token);
    c->token_expiry = 0;   /* not ours to expire */
  }

  if(c->login_url == NULL || c->api_version == NULL){
    sfcc_client_free(c);
    return NULL;
  }
  return c;
}

void sfcc_client_free(sfcc_client* c){
  if(c == NULL){
    return;
  }
  if(c->curl != NULL){
    curl_easy_cleanup((CURL*)c->curl);
  }
  sfcc_strfree(&c->login_url);
  sfcc_strfree(&c->client_id);
  sfcc_strfree(&c->client_secret);
  sfcc_strfree(&c->instance_url);
  sfcc_strfree(&c->access_token);
  sfcc_strfree(&c->api_version);
  sfcc_strfree(&c->cache_path);
  sfcc_strfree(&c->identity_url);
  sfcc_strfree(&c->last_error);
  free(c);
}

/* ------------------------------------------------------------------------ */
/* Validation                                                               */
/* ------------------------------------------------------------------------ */

sfcc_status sfcc_check_sobject(sfcc_client* c, const char* sobject){
  if(sobject == NULL || !*sobject){
    return sfcc_fail(c, SFCC_ERR_ARG, "sObject name is required");
  }
  for(const char* p = sobject ; *p ; ++p){
    /* The API names are alphanumeric with underscores. Rejecting anything else
     * here means a bad name cannot become a path traversal, and catches typos
     * before a confusing 404. */
    const char ch = *p;
    const int ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                   (ch >= '0' && ch <= '9') || ch == '_';
    if(!ok){
      return sfcc_fail(c, SFCC_ERR_ARG,
                       "invalid sObject name \"%s\": only letters, digits and "
                       "underscore are allowed", sobject);
    }
  }
  return SFCC_OK;
}

sfcc_status sfcc_check_id(sfcc_client* c, const char* id){
  if(id == NULL || !*id){
    return sfcc_fail(c, SFCC_ERR_ARG, "record id is required");
  }
  const size_t n = strlen(id);
  if(n != 15 && n != 18){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "record id \"%s\" is %zu characters; Salesforce ids are "
                     "15 or 18", id, n);
  }
  /* 18-character ids end in a 3-character case-sensitivity checksum; they are
   * not necessarily upper case (a lower-case 'a' is legal), so case is not
   * validated here. Only the base-62 alphabet is. */
  for(size_t i = 0 ; i < n ; ++i){
    const char ch = id[i];
    const int ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                   (ch >= '0' && ch <= '9');
    if(!ok){
      return sfcc_fail(c, SFCC_ERR_ARG,
                       "invalid record id \"%s\": not base-62", id);
    }
  }
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* URLs                                                                     */
/* ------------------------------------------------------------------------ */

sfcc_status sfcc_api_url(sfcc_client* c, const char* path, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  sfcc_buf b;
  sfcc_buf_init(&b);
  sfcc_buf_puts(&b, c->instance_url);
  sfcc_buf_puts(&b, "/services/data/");
  sfcc_buf_puts(&b, c->api_version);
  if(path != NULL){
    sfcc_buf_puts(&b, "/");
    sfcc_buf_puts(&b, path);
  }
  if(b.data == NULL){
    sfcc_buf_free(&b);
    return sfcc_fail(c, SFCC_ERR_MEM, "could not build the request URL");
  }
  *out = b.data;
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* Authentication gate                                                      */
/* ------------------------------------------------------------------------ */

sfcc_status sfcc_ensure_auth(sfcc_client* c){
  if(c == NULL){
    return SFCC_ERR_ARG;
  }
  sfcc_strfree(&c->last_error);
  if(c->instance_url != NULL && c->access_token != NULL){
    return SFCC_OK;          /* caller-supplied; nothing to do */
  }
  if(sfcc_token_is_fresh(c)){
    return SFCC_OK;
  }
  (void)sfcc_auth_load_cache(c);
  if(sfcc_token_is_fresh(c)){
    return SFCC_OK;
  }
  return sfcc_auth_fetch_token(c);
}

sfcc_status sfcc_authenticate(sfcc_client* c, char** instance_url){
  if(c == NULL){
    return SFCC_ERR_ARG;
  }
  sfcc_status rc = sfcc_ensure_auth(c);
  if(rc != SFCC_OK){
    return rc;
  }
  if(instance_url != NULL){
    char* copy = sfcc_strdup(c->instance_url);
    if(copy == NULL){
      return SFCC_ERR_MEM;
    }
    *instance_url = copy;
  }
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* The single request path                                                  */
/* ------------------------------------------------------------------------ */

/* Salesforce's own code for a dead session. Used to decide whether a failure
 * is worth retrying once with a fresh token. */
static int is_invalid_session(long status, const char* body){
  return status == 401 ||
         (body != NULL && strstr(body, "INVALID_SESSION_ID") != NULL) ||
         (body != NULL && strstr(body, "SESSION expired") != NULL);
}

/*
 * May this client replace a rejected token by authenticating again?
 *
 * Only when it holds the means to do so. The retry exists for a token *we*
 * obtained and cached, which can go stale at any time. A token the caller
 * supplied with --token is none of our business: we cannot re-mint it, so
 * discarding it and attempting a new grant would replace a precise "this token
 * was rejected" with a vague "no credentials" and send the caller looking in
 * the wrong place entirely.
 */
static int can_reauthenticate(const sfcc_client* c){
  return (c->client_id != NULL && c->client_secret != NULL);
}

static sfcc_status api_call(sfcc_client* c, sfcc_method method,
                            const char* path, const char* json_body,
                            char** out){
  sfcc_status rc = sfcc_ensure_auth(c);
  if(rc != SFCC_OK){
    return rc;
  }

  char* url = NULL;
  rc = sfcc_api_url(c, path, &url);
  if(rc != SFCC_OK){
    return rc;
  }

  sfcc_response resp;
  /*
   * One retry, and only for an invalid session. The cached token can be
   * revoked server-side at any moment, so a 401 here is not evidence that the
   * call was wrong; it is evidence that our token went stale. Dropping it and
   * re-minting once turns a class of "it works if I delete my cache file"
   * failures into a transparent recovery. A second failure is real and is
   * reported as such.
   */
  for(int attempt = 0 ; attempt < 2 ; ++attempt){
    rc = sfcc_http_request(c, method, url, c->access_token, json_body, NULL,
                           &resp);
    if(rc != SFCC_OK){
      free(url);
      return rc;
    }
    c->last_status = resp.status;
    if(resp.status >= 200 && resp.status < 300){
      free(url);
      return sfcc_finish(c, &resp, out);
    }
    if(attempt == 0 && is_invalid_session(resp.status, resp.body.data) &&
       can_reauthenticate(c)){
      sfcc_response_free(&resp);
      /* Invalidate locally and force a fresh token, whatever the cache says.
       * The identity URL belongs to the old token, so it goes too. */
      sfcc_strfree(&c->access_token);
      sfcc_strfree(&c->instance_url);
      sfcc_strfree(&c->identity_url);
      c->token_expiry = 0;
      if(!c->no_cache && c->cache_path != NULL){
        remove(c->cache_path);
      }
      rc = sfcc_auth_fetch_token(c);
      if(rc != SFCC_OK){
        free(url);
        return rc;
      }
      /* The token belongs to whichever org it says it does; the URL has to
       * follow it. */
      free(url);
      url = NULL;
      rc = sfcc_api_url(c, path, &url);
      if(rc != SFCC_OK){
        return rc;
      }
      continue;
    }
    break;
  }

  char detail[SFCC_ERRLEN_MAX];
  sfcc_json_describe_error(resp.body.data, resp.status, detail,
                           sizeof(detail));
  const long st = resp.status;
  /* Keep the body before the response is freed: the hint below needs it, and
   * describe_error already sanitised it. */
  char has_body[256] = "";
  if(resp.body.data != NULL && resp.body.len){
    snprintf(has_body, sizeof(has_body), "%.240s", resp.body.data);
  }
  sfcc_response_free(&resp);
  free(url);

  if(st == 401){
    /*
     * The most common cause by a wide margin is not an expired token but the
     * wrong kind of token. A Salesforce *session* id -- what Setup > Session
     * Settings > View Session shows, and what the sid cookie holds -- is not a
     * REST bearer token and is always rejected here. It is worth naming,
     * because the resulting error from Salesforce is unhelpfully terse and the
     * two things look similar at a glance.
     */
    return sfcc_fail(c, SFCC_ERR_AUTH,
                     "%s\n"
                     "       If this came from Setup > Session Settings > View "
                     "Session, or from the sid cookie,\n"
                     "       it is a session id, not a REST access token, and "
                     "the REST API will always reject it.\n"
                     "       Mint one with: sfcc auth   (needs "
                     "SFCC_CLIENT_ID and SFCC_CLIENT_SECRET)", detail);
  }
  if(st == 403){
    return sfcc_fail(c, SFCC_ERR_AUTH,
                     "%s\n"
                     "       The token was accepted but lacks permission for "
                     "this operation. Check the integration\n"
                     "       user's profile and object permissions.",
                     detail);
  }
  (void)has_body;
  return sfcc_fail(c, SFCC_ERR_HTTP, "%s", detail);
}

sfcc_status sfcc_finish(sfcc_client* c, sfcc_response* resp, char** out){
  if(c == NULL || resp == NULL || out == NULL){
    sfcc_response_free(resp);
    return SFCC_ERR_ARG;
  }
  /* A 204 has no body by definition, so success with no output is normal for
   * delete. Anything else should be JSON; if it is not, say so rather than
   * handing the caller text it will fail to parse. */
  if(resp->body.len == 0){
    if(resp->status == 204 || resp->status == 205){
      *out = NULL;
      sfcc_response_free(resp);
      return SFCC_OK;
    }
    sfcc_response_free(resp);
    return sfcc_fail(c, SFCC_ERR_JSON,
                     "expected a response body, got HTTP %ld with nothing",
                     resp->status);
  }
  if(!sfcc_json_valid(resp->body.data)){
    char excerpt[256];
    snprintf(excerpt, sizeof(excerpt), "%.240s",
             resp->body.data ? resp->body.data : "");
    sfcc_response_free(resp);
    return sfcc_fail(c, SFCC_ERR_JSON,
                     "response was not JSON (starts: %s). A proxy or captive "
                     "portal may be intercepting the request.", excerpt);
  }
  *out = resp->body.data;
  resp->body.data = NULL;   /* ownership transferred to the caller */
  resp->body.len = 0;
  resp->body.cap = 0;
  sfcc_response_free(resp);
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* Operations                                                               */
/* ------------------------------------------------------------------------ */

sfcc_status sfcc_query(sfcc_client* c, const char* soql, char** out){
  if(c == NULL || soql == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  /*
   * SOQL is percent-encoded as a whole. This is not optional: a query almost
   * always contains spaces, and a query with an apostrophe in a string
   * literal ('O''Brien') or a '+' in a filter will silently change meaning
   * if left unencoded. Salesforce's REST query endpoint takes the statement
   * as a single 'q' parameter value.
   */
  sfcc_buf path;
  sfcc_buf_init(&path);
  sfcc_buf_puts(&path, "query?q=");
  if(sfcc_buf_append_encoded(&path, soql)){
    sfcc_buf_free(&path);
    return sfcc_fail(c, SFCC_ERR_MEM, "could not encode the SOQL statement");
  }
  sfcc_status rc = api_call(c, SFCC_HTTP_GET, path.data, NULL, out);
  sfcc_buf_free(&path);
  return rc;
}

sfcc_status sfcc_get_record(sfcc_client* c, const char* sobject,
                            const char* id, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  sfcc_status rc = sfcc_check_sobject(c, sobject);
  if(rc != SFCC_OK){
    return rc;
  }
  rc = sfcc_check_id(c, id);
  if(rc != SFCC_OK){
    return rc;
  }
  sfcc_buf path;
  sfcc_buf_init(&path);
  sfcc_buf_printf(&path, "sobjects/%s/%s", sobject, id);
  rc = api_call(c, SFCC_HTTP_GET, path.data, NULL, out);
  sfcc_buf_free(&path);
  return rc;
}

static sfcc_status check_json_body(sfcc_client* c, const char* body){
  if(body == NULL || !*body){
    return sfcc_fail(c, SFCC_ERR_ARG, "a JSON object body is required");
  }
  if(!sfcc_json_valid(body)){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "the request body is not valid JSON");
  }
  return SFCC_OK;
}

sfcc_status sfcc_create(sfcc_client* c, const char* sobject,
                        const char* json_body, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  sfcc_status rc = sfcc_check_sobject(c, sobject);
  if(rc != SFCC_OK){
    return rc;
  }
  rc = check_json_body(c, json_body);
  if(rc != SFCC_OK){
    return rc;
  }
  sfcc_buf path;
  sfcc_buf_init(&path);
  sfcc_buf_printf(&path, "sobjects/%s", sobject);
  rc = api_call(c, SFCC_HTTP_POST, path.data, json_body, out);
  sfcc_buf_free(&path);
  return rc;
}

sfcc_status sfcc_update(sfcc_client* c, const char* sobject,
                        const char* id, const char* json_body, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  sfcc_status rc = sfcc_check_sobject(c, sobject);
  if(rc != SFCC_OK){
    return rc;
  }
  rc = sfcc_check_id(c, id);
  if(rc != SFCC_OK){
    return rc;
  }
  rc = check_json_body(c, json_body);
  if(rc != SFCC_OK){
    return rc;
  }
  sfcc_buf path;
  sfcc_buf_init(&path);
  sfcc_buf_printf(&path, "sobjects/%s/%s", sobject, id);
  rc = api_call(c, SFCC_HTTP_PATCH, path.data, json_body, out);
  sfcc_buf_free(&path);
  return rc;
}

sfcc_status sfcc_delete(sfcc_client* c, const char* sobject,
                        const char* id){
  if(c == NULL){
    return SFCC_ERR_ARG;
  }
  sfcc_status rc = sfcc_check_sobject(c, sobject);
  if(rc != SFCC_OK){
    return rc;
  }
  rc = sfcc_check_id(c, id);
  if(rc != SFCC_OK){
    return rc;
  }
  sfcc_buf path;
  sfcc_buf_init(&path);
  sfcc_buf_printf(&path, "sobjects/%s/%s", sobject, id);
  char* out = NULL;
  rc = api_call(c, SFCC_HTTP_DELETE, path.data, NULL, &out);
  sfcc_buf_free(&path);
  sfcc_strfree(&out);
  return rc;
}

sfcc_status sfcc_whoami(sfcc_client* c, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  sfcc_status rc = sfcc_ensure_auth(c);
  if(rc != SFCC_OK){
    return sfcc_fail(c, rc, "%s", sfcc_last_error(c) ? sfcc_last_error(c)
                                                     : sfcc_strerror(rc));
  }
  if(c->identity_url == NULL){
    /*
     * Only reached when the caller supplied instance+token directly, so no
     * token response was ever seen and there is no identity URL to ask. Saying
     * so is better than failing later with an opaque 404.
     */
    return sfcc_fail(c, SFCC_ERR_AUTH,
                     "whoami needs the identity URL from a token response, "
                     "which a caller-supplied token does not provide; drop "
                     "--token and let the client authenticate");
  }
  /* The identity endpoint is absolute and version-independent, so it cannot go
   * through api_call()'s versioned URL builder. */
  sfcc_response resp;
  rc = sfcc_http_request(c, SFCC_HTTP_GET, c->identity_url, c->access_token,
                         NULL, NULL, &resp);
  if(rc != SFCC_OK){
    return rc;
  }
  c->last_status = resp.status;
  if(resp.status < 200 || resp.status >= 300){
    char detail[SFCC_ERRLEN_MAX];
    sfcc_json_describe_error(resp.body.data, resp.status, detail,
                             sizeof(detail));
    const long st = resp.status;
    sfcc_response_free(&resp);
    if(st == 401){
      return sfcc_fail(c, SFCC_ERR_AUTH,
                       "%s\n"
                       "       The access token was rejected. If it came from "
                       "Setup > Session Settings > View Session it is a\n"
                       "       session id, not a REST access token.", detail);
    }
    return sfcc_fail(c, (st == 403) ? SFCC_ERR_AUTH : SFCC_ERR_HTTP, "%s",
                     detail);
  }
  return sfcc_finish(c, &resp, out);
}

sfcc_status sfcc_describe(sfcc_client* c, const char* sobject, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  sfcc_status rc = sfcc_check_sobject(c, sobject);
  if(rc != SFCC_OK){
    return rc;
  }
  sfcc_buf path;
  sfcc_buf_init(&path);
  sfcc_buf_printf(&path, "sobjects/%s/describe", sobject);
  rc = api_call(c, SFCC_HTTP_GET, path.data, NULL, out);
  sfcc_buf_free(&path);
  return rc;
}

sfcc_status sfcc_list_sobjects(sfcc_client* c, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  /* The bare collection, not one object's describe. Salesforce answers with a
   * single document holding every object the org can see, which is why this
   * cannot be expressed as a repeated per-object call. */
  return api_call(c, SFCC_HTTP_GET, "sobjects", NULL, out);
}

sfcc_status sfcc_list_versions(sfcc_client* c, char** out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  *out = NULL;
  /* Not under /services/data/<version>/, but it does live under /services/.
   * Built by hand rather than through sfcc_api_url, which would stamp a
   * version onto it. */
  sfcc_status rc = sfcc_ensure_auth(c);
  if(rc != SFCC_OK){
    /* Preserve whatever sfcc_ensure_auth recorded; its reason is far more
     * useful than a generic "authentication failed". */
    return sfcc_fail(c, rc, "%s", sfcc_last_error(c) ? sfcc_last_error(c)
                                                     : sfcc_strerror(rc));
  }
  sfcc_buf url;
  sfcc_buf_init(&url);
  sfcc_buf_puts(&url, c->instance_url);
  sfcc_buf_puts(&url, "/services/data/");
  sfcc_response resp;
  rc = sfcc_http_request(c, SFCC_HTTP_GET, url.data,
                         c->access_token, NULL, NULL, &resp);
  sfcc_buf_free(&url);
  if(rc != SFCC_OK){
    return rc;
  }
  c->last_status = resp.status;
  if(resp.status < 200 || resp.status >= 300){
    char detail[SFCC_ERRLEN_MAX];
    sfcc_json_describe_error(resp.body.data, resp.status, detail,
                             sizeof(detail));
    const long st = resp.status;
    sfcc_response_free(&resp);
    if(st == 401){
      return sfcc_fail(c, SFCC_ERR_AUTH,
                       "%s\n"
                       "       The access token was rejected. If it came from "
                       "Setup > Session Settings > View Session it is a\n"
                       "       session id, not a REST access token.", detail);
    }
    return sfcc_fail(c, (st == 403) ? SFCC_ERR_AUTH : SFCC_ERR_HTTP, "%s",
                     detail);
  }
  return sfcc_finish(c, &resp, out);
}
