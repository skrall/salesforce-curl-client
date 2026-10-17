/*
 * The generic REST passthrough.
 *
 * This is the escape hatch, and its whole value is being thin. Salesforce
 * adds REST resources faster than any client can wrap them, so rather than
 * growing a command per endpoint, this sends one request and hands back the
 * answer. Everything the caller would otherwise retype -- the instance URL, the
 * API version, the bearer token, the TLS policy, the error unpacking -- is
 * applied here.
 *
 * What it deliberately does *not* do:
 *
 *  - Encode the path. SOQL, composite batches and report filters all live in
 *    the query string, and re-encoding a path that already carries a working
 *    query string corrupts it. curl behaves the same way: the caller owns
 *    encoding. A raw space is rejected instead, so the failure is a clear
 *    message rather than an opaque 400 from the org.
 *
 *  - Retry. Every other call in this client funnels through api_call, which
 *    re-authenticates once on an invalid session. That is right for a known
 *    endpoint and wrong here: this is where a caller goes to send something
 *    new, possibly something not idempotent, and silently re-sending it would
 *    be the worst possible default.
 *
 *  - Second-guess the status code. A 404 from an unwrapped endpoint is a
 *    perfectly good answer and often the whole point of asking.
 */
#include "sfcc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */

static int eq_ignore_case(const char* a, const char* b){
  for( ; *a && *b ; ++a, ++b){
    const char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a - 'A' + 'a') : *a;
    const char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b - 'A' + 'a') : *b;
    if(ca != cb){
      return 0;
    }
  }
  return *a == '\0' && *b == '\0';
}

static sfcc_method parse_method(const char* m){
  if(m == NULL || !*m){
    return SFCC_HTTP_GET;
  }
  if(eq_ignore_case(m, "GET"))     return SFCC_HTTP_GET;
  if(eq_ignore_case(m, "POST"))    return SFCC_HTTP_POST;
  if(eq_ignore_case(m, "PATCH"))   return SFCC_HTTP_PATCH;
  if(eq_ignore_case(m, "PUT"))     return SFCC_HTTP_PUT;
  if(eq_ignore_case(m, "DELETE"))  return SFCC_HTTP_DELETE;
  return (sfcc_method)-1;
}

/* ------------------------------------------------------------------------ */
/* URL construction                                                          */
/* ------------------------------------------------------------------------ */

/*
 * Build the absolute URL.
 *
 * Three forms are accepted:
 *   "/services/data/v64.0/limits"  absolute, used as-is
 *   "sobjects/Account"              relative to /services/data/<version>/
 *   anything containing "{version}" has it substituted, so a script does not
 *   hardcode a number that goes out of support.
 */
static sfcc_status build_url(sfcc_client* c, const char* path, char** out){
  sfcc_buf b;
  sfcc_buf_init(&b);

  sfcc_buf_puts(&b, c->instance_url);

  if(*path == '/'){
    sfcc_buf_puts(&b, path);
  }else{
    sfcc_buf_puts(&b, "/services/data/");
    sfcc_buf_puts(&b, c->api_version);
    sfcc_buf_puts(&b, "/");
    sfcc_buf_puts(&b, path);
  }

  /* Substitute the {version} token if it appears, wherever it appears. */
  const char* token;
  while((token = strstr(b.data, "{version}")) != NULL){
    const size_t at = (size_t)(token - b.data);
    const size_t tlen = strlen("{version}");
    sfcc_buf rebuilt;
    sfcc_buf_init(&rebuilt);
    sfcc_buf_append(&rebuilt, b.data, at);
    sfcc_buf_puts(&rebuilt, c->api_version);
    sfcc_buf_append(&rebuilt, token + tlen, b.len - at - tlen);
    sfcc_buf_free(&b);
    b = rebuilt;
  }

  if(b.data == NULL){
    return sfcc_fail(c, SFCC_ERR_MEM, "could not build the request URL");
  }
  *out = b.data;
  return SFCC_OK;
}

/*
 * Reject a path that cannot have been intended.
 *
 * A raw space is the common one -- a SOQL statement pasted in without
 * encoding. The org's reply to that is a 400 that says nothing about the
 * missing %20, so it is caught here instead.
 */
static sfcc_status check_path(sfcc_client* c, const char* path){
  for(const char* p = path ; *p ; ++p){
    const unsigned char ch = (unsigned char)*p;
    if(ch == ' '){
      return sfcc_fail(c, SFCC_ERR_ARG,
                       "the path contains a raw space. sfcc rest does not "
                       "percent-encode for you, so encode it yourself:\n"
                       "  a space is %%20 (and note that '+' in a path means "
                       "a space to many servers)");
    }
    if(ch == '\n' || ch == '\r' || ch == '\t'){
      return sfcc_fail(c, SFCC_ERR_ARG,
                       "the path contains a control character");
    }
  }
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */

sfcc_status sfcc_rest(sfcc_client* c, const char* path,
                      const sfcc_rest_options* opts, sfcc_rest_result* out){
  if(c == NULL || path == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  memset(out, 0, sizeof(*out));

  sfcc_rest_options o;
  memset(&o, 0, sizeof(o));
  if(opts != NULL){
    o = *opts;
  }

  sfcc_status rc = check_path(c, path);
  if(rc != SFCC_OK){
    return rc;
  }

  const sfcc_method method = parse_method(o.method);
  if(method == (sfcc_method)-1){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "unsupported method \"%s\": use GET, POST, PATCH, PUT or "
                     "DELETE", o.method);
  }
  /* A body with no verb would otherwise be silently sent as a GET, which drops
   * the body on the floor. */
  sfcc_method effective = method;
  if(o.method == NULL){
    effective = (o.body != NULL) ? SFCC_HTTP_POST : SFCC_HTTP_GET;
  }
  if(o.body == NULL && (effective == SFCC_HTTP_POST ||
                        effective == SFCC_HTTP_PATCH ||
                        effective == SFCC_HTTP_PUT)){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "%s needs a request body; pass --data or --data-file",
                     o.method ? o.method :
                       (effective == SFCC_HTTP_POST ? "POST" : "PATCH"));
  }

  /* Authentication is mandatory: an unauthenticated request to an instance
   * gives a login page rather than an API error, which is a confusing thing to
   * hand back as if it were a response. */
  rc = sfcc_ensure_auth(c);
  if(rc != SFCC_OK){
    return sfcc_fail(c, rc, "%s", sfcc_last_error(c) ? sfcc_last_error(c)
                                                     : sfcc_strerror(rc));
  }

  char* url = NULL;
  rc = build_url(c, path, &url);
  if(rc != SFCC_OK){
    return rc;
  }

  sfcc_response resp;
  rc = sfcc_http_request_ex(c, effective, url, c->access_token, o.body,
                            o.content_type, o.extra_headers, &resp);
  free(url);
  if(rc != SFCC_OK){
    return rc;
  }
  c->last_status = resp.status;

  out->status = resp.status;
  /* Take ownership of both buffers rather than copying: a response can be large
   * and there is no reason to double it. */
  out->body_len = resp.body.len;
  out->body = resp.body.data;
  out->headers = resp.headers.data;
  resp.body.data = NULL;
  resp.headers.data = NULL;
  resp.body.len = resp.body.cap = 0;
  resp.headers.len = resp.headers.cap = 0;
  sfcc_response_free(&resp);

  /*
   * A completed exchange is a success even when the status says otherwise --
   * that is the whole point of an escape hatch. But record the reason when the
   * org sent one, so sfcc_last_error() is populated for anyone who looks.
   */
  if(resp.status >= 400 && resp.body.data != NULL){
    char detail[SFCC_ERRLEN_MAX];
    sfcc_json_describe_error(out->body, resp.status, detail, sizeof(detail));
    (void)sfcc_fail(c, resp.status == 401 ? SFCC_ERR_AUTH : SFCC_ERR_HTTP,
                     "%s", detail);
  }
  return SFCC_OK;
}

void sfcc_rest_result_free(sfcc_rest_result* r){
  if(r == NULL){
    return;
  }
  sfcc_strfree(&r->body);
  sfcc_strfree(&r->headers);
  r->status = 0;
  r->body_len = 0;
}