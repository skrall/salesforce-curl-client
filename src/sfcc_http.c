/*
 * The libcurl layer.
 *
 * Responsibilities are deliberately narrow: build a request, send it, collect
 * the whole body into a buffer, and report a status. It knows nothing about
 * Salesforce -- no URL construction, no OAuth, no interpretation of the
 * response. Everything above it in sfcc_client.c owns those concerns.
 *
 * Two decisions worth stating outright:
 *
 *  - One easy handle is kept per client and reused. curl_easy handles are not
 *    free to create and they clean up connection state when reset, so reusing
 *    one across requests preserves keep-alive within a run.
 *
 *  - Certificate verification is on unless explicitly disabled. There is no
 *    third option: no "verify but warn", and no default-off. A bearer token
 *    is bearer-authority for the whole org, so an unverified TLS session
 *    hands that authority to whoever is in the middle.
 */
#include "sfcc_internal.h"

#include <curl/curl.h>

#include <stdarg.h>
#include <stdio.h>
#include <strings.h>   /* strncasecmp */
#include <stdlib.h>
#include <string.h>

#ifndef SFCC_USERAGENT
#define SFCC_USERAGENT ("sfcc/" SFCC_VERSION)
#endif

/*
 * curl's global init is process-wide and not thread-safe to call repeatedly
 * without care. Reference-counting it here means every entry point can call
 * this unconditionally, and only the first caller pays. The cleanup is
 * registered with atexit rather than tied to any one client, because libcurl
 * documents that global cleanup must happen once, after all handles are gone.
 */
static int g_curl_refs = 0;

sfcc_status sfcc_http_global_init(void){
  if(g_curl_refs++ == 0){
    if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK){
      g_curl_refs = 0;
      return sfcc_fail(NULL, SFCC_ERR_NET, "curl_global_init failed");
    }
    atexit(curl_global_cleanup);
  }
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */

static const char* method_name(sfcc_method m){
  switch(m){
    case SFCC_HTTP_POST:   return "POST";
    case SFCC_HTTP_PATCH:  return "PATCH";
    case SFCC_HTTP_PUT:    return "PUT";
    case SFCC_HTTP_DELETE: return "DELETE";
    case SFCC_HTTP_GET:
    default:               return "GET";
  }
}

/*
 * Receives each chunk of the response body. Returning anything other than the
 * byte count tells curl to abort the transfer with CURLE_WRITE_ERROR, so this
 * only has to grow the buffer and report success.
 */
static size_t body_sink(char* ptr, size_t size, size_t nmemb, void* userdata){
  sfcc_response* r = userdata;
  const size_t total = size * nmemb;
  /* size * nmemb can wrap in theory; curl passes sane values, but a zero
   * total would otherwise look like a legitimate empty chunk. */
  if(total / (size ? size : 1) != nmemb){
    return 0;
  }
  if(sfcc_buf_append(&r->body, ptr, total)){
    return 0;
  }
  return total;
}

/*
 * Collects the response head verbatim. Used by the `rest` command's
 * --include, where the interesting headers (Location after a create,
 * Sforce-Limit-Info, content-type of a blob) are not in the body.
 */
static size_t header_sink(char* ptr, size_t size, size_t nmemb, void* userdata){
  sfcc_response* r = userdata;
  const size_t total = size * nmemb;
  /* Bounded: an unbounded server cannot make us allocate without limit. The
   * head is small; a megabyte of it means something is wrong. */
  if(r->headers.len + total > 64u * 1024u){
    return total;   /* drop it, do not abort the transfer */
  }
  if(sfcc_buf_append(&r->headers, ptr, total)){
    return 0;
  }
  return total;
}

static CURL* client_handle(sfcc_client* c){
  if(c->curl == NULL){
    c->curl = curl_easy_init();
  }
  return (CURL*)c->curl;
}

/*
 * Everything a request needs that is not the body: URL, TLS policy, timeouts,
 * the bearer token, the response sink, and the protocol allowlist.
 *
 * Factored out because there are now two body-carrying shapes -- a plain
 * payload (CURLOPT_POSTFIELDS) and a multipart form (CURLOPT_MIMEPOST) -- and
 * duplicating sixty lines of transport policy between them would guarantee the
 * two drift apart. Notably the bearer header lives here, which is what keeps
 * the "name the header" bug from having a second site to hide in.
 *
 * On success *headers_out owns a list the caller must free.
 */
/* Case-insensitive prefix match, because HTTP header names are not
 * case-sensitive and "authorization:" must suppress ours just as
 * "Authorization:" does. */
static int name_is(const char* line, const char* name){
  const size_t n = strlen(name);
  if(strncasecmp(line, name, n) != 0){
    return 0;
  }
  const char after = line[n];
  return after == ':' || after == ' ' || after == '\t';
}

static int http_has_header(const char* const* headers, const char* name){
  if(headers == NULL){
    return 0;
  }
  for(const char* const* h = headers ; *h ; ++h){
    if(name_is(*h, name)){
      return 1;
    }
  }
  return 0;
}

static CURL* http_prepare(sfcc_client* c, sfcc_method method,
                          const char* url, const char* auth_token,
                          const char* const* extra, sfcc_response* resp,
                          struct curl_slist** headers_out){
  *headers_out = NULL;

  CURL* h = client_handle(c);
  if(h == NULL){
    return NULL;
  }
  /* curl_easy_reset returns the handle to defaults, which is what we want:
   * it drops the auth header and TLS settings from any previous call so a
   * later unauthenticated request cannot inherit them. */
  curl_easy_reset(h);

  char errbuf[CURL_ERROR_SIZE] = { 0 };
  struct curl_slist* headers = NULL;

  curl_easy_setopt(h, CURLOPT_URL, url);
  curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(h, CURLOPT_USERAGENT, SFCC_USERAGENT);
  curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
  /* Transparent gzip/deflate/br. Costs nothing and a describe() response can
   * be a few hundred kilobytes. */
  curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(h, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, body_sink);
  curl_easy_setopt(h, CURLOPT_WRITEDATA, resp);
  /* Always on: the head is collected into the response struct and it is the
   * caller that decides whether to show it, so there is no cost to collecting
   * it and no second code path when someone wants to. */
  curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, header_sink);
  curl_easy_setopt(h, CURLOPT_HEADERDATA, resp);

  if(c->timeout_s > 0){
    curl_easy_setopt(h, CURLOPT_TIMEOUT, (long)c->timeout_s);
  }
  if(c->connect_timeout_s > 0){
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, (long)c->connect_timeout_s);
  }

  /*
   * Restrict the protocol set. Without this, a redirect or a hostile URL can
   * steer curl at file:// or scp:// and read local files. Salesforce is
   * HTTPS-only, so nothing legitimate is lost.
   */
#if LIBCURL_VERSION_NUM >= 0x075500   /* 7.85.0 */
  curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
  curl_easy_setopt(h, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
  curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

  /* Salesforce does not redirect its API endpoints. Following redirects would
   * mean replaying the Authorization header at whatever host the Location
   * points to, so it is off. */
  curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);

  if(!c->insecure){
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
  }else{
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);
  }

  headers = curl_slist_append(headers, "Accept: application/json");
  if(auth_token != NULL && *auth_token && !http_has_header(extra, "Authorization")){
    /*
     * The full header line, name included: "Authorization: Bearer <token>".
     *
     * The name is not optional. CURLOPT_HTTPHEADER entries must be
     * "Header: value" -- libcurl parses each string on its first colon, and
     * silently ignores any entry without one. Passing just "Bearer <token>"
     * therefore produces *no* Authorization header at all: no error, no
     * warning, and every request goes out unauthenticated. The result is a
     * 401 whose cause is invisible from the client side, which is considerably
     * worse than a build break.
     *
     * Skipped when the caller supplied their own Authorization, which is how
     * `rest` lets a user override the token rather than sending both.
     */
    static const char PREFIX[] = "Authorization: Bearer ";
    char* hdr = malloc(sizeof(PREFIX) + strlen(auth_token));  /* includes NUL */
    if(hdr == NULL){
      curl_slist_free_all(headers);
      return NULL;
    }
    snprintf(hdr, sizeof(PREFIX) + strlen(auth_token), "%s%s", PREFIX,
             auth_token);
    struct curl_slist* nh = curl_slist_append(headers, hdr);
    free(hdr);
    if(nh == NULL){
      curl_slist_free_all(headers);
      return NULL;
    }
    headers = nh;
  }
  *headers_out = headers;

  /* CUSTOMREQUEST rather than CURLOPT_POST: it sets the verb without changing
   * curl's understanding of whether there is a body, which is what we want for
   * PATCH. POST still goes through the same path so there is one code path
   * instead of two that differ only in a flag. */
  curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, method_name(method));
  return h;
}

/* Map a curl result onto a status code, with detail good enough to act on. */
static sfcc_status http_finish(sfcc_client* c, CURL* h, const char* url,
                               CURLcode cr, const char* errbuf,
                               sfcc_response* resp){
  if(cr != CURLE_OK){
    /*
     * Distinguish "we gave up waiting" from "the peer refused" from "TLS
     * verification failed", because the remedy is different in each case and
     * a generic "network error" sends people off in three directions.
     */
    const char* detail = errbuf[0] ? errbuf : curl_easy_strerror(cr);
    if(cr == CURLE_OPERATION_TIMEDOUT){
      return sfcc_fail(c, SFCC_ERR_NET, "timed out after %lds: %s",
                       c->timeout_s, detail);
    }
    if(cr == CURLE_PEER_FAILED_VERIFICATION || cr == CURLE_SSL_CACERT){
      return sfcc_fail(c, SFCC_ERR_NET,
                       "TLS certificate verification failed: %s\n"
                       "       Do not disable verification to work around this; "
                       "fix the trust store.", detail);
    }
    if(cr == CURLE_COULDNT_CONNECT || cr == CURLE_COULDNT_RESOLVE_HOST ||
       cr == CURLE_COULDNT_RESOLVE_PROXY){
      return sfcc_fail(c, SFCC_ERR_NET, "could not reach %s: %s", url, detail);
    }
    if(cr == CURLE_WRITE_ERROR){
      return sfcc_fail(c, SFCC_ERR_NET,
                       "response exceeded the %u MiB limit", SFCC_MAX_BODY >> 20);
    }
    return sfcc_fail(c, SFCC_ERR_NET, "%s", detail);
  }
  long status = 0;
  if(curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK){
    resp->status = status;
  }
  return SFCC_OK;
}

sfcc_status sfcc_http_request_ex(sfcc_client* c, sfcc_method method,
                                 const char* url, const char* auth_token,
                                 const char* body, const char* content_type,
                                 const char* const* extra_headers,
                                 sfcc_response* resp){
  if(c == NULL || url == NULL || resp == NULL){
    return SFCC_ERR_ARG;
  }
  memset(resp, 0, sizeof(*resp));
  resp->method = method;
  sfcc_buf_init(&resp->body);
  sfcc_buf_init(&resp->headers);

  struct curl_slist* headers = NULL;
  CURL* h = http_prepare(c, method, url, auth_token, extra_headers, resp,
                         &headers);
  if(h == NULL){
    sfcc_buf_free(&resp->body);
    sfcc_buf_free(&resp->headers);
    return sfcc_fail(c, SFCC_ERR_NET, "could not prepare the request");
  }
  sfcc_status rc;

  /* A JSON body also sets Content-Type, unless the caller supplied one. With
   * no body we send no Content-Type, which is what a GET or DELETE wants. */
  if(body != NULL && !http_has_header(extra_headers, "Content-Type")){
    const char* type = content_type ? content_type : "application/json";
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "Content-Type: %s", type);
    struct curl_slist* nh = curl_slist_append(headers, hdr);
    if(nh == NULL){
      curl_slist_free_all(headers);
      sfcc_buf_free(&resp->body);
      sfcc_buf_free(&resp->headers);
      return sfcc_fail(c, SFCC_ERR_MEM, "out of memory building headers");
    }
    headers = nh;
  }

  /* Caller headers last, so they win over ours where both name a header. curl
   * sends duplicate header lines rather than replacing, so suppressing our own
   * default in http_prepare is what actually makes an override work. */
  for(const char* const* eh = extra_headers ; eh && *eh ; ++eh){
    struct curl_slist* nh = curl_slist_append(headers, *eh);
    if(nh == NULL){
      curl_slist_free_all(headers);
      sfcc_buf_free(&resp->body);
      sfcc_buf_free(&resp->headers);
      return sfcc_fail(c, SFCC_ERR_MEM, "out of memory building headers");
    }
    headers = nh;
  }
  curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);

  if(body != NULL){
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
  }

  char errbuf[CURL_ERROR_SIZE] = { 0 };
  curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errbuf);
  rc = http_finish(c, h, url, curl_easy_perform(h), errbuf, resp);

  curl_slist_free_all(headers);
  /* The handle is deliberately not closed here: it is owned by the client and
   * reused. sfcc_client_free() closes it. */
  return rc;
}

sfcc_status sfcc_http_request(sfcc_client* c, sfcc_method method,
                              const char* url, const char* auth_token,
                              const char* body, const char* content_type,
                              sfcc_response* resp){
  return sfcc_http_request_ex(c, method, url, auth_token, body, content_type,
                              NULL, resp);
}


/*
 * A multipart/form-data POST.
 *
 * Used by metadata deploy, which sends a zip as a binary file part rather than
 * as a request body. The mime object is built by the caller because the parts
 * are specific to that endpoint; this function owns only the transport.
 *
 * curl_mime generates the boundary, so there is no hand-rolled delimiter to get
 * wrong -- and no way for a boundary to occur inside the zip and corrupt it.
 *
 * Takes ownership of *mime: it is freed here whether the call succeeds or
 * fails, so callers cannot leak it by forgetting a cleanup path.
 */
sfcc_status sfcc_http_request_mime(sfcc_client* c, const char* url,
                                   const char* auth_token, curl_mime** mime,
                                   sfcc_response* resp){
  if(c == NULL || url == NULL || mime == NULL || *mime == NULL ||
     resp == NULL){
    curl_mime_free(*mime);
    *mime = NULL;
    return SFCC_ERR_ARG;
  }
  memset(resp, 0, sizeof(*resp));
  resp->method = SFCC_HTTP_POST;
  sfcc_buf_init(&resp->body);
  sfcc_buf_init(&resp->headers);

  struct curl_slist* headers = NULL;
  /* POST is implicit here: CURLOPT_MIMEPOST sets the verb along with the body,
   * which differs from the CUSTOMREQUEST path used by sfcc_http_request. */
  CURL* h = http_prepare(c, SFCC_HTTP_POST, url, auth_token, NULL, resp, &headers);
  if(h == NULL){
    curl_mime_free(*mime);
    *mime = NULL;
    sfcc_buf_free(&resp->body);
    sfcc_buf_free(&resp->headers);
    return sfcc_fail(c, SFCC_ERR_NET, "could not prepare the request");
  }

  curl_easy_setopt(h, CURLOPT_POST, 1L);
  curl_easy_setopt(h, CURLOPT_MIMEPOST, *mime);

  char errbuf[CURL_ERROR_SIZE] = { 0 };
  curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errbuf);
  const sfcc_status rc = http_finish(c, h, url, curl_easy_perform(h), errbuf,
                                     resp);

  curl_mime_free(*mime);
  *mime = NULL;
  curl_slist_free_all(headers);
  return rc;
}

void sfcc_response_free(sfcc_response* r){
  if(r == NULL){
    return;
  }
  sfcc_buf_free(&r->body);
  sfcc_buf_free(&r->headers);
  r->status = 0;
  r->method = SFCC_HTTP_GET;
}