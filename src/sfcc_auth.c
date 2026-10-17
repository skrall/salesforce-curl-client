/*
 * OAuth 2.0, client-credentials grant, plus token caching.
 *
 * Why client credentials rather than something interactive: this is a
 * non-interactive command-line tool, and a flow that opens a browser cannot be
 * scripted. The alternative -- the old username + password + security-token
 * flow -- still appears in most examples but Salesforce is deprecating it in
 * favour of connected apps, and it requires storing a user's password. So:
 * connected app, client credentials, one API call, no user interaction.
 *
 * Two behaviours here exist because long-lived tokens are the norm:
 *
 *  - Tokens are cached to a file so repeated invocations do not burn an API
 *    call each. They are treated as valid for SFCC_TOKEN_TTL rather than
 *    forever, because Salesforce does not tell you when one expires.
 *
 *  - A token can be revoked server-side at any time, so a cached one can go
 *    stale without warning. When a request comes back INVALID_SESSION_ID we
 *    drop the cached token, fetch a new one, and retry exactly once. Without
 *    that, a long-running script would need the user to delete a cache file by
 *    hand.
 */
#include "sfcc_internal.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>      /* chmod, S_IRUSR, S_IWUSR */
#endif

#ifndef SFCC_TOKEN_TTL
/* Deliberately conservative. The platform does not advertise a lifetime for
 * access tokens from this flow, so we assume the worst plausible one and
 * re-mint rather than push on a token that might be about to die. */
#define SFCC_TOKEN_TTL 1800L   /* 30 minutes */
#endif

int sfcc_token_is_fresh(const sfcc_client* c){
  if(c == NULL || c->access_token == NULL || c->token_expiry <= 0){
    return 0;
  }
  /*
   * A minute of margin. A token that would expire while the request is in
   * flight produces a confusing mid-flight failure instead of a clean
   * re-mint, and the cost of being early is one extra token request.
   */
  return (time(NULL) + 60) < c->token_expiry;
}

/* ------------------------------------------------------------------------ */
/* Cache                                                                    */
/* ------------------------------------------------------------------------ */

sfcc_status sfcc_auth_load_cache(sfcc_client* c){
  if(c == NULL || c->no_cache || c->cache_path == NULL){
    return SFCC_OK;
  }
  FILE* f = fopen(c->cache_path, "rb");
  if(f == NULL){
    return SFCC_OK;   /* absent cache is the normal first-run case */
  }
  sfcc_buf b;
  sfcc_buf_init(&b);
  char chunk[4096];
  size_t n;
  while((n = fread(chunk, 1, sizeof(chunk), f)) > 0){
    if(sfcc_buf_append(&b, chunk, n)){
      break;
    }
  }
  fclose(f);

  sfcc_status rc = SFCC_OK;
  cJSON* root = cJSON_ParseWithLength(b.data ? b.data : "", b.len);
  if(root != NULL){
    const cJSON* tok = cJSON_GetObjectItemCaseSensitive(root, "access_token");
    const cJSON* inst = cJSON_GetObjectItemCaseSensitive(root, "instance_url");
    const cJSON* issued = cJSON_GetObjectItemCaseSensitive(root, "issued_at");
    const cJSON* ident = cJSON_GetObjectItemCaseSensitive(root, "identity_url");
    /* Only adopt the token if we get both halves. A cached instance_url
     * without a token, or the reverse, would produce confusing 401s. */
    if(cJSON_IsString(tok) && tok->valuestring &&
       cJSON_IsString(inst) && inst->valuestring){
      sfcc_strset(&c->access_token, tok->valuestring);
      sfcc_strset(&c->instance_url, inst->valuestring);
      sfcc_strip_trailing_slashes(c->instance_url);
      if(cJSON_IsString(ident) && ident->valuestring){
        sfcc_strset(&c->identity_url, ident->valuestring);
      }
      if(cJSON_IsNumber(issued)){
        c->token_expiry = (time_t)issued->valuedouble;
      }else{
        c->token_expiry = 0;   /* unknown age; treated as stale */
      }
    }
    cJSON_Delete(root);
  }else{
    rc = sfcc_fail(c, SFCC_ERR_IO,
                   "token cache at %s is not valid JSON; ignoring it "
                   "(delete the file to reset)", c->cache_path);
  }
  sfcc_buf_free(&b);
  return rc;
}

void sfcc_auth_save_cache(sfcc_client* c){
  if(c == NULL || c->no_cache || c->cache_path == NULL){
    return;
  }
  if(c->access_token == NULL || c->instance_url == NULL){
    return;
  }

  cJSON* root = cJSON_CreateObject();
  if(root == NULL){
    return;
  }
  /*
   * Built with the JSON library rather than by string concatenation. Tokens are
   * normally URL-safe, but writing them into a file by hand-assembled strings
   * is exactly the kind of shortcut that produces a malformed cache once
   * something unexpected turns up in a token.
   */
  cJSON_AddStringToObject(root, "access_token", c->access_token);
  cJSON_AddStringToObject(root, "instance_url", c->instance_url);
  if(c->identity_url != NULL){
    cJSON_AddStringToObject(root, "identity_url", c->identity_url);
  }
  cJSON_AddNumberToObject(root, "issued_at", (double)time(NULL));

  char* text = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if(text == NULL){
    return;
  }

  /* Write to a temporary file and rename, so an interrupted run cannot leave a
   * half-written cache that would then be treated as invalid JSON. */
  char tmp[4200];
  int n = snprintf(tmp, sizeof(tmp), "%s.tmp", c->cache_path);
  if(n > 0 && (size_t)n < sizeof(tmp)){
    FILE* f = fopen(tmp, "wb");
    if(f != NULL){
      fputs(text, f);
      fclose(f);
#ifndef _WIN32
      /*
       * Restrict to the owner *before* the rename, so the token is never
       * visible at the final path under the default umask.
       *
       * This matters more than it looks: the cache holds a bearer token that
       * grants whatever the connected app's integration user can do. Created
       * normally it lands at 0644, which means any other local account can
       * read it and use the org. fopen honours the umask and offers no way to
       * pass a mode, so this has to be an explicit chmod.
       *
       * No equivalent on Windows: POSIX mode bits are not consulted there, so
       * access is governed by the file's ACL. On Windows this call protects the
       * cache no more than any other file in the profile directory.
       */
      chmod(tmp, S_IRUSR | S_IWUSR);
#endif
      /* Best effort: a failed rename just means no caching next time. */
      remove(c->cache_path);
      if(rename(tmp, c->cache_path) != 0){
        remove(tmp);
      }
    }
  }
  free(text);
}

/* ------------------------------------------------------------------------ */
/* Token request                                                            */
/* ------------------------------------------------------------------------ */

static void force_expired(sfcc_client* c){
  sfcc_strfree(&c->access_token);
  sfcc_strfree(&c->instance_url);
  sfcc_strfree(&c->identity_url);
  c->token_expiry = 0;
}

sfcc_status sfcc_auth_fetch_token(sfcc_client* c){
  if(c == NULL){
    return SFCC_ERR_ARG;
  }
  /* Credentials supplied directly outrank the cache; they are how CI pins an
   * externally-minted token to a specific user. */
  if(c->access_token != NULL && c->instance_url != NULL){
    return SFCC_OK;
  }
  if(c->client_id == NULL || c->client_secret == NULL){
    /* One message for one condition. A second, differently-worded copy of
     * this used to live here and in main.c, which made it unclear which path a
     * given failure had come from. The CLI checks for missing credentials
     * before constructing a client, so reaching here means the caller supplied
     * a token the server rejected and we were asked to replace it. */
    return sfcc_fail(c, SFCC_ERR_AUTH,
                     "the supplied access token was rejected and no "
                     "SFCC_CLIENT_ID/SFCC_CLIENT_SECRET are set to obtain a "
                     "replacement");
  }

  sfcc_buf form;
  sfcc_buf_init(&form);
  sfcc_buf_puts(&form, "grant_type=client_credentials");
  sfcc_buf_puts(&form, "&client_id=");
  sfcc_buf_append_encoded(&form, c->client_id);
  sfcc_buf_puts(&form, "&client_secret=");
  sfcc_buf_append_encoded(&form, c->client_secret);

  sfcc_buf url;
  sfcc_buf_init(&url);
  sfcc_buf_puts(&url, c->login_url);
  sfcc_buf_puts(&url, "/services/oauth2/token");

  /*
   * The token endpoint takes form encoding, not JSON -- which is exactly why
   * sfcc_http_request takes a content type rather than assuming one.
   */
  sfcc_response resp;
  sfcc_status rc = sfcc_http_request(c, SFCC_HTTP_POST, url.data, NULL,
                                     form.data,
                                     "application/x-www-form-urlencoded",
                                     &resp);
  sfcc_buf_free(&url);
  sfcc_buf_free(&form);
  if(rc != SFCC_OK){
    sfcc_response_free(&resp);
    return rc;
  }

  if(resp.status < 200 || resp.status >= 300){
    char detail[SFCC_ERRLEN_MAX];
    sfcc_json_describe_error(resp.body.data, resp.status, detail,
                             sizeof(detail));
    sfcc_response_free(&resp);
    return sfcc_fail(c, SFCC_ERR_AUTH, "%s", detail);
  }

  cJSON* root = cJSON_ParseWithLength(resp.body.data ? resp.body.data : "",
                                      resp.body.len);
  sfcc_response_free(&resp);
  if(root == NULL){
    return sfcc_fail(c, SFCC_ERR_AUTH,
                     "token endpoint returned something that is not JSON");
  }

  const cJSON* tok = cJSON_GetObjectItemCaseSensitive(root, "access_token");
  const cJSON* inst = cJSON_GetObjectItemCaseSensitive(root, "instance_url");
  if(!cJSON_IsString(tok) || !tok->valuestring ||
     !cJSON_IsString(inst) || !inst->valuestring){
    cJSON_Delete(root);
    force_expired(c);
    return sfcc_fail(c, SFCC_ERR_AUTH,
                     "token response lacked access_token or instance_url; "
                     "check that the connected app has the Client Credentials "
                     "flow enabled");
  }

  sfcc_strset(&c->access_token, tok->valuestring);
  sfcc_strset(&c->instance_url, inst->valuestring);
  sfcc_strip_trailing_slashes(c->instance_url);
  /* Optional: only needed for `whoami`. */
  const cJSON* id = cJSON_GetObjectItemCaseSensitive(root, "id");
  if(cJSON_IsString(id) && id->valuestring){
    sfcc_strset(&c->identity_url, id->valuestring);
  }
  cJSON_Delete(root);
  if(c->access_token == NULL || c->instance_url == NULL){
    force_expired(c);
    return sfcc_fail(c, SFCC_ERR_MEM, "out of memory storing the token");
  }

  c->token_expiry = time(NULL) + SFCC_TOKEN_TTL;
  sfcc_auth_save_cache(c);
  return SFCC_OK;
}