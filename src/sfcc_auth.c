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

#include <errno.h>
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

/* Defined below sfcc_auth_save_cache, which needs the prototype because the
 * entry point is what callers use and it sits first. */
static void save_cache_record(sfcc_client* c, time_t expires_at);

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

/*
 * Where the derived KDF iteration count comes from, when writing.
 *
 * The default tracks published PBKDF2 guidance; an override exists because
 * the cost is paid on every command that reads the cache, and a machine the
 * passphrase was chosen for may prefer a lower number. A value the parser
 * cannot make sense of falls back to the default rather than to the floor --
 * "SFCC_CACHE_KDF_ITERS=oops" should not silently mean 1000.
 */
static unsigned long kdf_iters_from_env(void){
  const char* s = getenv("SFCC_CACHE_KDF_ITERS");
  if(s == NULL || *s == '\0'){
    return SFCC_CACHE_KDF_DEFAULT;
  }
  if(s[0] == '-' || s[0] == '+'){
    return SFCC_CACHE_KDF_DEFAULT;
  }
  char* end = NULL;
  errno = 0;
  unsigned long v = strtoul(s, &end, 10);
  if(end == s || errno == ERANGE || (end != NULL && *end != '\0')){
    return SFCC_CACHE_KDF_DEFAULT;
  }
  if(v < SFCC_CACHE_KDF_MINIMUM){
    v = SFCC_CACHE_KDF_MINIMUM;
  }
  if(v > SFCC_CACHE_KDF_MAXIMUM){
    v = SFCC_CACHE_KDF_MAXIMUM;
  }
  return v;
}

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

  /*
   * Encrypted frame or plaintext JSON? Deciding that from the first eight
   * bytes, before any parsing, is what keeps the two diagnosable in their
   * own terms. An SFCCENC1 frame is not "not valid JSON" to be reported as
   * such, and a plaintext cache is not a frame that any passphrase could
   * open. It also keeps decryption from ever running on an arbitrary file
   * that merely happens to be bigger than one frame.
   */
  const int encrypted = b.len >= SFCC_CACHE_MAGIC_LEN &&
                        memcmp(b.data, SFCC_CACHE_MAGIC,
                               SFCC_CACHE_MAGIC_LEN) == 0;

  const char* json = b.data;
  size_t json_len = b.len;
  sfcc_buf plain;
  sfcc_buf_init(&plain);

  sfcc_status rc = SFCC_OK;
  if(encrypted){
    int u = sfcc_cache_unwrap(sfcc_cache_passphrase(),
                              (const unsigned char*)b.data, b.len, &plain);
    switch(u){
      case SFCC_CACHE_OK:
        json = plain.data;
        json_len = plain.len;
        break;
      case SFCC_CACHE_ERR_NO_PASSPHRASE:
        rc = sfcc_fail(c, SFCC_ERR_IO,
                       "token cache at %s is encrypted; set "
                       "SFCC_CACHE_PASSPHRASE to the value it was written "
                       "with, or delete the file",
                       c->cache_path);
        break;
      case SFCC_CACHE_ERR_KEY_MISMATCH:
        rc = sfcc_fail(c, SFCC_ERR_IO,
                       "token cache at %s could not be decrypted with the "
                       "current SFCC_CACHE_PASSPHRASE -- wrong passphrase or "
                       "a corrupt file; delete it to reset",
                       c->cache_path);
        break;
      case SFCC_CACHE_ERR_BAD_HEADER:
        rc = sfcc_fail(c, SFCC_ERR_IO,
                       "token cache at %s has a damaged SFCCENC1 header; "
                       "delete the file to reset", c->cache_path);
        break;
      case SFCC_CACHE_ERR_OUT_OF_MEMORY:
        rc = sfcc_fail(c, SFCC_ERR_MEM, "out of memory reading %s",
                       c->cache_path);
        break;
      default:
        rc = sfcc_fail(c, SFCC_ERR_IO, "token cache at %s is unreadable",
                       c->cache_path);
        break;
    }
  }

  cJSON* root = (rc == SFCC_OK)
                  ? cJSON_ParseWithLength(json ? json : "", json_len)
                  : NULL;
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
      /*
       * expires_at is written by sfcc_auth_save_cache. Older caches predate it
       * and carry only issued_at, so the assumed TTL is applied here rather
       * than trusting the raw issue time as if it were an expiry.
       *
       * That distinction was worth a whole bug: reading issued_at straight into
       * token_expiry made every cached token older than the one-minute margin
       * look expired, so the cache was honoured for sixty seconds and no longer.
       */
      const cJSON* expires = cJSON_GetObjectItemCaseSensitive(root, "expires_at");
      if(cJSON_IsNumber(expires)){
        c->token_expiry = (time_t)expires->valuedouble;
      }else if(cJSON_IsNumber(issued)){
        c->token_expiry = (time_t)issued->valuedouble + SFCC_TOKEN_TTL;
      }else{
        c->token_expiry = 0;   /* unknown age; treated as stale */
      }

      /*
       * Migration, in place. The moment a passphrase and a working backend
       * exist, a plaintext cache is rewritten encrypted, so "I set the
       * passphrase" takes effect on the next run rather than the next
       * re-mint -- which might be weeks away, or never if the cache keeps
       * being reused. Only a *usable* record migrates: refreshing a dead one
       * is about to delete it anyway.
       *
       * The rewrite is idempotent, so a reader finding an already-encrypted
       * file costs one string comparison and stops.
       */
      if(!encrypted && rc == SFCC_OK && sfcc_token_is_fresh(c) &&
         sfcc_cache_passphrase() != NULL && sfcc_cache_crypto_available()){
        save_cache_record(c, c->token_expiry);
      }
    }
    cJSON_Delete(root);
  }else if(!encrypted && rc == SFCC_OK){
    rc = sfcc_fail(c, SFCC_ERR_IO,
                   "token cache at %s is not valid JSON; delete the file to "
                   "reset", c->cache_path);
  }

  /* Erase before release -- both buffers can have held the plaintext token
   * at one point or another in these paths. */
  sfcc_cache_zero(b.data, b.len);
  sfcc_buf_free(&b);
  sfcc_cache_zero(plain.data, plain.len);
  sfcc_buf_free(&plain);
  return rc;
}

void sfcc_auth_save_cache(sfcc_client* c){
  save_cache_record(c, time(NULL) + SFCC_TOKEN_TTL);
}

/*
 * The record writer behind sfcc_auth_save_cache. expires_at is a parameter
 * because the two callers disagree about what time it is: a new mint takes
 * the full TTL from now, but rewriting an existing -- still current --
 * record as part of migration must keep the expiry it was minted with, or
 * every migration quietly extends the token's assumed life.
 */
static void save_cache_record(sfcc_client* c, time_t expires_at){
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
  /*
   * Written explicitly rather than left for the reader to infer. The TTL is an
   * assumption -- the platform does not advertise a lifetime for this flow -- and
   * putting the conclusion in the file makes that assumption visible to anyone
   * reading it, instead of buried in the arithmetic on the load path.
   */
  cJSON_AddNumberToObject(root, "expires_at", (double)expires_at);

  char* text = cJSON_PrintUnformatted(root);
  const size_t text_len = text ? strlen(text) : 0;
  cJSON_Delete(root);
  if(text == NULL){
    return;
  }

  /*
   * Encrypted-or-nothing. With a passphrase set, the frame is what gets
   * written and a failed wrap caches nothing -- it never falls back to
   * plaintext, because "the protection this run promised" is not something a
   * cache should be allowed to quietly withdraw. The failure is loud, on
   * stderr, exactly because caching silently nothing turns into "why did
   * this run re-authenticate" three runs later.
   */
  const char* passphrase = sfcc_cache_passphrase();
  const unsigned char* payload = (const unsigned char*)text;
  size_t payload_len = text_len;
  sfcc_buf framed;
  sfcc_buf_init(&framed);
  if(passphrase != NULL){
    if(!sfcc_cache_crypto_available()){
      fprintf(stderr, "note: SFCC_CACHE_PASSPHRASE is set, but this build has "
                      "no cache-encryption backend; the token was not cached "
                      "(is libcrypto present at build time on this "
                      "platform?)\n");
      goto done_write;
    }
    int w = sfcc_cache_wrap(passphrase, payload, payload_len,
                            kdf_iters_from_env(), &framed);
    if(w != SFCC_CACHE_OK){
      fprintf(stderr, "note: the token was not cached (%s)\n",
              w == SFCC_CACHE_ERR_OUT_OF_MEMORY ? "out of memory"
              : w == SFCC_CACHE_ERR_KDF_RANGE   ? "unusable "
                                                "SFCC_CACHE_KDF_ITERS"
                                                : "frame init failed");
      goto done_write;
    }
    payload = (const unsigned char*)framed.data;
    payload_len = framed.len;
  }

  /* Write to a temporary file and rename, so an interrupted run cannot leave a
   * half-written cache that would then be treated as invalid JSON. */
  char tmp[4200];
  int n = snprintf(tmp, sizeof(tmp), "%s.tmp", c->cache_path);
  if(n > 0 && (size_t)n < sizeof(tmp)){
    FILE* f = fopen(tmp, "wb");
    if(f != NULL){
      fwrite(payload, 1, payload_len, f);
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

done_write:
  sfcc_cache_zero(text, text_len);
  free(text);
  sfcc_cache_zero(framed.data, framed.len);
  sfcc_buf_free(&framed);
}


/* ------------------------------------------------------------------------ */
/* Token request                                                            */
/* ------------------------------------------------------------------------ */

/*
 * Salesforce's own code for a dead session. Shared, because three separate
 * request paths meet the condition and each was previously deciding for itself.
 */
int sfcc_is_invalid_session(long status, const char* body){
  return status == 401 ||
         (body != NULL && strstr(body, "INVALID_SESSION_ID") != NULL) ||
         (body != NULL && strstr(body, "SESSION expired") != NULL);
}

/*
 * May this client replace a rejected token by authenticating again?
 *
 * Only when it holds the means to do so. The retry exists for a token *we*
 * obtained and cached, which can go stale at any time. A token the caller
 * supplied is none of our business: we cannot re-mint it, so discarding it and
 * attempting a new grant would replace a precise "this token was rejected" with a
 * vague "no credentials" and send the caller looking in the wrong place.
 */
static int can_reauthenticate(const sfcc_client* c){
  return (c->client_id != NULL && c->client_secret != NULL);
}

/*
 * Drop the token this client is holding, and the cache file holding the same
 * one.
 *
 * Removing the file matters as much as clearing the fields. A cache that still
 * names a token the server has rejected is read back on the next run, judged
 * stale, and -- before this was separated out -- quietly handed straight back
 * again, which is how an expired cache turned into a hard failure with no
 * recovery attempt at all.
 */
void sfcc_auth_discard_token(sfcc_client* c){
  if(c == NULL){
    return;
  }
  sfcc_strfree(&c->access_token);
  sfcc_strfree(&c->instance_url);
  sfcc_strfree(&c->identity_url);
  c->token_expiry = 0;
  if(!c->no_cache && c->cache_path != NULL){
    remove(c->cache_path);
  }
}

sfcc_status sfcc_auth_fetch_token(sfcc_client* c){
  if(c == NULL){
    return SFCC_ERR_ARG;
  }
  /* Credentials supplied directly outrank the cache; they are how CI pins an
   * externally-minted token to a specific user.
   *
   * The invariant this guard depends on is that reaching here with a token
   * already set means the *caller* set it. Every path that means "replace this
   * token" therefore calls sfcc_auth_discard_token() first -- without that, this
   * function cannot tell a rejected cache entry from a deliberate choice and
   * returns the stale token it was asked to replace. */
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
    sfcc_auth_discard_token(c);
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
    sfcc_auth_discard_token(c);
    return sfcc_fail(c, SFCC_ERR_MEM, "out of memory storing the token");
  }

  c->token_expiry = time(NULL) + SFCC_TOKEN_TTL;
  sfcc_auth_save_cache(c);
  return SFCC_OK;
}

sfcc_status sfcc_auth_reauthenticate(sfcc_client* c){
  if(c == NULL){
    return SFCC_ERR_ARG;
  }
  if(!can_reauthenticate(c)){
    return sfcc_fail(c, SFCC_ERR_AUTH,
                     "the access token was rejected and no "
                     "SFCC_CLIENT_ID/SFCC_CLIENT_SECRET are set to obtain a "
                     "replacement");
  }
  sfcc_auth_discard_token(c);
  return sfcc_auth_fetch_token(c);
}
