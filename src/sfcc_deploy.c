/*
 * Metadata deployment.
 *
 * Scope is deliberately one entry point: deploy a zip that already exists.
 * Building a zip from a source tree is a separate concern, added later, and
 * keeping it out of here means this file is entirely about the wire protocol --
 * multipart upload, an asynchronous job, and making sense of the status
 * document that comes back.
 *
 * Three things about this endpoint are worth knowing before reading on:
 *
 *  - It is asynchronous. The POST returns an id and a state of Pending or
 *    InProgress; the interesting answer arrives at
 *    /metadata/deployRequest/<id> later. Polling is not optional, and a
 *    deploy with tests can legitimately run for many minutes.
 *
 *  - The file part must be binary. Base64 belongs to the SOAP deploy() call;
 *    base64-ing the zip here is a common mistake that yields a 400 with a
 *    body that does not mention base64 at all.
 *
 *  - A deploy that "fails" is a successful API call. The request was accepted
 *    and the org then reported that some components were rejected. So the
 *    status code and the outcome are separate things, and this file is careful
 *    not to conflate them -- callers check result->succeeded.
 */
#include "sfcc_internal.h"

#include "cJSON.h"

#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>     /* Sleep */
#else
#include <time.h>        /* nanosleep, already above on most systems */
#endif

#define SFCC_DEPLOY_POLL_DEFAULT 5L
#define SFCC_DEPLOY_TIMEOUT_DEFAULT 900L   /* 15 minutes */

/*
 * Refuse anything larger up front. The platform does publish a component-size
 * limit and no legitimate single-package deploy approaches this; the point is
 * that reading the whole file into memory should be a deliberate act, not an
 * accident of pointing at the wrong file.
 */
#define SFCC_MAX_ZIP_BYTES (100u * 1024u * 1024u)

void sfcc_deploy_options_defaults(sfcc_deploy_options* opts){
  if(opts == NULL){
    return;
  }
  memset(opts, 0, sizeof(*opts));
  opts->validate_only = 0;
  opts->test_level = SFCC_TEST_NONE;
  opts->tests = NULL;
  opts->single_package = 0;
  opts->poll_interval_s = SFCC_DEPLOY_POLL_DEFAULT;
  opts->timeout_s = SFCC_DEPLOY_TIMEOUT_DEFAULT;
}

/* ------------------------------------------------------------------------ */
/* Local validation                                                         */
/* ------------------------------------------------------------------------ */

/*
 * Read the whole file, and check that it actually looks like a zip.
 *
 * The magic check is worth having: "deploy" pointed at the wrong file is an
 * easy mistake, and without it the round trip costs an API call and returns a
 * message about package.xml rather than about the file being wrong.
 *
 * The four recognised signatures are the local file header, the empty-archive
 * marker, and the two spanned variants.
 */
static sfcc_status read_zip(sfcc_client* c, const char* path, sfcc_buf* out){
  if(path == NULL || !*path){
    return sfcc_fail(c, SFCC_ERR_ARG, "no zip path given");
  }
  /* Binary mode: on Windows this is what stops CRLF translation from corrupting
   * the archive. A zip that "works on Linux and fails on Windows" is almost
   * always this. */
  FILE* f = fopen(path, "rb");
  if(f == NULL){
    return sfcc_fail(c, SFCC_ERR_IO, "cannot open %s", path);
  }

  sfcc_buf_init(out);
  char chunk[65536];
  size_t n;
  while((n = fread(chunk, 1, sizeof(chunk), f)) > 0){
    if(sfcc_buf_append(out, chunk, n)){
      fclose(f);
      sfcc_buf_free(out);
      return sfcc_fail(c, SFCC_ERR_MEM, "out of memory reading %s", path);
    }
    if(out->len > SFCC_MAX_ZIP_BYTES){
      fclose(f);
      sfcc_buf_free(out);
      return sfcc_fail(c, SFCC_ERR_ARG,
                       "%s is larger than %u MiB, which no legitimate metadata "
                       "package should be", path, SFCC_MAX_ZIP_BYTES >> 20);
    }
  }
  const int bad = ferror(f);
  fclose(f);
  if(bad){
    sfcc_buf_free(out);
    return sfcc_fail(c, SFCC_ERR_IO, "error reading %s", path);
  }
  if(out->len == 0){
    sfcc_buf_free(out);
    return sfcc_fail(c, SFCC_ERR_ARG, "%s is empty", path);
  }

  const unsigned char* p = (const unsigned char*)out->data;
  const size_t len = out->len;
  const int is_zip =
      (len >= 4 && p[0] == 'P' && p[1] == 'K' &&
       ((p[2] == 3 && p[3] == 4) ||   /* local file header */
        (p[2] == 5 && p[3] == 6) ||   /* empty archive */
        (p[2] == 7 && p[3] == 8)));  /* spanned */
  if(!is_zip){
    sfcc_buf_free(out);
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "%s does not start with a zip signature. A metadata "
                     "package must be a zip built by `zip` (not by tar, gzip "
                     "or Finder's Archive Utility, none of which make one)",
                     path);
  }
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* Deploy options document                                                  */
/* ------------------------------------------------------------------------ */

/*
 * The JSON part of the multipart body. Salesforce's metadata options are mostly
 * strings rather than booleans -- deployOptions is "validateOnly" or empty --
 * which is easy to get subtly wrong, so each field is built explicitly rather
 * than with a generic serialiser.
 */
static char* build_options_json(const sfcc_deploy_options* o){
  const char* test_level = "NoTestRun";
  if(o->test_level == SFCC_TEST_LOCAL){
    test_level = "RunLocalTests";
  }else if(o->test_level == SFCC_TEST_SPECIFIED){
    test_level = "RunSpecifiedTests";
  }

  sfcc_buf b;
  sfcc_buf_init(&b);
  sfcc_buf_puts(&b, "{");
  sfcc_buf_printf(&b, "\"deployOptions\":\"%s\"",
                  o->validate_only ? "validateOnly" : "");
  sfcc_buf_printf(&b, ",\"testLevel\":\"%s\"", test_level);
  sfcc_buf_printf(&b, ",\"singlePackage\":%s",
                  o->single_package ? "true" : "false");
  if(o->test_level == SFCC_TEST_SPECIFIED && o->tests != NULL && *o->tests){
    /*
     * tests is a caller-supplied list going straight into a JSON string, so it
     * has to be escaped. Salesforce expects it comma separated.
     */
    sfcc_buf_puts(&b, ",\"tests\":\"");
    for(const char* p = o->tests ; *p ; ++p){
      switch(*p){
        case '"':  sfcc_buf_puts(&b, "\\\""); break;
        case '\\': sfcc_buf_puts(&b, "\\\\"); break;
        case '\n': sfcc_buf_puts(&b, "\\n");  break;
        case '\r': sfcc_buf_puts(&b, "\\r");  break;
        case '\t': sfcc_buf_puts(&b, "\\t");  break;
        default:
          if((unsigned char)*p < 0x20){
            sfcc_buf_printf(&b, "\\u%04x", (unsigned char)*p);
          }else{
            char c = *p;
            sfcc_buf_append(&b, &c, 1);
          }
      }
    }
    sfcc_buf_puts(&b, "\"");
  }
  sfcc_buf_puts(&b, "}");
  return b.data;   /* caller frees; NULL on allocation failure */
}

/* ------------------------------------------------------------------------ */
/* Status reporting                                                         */
/* ------------------------------------------------------------------------ */

/*
 * Render the per-component detail lines.
 *
 * This is most of the value of the command. The raw status JSON is technically
 * complete and practically unreadable: a deploy touching forty components
 * reports as one enormous array, and the line and column numbers that tell you
 * *where* the Apex is wrong are easy to miss when buried in it. So failures
 * are listed one per line with their file and position.
 */
static void append_components(sfcc_buf* out, const cJSON* details,
                              const char* key, const char* mark){
  const cJSON* arr = cJSON_GetObjectItemCaseSensitive(details, key);
  if(!cJSON_IsArray(arr)){
    return;
  }
  const cJSON* it = NULL;
  cJSON_ArrayForEach(it, arr){
    const char* full = sfcc_json_str(it, "fullName", "?");
    const char* type = sfcc_json_str(it, "componentType", "?");
    const char* file = sfcc_json_str(it, "fileName", "");
    const int line = sfcc_json_int(it, "lineNumber", 0);
    const int col = sfcc_json_int(it, "columnNumber", 0);

    if(strcmp(key, "componentFailures") == 0){
      sfcc_buf_printf(out, "\n  %s %s (%s)\n", mark, full, type);
      /*
       * Salesforce pads "problem" with newlines of its own -- the text often
       * arrives as "\n  Unexpected token...\n". Printed as-is that turns each
       * failure into four ragged lines with a blank line through the middle, so
       * the padding is stripped and the remaining lines re-indented.
       */
      const char* problem = sfcc_json_str(it, "problem", "");
      while(*problem == '\n' || *problem == '\r' || *problem == ' ' ||
            *problem == '\t'){
        ++problem;
      }
      char clean[SFCC_ERRLEN_MAX];
      size_t plen = strlen(problem);
      while(plen > 0 && (problem[plen - 1] == '\n' ||
                         problem[plen - 1] == '\r' ||
                         problem[plen - 1] == ' '  ||
                         problem[plen - 1] == '\t')){
        --plen;
      }
      if(plen == 0 || plen >= sizeof(clean)){
        problem = "failed";
        plen = strlen(problem);
      }
      memcpy(clean, problem, plen);
      clean[plen] = '\0';
      /* The first line carries the indent that the stripped padding removed;
       * continuation lines get the same indent so a wrapped message stays
       * aligned under its own first line rather than running back to column 0. */
      sfcc_buf_puts(out, "      ");
      for(size_t i = 0 ; i < plen ; ++i){
        char ch = clean[i];
        if(ch == '\n'){
          sfcc_buf_puts(out, "\n      ");
          continue;
        }
        sfcc_buf_append(out, &ch, 1);
      }
      sfcc_buf_puts(out, "\n");
      if(*file){
        if(line > 0 && col > 0){
          sfcc_buf_printf(out, "      at %s:%d:%d\n", file, line, col);
        }else if(line > 0){
          sfcc_buf_printf(out, "      at %s:%d\n", file, line);
        }else{
          sfcc_buf_printf(out, "      at %s\n", file);
        }
      }
    }else{
      const char* action = sfcc_json_bool(it, "created") ? "created"
                       : sfcc_json_bool(it, "deleted") ? "deleted"
                       : sfcc_json_bool(it, "updated") ? "updated"
                       : "deployed";
      sfcc_buf_printf(out, "\n  %s %s (%s, %s)\n", mark, full, type, action);
      if(*file){
        sfcc_buf_printf(out, "      %s\n", file);
      }
    }
  }
}

static char* render_report(const sfcc_deploy_result* r,
                           const sfcc_deploy_options* opts){
  /* No client needed: the result already carries everything. */
  sfcc_buf out;
  sfcc_buf_init(&out);

  const char* state = r->status ? r->status : "(no status)";
  if(r->succeeded){
    sfcc_buf_printf(&out, "Deploy %s%s\n",
                    opts->validate_only ? "validated" : "succeeded",
                    opts->validate_only ? " (no changes were made)" : "");
  }else if(r->status && strcmp(state, "Canceled") == 0){
    sfcc_buf_puts(&out, "Deploy canceled\n");
  }else if(!r->done){
    sfcc_buf_puts(&out,
      "Deploy still running when we stopped waiting.\n"
      "  It may well finish; check on it with the id above.\n");
  }else{
    sfcc_buf_printf(&out, "Deploy failed (%s)\n", state);
  }
  if(r->total > 0 || r->deployed > 0 || r->errors > 0){
    sfcc_buf_printf(&out, "  %d of %d component%s deployed, %d error%s%s\n",
                    r->deployed, r->total, r->total == 1 ? "" : "s",
                    r->errors, r->errors == 1 ? "" : "s",
                    r->skipped ? "" : "");
    if(r->skipped){
      sfcc_buf_printf(&out, "  %d skipped\n", r->skipped);
    }
  }

  if(r->raw_json == NULL){
    return out.data ? out.data : sfcc_strdup("(no report)");
  }
  cJSON* root = cJSON_ParseWithLength(r->raw_json, strlen(r->raw_json));
  if(root == NULL){
    return out.data ? out.data : sfcc_strdup("(no report)");
  }
  const cJSON* details = cJSON_GetObjectItemCaseSensitive(root, "details");
  if(cJSON_IsObject(details)){
    append_components(&out, details, "componentFailures", "x");
    append_components(&out, details, "componentSuccesses", "+");
    /* Test results are a compact summary; the full detail is in
     * testResults.xml inside the result zip, which is XML and deliberately not
     * parsed here. The counts are JSON *numbers*, not strings -- reading them
     * with the string helper prints "?" for every one of them. */
    const cJSON* rt = cJSON_GetObjectItemCaseSensitive(details, "runTestResult");
    if(cJSON_IsObject(rt)){
      sfcc_buf_printf(&out,
                      "\n  tests: %d passed, %d failed, %d skipped of %d run",
                      sfcc_json_int(rt, "numberPassed", -1),
                      sfcc_json_int(rt, "numberFailed", -1),
                      sfcc_json_int(rt, "numberSkipped", -1),
                      sfcc_json_int(rt, "numberTestsRun", -1));
    }
  }
  cJSON_Delete(root);
  return out.data ? out.data : sfcc_strdup("(no report)");
}

/* ------------------------------------------------------------------------ */
/* Status parsing                                                           */
/* ------------------------------------------------------------------------ */

static void parse_status(const char* body, sfcc_deploy_result* out){
  /* Keep the document regardless of whether it parses: if it does not, the raw
   * text is the only evidence of what the org actually said. */
  sfcc_strset(&out->raw_json, body);
  if(body == NULL || !*body){
    return;
  }
  cJSON* root = cJSON_ParseWithLength(body, strlen(body));
  if(root == NULL || !cJSON_IsObject(root)){
    if(root != NULL){
      cJSON_Delete(root);
    }
    return;
  }
  sfcc_strset(&out->status, sfcc_json_str(root, "status", NULL));
  out->done = sfcc_json_bool(root, "done");
  out->total = sfcc_json_int(root, "numberComponentsTotal", 0);
  out->deployed = sfcc_json_int(root, "numberComponentsDeployed", 0);
  out->errors = sfcc_json_int(root, "numberComponentsError", 0);
  out->skipped = sfcc_json_int(root, "numberComponentsSkipped", 0);
  out->succeeded = (out->status != NULL && strcmp(out->status, "Succeeded") == 0);
  if(out->status != NULL && strcmp(out->status, "Canceled") == 0){
    out->was_cancelled = 1;
  }
  cJSON_Delete(root);
}

/* ------------------------------------------------------------------------ */
/* Polling                                                                  */
/* ------------------------------------------------------------------------ */

static void sleep_seconds(long s){
  if(s <= 0){
    return;
  }
#if defined(_WIN32)
  Sleep((DWORD)(s * 1000));
#else
  struct timespec ts;
  ts.tv_sec = (time_t)s;
  ts.tv_nsec = 0;
  nanosleep(&ts, NULL);
#endif
}

/*
 * Poll until the org says it is finished, or we run out of patience.
 *
 * The deadline is honoured as a wall-clock budget rather than an iteration
 * count, so a slow poll interval cannot silently multiply the total wait.
 */
static sfcc_status poll_status(sfcc_client* c, const char* id,
                               const sfcc_deploy_options* o,
                               sfcc_deploy_result* out){
  sfcc_buf url;
  sfcc_buf_init(&url);
  sfcc_buf_puts(&url, c->instance_url);
  sfcc_buf_puts(&url, "/services/data/");
  sfcc_buf_puts(&url, c->api_version);
  sfcc_buf_puts(&url, "/metadata/deployRequest/");
  sfcc_buf_puts(&url, id);

  const long interval = o->poll_interval_s > 0 ? o->poll_interval_s
                                                : SFCC_DEPLOY_POLL_DEFAULT;
  const long budget = o->timeout_s > 0 ? o->timeout_s
                                       : SFCC_DEPLOY_TIMEOUT_DEFAULT;

  sfcc_status rc = SFCC_OK;
  const time_t start = time(NULL);
  int announced = 0;

  for(;;){
    sfcc_response resp;
    rc = sfcc_http_request(c, SFCC_HTTP_GET, url.data, c->access_token, NULL,
                           NULL, &resp);
    if(rc != SFCC_OK){
      sfcc_buf_free(&url);
      return rc;
    }
    c->last_status = resp.status;
    if(resp.status < 200 || resp.status >= 300){
      char detail[SFCC_ERRLEN_MAX];
      sfcc_json_describe_error(resp.body.data, resp.status, detail,
                               sizeof(detail));
      sfcc_response_free(&resp);
      sfcc_buf_free(&url);
      return sfcc_fail(c, resp.status == 401 ? SFCC_ERR_AUTH : SFCC_ERR_HTTP,
                       "%s", detail);
    }
    parse_status(resp.body.data, out);
    sfcc_response_free(&resp);

    if(out->done){
      break;
    }
    /* Say something once, so a long poll is not a silent hang. */
    if(!announced){
      announced = 1;
      fprintf(stderr, "  deploy %s: %s... (this can take minutes)\n", id,
              out->status ? out->status : "in progress");
    }
    if(time(NULL) - start >= budget){
      rc = sfcc_fail(c, SFCC_ERR_NET,
                     "gave up waiting after %lds; the deploy may still be "
                     "running on the org", budget);
      break;
    }
    sleep_seconds(interval);
  }

  sfcc_buf_free(&url);
  return rc;
}

/* ------------------------------------------------------------------------ */
/* Entry point                                                              */
/* ------------------------------------------------------------------------ */

sfcc_status sfcc_deploy_zip(sfcc_client* c, const char* zip_path,
                            const sfcc_deploy_options* opts_in,
                            sfcc_deploy_result* out){
  if(c == NULL || out == NULL){
    return SFCC_ERR_ARG;
  }
  memset(out, 0, sizeof(*out));

  sfcc_deploy_options o;
  sfcc_deploy_options_defaults(&o);
  if(opts_in != NULL){
    o = *opts_in;
  }
  if(o.test_level == SFCC_TEST_SPECIFIED &&
     (o.tests == NULL || !*o.tests)){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "test level \"specified\" needs a comma-separated list of "
                     "test class names");
  }

  sfcc_status rc = sfcc_ensure_auth(c);
  if(rc != SFCC_OK){
    return sfcc_fail(c, rc, "%s", sfcc_last_error(c) ? sfcc_last_error(c)
                                                     : sfcc_strerror(rc));
  }

  /* Validate locally before spending a request. */
  sfcc_buf zip;
  rc = read_zip(c, zip_path, &zip);
  if(rc != SFCC_OK){
    return rc;
  }

  char* options_json = build_options_json(&o);
  if(options_json == NULL){
    sfcc_buf_free(&zip);
    return sfcc_fail(c, SFCC_ERR_MEM, "could not build the deploy options");
  }

  sfcc_buf url;
  sfcc_buf_init(&url);
  sfcc_buf_puts(&url, c->instance_url);
  sfcc_buf_puts(&url, "/services/data/");
  sfcc_buf_puts(&url, c->api_version);
  sfcc_buf_puts(&url, "/metadata/deployRequest");

  /*
   * Two parts, both required: "json" carries the deployment options and "file"
   * carries the zip as binary. curl_mime picks the boundary, so it cannot
   * collide with the archive's contents.
   */
  curl_mime* mime = curl_mime_init((CURL*)c->curl);
  if(mime == NULL){
    sfcc_buf_free(&zip);
    sfcc_buf_free(&url);
    free(options_json);
    return sfcc_fail(c, SFCC_ERR_NET, "could not create the multipart body");
  }
  curl_mimepart* part = curl_mime_addpart(mime);
  curl_mime_name(part, "json");
  curl_mime_type(part, "application/json");
  curl_mime_data(part, options_json, CURL_ZERO_TERMINATED);

  part = curl_mime_addpart(mime);
  curl_mime_name(part, "file");
  curl_mime_filename(part, "deploy.zip");
  curl_mime_type(part, "application/zip");
  curl_mime_data(part, zip.data, zip.len);

  sfcc_response resp;
  rc = sfcc_http_request_mime(c, url.data, c->access_token, &mime, &resp);
  sfcc_buf_free(&zip);
  sfcc_buf_free(&url);
  free(options_json);
  if(rc != SFCC_OK){
    return rc;
  }

  c->last_status = resp.status;
  if(resp.status < 200 || resp.status >= 300){
    char detail[SFCC_ERRLEN_MAX];
    sfcc_json_describe_error(resp.body.data, resp.status, detail,
                             sizeof(detail));
    sfcc_response_free(&resp);
    return sfcc_fail(c, (resp.status == 401 || resp.status == 403)
                         ? SFCC_ERR_AUTH : SFCC_ERR_HTTP, "%s", detail);
  }

  /* The POST's body is the initial state; the id is all we need from it. */
  cJSON* root = cJSON_ParseWithLength(resp.body.data ? resp.body.data : "",
                                      resp.body.len);
  if(root == NULL || !cJSON_IsObject(root)){
    if(root != NULL){
      cJSON_Delete(root);
    }
    sfcc_response_free(&resp);
    return sfcc_fail(c, SFCC_ERR_JSON,
                     "deploy request did not return the expected JSON");
  }
  sfcc_strset(&out->id, sfcc_json_str(root, "id", NULL));
  cJSON_Delete(root);
  sfcc_response_free(&resp);

  if(out->id == NULL){
    return sfcc_fail(c, SFCC_ERR_JSON,
                     "the deploy was accepted but no id came back, so there is "
                     "no way to poll it");
  }

  /* Some orgs answer the POST with a finished document rather than a pending
   * one; if it already says done, there is nothing to poll. */
  if(out->status != NULL && out->done){
    out->report = render_report(out, &o);
    return SFCC_OK;
  }

  rc = poll_status(c, out->id, &o, out);
  /* A timeout still leaves a usable report and id, so the caller can see what
   * was known and check on the deploy later. Only the status code signals that
   * we stopped waiting early. */
  out->report = render_report(out, &o);
  return rc;
}

void sfcc_deploy_result_free(sfcc_deploy_result* r){
  if(r == NULL){
    return;
  }
  sfcc_strfree(&r->id);
  sfcc_strfree(&r->status);
  sfcc_strfree(&r->raw_json);
  sfcc_strfree(&r->report);
  memset(r, 0, sizeof(*r));
}
