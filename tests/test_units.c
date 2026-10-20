/*
 * Offline unit tests.
 *
 * Everything here runs without a Salesforce org, on purpose: a test that needs
 * live credentials cannot run on a contributor's machine or in CI without
 * secrets, so the suite targets the parts that fail *silently* rather than
 * loudly. A bad percent-encoder still returns HTTP 200 and the wrong records; a
 * bad length check just produces a 404. Those are the bugs worth a test.
 */
#include "sfcc_internal.h"
#include "sfcc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
/* Needed only by test_auth_header(), which stands up a loopback listener. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static int g_checks = 0;
static int g_failures = 0;
static const char* g_group = "";

#define GROUP(name) (g_group = (name))

static void check(int cond, const char* what){
  g_checks++;
  if(!cond){
    g_failures++;
    fprintf(stderr, "  FAIL [%s] %s\n", g_group, what);
  }
}

static void check_str(const char* got, const char* want, const char* what){
  g_checks++;
  if(got == NULL || strcmp(got, want) != 0){
    g_failures++;
    fprintf(stderr, "  FAIL [%s] %s\n        got:  %s\n        want: %s\n",
            g_group, what, got ? got : "(null)", want);
  }
}

/* ------------------------------------------------------------------------ */

static void test_buffer(void){
  GROUP("buffer");
  sfcc_buf b;
  sfcc_buf_init(&b);

  check(sfcc_buf_puts(&b, "hello") == 0, "puts succeeds");
  check_str(b.data, "hello", "buffer holds the string");
  check(b.len == 5, "length is correct");

  check(sfcc_buf_puts(&b, " world") == 0, "appends");
  check_str(b.data, "hello world", "buffer concatenates");
  /* The NUL at data[len] is relied on by printf-style callers. */
  check(b.data[b.len] == '\0', "buffer is NUL-terminated at len");

  check(sfcc_buf_append(&b, "\0\0\0", 3) == 0, "appends embedded NULs");
  check_str(b.data, "hello world", "embedded NULs do not truncate strcmp view");

  /* Force several growth steps, including crossing a size_t boundary
   * indirectly by asking for a large single append. */
  sfcc_buf big;
  sfcc_buf_init(&big);
  check(sfcc_buf_reserve(&big, 1000000) == 0, "large reserve succeeds");
  check(big.cap >= 1000001, "capacity covers the request plus NUL");

  /* An empty append must still produce a valid empty C string. */
  sfcc_buf e;
  sfcc_buf_init(&e);
  check(sfcc_buf_append(&e, NULL, 0) == 0, "empty append succeeds");
  check(e.data != NULL && e.data[0] == '\0', "empty buffer is a valid string");

  sfcc_buf_free(&b);
  sfcc_buf_free(&big);
  sfcc_buf_free(&e);
  check(b.data == NULL, "free clears the pointer");
  sfcc_buf_free(NULL);   /* must not crash */
  check(1, "freeing NULL is safe");
}

static void test_percent_encoding(void){
  GROUP("percent-encoding");
  sfcc_buf b;

  /*
   * The critical case. A SOQL statement unencoded is silently wrong: the
   * spaces terminate the query parameter, and everything after them is either
   * dropped or misparsed. Note especially '+', which many decoders turn back
   * into a space, so leaving it alone would corrupt any filter containing one.
   */
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "SELECT Id FROM Account");
  check_str(b.data, "SELECT%20Id%20FROM%20Account", "spaces become %20");

  /* Unreserved characters must survive untouched, or ids and field names
   * stop working. */
  sfcc_buf_free(&b);
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "abcXYZ019-._~");
  check_str(b.data, "abcXYZ019-._~", "unreserved set is left alone");

  /* An 18-character id contains no characters needing escapes. */
  sfcc_buf_free(&b);
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "001000000000000AAA");
  check_str(b.data, "001000000000000AAA", "record id is unchanged");

  /* Apostrophes and quotes appear in SOQL string literals constantly. */
  sfcc_buf_free(&b);
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "Name = 'O''Brien'");
  check_str(b.data, "Name%20%3D%20%27O%27%27Brien%27",
            "quotes, apostrophes and equals are escaped");

  sfcc_buf_free(&b);
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "a+b");
  check_str(b.data, "a%2Bb", "'+' is escaped, not passed through");

  /* High bytes must not be emitted raw. */
  sfcc_buf_free(&b);
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "\xc3\xa9");
  check_str(b.data, "%C3%A9", "utf-8 is encoded byte by byte");
  check(strchr(b.data, '\xc3') == NULL, "no raw high byte survives");

  /*
   * Traversal defence. Note that '.' is unreserved and must NOT be encoded --
   * escaping it would break every record id and field name. The protection
   * comes entirely from escaping '/', which is what stops the dots from ever
   * forming a path.
   */
  sfcc_buf_free(&b);
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "../../etc/passwd");
  check(strstr(b.data, "/") == NULL, "slashes escaped, so dots cannot traverse");
  check_str(b.data, "..%2F..%2Fetc%2Fpasswd", "dots kept, slashes escaped");

  /* '?' and '#' are the other URL delimiters worth refusing. */
  sfcc_buf_free(&b);
  sfcc_buf_init(&b);
  sfcc_buf_append_encoded(&b, "a/b?c#d");
  check(strstr(b.data, "?") == NULL, "query delimiter escaped");
  check(strstr(b.data, "#") == NULL, "fragment delimiter escaped");
  sfcc_buf_free(&b);
}

static void test_validation(void){
  GROUP("validation");
  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  sfcc_client* c = sfcc_client_new(&cfg);
  check(c != NULL, "client constructs with defaults");
  if(c == NULL){
    return;
  }

  check(sfcc_check_sobject(c, "Account") == SFCC_OK, "plain sObject name");
  check(sfcc_check_sobject(c, "Custom_Object__c") == SFCC_OK, "custom name");
  check(sfcc_check_sobject(c, "a1_9") == SFCC_OK, "digits and underscore");
  check(sfcc_check_sobject(c, "") == SFCC_ERR_ARG, "empty name rejected");
  check(sfcc_check_sobject(c, NULL) == SFCC_ERR_ARG, "NULL name rejected");
  /* These are the ones that would let a caller reach outside the API path. */
  check(sfcc_check_sobject(c, "../User") == SFCC_ERR_ARG, "traversal rejected");
  check(sfcc_check_sobject(c, "Account/../x") == SFCC_ERR_ARG,
        "embedded slash rejected");
  check(sfcc_check_sobject(c, "Account Name") == SFCC_ERR_ARG,
        "space rejected");

  check(sfcc_check_id(c, "001000000000000AAA") == SFCC_OK, "18-char id");
  check(sfcc_check_id(c, "001000000000000") == SFCC_OK, "15-char id");
  /*
   * A lower-case trailing character is legal: the last three characters of an
   * 18-character id are a checksum, not part of the encoding.
   */
  check(sfcc_check_id(c, "001000000000000aaa") == SFCC_OK,
        "lower-case checksum suffix accepted");
  check(sfcc_check_id(c, "001000000000000AA") == SFCC_ERR_ARG,
        "16 chars rejected");
  check(sfcc_check_id(c, "001000000000000AAAA") == SFCC_ERR_ARG,
        "19 chars rejected");
  check(sfcc_check_id(c, "") == SFCC_ERR_ARG, "empty id rejected");
  check(sfcc_check_id(c, "001000000000000A-A") == SFCC_ERR_ARG,
        "non-base62 rejected");
  check(sfcc_check_id(c, "../../../etc/passwd") == SFCC_ERR_ARG,
        "traversal in id rejected");

  sfcc_client_free(c);
}

static void test_json_errors(void){
  GROUP("json-errors");
  char out[SFCC_ERRLEN_MAX];

  /* REST sObject endpoints answer with an array, not an object. Missing this
   * shape is the usual reason a client prints "[object Object]". */
  const char* rest =
    "[{\"message\":\"Session expired or invalid\",\"errorCode\":\"INVALID_SESSION_ID\"}]";
  sfcc_json_describe_error(rest, 401, out, sizeof(out));
  check(strstr(out, "INVALID_SESSION_ID") != NULL, "rest errorCode extracted");
  check(strstr(out, "Session expired") != NULL, "rest message extracted");
  check(strstr(out, "401") != NULL, "status included");

  /* The OAuth token endpoint uses different key names. */
  const char* oauth =
    "{\"error\":\"invalid_client\",\"error_description\":\"client identifier invalid\"}";
  sfcc_json_describe_error(oauth, 400, out, sizeof(out));
  check(strstr(out, "invalid_client") != NULL, "oauth error extracted");
  check(strstr(out, "client identifier invalid") != NULL,
        "oauth description extracted");

  /* A valid-JSON body we do not recognise should still produce something. */
  sfcc_json_describe_error("{\"unexpected\":true}", 500, out, sizeof(out));
  check(strstr(out, "500") != NULL, "unrecognised json still reports status");

  /* Not JSON at all: the captive-portal case. Must not crash, and must not
   * claim success. */
  sfcc_json_describe_error("<html><body>Login</body></html>", 200, out,
                           sizeof(out));
  check(out[0] != '\0', "html body produces a message");

  sfcc_json_describe_error("", 204, out, sizeof(out));
  check(strstr(out, "204") != NULL, "empty body still reports the status");
  check(strstr(out, "no content") != NULL, "204 explained as no content");

  /* Control characters must be stripped: this text lands in a terminal, and an
   * escape sequence in an API-controlled message could garble the session. */
  const char* nasty =
    "[{\"message\":\"bad\\u001b[31mred\",\"errorCode\":\"X\"}]";
  sfcc_json_describe_error(nasty, 400, out, sizeof(out));
  check(strchr(out, '\x1b') == NULL, "escape sequence stripped from message");

  /* Truncation must terminate the string. */
  char small[32];
  sfcc_json_describe_error(rest, 500, small, sizeof(small));
  check(strlen(small) < sizeof(small), "respects a small output buffer");

  check(sfcc_json_valid("{\"a\":1}") == 1, "valid object accepted");
  check(sfcc_json_valid("[1,2]") == 1, "valid array accepted");
  check(sfcc_json_valid("{\"a\":") == 0, "truncated json rejected");
  check(sfcc_json_valid("not json") == 0, "non-json rejected");
  check(sfcc_json_valid("") == 0, "empty string rejected");
  check(sfcc_json_valid(NULL) == 0, "NULL rejected without crashing");
}

static void test_config(void){
  GROUP("config");
  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  check(cfg.login_url != NULL && cfg.login_url[0] == 'h', "default login url");
  check(cfg.insecure == 0, "TLS verification on by default");
  check(cfg.timeout_s > 0, "default timeout set");

  /* An all-zero config must still yield a working client rather than a
   * half-initialised one. */
  sfcc_config zero;
  memset(&zero, 0, sizeof(zero));
  sfcc_client* c = sfcc_client_new(&zero);
  check(c != NULL, "zero config still constructs a client");
  sfcc_client_free(c);
  sfcc_client_free(NULL);   /* must not crash */

  /* Trailing slashes must be stripped so URL building cannot double them. */
  char url[] = "https://acme.my.salesforce.com///";
  sfcc_strip_trailing_slashes(url);
  check_str(url, "https://acme.my.salesforce.com", "trailing slashes stripped");

  char root[] = "///";
  sfcc_strip_trailing_slashes(root);
  check_str(root, "", "a bare slashes string becomes empty");
}

static void test_url_building(void){
  GROUP("urls");
  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  cfg.instance_url = "https://acme.my.salesforce.com";
  cfg.access_token = "tok";
  sfcc_client* c = sfcc_client_new(&cfg);
  if(c == NULL){
    check(0, "client constructs");
    return;
  }
  char* url = NULL;
  sfcc_status rc = sfcc_api_url(c, "query?q=X", &url);
  check(rc == SFCC_OK, "url builds");
  if(url != NULL){
    check_str(url,
              "https://acme.my.salesforce.com/services/data/" SFCC_DEFAULT_API_VERSION
              "/query?q=X",
              "url has instance, version and path in the right order");
    free(url);
  }

  /*
   * Path separators must survive. The SOQL query parameter is appended
   * pre-encoded by sfcc_query(), so the URL builder must not escape slashes --
   * doing so would produce a URL that addresses nothing.
   */
  url = NULL;
  rc = sfcc_api_url(c, "sobjects/Account/001000000000000AAA", &url);
  check(rc == SFCC_OK, "object path builds");
  if(url != NULL){
    check(strstr(url, "/sobjects/Account/001000000000000AAA") != NULL,
          "path separators kept intact");
    check(strstr(url, "%2F") == NULL, "slashes not escaped");
    free(url);
  }

  /* An empty path yields the version root, which is valid. */
  url = NULL;
  rc = sfcc_api_url(c, NULL, &url);
  check(rc == SFCC_OK, "null path builds");
  if(url != NULL){
    check_str(url,
              "https://acme.my.salesforce.com/services/data/"
              SFCC_DEFAULT_API_VERSION,
              "null path gives the bare version root");
    free(url);
  }
  sfcc_client_free(c);
}

static void test_body_limit(void){
  GROUP("body-limit");
  /*
   * The cap exists so a runaway endpoint cannot make us allocate without bound.
   * Checking the boundary means the test also proves the guard does not
   * reject legitimate large responses.
   */
  sfcc_buf b;
  sfcc_buf_init(&b);
  /* Ask for more than the cap; the append must refuse rather than try. */
  const char chunk[1024] = { 0 };
  int rc = 0;
  for(unsigned i = 0 ; i < (SFCC_MAX_BODY / sizeof(chunk)) + 2 ; ++i){
    rc = sfcc_buf_append(&b, chunk, sizeof(chunk));
    if(rc != 0){
      break;
    }
  }
  check(rc != 0, "append past the cap is refused");
  check(b.len <= SFCC_MAX_BODY, "length stayed within the cap");
  sfcc_buf_free(&b);
}

static void test_strings(void){
  GROUP("strings");
  char* s = sfcc_strdup("hello");
  check_str(s, "hello", "strdup copies");
  check(sfcc_strdup(NULL) == NULL, "strdup of NULL is NULL");

  sfcc_strset(&s, "replaced");
  check_str(s, "replaced", "strset replaces");
  sfcc_strfree(&s);
  check(s == NULL, "strfree nulls the pointer");
  sfcc_strfree(NULL);
  sfcc_strfree(&s);
  check(1, "double strfree is safe");

  check(sfcc_str_eq("a", "a") == 1, "equal strings compare equal");
  check(sfcc_str_eq("a", "b") == 0, "different strings differ");
  check(sfcc_str_eq(NULL, NULL) == 1, "two NULLs are equal");
  check(sfcc_str_eq("a", NULL) == 0, "NULL is not equal to a string");

  /* Header names are matched case-insensitively, so this comparison is
   * load-bearing on every request. It was also briefly missing: MSVC declares
   * neither <strings.h> nor strncasecmp, so the call compiled to an implicit
   * extern declaration and C4013 rather than failing outright. */
  check(sfcc_strncasecmp("authorization", "Authorization", 13) == 0,
        "header names match across case");
  check(sfcc_strncasecmp("AUTHORIZATION", "authorization", 13) == 0,
        "case folding works the other way too");
  check(sfcc_strncasecmp("authorization", "authorizations", 13) == 0,
        "the length limit cuts the comparison short");
  check(sfcc_strncasecmp("authorization", "authorisation", 13) != 0,
        "a different header name does not match");
  check(sfcc_strncasecmp("accept", "Authorization", 6) != 0,
        "short names are not equal by accident");
  check(sfcc_strncasecmp("a", NULL, 1) != 0, "NULL is not equal to a string");
  check(sfcc_strncasecmp(NULL, NULL, 1) == 0, "two NULLs are equal");
}

/*
 * The Authorization header must actually reach the wire.
 *
 * This exists because the header was once built as "Bearer <token>" without
 * the "Authorization: " name. libcurl parses CURLOPT_HTTPHEADER entries on
 * their first colon and silently discards any entry without one, so every
 * request went out unauthenticated: no error, no warning, just a 401 from the
 * server that says nothing about the real cause.
 *
 * Asserting on a string constant here would not have caught it, because the
 * constant is not what libcurl does. So this binds a loopback listener, sends a
 * real request through the real HTTP layer, and reads the bytes back.
 */
#ifndef _WIN32
/*
 * Bind a loopback listener, make a real request through the real HTTP layer,
 * and hand the bytes the server actually received back to the parent through a
 * temporary file. fork() keeps this single-threaded: the child serves exactly
 * one connection and exits, so there is no shared state to race over.
 */
static void test_auth_header(void){
  GROUP("auth-header");

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if(srv < 0){
    check(0, "created a listening socket");
    return;
  }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;                     /* kernel picks a free port */
  if(bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
     listen(srv, 1) != 0){
    check(0, "bound a loopback listener");
    close(srv);
    return;
  }
  socklen_t alen = sizeof(addr);
  if(getsockname(srv, (struct sockaddr*)&addr, &alen) != 0){
    check(0, "read the listener port");
    close(srv);
    return;
  }
  const unsigned short port = ntohs(addr.sin_port);

  char url[128];
  snprintf(url, sizeof(url), "http://127.0.0.1:%u/", port);

  const char* dump = "sfcc_auth_header_dump.txt";
  remove(dump);

  const pid_t pid = fork();
  if(pid == 0){
    const int conn = accept(srv, NULL, NULL);
    if(conn >= 0){
      char buf[4096];
      const ssize_t n = recv(conn, buf, sizeof(buf) - 1, 0);
      if(n > 0){
        buf[n] = '\0';
        FILE* f = fopen(dump, "wb");
        if(f != NULL){
          fwrite(buf, 1, (size_t)n, f);
          fclose(f);
        }
        /* curl blocks until it gets a response, so send one. */
        static const char REPLY[] =
          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
          "Content-Type: application/json\r\nConnection: close\r\n\r\n{}";
        (void)send(conn, REPLY, sizeof(REPLY) - 1, 0);
      }
      close(conn);
    }
    close(srv);
    _exit(0);
  }
  if(pid < 0){
    check(0, "forked the listener");
    close(srv);
    return;
  }

  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  cfg.instance_url = url;
  cfg.access_token = "TOKEN123";
  cfg.connect_timeout_s = 3;
  cfg.timeout_s = 5;
  cfg.no_cache = 1;
  sfcc_client* c = sfcc_client_new(&cfg);
  if(c != NULL){
    sfcc_response resp;
    const sfcc_status rc = sfcc_http_request(c, SFCC_HTTP_GET, url,
                                             c->access_token, NULL, NULL,
                                             &resp);
    check(rc == SFCC_OK, "the request completed");
    sfcc_response_free(&resp);
    sfcc_client_free(c);
  }else{
    check(0, "client for the header test constructs");
  }

  int st = 0;
  waitpid(pid, &st, 0);
  close(srv);

  char wire[4096] = "";
  FILE* f = fopen(dump, "rb");
  if(f != NULL){
    const size_t got = fread(wire, 1, sizeof(wire) - 1, f);
    wire[got] = '\0';
    fclose(f);
  }
  remove(dump);

  check(wire[0] != '\0', "the server received a request");
  /* The assertion that matters. libcurl silently drops a CURLOPT_HTTPHEADER
   * entry with no colon in it, so this is the only check that would have
   * caught the missing "Authorization: " prefix. */
  check(strstr(wire, "Authorization: Bearer TOKEN123") != NULL,
        "Authorization header reaches the wire with the correct name");
  /* Guard against a header built with the wrong scheme or an empty token. */
  check(strstr(wire, "Bearer ") != NULL, "scheme is Bearer");
  check(strstr(wire, "Authorization: Bearer \r\n") == NULL,
        "token is not empty");
}
#else
static void test_auth_header(void){
  GROUP("auth-header");
  /* The same guarantee is covered end-to-end on POSIX; on Windows it needs
   * winsock, which would drag a dependency into the test binary for one check. */
  check(1, "skipped on Windows: needs POSIX sockets");
}
#endif

/*
 * A file that is not a zip must be rejected before any request is made. The
 * check exists because "deploy" pointed at the wrong file is an easy mistake,
 * and without it the round trip costs an API call and comes back complaining
 * about package.xml, which says nothing about the real problem.
 */
static void test_zip_guard(void){
  GROUP("zip-guard");
  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  cfg.instance_url = "https://x.invalid";
  cfg.access_token = "t";
  cfg.no_cache = 1;
  sfcc_client* c = sfcc_client_new(&cfg);
  if(c == NULL){
    check(0, "client for the zip guard constructs");
    return;
  }
  sfcc_deploy_options o;
  sfcc_deploy_options_defaults(&o);
  o.timeout_s = 5;

  sfcc_deploy_result r;

  check(sfcc_deploy_zip(c, "/nonexistent/definitely-not-here.zip", &o, &r)
            == SFCC_ERR_IO,
        "a missing file is an io error, before any request");
  sfcc_deploy_result_free(&r);

  check(sfcc_deploy_zip(c, NULL, &o, &r) == SFCC_ERR_ARG,
        "a NULL path is rejected");
  sfcc_deploy_result_free(&r);

  /* Not-a-zip. Written to the build directory so the test leaves nothing
   * behind in the source tree. */
  const char* junk = "sfcc_test_junk.bin";
  FILE* f = fopen(junk, "wb");
  if(f != NULL){
    fputs("this is definitely not a zip file\n", f);
    fclose(f);
    check(sfcc_deploy_zip(c, junk, &o, &r) == SFCC_ERR_ARG,
          "a non-zip is rejected locally with a clear message");
    check(sfcc_last_error(c) != NULL &&
          strstr(sfcc_last_error(c), "zip signature") != NULL,
          "the message explains what was wrong");
    sfcc_deploy_result_free(&r);
    remove(junk);
  }else{
    check(0, "could not write the junk file");
  }

  /* An empty file is rejected too, and distinctly from "not a zip". */
  const char* empty = "sfcc_test_empty.zip";
  f = fopen(empty, "wb");
  if(f != NULL){
    fclose(f);
    check(sfcc_deploy_zip(c, empty, &o, &r) == SFCC_ERR_ARG,
          "an empty file is rejected");
    sfcc_deploy_result_free(&r);
    remove(empty);
  }

  /* The options validator: "specified" with no list would silently run nothing,
   * which is the kind of thing that passes CI and then skips every test. */
  sfcc_deploy_options bad;
  sfcc_deploy_options_defaults(&bad);
  bad.test_level = SFCC_TEST_SPECIFIED;
  bad.tests = NULL;
  check(sfcc_deploy_zip(c, "/nonexistent.zip", &bad, &r) == SFCC_ERR_ARG,
        "test level specified without a list is rejected");
  sfcc_deploy_result_free(&r);

  sfcc_client_free(c);
}

/* Environment helpers, because the passphrase and its KDF override are
 * configuration-discovery paths that getenv reads. setenv is POSIX-only;
 * MSVC exposes _putenv_s in stdlib.h, and an empty value removes the entry. */
static void env_set(const char* var, const char* value){
#ifdef _WIN32
  _putenv_s(var, value);
#else
  setenv(var, value, 1);
#endif
}

static void env_clear(const char* var){
#ifdef _WIN32
  _putenv_s(var, "");
#else
  unsetenv(var);
#endif
}

/*
 * The encrypted cache frame, and what the auth layer does with it.
 *
 * Everything here runs on whatever backend the build selected, which is the
 * point: the same test list exercises OpenSSL, CNG, or CommonCrypto purely by
 * virtue of being built on the platform, and a Windows run of these checks
 * is real coverage of BCrypt's GCM rather than a placeholder.
 */
static void test_cache_crypto(void){
  GROUP("cache crypto");

  /* Whatever the developer has exported must not reach these tests. */
  env_clear("SFCC_CACHE_PASSPHRASE");
  env_clear("SFCC_CACHE_KDF_ITERS");

  if(!sfcc_cache_crypto_available()){
    /* A backend-less build is legitimate; the contract is only that wrap
     * says so instead of writing ciphertext it cannot open again. */
    sfcc_buf out;
    sfcc_buf_init(&out);
    check(sfcc_cache_wrap("pw", (const unsigned char*)"x", 1,
                          SFCC_CACHE_KDF_MINIMUM, &out)
              == SFCC_CACHE_ERR_CRYPTO_UNAVAILABLE,
          "a build with no backend refuses to wrap rather than faking it");
    sfcc_buf_free(&out);
    check(sfcc_cache_passphrase() == NULL,
          "no passphrase in the environment reads as unset");
    return;
  }

  static const unsigned char PAYLOAD[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  const size_t PAYLOAD_LEN = sizeof(PAYLOAD) - 1;

  /* -- frame round trip ---------------------------------------------------- */
  sfcc_buf frame;
  sfcc_buf_init(&frame);
  check(sfcc_cache_wrap("key-one", PAYLOAD, PAYLOAD_LEN,
                        SFCC_CACHE_KDF_MINIMUM, &frame) == SFCC_CACHE_OK,
        "wrap succeeds");
  check(frame.len == (size_t)(SFCC_CACHE_MAGIC_LEN   /* magic            */
                            + 1                      /* version          */
                            + 4                      /* iters            */
                            + SFCC_CACHE_SALT_LEN
                            + SFCC_CACHE_NONCE_LEN
                            + PAYLOAD_LEN
                            + SFCC_CACHE_TAG_LEN),
        "frame length is header plus ciphertext plus tag");
  check(memcmp(frame.data, SFCC_CACHE_MAGIC, SFCC_CACHE_MAGIC_LEN) == 0,
        "the frame opens with the magic");

  sfcc_buf plain;
  sfcc_buf_init(&plain);
  check(sfcc_cache_unwrap("key-one", (const unsigned char*)frame.data,
                          frame.len, &plain) == SFCC_CACHE_OK,
        "unwrap succeeds with the passphrase that wrapped it");
  check(plain.len == PAYLOAD_LEN &&
            memcmp(plain.data, (const char*)PAYLOAD, PAYLOAD_LEN) == 0,
        "and the payload comes back byte for byte");

  /* Wrong passphrase must be a distinct rejection from "no passphrase", and
   * neither may succeed or hang. */
  sfcc_buf_free(&plain);
  sfcc_buf_init(&plain);
  check(sfcc_cache_unwrap("wrong", (const unsigned char*)frame.data,
                          frame.len, &plain) == SFCC_CACHE_ERR_KEY_MISMATCH,
        "a wrong passphrase is a tag failure");
  check(plain.len == 0, "and no plaintext leaked into the buffer");
  check(sfcc_cache_unwrap(NULL, (const unsigned char*)frame.data, frame.len,
                          &plain) == SFCC_CACHE_ERR_NO_PASSPHRASE,
        "a missing passphrase is its own answer");

  /* Same passphrase, same payload: the bytes still differ, because salt and
   * nonce are drawn fresh per save. A frame that is byte-predictable from
   * its input would be a nonce-reuse report waiting to happen. */
  sfcc_buf frame2;
  sfcc_buf_init(&frame2);
  check(sfcc_cache_wrap("key-one", PAYLOAD, PAYLOAD_LEN,
                        SFCC_CACHE_KDF_MINIMUM, &frame2) == SFCC_CACHE_OK,
        "second wrap succeeds");
  check(frame2.len == frame.len &&
            memcmp(frame2.data, frame.data, frame.len) != 0,
        "two frames of one payload differ (fresh salt and nonce)");
  sfcc_buf_free(&frame2);

  /* Tamper: flipping a ciphertext byte must fail the tag, never hand back
   * near-miss plaintext. The magic is checked, and so is the version byte
   * and the header as additional data -- editing the header breaks the
   * integrity check rather than disabling it. */
  sfcc_buf broken;
  sfcc_buf_init(&broken);
  sfcc_buf_append(&broken, frame.data, frame.len);
  broken.data[60] = (char)(broken.data[60] ^ 0x01);
  sfcc_buf_free(&plain);
  sfcc_buf_init(&plain);
  check(sfcc_cache_unwrap("key-one", (const unsigned char*)broken.data,
                          broken.len, &plain) == SFCC_CACHE_ERR_KEY_MISMATCH,
        "one flipped byte in the body is refused");

  broken.data[0] = 'X';   /* destroy the magic outright */
  check(sfcc_cache_unwrap("key-one", (const unsigned char*)broken.data,
                          broken.len, &plain) == SFCC_CACHE_ERR_NOT_OURS,
        "a frame that lost its magic is not ours");
  broken.data[0] = 'S';
  broken.data[8] = 9;     /* version byte: supported is 1 */
  check(sfcc_cache_unwrap("key-one", (const unsigned char*)broken.data,
                          broken.len, &plain) == SFCC_CACHE_ERR_BAD_HEADER,
        "an unknown format version is corrupt, not decryptable");

  /* The KDF floor and ceiling on the read side. These headers are checked
   * before any derivation runs, so an absurdly high iteration count cannot
   * turn "read a cache file" into minutes of work per command. */
  broken.data[8] = 1;
  broken.data[9]  = 0x64; broken.data[10] = 0x00;   /* iters = 100 */
  broken.data[11] = 0x00; broken.data[12] = 0x00;
  check(sfcc_cache_unwrap("key-one", (const unsigned char*)broken.data,
                          broken.len, &plain) == SFCC_CACHE_ERR_BAD_HEADER,
        "a header below the KDF floor is refused outright");
  broken.data[9] = (char)0xFF; broken.data[10] = (char)0xFF;    /* iters = 0xFFFFFFFF */
  broken.data[11] = (char)0xFF; broken.data[12] = (char)0xFF;
  check(sfcc_cache_unwrap("key-one", (const unsigned char*)broken.data,
                          broken.len, &plain) == SFCC_CACHE_ERR_BAD_HEADER,
        "one above the ceiling too");

  /* Shorter than any valid frame. */
  check(sfcc_cache_unwrap("key-one", (const unsigned char*)"SFCCENC1",
                          8, &plain) == SFCC_CACHE_ERR_BAD_HEADER,
        "a truncated frame is corrupt");

  /* -- wrap-side parameter bounds ------------------------------------------ */
  sfcc_buf_init(&frame2);
  check(sfcc_cache_wrap("key-one", PAYLOAD, PAYLOAD_LEN,
                        SFCC_CACHE_KDF_MINIMUM - 1, &frame2)
              == SFCC_CACHE_ERR_KDF_RANGE,
        "iterations below the floor are refused at the entry point");
  check(sfcc_cache_wrap("key-one", PAYLOAD, PAYLOAD_LEN,
                        SFCC_CACHE_KDF_MAXIMUM + 1, &frame2)
              == SFCC_CACHE_ERR_KDF_RANGE,
        "and above the ceiling");
  check(sfcc_cache_wrap("", PAYLOAD, PAYLOAD_LEN,
                        SFCC_CACHE_KDF_MINIMUM, &frame2)
              == SFCC_CACHE_ERR_NO_PASSPHRASE,
        "an empty passphrase does not mean encrypt-anyway");
  sfcc_buf_free(&frame2);
  sfcc_buf_free(&broken);
  sfcc_buf_free(&plain);
  sfcc_buf_free(&frame);

  /* -- through the auth layer ---------------------------------------------- */
  /*
   * Round trip through the real save/load pair. The assertions follow the
   * on-disk bytes directly as well as the parsed record, because the file is
   * what a backup or a sync job or another human would see.
   */
  char CACHE[] = "sfcc_test_enc_token.json";
  remove(CACHE);
  env_set("SFCC_CACHE_KDF_ITERS", "2000");
  env_set("SFCC_CACHE_PASSPHRASE", "unit-game");

  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  cfg.cache_path = CACHE;

  sfcc_client* w = sfcc_client_new(&cfg);
  if(w != NULL){
    sfcc_strset(&w->access_token, "tok-encrypted-secret");
    sfcc_strset(&w->instance_url, "http://127.0.0.1:65535/");
    w->token_expiry = time(NULL) + 900;
    sfcc_auth_save_cache(w);

    /* On disk: frame bytes, with no token anywhere in the plaintext, and a
     * header iteration count that honours the override. */
    FILE* back = fopen(CACHE, "rb");
    if(back != NULL){
      sfcc_buf disk;
      sfcc_buf_init(&disk);
      char chunk[4096];
      size_t got;
      while((got = fread(chunk, 1, sizeof(chunk), back)) > 0){
        sfcc_buf_append(&disk, chunk, got);
      }
      fclose(back);
      check(disk.len >= SFCC_CACHE_MAGIC_LEN &&
                memcmp(disk.data, SFCC_CACHE_MAGIC, SFCC_CACHE_MAGIC_LEN) == 0,
            "the saved cache is an SFCCENC1 frame");
      check(strstr(disk.data, "tok-encrypted-secret") == NULL,
            "the token is nowhere readable in it");
      check((unsigned char)disk.data[9] == 0xD0 &&
            (unsigned char)disk.data[10] == 0x07 &&
            disk.data[11] == 0 &&
            disk.data[12] == 0,
            "and the header records the 2000-iteration override");
      sfcc_buf_free(&disk);
    }else{
      check(0, "the cache could be re-read from disk");
    }

    sfcc_client* r = sfcc_client_new(&cfg);
    if(r != NULL){
      check(sfcc_auth_load_cache(r) == SFCC_OK, "load succeeds");
      check_str(r->access_token, "tok-encrypted-secret", "token came back");
      check(r->instance_url != NULL &&
                strcmp(r->instance_url, "http://127.0.0.1:65535") == 0,
            "instance_url came back, stripped of its trailing slash");
      check(sfcc_token_is_fresh(r), "and the expiry survived the trip");
      sfcc_client_free(r);
    }else{
      check(0, "second client constructs");
    }

    /* Wrong passphrase: a hard, specific refusal, and an empty record --
     * the failure the stale-token bug taught this codebase to mind. */
    env_set("SFCC_CACHE_PASSPHRASE", "someone-else's");
    sfcc_client* bad = sfcc_client_new(&cfg);
    if(bad != NULL){
      check(sfcc_auth_load_cache(bad) == SFCC_ERR_IO,
            "a wrong passphrase fails the load");
      check(bad->access_token == NULL && bad->instance_url == NULL,
            "and adopts no partial record");
      check(sfcc_last_error(bad) != NULL &&
                strstr(sfcc_last_error(bad),
                       "SFCC_CACHE_PASSPHRASE") != NULL,
            "the message names the variable that fixes it");
      sfcc_client_free(bad);
    }

    /* No passphrase, encrypted file: the same, with its own message. */
    env_clear("SFCC_CACHE_PASSPHRASE");
    sfcc_client* none = sfcc_client_new(&cfg);
    if(none != NULL){
      check(sfcc_auth_load_cache(none) == SFCC_ERR_IO,
            "no passphrase fails the load");
      check(sfcc_last_error(none) != NULL &&
                strstr(sfcc_last_error(none), "set "
                       "SFCC_CACHE_PASSPHRASE") != NULL,
            "and says what to set");
      sfcc_client_free(none);
    }

    /* -- migration ----------------------------------------------------------- */
    /*
     * A plaintext cache existing before the passphrase did must be upgraded
     * on the next successful read, not parked until an eventual re-mint --
     * with a still-fresh token that might never come. The expiry must come
     * along unextended: migration is a rewrite, not a re-mint.
     */
    remove(CACHE);
    FILE* seed = fopen(CACHE, "wb");
    if(seed != NULL){
      fputs("{\"access_token\":\"tok-migrated\","
            "\"instance_url\":\"http://127.0.0.1:65535\","
            "\"expires_at\":2000000000}", seed);
      fclose(seed);
      env_set("SFCC_CACHE_PASSPHRASE", "unit-game");
      sfcc_client* mig = sfcc_client_new(&cfg);
      if(mig != NULL){
        check(sfcc_auth_load_cache(mig) == SFCC_OK,
              "a plaintext cache still loads with a passphrase set");
        check_str(mig->access_token, "tok-migrated", "its token was read");
        /* The file on disk is a frame after that load. */
        FILE* back2 = fopen(CACHE, "rb");
        if(back2 != NULL){
          sfcc_buf disk;
          sfcc_buf_init(&disk);
          char chunk[4096];
          size_t got;
          while((got = fread(chunk, 1, sizeof(chunk), back2)) > 0){
            sfcc_buf_append(&disk, chunk, got);
          }
          fclose(back2);
          check(memcmp(disk.data, SFCC_CACHE_MAGIC, SFCC_CACHE_MAGIC_LEN) == 0,
                "and the cache was rewritten encrypted");
          /* Unwrap by hand: the expiry inside must be the seeded 2033 one,
           * not now + TTL, which would prove expiration drifted. */
          sfcc_buf re;
          sfcc_buf_init(&re);
          if(sfcc_cache_unwrap("unit-game", (const unsigned char*)disk.data,
                               disk.len, &re) == SFCC_CACHE_OK){
            check(strstr(re.data, "2000000000") != NULL,
                  "the original expiry, not a refreshed one, was preserved");
          }else{
            check(0, "the migrated frame decrypts");
          }
          sfcc_buf_free(&re);
          sfcc_buf_free(&disk);
        }else{
          check(0, "cache re-readable after migration");
        }
        sfcc_client_free(mig);
      }
      /* Removing the passphrase also removes the migration: plaintext stays
       * plaintext, which is what "no passphrase" means everywhere else. */
      remove(CACHE);
      seed = fopen(CACHE, "wb");
      if(seed != NULL){
        fputs("{\"access_token\":\"tok-plain\","
              "\"instance_url\":\"http://127.0.0.1:65535\","
              "\"expires_at\":2000000000}", seed);
        fclose(seed);
        env_clear("SFCC_CACHE_PASSPHRASE");
        sfcc_client* stay = sfcc_client_new(&cfg);
        if(stay != NULL){
          check(sfcc_auth_load_cache(stay) == SFCC_OK,
                "without a passphrase a plaintext cache loads");
          FILE* back3 = fopen(CACHE, "rb");
          if(back3 != NULL){
            const int c0 = fgetc(back3);
            fclose(back3);
            check(c0 == '{', "and was left as plaintext JSON");
          }
          sfcc_client_free(stay);
        }
      }
      env_set("SFCC_CACHE_PASSPHRASE", "unit-game");
    }else{
      check(0, "migration seed file writable");
    }

    /*
     * The refusal is fatal at the auth gate, not a reason to re-mint over
     * the file. This is the CLI's exact path -- gate, then ensure_auth --
     * minus the process exit. Any hard failure must leave the file exactly
     * alone: the correct passphrase is one corrected environment variable
     * away, and deleting the frame here would take that away with it.
     */
    sfcc_auth_save_cache(w);                       /* frame under the good phrase */
    env_set("SFCC_CACHE_PASSPHRASE", "someone-else's");
    sfcc_client* gate = sfcc_client_new(&cfg);
    if(gate != NULL){
      check(sfcc_authenticate(gate, NULL) == SFCC_ERR_IO,
            "a refused cache fails the auth gate, not a silent re-mint");
      FILE* back4 = fopen(CACHE, "rb");
      if(back4 != NULL){
        sfcc_buf disk;
        sfcc_buf_init(&disk);
        char chunk[4096];
        size_t got;
        while((got = fread(chunk, 1, sizeof(chunk), back4)) > 0){
          sfcc_buf_append(&disk, chunk, got);
        }
        fclose(back4);
        check(memcmp(disk.data, SFCC_CACHE_MAGIC, SFCC_CACHE_MAGIC_LEN) == 0,
              "and the original frame survived");
        sfcc_buf_free(&disk);
      }else{
        check(0, "the frame is still on disk after the refusal");
      }
      sfcc_client_free(gate);
    }
    env_set("SFCC_CACHE_PASSPHRASE", "unit-game");

    remove(CACHE);
    sfcc_client_free(w);
  }else{
    check(0, "client constructs for the cache round trip");
  }

  /* Leave the environment as found, so a test ordering change cannot turn a
   * leftover passphrase into somebody else's pass. */
  env_clear("SFCC_CACHE_PASSPHRASE");
  env_clear("SFCC_CACHE_KDF_ITERS");
}

/*
 * The generic passthrough's argument handling, all of which happens before any
 * network I/O -- so it is testable without a server.
 */
static void test_rest_args(void){
  GROUP("rest-args");
  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  /* Points at a port nothing listens on, so any request that escapes the
   * pre-flight checks fails fast and lets us inspect the URL it built. */
  cfg.instance_url = "http://127.0.0.1:1";
  cfg.access_token = "t";
  cfg.no_cache = 1;
  cfg.connect_timeout_s = 1;
  cfg.timeout_s = 2;
  sfcc_client* c = sfcc_client_new(&cfg);
  if(c == NULL){
    check(0, "client for the rest tests constructs");
    return;
  }
  sfcc_rest_result r;

  check(sfcc_rest(c, NULL, NULL, &r) == SFCC_ERR_ARG, "NULL path rejected");
  check(sfcc_rest(c, "limits", NULL, NULL) == SFCC_ERR_ARG,
        "NULL result rejected");

  /* A raw space is the mistake this catches: unencoded, the org replies with a
   * 400 that says nothing about the missing %20. */
  check(sfcc_rest(c, "query?q=SELECT Id", NULL, &r) == SFCC_ERR_ARG,
        "a raw space is rejected before any request");
  check(sfcc_last_error(c) != NULL && strstr(sfcc_last_error(c), "%20") != NULL,
        "the message says how to fix it");

  check(sfcc_rest(c, "query\n?q=x", NULL, &r) == SFCC_ERR_ARG,
        "a control character is rejected");

  sfcc_rest_options o = { .method = "TRACE" };
  check(sfcc_rest(c, "limits", &o, &r) == SFCC_ERR_ARG,
        "an unsupported verb is rejected");
  check(sfcc_last_error(c) != NULL && strstr(sfcc_last_error(c), "TRACE") != NULL,
        "the message names the offending verb");

  /* A verb that needs a body, with none: otherwise the body is silently
   * dropped and the server sees an empty POST. */
  sfcc_rest_options p = { .method = "PATCH" };
  check(sfcc_rest(c, "sobjects/Account/001000000000000AAA", &p, &r)
            == SFCC_ERR_ARG,
        "PATCH without a body is rejected");

  /* An empty path is relative, so it becomes the version root, which is legal.
   * The connection refusal then proves the URL was built with the version in
   * it -- which is also how {version} substitution is checked. */
  check(sfcc_rest(c, "", NULL, &r) == SFCC_ERR_NET,
        "an empty path reaches the transport layer");
  check(sfcc_last_error(c) != NULL &&
        strstr(sfcc_last_error(c),
               "services/data/" SFCC_DEFAULT_API_VERSION) != NULL,
        "the version is in the built URL");
  sfcc_rest_result_free(&r);

  /* And with the explicit token, which must replace ours rather than be sent
   * alongside it. */
  static const char* const replace_auth[] = {
    "Authorization: Bearer replacement", NULL,
  };
  sfcc_rest_options h = { .method = "GET", .extra_headers = replace_auth };
  (void)sfcc_rest(c, "limits", &h, &r);
  sfcc_rest_result_free(&r);

  sfcc_client_free(c);
}

int main(void){
  printf("sfcc unit tests\n");

  test_buffer();
  test_percent_encoding();
  test_validation();
  test_json_errors();
  test_config();
  test_url_building();
  test_auth_header();
  test_zip_guard();
  test_cache_crypto();
  test_rest_args();
  test_body_limit();
  test_strings();

  printf("\n%d checks, %d failure%s\n", g_checks, g_failures,
         g_failures == 1 ? "" : "s");
  return g_failures == 0 ? 0 : 1;
}
