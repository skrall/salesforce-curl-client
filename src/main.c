/*
 * sfcc -- command-line front end.
 *
 * Argument handling is done by hand rather than with getopt, for two reasons:
 * getopt is not on Windows without a POSIX compatibility layer, and this way
 * the same code compiles everywhere the library does. The cost is about eighty
 * lines, which is cheaper than a dependency.
 *
 * The secret is deliberately *not* accepted as a command-line flag. Arguments
 * are visible to every process on the machine through ps and /proc, so a
 * consumer secret passed that way leaks to anything running as the same user.
 * It comes from the environment only.
 */
#include "sfcc.h"
#include "sfcc_internal.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <io.h>      /* _isatty, _setmode, _fileno */
#include <fcntl.h>   /* _O_BINARY */
#else
#include <unistd.h>  /* isatty, fileno */
#endif

#define SFCC_PROGNAME "sfcc"

static int g_raw_output = 0;
static int g_quiet = 0;
/* Presentation, not a per-command choice: every table in the client
 * honours it. It was a field in each command's option struct, which
 * meant the flag only reached whichever command's struct the parser
 * happened to write to -- `describe --no-header` silently kept its
 * headers. */
static int g_no_header = 0;

/* ------------------------------------------------------------------------ */

/* Emitted as a sequence of fputs rather than one fprintf.
 *
 * A single string literal has to fit inside what ISO C guarantees -- 4095
 * characters after concatenation -- and the help text had reached 4228, which
 * gcc rejects under -Werror as -Woverlength-strings. Chunking it is the fix
 * rather than trimming the help or suppressing the warning, since the text is
 * only going to grow. */
static void usage(FILE* out){
  fputs(
"Usage: " SFCC_PROGNAME " [options] <command> [arguments]\n"
"\n"
"A minimal Salesforce REST client.\n"
"\n"
"Commands:\n"
"  auth                        fetch a token and show the instance URL\n"
"  whoami                      show the running user's identity\n"
"  query <soql>                run a SOQL query\n"
"  get <object> <id>           fetch one record\n"
"  create <object> <json>      insert a record\n"
"  update <object> <id> <json> update a record\n"
"  delete <object> <id>        delete a record\n"
"  describe <object>           object metadata: fields, children, record types\n"
"  sobjects                    every object in the org, as a table\n"
"  versions                    API versions this org supports\n"
"  deploy --zip <file>         deploy a prebuilt metadata package\n"
"  rest <path>                 one raw REST call, with auth applied\n"
"\n"
"Options:\n"
"  --instance <url>            org base URL, e.g. https://acme.my.salesforce.com\n"
"  --token <token>             use this access token instead of OAuth\n"
"  --api-version <v64.0>       API version (default ", out);
  fprintf(out, "%s", SFCC_DEFAULT_API_VERSION);
  fputs(
")\n"
"  --login-url <url>           token endpoint (default https://login.salesforce.com)\n"
"  --token-cache <path>        where to memoise the token\n"
"  --no-cache                  do not read or write the token cache\n"
"  --timeout <seconds>         whole-transfer timeout (default ", out);
  fprintf(out, "%ld", 60L);
  fputs(
")\n"
"  --raw                       print JSON on one line instead of indented\n"
"  --quiet                     suppress the trailing status line\n"
"  --insecure-skip-verify      DANGER: disable TLS certificate checks\n"
"\n"
"describe options:\n"
"  --json                      print the whole response as indented JSON\n"
"  --field <text>              only fields whose name or label contains <text>\n"
"  --no-header                 omit the column header line of each table\n"
"  Without these, three tables are printed: fields, child relationships and\n"
"  record types. Each column is documented under \"describe columns\" below.\n"
"\n"
"describe columns:\n"
"  fields:\n"
"    NAME          the field's API name, as used in SOQL\n"
"    LABEL         its display label\n"
"    TYPE          datatype: string, reference, currency, picklist, ...\n"
"    LEN           maximum length; \"-\" where the type has no length\n"
"    SIZE          precision,scale for numeric types; \"-\" otherwise\n"
"    REL NAME      the relationship this field provides, if any\n"
"    REFERENCE TO  the objects this field can point at; several for a\n"
"                  polymorphic reference such as OwnerId, which may be a\n"
"                  User or a Group\n"
"  child relationships:\n"
"    FIELD         the field on the child that points back at this object\n"
"    CHILD OBJECT  the child object's API name\n"
"    REL NAME      the name the relationship is exposed under\n"
"  record types:\n"
"    ID            the record type id\n"
"    NAME          its display name\n"
"    DEVELOPER NAME its API name\n"
"    ACTIVE, MASTER, AVAILABLE, DEFAULT\n"
"\n", out);
  fputs(
"sobjects options:\n"
"  --raw                       print the API response instead of the table\n"
"  --custom                    only custom objects, skipping the platform ones\n"
"  --filter <text>             keep objects whose name or label contains <text>\n"
"  --limit <n>                 show at most <n> objects\n"
"  --no-header                 omit the column header line\n"
"\n"
"Sobject table columns:\n"
"  NAME      object API name, as used in SOQL and in the REST paths\n"
"  LABEL     the object's display name\n"
"  PREFIX    key prefix, the leading characters of every one of its ids\n"
"  CUST      custom, i.e. added to the org rather than supplied by Salesforce\n"
"  CRE       createable      UPD     updateable    DEL    deletable\n"
"  UNDEL     undeletable    QRY     queryable     RET    retrieveable\n"
"  SRCH      searchable      LAY     layoutable    MRG    mergeable\n"
"  TRIG      triggerable\n"
"  Salesforce reports more flags than these; --raw prints all of them.\n"
"\n"
"Deploy options:\n"
"  --validate-only             check the package without changing anything\n"
"  --test-level <mode>         none | local | specified   (default: none)\n"
"  --tests <A,B>               test classes, for --test-level specified\n"
"  --single-package            treat the zip as one managed package\n"
"  --poll-interval <seconds>   status poll interval (default 5)\n"
"  --deploy-timeout <seconds>  give up waiting after this long (default 900)\n"
"\n"
"REST options:\n"
"  -X, --method <verb>         GET | POST | PATCH | PUT | DELETE\n"
"                             (default: POST if a body is given, else GET)\n"
"  -d, --data <text>           request body; @- is stdin, @path a file\n"
"  --data-file <path>          read the body from a file ('-' is stdin)\n"
"  -H, --header 'Name: value'  add a request header (repeatable)\n"
"  -i, --include               show the response headers\n"
"  -o, --output <path>         write the body to a file ('-' is stdout)\n"
"\n"
"  -h, --help                  this text\n"
"  -V, --version               version information\n"
"\n"
"Environment:\n"
"  SFCC_CLIENT_ID              connected app consumer key      (required)\n"
"  SFCC_CLIENT_SECRET          connected app consumer secret  (required)\n"
"  SFCC_LOGIN_URL              token endpoint base\n"
"  SFCC_INSTANCE_URL           org base URL\n"
"  SFCC_ACCESS_TOKEN           pre-minted access token\n"
"  SFCC_API_VERSION            API version\n"
"  SFCC_TOKEN_CACHE            token cache path\n"
"\n"
"The client secret is read from the environment only, never from an argument,\n"
"because command lines are readable by any process running as this user.\n"
"\n"
"Examples:\n"
"  " SFCC_PROGNAME " query \"SELECT Id, Name FROM Account LIMIT 5\"\n"
"  " SFCC_PROGNAME " get Account 001000000000000AAA\n"
"  " SFCC_PROGNAME " create Account '{\"Name\":\"Acme\",\"Industry\":\"Tech\"}'\n"
"  " SFCC_PROGNAME " update Account 001000000000000AAA '{\"Phone\":\"555-0100\"}'\n"
"\n"
"  " SFCC_PROGNAME " sobjects --custom --filter invoice\n"
"  " SFCC_PROGNAME " describe Account --field Revenue\n"
"\n"
"  " SFCC_PROGNAME " deploy --validate-only --test-level local ./package.zip\n", out);
}

static void version(void){
  printf(SFCC_PROGNAME " %s (libcurl-based Salesforce REST client)\n",
         sfcc_version());
}

/* ------------------------------------------------------------------------ */

/* Emit a response body as JSON, pretty-printed unless --raw. */
static void print_json(const char* body){
  if(body == NULL){
    return;
  }
  cJSON* root = cJSON_ParseWithLength(body, strlen(body));
  if(root == NULL){
    /* sfcc_finish() already validated this, so reaching here would be a bug
     * rather than bad input. Echo rather than drop it. */
    printf("%s\n", body);
    return;
  }
  char* text = g_raw_output ? cJSON_PrintUnformatted(root) : cJSON_Print(root);
  if(text != NULL){
    printf("%s\n", text);
    free(text);
  }
  cJSON_Delete(root);
}

/* Report a failure the same way every time, preferring the library's specific
 * message over the generic status text. */
static int report(const sfcc_client* c, sfcc_status rc){
  const char* detail = sfcc_last_error(c);
  fprintf(stderr, SFCC_PROGNAME ": %s\n",
          detail ? detail : sfcc_strerror(rc));
  return 1;
}

/* ------------------------------------------------------------------------ */

/*
 * whoami is nicer as its own command than as "look up the User record and hope
 * the tool has read access to it", so it surfaces the identity endpoint's
 * handful of interesting fields rather than dumping the raw record.
 */
static int cmd_whoami(sfcc_client* c){
  char* body = NULL;
  sfcc_status rc = sfcc_whoami(c, &body);
  if(rc != SFCC_OK){
    return report(c, rc);
  }
  /* Prefer a labelled, indented layout, but fall back to the raw document if
   * the identity endpoint ever returns something unrecognised. */
  cJSON* root = cJSON_ParseWithLength(body, strlen(body));
  if(root == NULL || !cJSON_IsObject(root)){
    print_json(body);
  }else{
    static const char* const FIELDS[] = {
      "user_id", "username", "display_name", "email",
      "organization_id", "url",
    };
    for(size_t i = 0 ; i < sizeof(FIELDS) / sizeof(FIELDS[0]) ; ++i){
      const cJSON* f = cJSON_GetObjectItemCaseSensitive(root, FIELDS[i]);
      if(cJSON_IsString(f) && f->valuestring){
        printf("%-16s %s\n", FIELDS[i], f->valuestring);
      }
    }
    const cJSON* org = cJSON_GetObjectItemCaseSensitive(root, "organization_id");
    if(cJSON_IsString(org) && org->valuestring){
      printf("%-16s %s\n", "org", org->valuestring);
    }
  }
  if(root != NULL){
    cJSON_Delete(root);
  }
  free(body);
  return 0;
}

/*
 * Deploy a prebuilt package.
 *
 * A failed deploy is a *successful* command: the request was accepted and the
 * org then rejected some components. So the exit status distinguishes the two,
 * while the report explains what happened.
 */
static int cmd_deploy(sfcc_client* c, const char* zip_path,
                      const sfcc_deploy_options* opts){
  if(zip_path == NULL){
    fprintf(stderr, SFCC_PROGNAME ": deploy needs --zip <file>\n"
                    "  This stage takes an already-built package; it does not\n"
                    "  zip a source directory for you yet.\n");
    return 2;
  }
  sfcc_deploy_result result;
  const sfcc_status rc = sfcc_deploy_zip(c, zip_path, opts, &result);
  if(rc != SFCC_OK){
    /* Even on a transport failure the report may hold what we learned, so show
     * it before the error: a deploy that got partway through is the interesting
     * case. */
    if(result.report != NULL){
      fputs(result.report, stdout);
    }
    const int bad = report(c, rc);
    sfcc_deploy_result_free(&result);
    return bad;
  }
  fputs(result.report ? result.report : "(no report)\n", stdout);
  const int failed = !result.succeeded;
  sfcc_deploy_result_free(&result);
  return failed ? 1 : 0;
}

/*
 * The generic passthrough's parsed flags, collected in main() and handed over
 * as a struct. A struct rather than eight parameters because these all belong
 * to one command and travel together. Declared up here because the body
 * resolver below takes it.
 */
typedef struct {
  const char* method;
  const char* data;
  const char* data_file;
  const char* output;
  int include;
  const char* const* headers;   /* NULL-terminated, or NULL */
} rest_args;

/*
 * Read all of standard input into a NUL-terminated buffer.
 *
 * Needed so a payload can be piped rather than pasted into an argument. That
 * matters for two reasons beyond convenience: a large body does not belong in a
 * command line, where it is visible in ps to every process on the machine, and
 * a body containing quotes or newlines is a quoting problem the shell solves
 * badly.
 *
 * Returns NULL with a message on stderr if stdin is a terminal, because
 * otherwise the read blocks forever and looks like a hang rather than a
 * mistake. On success *out_len receives the byte count, which is what makes
 * binary payloads safe to pass this way.
 */
#define SFCC_MAX_STDIN_BYTES (64u * 1024u * 1024u)

static char* read_stdin(const char* what, size_t* out_len){
  *out_len = 0;

#if defined(_WIN32)
  if(_isatty(_fileno(stdin))){
    fprintf(stderr,
      SFCC_PROGNAME ": %s asked for standard input, but stdin is a terminal.\n"
      "       Pipe or redirect something into it: cat body.json | sfcc ...\n",
      what);
    return NULL;
  }
  /* Binary mode: without it the CRT translates LF to CRLF, altering a body the
   * shell already handed us byte for byte. */
  _setmode(_fileno(stdin), _O_BINARY);
#else
  if(isatty(fileno(stdin))){
    fprintf(stderr,
      SFCC_PROGNAME ": %s asked for standard input, but stdin is a terminal.\n"
      "       Pipe or redirect something into it: cat body.json | sfcc ...\n",
      what);
    return NULL;
  }
#endif

  sfcc_buf b;
  sfcc_buf_init(&b);
  char chunk[65536];
  size_t n;
  while((n = fread(chunk, 1, sizeof(chunk), stdin)) > 0){
    if(sfcc_buf_append(&b, chunk, n)){
      sfcc_buf_free(&b);
      fprintf(stderr, SFCC_PROGNAME ": out of memory reading standard input\n");
      return NULL;
    }
    if(b.len > SFCC_MAX_STDIN_BYTES){
      sfcc_buf_free(&b);
      fprintf(stderr, SFCC_PROGNAME ": standard input exceeds %u MiB\n",
              SFCC_MAX_STDIN_BYTES >> 20);
      return NULL;
    }
  }
  if(ferror(stdin)){
    sfcc_buf_free(&b);
    fprintf(stderr, SFCC_PROGNAME ": error reading standard input\n");
    return NULL;
  }
  if(b.data == NULL){
    /* Nothing was piped at all. Distinct from an empty body, because an empty
     * POST is almost always a broken pipeline rather than the intent. */
    fprintf(stderr, SFCC_PROGNAME ": standard input was empty\n");
    return NULL;
  }
  *out_len = b.len;
  return b.data;   /* the buffer owns the NUL */
}

/* Read a whole file into a NUL-terminated buffer. Returns NULL with a message
 * on stderr. Used by --data-file and by the @file form of --data. */
static char* read_whole_file(const char* path, size_t* out_len){
  FILE* f = fopen(path, "rb");   /* binary: a body is not necessarily text */
  if(f == NULL){
    fprintf(stderr, SFCC_PROGNAME ": cannot read %s\n", path);
    return NULL;
  }
  sfcc_buf b;
  sfcc_buf_init(&b);
  char chunk[65536];
  size_t n;
  while((n = fread(chunk, 1, sizeof(chunk), f)) > 0){
    if(sfcc_buf_append(&b, chunk, n)){
      sfcc_buf_free(&b);
      fprintf(stderr, SFCC_PROGNAME ": out of memory reading %s\n", path);
      fclose(f);
      return NULL;
    }
  }
  const int bad = ferror(f);
  fclose(f);
  if(bad){
    sfcc_buf_free(&b);
    fprintf(stderr, SFCC_PROGNAME ": error reading %s\n", path);
    return NULL;
  }
  if(b.data == NULL){
    fprintf(stderr, SFCC_PROGNAME ": %s is empty\n", path);
    return NULL;
  }
  *out_len = b.len;
  return b.data;   /* the buffer owns the NUL */
}

/*
 * Resolve the request body from whatever the user pointed us at:
 *
 *   --data @-         standard input
 *   --data @path      a file, read verbatim
 *   --data text       the text itself
 *   --data-file -     standard input
 *   --data-file path  a file
 *
 * One deliberate divergence from curl: curl's "-d @file" form-*encodes* the
 * content unless you ask for --data-raw. Copying that here would quietly
 * corrupt every JSON body anyone piped in, which is the overwhelmingly common
 * case for this tool. So "@" means "read these bytes, unchanged".
 */
static const char* resolve_body(const rest_args* a, size_t* len, int* owned){
  *len = 0;
  *owned = 0;

  if(a->data != NULL && a->data[0] == '@'){
    const char* src = a->data + 1;
    if(*src == '\0'){
      fprintf(stderr, SFCC_PROGNAME ": \"@\" needs a filename, or \"-\" for "
                      "standard input\n");
      return NULL;
    }
    *owned = 1;
    if(strcmp(src, "-") == 0){
      return read_stdin("--data @-", len);
    }
    return read_whole_file(src, len);
  }

  if(a->data_file != NULL){
    *owned = 1;
    if(strcmp(a->data_file, "-") == 0){
      return read_stdin("--data-file -", len);
    }
    return read_whole_file(a->data_file, len);
  }

  if(a->data != NULL){
    *len = strlen(a->data);
  }
  /* An inline argument stays const: it points into argv, which outlives the
   * call, and casting away const to free it later would be a bug. */
  return a->data;
}

/*
 * The generic passthrough.
 *
 * Unlike every other command, a 4xx here is not an error: the request worked
 * and the server's answer is what the caller asked to see. So the body is
 * always printed and the exit status reports whether the exchange happened.
 */
static int cmd_rest(sfcc_client* c, const char* path, const rest_args* a){
  /* -d and --data-file are alternatives; silently preferring one would be a
   * nasty surprise. */
  if(a->data != NULL && a->data_file != NULL){
    fprintf(stderr, SFCC_PROGNAME ": pass either --data or --data-file, not "
                    "both\n");
    return 2;
  }

  /* Resolve the body once: an inline argument, a file, or standard input. */
  size_t body_len = 0;
  int body_owned = 0;
  const char* body = resolve_body(a, &body_len, &body_owned);
  if((a->data != NULL || a->data_file != NULL) && body == NULL){
    return 2;   /* resolve_body has already said what went wrong */
  }

  sfcc_rest_options o = {
    .method = a->method,
    .body = body,
    .extra_headers = a->headers,
  };
  sfcc_rest_result res;
  const sfcc_status rc = sfcc_rest(c, path, &o, &res);
  if(body_owned){
    /* The buffer came from read_stdin/read_whole_file, which malloc it. The
     * const is only so the inline-argument case can share this variable. */
    union { const char* c; char* m; } owned = { .c = body };
    free(owned.m);
  }
  if(rc != SFCC_OK){
    return report(c, rc);
  }

  if(a->include && res.headers != NULL){
    fputs(res.headers, stdout);
  }

  /* The body is the answer, not an error from this tool, so it goes to stdout
   * where a caller can parse it. Only the exit status reflects the status. */
  const int failed = (res.status >= 400);
  if(failed){
    fprintf(stderr, SFCC_PROGNAME ": HTTP %ld\n", res.status);
  }

  /* "-o -" means stdout, matching curl. Spelled out so a script can switch
   * between a file and the pipeline without special-casing the flag. */
  const int to_stdout = (a->output == NULL || strcmp(a->output, "-") == 0);

  if(!to_stdout){
    FILE* f = fopen(a->output, "wb");
    if(f == NULL){
      fprintf(stderr, SFCC_PROGNAME ": cannot write %s\n", a->output);
      sfcc_rest_result_free(&res);
      return 2;
    }
    /*
     * fwrite with the recorded length, not strlen. A VersionData fetch is a
     * PNG and a Bulk export is a CSV: both contain NUL bytes, and treating the
     * body as a C string truncates them at the first one.
     */
    if(res.body != NULL && res.body_len){
      fwrite(res.body, 1, res.body_len, f);
    }
    fclose(f);
    if(!g_quiet){
      /* Status on stderr, so it cannot contaminate a pipeline. */
      fprintf(stderr, SFCC_PROGNAME ": wrote %s (%lu bytes)\n", a->output,
              (unsigned long)res.body_len);
    }
  }else if(res.body != NULL){
    /*
     * Pretty-print when it is JSON, matching every other command; emit it
     * verbatim otherwise, because reformatting a non-JSON body would corrupt
     * whatever it actually is -- and write it with the length so binary data
     * survives.
     */
    if(g_raw_output || !sfcc_json_valid(res.body)){
      fwrite(res.body, 1, res.body_len, stdout);
    }else{
      print_json(res.body);
    }
  }

  sfcc_rest_result_free(&res);
  return failed;
}

/* ------------------------------------------------------------------------ */
/* sobjects                                                                  */
/* ------------------------------------------------------------------------ */

/* The capability flags Salesforce reports per object, in the order shown.
 *
 * The API returns more than this -- customSetting, deprecatedAndHidden,
 * feedEnabled, hasSubtypes, isSubtype, mruEnabled and replicateable among them.
 * Those are left out because they answer questions asked far less often than
 * "can I write to this", and every extra column costs width in a table that is
 * already wide. --raw prints the response with all of them, so nothing is
 * actually unavailable; it is only unlisted. */
static const char* const SOBJ_HEADERS[] = {
  "NAME", "LABEL", "PREFIX",
  "CUST", "CRE", "UPD", "DEL", "UNDEL", "QRY", "RET", "SRCH", "LAY", "MRG", "TRIG",
};
enum { SOBJ_COLS = (int)(sizeof(SOBJ_HEADERS) / sizeof(SOBJ_HEADERS[0])) };

typedef struct {
  int  custom_only;   /* --custom: platform objects are the majority and rarely
                       * what someone is looking for */
  long limit;         /* --limit, 0 for all */
  const char* filter; /* --filter, matched against name and label */
} sobjects_opts;

/* Case-insensitive substring test. POSIX has strcasestr; MSVC does not, and
 * this is the only place the client would want one. */
static int contains_ci(const char* hay, const char* needle){
  if(needle == NULL || *needle == '\0'){
    return 1;
  }
  if(hay == NULL){
    return 0;
  }
  for(const char* p = hay ; *p != '\0' ; ++p){
    size_t i = 0;
    while(needle[i] != '\0' && p[i] != '\0' &&
          sfcc_strncasecmp(p + i, needle + i, 1) == 0){
      ++i;
    }
    if(needle[i] == '\0'){
      return 1;
    }
  }
  return 0;
}

/* Fill one row of cell pointers from one SObject.
 *
 * The strings point into the parsed tree, which outlives the printing. An
 * absent flag becomes "no" rather than a blank: a capability table with holes in
 * it is harder to scan than one that is pessimistic. */
static void sobject_row(const cJSON* o, const char** cells){
  cells[0] = sfcc_json_str(o, "name", "");
  cells[1] = sfcc_json_str(o, "label", "");
  cells[2] = sfcc_json_str(o, "keyPrefix", "");
  cells[3] = sfcc_json_bool(o, "custom")        ? "yes" : "no";
  cells[4] = sfcc_json_bool(o, "createable")    ? "yes" : "no";
  cells[5] = sfcc_json_bool(o, "updateable")    ? "yes" : "no";
  cells[6] = sfcc_json_bool(o, "deletable")     ? "yes" : "no";
  cells[7] = sfcc_json_bool(o, "undeletable")   ? "yes" : "no";
  cells[8] = sfcc_json_bool(o, "queryable")     ? "yes" : "no";
  cells[9] = sfcc_json_bool(o, "retrieveable")  ? "yes" : "no";
  cells[10] = sfcc_json_bool(o, "searchable")   ? "yes" : "no";
  cells[11] = sfcc_json_bool(o, "layoutable")   ? "yes" : "no";
  cells[12] = sfcc_json_bool(o, "mergeable")    ? "yes" : "no";
  cells[13] = sfcc_json_bool(o, "triggerable")  ? "yes" : "no";
}

/* Decide whether one object survives the --custom and --filter options. Kept
 * apart from sobject_row so filtering never touches the output cells. */
static int sobject_wanted(const cJSON* o, const sobjects_opts* opt){
  if(opt->custom_only && !sfcc_json_bool(o, "custom")){
    return 0;
  }
  if(opt->filter != NULL){
    return contains_ci(sfcc_json_str(o, "name", ""), opt->filter) ||
           contains_ci(sfcc_json_str(o, "label", ""), opt->filter);
  }
  return 1;
}

/* ------------------------------------------------------------------------ */
/* Tables                                                                    */
/* ------------------------------------------------------------------------ */

/*
 * Rows are collected before anything is printed, because column widths have to
 * be known to lay out the first row. Measuring as you go would mean printing
 * before you knew how wide the columns were.
 *
 * Cells are borrowed, not copied: they point into the parsed response tree, or
 * into a scratch buffer the caller keeps alive until the table is printed. The
 * table therefore never outlives the tree it was filled from.
 *
 * ncols is dynamic rather than a fixed maximum. It was a compile-time bound
 * once, and table_print indexed a widths[] array of that size with the *actual*
 * column count -- so the widest table quietly wrote past the end of it and
 * smashed the caller's stack frame. The sobjects table has fourteen columns and
 * the bound said eight; the overflow landed on `shown`, which then read zero
 * and sent every invocation down the "no objects matched" path. That is a
 * confusing enough failure to keep the shape of it in the source.
 */
typedef struct {
  const char* const* headers;
  int ncols;
  size_t nrows;
  size_t cap;
  const char** cells;  /* nrows * ncols, row-major */
} table;

static void table_init(table* t, const char* const* headers, int ncols){
  t->headers = headers;
  t->ncols = ncols;
  t->nrows = 0;
  t->cap = 0;
  t->cells = NULL;
}

static int table_push(table* t, const char* const* row){
  if(t->nrows == t->cap){
    const size_t next = t->cap ? t->cap * 2 : 32;
    const char** grown = realloc(t->cells, next * (size_t)t->ncols
                                          * sizeof(*t->cells));
    if(grown == NULL){
      return 0;
    }
    t->cells = grown;
    t->cap = next;
  }
  memcpy(&t->cells[t->nrows * (size_t)t->ncols], row,
         (size_t)t->ncols * sizeof(*row));
  ++t->nrows;
  return 1;
}

/* Measure the columns over the rows actually collected, then print. */
static void table_print(const table* t, int no_header){
  int* widths = calloc((size_t)t->ncols, sizeof(*widths));
  if(widths == NULL){
    return;
  }
  for(int i = 0 ; i < t->ncols ; ++i){
    widths[i] = (int)strlen(t->headers[i]);
  }
  for(size_t r = 0 ; r < t->nrows ; ++r){
    for(int i = 0 ; i < t->ncols ; ++i){
      const char* cell = t->cells[r * (size_t)t->ncols + (size_t)i];
      if(cell != NULL){
        const int w = (int)strlen(cell);
        if(w > widths[i]){
          widths[i] = w;
        }
      }
    }
  }

  for(int r = -1 ; r < (int)t->nrows ; ++r){
    if(r < 0 && no_header){
      continue;
    }
    const char* const* row = (r < 0) ? t->headers
                                      : &t->cells[(size_t)r * (size_t)t->ncols];
    for(int i = 0 ; i < t->ncols ; ++i){
      const char* cell = row[i] ? row[i] : "";
      if(i > 0){
        fputs("  ", stdout);
      }
      fputs(cell, stdout);
      if(i + 1 < t->ncols){
        for(int pad = (int)strlen(cell) ; pad < widths[i] ; ++pad){
          fputc(' ', stdout);
        }
      }
    }
    fputc('\n', stdout);
  }
  free(widths);
}

static void table_free(table* t){
  free(t->cells);
  t->cells = NULL;
  t->nrows = 0;
  t->cap = 0;
}

/* Section heading between the tables, so the output says what each block is. */
static void table_title(const char* title, size_t nrows){
  printf("\n%s (%zu)\n", title, nrows);
}

static int cmd_sobjects(sfcc_client* c, const sobjects_opts* opt){
  char* body = NULL;
  sfcc_status rc = sfcc_list_sobjects(c, &body);
  if(rc != SFCC_OK){
    int r = report(c, rc);
    free(body);
    return r;
  }

  /* --raw means the response itself, which is what every other command does
   * with a body and what anyone scripting this one wants. */
  if(g_raw_output){
    print_json(body);
    free(body);
    return 0;
  }

  cJSON* root = cJSON_ParseWithLength(body, strlen(body));
  free(body);
  if(root == NULL){
    fprintf(stderr, SFCC_PROGNAME ": could not parse the response\n");
    return 1;
  }

  const cJSON* arr = cJSON_GetObjectItemCaseSensitive(root, "sobjects");
  if(!cJSON_IsArray(arr)){
    /* Not something this client knows how to read, and printing an empty table
     * without saying why would look like an org with no objects in it. */
    fprintf(stderr, SFCC_PROGNAME ": response has no \"sobjects\" array;"
                    " the endpoint may have changed (API %s)\n",
            SFCC_DEFAULT_API_VERSION);
    cJSON_Delete(root);
    return 1;
  }

  const int total = cJSON_GetArraySize(arr);

  table t;
  table_init(&t, SOBJ_HEADERS, SOBJ_COLS);

  int oom = 0;
  int shown = 0;
  const cJSON* o = NULL;
  cJSON_ArrayForEach(o, arr){
    if(!sobject_wanted(o, opt)){
      continue;
    }
    /* 'continue' rather than 'break': cJSON_ArrayForEach's increment is
     * unreachable after a break, which MSVC reports as C4702 and /WX turns
     * into a build failure. The remainder of the array is only a few hundred
     * pointer comparisons, so the walk is not worth a warning. */
    if(opt->limit > 0 && shown >= opt->limit){
      continue;
    }
    const char* cells[SOBJ_COLS];
    sobject_row(o, cells);
    if(!table_push(&t, cells)){
      oom = 1;
      break;   /* not inside the macro: no unreachable increment here */
    }
    ++shown;
  }

  if(oom){
    fprintf(stderr, SFCC_PROGNAME ": out of memory\n");
    table_free(&t);
    cJSON_Delete(root);
    return 1;
  }

  if(shown == 0){
    fprintf(stderr, SFCC_PROGNAME ": no objects matched (%d in this org)\n",
            total);
    table_free(&t);
    cJSON_Delete(root);
    return 1;
  }

  table_print(&t, g_no_header);
  table_free(&t);

  if(!g_quiet){
    printf("%d of %d object%s\n", shown, total, total == 1 ? "" : "s");
  }

  cJSON_Delete(root);
  return 0;
}

/* ------------------------------------------------------------------------ */
/* describe                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Column headers. The capability columns in the sobjects table are abbreviated
 * because eleven of them will not fit; here there are only seven, so the
 * headers spell themselves out. REL NAME is the exception, matching sobjects.
 */
static const char* const DESC_FIELD_HEADERS[] = {
  "NAME", "LABEL", "TYPE", "LEN", "SIZE", "REL NAME", "REFERENCE TO",
};
enum { DESC_FIELD_COLS = (int)(sizeof(DESC_FIELD_HEADERS) /
                              sizeof(DESC_FIELD_HEADERS[0])) };

static const char* const DESC_CHILD_HEADERS[] = {
  "FIELD", "CHILD OBJECT", "REL NAME",
};
enum { DESC_CHILD_COLS = (int)(sizeof(DESC_CHILD_HEADERS) /
                               sizeof(DESC_CHILD_HEADERS[0])) };

static const char* const DESC_RT_HEADERS[] = {
  "ID", "NAME", "DEVELOPER NAME", "ACTIVE", "MASTER", "AVAILABLE", "DEFAULT",
};
enum { DESC_RT_COLS = (int)(sizeof(DESC_RT_HEADERS) /
                            sizeof(DESC_RT_HEADERS[0])) };

typedef struct {
  int json;                  /* --json: the whole response, indented */
  const char* field_filter;  /* --field: substring of the field name or label */
} describe_opts;

/* Per-row scratch. The numeric columns and the joined reference list have to be
 * formatted somewhere, and the table borrows its cells rather than copying
 * them, so that somewhere has to outlive the table. One of these per field. */
typedef struct {
  char len[16];
  char size[24];
  char ref[512];
} describe_field_buf;

/* Join a referenceTo list into one cell.
 *
 * Usually a list of plain names, but the list elements are objects in some API
 * versions, carrying the target type under "type". Both are handled rather than
 * assumed, and anything else is skipped: printing "[object Object]" into a table
 * is worse than printing nothing. Truncated rather than allowed to overrun. */
static void join_reference(const cJSON* o, char* out, size_t outsz){
  out[0] = '\0';
  const cJSON* f = cJSON_GetObjectItemCaseSensitive(o, "referenceTo");
  if(cJSON_IsString(f)){
    snprintf(out, outsz, "%s", f->valuestring ? f->valuestring : "");
    return;
  }
  if(!cJSON_IsArray(f)){
    return;
  }
  size_t used = 0;
  const cJSON* it = NULL;
  cJSON_ArrayForEach(it, f){
    const char* name = NULL;
    if(cJSON_IsString(it)){
      name = it->valuestring;
    }else if(cJSON_IsObject(it)){
      name = sfcc_json_str(it, "type", NULL);
    }
    if(name == NULL || *name == '\0'){
      continue;
    }
    const int n = snprintf(out + used, outsz - used, "%s%s",
                           used ? ", " : "", name);
    if(n < 0 || (size_t)n >= outsz - used){
      break;   /* truncated: stop rather than wrap into the next field */
    }
    used += (size_t)n;
  }
}

static void desc_field_row(const cJSON* f, describe_field_buf* buf,
                           const char** cells){
  const int len = sfcc_json_int(f, "length", 0);
  const int prec = sfcc_json_int(f, "precision", 0);
  const int scale = sfcc_json_int(f, "scale", 0);

  /* Zero means "not applicable" rather than "zero characters": a datetime and a
   * boolean both report a length of 0, and printing 0 next to them invites the
   * reader to believe it. */
  snprintf(buf->len, sizeof(buf->len), "%s", len > 0 ? "" : "-");
  if(len > 0){
    snprintf(buf->len, sizeof(buf->len), "%d", len);
  }

  if(prec > 0 || scale > 0){
    snprintf(buf->size, sizeof(buf->size), "%d,%d", prec, scale);
  }else{
    snprintf(buf->size, sizeof(buf->size), "-");
  }

  join_reference(f, buf->ref, sizeof(buf->ref));

  cells[0] = sfcc_json_str(f, "name", "");
  cells[1] = sfcc_json_str(f, "label", "");
  cells[2] = sfcc_json_str(f, "type", "?");
  cells[3] = buf->len;
  cells[4] = buf->size;
  cells[5] = sfcc_json_str(f, "relationshipName", NULL);
  cells[6] = buf->ref[0] ? buf->ref : "-";
  if(cells[5] == NULL){
    cells[5] = "-";
  }
}

static int desc_field_wanted(const cJSON* f, const describe_opts* opt){
  if(opt->field_filter == NULL){
    return 1;
  }
  return contains_ci(sfcc_json_str(f, "name", ""), opt->field_filter) ||
         contains_ci(sfcc_json_str(f, "label", ""), opt->field_filter);
}

static int cmd_describe(sfcc_client* c, const char* sobject,
                        const describe_opts* opt){
  char* body = NULL;
  sfcc_status rc = sfcc_describe(c, sobject, &body);
  if(rc != SFCC_OK){
    int r = report(c, rc);
    free(body);
    return r;
  }

  /* --raw is the one-line form every command uses; --json is this response
   * indented, which is what `describe` printed before the tables existed and is
   * what anyone piping it into jq still wants. */
  if(g_raw_output || opt->json){
    print_json(body);
    free(body);
    return 0;
  }

  cJSON* root = cJSON_ParseWithLength(body, strlen(body));
  free(body);
  if(root == NULL){
    fprintf(stderr, SFCC_PROGNAME ": could not parse the response\n");
    return 1;
  }

  int rc_out = 0;

  /* --- fields ------------------------------------------------------------ */
  const cJSON* fields = cJSON_GetObjectItemCaseSensitive(root, "fields");
  const int nfields = cJSON_IsArray(fields) ? cJSON_GetArraySize(fields) : 0;
  /* One scratch per field, allocated up front: the table borrows the cells, so
   * they have to stay put for as long as the table does. */
  describe_field_buf* bufs = nfields > 0
    ? calloc((size_t)nfields, sizeof(*bufs)) : NULL;
  if(nfields > 0 && bufs == NULL){
    fprintf(stderr, SFCC_PROGNAME ": out of memory\n");
    cJSON_Delete(root);
    return 1;
  }

  table tf;
  table_init(&tf, DESC_FIELD_HEADERS, DESC_FIELD_COLS);
  int used = 0;
  int idx = 0;
  const cJSON* f = NULL;
  cJSON_ArrayForEach(f, fields){
    if(!desc_field_wanted(f, opt) || idx >= nfields){
      continue;
    }
    const char* cells[DESC_FIELD_COLS];
    desc_field_row(f, &bufs[idx], cells);
    if(!table_push(&tf, cells)){
      rc_out = 1;
      break;
    }
    ++idx;
    ++used;
  }

  table_title("fields", (size_t)used);
  if(rc_out == 0){
    table_print(&tf, g_no_header);
  }
  table_free(&tf);
  free(bufs);
  if(rc_out != 0){
    fprintf(stderr, SFCC_PROGNAME ": out of memory\n");
    cJSON_Delete(root);
    return 1;
  }

  /* --- child relationships ---------------------------------------------- */
  const cJSON* kids =
    cJSON_GetObjectItemCaseSensitive(root, "childRelationships");
  table tc;
  table_init(&tc, DESC_CHILD_HEADERS, DESC_CHILD_COLS);
  size_t nchild = 0;
  const cJSON* k = NULL;
  cJSON_ArrayForEach(k, kids){
    const char* cells[DESC_CHILD_COLS];
    cells[0] = sfcc_json_str(k, "field", "?");
    cells[1] = sfcc_json_str(k, "childSObject", "?");
    cells[2] = sfcc_json_str(k, "relationshipName", NULL);
    if(cells[2] == NULL){
      cells[2] = "-";
    }
    if(!table_push(&tc, cells)){
      rc_out = 1;
      break;
    }
    ++nchild;
  }
  table_title("child relationships", nchild);
  if(rc_out == 0){
    table_print(&tc, g_no_header);
  }
  table_free(&tc);

  /* --- record types ------------------------------------------------------ */
  const cJSON* rts = cJSON_GetObjectItemCaseSensitive(root, "recordTypeInfos");
  table tr;
  table_init(&tr, DESC_RT_HEADERS, DESC_RT_COLS);
  size_t nrt = 0;
  const cJSON* rt = NULL;
  cJSON_ArrayForEach(rt, rts){
    const char* cells[DESC_RT_COLS];
    cells[0] = sfcc_json_str(rt, "recordTypeId", "?");
    cells[1] = sfcc_json_str(rt, "name", "?");
    cells[2] = sfcc_json_str(rt, "developerName", "?");
    cells[3] = sfcc_json_bool(rt, "active")    ? "yes" : "no";
    cells[4] = sfcc_json_bool(rt, "master")    ? "yes" : "no";
    cells[5] = sfcc_json_bool(rt, "available") ? "yes" : "no";
    cells[6] = sfcc_json_bool(rt, "defaultRecordTypeMapping") ? "yes" : "no";
    if(!table_push(&tr, cells)){
      rc_out = 1;
      break;
    }
    ++nrt;
  }
  table_title("record types", nrt);
  if(rc_out == 0){
    table_print(&tr, g_no_header);
  }
  table_free(&tr);

  cJSON_Delete(root);
  return rc_out ? 1 : 0;
}

static int cmd_versions(sfcc_client* c){
  char* body = NULL;
  sfcc_status rc = sfcc_list_versions(c, &body);
  if(rc != SFCC_OK){
    return report(c, rc);
  }
  print_json(body);
  free(body);
  return 0;
}

static int cmd_auth(sfcc_client* c){
  char* instance = NULL;
  sfcc_status rc = sfcc_authenticate(c, &instance);
  if(rc != SFCC_OK){
    return report(c, rc);
  }
  printf("instance: %s\n", instance);
  if(!g_quiet){
    const char* cached = (c->cache_path && !c->no_cache) ? c->cache_path : NULL;
    printf("token:    obtained (not shown)%s\n",
           cached ? " and cached" : "");
    if(cached){
      printf("cache:    %s\n", cached);
    }
  }
  free(instance);
  return 0;
}

/* ------------------------------------------------------------------------ */

int main(int argc, char** argv){
  sfcc_config cfg;
  sfcc_config_defaults(&cfg);
  sfcc_config_apply_env(&cfg);

  /* Environment first, then flags override it -- so an explicit flag always
   * wins over a stale exported variable. */
  const char* instance = NULL;
  const char* token = NULL;
  const char* cache = NULL;
  const char* login = NULL;
  const char* apiver = NULL;
  long timeout = 0;
  int no_cache = 0;
  int insecure = 0;

  /* deploy options, parsed here but only used by the deploy command */
  const char* zip_path = NULL;
  sfcc_deploy_options dopts;
  sfcc_deploy_options_defaults(&dopts);

  /* sobjects options */
  sobjects_opts sopts = { .custom_only = 0, .limit = 0, .filter = NULL };

  /* describe options */
  describe_opts dopts_desc = { .json = 0, .field_filter = NULL };

  /* rest options */
  const char* rest_method = NULL;
  const char* rest_data = NULL;
  const char* rest_data_file = NULL;
  const char* rest_output = NULL;
  int rest_include = 0;
  /*
   * Repeatable header collection. One slot is reserved for the NULL
   * terminator the API requires, and the cap is bounded because this is a
   * stack array -- so it is checked rather than assumed.
   */
  const char* rest_headers[33];
  int nrest_headers = 0;

  /*
   * Options are recognised anywhere on the command line, not just before the
   * command. Permuting them the way getopt does is what people expect, and the
   * alternative is the failure this originally had: `sfcc query "SELECT ..."
   * --instance X --token Y` silently treated the flags as command arguments
   * and then complained about missing credentials, which sends you looking in
   * entirely the wrong place.
   *
   * A bare "--" ends option processing, for the rare case of an argument that
   * really does begin with a dash.
   */
  char* positional[32];
  int npos = 0;
  int end_of_options = 0;

  for(int i = 1 ; i < argc ; ++i){
    const char* a = argv[i];

    if(!end_of_options && strcmp(a, "--") == 0){
      end_of_options = 1;
      continue;
    }
    if(!end_of_options && a[0] == '-' && a[1] != '\0'){
    /* Support both "--flag value" and "--flag=value". */
    const char* inline_val = NULL;
    char name[64];
    const char* eq = strchr(a, '=');
    if(eq != NULL){
      const size_t n = (size_t)(eq - a);
      if(n < sizeof(name)){
        memcpy(name, a, n);
        name[n] = '\0';
        inline_val = eq + 1;
      }
    }else{
      snprintf(name, sizeof(name), "%s", a);
    }

#define NEEDS_VALUE(dst)                                                    \
  do {                                                                      \
    if(inline_val != NULL){                                                 \
      (dst) = inline_val;                                                   \
    }else{                                                                  \
      if(++i >= argc){                                                      \
        fprintf(stderr, SFCC_PROGNAME ": %s needs a value\n", name);        \
        return 2;                                                           \
      }                                                                     \
      (dst) = argv[i];                                                      \
    }                                                                       \
  } while(0)

    if(strcmp(name, "-h") == 0 || strcmp(name, "--help") == 0){
      usage(stdout);
      return 0;
    }else if(strcmp(name, "-V") == 0 || strcmp(name, "--version") == 0){
      version();
      return 0;
    }else if(strcmp(name, "--instance") == 0){
      NEEDS_VALUE(instance);
    }else if(strcmp(name, "--token") == 0){
      NEEDS_VALUE(token);
    }else if(strcmp(name, "--api-version") == 0){
      NEEDS_VALUE(apiver);
    }else if(strcmp(name, "--login-url") == 0){
      NEEDS_VALUE(login);
    }else if(strcmp(name, "--token-cache") == 0){
      NEEDS_VALUE(cache);
    }else if(strcmp(name, "--timeout") == 0){
      const char* v = NULL;
      NEEDS_VALUE(v);
      timeout = strtol(v, NULL, 10);
      if(timeout <= 0){
        fprintf(stderr, SFCC_PROGNAME ": --timeout must be a positive number\n");
        return 2;
      }
    }else if(strcmp(name, "--no-cache") == 0){
      no_cache = 1;
    }else if(strcmp(name, "--raw") == 0){
      g_raw_output = 1;
    }else if(strcmp(name, "--quiet") == 0){
      g_quiet = 1;
    }else if(strcmp(name, "--insecure-skip-verify") == 0){
      insecure = 1;
    }else if(strcmp(name, "--zip") == 0){
      NEEDS_VALUE(zip_path);
    }else if(strcmp(name, "--json") == 0){
      dopts_desc.json = 1;
    }else if(strcmp(name, "--field") == 0){
      NEEDS_VALUE(dopts_desc.field_filter);
    }else if(strcmp(name, "--custom") == 0){
      sopts.custom_only = 1;
    }else if(strcmp(name, "--no-header") == 0){
      g_no_header = 1;
    }else if(strcmp(name, "--filter") == 0){
      NEEDS_VALUE(sopts.filter);
    }else if(strcmp(name, "--limit") == 0){
      const char* v = NULL;
      NEEDS_VALUE(v);
      sopts.limit = strtol(v, NULL, 10);
      if(sopts.limit <= 0){
        fprintf(stderr, SFCC_PROGNAME ": --limit must be a positive number\n");
        return 2;
      }
    }else if(strcmp(name, "--validate-only") == 0){
      dopts.validate_only = 1;
    }else if(strcmp(name, "--single-package") == 0){
      dopts.single_package = 1;
    }else if(strcmp(name, "--tests") == 0){
      NEEDS_VALUE(dopts.tests);
    }else if(strcmp(name, "--test-level") == 0){
      const char* mode = NULL;
      NEEDS_VALUE(mode);
      if(strcmp(mode, "none") == 0){
        dopts.test_level = SFCC_TEST_NONE;
      }else if(strcmp(mode, "local") == 0){
        dopts.test_level = SFCC_TEST_LOCAL;
      }else if(strcmp(mode, "specified") == 0){
        dopts.test_level = SFCC_TEST_SPECIFIED;
      }else{
        fprintf(stderr, SFCC_PROGNAME ": --test-level must be none, local or "
                        "specified (got \"%s\")\n", mode);
        return 2;
      }
    }else if(strcmp(name, "--poll-interval") == 0){
      const char* v = NULL;
      NEEDS_VALUE(v);
      dopts.poll_interval_s = strtol(v, NULL, 10);
      if(dopts.poll_interval_s <= 0){
        fprintf(stderr, SFCC_PROGNAME ": --poll-interval must be positive\n");
        return 2;
      }
    }else if(strcmp(name, "--deploy-timeout") == 0){
      const char* v = NULL;
      NEEDS_VALUE(v);
      dopts.timeout_s = strtol(v, NULL, 10);
      if(dopts.timeout_s <= 0){
        fprintf(stderr, SFCC_PROGNAME ": --deploy-timeout must be positive\n");
        return 2;
      }
    }else if(strcmp(name, "-X") == 0 || strcmp(name, "--method") == 0){
      NEEDS_VALUE(rest_method);
    }else if(strcmp(name, "-d") == 0 || strcmp(name, "--data") == 0){
      NEEDS_VALUE(rest_data);
    }else if(strcmp(name, "--data-file") == 0){
      NEEDS_VALUE(rest_data_file);
    }else if(strcmp(name, "-o") == 0 || strcmp(name, "--output") == 0){
      NEEDS_VALUE(rest_output);
    }else if(strcmp(name, "-i") == 0 || strcmp(name, "--include") == 0){
      rest_include = 1;
    }else if(strcmp(name, "-H") == 0 || strcmp(name, "--header") == 0){
      const char* hdr = NULL;
      NEEDS_VALUE(hdr);
      /* A header with no colon is the same class of mistake as the
       * "Bearer" bug: curl would silently drop it. Catch it here where it can
       * still be pointed out. */
      if(strchr(hdr, ':') == NULL){
        fprintf(stderr, SFCC_PROGNAME ": header \"%s\" has no colon. Headers "
                        "are \"Name: value\".\n", hdr);
        return 2;
      }
      if(nrest_headers >= (int)(sizeof(rest_headers) /
                                sizeof(rest_headers[0])) - 1){
        fprintf(stderr, SFCC_PROGNAME ": too many -H headers\n");
        return 2;
      }
      rest_headers[nrest_headers++] = hdr;
    }else if(name[0] == '-'){
      fprintf(stderr, SFCC_PROGNAME ": unknown option '%s' (try --help)\n", a);
      return 2;
    }
#undef NEEDS_VALUE
    }else{
      /* A command or one of its arguments. Bounded, because an overflow here
       * would be a silent out-of-bounds write. */
      if(npos >= (int)(sizeof(positional) / sizeof(positional[0]))){
        fprintf(stderr, SFCC_PROGNAME ": too many arguments\n");
        return 2;
      }
      positional[npos++] = argv[i];
    }
  }

  if(npos == 0){
    usage(stderr);
    return 2;
  }
  const char* cmd = positional[0];
  char** args = positional + 1;
  const int nargs = npos - 1;

  if(insecure){
    fprintf(stderr,
      SFCC_PROGNAME ": WARNING: TLS certificate verification is disabled.\n"
      "       Anything on the network path can read and rewrite your traffic,\n"
      "       including the bearer token that grants full access to the org.\n");
  }

  /* Flags beat environment. */
  if(instance) cfg.instance_url = instance;
  if(token)    cfg.access_token = token;
  if(apiver)   cfg.api_version = apiver;
  if(login)    cfg.login_url = login;
  if(cache)    cfg.cache_path = cache;
  if(timeout)  cfg.timeout_s = timeout;
  if(no_cache) cfg.no_cache = 1;
  cfg.insecure = insecure;

  /* Give a clear message up front rather than a confusing 400 from the token
   * endpoint, and never echo the secret itself. */
  if(cfg.instance_url == NULL || cfg.access_token == NULL){
    if(cfg.client_id == NULL || cfg.client_secret == NULL){
      if(instance != NULL || token != NULL){
        /* Exactly one of the two was supplied. Each is useless alone: the
         * instance says which org, the token says you may act on it, and a
         * request missing either is rejected in a way that reads like bad
         * credentials. */
        fprintf(stderr,
          SFCC_PROGNAME ": --%s was given without --%s.\n"
          "  Both are required together:\n"
          "    --instance  org base URL, e.g. https://acme.my.salesforce.com\n"
          "    --token     an access token for that org\n",
          instance != NULL ? "instance" : "token",
          instance != NULL ? "token" : "instance");
        return 2;
      }
      fprintf(stderr,
        SFCC_PROGNAME ": no credentials.\n"
        "  Either set both of these and let the client authenticate:\n"
        "    SFCC_CLIENT_ID      connected app consumer key\n"
        "    SFCC_CLIENT_SECRET  connected app consumer secret\n"
        "  Or supply an already-issued token directly:\n"
        "    --instance https://acme.my.salesforce.com --token <access token>\n"
        "  The secret is read from the environment only, never from an\n"
        "  argument, because command lines are visible to other processes.\n");
      return 2;
    }
  }

  sfcc_client* c = sfcc_client_new(&cfg);
  if(c == NULL){
    fprintf(stderr, SFCC_PROGNAME ": out of memory\n");
    return 1;
  }

  int rc = 0;
  sfcc_status st;

  if(strcmp(cmd, "auth") == 0){
    rc = cmd_auth(c);
  }else if(strcmp(cmd, "deploy") == 0){
    rc = cmd_deploy(c, zip_path, &dopts);
  }else if(strcmp(cmd, "rest") == 0){
    if(nargs != 1){
      fprintf(stderr, SFCC_PROGNAME ": rest needs exactly one path\n"
                      "  e.g. sfcc rest sobjects/Account/001000000000000AAA\n"
                      "       sfcc rest /services/data/{version}/limits\n");
      rc = 2;
    }else{
      /*
       * NULL-terminate before handing the array over. The API takes a
       * NULL-terminated `const char* const*` and walks it until the sentinel,
       * so without this it runs off the end of the stack array and dereferences
       * whatever happens to be there. That is not a theoretical hazard: it
       * segfaulted at -O2, where the slot is not incidentally zero, while
       * working by luck in a debug build. One slot is reserved for this at the
       * declaration, and the -H parser refuses to fill it.
       */
      const char* const* hdrs = NULL;
      if(nrest_headers > 0){
        rest_headers[nrest_headers] = NULL;
        hdrs = rest_headers;
      }
      const rest_args ra = {
        .method = rest_method,
        .data = rest_data,
        .data_file = rest_data_file,
        .output = rest_output,
        .include = rest_include,
        .headers = hdrs,
      };
      rc = cmd_rest(c, args[0], &ra);
    }
  }else if(strcmp(cmd, "versions") == 0){
    rc = cmd_versions(c);
  }else if(strcmp(cmd, "sobjects") == 0){
    if(nargs != 0){
      fprintf(stderr, SFCC_PROGNAME ": sobjects takes no arguments"
                  " (to list one object's fields, use: describe <object>)\n");
      rc = 2;
    }else{
      rc = cmd_sobjects(c, &sopts);
    }
  }else if(strcmp(cmd, "whoami") == 0){
    rc = cmd_whoami(c);
  }else if(strcmp(cmd, "query") == 0){
    if(nargs != 1){
      fprintf(stderr, SFCC_PROGNAME ": query needs exactly one SOQL statement\n"
                  "  (quote it, or the shell will split it)\n");
      rc = 2;
    }else{
      char* body = NULL;
      st = sfcc_query(c, args[0], &body);
      if(st != SFCC_OK){
        rc = report(c, st);
      }else{
        print_json(body);
        free(body);
      }
    }
  }else if(strcmp(cmd, "get") == 0 || strcmp(cmd, "delete") == 0){
    if(nargs != 2){
      fprintf(stderr, SFCC_PROGNAME ": %s needs an object name and a record id\n",
              cmd);
      rc = 2;
    }else if(strcmp(cmd, "get") == 0){
      char* body = NULL;
      st = sfcc_get_record(c, args[0], args[1], &body);
      if(st != SFCC_OK){
        rc = report(c, st);
      }else{
        print_json(body);
        free(body);
      }
    }else{
      st = sfcc_delete(c, args[0], args[1]);
      if(st != SFCC_OK){
        rc = report(c, st);
      }else if(!g_quiet){
        printf("deleted %s %s\n", args[0], args[1]);
      }
    }
  }else if(strcmp(cmd, "create") == 0){
    if(nargs != 2){
      fprintf(stderr, SFCC_PROGNAME ": create needs an object name and a JSON "
                  "object\n");
      rc = 2;
    }else{
      char* body = NULL;
      st = sfcc_create(c, args[0], args[1], &body);
      if(st != SFCC_OK){
        rc = report(c, st);
      }else{
        print_json(body);
        free(body);
      }
    }
  }else if(strcmp(cmd, "update") == 0){
    if(nargs != 3){
      fprintf(stderr, SFCC_PROGNAME ": update needs an object name, a record "
                  "id, and a JSON object\n");
      rc = 2;
    }else{
      char* body = NULL;
      st = sfcc_update(c, args[0], args[1], args[2], &body);
      if(st != SFCC_OK){
        rc = report(c, st);
      }else{
        if(body != NULL){
          print_json(body);
        }
        free(body);
        if(!g_quiet){
          printf("updated %s %s\n", args[0], args[1]);
        }
      }
    }
  }else if(strcmp(cmd, "describe") == 0){
    if(nargs != 1){
      fprintf(stderr, SFCC_PROGNAME ": describe needs an object name\n");
      rc = 2;
    }else{
      rc = cmd_describe(c, args[0], &dopts_desc);
    }
  }else{
    fprintf(stderr, SFCC_PROGNAME ": unknown command '%s' (try --help)\n", cmd);
    rc = 2;
  }

  sfcc_client_free(c);
  return rc;
}
