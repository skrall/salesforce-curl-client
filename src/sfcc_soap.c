/*
 * Metadata retrieve, over SOAP.
 *
 * Why SOAP, when everything else here is REST: the Metadata API's retrieve has
 * no REST equivalent. Salesforce's own CLI and jsforce both call the SOAP
 * `retrieve` and `checkRetrieveStatus` operations, and a search of public code
 * turns up nothing using the REST deployRequest resource for retrieval --
 * `performRetrieve`, which would have been the obvious route, is documented as
 * "Reserved for future use". So this is the one place the client speaks SOAP,
 * and it speaks only as much as retrieve needs.
 *
 * Two properties shape the implementation:
 *
 * It does not parse XML. The <Package> element in a manifest has exactly the
 * shape of the <unpackaged> element the SOAP request wants, and both declare
 * the same default namespace, so the bytes between <Package ...> and </Package>
 * are copied across verbatim. Nothing is reinterpreted, so nothing can be
 * mis-escaped. A manifest that declares a namespace prefix on its contents is
 * refused rather than silently sent in the wrong namespace -- see the guard in
 * splice_unpackaged().
 *
 * It does not unpack. The retrieve response carries a base64 zipFile and
 * nothing else; there is no per-file content to write out. Storing the archive
 * as received keeps this small, and sidesteps the whole class of zip-slip
 * problems that come from trusting filenames in a remote archive. The archive
 * deploys straight back with sfcc deploy --zip.
 */
#include "sfcc_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>     /* Sleep, DWORD */
#endif

#define SFCC_RETRIEVE_POLL_DEFAULT 5L
#define SFCC_RETRIEVE_TIMEOUT_DEFAULT 900L   /* 15 minutes */

/*
 * SOAPAction is sent EMPTY, as SOAP 1.1 requires it to be present and as
 * Salesforce's Metadata binding expects: jsforce sends `SOAPAction: ""` and
 * dispatches on the body element, not the action.
 *
 * Naming the operation instead -- "retrieve", "checkRetrieveStatus" -- is what
 * this did first, and the org answered
 *
 *   Element {http://soap.sforce.com/2006/04/metadata}unpackaged invalid at this location
 *
 * Naming `unpackaged` as the offending element is the giveaway: it is a child of
 * <retrieve>, valid in the retrieve schema, so it could only be invalid if the
 * body were being validated against a different schema. That is what a
 * non-empty SOAPAction causes. The element names in the body were never the
 * problem; the header was.
 */
#define SOAPACTION_EMPTY "SOAPAction: \"\""

void sfcc_retrieve_options_defaults(sfcc_retrieve_options* opts){
  if(opts == NULL){
    return;
  }
  opts->poll_interval_s = SFCC_RETRIEVE_POLL_DEFAULT;
  opts->timeout_s = SFCC_RETRIEVE_TIMEOUT_DEFAULT;
}

/* ------------------------------------------------------------------------ */
/* Small helpers                                                              */
/* ------------------------------------------------------------------------ */

/*
 * memmem is a GNU extension and is not available on Windows or under a strict
 * C11 mode, so the two bounded searches this file needs are done here instead.
 */
static const char* find_bytes(const char* hay, size_t n, const char* needle){
  const size_t m = strlen(needle);
  if(m == 0 || m > n){
    return NULL;
  }
  for(size_t i = 0 ; i + m <= n ; ++i){
    if(memcmp(hay + i, needle, m) == 0){
      return hay + i;
    }
  }
  return NULL;
}

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

/* ------------------------------------------------------------------------ */
/* Reading the manifest                                                       */
/* ------------------------------------------------------------------------ */

/*
 * Copy the contents of the manifest's <Package> element into out.
 *
 * Not parsing: find the opening tag, take everything up to the closing tag, and
 * append it unchanged. The children of <Package> -- <types> with <members> and
 * <name>, and <version> -- are precisely the children of the SOAP request's
 * <unpackaged> element, and a conventionally written manifest already puts them
 * in the metadata namespace, so this is a faithful copy rather than a
 * reinterpretation.
 */
static sfcc_status splice_unpackaged(sfcc_client* c, const char* manifest,
                                     sfcc_buf* out){
  const char* open = strstr(manifest, "<Package");
  if(open == NULL){
    /*
     * A namespace-prefixed root, <md:Package>, is the realistic version of this
     * mistake and it fails the search above rather than reaching the xmlns guard
     * further down. Recognise it here so the explanation names the cause instead
     * of claiming the element is missing when it is plainly right there.
     */
    if(strstr(manifest, ":Package") != NULL){
      return sfcc_fail(c, SFCC_ERR_ARG,
                       "%s writes <Package> with a namespace prefix.\n"
                       "  sfcc copies the manifest's contents across unchanged,\n"
                       "  which works only when they use the default namespace:\n"
                       "    <Package xmlns=\"http://soap.sforce.com/2006/04/metadata\">\n"
                       "      <types><members>*</members><name>ApexClass</name></types>\n"
                       "    </Package>",
                       manifest);
    }
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "no <Package> element in %s -- is this a package.xml?",
                     manifest);
  }

  /* Past the attributes of the opening tag, to its '>'. Not a scan for the
   * first '>': an attribute value containing one would end the tag early. */
  const char* body = strchr(open, '>');
  if(body == NULL){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "<Package> element in %s is not closed", manifest);
  }
  ++body;

  const char* close = strstr(body, "</Package>");
  if(close == NULL){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "no closing </Package> in %s -- the file looks truncated",
                     manifest);
  }

  const size_t n = (size_t)(close - body);

  /*
   * Refuse an explicit namespace prefix on the contents.
   *
   * The default namespace is declared on the <Package> tag itself, which has
   * already been skipped, so any xmlns here is a prefix declaration -- meaning
   * the elements inside may be written as <md:types> rather than <types>.
   * Copying those across unchanged would put them in no namespace at all and the
   * org would answer with an opaque fault. Saying so beats sending it.
   */
  if(find_bytes(body, n, "xmlns:") != NULL){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "%s declares a namespace prefix inside <Package>.\n"
                     "  sfcc copies the manifest's contents across unchanged,\n"
                     "  which works only when they use the default namespace:\n"
                     "    <Package xmlns=\"http://soap.sforce.com/2006/04/metadata\">\n"
                     "      <types><members>*</members><name>ApexClass</name></types>\n"
                     "    </Package>",
                     manifest);
  }

  if(n == 0){
    return sfcc_fail(c, SFCC_ERR_ARG,
                     "<Package> in %s is empty -- nothing to retrieve", manifest);
  }
  if(sfcc_buf_append(out, body, n)){
    return sfcc_fail(c, SFCC_ERR_MEM,
                     "<Package> in %s is implausibly large to send", manifest);
  }
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* Building the request                                                       */
/* ------------------------------------------------------------------------ */

/*
 * The SOAP envelope.
 *
 * The default namespace is the metadata one, which is what lets the manifest's
 * bare element names be copied in unchanged.
 */
/*
 * The REST paths carry the version as "v64.0"; the SOAP/WSDL form is "64.0".
 * Same version, two spellings, and the org rejects the prefixed one here.
 */
static const char* bare_version(const char* v){
  if(v == NULL || *v == '\0'){
    v = SFCC_DEFAULT_API_VERSION;
  }
  return (v[0] == 'v' && v[1] != '\0') ? v + 1 : v;
}

/* The envelope head, shared by both operations. */
static void envelope_head(sfcc_buf* out, const char* session_id){
  sfcc_buf_puts(out,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"
    "              xmlns=\"http://soap.sforce.com/2006/04/metadata\">\n"
    "  <env:Header>\n"
    "    <SessionHeader>\n"
    "      <sessionId>");
  /*
   * A session id is an opaque Salesforce-generated string, so it is not markup
   * in practice. It is still escaped rather than trusted: putting a credential
   * into an XML document unsanitised is the one way it could become an injection
   * point, and the cost of not assuming is a few hundred bytes.
   */
  sfcc_buf_append_xml(out, session_id);
  sfcc_buf_puts(out,
    "</sessionId>\n"
    "    </SessionHeader>\n"
    "  </env:Header>\n"
    "  <env:Body>\n");
}

static void envelope_foot(sfcc_buf* out){
  sfcc_buf_puts(out,
    "  </env:Body>\n"
    "</env:Envelope>\n");
}

/*
 * checkRetrieveStatus, whose body must not be empty.
 *
 * Posting nothing gave "soapenv:Client: Premature end of file": the poll needs a
 * real envelope, not just the right method and content type. The WSDL:
 *
 *   <xsd:element name="checkRetrieveStatus">
 *     <xsd:sequence>
 *       <asyncProcessId type="tns:ID"/>       required
 *       <includeZip     type="xsd:boolean"/>  required
 *
 * Note the asymmetry with retrieve, which nests a single <retrieveRequest>
 * element; here the fields sit directly in the operation. Both are required, so
 * includeZip is sent true -- which is what asks for the archive rather than only
 * the status. There is no apiVersion in this request at all, which is why this
 * builder takes no version.
 */
static void build_check_envelope(const char* session_id, const char* async_id,
                                 sfcc_buf* out){
  envelope_head(out, session_id);
  sfcc_buf_puts(out, "    <checkRetrieveStatus>\n      <asyncProcessId>");
  sfcc_buf_append_xml(out, async_id);
  sfcc_buf_puts(out,
    "</asyncProcessId>\n"
    "      <includeZip>true</includeZip>\n"
    "    </checkRetrieveStatus>\n");
  envelope_foot(out);
}

static void build_envelope(const char* api_version, const char* session_id,
                           const char* unpackaged, sfcc_buf* out){
  const char* bare = bare_version(api_version);

  /*
   * Shape taken from the Metadata API WSDL rather than guessed:
   *
   *   <xsd:element name="retrieve">
   *     <xsd:sequence>
   *       <xsd:element name="retrieveRequest" type="tns:RetrieveRequest"/>
   *
   *   <xsd:complexType name="RetrieveRequest">
   *     <xsd:sequence>
   *       apiVersion        xsd:double       required
   *       packageNames      string           optional, repeated
   *       singlePackage     xsd:boolean      REQUIRED -- minOccurs defaults to 1
   *       specificFiles     string           optional, repeated
   *       unpackaged        tns:Package      optional
   *
   * Three things this version got wrong, each of which the org reported as
   * "Element {...}unpackaged invalid at this location":
   *
   *   - the retrieveRequest wrapper, so the fields were one level too high;
   *   - singlePackage omitted, because xsd defaults minOccurs to 1 and this
   *     reads as optional until you check;
   *   - sequence order, which is a sequence and not a choice.
   *
   * No LimitInfoHeader either: that is a partner-API header. The metadata WSDL
   * declares AllOrNoneHeader, DebuggingHeader and SessionHeader, and nothing
   * else.
   */
  envelope_head(out, session_id);
  sfcc_buf_puts(out,
    "    <retrieve>\n"
    "      <retrieveRequest>\n"
    "        <apiVersion>");
  sfcc_buf_puts(out, bare);
  sfcc_buf_puts(out,
    "</apiVersion>\n"
    "        <singlePackage>false</singlePackage>\n"
    "        <unpackaged>");
  sfcc_buf_puts(out, unpackaged);
  sfcc_buf_puts(out,
    "</unpackaged>\n"
    "      </retrieveRequest>\n"
    "    </retrieve>\n");
  envelope_foot(out);
}

/* ------------------------------------------------------------------------ */
/* Reading the response                                                       */
/* ------------------------------------------------------------------------ */

/*
 * Find <tag>...</tag> and copy the text between into out. Returns 1 if found.
 *
 * A deliberately tolerant tag scan rather than an XML parser, for the same
 * reason the request side does not parse: the response shape is fixed and
 * small, and a parser would be a large dependency to read six fields. Only
 * exactly-matching element names are found, so <id> never matches
 * <deployRequestId>.
 */
static int tag_text(const char* xml, const char* tag, sfcc_buf* out){
  char open[64];
  char close[64];
  const int no = snprintf(open, sizeof(open), "<%s>", tag);
  const int nc = snprintf(close, sizeof(close), "</%s>", tag);
  if(no <= 0 || no >= (int)sizeof(open) || nc <= 0 || nc >= (int)sizeof(close)){
    return 0;
  }

  const char* s = strstr(xml, open);
  if(s == NULL){
    return 0;
  }
  s += no;
  const char* e = strstr(s, close);
  if(e == NULL){
    return 0;
  }
  sfcc_buf_append(out, s, (size_t)(e - s));
  return 1;
}

static int tag_bool(const char* xml, const char* tag){
  sfcc_buf v;
  sfcc_buf_init(&v);
  const int found = tag_text(xml, tag, &v);
  const int truth = found && v.len == 4 && strncmp(v.data, "true", 4) == 0;
  sfcc_buf_free(&v);
  return truth;
}

static void unescape(sfcc_buf* s);

/* Pull a tag out of xml and unescape it into out. Returns 1 if found. */
static int tag_value(const char* xml, const char* tag, sfcc_buf* out){
  if(!tag_text(xml, tag, out)){
    return 0;
  }
  unescape(out);
  return 1;
}

/*
 * Undo XML escaping, in place.
 *
 * The five entities XML defines, plus numeric character references. A general
 * entity decoder is not wanted: Salesforce emits no custom entities, and a
 * hand-rolled DTD resolver would be both pointless and a liability.
 */
static void unescape(sfcc_buf* s){
  if(s == NULL || s->data == NULL || s->len == 0){
    return;
  }
  sfcc_buf o;
  sfcc_buf_init(&o);
  for(size_t i = 0 ; i < s->len ; ++i){
    if(s->data[i] != '&'){
      sfcc_buf_append(&o, s->data + i, 1);
      continue;
    }
    const char* rest = s->data + i;
    const char* semi = strchr(rest, ';');
    /* Bounded: no XML entity reference is longer than the longest one. */
    if(semi == NULL || semi - rest > 12){
      sfcc_buf_append(&o, s->data + i, 1);
      continue;
    }
    const size_t n = (size_t)(semi - rest - 1);
    const char* name = rest + 1;
    if(n == 2 && strncmp(name, "lt", 2) == 0){
      sfcc_buf_puts(&o, "<");
    }else if(n == 2 && strncmp(name, "gt", 2) == 0){
      sfcc_buf_puts(&o, ">");
    }else if(n == 3 && strncmp(name, "amp", 3) == 0){
      sfcc_buf_puts(&o, "&");
    }else if(n == 4 && strncmp(name, "quot", 4) == 0){
      sfcc_buf_puts(&o, "\"");
    }else if(n == 4 && strncmp(name, "apos", 4) == 0){
      sfcc_buf_puts(&o, "'");
    }else if(n >= 2 && name[0] == '#'){
      const unsigned long cp = (name[1] == 'x' || name[1] == 'X')
        ? strtoul(name + 2, NULL, 16) : strtoul(name + 1, NULL, 10);
      /* Re-encode as UTF-8. Only code points XML permits are produced; a
       * surrogate or out-of-range value is dropped rather than guessed at. */
      if(cp > 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF)){
        char b[4];
        int len;
        if(cp < 0x80){
          b[0] = (char)cp; len = 1;
        }else if(cp < 0x800){
          b[0] = (char)(0xC0 | (cp >> 6));
          b[1] = (char)(0x80 | (cp & 0x3F)); len = 2;
        }else if(cp < 0x10000){
          b[0] = (char)(0xE0 | (cp >> 12));
          b[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
          b[2] = (char)(0x80 | (cp & 0x3F)); len = 3;
        }else{
          b[0] = (char)(0xF0 | (cp >> 18));
          b[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
          b[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
          b[3] = (char)(0x80 | (cp & 0x3F)); len = 4;
        }
        sfcc_buf_append(&o, b, (size_t)len);
      }
    }else{
      sfcc_buf_append(&o, rest, (size_t)(semi - rest + 1));
    }
    i += (size_t)(semi - rest);
  }
  sfcc_buf_free(s);
  *s = o;
}

/*
 * Render a SOAP Fault as something worth reading.
 *
 * A different shape from every other error here: REST failures arrive as JSON
 * and sfcc_json_describe_error handles those. Here the useful text is in
 * <faultstring> with <faultcode> as the nearest thing to a code. The rest of the
 * fault is discarded, because it carries a stack trace nobody can act on.
 */
static void describe_fault(const char* body, char* out, size_t outsz){
  sfcc_buf code;
  sfcc_buf msg;
  sfcc_buf_init(&code);
  sfcc_buf_init(&msg);
  if(tag_value(body, "faultcode", &code)){ /* already unescaped */ }
  if(tag_value(body, "faultstring", &msg)){ /* already unescaped */ }

  if(msg.len == 0){
    /*
     * Not a SOAP fault. The likely cause is that the endpoint answered before
     * it looked at the body at all -- a wrong method or path produces an HTML
     * error page from the servlet, not a fault -- and echoing a page of markup
     * at the user is unreadable. Say what it was instead.
     */
    if(body != NULL && (strstr(body, "<html") != NULL ||
                        strstr(body, "<HTML") != NULL)){
      sfcc_buf title;
      sfcc_buf_init(&title);
      /* The one line of an HTML error page worth having. */
      if(tag_text(body, "title", &title)){
        unescape(&title);
        snprintf(out, outsz,
                 "the server returned an HTML page rather than a SOAP response"
                 " (%s) -- the request never reached the API", title.data);
      }else{
        snprintf(out, outsz,
                 "the server returned an HTML page rather than a SOAP response"
                 " -- the request never reached the API");
      }
      sfcc_buf_free(&title);
    }else{
      snprintf(out, outsz, "%s", body && *body ? body : "(no response)");
    }
  }else if(code.len > 0){
    snprintf(out, outsz, "%s: %s", code.data, msg.data);
  }else{
    snprintf(out, outsz, "%s", msg.data);
  }
  sfcc_buf_free(&code);
  sfcc_buf_free(&msg);
}

static void parse_status(const char* xml, sfcc_retrieve_result* out){
  sfcc_buf v;
  sfcc_buf_init(&v);
  sfcc_strset(&out->id, NULL);
  if(tag_value(xml, "id", &v)){
    sfcc_strset(&out->id, v.data);
  }
  sfcc_buf_free(&v);

  out->done = tag_bool(xml, "done");

  sfcc_buf_init(&v);
  if(tag_value(xml, "status", &v)){
    sfcc_strset(&out->status, v.data);
  }
  sfcc_buf_free(&v);

  out->succeeded = tag_bool(xml, "success");
}

void sfcc_retrieve_result_free(sfcc_retrieve_result* r){
  if(r == NULL){
    return;
  }
  sfcc_strfree(&r->id);
  sfcc_strfree(&r->status);
  r->done = 0;
  r->succeeded = 0;
  r->bytes = 0;
}

/* ------------------------------------------------------------------------ */
/* Base64                                                                     */
/* ------------------------------------------------------------------------ */

/*
 * Decode base64 into out.
 *
 * Characters outside the alphabet are skipped rather than rejected, and that is
 * not leniency for its own sake: Salesforce wraps the payload at line breaks
 * inside the XML, so a strict decoder would fail on every real response.
 */
static unsigned b64_value(unsigned char ch){
  if(ch >= 'A' && ch <= 'Z') return (unsigned)(ch - 'A');
  if(ch >= 'a' && ch <= 'z') return (unsigned)(ch - 'a' + 26);
  if(ch >= '0' && ch <= '9') return (unsigned)(ch - '0' + 52);
  if(ch == '+') return 62;
  if(ch == '/') return 63;
  return 0xFFFFFFFFu;   /* not a base64 character */
}

static sfcc_status base64_decode(const char* in, size_t n, sfcc_buf* out){
  sfcc_buf o;
  sfcc_buf_init(&o);
  unsigned long acc = 0;
  int bits = 0;
  for(size_t i = 0 ; i < n ; ++i){
    const unsigned v = b64_value((unsigned char)in[i]);
    if(v == 0xFFFFFFFFu){
      continue;   /* whitespace and '=' padding */
    }
    acc = (acc << 6) | v;
    bits += 6;
    if(bits >= 8){
      bits -= 8;
      const unsigned char byte = (unsigned char)((acc >> bits) & 0xFFu);
      if(sfcc_buf_append(&o, (const char*)&byte, 1)){
        sfcc_buf_free(&o);
        return SFCC_ERR_MEM;
      }
    }
  }
  sfcc_buf_free(out);
  *out = o;
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* Files                                                                      */
/* ------------------------------------------------------------------------ */

static sfcc_status read_manifest(const char* path, sfcc_buf* out){
  FILE* f = fopen(path, "rb");
  if(f == NULL){
    return SFCC_ERR_IO;
  }
  char chunk[8192];
  size_t got;
  int bad = 0;
  while((got = fread(chunk, 1, sizeof(chunk), f)) > 0){
    if(sfcc_buf_append(out, chunk, got)){
      bad = 1;
      break;
    }
  }
  if(ferror(f)){
    bad = 1;
  }
  fclose(f);
  if(bad){
    sfcc_buf_free(out);
    return SFCC_ERR_IO;
  }
  return SFCC_OK;
}

static sfcc_status write_file(const char* path, const char* data, size_t n){
  FILE* f = fopen(path, "wb");
  if(f == NULL){
    return SFCC_ERR_IO;
  }
  /* Written with the length, never strlen: a zip is binary and contains NUL
   * bytes well before its end. */
  const size_t wrote = (n > 0) ? fwrite(data, 1, n, f) : 0;
  const int ok = (wrote == n);
  if(fclose(f) != 0 || !ok){
    return SFCC_ERR_IO;
  }
  return SFCC_OK;
}

/* ------------------------------------------------------------------------ */
/* The command                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Build "<instance><path>" from the token's own instance_url.
 *
 * Built here rather than passed in by the caller so that a re-authentication
 * mid-call is reflected in the URL. A fresh token can name a different org than
 * the expired one did, and retrying against the old instance_url would produce a
 * 404 that looks nothing like the session error that caused the retry. This is
 * the same arrangement api_call() uses for the REST paths.
 */
static char* soap_url(const sfcc_client* c, const char* path){
  sfcc_buf b;
  sfcc_buf_init(&b);
  sfcc_buf_puts(&b, c->instance_url ? c->instance_url : "");
  sfcc_buf_puts(&b, path);
  char* url = sfcc_strdup(b.data ? b.data : "");
  sfcc_buf_free(&b);
  return url;
}

/*
 * Produce the request body for one attempt.
 *
 * A callback rather than a string because the envelope carries the session id.
 * Any retry mints a new token, so a body built once up front would go back out
 * still naming the session that had just been rejected -- and a stale session id
 * in an otherwise valid envelope produces a second failure that looks like a
 * bug rather than a retry.
 */
typedef void (*sfcc_soap_body_fn)(const sfcc_client* c, const void* ctx,
                                  sfcc_buf* out);

/*
 * One SOAP exchange, with one retry if the org says the session is dead.
 *
 * The retry is what the SOAP path was missing. REST had it and SOAP did not, so a
 * token that went stale between the cache being read and the request being sent
 * failed every retrieve outright while every query recovered silently -- the same
 * token, the same org, two different behaviours. That asymmetry is the whole
 * reason this reads as a bug worth fixing rather than an optimisation.
 *
 * One retry only. A second rejection means the credentials are wrong, and looping
 * would just make a clear error arrive slower.
 */
/* ctx for make_retrieve_body: the spliced <unpackaged> from the manifest. */
typedef struct {
  const char* unpackaged;
} retrieve_ctx;

/* ctx for make_check_body: the asyncProcessId returned by the request. */
typedef struct {
  const char* id;
} check_ctx;

static void make_retrieve_body(const sfcc_client* c, const void* ctx,
                               sfcc_buf* out){
  const retrieve_ctx* r = (const retrieve_ctx*)ctx;
  build_envelope(c->api_version, c->access_token, r->unpackaged, out);
}

static void make_check_body(const sfcc_client* c, const void* ctx, sfcc_buf* out){
  const check_ctx* cc = (const check_ctx*)ctx;
  build_check_envelope(c->access_token, cc->id ? cc->id : "", out);
}

static sfcc_status soap_call(sfcc_client* c, sfcc_method method,
                             const char* path, const char* action,
                             sfcc_soap_body_fn make_body, const void* ctx,
                             sfcc_buf* out){
  /*
   * Exactly "text/xml", with no charset parameter, on every call.
   *
   * Both halves of that were wrong. A real org answers
   *
   *   soapenv:Client: content-type of the request should be text/xml
   *
   * for "text/xml; charset=UTF-8", and for a request carrying no Content-Type
   * at all -- which is what the poll sent, because sfcc_http_request_ex only
   * sets Content-Type when there is a body, and the poll has none. jsforce
   * sends the bare 'text/xml' on both.
   *
   * So it goes in as an explicit header rather than as the content_type
   * argument: that argument is ignored without a body, and the header list is
   * honoured either way. One place sets it, and the bodyless poll is covered by
   * the same expression.
   */
  const char* headers[] = { action, "Content-Type: text/xml", NULL };

  for(int attempt = 0 ; attempt < 2 ; ++attempt){
    char* url = soap_url(c, path);
    if(url == NULL){
      return sfcc_fail(c, SFCC_ERR_MEM, "out of memory building the SOAP URL");
    }

    sfcc_buf body;
    sfcc_buf_init(&body);
    make_body(c, ctx, &body);

    sfcc_response resp;
    const sfcc_status rc = sfcc_http_request_ex(
        c, method, url, c->access_token, body.data, NULL, headers, &resp);
    sfcc_buf_free(&body);
    free(url);
    if(rc != SFCC_OK){
      return rc;
    }
    c->last_status = resp.status;

    if(resp.status >= 200 && resp.status < 300){
      if(out != NULL){
        /* The caller keeps the body: polling needs the final document to still
         * be there after the response has been released. */
        sfcc_buf_init(out);
        if(resp.body.data != NULL && resp.body.len > 0){
          sfcc_buf_append(out, resp.body.data, resp.body.len);
        }
      }
      sfcc_response_free(&resp);
      return SFCC_OK;
    }

    /* A SOAP fault for a dead session arrives as INVALID_SESSION_ID inside a
     * 500, not as a 401, so the shared test has to read the body as well as the
     * status. */
    if(attempt == 0 && sfcc_is_invalid_session(resp.status, resp.body.data) &&
       c->client_id != NULL && c->client_secret != NULL){
      sfcc_response_free(&resp);
      const sfcc_status auth = sfcc_auth_reauthenticate(c);
      if(auth != SFCC_OK){
        return auth;
      }
      /* Both the URL and the body are rebuilt on the next pass: the new token
       * can name a different org, and its session id is the one that has to
       * travel in the envelope. */
      continue;
    }

    char detail[SFCC_ERRLEN_MAX];
    describe_fault(resp.body.data ? resp.body.data : "", detail, sizeof(detail));
    sfcc_response_free(&resp);
    return sfcc_fail(c, (resp.status == 401 || resp.status == 403)
                     ? SFCC_ERR_AUTH : SFCC_ERR_HTTP, "%s", detail);
  }

  /* The loop returns on its last attempt, so this is unreachable. Returning a
   * real error rather than SFCC_OK keeps that a compiler-checked claim instead of
   * a comment: if a future edit added a third attempt, the fallthrough would be
   * visible here rather than silently reporting success. */
  return sfcc_fail(c, SFCC_ERR_AUTH,
                   "the org rejected the session after re-authenticating");
}

sfcc_status sfcc_retrieve(sfcc_client* c, const char* manifest_path,
                          const char* out_path,
                          const sfcc_retrieve_options* opts,
                          sfcc_retrieve_result* result){
  if(c == NULL || manifest_path == NULL || out_path == NULL || result == NULL){
    return SFCC_ERR_ARG;
  }
  memset(result, 0, sizeof(*result));

  sfcc_retrieve_options o;
  sfcc_retrieve_options_defaults(&o);
  if(opts != NULL){
    o = *opts;
  }
  if(o.poll_interval_s <= 0){
    o.poll_interval_s = SFCC_RETRIEVE_POLL_DEFAULT;
  }
  if(o.timeout_s <= 0){
    o.timeout_s = SFCC_RETRIEVE_TIMEOUT_DEFAULT;
  }

  sfcc_status rc = sfcc_ensure_auth(c);
  if(rc != SFCC_OK){
    return sfcc_fail(c, rc, "%s", sfcc_last_error(c) ? sfcc_last_error(c)
                                                     : sfcc_strerror(rc));
  }

  sfcc_buf manifest;
  sfcc_buf_init(&manifest);
  rc = read_manifest(manifest_path, &manifest);
  if(rc != SFCC_OK){
    sfcc_buf_free(&manifest);
    return sfcc_fail(c, rc, "cannot read %s", manifest_path);
  }

  sfcc_buf unpacked;
  sfcc_buf_init(&unpacked);
  rc = splice_unpackaged(c, manifest.data ? manifest.data : "", &unpacked);
  sfcc_buf_free(&manifest);
  if(rc != SFCC_OK){
    sfcc_buf_free(&unpacked);
    return rc;
  }

  /*
   * Bare version in the path, not the REST "v64.0" spelling: the endpoint is
   * /services/Soap/m/64.0 and a real org answers the prefixed form with
   *   soapenv:Client: Invalid Api version specified on URL : /m/v64.0
   * The envelope needs the same treatment and gets it from bare_version().
   *
   * Held as a path rather than a whole URL so soap_call can resolve it against
   * the token's own instance_url on each attempt, which is what makes a
   * re-authentication land on the right org.
   */
  sfcc_buf path;
  sfcc_buf_init(&path);
  sfcc_buf_puts(&path, "/services/Soap/m/");
  sfcc_buf_puts(&path, bare_version(c->api_version));

  const retrieve_ctx rctx = { unpacked.data };

  sfcc_buf doc;
  sfcc_buf_init(&doc);
  rc = soap_call(c, SFCC_HTTP_POST, path.data, SOAPACTION_EMPTY,
                 make_retrieve_body, &rctx, &doc);
  sfcc_buf_free(&unpacked);
  if(rc != SFCC_OK){
    sfcc_buf_free(&path);
    sfcc_buf_free(&doc);
    return rc;
  }

  /*
   * doc is deliberately kept alive past this point rather than released after
   * reading the status from it. A retrieve that is already done when it is
   * accepted skips the poll loop entirely, and the document holding the
   * archive is the one that came back with the request -- so freeing it here
   * lost the zipFile and reported "success but no archive".
   */
  parse_status(doc.data ? doc.data : "", result);

  if(result->id == NULL){
    sfcc_buf_free(&doc);
    sfcc_buf_free(&path);
    sfcc_retrieve_result_free(result);
    return sfcc_fail(c, SFCC_ERR_HTTP,
                     "the org accepted the request but returned no id");
  }

  /* --- poll -------------------------------------------------------------- */
  const time_t start = time(NULL);
  sfcc_progress prog;
  sfcc_progress_init(&prog);
  int first_poll = 1;

  while(!result->done){
    if(time(NULL) - start >= o.timeout_s){
      const char* id = result->id;
      sfcc_buf_free(&path);
      sfcc_retrieve_result_free(result);
      return sfcc_fail(c, SFCC_ERR_NET,
                       "gave up waiting after %lds; the retrieve may still be "
                       "running on the org (id %s)", o.timeout_s,
                       id ? id : "?");
    }

    if(!first_poll){
      sleep_seconds(o.poll_interval_s);
    }
    first_poll = 0;

    /* Replaced each round: the previous poll's document is no longer wanted,
     * and a retrieve that runs for a quarter of an hour would otherwise hold
     * every intermediate response until it finished. */
    sfcc_buf_free(&doc);
    /*
     * POST, not GET. Every SOAP operation is a POST in the SOAP 1.1 binding --
     * jsforce's soap() hardcodes method: 'POST' for retrieve and
     * checkRetrieveStatus alike -- and Salesforce answers anything else with an
     * HTML "Error 405 Only POST allowed" from its servlet, which is not a SOAP
     * fault and so arrives here as markup rather than as anything parseable.
     * The poll used to be a GET, carried over from the REST deployStatus
     * pattern, where a GET is exactly right.
     */
    const check_ctx cctx = { result->id };
    rc = soap_call(c, SFCC_HTTP_POST, path.data, SOAPACTION_EMPTY,
                   make_check_body, &cctx, &doc);
    if(rc != SFCC_OK){
      sfcc_buf_free(&path);
      sfcc_retrieve_result_free(result);
      return rc;
    }
    parse_status(doc.data ? doc.data : "", result);

    /*
     * Report on every poll rather than once. On a terminal that rewrites one
     * line, so it shows movement rather than accumulating; redirected, the
     * reporter throttles itself.
     */
    sfcc_progress_report(&prog, "retrieve", result->id, result->status,
                         (long)(time(NULL) - start), o.timeout_s,
                         o.poll_interval_s);
  }

  /* Clear the in-place line before anything else is printed. */
  sfcc_progress_finish(&prog);
  sfcc_buf_free(&path);

  /*
   * Retrieve is a successful call that can describe a failure, so this checks
   * succeeded rather than the return value: that is what says whether the org
   * produced an archive. On failure there is none, and writing an empty file
   * would look like a successful retrieve of nothing.
   */
  if(!result->succeeded){
    sfcc_buf problem;
    sfcc_buf_init(&problem);
    const int have = tag_value(doc.data ? doc.data : "", "problem", &problem);
    char why[SFCC_ERRLEN_MAX];
    if(have && problem.len > 0){
      snprintf(why, sizeof(why), "%s", problem.data);
    }else{
      snprintf(why, sizeof(why), "%s",
               result->status ? result->status : "the org reported a failure");
    }
    sfcc_buf_free(&problem);
    sfcc_buf_free(&doc);
    sfcc_retrieve_result_free(result);
    return sfcc_fail(c, SFCC_ERR_HTTP, "retrieve failed: %s", why);
  }

  /* --- the archive ------------------------------------------------------- */
  sfcc_buf b64;
  sfcc_buf_init(&b64);
  if(!tag_value(doc.data ? doc.data : "", "zipFile", &b64) || b64.len == 0){
    sfcc_buf_free(&b64);
    sfcc_buf_free(&doc);
    sfcc_retrieve_result_free(result);
    return sfcc_fail(c, SFCC_ERR_HTTP,
                     "the org reported success but returned no archive");
  }

  sfcc_buf zip;
  sfcc_buf_init(&zip);
  rc = base64_decode(b64.data, b64.len, &zip);
  sfcc_buf_free(&b64);
  sfcc_buf_free(&doc);
  if(rc != SFCC_OK){
    sfcc_buf_free(&zip);
    sfcc_retrieve_result_free(result);
    return sfcc_fail(c, rc, "could not decode the returned archive");
  }

  rc = write_file(out_path, zip.data ? zip.data : "", zip.len);
  const size_t n = zip.len;
  sfcc_buf_free(&zip);
  if(rc != SFCC_OK){
    sfcc_retrieve_result_free(result);
    return sfcc_fail(c, rc, "cannot write %s", out_path);
  }

  result->bytes = (long)n;
  return SFCC_OK;
}
