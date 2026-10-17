/*
 * Buffers, strings, and the percent-encoder.
 *
 * The buffer is the only dynamic-allocation primitive in the project. HTTP
 * response bodies arrive in arbitrary chunks with no length announced up
 * front, so everything that grows ends up here rather than in ad-hoc realloc
 * calls.
 */
#include "sfcc_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Buffer                                                                   */
/* ------------------------------------------------------------------------ */

void sfcc_buf_init(sfcc_buf* b){
  if(b == NULL){
    return;
  }
  b->data = NULL;
  b->len = 0;
  b->cap = 0;
}

void sfcc_buf_free(sfcc_buf* b){
  if(b == NULL){
    return;
  }
  free(b->data);
  b->data = NULL;
  b->len = 0;
  b->cap = 0;
}

int sfcc_buf_reserve(sfcc_buf* b, size_t extra){
  if(b == NULL){
    return -1;
  }
  /* +1 keeps room for a NUL terminator so the buffer can be handed to
   * printf-style APIs and to str* functions without copying first. Every
   * sfcc_buf is therefore NUL-terminated at data[len]. */
  if(b->cap - b->len > extra && b->data != NULL){
    return 0;
  }
  size_t need = b->len + extra + 1;
  /* Guard against overflow on 32-bit targets before the multiply. */
  if(need < b->len){
    return -1;
  }
  size_t cap = b->cap ? b->cap : 256;
  while(cap < need){
    if(cap > (size_t)-1 / 2){
      cap = need;
      break;
    }
    cap *= 2;
  }
  char* p = realloc(b->data, cap);
  if(p == NULL){
    return -1;
  }
  b->data = p;
  b->cap = cap;
  return 0;
}

int sfcc_buf_append(sfcc_buf* b, const char* data, size_t n){
  if(b == NULL || (data == NULL && n)){
    return -1;
  }
  if(n == 0){
    if(b->data == NULL && sfcc_buf_reserve(b, 0)){
      return -1;
    }
    b->data[b->len] = '\0';
    return 0;
  }
  if(b->len + n > SFCC_MAX_BODY){
    return -1;
  }
  if(sfcc_buf_reserve(b, n)){
    return -1;
  }
  memcpy(b->data + b->len, data, n);
  b->len += n;
  b->data[b->len] = '\0';
  return 0;
}

int sfcc_buf_puts(sfcc_buf* b, const char* s){
  if(s == NULL){
    return -1;
  }
  return sfcc_buf_append(b, s, strlen(s));
}

int sfcc_buf_printf(sfcc_buf* b, const char* fmt, ...){
  if(b == NULL || fmt == NULL){
    return -1;
  }
  va_list va;
  /* vsnprintf consumes the va_list, so measure first and then render. Two
   * passes, but only one heap allocation. */
  va_start(va, fmt);
  int need = vsnprintf(NULL, 0, fmt, va);
  va_end(va);
  if(need < 0){
    return -1;
  }
  if(b->len + (size_t)need > SFCC_MAX_BODY){
    return -1;
  }
  if(sfcc_buf_reserve(b, (size_t)need)){
    return -1;
  }
  va_start(va, fmt);
  int wrote = vsnprintf(b->data + b->len, (size_t)need + 1, fmt, va);
  va_end(va);
  if(wrote != need){
    return -1;
  }
  b->len += (size_t)need;
  return 0;
}

/* RFC 3986 unreserved set: ALPHA / DIGIT / "-" / "." / "_" / "~".
 * Everything else is escaped, including '+' and '/'. Escaping '+' matters for
 * SOQL -- a query containing one would otherwise be decoded as a space. */
static int is_unreserved(unsigned char c){
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') ||
         c == '-' || c == '.' || c == '_' || c == '~';
}

int sfcc_buf_append_encoded(sfcc_buf* b, const char* src){
  static const char HEX[] = "0123456789ABCDEF";
  if(b == NULL || src == NULL){
    return -1;
  }
  for(const unsigned char* p = (const unsigned char*)src ; *p ; ++p){
    if(is_unreserved(*p)){
      char c = (char)*p;
      if(sfcc_buf_append(b, &c, 1)){
        return -1;
      }
    }else{
      char esc[3] = { '%', HEX[*p >> 4], HEX[*p & 0x0f] };
      if(sfcc_buf_append(b, esc, 3)){
        return -1;
      }
    }
  }
  return 0;
}

/* ------------------------------------------------------------------------ */
/* Strings                                                                  */
/* ------------------------------------------------------------------------ */

char* sfcc_strdup(const char* s){
  if(s == NULL){
    return NULL;
  }
  size_t n = strlen(s);
  char* p = malloc(n + 1);
  if(p == NULL){
    return NULL;
  }
  memcpy(p, s, n + 1);
  return p;
}

void sfcc_strfree(char** s){
  if(s == NULL){
    return;
  }
  free(*s);
  *s = NULL;
}

void sfcc_strset(char** slot, const char* value){
  char* copy = sfcc_strdup(value);   /* dup first so freeing the old value
                                      * cannot lose a copy-on-failure */
  if(value != NULL && copy == NULL){
    return;                          /* leave the previous value intact */
  }
  free(*slot);
  *slot = copy;
}

int sfcc_str_eq(const char* a, const char* b){
  if(a == NULL || b == NULL){
    return a == b;
  }
  return strcmp(a, b) == 0;
}

void sfcc_strip_trailing_slashes(char* s){
  if(s == NULL){
    return;
  }
  size_t n = strlen(s);
  while(n > 0 && s[n - 1] == '/'){
    s[--n] = '\0';
  }
}

/* ------------------------------------------------------------------------ */
/* Paths                                                                    */
/* ------------------------------------------------------------------------ */

const char* sfcc_home_dir(void){
#if defined(_WIN32)
  const char* h = getenv("USERPROFILE");
  if(h == NULL || !*h){
    h = getenv("HOME");
  }
  if(h == NULL || !*h){
    /* Fall back to the drive/path split, which is what USERPROFILE is
     * derived from on Windows anyway. */
    const char* d = getenv("HOMEDRIVE");
    const char* p = getenv("HOMEPATH");
    if(d != NULL && *d && p != NULL && *p){
      static char joined[4096];
      if(snprintf(joined, sizeof(joined), "%s%s", d, p) < (int)sizeof(joined)){
        return joined;
      }
    }
  }
  return (h != NULL && *h) ? h : NULL;
#else
  const char* h = getenv("HOME");
  return (h != NULL && *h) ? h : NULL;
#endif
}

const char* sfcc_default_cache_path(void){
  const char* home = sfcc_home_dir();
  if(home == NULL){
    return NULL;
  }
  static char path[4096];
  int n = snprintf(path, sizeof(path), "%s/.sfcc-token.json", home);
  if(n < 0 || (size_t)n >= sizeof(path)){
    return NULL;
  }
  return path;
}