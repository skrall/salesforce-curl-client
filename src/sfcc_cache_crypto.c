/*
 * Encryption of the token cache at rest.
 *
 * The cache holds a bearer token that grants whatever the connected app's
 * integration user can do, and the explicit chmod 0600 in sfcc_auth.c protects
 * it only from other local accounts. It does not protect the file once it
 * leaves the machine: backups, cloud sync, disk images, and copied home
 * directories all carry the bytes along regardless of their mode bits.
 * Encryption is for that case, and for that case only. It says nothing about
 * anything already running as the user, who can read the token out of this
 * process's memory while it is in use.
 *
 * That scoping decides where the key may come from. A key stored on the same
 * disk as the ciphertext would only relocate the problem, so the key is
 * derived from SFCC_CACHE_PASSPHRASE and nothing else. There is no
 * --passphrase flag: arguments are visible to every process running as this
 * user, which is the same rule the client secret already follows.
 *
 * On-disk format, version 1 (all fields little-endian where they are wider
 * than a byte):
 *
 *     bytes  0..7    magic "SFCCENC1"
 *     byte   8       format version, currently 1
 *     bytes  9..12   PBKDF2 iteration count (uint32, part of the AAD)
 *     bytes 13..28   salt (16 bytes)
 *     bytes 29..40   nonce (12 bytes)
 *     then           ciphertext, same length as the plaintext
 *     last 16 bytes  AES-256-GCM tag
 *
 * The first 13 bytes -- magic, version, iteration count -- are the GCM
 * additional data, so a header cannot be edited without failing the tag
 * check. The salt and nonce are freshly random on every save, which store a
 * different key per file and mean the bytes are not stable until the next
 * token refresh rewrites them.
 *
 * Implementation note: every platform ships the primitives, so Windows uses
 * CNG and macOS uses CommonCrypto and pulls in nothing new. POSIX has no
 * standard equivalent, so Linux links libcrypto -- which is almost always
 * already loaded here, because libcurl needs TLS. The cost is a build-time
 * header requirement, not a new runtime package. The backend is chosen in
 * CMakeLists.txt, which defines exactly one SFCC_CRYPTO_BACKEND_*.
 */
#include "sfcc_internal.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The passphrase is read like every other secret: from the environment, and
 * only from the environment. An empty definition is treated as unset rather
 * than as a zero-character key, because "someone mean to set it" should not
 * produce a cache nobody can read back. */
const char* sfcc_cache_passphrase(void){
  const char* p = getenv("SFCC_CACHE_PASSPHRASE");
  if(p == NULL || *p == '\0'){
    return NULL;
  }
  return p;
}

/*
 * Zero memory holding key material before releasing it. free() leaves the
 * plaintext token in a reassignable heap block; a deliberate erase is the
 * only way to shorten that window, and a plain memset() can be optimized to
 * a no-op by the same compiler that knows the memory is dead. Writes through
 * a volatile pointer are not matched by that reasoning in any compiler this
 * project builds with.
 */
void sfcc_cache_zero(void* p, size_t n){
  if(p == NULL || n == 0){
    return;
  }
  volatile unsigned char* q = (volatile unsigned char*)p;
  while(n-- > 0){
    *q++ = 0;
  }
}

#if defined(SFCC_CRYPTO_BACKEND_OPENSSL)

#include <openssl/evp.h>
#include <openssl/rand.h>

int sfcc_cache_crypto_available(void){
  return 1;
}

static int backend_random(unsigned char* buf, size_t n){
  return RAND_bytes(buf, (int)n) == 1 ? 0 : -1;
}

static int backend_derive_key(const char* pass, size_t pass_len,
                              const unsigned char* salt, size_t salt_len,
                              unsigned long iters, unsigned char* key,
                              size_t key_len){
  unsigned long capped = iters;
  if(capped > (unsigned long)INT_MAX){
    /* PKCS5_PBKDF2_HMAC length fields are ints. Callers bound iterations
     * far below this at both ends, so the clamp is belt and braces rather
     * than load-bearing. */
    capped = (unsigned long)INT_MAX;
  }
  int rc = PKCS5_PBKDF2_HMAC(pass, (int)pass_len, salt, (int)salt_len,
                             (int)capped, EVP_sha256(),
                             (int)key_len, key);
  return rc == 1 ? 0 : -1;
}

static int backend_gcm_encrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* plaintext, size_t pt_len,
                               unsigned char* ciphertext, unsigned char* tag,
                               size_t tag_len){
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  int ok = 0;
  if(ctx == NULL){
    return -1;
  }
  int len = 0;
  (void)key_len;
  if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len,
                         NULL) == 1 &&
     EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
     (aad_len == 0 ||
      EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
     EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                       (int)pt_len) == 1 &&
     (size_t)len == pt_len &&
     EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) == 1 &&
     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len,
                         tag) == 1){
    ok = 1;
  }
  EVP_CIPHER_CTX_free(ctx);
  return ok ? 0 : -1;
}

static int backend_gcm_decrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* ciphertext, size_t ct_len,
                               unsigned char* plaintext, const unsigned char* tag,
                               size_t tag_len){
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  int ok = 0;
  if(ctx == NULL){
    return -1;
  }
  int len = 0;
  unsigned char sentinel[SFCC_CACHE_TAG_LEN];
  /* The expected tag is an input to SET_TAG, but the API types the
   * parameter as non-const; copying through a local keeps the cast, and
   * with it the -Wcast-qual trip, out of the source. */
  unsigned char given[SFCC_CACHE_TAG_LEN];
  memcpy(given, tag, tag_len);
  (void)key_len;
  /* The expected tag has to be installed before the final call, which is
   * what turns "decrypted cleanly" from an assumption into a check: the last
   * Update and the Final refuse the payload when the tag does not match. */
  if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len,
                         NULL) == 1 &&
     EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
                         given) == 1 &&
     (aad_len == 0 ||
      EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
     EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                       (int)ct_len) == 1 &&
     (size_t)len == ct_len &&
     EVP_DecryptFinal_ex(ctx, sentinel, &len) == 1){
    ok = 1;
  }
  EVP_CIPHER_CTX_free(ctx);
  return ok ? 0 : -1;
}

#elif defined(SFCC_CRYPTO_BACKEND_CNG)

#include <windows.h>
#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(st) (((NTSTATUS)(st)) >= 0)
#endif

int sfcc_cache_crypto_available(void){
  return 1;
}

static int backend_random(unsigned char* buf, size_t n){
  /* A NULL algorithm handle with the system-preferred-RNG flag is the
   * documented way to draw from the OS entropy pool; naming an algorithm
   * would make this depend on that provider being installed. */
  return NT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)n,
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ? 0 : -1;
}

static int backend_derive_key(const char* pass, size_t pass_len,
                              const unsigned char* salt, size_t salt_len,
                              unsigned long iters, unsigned char* key,
                              size_t key_len){
  BCRYPT_ALG_HANDLE h = NULL;
  int rc = -1;
  /* CNG carries PBKDF2 through a hash provider: PBKDF2 with SHA-256 is
   * requested by opening the SHA-256 algorithm and passing it as the PRF,
   * which is the same construction PKCS#5 spells out on paper. */
  if(NT_SUCCESS(BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM,
                                            NULL, 0)) &&
     NT_SUCCESS(BCryptDeriveKeyPBKDF2(h, (PUCHAR)pass, (ULONG)pass_len,
                                      (PUCHAR)salt, (ULONG)salt_len,
                                      (ULONGLONG)iters, key,
                                      (ULONG)key_len, 0))){
    rc = 0;
  }
  if(h != NULL){
    BCryptCloseAlgorithmProvider(h, 0);
  }
  return rc;
}

/*
 * Opens the AES provider preconfigured for GCM. Per call rather than cached
 * and reused: the KDF that precedes encryption costs three orders of
 * magnitude more time than this does, and a fresh handle needs no cleanup
 * reasoning across the retry paths.
 */
static int backend_gcm_open(BCRYPT_ALG_HANDLE* hAlg, BCRYPT_KEY_HANDLE* hKey,
                            const unsigned char* key, size_t key_len){
  if(!NT_SUCCESS(BCryptOpenAlgorithmProvider(hAlg, BCRYPT_AES_ALGORITHM,
                                             NULL, 0))){
    return -1;
  }
  if(!NT_SUCCESS(BCryptSetProperty(*hAlg, BCRYPT_CHAINING_MODE,
                                   (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                   sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) ||
     !NT_SUCCESS(BCryptGenerateSymmetricKey(*hAlg, hKey, NULL, 0,
                                            (PUCHAR)key, (ULONG)key_len, 0))){
    BCryptCloseAlgorithmProvider(*hAlg, 0);
    return -1;
  }
  return 0;
}

static void backend_gcm_close(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hKey){
  if(hKey != NULL){
    BCryptDestroyKey(hKey);
  }
  if(hAlg != NULL){
    BCryptCloseAlgorithmProvider(hAlg, 0);
  }
}

static int backend_gcm_encrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* plaintext, size_t pt_len,
                               unsigned char* ciphertext, unsigned char* tag,
                               size_t tag_len){
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_KEY_HANDLE hKey = NULL;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
  BCRYPT_INIT_AUTH_MODE_INFO(info);
  info.pbNonce = (PUCHAR)nonce;
  info.cbNonce = (ULONG)nonce_len;
  info.pbTag = tag;
  info.cbTag = (ULONG)tag_len;
  info.pbAAD = (PUCHAR)aad;
  info.cbAAD = (ULONG)aad_len;
  ULONG done = 0;
  int rc = -1;
  /* Both the struct and the trailing IV parameters name the nonce. They are
   * the same buffer by definition of the mode-info construction, which is
   * how CNG documents GCM. */
  if(backend_gcm_open(&hAlg, &hKey, key, key_len) == 0 &&
     NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)pt_len,
                              &info, (PUCHAR)nonce, (ULONG)nonce_len,
                              ciphertext, (ULONG)pt_len, &done, 0)) &&
     done == (ULONG)pt_len){
    rc = 0;
  }
  backend_gcm_close(hAlg, hKey);
  sfcc_cache_zero(&info, sizeof(info));
  return rc;
}

static int backend_gcm_decrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* ciphertext, size_t ct_len,
                               unsigned char* plaintext, const unsigned char* tag,
                               size_t tag_len){
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_KEY_HANDLE hKey = NULL;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
  BCRYPT_INIT_AUTH_MODE_INFO(info);
  info.pbNonce = (PUCHAR)nonce;
  info.cbNonce = (ULONG)nonce_len;
  info.pbTag = (PUCHAR)tag;      /* expected tag: BCryptDecrypt verifies */
  info.cbTag = (ULONG)tag_len;
  info.pbAAD = (PUCHAR)aad;
  info.cbAAD = (ULONG)aad_len;
  ULONG done = 0;
  int rc = -1;
  if(backend_gcm_open(&hAlg, &hKey, key, key_len) == 0 &&
     NT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)ct_len,
                              &info, (PUCHAR)nonce, (ULONG)nonce_len,
                              plaintext, (ULONG)ct_len, &done, 0)) &&
     done == (ULONG)ct_len){
    rc = 0;
  }
  backend_gcm_close(hAlg, hKey);
  sfcc_cache_zero(&info, sizeof(info));
  return rc;
}

#elif defined(SFCC_CRYPTO_BACKEND_CC)

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonRandom.h>

int sfcc_cache_crypto_available(void){
  return 1;
}

static int backend_random(unsigned char* buf, size_t n){
  return CCRandomGenerateBytes(buf, n) == kCCSuccess ? 0 : -1;
}

static int backend_derive_key(const char* pass, size_t pass_len,
                              const unsigned char* salt, size_t salt_len,
                              unsigned long iters, unsigned char* key,
                              size_t key_len){
  int rc = CCKeyDerivationPBKDF(kCCPBKDF2, pass, pass_len, salt, salt_len,
                                kCCPRFHmacAlgSHA256, iters, key, key_len);
  return rc == kCCSuccess ? 0 : -1;
}

/*
 * CommonCrypto's GCM interface predates the one-shot interface that replaced
 * it and is marked deprecated, which under -Werror would end this feature in
 * one line. There is no supported non-deprecated C-level GCM on macOS that
 * does not pull in another framework, and the deprecation describes an
 * interface preference rather than a defect in the primitive. So the warning
 * is deliberately suppressed around exactly this block, and CI is the place
 * that gets to say whether the suppression still compiles against the SDK of
 * the day.
 */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

static int backend_gcm_crypt(int decrypt,
                             const unsigned char* key, size_t key_len,
                             const unsigned char* nonce, size_t nonce_len,
                             const unsigned char* aad, size_t aad_len,
                             const unsigned char* in, size_t in_len,
                             unsigned char* out, unsigned char* tag,
                             size_t tag_len){
  CCCryptorRef cryptor = NULL;
  CCCryptorStatus st = CCCryptorCreateWithMode(
      decrypt ? kCCDecrypt : kCCEncrypt, kCCModeGCM, kCCAlgorithmAES,
      ccNoPadding, NULL /* GCM takes the IV through the GCM calls */,
      key, key_len, NULL, 0, 0 /* default rounds */, 0, &cryptor);
  if(st != kCCSuccess){
    return -1;
  }
  size_t moved = 0;
  int rc = -1;
  /* AAD, then payload, then the tag. The order does not change the GCM
   * result but keeps the two directions reading identically. */
  if(CCCryptorGCMAddIV(cryptor, nonce, nonce_len) == kCCSuccess &&
     (aad_len == 0 ||
      CCCryptorGCMaddCleartext(cryptor, aad, aad_len) == kCCSuccess) &&
     CCCryptorGCMaddCiphertext(cryptor, in, in_len, out, &moved) ==
         kCCSuccess &&
     moved == in_len &&
     CCCryptorGCMfinalize(cryptor, tag, tag_len) == kCCSuccess){
    rc = 0;
  }
  CCCryptorRelease(cryptor);
  return rc;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

static int backend_gcm_encrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* plaintext, size_t pt_len,
                               unsigned char* ciphertext, unsigned char* tag,
                               size_t tag_len){
  return backend_gcm_crypt(0, key, key_len, nonce, nonce_len, aad, aad_len,
                           plaintext, pt_len, ciphertext, tag, tag_len);
}

static int backend_gcm_decrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* ciphertext, size_t ct_len,
                               unsigned char* plaintext, const unsigned char* tag,
                               size_t tag_len){
  /* Verification is comparison in CommonCrypto: finalize computes the tag
   * for this input in either direction, and "did it verify" is the match
   * checked here, in constant time the compiler will still spot-check. */
  unsigned char computed[SFCC_CACHE_TAG_LEN];
  if(backend_gcm_crypt(1, key, key_len, nonce, nonce_len, aad, aad_len,
                       ciphertext, ct_len, plaintext, computed,
                       sizeof(computed))){
    sfcc_cache_zero(computed, sizeof(computed));
    return -1;
  }
  unsigned char diff = 0;
  for(size_t i = 0; i < SFCC_CACHE_TAG_LEN; i++){
    diff |= (unsigned char)(computed[i] ^ tag[i]);
  }
  sfcc_cache_zero(computed, sizeof(computed));
  return diff == 0 ? 0 : -1;
}

#else /* no backend compiled in */

/*
 * A build without a backend is not broken. Windows and macOS reach this
 * branch never, since their platform C APIs are unconditional; a Linux build
 * missing libcrypto reports that at configure time. What must work regardless
 * is the contract: every operation answers "not available", and the cache
 * layer stays on plaintext rather than pretending a file is protected.
 */
int sfcc_cache_crypto_available(void){
  return 0;
}

static int backend_random(unsigned char* buf, size_t n){
  (void)buf;
  (void)n;
  return -1;
}

static int backend_derive_key(const char* pass, size_t pass_len,
                              const unsigned char* salt, size_t salt_len,
                              unsigned long iters, unsigned char* key,
                              size_t key_len){
  (void)pass; (void)pass_len; (void)salt; (void)salt_len;
  (void)iters; (void)key; (void)key_len;
  return -1;
}

static int backend_gcm_encrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* plaintext, size_t pt_len,
                               unsigned char* ciphertext, unsigned char* tag,
                               size_t tag_len){
  (void)key; (void)key_len; (void)nonce; (void)nonce_len;
  (void)aad; (void)aad_len; (void)plaintext; (void)pt_len;
  (void)ciphertext; (void)tag; (void)tag_len;
  return -1;
}

static int backend_gcm_decrypt(const unsigned char* key, size_t key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* aad, size_t aad_len,
                               const unsigned char* ciphertext, size_t ct_len,
                               unsigned char* plaintext, const unsigned char* tag,
                               size_t tag_len){
  (void)key; (void)key_len; (void)nonce; (void)nonce_len;
  (void)aad; (void)aad_len; (void)ciphertext; (void)ct_len;
  (void)plaintext; (void)tag; (void)tag_len;
  return -1;
}

#endif /* backend */

/* ------------------------------------------------------------------------ */
/* Framing, shared by every backend                                          */
/* ------------------------------------------------------------------------ */

/* Greater than or equal to this means the buffer could be any well-formed
 * frame at all; less than it and the answer is "corrupt" before any field is
 * read: magic, version, iters, salt, nonce, tag, and a minimum ciphertext. */
#define SFCC_CACHE_HEADER_LEN 13
static size_t frame_fixed_len(void){
  return (size_t)SFCC_CACHE_MAGIC_LEN          /* magic                     */
       + 1                                     /* version                   */
       + 4                                     /* iters                     */
       + SFCC_CACHE_SALT_LEN
       + SFCC_CACHE_NONCE_LEN
       + SFCC_CACHE_TAG_LEN
       + 1;                                    /* minimum ciphertext        */
}

static void put_u32le(unsigned char* p, unsigned long v){
  p[0] = (unsigned char)(v & 0xffu);
  p[1] = (unsigned char)((v >> 8) & 0xffu);
  p[2] = (unsigned char)((v >> 16) & 0xffu);
  p[3] = (unsigned char)((v >> 24) & 0xffu);
}

static unsigned long get_u32le(const unsigned char* p){
  return (unsigned long)p[0] |
         ((unsigned long)p[1] << 8) |
         ((unsigned long)p[2] << 16) |
         ((unsigned long)p[3] << 24);
}

int sfcc_cache_wrap(const char* passphrase,
                    const unsigned char* plaintext, size_t pt_len,
                    unsigned long iters, sfcc_buf* out){
  if(out == NULL || (plaintext == NULL && pt_len != 0)){
    return SFCC_CACHE_ERR_ARG;
  }
  if(!sfcc_cache_crypto_available()){
    return SFCC_CACHE_ERR_CRYPTO_UNAVAILABLE;
  }
  if(passphrase == NULL || *passphrase == '\0'){
    return SFCC_CACHE_ERR_NO_PASSPHRASE;
  }
  if(iters < SFCC_CACHE_KDF_MINIMUM || iters > SFCC_CACHE_KDF_MAXIMUM){
    return SFCC_CACHE_ERR_KDF_RANGE;
  }
  if(pt_len > (size_t)INT_MAX || strlen(passphrase) > (size_t)INT_MAX){
    /* The backends hand lengths around as 32-bit ints. The cache is a token
     * record that never comes near this bound; reaching it means something
     * else has already gone wrong, so the honest answer is to stop. */
    return SFCC_CACHE_ERR_ARG;
  }
  size_t pass_len = strlen(passphrase);

  unsigned char key[SFCC_CACHE_KEY_LEN];
  unsigned char salt[SFCC_CACHE_SALT_LEN];
  unsigned char nonce[SFCC_CACHE_NONCE_LEN];
  unsigned char tag[SFCC_CACHE_TAG_LEN];
  unsigned char header[SFCC_CACHE_HEADER_LEN];
  unsigned char* ciphertext = malloc(pt_len > 0 ? pt_len : 1);
  if(ciphertext == NULL){
    return SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }

  memcpy(header, SFCC_CACHE_MAGIC, SFCC_CACHE_MAGIC_LEN);
  header[SFCC_CACHE_MAGIC_LEN] = SFCC_CACHE_FORMAT_VERSION;
  put_u32le(header + SFCC_CACHE_MAGIC_LEN + 1, iters);

  int rc = SFCC_CACHE_OK;
  if(backend_random(salt, sizeof(salt)) != 0){
    rc = SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }else if(backend_random(nonce, sizeof(nonce)) != 0){
    rc = SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }else if(backend_derive_key(passphrase, pass_len, salt, sizeof(salt),
                              iters, key, sizeof(key)) != 0){
    rc = SFCC_CACHE_ERR_OUT_OF_MEMORY;  /* backend failure, not memory; but
                                         * the cache layer treats every
                                         * failure here the same way */
  }else if(backend_gcm_encrypt(key, sizeof(key), nonce, sizeof(nonce),
                               header, sizeof(header),
                               plaintext, pt_len, ciphertext, tag,
                               sizeof(tag)) != 0){
    rc = SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }else if(sfcc_buf_append(out, (const char*)header, sizeof(header)) ||
           sfcc_buf_append(out, (const char*)salt, sizeof(salt)) ||
           sfcc_buf_append(out, (const char*)nonce, sizeof(nonce)) ||
           sfcc_buf_append(out, (const char*)ciphertext, pt_len) ||
           sfcc_buf_append(out, (const char*)tag, sizeof(tag))){
    rc = SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }

  sfcc_cache_zero(key, sizeof(key));
  sfcc_cache_zero(ciphertext, pt_len);
  free(ciphertext);
  if(rc != SFCC_CACHE_OK){
    /* A half-finished frame is worse than none: the caller cannot tell it
     * from a real one without repeating every length check. Rolled back to
     * whatever the buffer held before. */
    sfcc_cache_zero(out->data, out->len);
    sfcc_buf_free(out);
    sfcc_buf_init(out);
  }
  return rc;
}

int sfcc_cache_unwrap(const char* passphrase,
                      const unsigned char* frame, size_t frame_len,
                      sfcc_buf* out){
  if(out == NULL || (frame == NULL && frame_len != 0)){
    return SFCC_CACHE_ERR_ARG;
  }
  if(frame_len < frame_fixed_len()){
    return SFCC_CACHE_ERR_BAD_HEADER;
  }
  if(memcmp(frame, SFCC_CACHE_MAGIC, SFCC_CACHE_MAGIC_LEN) != 0){
    /* Only reachable when a caller did not check the magic first, which the
     * cache layer does and tests exploit: the answer to "is this file even
     * ours" happens before any decryption attempt. */
    return SFCC_CACHE_ERR_NOT_OURS;
  }
  if(frame[SFCC_CACHE_MAGIC_LEN] != SFCC_CACHE_FORMAT_VERSION){
    return SFCC_CACHE_ERR_BAD_HEADER;
  }
  unsigned long iters = get_u32le(frame + SFCC_CACHE_MAGIC_LEN + 1);
  if(iters < SFCC_CACHE_KDF_MINIMUM || iters > SFCC_CACHE_KDF_MAXIMUM){
    /* Both ends are checked, not only the floor. An iterations field near
     * 2^32 threatens nothing about security -- what it threatens is the
     * clock, burning minutes of KDF on every command until the file is
     * deleted. Refusing it reads as corruption, which is what it is. */
    return SFCC_CACHE_ERR_BAD_HEADER;
  }
  if(passphrase == NULL || *passphrase == '\0'){
    /* Checked after the format, so this distinguishes "an encrypted cache is
     * present" from "the file is corrupt" -- one of which is actionable. */
    return SFCC_CACHE_ERR_NO_PASSPHRASE;
  }

  const unsigned char* salt = frame + SFCC_CACHE_HEADER_LEN;
  const unsigned char* nonce = salt + SFCC_CACHE_SALT_LEN;
  const unsigned char* body = nonce + SFCC_CACHE_NONCE_LEN;
  size_t body_len = frame_len - (size_t)(body - frame) - SFCC_CACHE_TAG_LEN;
  const unsigned char* tag = body + body_len;
  const unsigned char* aad = frame;

  size_t pass_len = strlen(passphrase);
  unsigned char key[SFCC_CACHE_KEY_LEN];
  unsigned char* plaintext = malloc(body_len > 0 ? body_len : 1);
  if(plaintext == NULL){
    return SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }

  int rc = SFCC_CACHE_OK;
  if(backend_derive_key(passphrase, pass_len, salt, SFCC_CACHE_SALT_LEN,
                        iters, key, sizeof(key)) != 0){
    rc = SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }else if(backend_gcm_decrypt(key, sizeof(key), nonce, SFCC_CACHE_NONCE_LEN,
                               aad, SFCC_CACHE_HEADER_LEN, body, body_len,
                               plaintext, tag, SFCC_CACHE_TAG_LEN) != 0){
    /* Indistinguishable by design: a wrong passphrase, a file truncated in
     * the middle of a chain, and genuinely corrupt bytes all land here. One
     * code, one message. */
    rc = SFCC_CACHE_ERR_KEY_MISMATCH;
  }
  sfcc_cache_zero(key, sizeof(key));

  if(rc == SFCC_CACHE_OK &&
     (sfcc_buf_reserve(out, body_len) ||
      sfcc_buf_append(out, (const char*)plaintext, body_len))){
    rc = SFCC_CACHE_ERR_OUT_OF_MEMORY;
  }
  sfcc_cache_zero(plaintext, body_len);
  free(plaintext);
  if(rc != SFCC_CACHE_OK){
    sfcc_cache_zero(out->data, out->len);
    sfcc_buf_free(out);
    sfcc_buf_init(out);
  }
  return rc;
}
