// kssl_private_key.c: OpenSSL-compatible implementation of CloudFlare Keyless
//                     SSL private key operations
//
// Copyright (c) 2013 CloudFlare, Inc.

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "kssl.h"
#include "kssl_helpers.h"
#include "kssl_log.h"

#include "kssl_private_key.h"
#include "kssl_core.h"

extern int silent;

// private_key is an RSA key with its associate SHA256 digest
typedef struct {
  BYTE digest[KSSL_DIGEST_SIZE];   // SHA256 digest of key.
  RSA *key;                        // RSA private key
} private_key;

// pk_list_ is an array of private_key structures
struct pk_list_ {
  int current;           // Number of entries in privates
  int allocated;         // Size of the privates array
  private_key *privates; // Array of private_key
};

// Private functions

// ssl_error: call when a fatal SSL error occurs. Exits the program
// with return code 1.
static void ssl_error() {
  ERR_print_errors_fp(stderr);
  exit(1);
}

// opcode_to_digest_nid: returns NID suitable to use in RSA_sign().
static int opcode_to_digest_nid(BYTE opcode) {
  switch (opcode) {
    case KSSL_OP_RSA_SIGN_MD5SHA1:
      return NID_md5_sha1;
    case KSSL_OP_RSA_SIGN_SHA1:
      return NID_sha1;
    case KSSL_OP_RSA_SIGN_SHA224:
      return NID_sha224;
    case KSSL_OP_RSA_SIGN_SHA256:
      return NID_sha256;
    case KSSL_OP_RSA_SIGN_SHA384:
      return NID_sha384;
    case KSSL_OP_RSA_SIGN_SHA512:
      return NID_sha512;
  }

  return 0;
}

// digest_public_modulus: calculates the SHA256 digest of the
// hexadecimal representation of the public modulus of an RSA
// key. digest must be initialized with at least 32 bytes of
// space and is used to return the SHA256 digest.
static void digest_public_modulus(RSA *key, BYTE *digest) {
  char *hex;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
  hex = BN_bn2hex(key->n);
  EVP_DigestUpdate(ctx, hex, strlen(hex));
  EVP_DigestFinal_ex(ctx, digest, 0);
  EVP_MD_CTX_destroy(ctx);
  OPENSSL_free(hex);
}

// constant_time_eq: compare to blocks of memory in constant time,
// returns 1 if they are equal, 0 if not.
static int constant_time_eq(BYTE *x, BYTE *y, int len) {
  BYTE z = 0;
  int i;
  for (i = 0; i < len; ++i) {
    z |= x[i] ^ y[i];
  }

  z = ~z;
  z &= z >> 4;
  z &= z >> 2;
  z &= z >> 1;

  return z;
}

// add_key_from_bio: adds an RSA key from a BIO pointer, returns
// KSSL_ERROR_NONE if successful, or a KSSL_ERROR_* if a problem
// occurs. Adds the private key to the list if successful.
static kssl_error_code add_key_from_bio(BIO *key_bp,     // BIO Key value in PEM format
                                        pk_list list) {  // Array of private keys 
  RSA *local_key;

  local_key = PEM_read_bio_RSAPrivateKey(key_bp, 0, 0, 0);
  if (local_key == NULL) {
    ssl_error();
  }

  if (list->current >= list->allocated) {
    write_log("Private key list maximum reached");
    return KSSL_ERROR_INTERNAL;
  }

  if (RSA_check_key(local_key) != 1) {
    return KSSL_ERROR_INTERNAL;
  }

  list->privates[list->current].key = local_key;
  digest_public_modulus(local_key, list->privates[list->current].digest);

  list->current++;

  return KSSL_ERROR_NONE;
}


// Public functions

// new_pk_list: initializes an array of private keys. Returns a
// pointer to an opaque structure. count is the number of private keys
// to allocate space for.
pk_list new_pk_list(int count) {
  pk_list list = (pk_list)malloc(sizeof(struct pk_list_));
  if (list == NULL) {
    write_log("Memory error");
    return NULL;
  }

  list->privates = (private_key *)malloc(sizeof(private_key) * count);
  if (list->privates == NULL) {
    write_log("Memory error");
    free(list);
    return NULL;
  }

  list->current = 0;
  list->allocated = count;

  return list;
}

// free_pk_list: frees an array of private keys created with a call
// to new_pk_list
void free_pk_list(pk_list list) {
  if (list) {
    if (list->privates) {
      int j;

      for (j = 0; j < list->current; ++j) {
        RSA_free(list->privates[j].key);
      }
      free(list->privates);
    }
    free(list);
  }
}

// add_key_from_file: adds am RSA key from a file location, returns
// KSSL_ERROR_NONE if successful, or a KSSL_ERROR_* if a problem
// occurs. Adds the private key to the list if successful.
kssl_error_code add_key_from_file(const char *path, // Path to file containing key
                                  pk_list list) {   // Array of private keys from new_pk_list
  int rc;
  BIO *bp;
  kssl_error_code err = KSSL_ERROR_NONE;

  bp = BIO_new(BIO_s_file());
  if (bp == NULL) {
    ssl_error();
  }

  rc = BIO_read_filename(bp, path);
  if (!rc) {
    write_log("Failed to open private key file %s", path);
    return KSSL_ERROR_INTERNAL;
  }
  
  err = add_key_from_bio(bp, list);
  if (err != KSSL_ERROR_NONE) {
    write_log("Private RSA key from file %s is not valid", path);
    BIO_free(bp);

    return KSSL_ERROR_INTERNAL;
  }

  BIO_free(bp);

  return KSSL_ERROR_NONE;
}

// add_key_from_buffer: adds an RSA key from a pointer, returns
// KSSL_ERROR_NONE if successful, or a KSSL_ERROR_* if a problem
// occurs. Adds the private key to the list if successful.
kssl_error_code add_key_from_buffer(const char *key, // Key value in PEM format
                                    int key_len,     // Length of key in bytes
                                    pk_list list) {  // Array of private keys 
  BIO *bp;
  kssl_error_code err = KSSL_ERROR_NONE;

  if (!list) {
    write_log("Assigning to NULL");
    return KSSL_ERROR_INTERNAL;
  }

  bp = BIO_new_mem_buf((void*)key, key_len);
  if (bp == NULL) {
    ssl_error();
  }

  err = add_key_from_bio(bp, list);
  if (err != KSSL_ERROR_NONE) {
    write_log("Private RSA key is not valid");
    BIO_free(bp);
    return KSSL_ERROR_INTERNAL;
  }

  BIO_free(bp);
  return KSSL_ERROR_NONE;
}

// find_private_key: returns an id for the key that matches the digest.
// In this implementation key id is the index into the list of privates.
// A negative return indicates an error.
int find_private_key(pk_list list,   // Array of private keys from new_pk_list
                     BYTE *digest) { // Digest of key searched for (see digest_public_modulus)
  int j;
  int found = 0;
  for (j = 0; j < list->current; j++) {
    if (constant_time_eq(list->privates[j].digest, digest, KSSL_DIGEST_SIZE) == 1) {
      found = 1;
      break;
    }
  }

  if (!found) {
    // return non-fatal error indicating key missing
    return -1;
  }

  return j;
}

// private_key_operation: perform a private key operation
kssl_error_code private_key_operation(pk_list list,         // Private key array from new_pk_list
                                      int key_id,           // ID of key in pk_list from find_private_key
                                      int opcode,           // Opcode from a KSSL message indicating the operation
                                      int length,           // Length of data in message
                                      BYTE *message,        // Bytes to perform operation on
                                      BYTE *out,            // Buffer into which operation output is written
                                      unsigned int *size) { // Size of returned data written here
  int rc = KSSL_ERROR_NONE;

  // Currently, we only support decrypt or sign here

  if (opcode == KSSL_OP_RSA_DECRYPT) {
    int s = RSA_private_decrypt(length, message, out, list->privates[key_id].key,
                             RSA_PKCS1_PADDING);
    if (s != -1) {
      *size = (unsigned int)s;
    } else {
      rc = KSSL_ERROR_CRYPTO_FAILED;
    }
  } else {
    if (RSA_sign(opcode_to_digest_nid(opcode), message, length, out, size,
                 list->privates[key_id].key) != 1) {
      rc = KSSL_ERROR_CRYPTO_FAILED;
    }
  }

  return rc;
}

// key_size: returns the size of an RSA key in bytes
int key_size(pk_list list,  // Array of private keys from new_pk_list
             int key_id) {  // ID of key from find_private_key
  return RSA_size(list->privates[key_id].key);
}


