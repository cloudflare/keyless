// kssl_private_key.h: private key storage for the keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_PRIVATE_KEY
#define INCLUDED_KSSL_PRIVATE_KEY 1

#include "kssl.h"

// public definition of private key list
typedef struct pk_list_* pk_list;

// interface for private key list

// new_pk_list: initializes an array of private keys. Returns a
// pointer to an opaque structure. count is the number of private keys
// to allocate space for.
pk_list new_pk_list(int count);

// free_pk_list: frees an array of private keys created with a call
// to new_pk_list
void free_pk_list(pk_list list);

// add_key_from_file: adds an RSA key from a file location, returns
// KSSL_ERROR_NONE if successful, or a KSSL_ERROR_* if a problem
// occurs. Adds the private key to the list if successful.
kssl_error_code add_key_from_file(const char *path, // Path to file containing key
                                  pk_list list);    // Array of private keys from new_pk_list

// add_key_from_buffer: adds an RSA key from a pointer, returns
// KSSL_ERROR_NONE if successful, or a KSSL_ERROR_* if a problem
// occurs. Adds the private key to the list if successful.
kssl_error_code add_key_from_buffer(const char *key, // Key value in PEM format
                                    int key_len,     // Length of key in bytes
                                    pk_list list);   // Array of private keys 

// find_private_key: returns an id for the key that matches the digest.
// In this implementation key id is the index into the list of privates.
// A negative return indicates an error.
int find_private_key(pk_list list,   // Array of private keys from new_pk_list
                     BYTE *digest);  // Digest of key searched for (see digest_public_modulus)

// private_key_operation: perform a private key operation
kssl_error_code private_key_operation(pk_list list,         // Private key array from new_pk_list
                                      int key_id,           // ID of key in pk_list from find_private_key
                                      int opcode,           // Opcode from a KSSL message indicating the operation
                                      int length,           // Length of data in message
                                      BYTE *message,        // Bytes to perform operation on
                                      BYTE *out,            // Buffer into which operation output is written
                                      unsigned int *size);  // Size of returned data written here

// key_size: returns the size of an RSA key in bytes
int key_size(pk_list list,  // Array of private keys from new_pk_list
             int key_id);   // ID of key from find_private_key

#endif // INCLUDED_KSSL_PRIVATE_KEY
