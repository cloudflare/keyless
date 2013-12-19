// kssl_private_key.h: private key storage for the keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_PRIVATE_KEY
#define INCLUDED_KSSL_PRIVATE_KEY 1

#include "kssl.h"

// public definition of private key list
typedef struct pk_list_* pk_list;

// interface for private key list

// return a list that holds count private keys
pk_list new_pk_list(int count);

// free a pk_list
void free_pk_list(pk_list list);

// add a private key from a file
kssl_error_code add_key_from_file(const char *path, pk_list list);

// return the key id of a private key matching the given modulus hash
int find_private_key(pk_list list, BYTE *digest);

// apply private key operation for given key id and opcode
kssl_error_code private_key_operation(pk_list list, int key_id, int opcode,
    int length, BYTE *message, BYTE *out, unsigned int *size);

// return the size of a key by id in bytes
int key_size(pk_list list, int key_id);

#endif // INCLUDED_KSSL_PRIVATE_KEY
