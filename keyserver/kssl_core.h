// kssl_core.h: core operation for the keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_CORE
#define INCLUDED_KSSL_CORE 1

// Allocate and populate a response to a keyless SSL request
// using an opaque list of private keys response to be freed by caller
int kssl_operate(
    kssl_header *header,
    BYTE *payload,
    pk_list privates,
    BYTE **response,
    int *response_len);

// Create a keyless SSL response message corresponding to an error
// response to be freed by caller
int kssl_error(
    DWORD id,
    BYTE error,
    BYTE **response,
    int *response_len);

#endif // INCLUDED_KSSL_CORE
