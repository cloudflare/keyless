// kssl_core.h: core operation for the keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_CORE
#define INCLUDED_KSSL_CORE 1

#include "kssl.h"

// Allocate and populate a response to a keyless SSL request
// using an opaque list of private keys response to be freed by caller
kssl_error_code kssl_operate(
    kssl_header *header,        // pointer to the incoming header
    BYTE        *payload,       // pointer to the incoming payload
    pk_list      privates,      // reference to list of private keys
    BYTE       **response,      // response to be freed by caller
    int         *response_len); // length of response

// Create a keyless SSL response message corresponding to an error
// response to be freed by caller
kssl_error_code kssl_error(
    DWORD       id,             // id of error to create
    BYTE        error,          // value of error
    BYTE      **response,       // response to be freed by caller
    int        *response_len);  // length of response

#endif // INCLUDED_KSSL_CORE

