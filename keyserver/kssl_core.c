// kssl_core.c: Core APIs for CloudFlare Keyless SSL protocol
//
// Copyright (c) 2013 CloudFlare, Inc.

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "kssl.h"
#include "kssl_helpers.h"

#include "kssl_private_key.h"
#include "kssl_core.h"

extern int silent;

// Public functions

// kssl_operate: create a serialized response from a KSSL request
// header and payload
kssl_error_code kssl_operate(kssl_header *header,
							 BYTE *payload,
							 pk_list privates,
							 BYTE **out_response,
							 int *out_response_len) {
  kssl_error_code err = KSSL_ERROR_NONE;
  BYTE *local_resp = NULL;
  int local_resp_len = 0;

  // Parse the indices of the items out of the payload
  kssl_header out_header;
  kssl_operation request;
  kssl_operation response;
  BYTE *out_payload = NULL;
  zero_operation(&request);
  zero_operation(&response);

  // Extract the items from the payload
  err = parse_message_payload(payload, header->length, &request);
  if (err != KSSL_ERROR_NONE) {
    goto exit;
  }

  if (silent == 0) {
    log_operation(&request);
  }

  switch (request.opcode) {
    // Other side sent response, error or pong: unexpected
    case KSSL_OP_RESPONSE:
    case KSSL_OP_ERROR:
    case KSSL_OP_PONG:
    {
      err = KSSL_ERROR_UNEXPECTED_OPCODE;
      break;
    }

    // Echo is trivial, it just echos the complete state->header back
    // including the payload item
    case KSSL_OP_PING:
    {
      response.is_payload_set = 1;
      response.payload = request.payload;
      response.payload_len = request.payload_len;
      response.is_opcode_set = 1;
      response.opcode = KSSL_OP_PONG;

      break;
    }

    // Decrypt or sign the payload using the private key
    case KSSL_OP_RSA_DECRYPT:
    case KSSL_OP_RSA_SIGN_MD5SHA1:
    case KSSL_OP_RSA_SIGN_SHA1:
    case KSSL_OP_RSA_SIGN_SHA224:
    case KSSL_OP_RSA_SIGN_SHA256:
    case KSSL_OP_RSA_SIGN_SHA384:
    case KSSL_OP_RSA_SIGN_SHA512:
    {
      unsigned int payload_size;
      int max_payload_size;
	  int key_id;

      if (request.is_digest_set == 0) {
        err = KSSL_ERROR_FORMAT;
        break;
      }

      // Identify private key from request digest
      key_id = find_private_key(privates, request.digest);
      if (key_id < 0) {
        err = KSSL_ERROR_KEY_NOT_FOUND;
        break;
      }

      // Allocate buffer to hold output of private key operation
      max_payload_size = key_size(privates, key_id);
      out_payload = malloc(max_payload_size);
      if (out_payload == NULL) {
        err = KSSL_ERROR_INTERNAL;
        break;
      }

      // Operate on payload
      err = private_key_operation(privates, key_id, request.opcode,
          request.payload_len, request.payload, out_payload,
          &payload_size);
      if (err != KSSL_ERROR_NONE) {
        err = KSSL_ERROR_CRYPTO_FAILED;
        break;
      }

      response.is_payload_set = 1;
      response.payload        = out_payload;
      response.payload_len    = payload_size;
      response.is_opcode_set  = 1;
      response.opcode         = KSSL_OP_RESPONSE;

      break;
    }

    // This should not occur
  default:
    {
      err = KSSL_ERROR_BAD_OPCODE;
      break;
    }
  }

exit:
  if (err != KSSL_ERROR_NONE) {
    err = kssl_error(header->id, err, &local_resp, &local_resp_len);
  } else {
    // Create output header
    out_header.version_maj = KSSL_VERSION_MAJ;
    out_header.version_min = KSSL_VERSION_MIN;
    out_header.id          = header->id;
    err = flatten_operation(&out_header, &response, &local_resp,
        &local_resp_len);
  }
  if (out_payload != NULL) {
    free(out_payload);
  }

  if (err == KSSL_ERROR_NONE) {
    *out_response = local_resp;
    *out_response_len = local_resp_len;
  }

  return KSSL_ERROR_NONE;
}

// see core.h
kssl_error_code kssl_error(DWORD id,
						   BYTE error,
						   BYTE **response,
						   int *response_len) {
  kssl_header e;
  int offset = 0;
  int size = KSSL_HEADER_SIZE + KSSL_OPCODE_ITEM_SIZE + KSSL_ERROR_ITEM_SIZE;
  BYTE *resp;

  if (response == NULL || response_len == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  resp = (BYTE *)malloc(size);
  if (resp == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  e.version_maj = KSSL_VERSION_MAJ;
  e.version_min = KSSL_VERSION_MIN;
  e.length  = size - KSSL_HEADER_SIZE;
  e.id      = id;

  flatten_header(&e, resp, &offset);
  flatten_item_byte(KSSL_TAG_OPCODE, KSSL_OP_ERROR, resp, &offset);
  flatten_item_byte(KSSL_TAG_PAYLOAD, error, resp, &offset);

  *response = resp;
  *response_len = size;

  return KSSL_ERROR_NONE;
}