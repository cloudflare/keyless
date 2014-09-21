// kssl_helpers.c: protocol helper operations for keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "kssl.h"
#include "kssl_helpers.h"

#if PLATFORM_WINDOWS
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "kssl_log.h"

// Helper macros for stream processing. These macros ensure that the correct
// byte ordering is used.

// b is the buffer to read from/write to
// o is the offset in the buffer, incremented after the read/write
// v is the value to set
#define READ_BYTE(b, o) (b)[(o)]; (o)++;
#define READ_WORD(b, o) ntohs(*(WORD*)(&(b)[(o)])); (o) += sizeof(WORD);
#define READ_DWORD(b, o) ntohl(*(DWORD*)(&(b)[(o)])); (o) += sizeof(DWORD);
#define WRITE_BYTE(b, o, v) (b)[(o)] = (v); (o)++;
#define WRITE_WORD(b, o, v) *(WORD*)(&(b)[(o)]) = htons((v)); (o) += sizeof(WORD);
#define WRITE_DWORD(b, o, v) *(DWORD*)(&(b)[(o)]) = htonl((v)); (o) += sizeof(DWORD);
#define WRITE_BUFFER(b, o, v, l) memcpy(&(b)[(o)], (v), (l)); (o) += l;

#if PLATFORM_WINDOWS
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
#define PRINT_IP InetNtop
#else
#define PRINT_IP inet_ntop
#endif


// parse_header: populates a kssl_header structure from a byte stream. Returns
// KSSL_ERROR_NONE if successful.
kssl_error_code parse_header(BYTE *bytes,            // Stream of bytes
                                                     // containing a
                                                     // kssl_header
                             kssl_header *header) {  // Returns the populated
                                                     // header (must be
                                                     // allocated by caller)
  int offset = 0;

  if (bytes == NULL || header == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  header->version_maj = READ_BYTE(bytes, offset);
  header->version_min = READ_BYTE(bytes, offset);
  header->length = READ_WORD(bytes, offset);
  header->id = READ_DWORD(bytes, offset);

  return KSSL_ERROR_NONE;
}

// parse_item: Parse a kssl_item out of the body of a KSSL message
// NOTE: The payload for the item is not copied, a reference
// to the original stream is added to the kssl_item struct. The offset
// is updated if provided. Returns KSSL_ERROR_NONE if successful.
kssl_error_code parse_item(BYTE *bytes,       // Byte stream to parse
                                              // kssl_item from
                           int *offset,       // (optional) if present
                                              // specifies offset into bytes.
                           kssl_item *item) { // The kssl_item parsed (must be
                                              // allocated by caller)
  int local_offset = 0;
  BYTE local_tag;
  WORD local_len;
  BYTE *local_data;

  if (bytes == NULL || item == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  if (offset != NULL) {
    local_offset = *offset;
  }

  local_tag = READ_BYTE(bytes, local_offset);
  local_len = READ_WORD(bytes, local_offset);
  local_data = &bytes[local_offset];
  local_offset += local_len;

  item->tag = local_tag;
  item->length = local_len;
  item->data = local_data;

  if (offset != NULL) {
    *offset = local_offset;
  }

  return KSSL_ERROR_NONE;
}

// flatten_header: serialize a header into a pre-allocated byte array
// at a given offset. The offset is updated as bytes are written.  If
// offset pointer is NULL this function starts at offset 0.
kssl_error_code flatten_header(kssl_header *header, // Pointer to kssl_header
                                                    // to serialize
                               BYTE *bytes,         // Byte buffer to write
                                                    // into (must be allocated
                                                    // and have sufficient
                                                    // space for a
                                                    // kssl_header)
                               int *offset) {       // (optional) offset into
                                                    // bytes to
  int local_offset = 0;
                                                    // write to
  if (bytes == NULL || header == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  if (offset != NULL) {
    local_offset = *offset;
  }

  WRITE_BYTE(bytes, local_offset, header->version_maj);
  WRITE_BYTE(bytes, local_offset, header->version_min);
  WRITE_WORD(bytes, local_offset, header->length);
  WRITE_DWORD(bytes, local_offset, header->id);

  if (offset != NULL) {
    *offset = local_offset;
  }

  return KSSL_ERROR_NONE;
}

// flatten_item_byte: serialize a kssl_item with a given tag and one
// byte payload at an offset. The offset is updated as bytes are written.
// If offset pointer is NULL this function starts at offset 0. Returns
// KSSL_ERROR_NONE if successful.
kssl_error_code flatten_item_byte(BYTE tag,      // The kssl_item's tag (see
                                                 // kssl.h)
                                  BYTE payload , // A single byte for the
                                                 // payload
                                  BYTE *bytes,   // Buffer into which
                                                 // kssl_item is written (must
                                                 // be pre-allocated and have
                                                 // room)
                                  int *offset) { // (optional) offset into
                                                 // bytes to start writing at
  int local_offset = 0;
  if (bytes == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  if (offset != NULL) {
    local_offset = *offset;
  }

  WRITE_BYTE(bytes, local_offset, tag);
  WRITE_WORD(bytes, local_offset, 1);
  WRITE_BYTE(bytes, local_offset, payload);

  if (offset != NULL) {
    *offset = local_offset;
  }

  return KSSL_ERROR_NONE;
}

// flatten_item: Serialize a single kssl_item. The offset is updated
// as bytes are written. If offset pointer is NULL this function
// starts at offset 0. Returns KSSL_ERROR_NONE if successful.
kssl_error_code flatten_item(BYTE tag,         // The kssl_item's tag (see
                                               // kssl.h)
                             BYTE *payload,    // Buffer containing the item's
                                               // payload
                             WORD payload_len, // Length of data from payload
                                               // to copy
                             BYTE *bytes,      // Buffer into which item is
                                               // serialized
                             int *offset) {    // (optional) offset into bytes
                                               // to write from
  int local_offset = 0;

  if (bytes == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  if (offset != NULL) {
    local_offset = *offset;
  }

  WRITE_BYTE(bytes, local_offset, tag);
  WRITE_WORD(bytes, local_offset, payload_len);
  if (payload_len > 0) {
    WRITE_BUFFER(bytes, local_offset, payload, payload_len);
  }

  if (offset != NULL) {
    *offset = local_offset;
  }

  return KSSL_ERROR_NONE;
}

// add_padding: adds padding bytes to a KSSL message. Assumes that the buffer
// being written to is calloced.
kssl_error_code add_padding(WORD size,      // Length of padding
                            BYTE *bytes,    // Buffer into which item is
                                            // serialized
                            int *offset) {  // (optional) offset into bytes
                                            // to write from
  int local_offset = 0;

  if (bytes == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  if (offset != NULL) {
    local_offset = *offset;
  }

  // Add the padding. This gets added even is padding_size == 0

  WRITE_BYTE(bytes, local_offset, KSSL_TAG_PADDING);
  WRITE_WORD(bytes, local_offset, size);

  if (offset != NULL) {
    *offset = local_offset;
  }

  return KSSL_ERROR_NONE;
}

// flatten_operation: serialize a kssl_operation
kssl_error_code flatten_operation(kssl_header *header,       
                                  kssl_operation *operation, 
                                  BYTE **out_operation,      
                                  int *length) {             
  int local_req_len;
  BYTE *local_req;
  int offset = 0;
  int padding_size = 0;
  if (header == NULL        ||
      operation == NULL     ||
      out_operation == NULL ||
      length == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  // Allocate response (header + opcode + response)
  local_req_len = KSSL_HEADER_SIZE;

  if (operation->is_opcode_set) {
    local_req_len += KSSL_OPCODE_ITEM_SIZE;
  }
  if (operation->is_payload_set) {
    local_req_len += KSSL_ITEM_HEADER_SIZE + operation->payload_len;
  }
  if (operation->is_digest_set) {
    local_req_len += KSSL_ITEM_HEADER_SIZE + KSSL_DIGEST_SIZE;
  }
  if (operation->is_ip_set) {
    local_req_len += KSSL_ITEM_HEADER_SIZE + operation->ip_len;
  }

  // The operation will always be padded to KSSL_PAD_TO +
  // KSSL_ITEM_HEADER_SIZE bytes

  if (local_req_len < KSSL_PAD_TO) {
    padding_size = KSSL_PAD_TO - local_req_len;
  }
  
  local_req_len += KSSL_ITEM_HEADER_SIZE + padding_size;

  // The memory is calloced here to ensure that it is all zero. This is
  // important because the padding added below is done by just adding a
  // KSSL_ITEM at the end of the message stating that it has N bytes of
  // padding. 

  local_req = (BYTE *)calloc(local_req_len, 1);
  if (local_req == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  // Override header length
  header->length = local_req_len - KSSL_HEADER_SIZE;

  flatten_header(header, local_req, &offset);
  if (operation->is_opcode_set) {
    flatten_item_byte(KSSL_TAG_OPCODE, operation->opcode, local_req, &offset);
  }
  if (operation->is_payload_set) {
    flatten_item(KSSL_TAG_PAYLOAD, operation->payload, operation->payload_len,
        local_req, &offset);
  }
  if (operation->is_digest_set) {
    flatten_item(KSSL_TAG_DIGEST, operation->digest, KSSL_DIGEST_SIZE,
        local_req, &offset);
  }
  if (operation->is_ip_set) {
    flatten_item(KSSL_TAG_CLIENT_IP, operation->ip, operation->ip_len,
        local_req, &offset);
  }

  add_padding(padding_size, local_req, &offset);

  *out_operation = local_req;
  *length = local_req_len;

  return KSSL_ERROR_NONE;
}

// zero_operation: initialize a kssl_operation struct
void zero_operation(kssl_operation *operation) {
  if (operation != NULL) {
    operation->is_opcode_set = 0;
    operation->opcode = 0;
    operation->is_digest_set = 0;
    operation->digest = NULL;
    operation->is_payload_set = 0;
    operation->payload = NULL;
    operation->payload_len = 0;
    operation->is_ip_set = 0;
    operation->ip = NULL;
    operation->ip_len = 0;
  }
}

// parse_message_payload: parse a message payload into a
// kssl_operation struct
kssl_error_code parse_message_payload(BYTE *payload,               //
                                      int len,                     //
                                      kssl_operation *operation) { //
  int offset = 0;
  kssl_item temp_item;
  if (payload == NULL || operation == NULL) {
    return KSSL_ERROR_INTERNAL;
  }

  zero_operation(operation);

  // Count number of items and validate structure
  while (offset < len) {
    if (len - offset < (int)(KSSL_ITEM_HEADER_SIZE)) {
      return KSSL_ERROR_FORMAT;
    }

    if (parse_item(payload, &offset, &temp_item) != KSSL_ERROR_NONE ||
        len < offset) {
      return KSSL_ERROR_FORMAT;
    }

    // Iterate through known tags, populating necessary values
    switch (temp_item.tag) {
      case KSSL_TAG_OPCODE:
      {
        // Skip over malformed tags
        if (temp_item.length != 1) {
          continue;
        }

        operation->opcode = temp_item.data[0];
        operation->is_opcode_set = 1;
        break;
      }
      case KSSL_TAG_DIGEST:
      {
        // Skip over malformed tags
        if (temp_item.length != KSSL_DIGEST_SIZE) continue;
        operation->digest = temp_item.data;
        operation->is_digest_set = 1;
        break;
      }
      case KSSL_TAG_PAYLOAD:
      {
        operation->payload_len = temp_item.length;
        operation->payload = temp_item.data;
        operation->is_payload_set = 1;
        break;
      }
      case KSSL_TAG_CLIENT_IP:
      {
        operation->ip_len = temp_item.length;
        operation->ip = temp_item.data;
        operation->is_ip_set = 1;
        break;
      }
      case KSSL_TAG_PADDING:
      {
        break;
      }
      default:
        break;
    }
  }

  // check to see if opcode and payload are set
  if (operation->is_opcode_set == 0 || operation->is_payload_set == 0) {
    return KSSL_ERROR_FORMAT;
  }

  return KSSL_ERROR_NONE;
}

// opstring: convert a KSSL opcode byte to a string
const char *opstring(BYTE op) {
  switch (op) {
  case KSSL_OP_ERROR:
    return "KSSL_OP_ERROR";
  case KSSL_OP_PING:
    return "KSSL_OP_PING";
  case KSSL_OP_PONG:
    return "KSSL_OP_PONG";
  case KSSL_OP_RSA_DECRYPT:
    return "KSSL_OP_RSA_DECRYPT";
  case KSSL_OP_RESPONSE:
    return "KSSL_OP_RESPONSE";
  case KSSL_OP_RSA_SIGN_MD5SHA1:
    return "KSSL_OP_RSA_SIGN_MD5SHA1";
  case KSSL_OP_RSA_SIGN_SHA1:
    return "KSSL_OP_RSA_SIGN_SHA1";
  case KSSL_OP_RSA_SIGN_SHA224:
    return "KSSL_OP_RSA_SIGN_SHA224";
  case KSSL_OP_RSA_SIGN_SHA256:
    return "KSSL_OP_RSA_SIGN_SHA256";
  case KSSL_OP_RSA_SIGN_SHA384:
    return "KSSL_OP_RSA_SIGN_SHA384";
  case KSSL_OP_RSA_SIGN_SHA512:
    return "KSSL_OP_RSA_SIGN_SHA512";
  }
  return "UNKNOWN";
}

// errstring: convert a KSSL error to a string
const char *errstring(BYTE err) {
  switch (err) {
  case KSSL_ERROR_NONE:
    return "KSSL_ERROR_NONE";
  case KSSL_ERROR_CRYPTO_FAILED:
   return "KSSL_ERROR_CRYPTO_FAILED";
  case KSSL_ERROR_KEY_NOT_FOUND:
    return "KSSL_ERROR_KEY_NOT_FOUND";
  case KSSL_ERROR_READ:
    return "KSSL_ERROR_READ";
  case KSSL_ERROR_VERSION_MISMATCH:
    return "KSSL_ERROR_VERSION_MISMATCH";
  case KSSL_ERROR_BAD_OPCODE:
    return "KSSL_ERROR_BAD_OPCODE";
  case KSSL_ERROR_UNEXPECTED_OPCODE:
    return "KSSL_ERROR_UNEXPECTED_OPCODE";
  case KSSL_ERROR_FORMAT:
    return "KSSL_ERROR_FORMAT";
  case KSSL_ERROR_INTERNAL:
    return "KSSL_ERROR_INTERNAL";
  }
  return "UNKNOWN";
}

static void print_ip(kssl_operation *op, char *ip_string) {
  if (op == NULL) return;
  if (op->is_ip_set) {
    // IPv4 printing
    if (op->ip_len == 4) {
      struct in_addr ip;
      memcpy((void *)&ip.s_addr, op->ip, 4);
      PRINT_IP(AF_INET, &ip, ip_string, INET_ADDRSTRLEN);
    }
    if (op->ip_len == 16) {
      struct in6_addr ip;
      memcpy((void *)ip.s6_addr, op->ip, 16);
      PRINT_IP(AF_INET6, &ip, ip_string, INET6_ADDRSTRLEN);
    }
  }
}

// log_operation: write out a KSSL operation to the log
void log_operation(kssl_header *header, kssl_operation *op) {
  char ip_string[INET6_ADDRSTRLEN] = {0};

  // The \n at the end of the ctime return is chopped off here.

  time_t now = time(NULL); 
  char *nowstring = ctime(&now);
  nowstring[strlen(nowstring)-1] = '\0';

  print_ip(op, ip_string);
  
  write_log(0, "version:%d.%d, id:%d, op:%s, ip <%s>, time %s",
    header->version_maj, header->version_min, header->id,
    opstring(op->opcode), ip_string, nowstring);
}

// log_error: log an error of the operation
void log_error(DWORD id, BYTE code) {
  time_t result;
  result = time(NULL);
  write_log(1, "id:%d, error:%s, time:%s",
    id, errstring(code), ctime(&result));
}

