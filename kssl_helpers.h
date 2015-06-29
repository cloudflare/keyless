// kssl_helpers.h: protocol helper operations for keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_HELPERS
#define INCLUDED_KSSL_HELPERS 1

#include "kssl.h"

#ifdef _MSC_VER
#define PLATFORM_WINDOWS 1
#define WIN32_LEAN_AND_MEAN
#else
#define PLATFORM_WINDOWS 0
#endif

// Helper macros for known sizes of V1 items
#define KSSL_OPCODE_ITEM_SIZE (KSSL_ITEM_HEADER_SIZE + 1)
#define KSSL_ERROR_ITEM_SIZE (KSSL_ITEM_HEADER_SIZE + 1)
#define KSSL_SKI_SIZE 20
#define KSSL_DIGEST_SIZE 32

// Structure containing request information parsed from payload
typedef struct kssl_operation_ {
  int is_opcode_set;
  BYTE opcode;
  int is_ski_set;
  BYTE *ski;
  int is_digest_set;
  BYTE *digest;
  int is_payload_set;
  WORD payload_len;
  BYTE *payload;
  int is_ip_set;
  WORD ip_len;
  BYTE *ip;
} kssl_operation;

// Initialize a kssl_operation
void zero_operation(kssl_operation *request);

// Parse a raw message to extract kssl_operation information
kssl_error_code parse_message_payload(
  BYTE           *payload,  // incoming payload to parse
  int             len,      // length of payload
  kssl_operation *request); // request structure to populate

// Populate a kssl_header structure from a byte stream
kssl_error_code parse_header(
  BYTE           *bytes,    // incoming header to parse
  kssl_header    *header);  // header structure to populate

// Extract the data from a payload item from a given offset.
// the offset is updated as bytes are read.  If offset pointer is
// NULL this function starts at offset 0.
kssl_error_code parse_item(
  BYTE           *bytes,    // buffer containing payload
  int            *offset,   // offset payload begins, updated to end
  kssl_item      *item);    // item structure to populate

// Serialize a header into a pre-allocated byte array at a given
// offset. The offset is updated as bytes are written.  If offset
// pointer is NULL this function starts at offset 0.
kssl_error_code flatten_header(
  kssl_header   *header,    // header to serialize
  BYTE          *bytes,     // buffer to serialize into
  int           *offset);   // offset to write header, updated to end

// Serialize a KSSL item with a given tag and one byte payload at an
// offset. The offset is updated as bytes are written.  If offset
// pointer is NULL this function starts at offset 0.
kssl_error_code flatten_item_byte(
  BYTE           tag,       // tag value
  BYTE           payload,   // one-byte payload
  BYTE          *bytes,     // buffer to serialize into
  int           *offset);   // offset to write item, updated to end

// Serialize a KSSL item with a given tag and a payload at an offset.
// The offset is updated as bytes are written.  If offset pointer is NULL
// this function starts at offset 0.
kssl_error_code flatten_item(
  BYTE           tag,       // tag value
  BYTE          *payload,   // payload buffer
  WORD           payload_len,// size of payload
  BYTE          *bytes,     // buffer to serialize into
  int           *offset);   // offset to write item, updated to end

// Serialize a KSSL request
kssl_error_code flatten_operation(
  kssl_header   *header,    // header information
  kssl_operation *request,  // request information, including pointer to payload
  BYTE         **request_out,// request bytes, to be freed by caller
  int           *length);   // length of output

// add_padding: adds padding bytes to a KSSL message. Assumes that the buffer
// being written to is calloced.
kssl_error_code add_padding(WORD size,      // Length of padding
                            BYTE *bytes,    // Buffer into which item is
                                            // serialized
                            int *offset);   // (optional) offset into bytes
                                            // to write from

// Log a summary of the operation
void log_operation(kssl_header *header, kssl_operation *op);

// Log an error of the operation
void log_error(DWORD id, BYTE code);

// Map an opcode to the corresponding string
const char *opstring(BYTE op);

// Map an error code to a string
const char * error_string(int e);

#endif // INCLUDED_KSSL_HELPERS
