// kssl_helpers.h: protocol helper operations for keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_HELPERS
#define INCLUDED_KSSL_HELPERS 1

// Helper macros for known sizes of V1 items
#define KSSL_OPCODE_ITEM_SIZE (KSSL_ITEM_HEADER_SIZE + 1)
#define KSSL_ERROR_ITEM_SIZE (KSSL_ITEM_HEADER_SIZE + 1)
#define KSSL_DIGEST_SIZE 32

// Structure containing request information parsed from payload
typedef struct kssl_operation_ {
  int is_opcode_set;
  BYTE opcode;
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
kssl_error_code parse_message_payload(BYTE *payload, int len, kssl_operation *request);

// Populate a kssl_header structure from a byte stream
kssl_error_code parse_header(BYTE *bytes, kssl_header *header);

// Extract the data from a payload item from a given offset.
// the offset is updated as bytes are written.  If offset pointer is
// NULL this function starts at offset 0.
kssl_error_code parse_item(BYTE *bytes, int *offset, kssl_item *item);

// Serialize a header into a pre-allocated byte array at a given
// offset. The offset is updated as bytes are written.  If offset
// pointer is NULL this function starts at offset 0.
kssl_error_code flatten_header(kssl_header *header, BYTE *bytes, int *offset);

// Serialize a KSSL item with a given tag and one byte payload at an
// offset. The offset is updated as bytes are written.  If offset
// pointer is NULL this function starts at offset 0.
kssl_error_code flatten_item_byte(BYTE tag, BYTE payload, BYTE *bytes, int *offset);

// Serialize a KSSL item with a given tag and a payload at an offset.
// The offset is updated as bytes are written.  If offset pointer is NULL
// this function starts at offset 0.
kssl_error_code flatten_item(BYTE tag, BYTE *payload, WORD payload_len, BYTE *bytes,
    int *offset);

// Serialize a KSSL request
kssl_error_code flatten_operation(kssl_header *header, kssl_operation *request,
    BYTE **request_out, int *length);

// Log a summary of the operation
void log_operation(kssl_operation *op);

#endif // INCLUDED_KSSL_HELPERS
