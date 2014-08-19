// kssl_thread.h: header for kssl_thread.c
//
// Copyright (c) 2014 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_THREAD
#define INCLUDED_KSSL_THREAD 1

#include "kssl.h"

extern void allocate_cb(uv_handle_t *h, size_t s, uv_buf_t *buf);
extern void new_connection_cb(uv_stream_t *server, int status);

extern void log_err_error();
extern void log_ssl_error(SSL *ssl, int rc);
extern pk_list privates;
extern uv_rwlock_t *pk_lock;

// This structure holds information about a single 'worker' (a thread)

#define CONNECTION_STATE_NEW 0x00

// Waiting for a connection header to be received

#define CONNECTION_STATE_GET_HEADER 0x01

// Waiting for the payload to be received

#define CONNECTION_STATE_GET_PAYLOAD 0x02

// The maximum number of items that can be queued to send. This must
// never be exceeded.

#define QUEUE_LENGTH 16

// An element in the queue of buffers to send

typedef struct {
  BYTE *start; // Start of the buffer (used for free())
  BYTE *send;  // Pointer to portion of buffer to send
  int len;     // Remaining number of bytes to send
} queued;

// This is the state of an individual SSL connection and is used for buffering
// of data received by SSL_read

typedef struct _connection_state {
  // Used to implement a doubly-linked list of connections that are
  // currently active. This is needed for cleanup on shutdown.

  struct _connection_state **prev;
  struct _connection_state *next;

  SSL *ssl;
  BYTE *start;   // Pointer to buffer into which SSL_read data is placed
  BYTE *current; // Pointer into start where SSL_read should write to
  int need;      // Number of bytes needed before start is considered 'full'
  int state;     // Current state of the connection (see defines above)
  BYTE wire_header[KSSL_HEADER_SIZE]; // Complete header once read from wire
  kssl_header header; // Parsed version of the header
  BYTE *payload; // Allocated for payload when necessary
  queued q[QUEUE_LENGTH];

  // File descriptor of the file this connection is on

  int fd;

  // These implement a circular buffer in q. qw points to the next entry
  // in the q that can be used to queue a buffer to send. qr points to
  // the next entry to be sent.
  //
  // if qr == qw then the buffer is empty.

  int qr;
  int qw;

  // Back link just used when cleaning up. This points to the TCP
  // connection that points to this connection_state through its data
  // pointer

  uv_tcp_t *tcp;

  // Pointers to the memory BIO used for communication with OpenSSL

  BIO *read_bio;
  BIO *write_bio;

  // Set to true when the TLS connection is set up

  int connected;
} connection_state;

typedef struct {
  uv_sem_t    semaphore;    // Semaphore used in thread startup
  uv_thread_t thread;       // The thread handle
  uv_tcp_t    server;       // The TCP server listen handle
  uv_async_t  stopper;      // Used to terminate threads
  SSL_CTX *   ctx;          // The OpenSSL context
  connection_state *active; // Active connection list
} worker_data;

#endif // INCLUDED_KSSL_THREAD

