// kssl_thread.c: all the functions used by a single thread
//
// Copyright (c) 2014 CloudFlare, Inc.

#include "kssl.h"
#include "kssl_helpers.h"

#if PLATFORM_WINDOWS
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/ip.h>
#include <getopt.h>
#include <glob.h>
#endif
#include <fcntl.h>
#include <uv.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include <stdarg.h>

#include "kssl_log.h"
#include "kssl_private_key.h"
#include "kssl_core.h"
#include "kssl_thread.h"

// initialize_state: set the initial state on a newly created connection_state
void initialize_state(connection_state **active, connection_state *state)
{
  // Insert at the start of the list
  state->prev = active;
  if (*active) {
    state->next = *active;
    (*active)->prev = &state->next;
  } else {
    state->next = 0;
  }
  *active = state;

  state->ssl = 0;
  state->start = 0;
  state->current = 0;
  state->need = 0;
  state->state = CONNECTION_STATE_NEW;
  state->payload = 0;
  state->qr = 0;
  state->qw = 0;
  state->fd = 0;
  state->connected = 0;
}

// queue_write: adds a buffer of dynamically allocated memory to the
// queue in the connection_state.
void queue_write(connection_state *state, BYTE *b, int len)
{
  state->q[state->qw].start = b;
  state->q[state->qw].send = b;
  state->q[state->qw].len = len;

  state->qw += 1;

  if (state->qw == QUEUE_LENGTH) {
    state->qw = 0;
  }

  // If the write marker catches up with the read marker then the buffer
  // has overflowed. This is a fatal condition and causes data to be
  // lost. This should *never* happen as the queue should be sized so that
  // there are never more than QUEUE_LENGTH buffers waiting to be
  // sent.

  if (state->qr == state->qw) {
    write_log(1, "Connection state queue full. Data lost.");
    state->qw -= 1;
    free(b);
    if (state->qw == -1) {
      state->qw = QUEUE_LENGTH-1;
    }
  }
}

// write_error: queues a KSSL error message for sending.
void write_error(connection_state *state, DWORD id, BYTE error)
{
  int size = 0;
  BYTE *resp = NULL;

  kssl_error_code err = kssl_error(id, error, &resp, &size);
  log_error(id, error);
  if (err != KSSL_ERROR_INTERNAL) {
    queue_write(state, resp, size);
  }
}

// set_get_header_state: puts a connection_state in the state to receive
// a complete kssl_header.
void set_get_header_state(connection_state *state)
{
  state->start = state->wire_header;
  state->current = state->start;
  state->need = KSSL_HEADER_SIZE;
  state->state = CONNECTION_STATE_GET_HEADER;
  state->payload = 0;

  state->header.version_maj = 0;
  state->header.version_min = 0;
  state->header.length = 0;
  state->header.id = 0;
  state->header.data = 0;
}

// set_get_payload_state: puts a connection_state in the state to receive
// a message payload. Memory allocated can be freed by calling
// free_read_state()
void set_get_payload_state(connection_state *state, int size)
{
  state->payload = (BYTE *)malloc(size);
  state->start = state->payload;
  state->current = state->start;
  state->need = size;
  state->state = CONNECTION_STATE_GET_PAYLOAD;
}

// free_read_state: free memory allocated in a connection_state for
// reads
void free_read_state(connection_state *state)
{
  if (state->payload != 0) {
    free(state->payload);
  }

  state->start = 0;
  state->payload = 0;
  state->current = 0;
}

// close_cb: called when a TCP connection has been closed
void close_cb(uv_handle_t *tcp)
{
  connection_state *state = (connection_state *)tcp->data;

  if (state != NULL) {
    SSL_free(state->ssl);
  }

  free(tcp);
  if (state != NULL) {
    free_read_state(state);
    free(state);
  }
}

// connection_terminate: terminate an SSL connection and remove from
// event loop. Clean up any allocated memory.
void connection_terminate(uv_tcp_t *tcp)
{
  connection_state *state = (connection_state *)tcp->data;
  SSL *ssl = state->ssl;

  int rc = SSL_shutdown(ssl);
  if (rc == 0) {
    SSL_shutdown(ssl);
  }

  rc = uv_read_stop((uv_stream_t *)tcp);
  if (rc != 0) {
    write_log(1, "Failed to stop TCP read: %s", 
              error_string(rc));
  }

  *(state->prev) = state->next;
  if (state->next) {
    state->next->prev = state->prev;
  }

  uv_close((uv_handle_t *)tcp, close_cb);
}

// write_queued_message: write all messages in the queue onto the wire
kssl_error_code write_queued_messages(connection_state *state)
{
  SSL *ssl = state->ssl;
  int rc;
  while ((state->qr != state->qw) && (state->q[state->qr].len > 0)) {
    queued *q = &state->q[state->qr];
    rc = SSL_write(ssl, q->send, q->len);

    if (rc > 0) {
      q->len -= rc;
      q->send += rc;

      // If the entire buffer has been sent then it should be removed from
      // the queue and its memory freed

      if (q->len == 0) {
        free(q->start);
        state->qr += 1;
        if (state->qr == QUEUE_LENGTH) {
          state->qr = 0;
        }
      }
    } else {
      switch (SSL_get_error(ssl, rc)) {

        // If either occurs then OpenSSL documentation states that the
        // SSL_write must be retried which will happen next time

      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        ERR_clear_error();
        break;

        // Indicates that the connection has been shutdown and the
        // write failed.

      case SSL_ERROR_ZERO_RETURN:
        ERR_clear_error();
        return KSSL_ERROR_INTERNAL;

      default:
        log_ssl_error(ssl, rc);
        return KSSL_ERROR_INTERNAL;
      }
    }

    // On any error condition leave the send loop

    break;
  }

  return KSSL_ERROR_NONE;
}

// clear_read_queue: a message of unknown version was sent, so ignore
// the rest of the message
void clear_read_queue(connection_state *state)
{
  SSL *ssl = state->ssl;
  int read = 0;
  BYTE ignore[1024];

  do {
    read = SSL_read(ssl, ignore, 1024);
  } while (read > 0);
}

// wrote_cb: called when a socket wrote has succeeded
void wrote_cb(uv_write_t* req, int status)
{
  if (req) {
    free(req);
  }
}

// flush_write: flushes data in the write BIO to the network
// connection. Returns 1 if successful, 0 on error
int flush_write(connection_state *state)
{
#define BUF_SIZE 1024
  char b[BUF_SIZE];
  int n;

  while ((n = BIO_read(state->write_bio, &b[0], BUF_SIZE)) > 0) {
    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    uv_buf_t buf = uv_buf_init(&b[0], n);

    int rc = uv_write(req, (uv_stream_t*)state->tcp, &buf, 1, wrote_cb);
    if (rc < 0) {
      return 0;
    }
  }

  return 1;
}

// do_ssl: process pending data from OpenSSL and send any data that's
// waiting. Returns 1 if ok, 0 if the connection should be terminated
int do_ssl(connection_state *state)
{
  BYTE *response = NULL;
  int response_len = 0;
  kssl_error_code err;

  // First determine whether the SSL_accept has completed. If not then any
  // data on the TCP connection is related to the handshake and is not
  // application data.

  if (!state->connected) {
    if (!SSL_is_init_finished(state->ssl)) {
      int rc = SSL_do_handshake(state->ssl);
  
      if (rc != 1) {
        switch (SSL_get_error(state->ssl, rc)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          ERR_clear_error();
          return 1;
          
        default:
          ERR_clear_error();
          return 0;
        }
      }
    }

    state->connected = 1;
  }

  // Read whatever data needs to be read (controlled by state->need)

  while (state->need > 0) {
    int read = SSL_read(state->ssl, state->current, state->need);

    if (read <= 0) {
      int err = SSL_get_error(state->ssl, read);
      switch (err) {

        // Nothing to read so wait for an event notification by exiting
        // this function, or SSL needs to do a write (typically because of
        // a connection regnegotiation happening) and so an SSL_read
        // isn't possible right now. In either case return from this
        // function and wait for a callback indicating that the socket
        // is ready for a read.

      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        ERR_clear_error();
        return 1;

        // Connection termination

      case SSL_ERROR_ZERO_RETURN:
        ERR_clear_error();
        return 0;

        // Something went wrong so give up on connetion

      default:
        log_ssl_error(state->ssl, read);
        return 0;
      }
    }

    // Read some number of bytes into the state->current buffer so move that
    // pointer on and reduce the state->need. If there's still more
    // needed then loop around to see if we can read it. This is
    // essential because we will only get a single event when data
    // becomes ready and will need to read it all.

    state->need -= read;
    state->current += read;

    if (state->need > 0) {
      continue;
    }

    // All the required data has been read and is in state->start. If
    // it's a header then do basic checks on the header and then get
    // ready to receive the payload if there is one. If it's the
    // payload then the entire header and payload can now be
    // processed.

    if (state->state == CONNECTION_STATE_GET_HEADER) {
      err = parse_header(state->wire_header, &state->header);
      if (err != KSSL_ERROR_NONE) {
        return 0;
      }

      state->start = 0;

      if (state->header.version_maj != KSSL_VERSION_MAJ) {
        write_log(1, "Message version mismatch %02x != %02x",
                  state->header.version_maj, KSSL_VERSION_MAJ);
        write_error(state, state->header.id, KSSL_ERROR_VERSION_MISMATCH);
        clear_read_queue(state);
        free_read_state(state);
        set_get_header_state(state);
        return 1;
      }

      // If the header indicates that a payload is coming then read it
      // before processing the operation requested in the header

      if (state->header.length > 0) {
        set_get_payload_state(state, state->header.length);
        continue;
      }
    } if (state->state == CONNECTION_STATE_GET_PAYLOAD) {

      // Do nothing here. If we reach here then we know that the
      // entire payload has been read.

    } else {

      // This should be unreachable. If this occurs give up processing
      // and reset.

      write_log(1, "Connection in unknown state %d", state->state);
      free_read_state(state);
      set_get_header_state(state);
      return 1;
    }

    // When we reach here state->header is valid and filled in and if
    // necessary state->start points to the payload.

    err = kssl_operate(&state->header, state->start, privates, &response, &response_len);
    if (err != KSSL_ERROR_NONE) {
      log_err_error();
    } else  {
      queue_write(state, response, response_len);
    }

    // When this point is reached a complete header (and optional
    // payload) have been received and processed by the switch()
    // statement above. So free the allocated memory and get ready to
    // receive another header.

    free_read_state(state);
    set_get_header_state(state);

    return 1;
  }

  return 1;
}

// read_cb: a TCP connection is readable so read the bytes that are on
// it and pass them to OpenSSL
void read_cb(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf)
{
  connection_state *state = (connection_state *)s->data;

  if (nread > 0) {

    // If there's data to read then pass it to OpenSSL via the BIO
    // TODO: check return value

    BIO_write(state->read_bio, buf->base, nread);
  }

  if ((nread == UV_EOF) || (nread < 0)) {
    connection_terminate(state->tcp);
  } else {
    if (do_ssl(state)) {
      write_queued_messages(state);
      flush_write(state);
    } else {
      connection_terminate(state->tcp);
    }
  }

  // Buffer was previously allocated by us in a call to
  // allocate_cb. libuv will not reuse so we must free.

  if (buf && buf->base) {
    free(buf->base);
  }
}

// allocate_cb: libuv needs buffer space so allocate it. We are
// responsible for freeing this buffer.
void allocate_cb(uv_handle_t *h, size_t s, uv_buf_t *buf)
{
  buf->base = (char *)malloc(s);

  if (buf->base) {
    buf->len = s;
  } else {
    buf->len = 0;
  }
}

// new_connection_cb: gets called when the listen socket for the
// server is ready to read (i.e. there's an incoming connection).
void new_connection_cb(uv_stream_t *server, int status)
{
  SSL *ssl;
  uv_tcp_t *client;
  connection_state *state;
  worker_data *worker = (worker_data *)server->data;
  int rc;

  if (status == -1) {
    // TODO: should we log this?
    return;
  }

  client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
  client->data = NULL;
  rc = uv_tcp_init(server->loop, client);
  if (rc != 0) {
    write_log(1, "Failed to setup TCP socket on new connection: %s", 
              error_string(rc));
  } else {
    rc = uv_accept(server, (uv_stream_t *)client);
    if (rc != 0) {
      uv_close((uv_handle_t *)client, close_cb);
      write_log(1, "Failed to accept TCP connection: %s",
                error_string(rc));
      return;
    }
  }

  // The TCP connection has been accept so now pass it off to a worker
  // thread to handle

  state = (connection_state *)malloc(sizeof(connection_state));
  initialize_state(&worker->active, state);
  state->tcp = client;
  set_get_header_state(state);

  ssl = SSL_new(worker->ctx);
  if (!ssl) {
    uv_close((uv_handle_t *)client, close_cb);
    write_log(1, "Failed to create SSL context");
    return;
  }

  state->ssl = ssl;

  // Set up OpenSSL to use a memory BIO. We'll read and write from this BIO
  // when the TCP connection has data or is writeable. The BIOs are set to
  // non-blocking mode.

  state->read_bio = BIO_new(BIO_s_mem());
  BIO_set_nbio(state->read_bio, 1);
  state->write_bio = BIO_new(BIO_s_mem());
  BIO_set_nbio(state->write_bio, 1);
  SSL_set_bio(ssl, state->read_bio, state->write_bio);

  client->data = (void *)state;

  rc = uv_read_start((uv_stream_t*)client, allocate_cb, read_cb);
  if (rc != 0) {
    write_log(1, "Failed to start reading on client connection: %s", 
              error_string(rc));
    return;
  }

  // Start accepting the TLS connection. This will likely not
  // complete here and will be completed in the read_cb/do_ssl above.

  SSL_set_accept_state(ssl);
  SSL_do_handshake(ssl);
}

