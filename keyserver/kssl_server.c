// kssl_server.c: TLSv1.2 server for the CloudFlare Keyless SSL
// protocol
//
// Copyright (c) 2013 CloudFlare, Inc.

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

#include "kssl_cli.h"

#include "kssl_log.h"
#include "kssl_private_key.h"
#include "kssl_core.h"

// ssl_error: call when a fatal SSL error occurs. Exits the program
// with return code 1.
void ssl_error()
{
  ERR_print_errors_fp(stderr);
  exit(1);
}

// fatal_error: call to print an error message to STDERR. Exits the
// program with return code 1.
void fatal_error(const char *fmt, ...)
{
  va_list l;
  va_start(l, fmt);
  vfprintf(stderr, fmt, l);
  va_end(l);
  fprintf(stderr, "\n");

  exit(1);
}

// log_ssl_error: log an SSL error and clear the OpenSSL error buffer
void log_ssl_error(SSL *ssl, int rc)
{
  const char *err = ERR_error_string(SSL_get_error(ssl, rc), 0);
  write_log("SSL error: %s", err);
  ERR_clear_error();
}

// log_err_error: log an OpenSSL error and clear the OpenSSL error buffer
void log_err_error()
{
  const char *err = ERR_error_string(ERR_get_error(), 0);
  write_log("SSL error: %s", err);
  ERR_clear_error();
}

// This defines the maximum number of workers to create

#define DEFAULT_WORKERS 1
#define MAX_WORKERS 32

// This is the state of an individual SSL connection and is used for buffering
// of data received by SSL_read

#define CONNECTION_STATE_NEW 0x00

// Waiting for a connection header to be received

#define CONNECTION_STATE_GET_HEADER 0x01

// Waiting for the payload to be received

#define CONNECTION_STATE_GET_PAYLOAD 0x02

// An element in the queue of buffers to send

typedef struct {
  BYTE *start; // Start of the buffer (used for free())
  BYTE *send;  // Pointer to portion of buffer to send
  int len;     // Remaining number of bytes to send
} queued;

// The maximum number of items that can be queued to send. This must
// never be exceeded.

#define QUEUE_LENGTH 16

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

// Linked list of active connections
connection_state *active = 0;

// initialize_state: set the initial state on a newly created connection_state
void initialize_state(connection_state *state)
{
  // Insert at the start of the list
  state->prev = &active;
  if (active) {
    state->next = active;
    active->prev = &state->next;
  } else {
    state->next = 0;
  }
  active = state;

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
    write_log("Connection state queue full. Data lost.");
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
  if (err != KSSL_ERROR_INTERNAL) {
    queue_write(state, resp, size);
  }
}

// This structure is used to store a private key and the SHA256 hash
// of the modulus of the public key which it is associated with.
pk_list privates = 0;

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
void close_cb(uv_handle_t *h)
{
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
  uv_read_stop((uv_stream_t *)tcp);
  uv_close((uv_handle_t *)tcp, close_cb);
  SSL_free(ssl);
  BIO_free_all(state->read_bio);
  BIO_free_all(state->write_bio);

  *(state->prev) = state->next;
  if (state->next) {
    state->next->prev = state->prev;
  }

  free(tcp);
  free_read_state(state);
  free(state);
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
        fprintf(stderr, "SSL_write: %d/%d\n", rc, SSL_get_error(ssl, rc));
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
    if (SSL_do_handshake(state->ssl) != 1) {
      return 1;
    }
  }

  state->connected = 1;
  }

  // Read whatever data needs to be read (controlled by state->need)

  while (state->need > 0) {
    int read = SSL_read(state->ssl, state->current, state->need);

    if (read == 0) {
      return 1;
    }

    if (read < 0) {
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
        write_log("Message version mismatch %02x != %02x\n", state->header.version_maj, KSSL_VERSION_MAJ);
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

      write_log("Connection in unknown state %d", state->state);
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

  if (nread == -1) {
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
  SSL_CTX *ctx;
  SSL *ssl;
  uv_tcp_t *client;
  connection_state *state;
  
  if (status == -1) {
    // TODO: should we log this?
    return;
  }

  ctx = (SSL_CTX *)server->data;
  ssl = SSL_new(ctx);
  if (!ssl) {
    write_log("Failed to create SSL context");
    return;
  }

  client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
  uv_tcp_init(server->loop, client);
  if (uv_accept(server, (uv_stream_t *)client) != 0) {
    uv_close((uv_handle_t *)client, close_cb);
    write_log("Failed to accept TCP connection");
    return;
  }

  state = (connection_state *)malloc(sizeof(connection_state));
  initialize_state(state);
  state->tcp = client;
  set_get_header_state(state);
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

  uv_read_start((uv_stream_t*)client, allocate_cb, read_cb);

  // Start accepting the TLS connection. This will likely not
  // complete here and will be completed in the read_cb/do_ssl above.

  SSL_set_accept_state(ssl);
  SSL_do_handshake(ssl);
}

int num_workers = DEFAULT_WORKERS;

// This is the TCP connection on which we listen for TLS connections

uv_tcp_t tcp_server;

// sigterm_cb: handle SIGTERM and terminates program cleanly
void sigterm_cb(uv_signal_t *w, int signum)
{
  uv_signal_stop(w);
  uv_close((uv_handle_t *)&tcp_server, 0);
}

// cleanup: cleanup state. This is a function because it is needed by
// children and parent.
void cleanup(uv_loop_t *loop, SSL_CTX *ctx, pk_list privates)
{
  uv_loop_delete(loop);
  SSL_CTX_free(ctx);

  free_pk_list(privates);

  // This monstrous sequence of calls is attempting to clean up all
  // the memory allocated by SSL_library_init() which has no analagous
  // SSL_library_free()!

  CONF_modules_unload(1);
  EVP_cleanup();
  ENGINE_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);
  ERR_free_strings();
}

int main(int argc, char *argv[])
{
  int port = -1;
  char *server_cert = 0;
  char *server_key = 0;
  char *private_key_directory = 0;
  char *cipher_list = 0;
  char *ca_file = 0;
  char *pid_file = 0;

  const SSL_METHOD *method;
  SSL_CTX *ctx;
  char *pattern;
#if PLATFORM_WINDOWS
  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;
  const char *starkey = "\\*.key";
#else
  glob_t g;
  const char *starkey = "/*.key";
#endif

  int rc, privates_count, i;
  struct sockaddr_in addr;
  STACK_OF(X509_NAME) *cert_names;
  uv_loop_t *loop;
  uv_signal_t sigterm_watcher;

  const struct option long_options[] = {
    {"port",                  required_argument, 0, 0},
    {"server-cert",           required_argument, 0, 1},
    {"server-key",            required_argument, 0, 2},
    {"private-key-directory", required_argument, 0, 3},
    {"cipher-list",           required_argument, 0, 4},
    {"ca-file",               required_argument, 0, 5},
    {"silent",                no_argument,       0, 6},
    {"pid-file",              required_argument, 0, 7},
    {"num-workers",           optional_argument, 0, 8}
  };

  while (1) {
    int c = getopt_long(argc, argv, "", long_options, 0);
    if (c == -1) {
      break;
    }

    switch (c) {
    case 0:
      port = atoi(optarg);
      break;

    case 1:
      server_cert = (char *)malloc(strlen(optarg)+1);
      strcpy(server_cert, optarg);
      break;

    case 2:
      server_key = (char *)malloc(strlen(optarg)+1);
      strcpy(server_key, optarg);
      break;

    case 3:
      private_key_directory = (char *)malloc(strlen(optarg)+1);
      strcpy(private_key_directory, optarg);
      break;

    case 4:
      cipher_list = (char *)malloc(strlen(optarg)+1);
      strcpy(cipher_list, optarg);
      break;

    case 5:
      ca_file = (char *)malloc(strlen(optarg)+1);
      strcpy(ca_file, optarg);
      break;

    case 6:
      silent = 1;
      break;

    case 7:
      pid_file = (char *)malloc(strlen(optarg)+1);
      strcpy(pid_file, optarg);
      break;

    case 8:
      num_workers = atoi(optarg);
      break;
    }
  }

  if (port == -1) {
    fatal_error("The --port parameter must be specified with the listen port");
  }
  if (!server_cert) {
    fatal_error("The --server-cert parameter must be specified with the path to the server's SSL certificate");
  }
  if (!server_key) {
    fatal_error("The --server-key parameter must be specified with the path to the server's SSL private key");
  }
  if (!private_key_directory) {
    fatal_error("The --private-key-directory parameter must be specified with the path to directory containing private keys");
  }
  if (!cipher_list) {
    fatal_error("The --cipher-list parameter must be specified with a list of acceptable ciphers");
  }
  if (num_workers <= 0 || num_workers > MAX_WORKERS) {
    fatal_error("The --num-workers parameter must between 1 and %d", MAX_WORKERS);
  }

  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();

  method = TLSv1_2_server_method();
  ctx = SSL_CTX_new(method);

  if (!ctx) {
    ssl_error();
  }

  // Set a specific cipher list that comes from the command-line and then set
  // the context to ask for a peer (i.e. client certificate on connection) and
  // to refuse connections that do not have a client certificate. The client
  // certificate must be signed by the CA in the --ca-file parameter.

  if (SSL_CTX_set_cipher_list(ctx, cipher_list) == 0) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to set cipher list %s", cipher_list);
  }

  free(cipher_list);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

  cert_names = SSL_load_client_CA_file(ca_file);
  if (!cert_names) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to load CA file %s", ca_file);
  }

  SSL_CTX_set_client_CA_list(ctx, cert_names);
  SSL_CTX_set_verify_depth(ctx, 1);

  if (SSL_CTX_load_verify_locations(ctx, ca_file, 0) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to load CA file %s", ca_file);
  }

  free(ca_file);

#define SSL_FAILED(func) if (func != 1) { ssl_error(); }
  SSL_FAILED(SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM))
  SSL_FAILED(SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM))
  if (SSL_CTX_check_private_key(ctx) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("Private key %s and certificate %s do not match", server_key, server_cert);
  }

  free(server_cert);
  free(server_key);

  // Load all the private keys found in the private_key_directory. This only looks for
  // files that end with .key and the part before the .key is taken to
  // be the DNS name.

  pattern = (char *)malloc(strlen(private_key_directory)+strlen(starkey)+1);
  strcpy(pattern, private_key_directory);
  strcat(pattern, starkey);

#if PLATFORM_WINDOWS
  hFind = FindFirstFile(starkey, &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) {
    SSL_CTX_free(ctx);
    fatal_error("Error %d finding private keys in %s", rc, private_key_directory);
  }

  // count the number of files
  privates_count = 1;
  while (FindNextFile(hFind, &FindFileData) != 0) {
    privates_count++;
  }
  FindClose(hFind);

  privates = new_pk_list(privates_count);
  if (privates == NULL) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to allocate room for private keys");
  }

  hFind = FindFirstFile(starkey, &FindFileData);
  for (i = 0; i < privates_count; ++i) {
    if (add_key_from_file(FindFileData.cFileName, privates) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to add private keys");
    }
    FindNextFile(hFind, &FindFileData);
  }
  FindClose(hFind);
#else
  g.gl_pathc  = 0;
  g.gl_offs   = 0;

  rc = glob(pattern, GLOB_NOSORT, 0, &g);

  if (rc != 0) {
    SSL_CTX_free(ctx);
    fatal_error("Error %d finding private keys in %s", rc, private_key_directory);
  }

  if (g.gl_pathc == 0) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to find any private keys in %s", private_key_directory);
  }

  free(private_key_directory);

  privates_count = g.gl_pathc;
  privates = new_pk_list(privates_count);
  if (privates == NULL) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to allocate room for private keys");
  }

  for (i = 0; i < privates_count; ++i) {
    if (add_key_from_file(g.gl_pathv[i], privates) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to add private keys");
    }
  }

  free(pattern);
  globfree(&g);
#endif

  // TODO: port this to libuv
  //
  //  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int)) == -1) {
  //  SSL_CTX_free(ctx);
  //  fatal_error("Failed to set socket option SO_REUSERADDR");
  // }

  loop = uv_loop_new();
  uv_tcp_init(loop, &tcp_server);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  memset(&(addr.sin_zero), 0, 8);

  if (uv_tcp_bind(&tcp_server, (const struct sockaddr*)&addr, 0) != 0) {
    SSL_CTX_free(ctx);
    fatal_error("Can't bind to port %d", port);
  }

  tcp_server.data = (char *)ctx;

  if (uv_listen((uv_stream_t *)&tcp_server, SOMAXCONN, new_connection_cb) != 0) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to listen on TCP socket");
  }

  uv_signal_init(loop, &sigterm_watcher);
  uv_signal_start(&sigterm_watcher, sigterm_cb, SIGTERM);

  if (pid_file) {
    FILE *fp = fopen(pid_file, "w");
    if (fp) {
      fprintf(fp, "%d\n", getpid());
      fclose(fp);
    } else {
      SSL_CTX_free(ctx);
      fatal_error("Can't write to pid file %s", pid_file);
    }
    free(pid_file);
  }

  uv_run(loop, UV_RUN_DEFAULT);
  cleanup(loop, ctx, privates);

  return 0;
}

