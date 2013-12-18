// keyserver.c: TLSv1.2 server for the CloudFlare Keyless SSL protocol
//
// Copyright (c) 2013 CloudFlare, Inc.

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <stdarg.h>
#include <getopt.h>

#include <fcntl.h>
#include <glob.h>

#include <ev.h>

#include "kssl.h"
#include "kssl_helpers.h"
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
  printf("\n");

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

// This defines the maximum number of processes to fork

#define DEFAULT_PROCESSES 1
#define MAX_PROCESSES 32

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
  BYTE header[KSSL_HEADER_SIZE]; // Complete header once read
  BYTE *payload; // Allocated for payload when necessary
  queued q[QUEUE_LENGTH];

  // These implement a circular buffer in q. qw points to the next entry
  // in the q that can be used to queue a buffer to send. qr points to
  // the next entry to be sent.
  //
  // if qr == qw then the buffer is empty.

  int qr;
  int qw;

  // Back link just used when cleaning up. This points to the watcher
  // that pointer to this connection_state through it's data pointer
  struct ev_io *watcher;
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

  int err = kssl_error(id, error, &resp, &size);
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
  state->start = state->header;
  state->current = state->start;
  state->need = KSSL_HEADER_SIZE;
  state->state = CONNECTION_STATE_GET_HEADER;
  state->payload = 0;
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

// watcher_terminate: terminate an SSL connection and remove from event
// loop. Clean up any allocated memory.
void watcher_terminate(struct ev_loop *loop, struct ev_io *watcher) {
  connection_state *state = (connection_state *)watcher->data;
  SSL *ssl = state->ssl;

  int rc = SSL_shutdown(ssl);
  if (rc == 0) {
    SSL_shutdown(ssl);
  }
  close(watcher->fd);
  SSL_free(ssl);
  ev_io_stop(loop, watcher);

  *(state->prev) = state->next;
  if (state->next) {
    state->next->prev = state->prev;
  }

  free(watcher);
  free_read_state(state);
  free(state);
}

// write all messages in the queue onto the wire
int write_queued_messages(connection_state *state) {
  SSL *ssl = state->ssl;
  while ((state->qr != state->qw) && (state->q[state->qr].len > 0)) {
    queued *q = &state->q[state->qr];
    int rc = SSL_write(ssl, q->send, q->len);

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
        // SSL_write must be retried which will happen on the next
        // EV_WRITE

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
        return -2;
      }
    }

    // On any error condition leave the send loop

    break;
  }

  return 0;
}

// clear_read_queue: a message of unknown version was sent, so ignore
// the rest of the message
int clear_read_queue(connection_state *state) {
  SSL *ssl = state->ssl;
  int read = 0;
  BYTE ignore[1024];

  do {
    read = SSL_read(ssl, ignore, 1024);
  } while (read > 0);

  return 0;
}

// read_message: read up to state->need bytes into state->current
int read_message(connection_state *state) {
  SSL *ssl = state->ssl;
  int read = 0;

  while (state->need > 0) {
    read = SSL_read(state->ssl, state->current, state->need);
    if (read <= 0) {
      switch (SSL_get_error(ssl, read)) {

        // Nothing to read so wait for an event notification by exiting
        // this function, or SSL needs to do a write (typically because of
        // a connection regnegotiation happening) and so an SSL_read isn't
        // possible right now. In either case return from this function
        // and wait for a callback indicating that the socket is ready
        // for a read.

      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        ERR_clear_error();
        break;

        // Connection termination

      case SSL_ERROR_ZERO_RETURN:
        ERR_clear_error();
        return KSSL_ERROR_INTERNAL;

        // Something went wrong so give up on connetion

      default:
        log_ssl_error(ssl, read);
        return KSSL_ERROR_INTERNAL;
      }
    } else {
      // Read some number of bytes into the state->current buffer so move that
      // pointer on and reduce the state->need. If there's still more needed
      // then loop around to see if we can read it. This is essential because we
      // will only get a single event when data becomes ready and will need to read
      // it all.

      state->need -= read;
      state->current += read;
    }
  }

  return 0;
}

// connection_cb: called when a client SSL connection has data to read
// or is ready to write
void connection_cb(struct ev_loop *loop, struct ev_io *watcher, int events)
{
  int err = 0;
  kssl_header header;

  connection_state *state = (connection_state *)watcher->data;
  // If the connection is writeable and there is data to write then get on
  // and write it

  if (events & EV_WRITE) {
    err = write_queued_messages(state);
    if (err != KSSL_ERROR_NONE) {
      if (err == KSSL_ERROR_INTERNAL) {
        watcher_terminate(loop, watcher);
      }
      return;
    }
  }

  // If the socket is not readable then we're done. The rest of the function
  // is to do with reading kssl_headers and handling requests.

  if (!(events & EV_READ)) {
    return;
  }

  // Read in the header
  err = read_message(state);
  if (err != KSSL_ERROR_NONE) {
    if (err == KSSL_ERROR_INTERNAL) {
      watcher_terminate(loop, watcher);
    }
    return;
  }

  // Parse the header into the local struct
  err = parse_header(state->header, &header);
  if (err != KSSL_ERROR_NONE) {
    if (err == KSSL_ERROR_INTERNAL) {
      watcher_terminate(loop, watcher);
    }
    return;
  }

  // All the required data has been read and is in state->start. If it's a header
  // then do basic checks on the header and then get ready to receive the payload
  // if there is one. If it's the payload then the entire header and payload can
  // now be processed.

  if (state->state == CONNECTION_STATE_GET_HEADER) {
    state->start = 0;

    if (header.version_maj != KSSL_VERSION_MAJ) {
      write_log("Message version mismatch %02x != %02x\n", header.version_maj, KSSL_VERSION_MAJ);
      write_error(state, header.id, KSSL_ERROR_VERSION_MISMATCH);
      clear_read_queue(state);
      free_read_state(state);
      set_get_header_state(state);
      return;
    }

    // If the header indicates that a payload is coming then read it
    // before processing the operation requested in the header

    if (header.length > 0) {
      set_get_payload_state(state, header.length);
      if (read_message(state) != 0) {
        return;
      }
    }
  } else {

    // This should be unreachable. If this occurs give up processing
    // and reset.

    write_log("Connection in unknown state %d", state->state);
    free_read_state(state);
    set_get_header_state(state);
  }

  // When we reach here header is valid and filled in and if necessary
  // state->start points to the payload. Note that you cannot rely
  // on header + sizeof(kssl_header) == state->start since
  // they are allocated at different times.

  BYTE *response = NULL;
  int response_len = 0;

  err = kssl_operate(&header, state->start, privates, &response, &response_len);
  if (err != KSSL_ERROR_NONE) {
    log_err_error();
  } else  {
    queue_write(state, response, response_len);
  }

  // When this point is reached a complete header (and optional payload) have been received
  // and processed by the switch() statement above. So free the allocated memory and get
  // ready to receive another header.

  free_read_state(state);
  set_get_header_state(state);
}

// server_cb: gets called when the listen socket for the server is
// ready to read (i.e. there's an incoming connection).
void server_cb(struct ev_loop *loop, struct ev_io *watcher, int events)
{
  int client = accept(watcher->fd, 0, 0);
  if (client == -1) {
    return;
  }

  SSL_CTX *ctx = (SSL_CTX *)watcher->data;
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    write_log("Failed to create SSL context for fd %d", client);
    close(client);
    return;
  }

  SSL_set_fd(ssl, client);

  int rc = SSL_accept(ssl);
  if (rc != 1) {
    log_ssl_error(ssl, rc);
    close(client);
    SSL_free(ssl);
    return;
  }

  struct ev_io *ssl_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
  connection_state *state = (connection_state *)malloc(sizeof(connection_state));
  initialize_state(state);
  state->watcher = ssl_watcher;
  set_get_header_state(state);
  state->ssl = ssl;
  ssl_watcher->data = (void *)state;
  ev_io_init(ssl_watcher, connection_cb, client, EV_READ | EV_WRITE);
  ev_io_start(loop, ssl_watcher);

  int flags = fcntl(client, F_GETFL, 0);
  flags |= O_NONBLOCK;
  fcntl(client, F_SETFL, flags);
}

// sigint_cb: handle SIGINT and terminate program cleanly
void sigint_cb(struct ev_loop *loop, ev_signal *w, int events)
{
  ev_break(loop, EVBREAK_ALL);
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
  int num_processes = DEFAULT_PROCESSES;

  const struct option long_options[] = {
    {"port",                  required_argument, 0, 0},
    {"server-cert",           required_argument, 0, 1},
    {"server-key",            required_argument, 0, 2},
    {"private-key-directory", required_argument, 0, 3},
    {"cipher-list",           required_argument, 0, 4},
    {"ca-file",               required_argument, 0, 5},
    {"silent",                no_argument,       0, 6},
    {"pid-file",              required_argument, 0, 7},
    {"num-processes",         optional_argument, 0, 8}
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
      num_processes = atoi(optarg);
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
  if (num_processes <= 0 || num_processes > MAX_PROCESSES) {
    fatal_error("The --num-processes parameter must between 1 and %d", MAX_PROCESSES);
  }

  SSL_library_init();
  SSL_load_error_strings();

  const SSL_METHOD *method = TLSv1_2_server_method();
  SSL_CTX *ctx = SSL_CTX_new(method);

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

  STACK_OF(X509_NAME) *cert_names = SSL_load_client_CA_file(ca_file);
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

  glob_t g;
  g.gl_pathc  = 0;
  g.gl_offs   = 0;

  const char *starkey = "/*.key";
  char *pattern = (char *)malloc(strlen(private_key_directory)+strlen(starkey)+1);
  strcpy(pattern, private_key_directory);
  strcat(pattern, starkey);

  int rc = glob(pattern, GLOB_NOSORT, 0, &g);

  if (rc != 0) {
    SSL_CTX_free(ctx);
    fatal_error("Error %d finding private keys in %s", rc, private_key_directory);
  }

  if (g.gl_pathc == 0) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to find any private keys in %s", private_key_directory);
  }

  free(private_key_directory);

  int privates_count = g.gl_pathc;
  privates = new_pk_list(privates_count);
  if (privates == NULL) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to allocate room for private keys");
  }

  int i;
  for (i = 0; i < privates_count; ++i) {
    if (add_key_from_file(g.gl_pathv[i], privates) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to add private keys");
    }
  }

  free(pattern);
  globfree(&g);

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    SSL_CTX_free(ctx);
    fatal_error("Can't create TCP socket");
  }

  int t = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int)) == -1) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to set socket option SO_REUSERADDR");
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  bzero(&(addr.sin_zero), 8);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1) {
    SSL_CTX_free(ctx);
    close(sock);
    fatal_error("Can't bind to port %d", port);
  }

  if (listen(sock, SOMAXCONN) == -1) {
    SSL_CTX_free(ctx);
    close(sock);
    fatal_error("Failed to listen on TCP socket");
  }

  if (pid_file) {
    FILE *fp = fopen(pid_file, "w");
    if (fp) {
      fprintf(fp, "%d\n", getpid());
      fclose(fp);
    } else {
      SSL_CTX_free(ctx);
      close(sock);
      fatal_error("Can't write to pid file %s", pid_file);
    }
    free(pid_file);
  }

  struct ev_loop *loop = ev_default_loop(0);
  struct ev_io *server_watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
  server_watcher->data = (void *)ctx;
  ev_io_init(server_watcher, server_cb, sock, EV_READ);
  ev_io_start(loop, server_watcher);

  ev_signal signal_watcher;
  ev_signal_init(&signal_watcher, sigint_cb, SIGINT);
  ev_signal_start(loop, &signal_watcher);

  pid_t pid[MAX_PROCESSES];
  for (i = 0; i < num_processes; i++) {
    pid[i] = fork();
    if(pid[i] == 0) {

      ev_run(loop, 0);

      ev_io_stop(loop, server_watcher);
      close(sock);
      free(server_watcher);

      ev_signal_stop(loop, &signal_watcher);

      connection_state *f = active;
      while (f) {
        connection_state *n = f->next;
        watcher_terminate(loop, f->watcher);
        f = n;
      }

      ev_loop_destroy(loop);
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

      return 0;
    }
  }

  for (i = 0; i < num_processes; i++) {
    waitpid(pid[i], NULL, 0);
  }

  return 0;
}
