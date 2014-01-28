// kssl_server.c: TLSv1.2 server for the CloudFlare Keyless SSL
// protocol
//
// Copyright (c) 2013-2014 CloudFlare, Inc.

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

#include "kssl_getopt.h"

#include "kssl_log.h"
#include "kssl_private_key.h"
#include "kssl_core.h"
#include "kssl_thread.h"

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
  write_verbose_log("SSL error: %s\n", err);
  ERR_clear_error();
}

// log_err_error: log an OpenSSL error and clear the OpenSSL error buffer
void log_err_error()
{
  const char *err = ERR_error_string(ERR_get_error(), 0);
  write_verbose_log("SSL error: %s\n", err);
  ERR_clear_error();
}

// This defines the maximum number of workers to create

#define DEFAULT_WORKERS 1
#define MAX_WORKERS 32

// This structure is used to store a private key and the SHA256 hash
// of the modulus of the public key which it is associated with.
pk_list privates = 0;

int num_workers = DEFAULT_WORKERS;

worker_data worker[MAX_WORKERS];

// This is the TCP connection on which we listen for TLS connections

uv_tcp_t tcp_server;

// sigterm_cb: handle SIGTERM and terminates program cleanly. The
// actual termination is handled in main once the uv_run has
// exited. That will happen when this is called because we call
// uv_signal_stop which is the last event handler running in the main
// thread.
void sigterm_cb(uv_signal_t *w, int signum)
{
  uv_signal_stop(w);
}

// thread_stop_cb: called via async_* to stop a thread
void thread_stop_cb(uv_async_t* handle, int status) {
  worker_data *worker = (worker_data *)handle->data;

  uv_close((uv_handle_t*)&worker->server, NULL);
  uv_close((uv_handle_t*)&worker->stopper, NULL);
}

typedef struct {
  uv_pipe_t pipe;
  uv_tcp_t *handle;
  uv_connect_t connect_req;
} ipc_client;

// ipc_client_close_cb: called when the client has finished reading the
// server handle from the pipe and has called uv_close()
void ipc_client_close_cb(uv_handle_t *handle) {
  ipc_client *client = (ipc_client *)handle->data;
  free(client);
}

// ipc_read2_cb: data (the TCP server handle) ready to read on the pipe.
// Read the handle and close the pipe.
void ipc_read2_cb(uv_pipe_t* pipe,
                  ssize_t nread,
                  const uv_buf_t* buf,
                  uv_handle_type type) {
  ipc_client *client = (ipc_client *)pipe->data;
  uv_loop_t *loop = pipe->loop;

  uv_tcp_init(loop, (uv_tcp_t *)client->handle);
  uv_accept((uv_stream_t*)&client->pipe, (uv_stream_t *)client->handle);
  uv_close((uv_handle_t*)&client->pipe, NULL);
}

// ipc_connect_cb: call when a thread has made a connection to the IPC
// server. Just reads the TCP server handle.
void ipc_connect_cb(uv_connect_t* req, int status) {
  ipc_client *client = (ipc_client *)req->data;
  uv_read2_start((uv_stream_t*)&client->pipe, allocate_cb,
                 ipc_read2_cb);
}

#if PLATFORM_WINDOWS
#define PIPE_NAME "\\\\.\\pipe\\cloudflare-keyless"
#else
#define PIPE_NAME "/tmp/cloudflare-keyless"
#endif

// get_handle: retrieves the handle of the TCP server.
void get_handle(uv_loop_t* loop, uv_tcp_t* server) {
  ipc_client *client = (ipc_client *)malloc(sizeof(ipc_client));
  client->handle = server;

  client->connect_req.data = (void *)client;

  uv_pipe_init(loop, &client->pipe, 1);
  client->pipe.data = (void *)client;
  uv_pipe_connect(&client->connect_req, &client->pipe,
                  PIPE_NAME, ipc_connect_cb);
  uv_run(loop, UV_RUN_DEFAULT);
}

// thread_entry: starts a new thread and begins listening for
// connections. Before listening it obtains the server handle from
// the main thread.
void thread_entry(void *data) {
  worker_data *worker = (worker_data *)data;
  uv_loop_t* loop = uv_loop_new();

  // The stopper is used to terminate the thread gracefully. The
  // uv_unref is here so that if the thread has terminated the
  // async event doesn't keep the loop alive.

  worker->stopper.data = (void *)worker;
  uv_async_init(loop, &worker->stopper, thread_stop_cb);
  uv_unref((uv_handle_t*)&worker->stopper);

  // Wait for the main thread to be ready and obtain the
  // server handle

  uv_sem_wait(&worker->semaphore);
  get_handle(loop, &worker->server);
  uv_sem_post(&worker->semaphore);

  worker->server.data = (void *)worker;
  worker->active = 0;

  if (uv_listen((uv_stream_t *)&worker->server, SOMAXCONN,
                new_connection_cb) == 0) {
    uv_run(loop, UV_RUN_DEFAULT);
  }

  uv_loop_delete(loop);
}

// cleanup: cleanup state.
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

typedef struct {
  uv_pipe_t pipe;
  uv_tcp_t  *server;
  int       connects;
} ipc_server;

typedef struct {
  uv_pipe_t pipe;
  uv_write_t write_req;
} ipc_peer;

// ipc_close_cb: called when the uv_close in ipc_write_cb has
// completed and frees memory allocated for the peer connection.
void ipc_close_cb(uv_handle_t *handle) {
  ipc_peer *peer = (ipc_peer *)handle->data;
  free(peer);
}

// ipc_write_cb: called when the uv_write2 (sending the handle)
// completes. Just closes the connection to the peer (i.e. the
// thread).
void ipc_write_cb(uv_write_t *req, int status) {
  ipc_peer *peer = (ipc_peer *)req->data;
  uv_close((uv_handle_t *)&peer->pipe, ipc_close_cb);
}

// ipc_connection_cb: called when a connection is made to the IPC
// server. Connections come from worker threads requesting the listen
// handle.
void ipc_connection_cb(uv_stream_t *pipe, int status) {
  ipc_server *server = (ipc_server *)pipe->data;
  ipc_peer *peer = (ipc_peer *)malloc(sizeof(ipc_peer));
  uv_loop_t *loop = pipe->loop;
  uv_buf_t buf = uv_buf_init("ABCD", 4);

  // Accept the connection on the pipe and immediately write the
  // server handle to it using uv_write2 to send a handle

  uv_pipe_init(loop, (uv_pipe_t*)&peer->pipe, 1);
  uv_accept(pipe, (uv_stream_t*)&peer->pipe);
  peer->write_req.data = (void *)peer;
  peer->pipe.data = (void *)peer;
  uv_write2(&peer->write_req, (uv_stream_t*)&peer->pipe,
            &buf, 1, (uv_stream_t*)server->server,
            ipc_write_cb);

  // Decrement the connection counter. Once this reaches 0 it indicates
  // that every thread has connected and obtained the server handle so
  // the IPC server can be terminated.

  server->connects -= 1;
  if (server->connects == 0) {
    uv_close((uv_handle_t*)pipe, NULL);
  }
}

uv_mutex_t *locks;

// thread_id_cb: used by OpenSSL to get the currently running thread's
// ID
unsigned long thread_id_cb(void) {
  return uv_thread_self();
}

// locking_cb: used by OpenSSL to lock its internal data
void locking_cb(int mode, int type, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    uv_mutex_lock(&locks[type]);
  } else {
    uv_mutex_unlock(&locks[type]);
  }
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
  ipc_server *p;

  const struct option long_options[] = {
    {"port",                  required_argument, 0, 0},
    {"server-cert",           required_argument, 0, 1},
    {"server-key",            required_argument, 0, 2},
    {"private-key-directory", required_argument, 0, 3},
    {"cipher-list",           required_argument, 0, 4},
    {"ca-file",               required_argument, 0, 5},
    {"silent",                no_argument,       0, 6},
    {"verbose",               no_argument,       0, 7},
    {"pid-file",              required_argument, 0, 8},
    {"num-workers",           optional_argument, 0, 9}
  };
  optind = 1;
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
      verbose = 1;
      break;

    case 8:
      pid_file = (char *)malloc(strlen(optarg)+1);
      strcpy(pid_file, optarg);
      break;

    case 9:
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
  hFind = FindFirstFile(pattern, &FindFileData);
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

  hFind = FindFirstFile(pattern, &FindFileData);
  for (i = 0; i < privates_count; ++i) {
    char* path = (char *)malloc(strlen(private_key_directory)+1+strlen(FindFileData.cFileName)+1);
    strcpy(path, private_key_directory);
    strcat(path, "\\");
    strcat(path, FindFileData.cFileName);
    if (add_key_from_file(path, privates) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to add private keys");
    }
    FindNextFile(hFind, &FindFileData);
    free(path);
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

  tcp_server.data = (void *)ctx;

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

  // Make the worker threads

  for (i = 0; i < num_workers; i++) {
    if (uv_sem_init(&worker[i].semaphore, 0) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to create semaphore");
    }

    worker[i].ctx = ctx;

    if (uv_thread_create(&worker[i].thread, thread_entry,
                         &worker[i]) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to create worker thread");
    }
  }

  // Create a pipe server which will hand the tcp_server handle
  // to threads. Note the 1 in the third parameter of uv_pipe_init:
  // that specifies that this pipe will be used to pass handles.

  p = (ipc_server *)malloc(sizeof(ipc_server));
  p->connects = num_workers;
  p->server = &tcp_server;

  if (uv_pipe_init(loop, &p->pipe, 1) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to create pipe");
  }
  if (uv_pipe_bind(&p->pipe, PIPE_NAME) != 0) {
      SSL_CTX_free(ctx);
      fatal_error("Failed to bind pipe to name %s", PIPE_NAME);
  }
  p->pipe.data = (void *)p;
  if (uv_listen((uv_stream_t*)&p->pipe, MAX_WORKERS,
                ipc_connection_cb) != 0) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to listen on pipe");
  }

  // Pass the tcp_server to all the worker threads and close it
  // here as it is not needed in the main thread.

  for (i = 0; i < num_workers; i++) {
    uv_sem_post(&worker[i].semaphore);
  }
  uv_run(loop, UV_RUN_DEFAULT);
  uv_close((uv_handle_t*)&tcp_server, NULL);
  uv_run(loop, UV_RUN_DEFAULT);
  for (i = 0; i < num_workers; i++) {
    uv_sem_wait(&worker[i].semaphore);
  }

  // The main thread will just wait around for SIGTERM

  uv_signal_init(loop, &sigterm_watcher);
  uv_signal_start(&sigterm_watcher, sigterm_cb, SIGTERM);

  // Since we'll be running multiple threads OpenSSL needs mutexes
  // as its state is shared across them.

  locks = (uv_mutex_t *)malloc(CRYPTO_num_locks() * sizeof(uv_mutex_t));

  for ( i = 0; i < CRYPTO_num_locks(); i++) {
    uv_mutex_init(&locks[i]);
  }

  CRYPTO_set_id_callback(thread_id_cb);
  CRYPTO_set_locking_callback(locking_cb);

  uv_run(loop, UV_RUN_DEFAULT);

  // Now clean up all the running threads

  for (i = 0; i < num_workers; i++) {
    uv_async_send(&worker[i].stopper);
    uv_thread_join(&worker[i].thread);
    uv_sem_destroy(&worker[i].semaphore);
  }

  cleanup(loop, ctx, privates);

  for ( i = 0; i < CRYPTO_num_locks(); i++) {
    uv_mutex_destroy(&locks[i]);
  }
  free(locks);

  return 0;
}

