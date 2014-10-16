// kssl_testclient.c: test program to communicate with a keyserver
//
// Copyright (c) 2013-2014 CloudFlare, Inc.
//
// Command-line options:
//
// --port
//
// TCP port to contact the kssl_server on (matches the --port parameter of
// kssl_server)
//
// --server
//
// Hostname or IP of the kssl_server.
//
// --client-cert
// --client-key
//
// The filenames of a client certificate to present to the server to verify
// that this client is a valid user of kssl_server. These must be signed by a
// CA that kssl_server can check the certificate against (i.e one in the
// --ca-file parameter of kssl_server).
//
// --ca-file
//
// Path to a PEM-encoded file containing the CA certificate used to verify
// server certificates presented on connection.
// 
// --rsa-pubkey
//
// The filename of an RSA rsa_pubkey key file (PEM encoded) that is used for
// testing. This must be one of the rsa_pubkey keys specified in the
// kssl_server's --rsa_pubkey-key-directory.
//
// --debug
//
// Turns in debug logging
//
// --short
//
// Just do a connectivity test. Exit code 0 if successful.
//
// --alive
//
// Instead of performing all the tests this simply checks connectivity with
// the kssl_server by running a limit number of tests.

#include "kssl.h"
#include "kssl_helpers.h"
#include "kssl_private_key.h"

#if PLATFORM_WINDOWS
#include <winsock2.h>
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#endif

#include <ctype.h>
#include <uv.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <stdarg.h>

#include "kssl_getopt.h"

unsigned char ipv6[16] = {0x0, 0xf2, 0x13, 0x48, 0x43, 0x01};
unsigned char ipv4[4] = {127, 0, 0, 1};

#if PLATFORM_WINDOWS
#define SOCKET_CLOSE closesocket
#else
#define SOCKET_CLOSE close
#endif

// libuv locking primitives
#define MUTEX_TYPE            uv_mutex_t
#define MUTEX_SETUP(x)        uv_mutex_init(&(x))
#define MUTEX_CLEANUP(x)      uv_mutex_destroy(&(x))
#define MUTEX_LOCK(x)         uv_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)       uv_mutex_unlock(&(x))
#define THREAD_ID             uv_thread_self()

struct hostent *localhost;

char *server = 0;

int tests = 0;
int debug = 0;
int health = 0;
int alive = 0;

// This array will store all of the mutexes available to OpenSSL.
static MUTEX_TYPE *mutex_buf=NULL;

static void locking_function(int mode, int n, const char * file, int line)
{
  if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
  return ((unsigned long)THREAD_ID);
}

int thread_setup(void)
{
  int i;

  mutex_buf = malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
  if (!mutex_buf)
    return 0;
  for (i = 0; i < CRYPTO_num_locks();  i++)
    MUTEX_SETUP(mutex_buf[i]);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}

int thread_cleanup(void)
{
  int i;
  if (!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks();  i++)
    MUTEX_CLEANUP(mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}

// ssl_error: call when a fatal SSL error occurs. Exits the program
// with return code 1.
void ssl_error(void)
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

// digest_public_rsa: calculates the SHA256 digest of the
// hexadecimal representation of the public modulus of an RSA
// key. digest must be initialized with at least 32 bytes of
// space.
void digest_public_rsa(RSA *key, BYTE *digest)
{
  // QUESTION: can we use a single EVP_MD_CTX for multiple
  // digests?
  char *hex;
  EVP_MD_CTX *ctx;

  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
  hex = BN_bn2hex(key->n);
  EVP_DigestUpdate(ctx, hex, strlen(hex));
  EVP_DigestFinal_ex(ctx, digest, 0);
  EVP_MD_CTX_destroy(ctx);
  OPENSSL_free(hex);
}

// digest_public_ec: calculates the SHA256 digest of the
// hexadecimal representation of the EC public key group and
// point. digest must be initialized with at least 32 bytes of
// space.
void digest_public_ec(EC_KEY *ec_key, BYTE *digest) {
  const EC_POINT *ec_pub_key = EC_KEY_get0_public_key(ec_key);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  char *hex = EC_POINT_point2hex(group, ec_pub_key, POINT_CONVERSION_COMPRESSED, NULL);
  EVP_MD_CTX *ctx;

  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
  EVP_DigestUpdate(ctx, hex, strlen(hex));
  EVP_DigestFinal_ex(ctx, digest, 0);
  EVP_MD_CTX_destroy(ctx);
  OPENSSL_free(hex);
}

// ok: indicate that some tests passed and free memory
void ok(kssl_header *h)
{
  if (!alive) {
    printf(" ok\n");
  }
  if (h != 0) {
    free(h->data);
    free(h);
  }
}

// test: start a set of test
void test(const char *fmt, ...)
{
  if (!alive) {
    va_list l;
    va_start(l, fmt);
    vfprintf(stderr, fmt, l);
    va_end(l);
  }
}

// test_assert: assert that some condition is true, fatal
// error if not
void test_assert(int a)
{
  if (!a) {
    fatal_error(" test failure");
  }
  tests += 1;
}

static void dump_request(kssl_operation *request) {
  BYTE op;
  BYTE *p = request->payload;
  int l = request->payload_len;
  if (!debug) {
    return;
  }

  op = request->opcode;
  printf("OPCODE: %s ", opstring(op));

  if (op == KSSL_OP_RSA_DECRYPT) {
    int i;
    printf("  Digest: ");
    for (i = 0; i < KSSL_DIGEST_SIZE; ++i) {
      printf("%02x", request->digest[i]);
    }
    printf("\n");
  }

  if (op == KSSL_OP_ERROR && request->payload_len > 0) {
    printf("  Error: ");
    switch(request->payload[0]) {
    case KSSL_ERROR_CRYPTO_FAILED:
      printf("KSSL_ERROR_CRYPTO_FAILED\n");
      break;
    case KSSL_ERROR_KEY_NOT_FOUND:
      printf("KSSL_ERROR_KEY_NOT_FOUND\n");
      break;
    case KSSL_ERROR_BAD_OPCODE:
      printf("KSSL_ERROR_BAD_OPCODE\n");
      break;
    case KSSL_ERROR_READ:
      printf("KSSL_ERROR_READ\n");
      break;
    case KSSL_ERROR_VERSION_MISMATCH:
      printf("KSSL_ERROR_VERSION_MISMATCH\n");
      break;
    case KSSL_ERROR_UNEXPECTED_OPCODE:
      printf("KSSL_ERROR_UNEXPECTED_OPCODE\n");
      break;
    default:
      printf("unknown KSSL error: %02x\n", request->payload[0]);
      break;
    }
    return;
  }

  if (l > 0) {
    int printable = 1;
    int i;
    for (i = 0; i < l; i++) {
      if (iscntrl(p[i])) {
        printable = 0;
        break;
      }
    }

    printf("  Payload: ");
    for (i = 0; i < l; ++i) {
      if (!printable && (i != 0) && (i%16 == 0)) {
        printf("\n           ");
      }
      printf(printable?"%c":"%02x ", p[i]);
    }
    printf("\n");
  }
}

// dump_payload: print out the payload from a KSSL operation in hex
void dump_payload(int l, BYTE *p)
{
  kssl_operation request;

  if (!debug) return;

  if (l > 0) {
    int i;
    printf("  Payload Raw: ");
    for (i = 0; i < l; ++i) {
      if ((i != 0) && (i%16 == 0)) {
        printf("\n           ");
      }
      printf("%02x ", p[i]);
    }
    printf("\n");
  }
  parse_message_payload(p, l, &request);

  dump_request(&request);
}

// dump_header: print out a KSSL header
void dump_header(kssl_header *k, const char *msg)
{
  if (debug) {
    printf("  KSSL %s: %02x %02x %08x %d\n", msg, k->version_maj, k->version_min,
        k->id, k->length);
  }
}

// kssl: send a KSSL message to the server and read the response
kssl_header *kssl(SSL *ssl, kssl_header *k, kssl_operation *r)
{
  BYTE buf[KSSL_HEADER_SIZE];
  BYTE *req;
  int req_len;
  int n;
  kssl_header h;
  kssl_header *to_return;

  flatten_operation(k, r, &req, &req_len);

  dump_header(k, "send");
  dump_request(r);

  n = SSL_write(ssl, req, req_len);
  if (n != req_len) {
    fatal_error("Failed to send KSSL header");
  }

  free(req);

  while (1) {
    n = SSL_read(ssl, buf, KSSL_HEADER_SIZE);
    if (n <= 0) {
      int x = SSL_get_error(ssl, n);
      if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE) {
        continue;
      } else if (x == SSL_ERROR_ZERO_RETURN) {
        fatal_error("Connection closed while reading header\n");
      } else {
        fatal_error("Error performing SSL_read: %x\n", x);
      }
    } else {
      if (n != KSSL_HEADER_SIZE) {
        fatal_error("Error receiving KSSL header, size: %d", n);
      }
    }

    break;
  }

  parse_header(buf, &h);
  if (h.version_maj != KSSL_VERSION_MAJ) {
    fatal_error("Version mismatch %d != %d", h.version_maj, KSSL_VERSION_MAJ);
  }
  if (k->id != h.id) {
    fatal_error("ID mismatch %08x != %08x", k->id, h.id);
  }

  dump_header(&h, "recv");

  to_return = (kssl_header *)malloc(sizeof(kssl_header));
  memcpy(to_return, &h, sizeof(kssl_header));


  if (h.length > 0) {
    BYTE *payload = (BYTE *)malloc(h.length);
    while (1) {
      n = SSL_read(ssl, payload, h.length);
      if (n <= 0) {
        int x = SSL_get_error(ssl, n);
        if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE) {
          continue;
        } else if (x == SSL_ERROR_ZERO_RETURN) {
          fatal_error("Connection closed while reading payload\n");
        } else {
          fatal_error("Error performing SSL_read: %x\n", x);
        }
      } else {
        if (n != h.length) {
          fatal_error("Error receiving KSSL payload, size: %d", n);
        }
      }

      break;
    }

    if (n != h.length) {
      fatal_error("Failed to read payload got length %d wanted %d", n, h.length);
    }

    dump_payload(h.length, payload);
    to_return->data = payload;
  }

  return to_return;
}

void kssl_write(SSL *ssl, kssl_header *k, kssl_operation *r)
{
  BYTE *req;
  int req_len, n;

  flatten_operation(k, r, &req, &req_len);

  dump_header(k, "send");
  dump_request(r);

  n = SSL_write(ssl, req, req_len);
  if (n != req_len) {
      fatal_error("Failed to send KSSL header");
  }
  free(req);
}

kssl_header* kssl_read(SSL *ssl, kssl_header *k, kssl_operation *r)
{
  kssl_header h, *to_return;
  BYTE buf[KSSL_HEADER_SIZE];
  int n;

  while (1) {
    n = SSL_read(ssl, buf, KSSL_HEADER_SIZE);
    if (n <= 0) {
      int x = SSL_get_error(ssl, n);
      if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE) {
        continue;
      } else if (x == SSL_ERROR_ZERO_RETURN) {
        fatal_error("Connection closed while reading header\n");
      } else {
        fatal_error("Error performing SSL_read: %x\n", x);
      }
    } else {
      if (n != KSSL_HEADER_SIZE) {
        fatal_error("Error receiving KSSL header, size: %d", n);
      }
    }
    break;
  }
  
  parse_header(buf, &h);
  if (h.version_maj != KSSL_VERSION_MAJ) {
    fatal_error("Version mismatch %d != %d", h.version_maj, KSSL_VERSION_MAJ);
  }
  if (k->id != h.id) {
    fatal_error("ID mismatch %08x != %08x", k->id, h.id);
  }

  dump_header(&h, "recv");

  to_return = (kssl_header *)malloc(sizeof(kssl_header));
  memcpy(to_return, &h, sizeof(kssl_header));

  to_return->data = 0;
  if (h.length > 0) {
    BYTE *payload = (BYTE *)malloc(h.length);
    while (1) {
      n = SSL_read(ssl, payload, h.length);
      if (n <= 0) {
        int x = SSL_get_error(ssl, n);
        if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE) {
          continue;
        } else if (x == SSL_ERROR_ZERO_RETURN) {
          fatal_error("Connection closed while reading payload\n");
        } else {
          fatal_error("Error performing SSL_read: %x\n", x);
        }
      } else {
        if (n != h.length) {
          fatal_error("Error receiving KSSL payload, size: %d", n);
        }
      }

      break;
    }

    if (n != h.length) {
      fatal_error("Failed to read payload got length %d wanted %d", n, h.length);
    }

    dump_payload(h.length, payload);
    to_return->data = payload;
  }

  return to_return;
}

// verify response, only verify kssl header currently
// TODO: verify different kssl payload 
int verify_response(kssl_header* k, kssl_operation* r, kssl_header* resp_k)
{
    test_assert(resp_k->id == k->id);
    test_assert(resp_k->version_maj == KSSL_VERSION_MAJ);
    // TODO: add other verification logic here
    return 1;
}

// send and read pipeline requests and responses
void kssl_pipeline(SSL *ssl, kssl_header *k, kssl_operation *r, int repeat)
{
    int i, cur_gap, max_gap = 300;
    int w_count = 0, r_count = 0;
    long int increment;
    kssl_header *to_return;
    
    srand((unsigned int) time(NULL));

    while (w_count < repeat || r_count < repeat) {
        cur_gap = w_count - r_count;

        // pipeline write
        increment = (random() % max_gap);
        if ((increment + cur_gap) > max_gap) {
            increment = max_gap - cur_gap;
        }
        if ((increment + w_count) > repeat) {
            increment = repeat - w_count;
        }
        for (i = 0; i < increment; i++) {
            kssl_write(ssl, k, r);
            w_count += 1;
        }

        // pipeline read
        increment = (random() % max_gap);
        if ((r_count + increment) > w_count) {
            increment = w_count - r_count;
        }
        for (i = 0; i < increment; i++) {
            to_return = kssl_read(ssl, k, r);
            verify_response(k, r, to_return);
            free(to_return->data);
            free(to_return);
            r_count += 1;
        }
    }
}

typedef struct {
  SSL *ssl;
  int fd;
} connection;

void kssl_bad_opcode(connection *c)
{
  kssl_header bad;
  kssl_operation req, resp;
  kssl_header *h;

  test("Bad KSSL opcode (%p)", c);
  bad.version_maj = KSSL_VERSION_MAJ;
  bad.version_min = KSSL_VERSION_MIN;
  bad.id = 0x12345678;
  bad.length = 0; // to be overridden by serialization
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = 0xBB;
  req.payload_len = 0;
  h = kssl(c->ssl, &bad, &req);
  test_assert(h->id == bad.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_BAD_OPCODE);
  ok(h);
}

void kssl_op_pong(connection *c)
{
  kssl_header echo0;
  kssl_operation req, resp;
  kssl_header *h;
  test("KSSL_OP_PONG (%p)", c);

  echo0.version_maj = KSSL_VERSION_MAJ;
  echo0.version_min = KSSL_VERSION_MIN;
  echo0.id = 0x12345678;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = KSSL_OP_PONG;
  req.payload_len = 0;
  h = kssl(c->ssl, &echo0, &req);
  test_assert(h->id == echo0.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_UNEXPECTED_OPCODE);
  ok(h);
}

void kssl_op_error(connection *c)
{
  kssl_header echo0;
  kssl_operation req, resp;
  kssl_header *h;
  test("KSSL_OP_ERROR (%p)", c);

  echo0.version_maj = KSSL_VERSION_MAJ;
  echo0.id = 0x12345678;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = KSSL_OP_ERROR;
  req.payload_len = 0;
  h = kssl(c->ssl, &echo0, &req);
  test_assert(h->id == echo0.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_UNEXPECTED_OPCODE);
  ok(h);
}

void kssl_op_ping_no_payload(connection *c)
{
  kssl_header echo0;
  kssl_operation req, resp;
  kssl_header *h;
  test("KSSL_OP_PING with no payload (%p)", c);

  echo0.version_maj = KSSL_VERSION_MAJ;
  echo0.id = 0x12345678;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = KSSL_OP_PING;
  req.payload_len = 0;
  h = kssl(c->ssl, &echo0, &req);
  test_assert(h->id == echo0.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_PONG);
  test_assert(resp.payload_len == 0);
  ok(h);
}

void kssl_op_ping_payload(connection *c)
{
  const char *hello = "Hello, World!";
  kssl_operation req, resp;
  kssl_header echo1;
  kssl_header *h;
  BYTE *payload;
  test("KSSL_OP_PING with payload (%p)", c);

  payload = malloc(strlen(hello) + 1);
  echo1.version_maj = KSSL_VERSION_MAJ;
  echo1.id = 0x12345679;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = KSSL_OP_PING;
  req.payload_len = strlen(hello);
  req.payload = payload;
  memcpy((char *)payload, hello, strlen(hello));
  h = kssl(c->ssl, &echo1, &req);
  test_assert(h->id == echo1.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_PONG);
  test_assert(resp.payload_len == req.payload_len);
  test_assert(strncmp((char *)resp.payload, (char *)req.payload, strlen(hello)) == 0);
  ok(h);
  free(payload);
}

void kssl_repeat_op_ping(connection *c, int repeat)
{
  char hello[255];
  kssl_header echo1;
  kssl_operation req, resp;
  kssl_header *h;
  int i;
  BYTE *payload = malloc(255 + 1);
  test("Repeat KSSL_OP_PING %d times (%p)", repeat, c);
  echo1.version_maj = KSSL_VERSION_MAJ;
  echo1.id = 0x12345679;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = KSSL_OP_PING;
  req.payload_len = 255 + 1;
  req.payload = payload;
  for (i = 0; i < repeat; i++) {
    sprintf(hello, "Hello, World! %d", i);
    memcpy((char *)payload, hello, strlen(hello)+1);
    req.payload_len = strlen(hello)+1;
    h = kssl(c->ssl, &echo1, &req);
    test_assert(h->id == echo1.id);
    test_assert(h->version_maj == KSSL_VERSION_MAJ);
    parse_message_payload(h->data, h->length, &resp);
    test_assert(resp.opcode == KSSL_OP_PONG);
    test_assert(resp.payload_len == req.payload_len);
    test_assert(strncmp((char *)resp.payload, (char *)req.payload, strlen(hello)) == 0);
    free(h->data);
    free(h);
  }
  ok(0);
  free(payload);
}

void kssl_pipeline_op_ping(connection *c, int repeat)
{
  char hello[255];
  kssl_header echo1;
  kssl_operation req;
  BYTE *payload = malloc(255 + 1);

  test("Pipeline KSSL_OP_PING %d times (%p)", repeat, c);
  echo1.version_maj = KSSL_VERSION_MAJ;
  echo1.id = 0x12345679;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = KSSL_OP_PING;
  req.payload_len = 255 + 1;
  req.payload = payload;
  sprintf(hello, "Hello, World! Pipeline");
  memcpy((char *)payload, hello, strlen(hello)+1);
  req.payload_len = strlen(hello)+1;
  kssl_pipeline(c->ssl, &echo1, &req, repeat);
  ok(0);
  free(payload);
}

void kssl_op_ping_bad_version(connection *c)
{
  kssl_header echo0;
  kssl_operation req, resp;
  kssl_header *h;
  test("KSSL_OP_PING with bad version (%p)", c);
  echo0.id = 0x12345678;
  echo0.version_maj = KSSL_VERSION_MAJ+1;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.opcode = KSSL_OP_PING;
  req.payload_len = 0;
  h = kssl(c->ssl, &echo0, &req);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  test_assert(h->id == echo0.id);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_VERSION_MISMATCH);
  ok(h);
}

void kssl_op_rsa_decrypt(connection *c, RSA *rsa_pubkey)
{
  static int count = 0;
  char kryptos2[255];
  kssl_header decrypt;
  kssl_operation req, resp;
  kssl_header *h;
  int size;
  test("KSSL_OP_RSA_DECRYPT (%p)", c);
  decrypt.version_maj = KSSL_VERSION_MAJ;
  decrypt.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.is_ip_set = 1;
  req.ip = ipv6;
  req.ip_len = 16;
  req.payload = malloc(RSA_size(rsa_pubkey));
  req.payload_len = RSA_size(rsa_pubkey);
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_rsa(rsa_pubkey, req.digest);
  req.opcode = KSSL_OP_RSA_DECRYPT;
  sprintf(kryptos2, "%02x It was totally invisible, how's that possible?", count);
  count += 1;

  size = RSA_public_encrypt(strlen(kryptos2), (unsigned char *)kryptos2,
                                (unsigned char *)req.payload,
                                rsa_pubkey, RSA_PKCS1_PADDING);
  if (size == -1) {
    fatal_error("Failed to RSA encrypt");
  }

  h = kssl(c->ssl, &decrypt, &req);
  test_assert(h->id == decrypt.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_RESPONSE);
  test_assert(resp.payload_len == strlen(kryptos2));
  test_assert(strncmp((char *)resp.payload, kryptos2, strlen(kryptos2)) == 0);
  ok(h);
  free(req.payload);
  free(req.digest);
}

void kssl_op_rsa_decrypt_raw(connection *c, RSA *rsa_pubkey)
{
  static int count = 0;
  char kryptos2[255];
  char unpadded_resp[255];
  int unpadded_len;
  kssl_header decrypt;
  kssl_operation req, resp;
  kssl_header *h;
  int size;
  test("KSSL_OP_RSA_DECRYPT_RAW (%p)", c);
  decrypt.version_maj = KSSL_VERSION_MAJ;
  decrypt.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.is_ip_set = 1;
  req.ip = ipv6;
  req.ip_len = 16;
  req.payload = malloc(RSA_size(rsa_pubkey));
  req.payload_len = RSA_size(rsa_pubkey);
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_rsa(rsa_pubkey, req.digest);
  req.opcode = KSSL_OP_RSA_DECRYPT_RAW;
  sprintf(kryptos2, "%02x It was totally invisible, how's that possible?", count);
  count += 1;

  size = RSA_public_encrypt(strlen(kryptos2), (unsigned char *)kryptos2,
                                (unsigned char *)req.payload,
                                rsa_pubkey, RSA_PKCS1_PADDING);

  if (size == -1) {
    fatal_error("Failed to RSA encrypt");
  }

  h = kssl(c->ssl, &decrypt, &req);
  test_assert(h->id == decrypt.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_RESPONSE);
  test_assert(resp.payload_len == RSA_size(rsa_pubkey));
  test_assert(*(resp.payload++) == 0);
  unpadded_len = RSA_padding_check_PKCS1_type_2((unsigned char *)unpadded_resp,
                                                sizeof(unpadded_resp),
                                                resp.payload,
                                                resp.payload_len-1,
                                                RSA_size(rsa_pubkey));
  test_assert(unpadded_len == (int)strlen(kryptos2));
  test_assert(strncmp(unpadded_resp, kryptos2, strlen(kryptos2)) == 0);
  ok(h);
  free(req.payload);
  free(req.digest);
}

#define ALGS_COUNT 6

// RSA signing algorithm opcodes
static int rsa_algs[ALGS_COUNT] = {
  KSSL_OP_RSA_SIGN_MD5SHA1,
  KSSL_OP_RSA_SIGN_SHA1,
  KSSL_OP_RSA_SIGN_SHA224,
  KSSL_OP_RSA_SIGN_SHA256,
  KSSL_OP_RSA_SIGN_SHA384,
  KSSL_OP_RSA_SIGN_SHA512,
};

// ECDSA signing algorithm opcodes
static int ecdsa_algs[ALGS_COUNT] = {
  KSSL_OP_ECDSA_SIGN_MD5SHA1,
  KSSL_OP_ECDSA_SIGN_SHA1,
  KSSL_OP_ECDSA_SIGN_SHA224,
  KSSL_OP_ECDSA_SIGN_SHA256,
  KSSL_OP_ECDSA_SIGN_SHA384,
  KSSL_OP_ECDSA_SIGN_SHA512,
};

// OpenSSL digest NIDs 
static int nid[ALGS_COUNT] = {
  NID_md5_sha1,
  NID_sha1,
  NID_sha224,
  NID_sha256,
  NID_sha384,
  NID_sha512,
};

// These are totally bogus but they have the right lengths (and, anyway, who's to say these aren't real
// message digests?)
static char* digests[ALGS_COUNT] = {
  "123456789012345678901234567890123456",                              // MD5SH1 is 36 bytes
  "12345678901234567890",                                              // SHA1 is 20 bytes
  "1234567890123456789012345678",                                      // SHA224 is 28 bytes
  "12345678901234567890123456789012",                                  // SHA256 is 32 bytes
  "123456789012345678901234567890123456789012345678",                  // SHA384 is 48 bytes
  "1234567890123456789012345678901234567890123456789012345678901234",  // SHA512 is 64 bytes
};

void kssl_op_rsa_sign(connection *c, RSA *rsa_pubkey, int opcode)
{
  int i, rc;
  kssl_header *h;
  test("KSSL_OP_RSA_SIGN_* (%p)", c);
  for (i = 0; i < ALGS_COUNT; i++) {
    kssl_header sign;
    kssl_operation req, resp;
    if (opcode != rsa_algs[i] && opcode != 0) continue;
    sign.version_maj = KSSL_VERSION_MAJ;
    sign.id = 0x1234567a;
    zero_operation(&req);
    req.is_opcode_set = 1;
    req.is_payload_set = 1;
    req.is_digest_set = 1;
    req.is_ip_set = 1;
    req.ip = ipv4;
    req.ip_len = 4;
    req.digest = malloc(KSSL_DIGEST_SIZE);
    digest_public_rsa(rsa_pubkey, req.digest);
    req.payload = (BYTE *)digests[i];
    req.payload_len = strlen(digests[i]);
    req.opcode = rsa_algs[i];

    h = kssl(c->ssl, &sign, &req);
    test_assert(h->id == sign.id);
    test_assert(h->version_maj == KSSL_VERSION_MAJ);
    parse_message_payload(h->data, h->length, &resp);
    test_assert(resp.opcode == KSSL_OP_RESPONSE);

    rc = RSA_verify(nid[i], (unsigned char *)digests[i], strlen(digests[i]), resp.payload, resp.payload_len, rsa_pubkey);
    test_assert(rc == 1);

    free(h);
    free(req.digest);
  }

  ok(0);
}

void kssl_op_ecdsa_sign(connection *c, EC_KEY *ecdsa_pubkey, int opcode)
{
  int i, rc;
  kssl_header *h;
  test("KSSL_OP_ECDSA_SIGN_* (%p)", c);
  for (i = 0; i < ALGS_COUNT; i++) {
    kssl_header sign;
    kssl_operation req, resp;
    if (opcode != ecdsa_algs[i] && opcode != 0) continue;
    sign.version_maj = KSSL_VERSION_MAJ;
    sign.id = 0x1234567a;
    zero_operation(&req);
    req.is_opcode_set = 1;
    req.is_payload_set = 1;
    req.is_digest_set = 1;
    req.is_ip_set = 1;
    req.ip = ipv4;
    req.ip_len = 4;
    req.digest = malloc(KSSL_DIGEST_SIZE);
    digest_public_ec(ecdsa_pubkey, req.digest);
    req.payload = (BYTE *)digests[i];
    req.payload_len = strlen(digests[i]);
    req.opcode = ecdsa_algs[i];

    h = kssl(c->ssl, &sign, &req);
    test_assert(h->id == sign.id);
    test_assert(h->version_maj == KSSL_VERSION_MAJ);
    parse_message_payload(h->data, h->length, &resp);
    test_assert(resp.opcode == KSSL_OP_RESPONSE);

    rc = ECDSA_verify(nid[i], (unsigned char *)digests[i], strlen(digests[i]), resp.payload, resp.payload_len, ecdsa_pubkey);
    test_assert(rc == 1);

    free(h);
    free(req.digest);
  }

  ok(0);
}

// Sign but don't verify, used for performance testing
void kssl_repeat_op_rsa_sign(connection *c, RSA *rsa_pubkey, int repeat, int opcode)
{
  int i, j;
  kssl_header *h;
  for (i = 0; i < ALGS_COUNT; i++) {
    kssl_header sign;
    kssl_operation req, resp;

    if (opcode != rsa_algs[i]) continue;
    sign.version_maj = KSSL_VERSION_MAJ;
    sign.id = 0x1234567a;
    zero_operation(&req);
    req.is_opcode_set = 1;
    req.is_payload_set = 1;
    req.is_digest_set = 1;
    req.is_ip_set = 1;
    req.ip = ipv4;
    req.ip_len = 4;
    req.digest = malloc(KSSL_DIGEST_SIZE);
    digest_public_rsa(rsa_pubkey, req.digest);
    req.payload = (BYTE *)digests[i];
    req.payload_len = strlen(digests[i]);
    req.opcode = rsa_algs[i];

    for (j = 0; j < repeat; j++) {
      h = kssl(c->ssl, &sign, &req);
      test_assert(h->id == sign.id);
      test_assert(h->version_maj == KSSL_VERSION_MAJ);
      parse_message_payload(h->data, h->length, &resp);
      test_assert(resp.opcode == KSSL_OP_RESPONSE);
      free(h);
    }

    free(req.digest);
  }
}

void kssl_repeat_op_ecdsa_sign(connection *c, EC_KEY *ecdsa_pubkey, int repeat, int opcode)
{
  int i, j;
  kssl_header *h;
  for (i = 0; i < ALGS_COUNT; i++) {
    kssl_header sign;
    kssl_operation req, resp;

    if (opcode != ecdsa_algs[i]) continue;
    sign.version_maj = KSSL_VERSION_MAJ;
    sign.id = 0x1234567a;
    zero_operation(&req);
    req.is_opcode_set = 1;
    req.is_payload_set = 1;
    req.is_digest_set = 1;
    req.is_ip_set = 1;
    req.ip = ipv4;
    req.ip_len = 4;
    req.digest = malloc(KSSL_DIGEST_SIZE);
    digest_public_ec(ecdsa_pubkey, req.digest);
    req.payload = (BYTE *)digests[i];
    req.payload_len = strlen(digests[i]);
    req.opcode = ecdsa_algs[i];

    for (j = 0; j < repeat; j++) {
      h = kssl(c->ssl, &sign, &req);
      test_assert(h->id == sign.id);
      test_assert(h->version_maj == KSSL_VERSION_MAJ);
      parse_message_payload(h->data, h->length, &resp);
      test_assert(resp.opcode == KSSL_OP_RESPONSE);
      free(h);
    }

    free(req.digest);
  }
}

void kssl_pipeline_op_rsa_sign(connection *c, RSA *rsa_pubkey, int repeat, int opcode)
{
  int i;
  for (i = 0; i < ALGS_COUNT; i++) {
    kssl_header sign;
    kssl_operation req;

    if (opcode != rsa_algs[i]) continue;
    sign.version_maj = KSSL_VERSION_MAJ;
    sign.id = 0x1234567a;
    zero_operation(&req);
    req.is_opcode_set = 1;
    req.is_payload_set = 1;
    req.is_digest_set = 1;
    req.is_ip_set = 1;
    req.ip = ipv4;
    req.ip_len = 4;
    req.digest = malloc(KSSL_DIGEST_SIZE);
    digest_public_rsa(rsa_pubkey, req.digest);
    req.payload = (BYTE *)digests[i];
    req.payload_len = strlen(digests[i]);
    req.opcode = rsa_algs[i];

    kssl_pipeline(c->ssl, &sign, &req, repeat);
    free(req.digest);
  }
}

void kssl_pipeline_op_ecdsa_sign(connection *c, EC_KEY *ecdsa_pubkey, int repeat, int opcode)
{
  int i;
  for (i = 0; i < ALGS_COUNT; i++) {
    kssl_header sign;
    kssl_operation req;

    if (opcode != ecdsa_algs[i]) continue;
    sign.version_maj = KSSL_VERSION_MAJ;
    sign.id = 0x1234567a;
    zero_operation(&req);
    req.is_opcode_set = 1;
    req.is_payload_set = 1;
    req.is_digest_set = 1;
    req.is_ip_set = 1;
    req.ip = ipv4;
    req.ip_len = 4;
    req.digest = malloc(KSSL_DIGEST_SIZE);
    digest_public_ec(ecdsa_pubkey, req.digest);
    req.payload = (BYTE *)digests[i];
    req.payload_len = strlen(digests[i]);
    req.opcode = ecdsa_algs[i];

    kssl_pipeline(c->ssl, &sign, &req, repeat);
    free(req.digest);
  }
}

void kssl_op_rsa_decrypt_bad_data(connection *c, RSA *rsa_pubkey)
{
  char *kryptos2 = "It was totally invisible, how's that possible?";
  BYTE *payload = malloc(RSA_size(rsa_pubkey));
  kssl_header decrypt;
  kssl_operation req, resp;
  int size;
  kssl_header *h;

  test("KSSL_OP_RSA_DECRYPT with bad data (%p)", c);
  decrypt.version_maj = KSSL_VERSION_MAJ;
  decrypt.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.payload = payload;
  req.payload_len = RSA_size(rsa_pubkey);
  req.is_ip_set = 1;
  req.ip = ipv4;
  req.ip_len = 4;
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_rsa(rsa_pubkey, req.digest);
  req.opcode = KSSL_OP_RSA_DECRYPT;

  size = RSA_public_encrypt(strlen(kryptos2), (unsigned char *)kryptos2,
                                (unsigned char *)payload,
                                rsa_pubkey, RSA_PKCS1_PADDING);
  if (size == -1) {
    fatal_error("Failed to RSA encrypt");
  }

  memset(payload, 0, size);
  h = kssl(c->ssl, &decrypt, &req);
  test_assert(h->id == decrypt.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_CRYPTO_FAILED);
  ok(h);
  free(req.payload);
  free(req.digest);
}

void kssl_op_rsa_decrypt_raw_bad_data(connection *c, RSA *rsa_pubkey)
{
  kssl_header decrypt;
  kssl_operation req, resp;
  int size = RSA_size(rsa_pubkey) + 1;
  BYTE *payload = malloc(size);
  kssl_header *h;

  test("KSSL_OP_RSA_DECRYPT_RAW with bad data (%p)", c);
  decrypt.version_maj = KSSL_VERSION_MAJ;
  decrypt.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.payload = payload;
  req.payload_len = size;
  req.is_ip_set = 1;
  req.ip = ipv4;
  req.ip_len = 4;
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_rsa(rsa_pubkey, req.digest);
  req.opcode = KSSL_OP_RSA_DECRYPT_RAW;
  memset(payload, 0, size);

  h = kssl(c->ssl, &decrypt, &req);
  test_assert(h->id == decrypt.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_CRYPTO_FAILED);
  ok(h);
  free(req.payload);
  free(req.digest);
}

// ssl_connect: establish a TLS connection to the keyserver on
// the passed in port number
connection *ssl_connect(SSL_CTX *ctx, int port)
{
  struct sockaddr_in addr;
  int rc;
  connection *c = (connection *)calloc(1, sizeof(connection));

  c->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (c->fd == -1) {
    fatal_error("Can't create TCP socket");
  }

  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = ((struct in_addr*)(localhost->h_addr_list[0]))->s_addr;
  memset(&(addr.sin_zero), 0, 8);

  if (connect(c->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {
    fatal_error("Failed to connect to keyserver on port %d", port);
  }

  c->ssl = SSL_new(ctx);
  if (!c->ssl) {
    fatal_error("Failed to create new SSL context");
  }
  SSL_set_fd(c->ssl, c->fd);

  rc = SSL_connect(c->ssl);
  if (rc != 1) {
    ERR_print_errors_fp(stderr);
    fatal_error("TLS handshake error %d/%d/%d\n", rc,
                SSL_get_error(c->ssl, rc), errno);
  }

  return c;
}

// ssl_disconnect: drop and cleanup connection to TLS server created using
// ssl_connect
void ssl_disconnect(connection *c)
{
  SSL_shutdown(c->ssl);
  SOCKET_CLOSE(c->fd);
  SSL_free(c->ssl);
  free(c);
}

void kssl_op_rsa_decrypt_bad_digest(connection *c, RSA *rsa_pubkey)
{
  char *kryptos2 = "It was totally invisible, how's that possible?";
  BYTE *payload = malloc(RSA_size(rsa_pubkey));
  kssl_header decrypt;
  int size;
  kssl_header *h;
  kssl_operation req, resp;

  test("KSSL_OP_RSA_DECRYPT with bad digest (%p)", c);
  decrypt.version_maj = KSSL_VERSION_MAJ;
  decrypt.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_rsa(rsa_pubkey, req.digest);
  req.opcode = KSSL_OP_RSA_DECRYPT;
  req.payload = payload;
  req.payload_len = RSA_size(rsa_pubkey);

  size = RSA_public_encrypt(strlen(kryptos2), (unsigned char *)kryptos2,
                                (unsigned char *)payload,
                                rsa_pubkey, RSA_PKCS1_PADDING);
  if (size == -1) {
    fatal_error("Failed to RSA encrypt");
  }

  req.digest[0] ^= 0xff;
  h = kssl(c->ssl, &decrypt, &req);
  test_assert(h->id == decrypt.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_KEY_NOT_FOUND);
  ok(h);
  free(req.payload);
  free(req.digest);
}

void kssl_op_rsa_decrypt_raw_bad_digest(connection *c, RSA *rsa_pubkey)
{
  char *kryptos2 = "It was totally invisible, how's that possible?";
  BYTE *payload = malloc(RSA_size(rsa_pubkey));
  kssl_header decrypt;
  int size;
  kssl_header *h;
  kssl_operation req, resp;

  test("KSSL_OP_RSA_DECRYPT_RAW with bad digest (%p)", c);
  decrypt.version_maj = KSSL_VERSION_MAJ;
  decrypt.id = 0x1234567a;
  zero_operation(&req);
  req.is_opcode_set = 1;
  req.is_payload_set = 1;
  req.is_digest_set = 1;
  req.digest = malloc(KSSL_DIGEST_SIZE);
  digest_public_rsa(rsa_pubkey, req.digest);
  req.opcode = KSSL_OP_RSA_DECRYPT_RAW;
  req.payload = payload;
  req.payload_len = RSA_size(rsa_pubkey);

  size = RSA_public_encrypt(strlen(kryptos2), (unsigned char *)kryptos2,
                                (unsigned char *)payload,
                                rsa_pubkey, RSA_PKCS1_PADDING);
  if (size == -1) {
    fatal_error("Failed to RSA encrypt");
  }

  req.digest[0] ^= 0xff;
  h = kssl(c->ssl, &decrypt, &req);
  test_assert(h->id == decrypt.id);
  test_assert(h->version_maj == KSSL_VERSION_MAJ);
  parse_message_payload(h->data, h->length, &resp);
  test_assert(resp.opcode == KSSL_OP_ERROR);
  test_assert(resp.payload_len == 1);
  test_assert(resp.payload[0] == KSSL_ERROR_KEY_NOT_FOUND);
  ok(h);
  free(req.payload);
  free(req.digest);
}

typedef struct signing_data_rsa {
  SSL_CTX *ctx;
  RSA *rsa_pubkey;
  int port;
  int repeat;
  int alg;
} signing_data_rsa;

typedef struct signing_data_ecdsa {
  SSL_CTX *ctx;
  EC_KEY *ecdsa_pubkey;
  int port;
  int repeat;
  int alg;
} signing_data_ecdsa;

void thread_repeat_rsa_sign(void *ptr)
{
  signing_data_rsa *data = (signing_data_rsa*)ptr;

  connection *c1 = ssl_connect(data->ctx, data->port);
  kssl_repeat_op_rsa_sign(c1, data->rsa_pubkey, data->repeat, data->alg);
  ssl_disconnect(c1);
}

void thread_repeat_ecdsa_sign(void *ptr)
{
  signing_data_ecdsa *data = (signing_data_ecdsa*)ptr;

  connection *c1 = ssl_connect(data->ctx, data->port);
  kssl_repeat_op_ecdsa_sign(c1, data->ecdsa_pubkey, data->repeat, data->alg);
  ssl_disconnect(c1);
}

void thread_pipeline_rsa_sign(void *ptr)
{
  signing_data_rsa *data = (signing_data_rsa*)ptr;

  connection *c1 = ssl_connect(data->ctx, data->port);
  kssl_pipeline_op_rsa_sign(c1, data->rsa_pubkey, data->repeat, data->alg);
  ssl_disconnect(c1);
}

void thread_pipeline_ecdsa_sign(void *ptr)
{
  signing_data_ecdsa *data = (signing_data_ecdsa*)ptr;

  connection *c1 = ssl_connect(data->ctx, data->port);
  kssl_pipeline_op_ecdsa_sign(c1, data->ecdsa_pubkey, data->repeat, data->alg);
  ssl_disconnect(c1);
}

int main(int argc, char *argv[])
{
  int port = -1;
  char *rsa_pubkey_path = 0;
  char *ecdsa_pubkey_path = 0;
  char *client_cert = 0;
  char *client_key = 0;
  char *ca_file = 0;

  const SSL_METHOD *method;
  EVP_PKEY *evp_pubkey_tmp;
  RSA *rsa_pubkey;
  EC_KEY *ecdsa_pubkey;
  BIO *bio;
  SSL_CTX *ctx;
  connection *c0, *c1, *c2, *c3, *c;
  int i, j;
  int opt;
  struct timeval stop, start;
  const char * cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH";
  const char * ec_curve_name = "prime256v1";
  const struct option long_options[] = {
    {"port",        required_argument, 0, 0},
    {"rsa-pubkey",  required_argument, 0, 1},
    {"ec-pubkey",   required_argument, 0, 2},
    {"client-cert", required_argument, 0, 3},
    {"client-key",  required_argument, 0, 4},
    {"ca-file",     required_argument, 0, 5},
    {"debug",       no_argument,       0, 6},
    {"server",      required_argument, 0, 7},
    {"short",       no_argument,       0, 8},
    {"alive",       no_argument,       0, 9},
  };

  optind = 1;
  while (1) {
    opt = getopt_long(argc, argv, "", long_options, 0);
    if (opt == -1) {
      break;
    }

    switch (opt) {
    case 0:
      port = atoi(optarg);
      break;

    case 1:
      rsa_pubkey_path = (char *)malloc(strlen(optarg)+1);
      strcpy(rsa_pubkey_path, optarg);
      break;

    case 2:
      ecdsa_pubkey_path = (char *)malloc(strlen(optarg)+1);
      strcpy(ecdsa_pubkey_path, optarg);
      break;

    case 3:
      client_cert = (char *)malloc(strlen(optarg)+1);
      strcpy(client_cert, optarg);
      break;

    case 4:
      client_key = (char *)malloc(strlen(optarg)+1);
      strcpy(client_key, optarg);
      break;

    case 5:
      ca_file = (char *)malloc(strlen(optarg)+1);
      strcpy(ca_file, optarg);
      break;

    case 6:
      debug = 1;
      break;

    case 7:
      server = (char *)malloc(strlen(optarg)+1);
      strcpy(server, optarg);
      break;
      
    case 8:
      health = 1;
      break;
      
    case 9:
      alive = 1;
      break;
    }
  }

  if (port == -1) {
    fatal_error("The --port parameter must be specified with the connect port");
  }
  if (!rsa_pubkey_path) {
    fatal_error("The --rsa-pubkey parameter must be specified with the path to "
                "the RSA public key file to be used for RSA encryption and signature verification");
  }
  if (!ecdsa_pubkey_path) {
    fatal_error("The --ec-pubkey parameter must be specified with the path to "
                "the EC public key file to be used for ECDSA signature verification");
  }
  if (!client_cert) {
    fatal_error("The --client-cert parameter must be specified with a signed client certificate file name");
  }
  if (!server) {
    fatal_error("The --server must be specified");
  }

  localhost = gethostbyname(server);
  if (!localhost) {
    fatal_error("Could not look up address of localhost");
  }

  SSL_library_init();
  SSL_load_error_strings();
  method = TLSv1_2_client_method();

  bio = BIO_new(BIO_s_file());
  BIO_read_filename(bio, rsa_pubkey_path);
  evp_pubkey_tmp = PEM_read_bio_PUBKEY(bio, 0, 0, 0);
  if (!evp_pubkey_tmp) {
    fatal_error("Error reading RSA pubkey");
  }
  rsa_pubkey = EVP_PKEY_get1_RSA(evp_pubkey_tmp);
  if (!rsa_pubkey) {
    fatal_error("Error reading RSA pubkey");
  }

  BIO_free(bio);
  if (!rsa_pubkey) {
    ssl_error();
  }
  bio = BIO_new(BIO_s_file());
  BIO_read_filename(bio, ecdsa_pubkey_path);
  evp_pubkey_tmp = PEM_read_bio_PUBKEY(bio, 0, 0, 0);
  if (!evp_pubkey_tmp) {
    fatal_error("Error reading EC pubkey");
  }
  ecdsa_pubkey = EVP_PKEY_get1_EC_KEY(evp_pubkey_tmp);

  BIO_free(bio);
  if (!ecdsa_pubkey) {
    ssl_error();
  }

  ctx = SSL_CTX_new(method);

  if (!ctx) {
    ssl_error();
  }

  if (SSL_CTX_set_cipher_list(ctx, cipher_list) == 0) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to set cipher list: %s", cipher_list);
  }

  int nid = OBJ_sn2nid(ec_curve_name);
  if (NID_undef == nid) {
    SSL_CTX_free(ctx);
    fatal_error("ECDSA curve not present");
  }

  EC_KEY *ecdh = EC_KEY_new_by_curve_name(nid);
  if (NULL == ecdh) {
    SSL_CTX_free(ctx);
    fatal_error("ECDSA new curve error");
  }

  if(SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("Call to SSL_CTX_set_tmp_ecdh failed");
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

  if (SSL_CTX_load_verify_locations(ctx, ca_file, 0) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to load CA file %s", ca_file);
  }

  if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("Call to SSL_CTX_set_default_verify_paths failed");
  }

  if (SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to load client certificate from %s", client_cert);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("Failed to load client private key from %s", client_key);
  }

  if (SSL_CTX_check_private_key(ctx) != 1) {
    SSL_CTX_free(ctx);
    fatal_error("SSL_CTX_check_private_key failed");
  }

  // If --alive set then just check connectivity to the kssl_server by
  // sending an receiving a ping/pong
  
  if (alive) {
    c0 = ssl_connect(ctx, port);
    kssl_op_pong(c0);
    ssl_disconnect(c0);
    SSL_CTX_free(ctx);

    return 0;
  }

  // Use a new connection for each test
  c0 = ssl_connect(ctx, port);
  kssl_bad_opcode(c0);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_pong(c0);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_error(c0);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_ping_no_payload(c0);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_ping_payload(c0);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_ping_bad_version(c0);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_rsa_decrypt(c0, rsa_pubkey);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_rsa_decrypt_bad_data(c0, rsa_pubkey);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_rsa_decrypt_bad_digest(c0, rsa_pubkey);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_rsa_decrypt_raw(c0, rsa_pubkey);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_rsa_decrypt_raw_bad_data(c0, rsa_pubkey);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_rsa_decrypt_raw_bad_digest(c0, rsa_pubkey);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_rsa_sign(c0, rsa_pubkey, 0);
  ssl_disconnect(c0);

  c0 = ssl_connect(ctx, port);
  kssl_op_ecdsa_sign(c0, ecdsa_pubkey, 0);
  ssl_disconnect(c0);

  // Use a single connection to perform tests in sequence

  c = ssl_connect(ctx, port);
  kssl_bad_opcode(c);
  kssl_op_pong(c);
  kssl_op_error(c);
  kssl_op_ping_no_payload(c);
  kssl_op_ping_payload(c);
  kssl_op_ping_bad_version(c);
  kssl_op_rsa_decrypt(c, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_data(c, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_digest(c, rsa_pubkey);
  kssl_op_rsa_decrypt_raw(c, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_data(c, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_digest(c, rsa_pubkey);
  kssl_op_rsa_sign(c, rsa_pubkey, 0);
  kssl_op_ecdsa_sign(c, ecdsa_pubkey, 0);
  ssl_disconnect(c);

  // Make two connections and perform interleaved tests

  c1 = ssl_connect(ctx, port);
  c2 = ssl_connect(ctx, port);
  kssl_bad_opcode(c1);
  kssl_bad_opcode(c2);
  kssl_op_pong(c1);
  kssl_op_pong(c2);
  kssl_op_error(c1);
  kssl_op_error(c2);
  kssl_op_ping_no_payload(c1);
  kssl_op_ping_no_payload(c2);
  kssl_op_ping_payload(c1);
  kssl_op_ping_payload(c2);
  kssl_op_ping_bad_version(c1);
  kssl_op_ping_bad_version(c2);
  kssl_op_rsa_decrypt(c1, rsa_pubkey);
  kssl_op_rsa_decrypt(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_data(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_data(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_digest(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_digest(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_raw(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_raw(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_data(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_data(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_digest(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_digest(c2, rsa_pubkey);
  kssl_op_rsa_sign(c1, rsa_pubkey, 0);
  kssl_op_rsa_sign(c2, rsa_pubkey, 0);
  kssl_op_ecdsa_sign(c1, ecdsa_pubkey, 0);
  kssl_op_ecdsa_sign(c2, ecdsa_pubkey, 0);
  ssl_disconnect(c2);
  ssl_disconnect(c1);

  // Make two connections and perform interleaved tests

  c1 = ssl_connect(ctx, port);
  c2 = ssl_connect(ctx, port);
  kssl_bad_opcode(c1);
  kssl_bad_opcode(c2);
  kssl_op_pong(c1);
  kssl_op_pong(c2);
  kssl_op_error(c1);
  kssl_op_error(c2);
  ssl_disconnect(c2);
  c2 = ssl_connect(ctx, port);
  kssl_op_ping_no_payload(c1);
  kssl_op_ping_no_payload(c2);
  kssl_op_ping_payload(c1);
  kssl_op_ping_payload(c2);
  kssl_op_ping_bad_version(c1);
  kssl_op_ping_bad_version(c2);
  kssl_op_rsa_decrypt(c1, rsa_pubkey);
  kssl_op_rsa_decrypt(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_raw(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_raw(c2, rsa_pubkey);
  ssl_disconnect(c1);
  c1 = ssl_connect(ctx, port);
  kssl_op_rsa_decrypt_bad_data(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_data(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_digest(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_bad_digest(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_data(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_data(c2, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_digest(c1, rsa_pubkey);
  kssl_op_rsa_decrypt_raw_bad_digest(c2, rsa_pubkey);
  kssl_op_rsa_sign(c1, rsa_pubkey, 0);
  kssl_op_rsa_sign(c2, rsa_pubkey, 0);
  kssl_op_ecdsa_sign(c1, ecdsa_pubkey, 0);
  kssl_op_ecdsa_sign(c2, ecdsa_pubkey, 0);
  ssl_disconnect(c2);
  ssl_disconnect(c1);

  c3 = ssl_connect(ctx, port);
  kssl_repeat_op_ping(c3, 18);
  kssl_pipeline_op_ping(c3, 1000);
  ssl_disconnect(c3);

  if (!health) {
    {
      // Compute timing for various operations
      #define LOOP_COUNT 1000
      c1 = ssl_connect(ctx, port);
      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        kssl_repeat_op_rsa_sign(c1, rsa_pubkey, LOOP_COUNT, rsa_algs[i]);
        gettimeofday(&stop, NULL);
        printf("\n %d sequential %s takes %ld ms\n", LOOP_COUNT, opstring(rsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }
      ssl_disconnect(c1);

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        c1 = ssl_connect(ctx, port);
        kssl_repeat_op_rsa_sign(c1, rsa_pubkey, LOOP_COUNT, rsa_algs[i]);
        ssl_disconnect(c1);
        gettimeofday(&stop, NULL);
        printf("\n %d sequential %s with one connection takes %ld ms\n", LOOP_COUNT, opstring(rsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        for (j = 0; j < LOOP_COUNT/10; j++) {
          c1 = ssl_connect(ctx, port);
          kssl_repeat_op_rsa_sign(c1, rsa_pubkey, 10, rsa_algs[i]);
          ssl_disconnect(c1);
        }
        gettimeofday(&stop, NULL);
        printf("\n %d sequential %s with 10 requests per re-connection takes %ld ms\n", LOOP_COUNT, opstring(rsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }

      c1 = ssl_connect(ctx, port);
      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        kssl_repeat_op_ecdsa_sign(c1, ecdsa_pubkey, LOOP_COUNT, ecdsa_algs[i]);
        gettimeofday(&stop, NULL);
        printf("\n %d sequential %s takes %ld ms\n", LOOP_COUNT, opstring(ecdsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }
      ssl_disconnect(c1);

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        c1 = ssl_connect(ctx, port);
        kssl_repeat_op_ecdsa_sign(c1, ecdsa_pubkey, LOOP_COUNT, ecdsa_algs[i]);
        ssl_disconnect(c1);
        gettimeofday(&stop, NULL);
        printf("\n %d sequential %s with one connection takes %ld ms\n", LOOP_COUNT, opstring(ecdsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        for (j = 0; j < LOOP_COUNT/10; j++) {
          c1 = ssl_connect(ctx, port);
          kssl_repeat_op_ecdsa_sign(c1, ecdsa_pubkey, 10, ecdsa_algs[i]);
          ssl_disconnect(c1);
        }
        gettimeofday(&stop, NULL);
        printf("\n %d sequential %s with 10 requests per re-connection takes %ld ms\n", LOOP_COUNT, opstring(ecdsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }
    }

    // 2 threads
    {
      uv_thread_t thread[LOOP_COUNT];
      signing_data_rsa data_rsa[LOOP_COUNT];
      signing_data_ecdsa data_ecdsa[LOOP_COUNT];
      thread_setup();

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        for (j = 0; j < 2; j++) {
          data_rsa[j].ctx = ctx;
          data_rsa[j].rsa_pubkey = rsa_pubkey;
          data_rsa[j].port = port;
          data_rsa[j].repeat = LOOP_COUNT/2;
          data_rsa[j].alg = rsa_algs[i];
          uv_thread_create(&thread[j], thread_repeat_rsa_sign, (void *)&data_rsa[j]);
        }
        for (j = 0; j < 2; j++) {
          uv_thread_join(&thread[j]);
        }
        gettimeofday(&stop, NULL);
        printf("\n %d requests %s over 2 threads takes %ld ms\n", LOOP_COUNT, opstring(rsa_algs[i]),
          (stop.tv_sec - start.tv_sec) * 1000 +
          (stop.tv_usec - start.tv_usec) / 1000);
      }

      thread_cleanup();

      thread_setup();

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        for (j = 0; j < 2; j++) {
          data_ecdsa[j].ctx = ctx;
          data_ecdsa[j].ecdsa_pubkey = ecdsa_pubkey;
          data_ecdsa[j].port = port;
          data_ecdsa[j].repeat = LOOP_COUNT/2;
          data_ecdsa[j].alg = ecdsa_algs[i];
          uv_thread_create(&thread[j], thread_repeat_ecdsa_sign, (void *)&data_ecdsa[j]);
        }
        for (j = 0; j < 2; j++) {
          uv_thread_join(&thread[j]);
        }
        gettimeofday(&stop, NULL);
        printf("\n %d requests %s over 2 threads takes %ld ms\n", LOOP_COUNT, opstring(ecdsa_algs[i]),
          (stop.tv_sec - start.tv_sec) * 1000 +
          (stop.tv_usec - start.tv_usec) / 1000);
      }

      thread_cleanup();
    }

    // pipeline request tests
    {
      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        c0 = ssl_connect(ctx, port);
        kssl_pipeline_op_rsa_sign(c0, rsa_pubkey, LOOP_COUNT, rsa_algs[i]);
        ssl_disconnect(c0);
        gettimeofday(&stop, NULL);
        printf("\n %d pipeline %s requests takes %ld ms\n", LOOP_COUNT, opstring(rsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        c0 = ssl_connect(ctx, port);
        kssl_pipeline_op_ecdsa_sign(c0, ecdsa_pubkey, LOOP_COUNT, ecdsa_algs[i]);
        ssl_disconnect(c0);
        gettimeofday(&stop, NULL);
        printf("\n %d pipeline %s requests takes %ld ms\n", LOOP_COUNT, opstring(ecdsa_algs[i]),
            (stop.tv_sec - start.tv_sec) * 1000 +
            (stop.tv_usec - start.tv_usec) / 1000);
      }
    }

    // 2 threads for pipeline request
    {
      uv_thread_t thread[LOOP_COUNT];
      signing_data_rsa data_rsa[LOOP_COUNT];
      signing_data_ecdsa data_ecdsa[LOOP_COUNT];
      thread_setup();

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        for (j = 0; j < 2; j++) {
          data_rsa[j].ctx = ctx;
          data_rsa[j].rsa_pubkey = rsa_pubkey;
          data_rsa[j].port = port;
          data_rsa[j].repeat = LOOP_COUNT/2;
          data_rsa[j].alg = rsa_algs[i];
          uv_thread_create(&thread[j], thread_pipeline_rsa_sign, (void *)&data_rsa[j]);
        }
        for (j = 0; j < 2; j++) {
          uv_thread_join(&thread[j]);
        }
        gettimeofday(&stop, NULL);
        printf("\n %d pipeline requests %s over 2 threads takes %ld ms\n", LOOP_COUNT, opstring(rsa_algs[i]),
          (stop.tv_sec - start.tv_sec) * 1000 +
          (stop.tv_usec - start.tv_usec) / 1000);
      }

      thread_cleanup();

      thread_setup();

      for (i = 0; i < ALGS_COUNT; i++) {
        gettimeofday(&start, NULL);
        for (j = 0; j < 2; j++) {
          data_ecdsa[j].ctx = ctx;
          data_ecdsa[j].ecdsa_pubkey = ecdsa_pubkey;
          data_ecdsa[j].port = port;
          data_ecdsa[j].repeat = LOOP_COUNT/2;
          data_ecdsa[j].alg = ecdsa_algs[i];
          uv_thread_create(&thread[j], thread_pipeline_ecdsa_sign, (void *)&data_ecdsa[j]);
        }
        for (j = 0; j < 2; j++) {
          uv_thread_join(&thread[j]);
        }
        gettimeofday(&stop, NULL);
        printf("\n %d pipeline requests %s over 2 threads takes %ld ms\n", LOOP_COUNT, opstring(ecdsa_algs[i]),
          (stop.tv_sec - start.tv_sec) * 1000 +
          (stop.tv_usec - start.tv_usec) / 1000);
      }

      thread_cleanup();
    }

#if !PLATFORM_WINDOWS
    // Test requests over multiple processes
    {
      int k;
      int forks[8] = {1, 2, 4, 8, 16, 32, 64, 128};
      pid_t pid[LOOP_COUNT];
      signing_data_rsa data_rsa[LOOP_COUNT];
      signing_data_ecdsa data_ecdsa[LOOP_COUNT];
      for (k = 0; k < 8; k++) {
        for (i = 0; i < ALGS_COUNT; i++) {
          gettimeofday(&start, NULL);
          for (j = 0; j < forks[k]; j++) {
            data_rsa[j].ctx = ctx;
            data_rsa[j].rsa_pubkey = rsa_pubkey;
            data_rsa[j].port = port;
            data_rsa[j].repeat = LOOP_COUNT / forks[k];
            data_rsa[j].alg = rsa_algs[i];
            pid[j] = fork();
            if (pid[j] == 0) {
              thread_repeat_rsa_sign((void *)&data_rsa[j]);
              exit(0);
            }
          }
          for (j = 0; j < forks[k]; j++) {
            waitpid(pid[j], NULL, 0);
          }
          gettimeofday(&stop, NULL);
          printf("\n %d requests %s over %d forks takes %ld ms\n", LOOP_COUNT,
              opstring(rsa_algs[i]), forks[k],
              (stop.tv_sec - start.tv_sec) * 1000 +
              (stop.tv_usec - start.tv_usec) / 1000);
        }
      }

      for (k = 0; k < 8; k++) {
        for (i = 0; i < ALGS_COUNT; i++) {
          gettimeofday(&start, NULL);
          for (j = 0; j < forks[k]; j++) {
            data_ecdsa[j].ctx = ctx;
            data_ecdsa[j].ecdsa_pubkey = ecdsa_pubkey;
            data_ecdsa[j].port = port;
            data_ecdsa[j].repeat = LOOP_COUNT / forks[k];
            data_ecdsa[j].alg = ecdsa_algs[i];
            pid[j] = fork();
            if (pid[j] == 0) {
              thread_repeat_ecdsa_sign((void *)&data_ecdsa[j]);
              exit(0);
            }
          }
          for (j = 0; j < forks[k]; j++) {
            waitpid(pid[j], NULL, 0);
          }
          gettimeofday(&stop, NULL);
          printf("\n %d requests %s over %d forks takes %ld ms\n", LOOP_COUNT,
              opstring(rsa_algs[i]), forks[k],
              (stop.tv_sec - start.tv_sec) * 1000 +
              (stop.tv_usec - start.tv_usec) / 1000);
        }
      }
    }
#endif // PLATFORM_WINDOWS
  }

  SSL_CTX_free(ctx);

  printf("\nAll %d tests passed\n", tests);

  return 0;
}

