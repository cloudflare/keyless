CloudFlare Keyless SSL
==========================================================

This repository contains a reference implementation of CloudFlare's keyless
SSL server.

## Protocol

The CloudFlare Keyless SSL client communicates to the server via a binary
protocol over a mutually authenticated TLS 1.2 tunnel.  Messages are in binary
format and identified by a unique ID.

Messages consist of a fixed length header, and a variable length body.  The
body of the message consists of a sequence of items in TLV (tag, length,
value) messages.

All messages with major version 1 will conform to the following
format.  The minor version is currently set to 0 and is reserved for
communicating policy information.

Header:

    0 - - 1 - - 2 - - 3 - - 4 - - - - 6 - - 7 - - 8
    | Maj | Min |   Length  |          ID           |
    |                    Body                       |
    |     Body     | <- 8 + Length

Item:

    0 - - 1 - - 2 - - 3 - - 4 - - - - 6 - - 7 - - 8
    | Tag |   Length  |          Data               |
    |           Data             | <- 3 + Length

All numbers are in network byte order (big endian).

The following tag values are possible for items:

    0x01 - Certificate Digest,
    0x02 - Server Name Indication,
    0x03 - Client's IP address,
    0x11 - Opcode,
    0x12 - Payload,

A requests contains a header and the following items:

    0x01 - length: 32 bytes, data: SHA256 of RSA modulus
    0x02 - length: variable, data: SNI string
    0x03 - length: 4 or 16 bytes, data: IPv4/6 address
    0x11 - length: 1, data: opcode describing operation
    0x12 - length: variable, data: payload to sign or encrypt

The following opcodes are supported in the opcode item:

    0x01 - operation: RSA decrypt payload 
    0x02 - operation: RSA sign MD5SHA1
    0x03 - operation: RSA sign SHA1
    0x04 - operation: RSA sign SHA224
    0x05 - operation: RSA sign SHA256
    0x06 - operation: RSA sign SHA384
    0x07 - operation: RSA sign SHA512

Responses contain a header with a matching ID and only two items:

    0x11 - length: 1, data: opcode describing operation status
    0x12 - length: variable, data: payload response

The following opcodes are supported in the opcode item:

    0xF0 - operation: success, payload: modified payload
    0xFF - operation: RSA decrypt payload, payload: 

On an error, these are the possible 1-byte payloads:

    0x01 - cryptography failure
    0x02 - key not found - no matching certificate ID
    0x03 - read error - disk read failure
    0x04 - version mismatch - unsupported version incorrect
    0x05 - bad opcode - use of unknown opcode in request
    0x06 - unexpected opcode - use of response opcode in request
    0x07 - format error - malformed message
    0x08 - internal error - memory or other internal error

Defines and further details of the protocol can be found in [kssl.h](kssl.h)

![Image](docs/keyless_exchange_diagram.png)

## Key Management

The Keyless SSL server is a TLS server and therefore requires cryptographic
keys. All requests are mutually authenticated, so both the client and the
server need a TLS 1.2 compatible key pair. The client must present a client
certificate that can be verified against the CA that the keyless server is
configured to use.

The server will need a valid key and certificate pair in PEM format.  The
following options are required and take a path to these files. These two
parameters set up the certificate (and associated private key) that will be
presented by the server when a client connects.

     --server-cert 
     --server-key

The private keys that this server is able to use should be stored in
PEM format in a directory denoted by the option:

    --private-key-directory

In order to authenticate the client's certificate, a custom CA file is
required.  This CA file available is provided by CloudFlare and specified
with:

    --ca-file

# Deploying 

## Installing

### Source

Use Git to get the latest development version from our repository:

    git clone https://github.com/cloudflare/keyless.git
    cd keyless
    make && make install

Alternatively you can just 
[download](https://github.com/cloudflare/keyless/archive/master.tar.gz) the
bleeding edge code directly.

### Packages


## Running

A typical invocation of `keyless` might look like:

    keyless --port=2412 --server-cert=server-cert/cert.pem \
            --server-key=server-cert/key.pem               \
            --private-key-directory=keys                   \
            --ca-file=CA/cacert.pem                        \
            --pid-file=keyless.pid                         \
            --num-workers=4 --daemon --silent              \
            --user nobody:nobody

That runs the `keyless` server as a daemon process (and outputs the 
parent PID in `keyless.pid`) after changing to the user `nobody` in
group `nobody`.

It sets up four workers (threads) which will process connections from
CloudFlare handling cryptographic requests using the private keys from
a directory called `keys`.

### Command-line Arguments

This is the keyserver for Keyless SSL. It consists of a single binary file
'kssl_server' that has the following command-line options:

- `--port` (optional) The TCP port on which to listen for connections. These
  connections must be TLSv1.2. Defaults to 2407.
- `--ip` (optional) The IP address of the interface to bind to. If missing
  binds to all available interfaces.
- `--ca-file` Path to a PEM-encoded file containing the CA certificate used to
  sign client certificates presented on connection.
- `--server-cert`, `--server-key` Path to PEM-encoded files containing the
  certificate and private key that are used when a connection is made to the
  server. These must be signed by an authority that the client side recognizes
  (e.g. the same CA as --ca-file).
- `--cipher-list` An OpenSSL list of ciphers that the TLS server will accept
  for connections. e.g. ECDHE-RSA-AES128-SHA256:RC4:HIGH:!MD5
- `--private-key-directory` Path to a directory containing private keys which
  the keyserver provides decoding service against. The key files must end with
  ".key" and be PEM-encoded. There should be no trailing / on the path.
- `--silent` Prevents keyserver from producing any log output. Fatal start up
  errors are sent to stderr.
- `--verbose` Enables verbose logging. When enabled access log data is sent to
  the logger as well as errors.
- `--num-workers` (optional) The number of worker threads to start. Each
  worker thread will handle a single connection from a KSSL client.  Defaults
  to 1.
- `--pid-file` (optional) Path to a file into which the PID of the
  keyserver. This file is only written if the keyserver starts successfully.
- `--test` (optional) Run through program start up and check that the keyless
  server is correctly configured. Returns 0 if good, 1 if an error.

The following options are not available on Windows systems:

- `--user` (optional) user and group to switch to. Can be in the form
  `user:group` or just `user` (in which case `user:user` is implied) (root
  only)
- `--daemon` (optional) Forks and abandons the parent process.
- `--syslog` (optional) Log lines are sent to syslog (instead of stdout or
  stderr).

# Developing

## Code Organization

The code is split into several files by function in order to enable
swapping with custom implementations.

    kssl.h              contains the shared constants and structures
    kssl_core.h         APIs for performing the keyless operation
    kssl_helpers.h      APIs for serialization and parsing functions
    kssl_private_key.h  APIs for storing and matching private keys
    kssl_log.h          APIs for writing logs

    keyless.c           Sample server implementation with OpenSSL and libuv
    testclient.c        Client implementation with OpenSSL

The following files are reference implementations of the APIs above.

    kssl_core.c         Implementation of v1.0 policy for keyless operation
    kssl_helpers.c      Implementation of v1.0 serialization and parsing
    kssl_private_key.c  Implementation of reading, storage and operations of
                        private keys using OpenSSL
    kssl_log.c          Implementation of logging

## Prerequisites
    
On Debian-based Linuxes:

    sudo apt-get install gcc automake libtool
    sudo apt-get install rubygems # only required for packages
    sudo gem install fpm --no-ri --no-rdoc # only required for packages

On Centos:

    sudo yum install gcc automake libtool
    sudo yum install rpm-build rubybgems ruby-devel # only required for packages
    sudo gem install fpm --no-ri --no-rdoc # only required for packages

On OS X (homebrew):

    sudo gem install fpm

## Makefile

The Makefile has the following useful targets:

- `all` - The default target that builds both the keyless server and the
 testclient
- `clean` - Deletes the keyless server, testclient and related object files
- `install` - Install the keyless server
- `run` - Runs the keyless server with a configuration suitable for testing
 (with the testclient)
- `kill` - Stops the keyless server started by 'make run'
- `test` - Runs the testclient against the keyless server
- `release` - Increment the minor version number and generate an updated
  RELEASE_NOTES with all changes to keyless since the last time a release was
  performed.
- `package` - build and make app package for specific OS. e.g. deb for Debian

## Building

The Keyless SSL server implementation has two external dependencies,
[OpenSSL](https://www.openssl.org/) and
[libuv](https://github.com/joyent/libuv).  These are open source and available
for most platforms.  For ease of deployment and consistency these dependencies
are statically compiled by default.

For Unix-based systems, the server and test suite are built with a GNU make
makefile.

To build:

    make

This will create the files `o/testclient`, `o/keyless` after downloading and
building OpenSSL and libuv.

To test:

    make test

This runs the `testclient` against the `keyless` server using test
certificates and keys provided in the repository.

There is also a short version of the test suite that can be used to test that
the keyless server works (at all!):

    make test-short

# License

See the LICENSE file for details

