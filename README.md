CloudFlare Keyless SSL
==========================================================

This repository contains a reference implementation of CloudFlare's keyless SSL server.

## Protocol

The CloudFlare Keyless SSL client communicates to the server via a
binary protocol over a mutually authenticated TLS tunnel.  Messages
are in binary format and identified by a unique ID.

Messages consist of a fixed length header, and a variable length body.
The body of the message consists of a sequence of items in TLV (tag,
length, value) messages.

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

![Image](https://raw.githubusercontent.com/cloudflare/keyless/master/docs/keyless_exchange_diagram.png)

## Key Management

The Keyless SSL server is a TLS server and therefore requires
cryptographic keys. All requests are mutually authenticated, so both
the client and the server need a TLS 1.2 compatible key pair.

The server will need a valid key and certificate pair in PEM format.
The following options are required and take a path to these files:

     --server-cert 
     --server-key

The private keys that this server is able to use should be stored in
PEM format in a directory denoted by the option:

    --private-key-directory

In order to authenticate the client'certificate, a custom CA file is
required.  This CA file available is provided by CloudFlare and provided with:

    --ca-file

# Deploying 

## Installing

### Source

### Packages

## Running

### Commandline Arguments

This is the keyserver for Keyless SSL. It consists of a single binary file 'kssl_server' that has the following command-line options:

- `--port` (optional) The TCP port on which to listen for connections. These connections must be TLSv1.2. Defaults to 2407.
- `--ip` (optional) The IP address of the interface to bind to. If missing binds to all available interfaces.
- `--ca-file` Path to a PEM-encoded file containing the CA certificate used to sign client certificates presented on connection.
- `--server-cert`
- `--server-key` Path to PEM-encoded files containing the certificate and private key that are used when a connection is made to the server. These must be signed by an authority that the client side recognizes (e.g. the same CA as --ca-file).
- `--cipher-list` An OpenSSL list of ciphers that the TLS server will accept for connections. e.g. ECDHE-RSA-AES128-SHA256:RC4:HIGH:!MD5
- `--private-key-directory` Path to a directory containing private keys which the keyserver provides decoding service against. The key files must end with ".key" and be PEM-encoded. There should be no trailing / on  the path.
- `--silent` Prevents keyserver from producing any log output. Fatal start up errors are sent to stderr.
`--verbose` Enables verbose logging. When enabled access log data is sent to the logger as well as errors.
`--num-workers` (optional) The number of worker threads to start. Each worker thread will handle a single connection from a KSSL client.  Defaults to 1.
- `--pid-file` (optional) Path to a file into which the PID of the keyserver. This file is only written if the keyserver starts successfully.

The following options are not available on Windows systems:

- `--user` (optional) user:group to switch to. Can be in the form user:group or just user (in which case user:user is implied) (root only)
- `--daemon` (optional) Forks and abandons the parent process.
- `--syslog` (optional) Log lines are sent to syslog (instead of stdout or stderr). 

# Developing

## Code Organization

The code is split into several files by function in order to enable
swapping with custom implementations.

    kssl.h              contains the shared constants and structures
    kssl_core.h         APIs for performing the keyless operation
    kssl_helpers.h      APIs for serialization and parsing functions
    kssl_private_key.h  APIs for storing and matching private keys
    kssl_log.h          APIs for writing logs

    kssl_server.c       sample server implementation with openssl and libuv
    kssl_testclient.c   client implementation with openssl

The following files are reference implementations of the APIs above.

    kssl_core.c         implementation of v1.0 policy for keyless operation
    kssl_helpers.c      implementation of v1 serialization and parsing
    kssl_private_key.c  implementation of reading, storage and operations of
                        private keys using openssl
    kssl_log.c          implementation of logging to stderr

## Prerequisites
    
On Debian-based Linuxes:

``` sh
sudo apt-get install gcc
sudo gem install fpm
```

On Centos:

``` sh
sudo yum install gcc
sudo gem install fpm
```

On OS X (homebrew):

``` sh
sudo gem install fpm
```

## Makefile

The Makefile has the following useful targets:

- `make all` - The default target that builds both the keyserver and the testclient
- `make clean` - Deletes the keyserver, testclient and related object files
- `make run` - Runs the keyserver with a configuration suitable for testing (with the testclient)
- `make kill` - Stops the keyserver started by 'make run'
- `make test` - Runs the testclient against the keyserver.
- `make release` - Increment the minor version number and generate and updated RELEASE_NOTES with all changes to keyless since the last time a release was performed.
- `make package` - build and make app package for specific OS. e.g. deb for Debian

## Building

The Keyless SSL server implementation has two external dependencies, OpenSSL and libuv.  These are open source and available for most platforms.  For ease of deployment and consistency these depencecies are statically compiled by default. 

For Unix-based systems, the server and test suite are built with a Makefile.

To build:

    `make`

Result:

    `o/kssl_testclient o/kssl_server`

To test:

    `make test`


# License

