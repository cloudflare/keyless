// kssl_getopt.h: header for kssl_getopt.c
//
// Copyright (c) 2014 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_CLI
#define INCLUDED_KSSL_CLI 1

#include "kssl.h"

#if __GNUC__
#include <getopt.h>
#else // __GNUC__

// On other platforms use the code in kssl_getopt.c

#endif // __GNUC__

#endif // INCLUDED_KSSL_CLI
