// kssl_log.h: logging support functions
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_LOG
#define INCLUDED_KSSL_LOG 1

#include "kssl_helpers.h"

extern int silent;
extern int verbose;

#if PLATFORM_WINDOWS == 0
extern int use_syslog;
#endif

void write_log(int e, const char *fmt, ...);

#endif // INCLUDED_KSSL_LOG
