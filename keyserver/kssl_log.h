// kssl_log.h: logging support functions
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_LOG
#define INCLUDED_KSSL_LOG 1

extern int silent;

// Call to print an error message to log.
void write_log(const char *fmt, ...);

#endif // INCLUDED_KSSL_LOG
