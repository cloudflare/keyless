// kssl_log.c: logging support functions
//
// Copyright (c) 2013 CloudFlare, Inc.

#include <stdio.h>
#include <stdarg.h>

#include "kssl_log.h"

int silent = 0;

// write_log: call to print an error message to STDERR.
void write_log(const char *fmt, ...)
{
  va_list l;
  if (silent) {
    return;
  }
  va_start(l, fmt);
  vfprintf(stderr, fmt, l);
  va_end(l);
  fprintf(stderr, "\n");
}

