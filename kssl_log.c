// kssl_log.c: logging support functions
//
// Copyright (c) 2013 CloudFlare, Inc.

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "kssl_log.h"

#if PLATFORM_WINDOWS == 0
#include <syslog.h>
#endif

int silent = 0;
int verbose = 0;

#if PLATFORM_WINDOWS == 0
int use_syslog = 0;
#endif

// write_log: call to log a message. If syslog is not enabled then error
// message are written to STDERR, other messages are written to STDOUT.  If
// syslog is enabled then error messages are sent with LOG_ERR, other messages
// with LOG_INFO. syslog messages are sent with the LOG_USER facility.
void write_log(int e,                // If set this is an error message
               const char *fmt, ...) // printf style
{
  // Note the use of [] here. When syslogging, syslog will strip them off and
  // create a message using that as the name of the program.

  char * name = "[kssl_server] ";
  char * newfmt;
  va_list l;

#if PLATFORM_WINDOWS == 0
  if (silent && !use_syslog) {
	  return;
  }
#endif
  if (!e && !verbose) {
	  return;
  }


  // +1 for the terminating 0
  // +1 for the \n we append in non-syslog mode

  newfmt = (char *)malloc(strlen(fmt)+1+strlen(name)+1);
  strcpy(newfmt, name);
  strcat(newfmt, fmt);

  va_start(l, fmt);

  // Note the syntax abuse below. Be careful to look at the dandling 
  // } else

#if PLATFORM_WINDOWS == 0
  if (use_syslog) {
    vsyslog(LOG_USER | (e?LOG_ERR:LOG_INFO), newfmt, l);
  } else
#endif
  {
    strcat(newfmt, "\n");
    vfprintf(e?stderr:stdout, newfmt, l);
  }

  va_end(l);
  free(newfmt);
}
