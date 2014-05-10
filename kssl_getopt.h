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

#define GNU_COMPATIBLE		/* Be more compatible, configure's use us! */

struct option
{
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

extern int	opterr;	      	/* if error message should be printed */
extern int	optind;   		/* index into parent argv vector */
extern int	optopt;		    /* character checked for validity */
extern int	optreset;		/* reset getopt */
extern char *optarg;		/* argument associated with option */

int getopt(int, char**, char*);
int getopt_long(int, char**, char*, struct option*, int*);


#endif // __GNUC__

#endif // INCLUDED_KSSL_CLI
