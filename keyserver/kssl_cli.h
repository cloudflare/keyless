#include <assert.h>

#if __GNUC__
#include <getopt.h>
#else
struct option
{
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

#define no_argument       0
#define required_argument 1
#define optional_argument 2

int getopt(int, char**, char*);
int getopt_long(int, char**, char*, struct option*, int*);

extern int    opterr;  /* if error message should be printed */
extern int    optind;  /* index into parent argv vector */
extern int    optopt;  /* character checked for validity */
extern int    optreset;  /* reset getopt */
extern char *optarg;  /* argument associated with option */

#define __P(x) x
#define _DIAGASSERT(x) assert(x)

static char * __progname __P((char *));
int getopt_internal __P((int, char * const *, const char *));

static char *
__progname(nargv0)
  char * nargv0;
{
  char * tmp;

  _DIAGASSERT(nargv0 != NULL);

  tmp = strrchr(nargv0, '/');
  if (tmp)
    tmp++;
  else
    tmp = nargv0;
  return(tmp);
}

#define  BADCH  (int)'?'
#define  BADARG  (int)':'
#define  EMSG  ""

/*
 * getopt --
 *  Parse argc/argv argument vector.
 */
int
getopt_internal(nargc, nargv, ostr)
  int nargc;
  char * const *nargv;
  const char *ostr;
{
  static char *place = EMSG;    /* option letter processing */
  char *oli;        /* option letter list index */

  _DIAGASSERT(nargv != NULL);
  _DIAGASSERT(ostr != NULL);

  if (optreset || !*place) {    /* update scanning pointer */
    optreset = 0;
    if (optind >= nargc || *(place = nargv[optind]) != '-') {
      place = EMSG;
      return (-1);
    }
    if (place[1] && *++place == '-') {  /* found "--" */
      /* ++optind; */
      place = EMSG;
      return (-2);
    }
  }          /* option letter okay? */
  if ((optopt = (int)*place++) == (int)':' ||
      !(oli = strchr(ostr, optopt))) {
    /*
     * if the user didn't specify '-' as an option,
     * assume it means -1.
     */
    if (optopt == (int)'-')
      return (-1);
    if (!*place)
      ++optind;
    if (opterr && *ostr != ':')
      (void)fprintf(stderr,
          "%s: illegal option -- %c\n", __progname(nargv[0]), optopt);
    return (BADCH);
  }
  if (*++oli != ':') {      /* don't need argument */
    optarg = NULL;
    if (!*place)
      ++optind;
  } else {        /* need an argument */
    if (*place)      /* no white space */
      optarg = place;
    else if (nargc <= ++optind) {  /* no arg */
      place = EMSG;
      if ((opterr) && (*ostr != ':'))
        (void)fprintf(stderr,
            "%s: option requires an argument -- %c\n",
            __progname(nargv[0]), optopt);
      return (BADARG);
    } else        /* white space */
      optarg = nargv[optind];
    place = EMSG;
    ++optind;
  }
  return (optopt);      /* dump back option letter */
}

/*
 * getopt_long --
 *  Parse argc/argv argument vector.
 */
int
getopt_long(nargc, nargv, options, long_options, index)
  int nargc;
  char ** nargv;
  char * options;
  struct option * long_options;
  int * index;
{
  int retval;

  _DIAGASSERT(nargv != NULL);
  _DIAGASSERT(options != NULL);
  _DIAGASSERT(long_options != NULL);
  /* index may be NULL */

  if ((retval = getopt_internal(nargc, nargv, options)) == -2) {
    char *current_argv = nargv[optind++] + 2, *has_equal;
    int i, current_argv_len, match = -1;

    if (*current_argv == '\0') {
      return(-1);
    }
    if ((has_equal = strchr(current_argv, '=')) != NULL) {
      current_argv_len = has_equal - current_argv;
      has_equal++;
    } else
      current_argv_len = strlen(current_argv);

    for (i = 0; long_options[i].name; i++) {
      if (strncmp(current_argv, long_options[i].name, current_argv_len))
        continue;

      if (strlen(long_options[i].name) == (unsigned)current_argv_len) {
        match = i;
        break;
      }
      if (match == -1)
        match = i;
    }
    if (match != -1) {
      if (long_options[match].has_arg == required_argument ||
          long_options[match].has_arg == optional_argument) {
        if (has_equal)
          optarg = has_equal;
        else
          optarg = nargv[optind++];
      }
      if ((long_options[match].has_arg == required_argument)
          && (optarg == NULL)) {
        /*
         * Missing argument, leading :
         * indicates no error should be generated
         */
        if ((opterr) && (*options != ':'))
          (void)fprintf(stderr,
              "%s: option requires an argument -- %s\n",
              __progname(nargv[0]), current_argv);
        return (BADARG);
      }
    } else { /* No matching argument */
      if ((opterr) && (*options != ':'))
        (void)fprintf(stderr,
            "%s: illegal option -- %s\n", __progname(nargv[0]), current_argv);
      return (BADCH);
    }
    if (long_options[match].flag) {
      *long_options[match].flag = long_options[match].val;
      retval = 0;
    } else
      retval = long_options[match].val;
    if (index)
      *index = match;
  }
  return(retval);
}

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

struct timezone
{
  int  tz_minuteswest; /* minutes W of Greenwich */
  int  tz_dsttime;     /* type of dst correction */
};

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
  FILETIME ft;
  unsigned __int64 tmpres = 0;
  static int tzflag;

  if (NULL != tv)
  {
    GetSystemTimeAsFileTime(&ft);

    tmpres |= ft.dwHighDateTime;
    tmpres <<= 32;
    tmpres |= ft.dwLowDateTime;

    /*converting file time to unix epoch*/
    tmpres -= DELTA_EPOCH_IN_MICROSECS;
    tmpres /= 10;  /*convert into microseconds*/
    tv->tv_sec = (long)(tmpres / 1000000UL);
    tv->tv_usec = (long)(tmpres % 1000000UL);
  }

  if (NULL != tz)
  {
    if (!tzflag)
    {
      _tzset();
      tzflag++;
    }
    tz->tz_minuteswest = _timezone / 60;
    tz->tz_dsttime = _daylight;
  }

  return 0;
}

#endif  /* __GNUC__ */

