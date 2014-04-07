/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2014 - T50 developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <common.h>
#include <sys/wait.h> /* POSIX.1 compliant */

static void initialize(void);
static const char *getOrdinalSuffix(unsigned);
static const char *getMonth(unsigned);

/* Main function launches all T50 modules */
int main(int argc, char *argv[])
{
  struct config_options *co;  /* Pointer to options. */
  struct cidr *cidr_ptr;      /* Pointer to cidr host id and 1st ip address. */

  time_t lt;
  struct tm *tm;

  initialize();

  /* Configuring command line interface options. */
  co = getConfigOptions(argc, argv);

  /* This is a requirement of t50. User must be root to use it. 
     Previously on checkConfigOptions(). */
  if (getuid())
  {
    ERROR("User must have root priviledge to run.");
    return EXIT_FAILURE;
  }

  /* Validating command line interface options. */
  if (!checkConfigOptions(co))
    return EXIT_FAILURE;

  /* Setup random seed using current date/time timestamp. */
  /* NOTE: Random seed don't need to be so precise! */
  srandom(time(NULL));

  /* Calculates CIDR for destination address. */
  cidr_ptr = config_cidr(co->bits, co->ip.daddr);

  /* Setting socket file descriptor. */
  /* NOTE: createSocket() handles its own errors before returning. */
  createSocket();

  /* Show launch info. */
  lt = time(NULL); 
  tm = localtime(&lt);

  printf("\b\n%s %s successfully launched on %s %2d%s %d %.02d:%.02d:%.02d\n",
    PACKAGE,  
    VERSION, 
    getMonth(tm->tm_mon), 
    tm->tm_mday, 
    getOrdinalSuffix(tm->tm_mday),
    (tm->tm_year + 1900), 
    tm->tm_hour, 
    tm->tm_min, 
    tm->tm_sec);

  createWorkers(co, cidr_ptr);
  waitForWorkers();

  closeSocket();

  lt = time(NULL); 
  tm = localtime(&lt);

  printf("\b\n%s %s successfully finished on %s %2d%s %d %.02d:%.02d:%.02d\n",
    PACKAGE,
    VERSION,
    getMonth(tm->tm_mon),
    tm->tm_mday,
    getOrdinalSuffix(tm->tm_mday),
    (tm->tm_year + 1900),
    tm->tm_hour,
    tm->tm_min,
    tm->tm_sec);
}

/* This function handles interruptions. */
static void signal_handler(int signal)
{
  closeSocket();

  /* FIX: The shell documentation (bash) specifies that a process
          when exits because a signal, must return 128+signal#. */
  exit(128 + signal);
}

static void initialize(void)
{
  /* NOTE: See 'man 2 signal' */
  struct sigaction sa;

  /* --- Initialize signal handlers --- */

  /* Using sig*() functions for compability. */
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; /* same signal() semantics?! */

  /* Trap all "interrupt" signals, except SIGKILL, SIGSTOP and SIGSEGV (uncatchable, accordingly to 'man 7 signal'). */
  sa.sa_handler = signal_handler;
  sigaction(SIGHUP,  &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
  sigaction(SIGINT,  &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGTSTP, &sa, NULL);

  /* --- Make sure stdout is unbuffered (otherwise, it's line buffered). --- */
  fflush(stdout);
  setvbuf(stdout, NULL, _IONBF, 0); 
}

/* Auxiliary function to return the [constant] ordinary suffix string for a number. */
static const char *getOrdinalSuffix(unsigned n)
{
  static const char *suffixes[] = { "st", "nd", "rd", "th" };

  /* FIX: 11, 12 & 13 have 'th' suffix, not 'st, nd or rd'. */
  if ((n < 11) || (n > 13))
    switch (n % 10) {
      case 1: return suffixes[0];
      case 2: return suffixes[1];
      case 3: return suffixes[2];
    }

  return suffixes[3];
}

static const char *getMonth(unsigned n)
{
  /* Months */
  static const char * const months[] =
    { "Jan", "Feb", "Mar", "Apr", "May",  "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov",  "Dec" };

  if (n > 11)
    return "";

  return months[n];
}
