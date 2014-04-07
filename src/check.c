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

/* Evaluate the threshold configuration */
static int checkThreshold(const struct config_options * const __restrict__);
static int checkThreads(const struct config_options * const __restrict__);

/* Validate options 
   NOTE: This function must be called befor forking!
   Returns 0 on failure. */
int checkConfigOptions(const struct config_options * const __restrict__ co)
{
  /* Warning missed target. */
  if (co->ip.daddr == INADDR_ANY)
  {
    ERROR("Need target address. Try --help for usage");
    return 0;
  }

  /* Sanitizing the CIDR. */
  if ((co->bits < CIDR_MINIMUM) || (co->bits > CIDR_MAXIMUM))
  {
    char errstr[64];

    sprintf(errstr, "CIDR must be between %d and %d", CIDR_MINIMUM, CIDR_MAXIMUM);
    ERROR(errstr);
    return 0;
  }

  /* Sanitizing the TCP Options SACK_Permitted and SACK Edges. */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_SACK_OK) &&
      TEST_BITS(co->tcp.options, TCP_OPTION_SACK_EDGE))
  {
    ERROR("TCP options SACK-Permitted and SACK Edges are not allowed");
    return 0;
  }

  /* Sanitizing the TCP Options T/TCP CC and T/TCP CC.ECHO. */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_CC) && (co->tcp.cc_echo))
  {
    ERROR("TCP options T/TCP CC and T/TCP CC.ECHO are not allowed");
    return 0;
  }

  if (!checkThreshold(co))
    return 0;

  if (!checkThreads(co))
    return 0;

  if (co->flood)
  {
    /* Warning FLOOD mode. */
    puts("Entering in flood mode...");

    /* Warning CIDR mode. */
    if (co->bits != 0)
      puts("Performing DDoS...");

    puts("Hit CTRL+C to break.");
  }

  /* Returning. */
  return 1;
}

static int checkThreshold(const struct config_options * const __restrict__ co)
{
  if (co->ip.protocol == IPPROTO_T50)
  {
    threshold_t minThreshold = (threshold_t)getNumberOfRegisteredModules();

    if (co->threshold < minThreshold)
    {
      fprintf(stderr,
              "%s: protocol %s cannot have threshold smaller than %d\n",
              PACKAGE,
              mod_table[co->ip.protoname].acronym,
              minThreshold);
      return 0;
    }
  }
  else
  {
    if (co->threshold < 1)
    {
      fprintf(stderr,
              "%s: protocol %s cannot have threshold smaller than 1\n",
              PACKAGE,
              mod_table[co->ip.protoname].acronym);
      return 0;
    }
  }

  return 1;
}

static int checkThreads(const struct config_options * const __restrict__ co)
{
  long num_processors;

  if (co->threads > co->threshold)
  {
    ERROR("Number of threads cannot be greater than the threshold.");
    return 0;
  }

  if (co->threads > MAX_THREADS)
  {
    char msg[144];

    sprintf(msg, "Number of threads cannot be greater than %d.\n", MAX_THREADS);
    ERROR(msg);
    return 0;
  }

  num_processors = sysconf( _SC_NPROCESSORS_ONLN );
  if (num_processors > 0)
    if (co->threads > num_processors)
      fprintf(stderr, "WARNING: Number of threads is greater than number of processors online.\n");

  return 1;
}

