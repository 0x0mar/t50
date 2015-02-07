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

/* "private" variable holding the number of modules. Use getNumberOfRegisteredModules() funcion to get it. */
static size_t numOfModules = 0;

/* NOTE: This routine shouldn't be inlined due to its compliexity. */
/* FIXME: Maybe we can mark this function __attribute__((inline))? */
unsigned __RND(unsigned value)
{
#ifndef __HAVE_RDRAND__
  struct random_data rndState;
#endif

  if (value == 0)
#ifdef __HAVE_RDRAND__
    value = readrand();
#else
    random_r(&rndState, (int *)&value);
#endif
  return value;
}

/* FIXME: Maybe we can mark this function __attribute__((inline))? */
uint32_t NETMASK_RND(uint32_t foo)
{
  if (foo == INADDR_ANY)
    foo = ~(0xffffffffUL >> (8 + (__RND(0) % 23)));

  return htonl(foo);
}

/* NOTE: Since VLAs are "dirty" allocations on stack frame, it's not a problem to use
   the technique below. 

   The function will reallocate memory only if the buffer isn't big enough to acomodate
   new_packet_size bytes. */
void alloc_packet(worker_data_t *data)
{
  void *p;

  if (data->upktsize > data->tpktsize)
  {
    /* NOTE: GNU Libc documentation says malloc(), calloc() and realloc()
             are thread safe! */
    if ((p = realloc(data->pktbuffer, data->upktsize)) == NULL)
    {
      ERROR("Error reallocating packet buffer");
      exit(EXIT_FAILURE);
    }

    data->pktbuffer = p;
    data->tpktsize = data->upktsize;
  }
}

/* Scan the list of modules (ONCE!), returning the number of itens in the list. */
/* Function prototype moved to modules.h. */
/* NOTE: This function is here to not polute modules.c, where we keep only the modules definitions. */
size_t getNumberOfRegisteredModules(void)
{
	modules_table_t *ptbl;

  /* scan just once in a lifetime. */
  if (numOfModules == 0)
	  for (ptbl = mod_table; ptbl->func != NULL; ptbl++, numOfModules++);

	return numOfModules;
}

#ifdef __HAVE_RDRAND__
uint32_t readrand(void)
{
  uint32_t d;

  __asm__ __volatile__ (
    "1:\n"
    "rdrand %0\n"
    "jnc 1b" : "=r" (d)
  );

  return d;
}
#endif
