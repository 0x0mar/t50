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

#define RIPVERSION 1

#include <common.h>

/* Function Name: RIPv1 packet header configuration.

Description:   This function configures and sends the RIPv1 packet header.

Targets:       N/A */
int ripv1(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,   /* GRE options size. */
         packet_size,
         offset;

  mptr_t buffer;

  /* Socket address, IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip;

  /* UDP header and PSEUDO header. */
  struct udphdr * udp;
  struct psdhdr * pseudo;

  assert(o != NULL);

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  packet_size = sizeof(struct iphdr)  + 
                greoptlen             + 
                sizeof(struct udphdr) + 
                rip_hdr_len(0);

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  /* GRE Encapsulation takes place. */
  gre_ip = gre_encapsulation(packet, o,
        sizeof(struct iphdr) + 
        sizeof(struct udphdr)      + 
        rip_hdr_len(0));

  /* UDP Header structure making a pointer to IP Header structure. */
  udp         = (struct udphdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  udp->source = htons(IPPORT_RIP); 
  udp->dest   = htons(IPPORT_RIP);
  udp->len    = htons(sizeof(struct udphdr) + rip_hdr_len(0));
  udp->check  = 0;

  offset = sizeof(struct udphdr);

  buffer.ptr = (void *)udp + offset;

  /*
   * Routing Information Protocol (RIP) (RFC 1058)
   *
   * 3.1 Message formats
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | command (1)   | version (1)   |      must be zero (2)         |
   *   +---------------+---------------+-------------------------------+
   *   | address family identifier (2) |      must be zero (2)         |
   *   +-------------------------------+-------------------------------+
   *   |                         IP address (4)                        |
   *   +---------------------------------------------------------------+
   *   |                        must be zero (4)                       |
   *   +---------------------------------------------------------------+
   *   |                        must be zero (4)                       |
   *   +---------------------------------------------------------------+
   *   |                          metric (4)                           |
   *   +---------------------------------------------------------------+
   */
  *buffer.byte_ptr++ = o->rip.command;
  *buffer.byte_ptr++ = RIPVERSION;
  *buffer.word_ptr++ = FIELD_MUST_BE_ZERO;

  *buffer.word_ptr++ = htons(__RND(o->rip.family));
  *buffer.word_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = INADDR_RND(o->rip.address);
  *buffer.inaddr_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = htonl(__RND(o->rip.metric));

  offset += RIP_HEADER_LENGTH + RIP_MESSAGE_LENGTH;

  /* PSEUDO Header structure making a pointer to Checksum. */
  pseudo           = (struct psdhdr *)buffer.ptr;
  pseudo->saddr    = o->encapsulated ? gre_ip->saddr : ip->saddr;
  pseudo->daddr    = o->encapsulated ? gre_ip->daddr : ip->daddr;
  pseudo->zero     = 0;
  pseudo->protocol = o->ip.protocol;
  pseudo->len      = htons(offset);

  offset += sizeof(struct psdhdr);

  /* Computing the checksum. */
  udp->check  = o->bogus_csum ? 
                random() : 
                cksum((uint16_t *)udp, offset);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}
