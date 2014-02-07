/*
 * ifdown.c	Find all network interfaces on the system and
 *		shut them down.
 *
 * Copyright (C) 1998 Miquel van Smoorenburg.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
char *v_ifdown = "@(#)ifdown.c  1.11  02-Jun-1998  miquels@cistron.nl";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>

#define MAX_IFS	64

/* XXX: Ideally this would get detected at configure time... */
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || defined(__OpenBSD__)
#define HAVE_SOCKADDR_SA_LEN 1
#endif

#ifndef _SIZEOF_ADDR_IFREQ
#ifdef HAVE_SOCKADDR_SA_LEN
#define _SIZEOF_ADDR_IFREQ(ifr) \
	((ifr).ifr_addr.sa_len > sizeof(struct sockaddr) ? \
	 (sizeof((ifr).ifr_name) + (ifr).ifr_addr.sa_len) : \
	  sizeof(struct ifreq))
#else
#define _SIZEOF_ADDR_IFREQ(ifr) sizeof(struct ifreq)
#endif
#endif

/*
 *	First, we find all shaper devices and down them. Then we
 *	down all real interfaces. This is because the comment in the
 *	shaper driver says "if you down the shaper device before the
 *	attached inerface your computer will follow".
 */
int ifdown(void)
{
	char ifr_buf[sizeof(struct ifreq) * MAX_IFS];
	char *ifr_end;
	struct ifconf ifc;
	int fd;
	int shaper;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "ifdown: ");
		perror("socket");
		return -1;
	}
	ifc.ifc_len = sizeof(ifr_buf);
	ifc.ifc_buf = ifr_buf;

	if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
		fprintf(stderr, "ifdown: ");
		perror("SIOCGIFCONF");
		close(fd);
		return -1;
	}
	ifr_end = ifr_buf + ifc.ifc_len;

	for (shaper = 1; shaper >= 0; shaper--) {
		char *ifr_next = ifr_buf;

		while (ifr_next < ifr_end) {
			struct ifreq *ifr;
			int flags;

			ifr = (struct ifreq *)ifr_next;
			ifr_next += _SIZEOF_ADDR_IFREQ(*ifr);

			if ((strncmp(ifr->ifr_name, "shaper", 6) == 0)
			    != shaper) continue;

			if (strncmp(ifr->ifr_name, "lo", 2) == 0)
				continue;
			if (strchr(ifr->ifr_name, ':') != NULL)
				continue;

			/* Read interface flags */
			if (ioctl(fd, SIOCGIFFLAGS, ifr) < 0) {
				fprintf(stderr, "ifdown: shutdown ");
				perror(ifr->ifr_name);
				continue;
			}
			/*
			 * Expected in <net/if.h> according to
			 * "UNIX Network Programming".
			 */
#ifdef ifr_flagshigh
			flags = (ifr->ifr_flags & 0xffff) |
			        (ifr->ifr_flagshigh << 16);
#else
			flags = ifr->ifr_flags;
#endif
			if (flags & IFF_UP) {
				flags &= ~(IFF_UP);
#ifdef ifr_flagshigh
				ifr->ifr_flags = flags & 0xffff;
				ifr->ifr_flagshigh = flags >> 16;
#else
				ifr->ifr_flags = flags;
#endif
				if (ioctl(fd, SIOCSIFFLAGS, ifr) < 0) {
					fprintf(stderr, "ifdown: shutdown ");
					perror(ifr->ifr_name);
				}
			}
		}
	}
	close(fd);

	return 0;
}
