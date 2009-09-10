/*
 * oldutmp.h	Definition of the old libc5 utmp structure.
 *
 * Version:	@(#)oldutmp.h  1.00  29-Mar-1998  miquels@cistron.nl
 *
 * Copyright (C) 1991-2000 Miquel van Smoorenburg.
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
#ifndef OLD_UTMP_H
#define OLD_UTMP_H

#define OLD_LINESIZE		12
#define OLD_NAMESIZE		8
#define OLD_HOSTSIZE		16

struct oldutmp {
	short	ut_type;
	int	ut_pid;
	char	ut_line[OLD_LINESIZE];
	char	ut_id[4];
	long	ut_oldtime;
	char	ut_user[OLD_NAMESIZE];
	char	ut_host[OLD_HOSTSIZE];
	long	ut_oldaddr;
};

#endif
