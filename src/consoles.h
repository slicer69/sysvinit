/*
 * consoles.h	    Header file for routines to detect the system consoles
 *
 * Copyright (c) 2011 SuSE LINUX Products GmbH, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING); if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * Author: Werner Fink <werner@suse.de>
 */

#include <termios.h>

struct console {
	char * tty;
	int tlock;
	struct termios ltio, otio;
	struct console *next;
};
extern struct console *consoles;
extern void detect_consoles(void);
