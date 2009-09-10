/*
 * reboot.h	Headerfile that defines how to handle
 *		the reboot() system call.
 *
 * Version:	@(#)reboot.h  2.85-17  04-Jun-2004  miquels@cistron.nl
 *
 * Copyright (C) (C) 1991-2004 Miquel van Smoorenburg.
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
 */

#include <sys/reboot.h>

#ifdef RB_ENABLE_CAD
#  define BMAGIC_HARD		RB_ENABLE_CAD
#endif

#ifdef RB_DISABLE_CAD
#  define BMAGIC_SOFT		RB_DISABLE_CAD
#endif

#ifdef RB_HALT_SYSTEM
#  define BMAGIC_HALT		RB_HALT_SYSTEM
#else
#  define BMAGIC_HALT		RB_HALT
#endif

#define BMAGIC_REBOOT		RB_AUTOBOOT

#ifdef RB_POWER_OFF
#  define BMAGIC_POWEROFF	RB_POWER_OFF
#elif defined(RB_POWEROFF)
#  define BMAGIC_POWEROFF	RB_POWEROFF
#else
#  define BMAGIC_POWEROFF	BMAGIC_HALT
#endif

#define init_reboot(magic)	reboot(magic)

