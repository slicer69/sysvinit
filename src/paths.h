/*
 * paths.h	Paths of files that init and related utilities need.
 *
 * Version:	@(#) paths.h 2.85-8 05-Nov-2003
 *
 * Author:	Miquel van Smoorenburg, <miquels@cistron.nl>
 *
 *		This file is part of the sysvinit suite,
 *		Copyright (C) 1991-2001 Miquel van Smoorenburg.
 *
 *		This program is free software; you can redistribute it and/or modify
 *		it under the terms of the GNU General Public License as published by
 *		the Free Software Foundation; either version 2 of the License, or
 *		(at your option) any later version.
 *
 *		This program is distributed in the hope that it will be useful,
 *		but WITHOUT ANY WARRANTY; without even the implied warranty of
 *		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *		GNU General Public License for more details.
 *
 *		You should have received a copy of the GNU General Public License
 *		along with this program; if not, write to the Free Software
 *		Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#define VT_MASTER	"/dev/tty0"		/* Virtual console master */
#define CONSOLE		"/dev/console"		/* Logical system console */
#define SECURETTY	"/etc/securetty"	/* List of root terminals */
#define SDALLOW		"/etc/shutdown.allow"	/* Users allowed to shutdown */
#define INITTAB		"/etc/inittab"		/* Location of inittab */
#define INIT		"/sbin/init"		/* Location of init itself. */
#define NOLOGIN		"/etc/nologin"		/* Stop user logging in. */
#define FASTBOOT	"/fastboot"		/* Enable fast boot. */
#define FORCEFSCK	"/forcefsck"		/* Force fsck on boot */
#define SDPID		"/var/run/shutdown.pid"	/* PID of shutdown program */
#define SHELL		"/bin/sh"		/* Default shell */
#define SULOGIN		"/sbin/sulogin"		/* Sulogin */
#define INITSCRIPT	"/etc/initscript"	/* Initscript. */
#define PWRSTAT		"/etc/powerstatus"	/* COMPAT: SIGPWR reason (OK/BAD) */

#if 0
#define INITLVL		"/etc/initrunlvl"	/* COMPAT: New runlevel */
#define INITLVL2	"/var/log/initrunlvl"	/* COMPAT: New runlevel */
				/* Note: INITLVL2 definition needs INITLVL */
#define HALTSCRIPT1	"/etc/init.d/halt"	/* Called by "fast" shutdown */
#define HALTSCRIPT2	"/etc/rc.d/rc.0"	/* Called by "fast" shutdown */
#define REBOOTSCRIPT1	"/etc/init.d/reboot"	/* Ditto. */
#define REBOOTSCRIPT2	"/etc/rc.d/rc.6"	/* Ditto. */
#endif

