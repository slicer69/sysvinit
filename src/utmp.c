/*
 * utmp.c	Routines to read/write the utmp and wtmp files.
 *		Basically just wrappers around the library routines.
 *
 * Version:	@(#)utmp.c  2.77  09-Jun-1999  miquels@cistron.nl
 *
 * Copyright (C) 1999 Miquel van Smoorenburg.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <utmp.h>

#include "init.h"
#include "initreq.h"
#include "paths.h"


#if defined(__GLIBC__)
#  if (__GLIBC__ == 2) && (__GLIBC_MINOR__ == 0) && defined(__powerpc__)
#    define HAVE_UPDWTMP 0
#  else
#    define HAVE_UPDWTMP 1
#  endif
#else
#  define HAVE_UPDWTMP 0
#endif


/*
 *	Log an event in the wtmp file (reboot, runlevel)
 */
void write_wtmp(
char *user,			/* name of user */
char *id,			/* inittab ID */
int pid,			/* PID of process */
int type,			/* TYPE of entry */
char *line)			/* Which line is this */
{
	int fd;
	struct utmp utmp;
	struct utsname uname_buf;
	struct timeval tv;
	
	/*
	 *	Try to open the wtmp file. Note that we even try
	 *	this if we have updwtmp() so we can see if the
	 *	wtmp file is accessible.
	 */
	if ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND)) < 0) return;

#ifdef INIT_MAIN
	/*
	 *	Note if we are going to write a boot record.
	 */
	if (type == BOOT_TIME) wrote_wtmp_reboot++;

	/*
	 *	See if we need to write a reboot record. The reason that
	 *	we are being so paranoid is that when we first tried to
	 *	write the reboot record, /var was possibly not mounted
	 *	yet. As soon as we can open WTMP we write a delayed boot record.
	 */
	if (wrote_wtmp_reboot == 0 && type != BOOT_TIME)
  		write_wtmp("reboot", "~~", 0, BOOT_TIME, "~");
#endif

	/*
	 *	Zero the fields and enter new fields.
	 */
	memset(&utmp, 0, sizeof(utmp));
#if defined(__GLIBC__)
	gettimeofday(&tv, NULL);
	utmp.ut_tv.tv_sec = tv.tv_sec;
	utmp.ut_tv.tv_usec = tv.tv_usec;
#else
	time(&utmp.ut_time);
#endif
	utmp.ut_pid  = pid;
	utmp.ut_type = type;
	strncpy(utmp.ut_name, user, sizeof(utmp.ut_name));
	strncpy(utmp.ut_id  , id  , sizeof(utmp.ut_id  ));
	strncpy(utmp.ut_line, line, sizeof(utmp.ut_line));
        
        /* Put the OS version in place of the hostname */
        if (uname(&uname_buf) == 0)
		strncpy(utmp.ut_host, uname_buf.release, sizeof(utmp.ut_host));

#if HAVE_UPDWTMP
	updwtmp(WTMP_FILE, &utmp);
#else
	write(fd, (char *)&utmp, sizeof(utmp));
#endif
	close(fd);
}

/*
 *	Write an entry to the UTMP file. For DEAD_PROCESS, put
 *	the previous ut_line into oldline if oldline != NULL.
 */
static void write_utmp(
char *user,			/* name of user */
char *id,			/* inittab ID */
int pid,			/* PID of process */
int type,			/* TYPE of entry */
char *line,			/* LINE if used. */
char *oldline)			/* Line of old utmp entry. */
{
	struct utmp utmp;
	struct utmp tmp;
	struct utmp *utmptr;
	struct timeval tv;

	/*
	 *	Can't do much if UTMP_FILE is not present.
	 */
	if (access(UTMP_FILE, F_OK) < 0)
		return;

#ifdef INIT_MAIN
	/*
	 *	Note if we are going to write a boot record.
	 */
	if (type == BOOT_TIME) wrote_utmp_reboot++;

	/*
	 *	See if we need to write a reboot record. The reason that
	 *	we are being so paranoid is that when we first tried to
	 *	write the reboot record, /var was possibly not mounted
	 *	yet. As soon as we can open WTMP we write a delayed boot record.
	 */
	if (wrote_utmp_reboot == 0 && type != BOOT_TIME)
  		write_utmp("reboot", "~~", 0, BOOT_TIME, "~", NULL);
#endif

	/*
	 *	Fill out an utmp struct.
	 */
	memset(&utmp, 0, sizeof(utmp));
	utmp.ut_type = type;
	utmp.ut_pid = pid;
	strncpy(utmp.ut_id, id, sizeof(utmp.ut_id));
#if defined(__GLIBC__)
	gettimeofday(&tv, NULL);
	utmp.ut_tv.tv_sec = tv.tv_sec;
	utmp.ut_tv.tv_usec = tv.tv_usec;
#else
	time(&utmp.ut_time);
#endif
	strncpy(utmp.ut_user, user, UT_NAMESIZE);
	if (line) strncpy(utmp.ut_line, line, UT_LINESIZE);
	
	/*
	 *	We might need to find the existing entry first, to
	 *	find the tty of the process (for wtmp accounting).
	 */
	if (type == DEAD_PROCESS) {
		/*
		 *	Find existing entry for the tty line.
		 */
		setutent();
		tmp = utmp;
		if ((utmptr = getutid(&tmp)) != NULL) {
			strncpy(utmp.ut_line, utmptr->ut_line, UT_LINESIZE);
			if (oldline)
				strncpy(oldline, utmptr->ut_line, UT_LINESIZE);
		}
	}

	/*
	 *	Update existing utmp file.
	 */
	setutent();
	pututline(&utmp);
	endutent();
}

/*
 *	Write a record to both utmp and wtmp.
 */
void write_utmp_wtmp(
char *user,			/* name of user */
char *id,			/* inittab ID */
int pid,			/* PID of process */
int type,			/* TYPE of entry */
char *line)			/* LINE if used. */
{
	char	oldline[UT_LINESIZE];

	/*
	 *	For backwards compatibility we just return
	 *	if user == NULL (means : clean up utmp file).
	 */
	if (user == NULL)
		return;

	oldline[0] = 0;
	write_utmp(user, id, pid, type, line, oldline);
	write_wtmp(user, id, pid, type, line && line[0] ? line : oldline);
}

