/*
 * dowall.c	Write to all users on the system.
 *
 * Author:	Miquel van Smoorenburg, miquels@cistron.nl
 * 
 * Version:	@(#)dowall.c  2.85-5  02-Jul-2003  miquels@cistron.nl
 *
 *		This file is part of the sysvinit suite,
 *		Copyright (C) 1991-2003 Miquel van Smoorenburg.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <utmp.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <paths.h>

#ifndef _PATH_DEV
# define _PATH_DEV	"/dev/"
#endif
#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX	255
#endif

static sigjmp_buf jbuf;

/*
 *	Alarm handler
 */
/*ARGSUSED*/
# ifdef __GNUC__
static void handler(int arg __attribute__((unused)))
# else
static void handler(int arg)
# endif
{
	siglongjmp(jbuf, 1);
}


/*
 *	Print a text, escape all characters not in Latin-1.
 */
static void feputs(const char *line, FILE *fp)
{
	unsigned char		*p;

	for (p = (unsigned char *)line; *p; p++) {
		if (strchr("\t\r\n", *p) ||
		    (*p >= 32 && *p <= 127) || (*p >= 160)) {
			fputc(*p, fp);
		} else {
			fprintf(fp, "^%c", (*p & 0x1f) + 'A' - 1);
		}
	}
	fflush(fp);
}


static void getuidtty(char **userp, char **ttyp)
{
	struct passwd 		*pwd;
	uid_t			uid;
	char			*tty;
	static char		uidbuf[32];
	static char		ttynm[UT_LINESIZE + 4];
	static int		init = 0;

	if (!init) {

		uid = getuid();
		if ((pwd = getpwuid(uid)) != NULL) {
			uidbuf[0] = 0;
			strncat(uidbuf, pwd->pw_name, sizeof(uidbuf) - 1);
		} else {
			sprintf(uidbuf, uid ? "uid %d" : "root", (int)uid);
		}

		if ((tty = ttyname(0)) != NULL) {
			const size_t plen = strlen(_PATH_DEV);
			if (strncmp(tty, _PATH_DEV, plen) == 0) {
				tty += plen;
				if (tty[0] == '/')
					tty++;
			}
			snprintf(ttynm, sizeof(ttynm), "(%.*s) ",
				 UT_LINESIZE, tty);
		} else
			ttynm[0] = 0;
		init++;
	}

	*userp = uidbuf;
	*ttyp  = ttynm;
}

/*
 *	Check whether given filename looks like tty device.
 */
static int file_isatty(const char *fname)
{
	struct stat		st;
	int			major;

	if (stat(fname, &st) < 0)
		return 0;

	if (st.st_nlink != 1 || !S_ISCHR(st.st_mode))
		return 0;

	/*
	 *	It would be an impossible task to list all major/minors
	 *	of tty devices here, so we just exclude the obvious
	 *	majors of which just opening has side-effects:
	 *	printers and tapes.
	 */
	major = major(st.st_dev);
	if (major == 1 || major == 2 || major == 6 || major == 9 ||
	    major == 12 || major == 16 || major == 21 || major == 27 ||
	    major == 37 || major == 96 || major == 97 || major == 206 ||
	    major == 230) return 0;

	return 1;
}

/*
 *	Wall function.
 */
void wall(const char *text, int remote)
{
	FILE			*tp;
	struct sigaction	sa;
	struct utmp		*utmp;
	time_t			t;
	char			term[UT_LINESIZE+ strlen(_PATH_DEV) + 1];
	char			line[81];
	char			hostname[HOST_NAME_MAX+1];
	char			*date, *p;
	char			*user, *tty;
	int			fd, flags;

	/*
	 *	Make sure tp and fd aren't in a register. Some versions
	 *	of gcc clobber those after longjmp (or so I understand).
	 */
	(void) &tp;
	(void) &fd;

	getuidtty(&user, &tty);

	/* Get and report current hostname, to make it easier to find
	   out which machine is being shut down. */
	if (0 != gethostname(hostname, sizeof(hostname))) {
		strncpy(hostname, "[unknown]", sizeof(hostname)-1);
	}
	/* If hostname is truncated, it is unspecified if the string
	   is null terminated or not.  Make sure we know it is null
	   terminated. */
	hostname[sizeof(hostname)-1] = 0;

	/* Get the time */
	time(&t);
	date = ctime(&t);
	for(p = date; *p && *p != '\n'; p++)
		;
	*p = 0;
	
	if (remote) {
		snprintf(line, sizeof(line),
			"\007\r\nRemote broadcast message (%s):\r\n\r\n",
			date);
	} else {
		snprintf(line, sizeof(line),
			"\007\r\nBroadcast message from %s@%s %s(%s):\r\n\r\n",
			user, hostname, tty, date);
	}

	/*
	 *	Fork to avoid us hanging in a write()
	 */
	if (fork() != 0)
		return;
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);

	setutent();

	while ((utmp = getutent()) != NULL) {
		if(utmp->ut_type != USER_PROCESS ||
		   utmp->ut_user[0] == 0) continue;
		if (strncmp(utmp->ut_line, _PATH_DEV, strlen(_PATH_DEV)) == 0) {
			term[0] = 0;
			strncat(term, utmp->ut_line, sizeof(term)-1);
		} else
			snprintf(term, sizeof(term), _PATH_DEV "%.*s",
				UT_LINESIZE, utmp->ut_line);
		if (strstr(term, "/../")) continue;

		fd = -1;
		tp = NULL;

		/*
		 *	Open it non-delay
		 */
		if (sigsetjmp(jbuf, 1) == 0) {
			alarm(2);
			flags = O_WRONLY|O_NDELAY|O_NOCTTY;
			if (file_isatty(term) &&
			    (fd = open(term, flags)) >= 0) {
				if (isatty(fd) &&
				    (tp = fdopen(fd, "w")) != NULL) {
					fputs(line, tp);
					feputs(text, tp);
					fflush(tp);
				}
			}
		}
		alarm(0);
		if (fd >= 0) close(fd);
		if (tp != NULL) fclose(tp);
	}
	endutent();

	exit(0);
}

