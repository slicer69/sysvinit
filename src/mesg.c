/*
 * mesg.c	The "mesg" utility. Gives / restrict access to
 *		your terminal by others.
 *
 * Usage:	mesg [y|n].
 *		Without arguments prints out the current settings.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>

char *Version = "@(#) mesg 2.81 31-Jul-2001 miquels@cistron.nl";

#define TTYGRP		"tty"

/*
 *	See if the system has a special 'tty' group.
 *	If it does, and the tty device is in that group,
 *	we set the modes to -rw--w--- instead if -rw--w--w.
 */
int hasttygrp(void)
{
	struct group *grp;

	if ((grp = getgrnam(TTYGRP)) != NULL)
		return 1;
	return 0;
}


/*
 *	See if the tty devices group is indeed 'tty'
 */
int tty_in_ttygrp(struct stat *st)
{
	struct group *gr;

	if ((gr = getgrgid(st->st_gid)) == NULL)
		return 0;
	if (strcmp(gr->gr_name, TTYGRP) != 0)
		return 0;

	return 1;
}

int main(int argc, char **argv)
{
	struct stat	st;
	unsigned int	ttymode, st_mode_old;
	int		ht;
	int		it;
	int		e;

	if (!isatty(0)) {
		/* Or should we look in /var/run/utmp? */
		fprintf(stderr, "stdin: is not a tty\n");
		return(1);
	}

	if (fstat(0, &st) < 0) {
		perror("fstat");
		return(1);
	}

	ht = hasttygrp();
	it = tty_in_ttygrp(&st);

	if (argc < 2) {
		ttymode = (ht && it) ? 020 : 002;
		printf("is %s\n", (st.st_mode & ttymode) ? "y" : "n");
		return 0;
	}
	if (argc > 2 || (argv[1][0] != 'y' && argv[1][0] != 'n')) {
		fprintf(stderr, "Usage: mesg [y|n]\n");
		return 1;
	}

	/*
	 *	Security check: allow mesg n when group is
	 *	weird, but don't allow mesg y.
	 */
	ttymode = ht ? 020 : 022;
	if (ht && !it && argv[1][0] == 'y') {
		fprintf(stderr, "mesg: error: tty device is not owned "
			"by group `%s'\n", TTYGRP);
		exit(1);
	}

	st_mode_old = st.st_mode;
	if (argv[1][0] == 'y')
		st.st_mode |= ttymode;
	else
		st.st_mode &= ~(ttymode);
	if (st_mode_old != st.st_mode && fchmod(0, st.st_mode) != 0) {
		e = errno;
		fprintf(stderr, "mesg: %s: %s\n",
			ttyname(0), strerror(e));
		exit(1);
	}

	return 0;
}
