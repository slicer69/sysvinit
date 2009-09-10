/*
 * mountpoint	See if a directory is a mountpoint.
 *
 * Author:	Miquel van Smoorenburg.
 *
 * Version:	@(#)mountpoint  2.85-12  17-Mar-2004	 miquels@cistron.nl
 *
 *		This file is part of the sysvinit suite,
 *		Copyright (C) 1991-2004 Miquel van Smoorenburg.
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

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <getopt.h>
#include <stdio.h>

int dostat(char *path, struct stat *st, int do_lstat, int quiet)
{
	int		n;

	if (do_lstat)
		n = lstat(path, st);
	else
		n = stat(path, st);

	if (n != 0) {
		if (!quiet)
			fprintf(stderr, "mountpoint: %s: %s\n", path,
				strerror(errno));
		return -1;
	}
	return 0;
}

void usage(void) {
	fprintf(stderr, "Usage: mountpoint [-q] [-d] [-x] path\n");
	exit(1);
}

int main(int argc, char **argv)
{
	struct stat	st, st2;
	char		buf[256];
	char		*path;
	int		quiet = 0;
	int		showdev = 0;
	int		xdev = 0;
	int		c, r;

	while ((c = getopt(argc, argv, "dqx")) != EOF) switch(c) {
		case 'd':
			showdev = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'x':
			xdev = 1;
			break;
		default:
			usage();
			break;
	}
	if (optind != argc - 1) usage();
	path = argv[optind];

	if (dostat(path, &st, !xdev, quiet) < 0)
		return 1;

	if (xdev) {
#ifdef __linux__
		if (!S_ISBLK(st.st_mode))
#else
		if (!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode))
#endif
		{
			if (quiet)
				printf("\n");
			else
			fprintf(stderr, "mountpoint: %s: not a block device\n",
				path);
			return 1;
		}
		printf("%u:%u\n", major(st.st_rdev), minor(st.st_rdev));
		return 0;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (!quiet)
			fprintf(stderr, "mountpoint: %s: not a directory\n",
				path);
		return 1;
	}

	memset(buf, 0, sizeof(buf));
	strncpy(buf, path, sizeof(buf) - 4);
	strcat(buf, "/..");
	if (dostat(buf, &st2, 0, quiet) < 0)
		return 1;

	r = (st.st_dev != st2.st_dev) ||
	    (st.st_dev == st2.st_dev && st.st_ino == st2.st_ino);

	if (!quiet && !showdev)
		printf("%s is %sa mountpoint\n", path, r ? "" : "not ");
	if (showdev)
		printf("%u:%u\n", major(st.st_dev), minor(st.st_dev));

	return r ? 0 : 1;
}
