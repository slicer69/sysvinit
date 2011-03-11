/*
 * consoles.c	    Routines to detect the system consoles
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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "consoles.h"

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
# ifndef  typeof
#  define typeof		__typeof__
# endif
# ifndef  restrict
#  define restrict		__restrict__
# endif
#endif

#define alignof(type)		((sizeof(type)+(sizeof(void*)-1)) & ~(sizeof(void*)-1))

struct console *consoles;

static dev_t comparedev;
static char* scandev(DIR *dir)
{
	char *name = (char*)0;
	struct dirent *dent;
	int fd;

	fd = dirfd(dir);
	rewinddir(dir);
	while ((dent = readdir(dir))) {
		char path[PATH_MAX];
		struct stat st;
		if (fstatat(fd, dent->d_name, &st, 0) < 0)
			continue;
		if (!S_ISCHR(st.st_mode))
			continue;
		if (comparedev != st.st_rdev)
			continue;
		if ((size_t)snprintf(path, sizeof(path), "/dev/%s", dent->d_name) >= sizeof(path))
			continue;
		name = realpath(path, NULL);
		break;
	}
	return name;
}

void detect_consoles(void)
{
	FILE *fc;
	if ((fc = fopen("/proc/consoles", "r"))) {
		char fbuf[16];
		int maj, min;
		DIR *dir;
		dir = opendir("/dev");
		if (!dir)
			goto out;
		while ((fscanf(fc, "%*s %*s (%[^)]) %d:%d", &fbuf[0], &maj, &min) == 3)) {
			struct console *restrict tail;
			char * name;

			if (!strchr(fbuf, 'E'))
				continue;
			comparedev = makedev(maj, min);
			name = scandev(dir);

			if (!name)
				continue;

			if (posix_memalign((void*)&tail, sizeof(void*), alignof(typeof(struct console))) != 0)
				perror("memory allocation");

			tail->next = (struct console*)0;
			tail->tty = name;

			if (!consoles)
				consoles = tail;
			else
				consoles->next = tail;
		}
		closedir(dir);
out:
		fclose(fc);
	}
}
