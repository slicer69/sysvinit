/* fstab-decode(8).

Copyright (c) 2006 Red Hat, Inc. All rights reserved.

This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU General
Public License v.2.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110-1301, USA.

Author: Miloslav Trmac <mitr@redhat.com> */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Decode the fstab-encoded string in place. */
static void
decode(char *s)
{
	const char *src;
	char *dest;

	src = s;
	dest = s;
	while (*src != '\0') {
		if (*src != '\\')
			*dest = *src++;
		else {
			static const struct repl {
				char orig[4];
				size_t len;
				char new;
			} repls[] = {
#define R(X, Y) { X, sizeof(X) - 1, Y }
				R("\\", '\\'),
				R("011", '\t'),
				R("012", '\n'),
				R("040", ' '),
				R("134", '\\')
#undef R
			};

			size_t i;

			for (i = 0; i < sizeof (repls) / sizeof (repls[0]);
			     i++) {
				if (memcmp(src + 1, repls[i].orig,
					   repls[i].len) == 0) {
					*dest = repls[i].new;
					src += 1 + repls[i].len;
					goto found;
				}
			}
			*dest = *src++;
		found:
			;
		}
		dest++;
	}
	*dest = '\0';
}

int
main (int argc, char *argv[])
{
	size_t i;

	if (argc < 2) {
		fprintf(stderr, "Usage: fstab-decode command [arguments]\n");
		return EXIT_FAILURE;
	}
	for (i = 2; i < (size_t)argc; i++)
		decode(argv[i]);
	execvp(argv[1], argv + 1);
	fprintf(stderr, "fstab-decode: %s: %s\n", argv[1], strerror(errno));
	return 127;
}
