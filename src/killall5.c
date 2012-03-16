/*
 * kilall5.c	Kill all processes except processes that have the
 *		same session id, so that the shell that called us
 *		won't be killed. Typically used in shutdown scripts.
 *
 * pidof.c	Tries to get the pid of the process[es] named.
 *
 * Version:	2.86 30-Jul-2004 MvS
 *
 * Usage:	killall5 [-][signal]
 *		pidof [-s] [-o omitpid [-o omitpid]] program [program..]
 *
 * Authors:	Miquel van Smoorenburg, miquels@cistron.nl
 *
 *		Riku Meskanen, <mesrik@jyu.fi>
 *		- return all running pids of given program name
 *		- single shot '-s' option for backwards combatibility
 *		- omit pid '-o' option and %PPID (parent pid metavariable)
 *		- syslog() only if not a connected to controlling terminal
 *		- swapped out programs pids are caught now
 *
 *		Werner Fink
 *		- make omit dynamic
 *		- provide '-n' to skip stat(2) syscall on network based FS
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
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <mntent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

char *Version = "@(#)killall5 2.86 31-Jul-2004 miquels@cistron.nl";

#ifndef PATH_MAX
#  ifdef MAXPATHLEN
#    define PATH_MAX MAXPATHLEN
#  else
#    define PATH_MAX 2048
#  endif
#endif

#define STATNAMELEN	15
#define DO_NETFS 2
#define DO_STAT 1
#define NO_STAT 0

/* Info about a process. */
typedef struct proc {
	char *pathname;		/* full path to executable        */
	char *argv0;		/* Name as found out from argv[0] */
	char *argv0base;	/* `basename argv[1]`		  */
	char *argv1;		/* Name as found out from argv[1] */
	char *argv1base;	/* `basename argv[1]`		  */
	char *statname;		/* the statname without braces    */
	ino_t ino;		/* Inode number			  */
	dev_t dev;		/* Device it is on		  */
	pid_t pid;		/* Process ID.			  */
	pid_t sid;		/* Session ID.			  */
	char kernel;		/* Kernel thread or zombie.	  */
	char nfs;		/* Name found on network FS.	  */
	struct proc *next;	/* Pointer to next struct. 	  */
} PROC;

/* pid queue */

typedef struct pidq {
	PROC		*proc;
	struct pidq	*next;
} PIDQ;

typedef struct {
	PIDQ		*head;
	PIDQ		*tail;
	PIDQ		*next;
} PIDQ_HEAD;

typedef struct _s_omit {
	struct _s_omit *next;
	struct _s_omit *prev;
	pid_t pid;
} OMIT;

typedef struct _s_shadow
{
	struct _s_shadow *next;
	struct _s_shadow *prev;
	size_t nlen;
	char * name;
} SHADOW;

typedef struct _s_nfs
{
	struct _s_nfs *next;	/* Pointer to next struct. */
	struct _s_nfs *prev;	/* Pointer to previous st. */
	SHADOW *shadow;		/* Pointer to shadows      */
	size_t nlen;
	char * name;
} NFS;

/* List of processes. */
PROC *plist;

/* List of processes to omit. */
OMIT *omit;

/* List of NFS mountes partitions. */
NFS *nlist;

/* Did we stop all processes ? */
int sent_sigstop;

int scripts_too = 0;

char *progname;	/* the name of the running program */
#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
#endif
void nsyslog(int pri, char *fmt, ...);

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
# ifndef  inline
#  define inline	__inline__
# endif
# ifndef  restrict
#  define restrict	__restrict__
# endif
#endif
#define alignof(type)	((sizeof(type)+(sizeof(void*)-1)) & ~(sizeof(void*)-1))

/*
 *	Malloc space, barf if out of memory.
 */
#ifdef __GNUC__
static void *xmalloc(size_t) __attribute__ ((__malloc__));
#endif
static void *xmalloc(size_t bytes)
{
	void *p;

	if ((p = malloc(bytes)) == NULL) {
		if (sent_sigstop) kill(-1, SIGCONT);
		nsyslog(LOG_ERR, "out of memory");
		exit(1);
	}
	return p;
}

#ifdef __GNUC__
static inline void xmemalign(void **, size_t, size_t) __attribute__ ((__nonnull__ (1)));
#endif
static inline void xmemalign(void **memptr, size_t alignment, size_t size)
{
	if ((posix_memalign(memptr, alignment, size)) < 0) {
		if (sent_sigstop) kill(-1, SIGCONT);
		nsyslog(LOG_ERR, "out of memory");
		exit(1);
	}
}

/*
 *	See if the proc filesystem is there. Mount if needed.
 */
int mount_proc(void)
{
	struct stat	st;
	char		*args[] = { "mount", "-t", "proc", "proc", "/proc", 0 };
	pid_t		pid, rc;
	int		wst;
	int		did_mount = 0;

	/* Stat /proc/version to see if /proc is mounted. */
	if (stat("/proc/version", &st) < 0 && errno == ENOENT) {

		/* It's not there, so mount it. */
		if ((pid = fork()) < 0) {
			nsyslog(LOG_ERR, "cannot fork");
			exit(1);
		}
		if (pid == 0) {
			/* Try a few mount binaries. */
			execv("/bin/mount", args);
			execv("/sbin/mount", args);

			/* Okay, I give up. */
			nsyslog(LOG_ERR, "cannot execute mount");
			exit(1);
		}
		/* Wait for child. */
		while ((rc = wait(&wst)) != pid)
			if (rc < 0 && errno == ECHILD)
				break;
		if (rc != pid || WEXITSTATUS(wst) != 0)
			nsyslog(LOG_ERR, "mount returned non-zero exit status");

		did_mount = 1;
	}

	/* See if mount succeeded. */
	if (stat("/proc/version", &st) < 0) {
		if (errno == ENOENT)
			nsyslog(LOG_ERR, "/proc not mounted, failed to mount.");
		else
			nsyslog(LOG_ERR, "/proc unavailable.");
		exit(1);
	}

	return did_mount;
}

static inline int isnetfs(const char * type)
{
	static const char* netfs[] = {"nfs", "nfs4", "smbfs", "cifs", "afs", "ncpfs", (char*)0};
	int n;
	for (n = 0; netfs[n]; n++) {
		if (!strcasecmp(netfs[n], type))
			return 1;
	}
	return 0;
}

/*
 *     Remember all NFS typed partitions.
 */
void init_nfs(void)
{
        struct stat st;
        struct mntent * ent;
	FILE * mnt;

	nlist = (NFS*)0;

	if (stat("/proc/version", &st) < 0)
		return;
	if ((mnt = setmntent("/proc/mounts", "r")) == (FILE*)0)
		return;

	while ((ent = getmntent(mnt))) {
		if (isnetfs(ent->mnt_type)) {
			size_t nlen = strlen(ent->mnt_dir);
			NFS *restrict p;
			xmemalign((void*)&p, sizeof(void*), alignof(NFS)+(nlen+1));
			p->name = ((char*)p)+alignof(NFS);
			p->nlen = nlen;
			p->shadow = (SHADOW*)0;

			strcpy(p->name, ent->mnt_dir);
			if (nlist)
				nlist->prev = p;
			p->next = nlist;
			p->prev = (NFS*)0;
			nlist = p;
		}
	}
	endmntent(mnt);

	if ((mnt = setmntent("/proc/mounts", "r")) == (FILE*)0)
		return;

	while ((ent = getmntent(mnt))) {
		NFS *p;

		for (p = nlist; p; p = p->next) {
			SHADOW * restrict s;
			size_t nlen;

			if (strcmp(ent->mnt_dir, p->name) == 0)
				continue;
			if (strncmp(ent->mnt_dir, p->name, p->nlen) != 0)
				continue;

			nlen = strlen(ent->mnt_dir);
			xmemalign((void*)&s, sizeof(void*), alignof(SHADOW)+(nlen+1));
			s->name = ((char*)s)+alignof(SHADOW);
			s->nlen = nlen;

			strcpy(s->name, ent->mnt_dir);
			if (p->shadow)
			    p->shadow->prev = s;
			s->next = p->shadow;
			s->prev = (SHADOW*)0;
			p->shadow = s;
		}
	}
	endmntent(mnt);
}

static void clear_shadow(SHADOW *restrict shadow)
{
	SHADOW *s, *n, *l;

	n = shadow;
	l = (SHADOW*)0;
	for (s = shadow; n; s = n) {
		l = s->prev;
		n = s->next;
		if (s == shadow) {
			if (n) n->prev = (SHADOW*)0;
			shadow = n;
		} else if (l) {
			if (n) n->prev = l;
			l->next = n;
		}
		free(s);
	}
}

static void clear_mnt(void)
{
	NFS *p, *n, *l;

	n = nlist;
	l = (NFS*)0;
	for (p = nlist; n; p = n) {
		l = p->prev;
		n = p->next;
		if (p == nlist) {
			if (n) n->prev = (NFS*)0;
			nlist = n;
		} else if (l) {
			if (n) n->prev = l;
			l->next = n;
		}
		if (p->shadow)
			clear_shadow(p->shadow);
		free(p);
	}
}

/*
 *     Check if path is a shadow off a NFS partition.
 */
static int shadow(SHADOW *restrict this, const char *restrict name, const size_t nlen)
{
	SHADOW *s;

	if (!this)
		goto out;
	for (s = this; s; s = s->next) {
		if (nlen < s->nlen)
			continue;
		if (name[s->nlen] != '\0' && name[s->nlen] != '/')
			continue;
		if (strncmp(name, s->name, s->nlen) == 0)
			return 1;
	}
out:
	return 0;
}

/*
 *     Check path is located on a network based partition.
 */
int check4nfs(const char * path, char * real)
{
	char buf[PATH_MAX+1];
	const char *curr;
	int deep = MAXSYMLINKS;

	if (!nlist) return 0;

	curr = path;
	do {
		const char *prev;
		int len;

		if ((prev = strdupa(curr)) == NULL) {
			nsyslog(LOG_ERR, "strdupa(): %s\n", strerror(errno));
			return 0;
		}

		errno = 0;
		if ((len = readlink(curr, buf, PATH_MAX)) < 0)
			break;
		buf[len] = '\0';

		if (buf[0] != '/') {
			const char *slash;

			if ((slash = strrchr(prev, '/'))) {
				size_t off = slash - prev + 1;

				if (off + len > PATH_MAX)
					len = PATH_MAX - off;

				memmove(&buf[off], &buf[0], len + 1);
				memcpy(&buf[0], prev, off);
			}
		}
		curr = &buf[0];

		if (deep-- <= 0) return 0;

	} while (1);

	if (real) strcpy(real, curr);

	if (errno == EINVAL) {
		const size_t nlen = strlen(curr);
		NFS *p;
		for (p = nlist; p; p = p->next) {
			if (nlen < p->nlen)
				continue;
			if (curr[p->nlen] != '\0' && curr[p->nlen] != '/')
				continue;
			if (!strncmp(curr, p->name, p->nlen)) {
				if (shadow(p->shadow, curr, nlen))
					continue;
				return 1;
			}
		}
	}

	return 0;
}

int readarg(FILE *fp, char *buf, int sz)
{
	int		c = 0, f = 0;

	while (f < (sz-1) && (c = fgetc(fp)) != EOF && c)
		buf[f++] = c;
	buf[f] = 0;

	return (c == EOF && f == 0) ? c : f;
}

/*
 *	Read the proc filesystem.
 *	CWD must be /proc to avoid problems if / is affected by the killing (ie depend on fuse).
 */
int readproc(int do_stat)
{
	DIR		*dir;
	FILE		*fp;
	PROC		*p, *n;
	struct dirent	*d;
	struct stat	st;
	char		path[PATH_MAX+1];
	char		buf[PATH_MAX+1];
	char		*s, *q;
	unsigned long	startcode, endcode;
	int		pid, f;
	ssize_t		len;

	/* Open the /proc directory. */
	if (chdir("/proc") == -1) {
		nsyslog(LOG_ERR, "chdir /proc failed");
		return -1;
	}
	if ((dir = opendir(".")) == NULL) {
		nsyslog(LOG_ERR, "cannot opendir(/proc)");
		return -1;
	}

	/* Free the already existing process list. */
	n = plist;
	for (p = plist; n; p = n) {
		n = p->next;
		if (p->argv0) free(p->argv0);
		if (p->argv1) free(p->argv1);
		if (p->statname) free(p->statname);
		free(p->pathname);
		free(p);
	}
	plist = NULL;

	/* Walk through the directory. */
	while ((d = readdir(dir)) != NULL) {

		/* See if this is a process */
		if ((pid = atoi(d->d_name)) == 0) continue;

		/* Get a PROC struct . */
		p = (PROC *)xmalloc(sizeof(PROC));
		memset(p, 0, sizeof(PROC));

		/* Open the status file. */
		snprintf(path, sizeof(path), "%s/stat", d->d_name);

		/* Read SID & statname from it. */
		if ((fp = fopen(path, "r")) != NULL) {
			if (!fgets(buf, sizeof(buf), fp))
				buf[0] = '\0';

			if (buf[0] == '\0') {
				nsyslog(LOG_ERR,
					"can't read from %s\n", path);
				fclose(fp);
				free(p);
				continue;
			}

			/* See if name starts with '(' */
			s = buf;
			while (*s && *s != ' ') s++;
			if (*s) s++;
			if (*s == '(') {
				/* Read program name. */
				q = strrchr(buf, ')');
				if (q == NULL) {
					p->sid = 0;
					nsyslog(LOG_ERR,
					"can't get program name from /proc/%s\n",
						path);
					fclose(fp);
					if (p->argv0) free(p->argv0);
					if (p->argv1) free(p->argv1);
					if (p->statname) free(p->statname);
					free(p->pathname);
					free(p);
					continue;
				}
				s++;
			} else {
				q = s;
				while (*q && *q != ' ') q++;
			}
			if (*q) *q++ = 0;
			while (*q == ' ') q++;
			p->statname = (char *)xmalloc(strlen(s)+1);
			strcpy(p->statname, s);

			/* Get session, startcode, endcode. */
			startcode = endcode = 0;
			if (sscanf(q, 	"%*c %*d %*d %d %*d %*d %*u %*u "
					"%*u %*u %*u %*u %*u %*d %*d "
					"%*d %*d %*d %*d %*u %*u %*d "
					"%*u %lu %lu",
					&p->sid, &startcode, &endcode) != 3) {
				p->sid = 0;
				nsyslog(LOG_ERR, "can't read sid from %s\n",
					path);
				fclose(fp);
				if (p->argv0) free(p->argv0);
				if (p->argv1) free(p->argv1);
				if (p->statname) free(p->statname);
				free(p->pathname);
				free(p);
				continue;
			}
			if (startcode == 0 && endcode == 0)
				p->kernel = 1;
			fclose(fp);
		} else {
			/* Process disappeared.. */
			if (p->argv0) free(p->argv0);
			if (p->argv1) free(p->argv1);
			if (p->statname) free(p->statname);
			free(p->pathname);
			free(p);
			continue;
		}

		snprintf(path, sizeof(path), "%s/cmdline", d->d_name);
		if ((fp = fopen(path, "r")) != NULL) {

			/* Now read argv[0] */
			f = readarg(fp, buf, sizeof(buf));

			if (buf[0]) {
				/* Store the name into malloced memory. */
				p->argv0 = (char *)xmalloc(f + 1);
				strcpy(p->argv0, buf);

				/* Get a pointer to the basename. */
				p->argv0base = strrchr(p->argv0, '/');
				if (p->argv0base != NULL)
					p->argv0base++;
				else
					p->argv0base = p->argv0;
			}

			/* And read argv[1] */
			while ((f = readarg(fp, buf, sizeof(buf))) != EOF)
				if (buf[0] != '-') break;

			if (buf[0]) {
				/* Store the name into malloced memory. */
				p->argv1 = (char *)xmalloc(f + 1);
				strcpy(p->argv1, buf);

				/* Get a pointer to the basename. */
				p->argv1base = strrchr(p->argv1, '/');
				if (p->argv1base != NULL)
					p->argv1base++;
				else
					p->argv1base = p->argv1;
			}

			fclose(fp);

		} else {
			/* Process disappeared.. */
			if (p->argv0) free(p->argv0);
			if (p->argv1) free(p->argv1);
			if (p->statname) free(p->statname);
			free(p->pathname);
			free(p);
			continue;
		}

		/* Try to stat the executable. */
		snprintf(path, sizeof(path), "/proc/%s/exe", d->d_name);

		p->nfs = 0;

		switch (do_stat) {
		case DO_NETFS:
			if ((p->nfs = check4nfs(path, buf)))
				goto link;
		case DO_STAT:
			if (stat(path, &st) != 0) {
				char * ptr;

				len = readlink(path, buf, PATH_MAX);
				if (len <= 0)
					break;
				buf[len] = '\0';

				ptr = strstr(buf, " (deleted)");
				if (!ptr)
					break;
				*ptr = '\0';
				len -= strlen(" (deleted)");

				if (stat(buf, &st) != 0)
					break;
				p->dev = st.st_dev;
				p->ino = st.st_ino;
				p->pathname = (char *)xmalloc(len + 1);
				memcpy(p->pathname, buf, len);
				p->pathname[len] = '\0';

				/* All done */
				break;
			}

			p->dev = st.st_dev;
			p->ino = st.st_ino;

			/* Fall through */
		default:
		link:
			len = readlink(path, buf, PATH_MAX);
			if (len > 0) {
				p->pathname = (char *)xmalloc(len + 1);
				memcpy(p->pathname, buf, len);
				p->pathname[len] = '\0';
			}
			break;
		}

		/* Link it into the list. */
		p->next = plist;
		plist = p;
		p->pid = pid;
	}
	closedir(dir);

	/* Done. */
	return 0;
}

PIDQ_HEAD *init_pid_q(PIDQ_HEAD *q)
{
	q->head =  q->next = q->tail = NULL;
	return q;
}

int empty_q(PIDQ_HEAD *q)
{
	return (q->head == NULL);
}

int add_pid_to_q(PIDQ_HEAD *q, PROC *p)
{
	PIDQ *tmp;

	tmp = (PIDQ *)xmalloc(sizeof(PIDQ));

	tmp->proc = p;
	tmp->next = NULL;

	if (empty_q(q)) {
		q->head = tmp;
		q->tail  = tmp;
	} else {
		q->tail->next = tmp;
		q->tail = tmp;
	}
	return 0;
}

PROC *get_next_from_pid_q(PIDQ_HEAD *q)
{
	PROC		*p;
	PIDQ		*tmp = q->head;

	if (!empty_q(q)) {
		p = q->head->proc;
		q->head = tmp->next;
		free(tmp);
		return p;
	}

	return NULL;
}

/* Try to get the process ID of a given process. */
PIDQ_HEAD *pidof(char *prog)
{
	PROC		*p;
	PIDQ_HEAD	*q;
	struct stat	st;
	char		*s;
	int		nfs = 0;
	int		dostat = 0;
	int		foundone = 0;
	int		ok = 0;
	const int	root = (getuid() == 0);
	char		real[PATH_MAX+1];

	if (! prog)
		return NULL;

	/* Try to stat the executable. */
	if (prog[0] == '/') {
		memset(&real[0], 0, sizeof(real));

		if (check4nfs(prog, real))
			nfs++;

		if (real[0] != '\0')
			prog = &real[0];	/* Binary located on network FS. */

		if ((nfs == 0) && (stat(prog, &st) == 0))
			dostat++;		/* Binary located on a local FS. */
	}

	/* Get basename of program. */
	if ((s = strrchr(prog, '/')) == NULL)
		s = prog;
	else
		s++;

	if (! *s)
		return NULL;

	q = (PIDQ_HEAD *)xmalloc(sizeof(PIDQ_HEAD));
	q = init_pid_q(q);

	/* First try to find a match based on dev/ino pair. */
	if (dostat && !nfs) {
		for (p = plist; p; p = p->next) {
			if (p->nfs)
				continue;
			if (p->dev == st.st_dev && p->ino == st.st_ino) {
				add_pid_to_q(q, p);
				foundone++;
			}
		}
	}

	/* Second try to find a match based on full path name on
	 * network FS located binaries */
	if (!foundone && nfs) {
		for (p = plist; p; p = p->next) {
			if (!p->pathname)
				continue;
			if (!p->nfs)
				continue;
			if (strcmp(prog, p->pathname) != 0)
				continue;
			add_pid_to_q(q, p);
			foundone++;
		}
	}

	/* If we didn't find a match based on dev/ino, try the name. */
	if (!foundone) for (p = plist; p; p = p->next) {
		if (prog[0] == '/') {
			if (!p->pathname) {
				if (root)
					continue;
				goto fallback; 
			}
			if (strcmp(prog, p->pathname)) {
				int len = strlen(prog);
				if (strncmp(prog, p->pathname, len))
				{
					if (scripts_too)
						goto fallback;
					continue;
				}
				if (strcmp(" (deleted)", p->pathname + len))
				{
					if (scripts_too)
						goto fallback;
					continue;
				}
			}
			add_pid_to_q(q, p);
			continue;
		}

	fallback:
		ok = 0;

		/*             matching        nonmatching
		 * proc name   prog name       prog name
		 * ---         -----------     ------------
		 *   b         b, p/b, q/b
		 * p/b         b, p/b          q/b
		 *
		 * Algorithm: Match if:
		 *    cmd = arg
		 * or cmd = base(arg)
		 * or base(cmd) = arg
		 *
		 * Specifically, do not match just because base(cmd) = base(arg)
		 * as was done in earlier versions of this program, since this
		 * allows /aaa/foo to match /bbb/foo .
		 */
		ok |=
			(p->argv0 && strcmp(p->argv0, prog) == 0)
			|| (p->argv0 && s != prog && strcmp(p->argv0, s) == 0)
			|| (p->argv0base && strcmp(p->argv0base, prog) == 0);

		/* For scripts, compare argv[1] as well. */
		if (
			scripts_too && p->statname && p->argv1base
			&& !strncmp(p->statname, p->argv1base, STATNAMELEN)
		) {
			ok |=
				(p->argv1 && strcmp(p->argv1, prog) == 0)
				|| (p->argv1 && s != prog && strcmp(p->argv1, s) == 0)
				|| (p->argv1base && strcmp(p->argv1base, prog) == 0);
		}

		/*
		 *	if we have a space in argv0, process probably
		 *	used setproctitle so try statname.
		 */
		if (strlen(s) <= STATNAMELEN &&
		    (p->argv0 == NULL ||
		     p->argv0[0] == 0 ||
		     strchr(p->argv0, ' '))) {
			ok |= (strcmp(p->statname, s) == 0);
		}

		/*
		 *	if we have a `-' as the first character, process
		 *	probably used as a login shell
		 */
		if (strlen(s) <= STATNAMELEN &&
		    p->argv1 == NULL &&
		    (p->argv0 != NULL &&
		     p->argv0[0] == '-')) {
			ok |= (strcmp(p->statname, s) == 0);
		}

		if (ok) add_pid_to_q(q, p);
	}

	return q;
}

/* Give usage message and exit. */
void usage(void)
{
	nsyslog(LOG_ERR, "only one argument, a signal number, allowed");
	closelog();
	exit(1);
}

/* write to syslog file if not open terminal */
#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
#endif
void nsyslog(int pri, char *fmt, ...)
{
	va_list  args;

	va_start(args, fmt);

	if (ttyname(0) == NULL) {
		vsyslog(pri, fmt, args);
	} else {
		fprintf(stderr, "%s: ",progname);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
	}

	va_end(args);
}

#define PIDOF_SINGLE	0x01
#define PIDOF_OMIT	0x02
#define PIDOF_NETFS	0x04

/*
 *	Pidof functionality.
 */
int main_pidof(int argc, char **argv)
{
	PIDQ_HEAD	*q;
	PROC		*p;
	char		*token, *here;
	int		f;
	int		first = 1;
	int		opt, flags = 0;
	int		chroot_check = 0;
	struct stat	st;
	char		tmp[512];

	omit = (OMIT*)0;
	nlist = (NFS*)0;
	opterr = 0;

	if ((token = getenv("PIDOF_NETFS")) && (strcmp(token,"no") != 0))
		flags |= PIDOF_NETFS;

	while ((opt = getopt(argc,argv,"hco:sxn")) != EOF) switch (opt) {
		case '?':
			nsyslog(LOG_ERR,"invalid options on command line!\n");
			closelog();
			exit(1);
		case 'c':
			if (geteuid() == 0) chroot_check = 1;
			break;
		case 'o':
			here = optarg;
			while ((token = strsep(&here, ",;:"))) {
				OMIT *restrict optr;
				pid_t opid;

				if (strcmp("%PPID", token) == 0)
					opid = getppid();
				else
					opid = (pid_t)atoi(token);

				if (opid < 1) {
					nsyslog(LOG_ERR,
						"illegal omit pid value "
						"(%s)!\n", token);
					continue;
				}
				xmemalign((void*)&optr, sizeof(void*), alignof(OMIT));
				optr->next = omit;
				optr->prev = (OMIT*)0;
				optr->pid  = opid;
				omit = optr;
			}
			flags |= PIDOF_OMIT;
			break;
		case 's':
			flags |= PIDOF_SINGLE;
			break;
		case 'x':
			scripts_too++;
			break;
		case 'n':
			flags |= PIDOF_NETFS;
			break;
		default:
			/* Nothing */
			break;
	}
	argc -= optind;
	argv += optind;

	/* Check if we are in a chroot */
	if (chroot_check) {
		snprintf(tmp, 512, "/proc/%d/root", getpid());
		if (stat(tmp, &st) < 0) {
			nsyslog(LOG_ERR, "stat failed for %s!\n", tmp);
			closelog();
			exit(1);
		}
	}

	if (flags & PIDOF_NETFS)
		init_nfs();		/* Which network based FS are online? */

	/* Print out process-ID's one by one. */
	readproc((flags & PIDOF_NETFS) ? DO_NETFS : DO_STAT);

	for(f = 0; f < argc; f++) {
		if ((q = pidof(argv[f])) != NULL) {
			pid_t spid = 0;
			while ((p = get_next_from_pid_q(q))) {
				if ((flags & PIDOF_OMIT) && omit) {
					OMIT * optr;
					for (optr = omit; optr; optr = optr->next) {
						if (optr->pid == p->pid)
							break;
					}

					/*
					 *	On a match, continue with
					 *	the for loop above.
					 */
					if (optr)
						continue;
				}
				if (flags & PIDOF_SINGLE) {
					if (spid)
						continue;
					else
						spid = 1;
				}
				if (chroot_check) {
					struct stat st2;
					snprintf(tmp, 512, "/proc/%d/root",
						 p->pid);
					if (stat(tmp, &st2) < 0 ||
					    st.st_dev != st2.st_dev ||
					    st.st_ino != st2.st_ino) {
						continue;
					}
				}
				if (!first)
					printf(" ");
				printf("%d", p->pid);
				first = 0;
			}
		}
	}
	if (!first)
		printf("\n");

	clear_mnt();

	closelog();
	return(first ? 1 : 0);
}

/* Main for either killall or pidof. */
int main(int argc, char **argv)
{
	PROC		*p;
	int		pid, sid = -1;
	int		sig = SIGKILL;
	int		c;

	/* return non-zero if no process was killed */
	int		retval = 2;

	/* Get program name. */
	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	/* Now connect to syslog. */
	openlog(progname, LOG_CONS|LOG_PID, LOG_DAEMON);

	/* Were we called as 'pidof' ? */
	if (strcmp(progname, "pidof") == 0)
		return main_pidof(argc, argv);

	/* Right, so we are "killall". */
	omit = (OMIT*)0;

	if (argc > 1) {
		for (c = 1; c < argc; c++) {
			if (argv[c][0] == '-') (argv[c])++;
			if (argv[c][0] == 'o') {
				char * token, * here;

				if (++c >= argc)
					usage();

				here = argv[c];
				while ((token = strsep(&here, ",;:"))) {
					OMIT *restrict optr;
					pid_t opid = (pid_t)atoi(token);

					if (opid < 1) {
						nsyslog(LOG_ERR,
							"illegal omit pid value "
							"(%s)!\n", token);
						continue;
					}
					xmemalign((void*)&optr, sizeof(void*), alignof(OMIT));
					optr->next = omit;
					optr->prev = (OMIT*)0;
					optr->pid  = opid;
					omit = optr;
				}
			}
			else if ((sig = atoi(argv[1])) <= 0 || sig > 31)
				usage();
		}
	}

	/* First get the /proc filesystem online. */
	mount_proc();

	/*
	 *	Ignoring SIGKILL and SIGSTOP do not make sense, but
	 *	someday kill(-1, sig) might kill ourself if we don't
	 *	do this. This certainly is a valid concern for SIGTERM-
	 *	Linux 2.1 might send the calling process the signal too.
	 */
	signal(SIGTERM, SIG_IGN);
	signal(SIGSTOP, SIG_IGN);
	signal(SIGKILL, SIG_IGN);

	/* lock us into memory */
	mlockall(MCL_CURRENT | MCL_FUTURE);

	/* Now stop all processes. */
	kill(-1, SIGSTOP);
	sent_sigstop = 1;

	/* Read /proc filesystem */
	if (readproc(NO_STAT) < 0) {
		kill(-1, SIGCONT);
		return(1);
	}

	/* Now kill all processes except init (pid 1) and our session. */
	sid = (int)getsid(0);
	pid = (int)getpid();
	for (p = plist; p; p = p->next) {
		if (p->pid == 1 || p->pid == pid || p->sid == sid || p->kernel)
			continue;

		if (omit) {
			OMIT * optr;
			for (optr = omit; optr; optr = optr->next) {
				if (optr->pid == p->pid)
					break;
			}

			/* On a match, continue with the for loop above. */
			if (optr)
				continue;
		}

		kill(p->pid, sig);
		retval = 0;
	}

	/* And let them continue. */
	kill(-1, SIGCONT);

	/* Done. */
	closelog();

	/* Force the kernel to run the scheduler */
	usleep(1);

	return retval;
}
