/*
 * Init		A System-V Init Clone.
 *
 * Usage:	/sbin/init
 *		     init [0123456SsQqAaBbCc]
 *		  telinit [0123456SsQqAaBbCc]
 *
 * Version:	@(#)init.c  2.86  30-Jul-2004  miquels@cistron.nl
 */
#define VERSION "2.88"
#define DATE    "31-Jul-2004"
/*
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
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/kd.h>
#endif
#include <sys/resource.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <utmp.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/syslog.h>
#include <sys/time.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <sys/mount.h>
#endif


#ifdef __i386__
#  ifdef __GLIBC__
     /* GNU libc 2.x */
#    define STACK_DEBUG 1
#    if (__GLIBC__ == 2 && __GLIBC_MINOR__ == 0)
       /* Only glibc 2.0 needs this */
#      include <sigcontext.h>
#    elif ( __GLIBC__ > 2) && ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 1))
#      include <bits/sigcontext.h>
#    endif
#  endif
#endif

#include "init.h"
#include "initreq.h"
#include "paths.h"
#include "reboot.h"
#include "set.h"

#ifndef SIGPWR
#  define SIGPWR SIGUSR2
#endif

#ifndef CBAUD
#  define CBAUD		0
#endif
#ifndef CBAUDEX
#  define CBAUDEX	0
#endif

/* Set a signal handler. */
#define SETSIG(sa, sig, fun, flags) \
		do { \
			sa.sa_handler = fun; \
			sa.sa_flags = flags; \
			sigemptyset(&sa.sa_mask); \
			sigaction(sig, &sa, NULL); \
		} while(0)

/* Version information */
char *Version = "@(#) init " VERSION "  " DATE "  miquels@cistron.nl";
char *bootmsg = "version " VERSION " %s";
#define E_VERSION "INIT_VERSION=sysvinit-" VERSION

CHILD *family = NULL;		/* The linked list of all entries */
CHILD *newFamily = NULL;	/* The list after inittab re-read */

CHILD ch_emerg = {		/* Emergency shell */
	WAITING, 0, 0, 0, 0,
	"~~",
	"S",
	3,
	"/sbin/sulogin",
	NULL,
	NULL
};

char runlevel = 'S';		/* The current run level */
char thislevel = 'S';		/* The current runlevel */
char prevlevel = 'N';		/* Previous runlevel */
int dfl_level = 0;		/* Default runlevel */
sig_atomic_t got_cont = 0;	/* Set if we received the SIGCONT signal */
sig_atomic_t got_signals;	/* Set if we received a signal. */
int emerg_shell = 0;		/* Start emergency shell? */
int wrote_wtmp_reboot = 1;	/* Set when we wrote the reboot record */
int wrote_utmp_reboot = 1;	/* Set when we wrote the reboot record */
int wrote_wtmp_rlevel = 1;	/* Set when we wrote the runlevel record */
int wrote_utmp_rlevel = 1;	/* Set when we wrote the runlevel record */
int sltime = 5;			/* Sleep time between TERM and KILL */
char *argv0;			/* First arguments; show up in ps listing */
int maxproclen;			/* Maximal length of argv[0] with \0 */
struct utmp utproto;		/* Only used for sizeof(utproto.ut_id) */
char *console_dev;		/* Console device. */
int pipe_fd = -1;		/* /dev/initctl */
int did_boot = 0;		/* Did we already do BOOT* stuff? */
int main(int, char **);

/*	Used by re-exec part */
int reload = 0;			/* Should we do initialization stuff? */
char *myname="/sbin/init";	/* What should we exec */
int oops_error;			/* Used by some of the re-exec code. */
const char *Signature = "12567362";	/* Signature for re-exec fd */

/* Macro to see if this is a special action */
#define ISPOWER(i) ((i) == POWERWAIT || (i) == POWERFAIL || \
		    (i) == POWEROKWAIT || (i) == POWERFAILNOW || \
		    (i) == CTRLALTDEL)

/* ascii values for the `action' field. */
struct actions {
  char *name;
  int act;
} actions[] = {
  { "respawn", 	   RESPAWN	},
  { "wait",	   WAIT		},
  { "once",	   ONCE		},
  { "boot",	   BOOT		},
  { "bootwait",	   BOOTWAIT	},
  { "powerfail",   POWERFAIL	},
  { "powerfailnow",POWERFAILNOW },
  { "powerwait",   POWERWAIT	},
  { "powerokwait", POWEROKWAIT	},
  { "ctrlaltdel",  CTRLALTDEL	},
  { "off",	   OFF		},
  { "ondemand",	   ONDEMAND	},
  { "initdefault", INITDEFAULT	},
  { "sysinit",	   SYSINIT	},
  { "kbrequest",   KBREQUEST    },
  { NULL,	   0		},
};

/*
 *	State parser token table (see receive_state)
 */
struct {
  char name[4];	
  int cmd;
} cmds[] = {
  { "VER", 	   C_VER	},
  { "END",	   C_END	},
  { "REC",	   C_REC	},
  { "EOR",	   C_EOR	},
  { "LEV",	   C_LEV	},
  { "FL ",	   C_FLAG	},
  { "AC ",	   C_ACTION	},
  { "CMD",	   C_PROCESS	},
  { "PID",	   C_PID	},
  { "EXS",	   C_EXS	},
  { "-RL",	   D_RUNLEVEL	},
  { "-TL",	   D_THISLEVEL	},
  { "-PL",	   D_PREVLEVEL	},
  { "-SI",	   D_GOTSIGN	},
  { "-WR",	   D_WROTE_WTMP_REBOOT},
  { "-WU",	   D_WROTE_UTMP_REBOOT},
  { "-ST",	   D_SLTIME	},
  { "-DB",	   D_DIDBOOT	},
  { "-LW",	   D_WROTE_WTMP_RLEVEL},
  { "-LU",	   D_WROTE_UTMP_RLEVEL},
  { "",	   	   0		}
};
struct {
	char *name;
	int mask;
} flags[]={
	{"RU",RUNNING},
	{"DE",DEMAND},
	{"XD",XECUTED},
	{"WT",WAITING},
	{NULL,0}
};

#define NR_EXTRA_ENV	16
char *extra_env[NR_EXTRA_ENV];


/*
 *	Sleep a number of seconds.
 *
 *	This only works correctly because the linux select updates
 *	the elapsed time in the struct timeval passed to select!
 */
static
void do_sleep(int sec)
{
	struct timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = 0;

	while(select(0, NULL, NULL, NULL, &tv) < 0 && errno == EINTR)
		;
}


/*
 *	Non-failing allocation routines (init cannot fail).
 */
static
void *imalloc(size_t size)
{
	void	*m;

	while ((m = malloc(size)) == NULL) {
		initlog(L_VB, "out of memory");
		do_sleep(5);
	}
	memset(m, 0, size);
	return m;
}

static
char *istrdup(char *s)
{
	char	*m;
	int	l;

	l = strlen(s) + 1;
	m = imalloc(l);
	memcpy(m, s, l);
	return m;
}


/*
 *	Send the state info of the previous running init to
 *	the new one, in a version-independant way.
 */
static
void send_state(int fd)
{
	FILE	*fp;
	CHILD	*p;
	int	i,val;

	fp = fdopen(fd,"w");

	fprintf(fp, "VER%s\n", Version);
	fprintf(fp, "-RL%c\n", runlevel);
	fprintf(fp, "-TL%c\n", thislevel);
	fprintf(fp, "-PL%c\n", prevlevel);
	fprintf(fp, "-SI%u\n", got_signals);
	fprintf(fp, "-WR%d\n", wrote_wtmp_reboot);
	fprintf(fp, "-WU%d\n", wrote_utmp_reboot);
	fprintf(fp, "-ST%d\n", sltime);
	fprintf(fp, "-DB%d\n", did_boot);

	for (p = family; p; p = p->next) {
		fprintf(fp, "REC%s\n", p->id);
		fprintf(fp, "LEV%s\n", p->rlevel);
		for (i = 0, val = p->flags; flags[i].mask; i++)
			if (val & flags[i].mask) {
				val &= ~flags[i].mask;
				fprintf(fp, "FL %s\n",flags[i].name);
			}
		fprintf(fp, "PID%d\n",p->pid);
		fprintf(fp, "EXS%u\n",p->exstat);
		for(i = 0; actions[i].act; i++)
			if (actions[i].act == p->action) {
				fprintf(fp, "AC %s\n", actions[i].name);
				break;
			}
		fprintf(fp, "CMD%s\n", p->process);
		fprintf(fp, "EOR\n");
	}
	fprintf(fp, "END\n");
	fclose(fp);
}

/*
 *	Read a string from a file descriptor.
 *	FIXME: why not use fgets() ?
 */
static int get_string(char *p, int size, FILE *f)
{
	int	c;

	while ((c = getc(f)) != EOF && c != '\n') {
		if (--size > 0)
			*p++ = c;
	}
	*p = '\0';
	return (c != EOF) && (size > 0);
}

/*
 *	Read trailing data from the state pipe until we see a newline.
 */
static int get_void(FILE *f)
{
	int	c;

	while ((c = getc(f)) != EOF && c != '\n')
		;

	return (c != EOF);
}

/*
 *	Read the next "command" from the state pipe.
 */
static int get_cmd(FILE *f)
{
	char	cmd[4] = "   ";
	int	i;

	if (fread(cmd, 1, sizeof(cmd) - 1, f) != sizeof(cmd) - 1)
		return C_EOF;

	for(i = 0; cmds[i].cmd && strcmp(cmds[i].name, cmd) != 0; i++)
		;
	return cmds[i].cmd;
}

/*
 *	Read a CHILD * from the state pipe.
 */
static CHILD *get_record(FILE *f)
{
	int	cmd;
	char	s[32];
	int	i;
	CHILD	*p;

	do {
		switch (cmd = get_cmd(f)) {
			case C_END:
				get_void(f);
				return NULL;
			case 0:
				get_void(f);
				break;
			case C_REC:
				break;
			case D_RUNLEVEL:
				fscanf(f, "%c\n", &runlevel);
				break;
			case D_THISLEVEL:
				fscanf(f, "%c\n", &thislevel);
				break;
			case D_PREVLEVEL:
				fscanf(f, "%c\n", &prevlevel);
				break;
			case D_GOTSIGN:
				fscanf(f, "%u\n", &got_signals);
				break;
			case D_WROTE_WTMP_REBOOT:
				fscanf(f, "%d\n", &wrote_wtmp_reboot);
				break;
			case D_WROTE_UTMP_REBOOT:
				fscanf(f, "%d\n", &wrote_utmp_reboot);
				break;
			case D_SLTIME:
				fscanf(f, "%d\n", &sltime);
				break;
			case D_DIDBOOT:
				fscanf(f, "%d\n", &did_boot);
				break;
			case D_WROTE_WTMP_RLEVEL:
				fscanf(f, "%d\n", &wrote_wtmp_rlevel);
				break;
			case D_WROTE_UTMP_RLEVEL:
				fscanf(f, "%d\n", &wrote_utmp_rlevel);
				break;
			default:
				if (cmd > 0 || cmd == C_EOF) {
					oops_error = -1;
					return NULL;
				}
		}
	} while (cmd != C_REC);

	p = imalloc(sizeof(CHILD));
	get_string(p->id, sizeof(p->id), f);

	do switch(cmd = get_cmd(f)) {
		case 0:
		case C_EOR:
			get_void(f);
			break;
		case C_PID:
			fscanf(f, "%d\n", &(p->pid));
			break;
		case C_EXS:
			fscanf(f, "%u\n", &(p->exstat));
			break;
		case C_LEV:
			get_string(p->rlevel, sizeof(p->rlevel), f);
			break;
		case C_PROCESS:
			get_string(p->process, sizeof(p->process), f);
			break;
		case C_FLAG:
			get_string(s, sizeof(s), f);
			for(i = 0; flags[i].name; i++) {
				if (strcmp(flags[i].name,s) == 0)
					break;
			}
			p->flags |= flags[i].mask;
			break;
		case C_ACTION:
			get_string(s, sizeof(s), f);
			for(i = 0; actions[i].name; i++) {
				if (strcmp(actions[i].name, s) == 0)
					break;
			}
			p->action = actions[i].act ? actions[i].act : OFF;
			break;
		default:
			free(p);
			oops_error = -1;
			return NULL;
	} while( cmd != C_EOR);

	return p;
}

/*
 *	Read the complete state info from the state pipe.
 *	Returns 0 on success
 */
static
int receive_state(int fd)
{
	FILE	*f;
	char	old_version[256];
	CHILD	**pp;

	f = fdopen(fd, "r");

 	if (get_cmd(f) != C_VER)
		return -1;
	get_string(old_version, sizeof(old_version), f);
	oops_error = 0;
	for (pp = &family; (*pp = get_record(f)) != NULL; pp = &((*pp)->next))
		;
	fclose(f);
	return oops_error;
}

/*
 *	Set the process title.
 */
#ifdef __GNUC__
__attribute__ ((format (printf, 1, 2)))
#endif
static int setproctitle(char *fmt, ...)
{
	va_list ap;
	int len;
	char buf[256];

	buf[0] = 0;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (maxproclen > 1) {
		memset(argv0, 0, maxproclen);
		strncpy(argv0, buf, maxproclen - 1);
	}

	return len;
}

/*
 *	Set console_dev to a working console.
 */
static
void console_init(void)
{
	int fd;
	int tried_devcons = 0;
	int tried_vtmaster = 0;
	char *s;

	if ((s = getenv("CONSOLE")) != NULL)
		console_dev = s;
	else {
		console_dev = CONSOLE;
		tried_devcons++;
	}

	while ((fd = open(console_dev, O_RDONLY|O_NONBLOCK)) < 0) {
		if (!tried_devcons) {
			tried_devcons++;
			console_dev = CONSOLE;
			continue;
		}
		if (!tried_vtmaster) {
			tried_vtmaster++;
			console_dev = VT_MASTER;
			continue;
		}
		break;
	}
	if (fd < 0)
		console_dev = "/dev/null";
	else
		close(fd);
}


/*
 *	Open the console with retries.
 */
static
int console_open(int mode)
{
	int f, fd = -1;
	int m;

	/*
	 *	Open device in nonblocking mode.
	 */
	m = mode | O_NONBLOCK;

	/*
	 *	Retry the open five times.
	 */
	for(f = 0; f < 5; f++) {
		if ((fd = open(console_dev, m)) >= 0) break;
		usleep(100);
	}

	if (fd < 0) return fd;

	/*
	 *	Set original flags.
	 */
	if (m != mode)
  		fcntl(fd, F_SETFL, mode);
	return fd;
}

/*
 *	We got a signal (HUP PWR WINCH ALRM INT)
 */
static
void signal_handler(int sig)
{
	ADDSET(got_signals, sig);
}

/*
 *	SIGCHLD: one of our children has died.
 */
static
# ifdef __GNUC__
void chld_handler(int sig __attribute__((unused)))
# else
void chld_handler(int sig)
# endif
{
	CHILD		*ch;
	int		pid, st;
	int		saved_errno = errno;

	/*
	 *	Find out which process(es) this was (were)
	 */
	while((pid = waitpid(-1, &st, WNOHANG)) != 0) {
		if (errno == ECHILD) break;
		for( ch = family; ch; ch = ch->next )
			if ( ch->pid == pid && (ch->flags & RUNNING) ) {
				INITDBG(L_VB,
					"chld_handler: marked %d as zombie",
					ch->pid);
				ADDSET(got_signals, SIGCHLD);
				ch->exstat = st;
				ch->flags |= ZOMBIE;
				if (ch->new) {
					ch->new->exstat = st;
					ch->new->flags |= ZOMBIE;
				}
				break;
			}
		if (ch == NULL) {
			INITDBG(L_VB, "chld_handler: unknown child %d exited.",
				pid);
		}
	}
	errno = saved_errno;
}

/*
 *	Linux ignores all signals sent to init when the
 *	SIG_DFL handler is installed. Therefore we must catch SIGTSTP
 *	and SIGCONT, or else they won't work....
 *
 *	The SIGCONT handler
 */
static
# ifdef __GNUC__
void cont_handler(int sig __attribute__((unused)))
# else
void cont_handler(int sig)
# endif
{
	got_cont = 1;
}

/*
 *	Fork and dump core in /.
 */
static
void coredump(void)
{
	static int		dumped = 0;
	struct rlimit		rlim;
	sigset_t		mask;

	if (dumped) return;
	dumped = 1;

	if (fork() != 0) return;

	sigfillset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &rlim);
	chdir("/");

	signal(SIGSEGV, SIG_DFL);
	raise(SIGSEGV);
	sigdelset(&mask, SIGSEGV);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	do_sleep(5);
	exit(0);
}

/*
 *	OOPS: segmentation violation!
 *	If we have the info, print where it occured.
 *	Then sleep 30 seconds and try to continue.
 */
static
#if defined(STACK_DEBUG) && defined(__linux__)
# ifdef __GNUC__
void segv_handler(int sig __attribute__((unused)), struct sigcontext ctx)
# else
void segv_handler(int sig, struct sigcontext ctx)
# endif
{
	char	*p = "";
	int	saved_errno = errno;

	if ((void *)ctx.eip >= (void *)do_sleep &&
	    (void *)ctx.eip < (void *)main)
		p = " (code)";
	initlog(L_VB, "PANIC: segmentation violation at %p%s! "
		  "sleeping for 30 seconds.", (void *)ctx.eip, p);
	coredump();
	do_sleep(30);
	errno = saved_errno;
}
#else
# ifdef __GNUC__
void segv_handler(int sig __attribute__((unused)))
# else
void segv_handler(int sig)
# endif
{
	int	saved_errno = errno;

	initlog(L_VB,
		"PANIC: segmentation violation! sleeping for 30 seconds.");
	coredump();
	do_sleep(30);
	errno = saved_errno;
}
#endif

/*
 *	The SIGSTOP & SIGTSTP handler
 */
static
# ifdef __GNUC__
void stop_handler(int sig __attribute__((unused)))
# else
void stop_handler(int sig)
# endif
{
	int	saved_errno = errno;

	got_cont = 0;
	while(!got_cont) pause();
	got_cont = 0;
	errno = saved_errno;
}

/*
 *	Set terminal settings to reasonable defaults
 */
static
void console_stty(void)
{
	struct termios tty;
	int fd;

	if ((fd = console_open(O_RDWR|O_NOCTTY)) < 0) {
		initlog(L_VB, "can't open %s", console_dev);
		return;
	}

	(void) tcgetattr(fd, &tty);

	tty.c_cflag &= CBAUD|CBAUDEX|CSIZE|CSTOPB|PARENB|PARODD;
	tty.c_cflag |= HUPCL|CLOCAL|CREAD;

	tty.c_cc[VINTR]	    = CINTR;
	tty.c_cc[VQUIT]	    = CQUIT;
	tty.c_cc[VERASE]    = CERASE; /* ASCII DEL (0177) */
	tty.c_cc[VKILL]	    = CKILL;
	tty.c_cc[VEOF]	    = CEOF;
	tty.c_cc[VTIME]	    = 0;
	tty.c_cc[VMIN]	    = 1;
	tty.c_cc[VSWTC]	    = _POSIX_VDISABLE;
	tty.c_cc[VSTART]    = CSTART;
	tty.c_cc[VSTOP]	    = CSTOP;
	tty.c_cc[VSUSP]	    = CSUSP;
	tty.c_cc[VEOL]	    = _POSIX_VDISABLE;
	tty.c_cc[VREPRINT]  = CREPRINT;
	tty.c_cc[VDISCARD]  = CDISCARD;
	tty.c_cc[VWERASE]   = CWERASE;
	tty.c_cc[VLNEXT]    = CLNEXT;
	tty.c_cc[VEOL2]	    = _POSIX_VDISABLE;

	/*
	 *	Set pre and post processing
	 */
	tty.c_iflag = IGNPAR|ICRNL|IXON|IXANY;
#ifdef IUTF8 /* Not defined on FreeBSD */
	tty.c_iflag |= IUTF8;
#endif /* IUTF8 */
	tty.c_oflag = OPOST|ONLCR;
	tty.c_lflag = ISIG|ICANON|ECHO|ECHOCTL|ECHOPRT|ECHOKE;

#if defined(SANE_TIO) && (SANE_TIO == 1)
	/*
	 *	Disable flow control (-ixon), ignore break (ignbrk),
	 *	and make nl/cr more usable (sane).
	 */
	tty.c_iflag |=  IGNBRK;
	tty.c_iflag &= ~(BRKINT|INLCR|IGNCR|IXON);
	tty.c_oflag &= ~(OCRNL|ONLRET);
#endif
	/*
	 *	Now set the terminal line.
	 *	We don't care about non-transmitted output data
	 *	and non-read input data.
	 */
	(void) tcsetattr(fd, TCSANOW, &tty);
	(void) tcflush(fd, TCIOFLUSH);
	(void) close(fd);
}

/*
 *	Print to the system console
 */
void print(char *s)
{
	int fd;

	if ((fd = console_open(O_WRONLY|O_NOCTTY|O_NDELAY)) >= 0) {
		write(fd, s, strlen(s));
		close(fd);
	}
}

/*
 *	Log something to a logfile and the console.
 */
#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
#endif
void initlog(int loglevel, char *s, ...)
{
	va_list va_alist;
	char buf[256];
	sigset_t nmask, omask;

	va_start(va_alist, s);
	vsnprintf(buf, sizeof(buf), s, va_alist);
	va_end(va_alist);

	if (loglevel & L_SY) {
		/*
		 *	Re-establish connection with syslogd every time.
		 *	Block signals while talking to syslog.
		 */
		sigfillset(&nmask);
		sigprocmask(SIG_BLOCK, &nmask, &omask);
		openlog("init", 0, LOG_DAEMON);
		syslog(LOG_INFO, "%s", buf);
		closelog();
		sigprocmask(SIG_SETMASK, &omask, NULL);
	}

	/*
	 *	And log to the console.
	 */
	if (loglevel & L_CO) {
		print("\rINIT: ");
		print(buf);
		print("\r\n");
	}
}


/*
 *	Build a new environment for execve().
 */
char **init_buildenv(int child)
{
	char		i_lvl[] = "RUNLEVEL=x";
	char		i_prev[] = "PREVLEVEL=x";
	char		i_cons[32];
	char		i_shell[] = "SHELL=" SHELL;
	char		**e;
	int		n, i;

	for (n = 0; environ[n]; n++)
		;
	n += NR_EXTRA_ENV + 8;
	e = calloc(n, sizeof(char *));

	for (n = 0; environ[n]; n++)
		e[n] = istrdup(environ[n]);

	for (i = 0; i < NR_EXTRA_ENV; i++)
		if (extra_env[i])
			e[n++] = istrdup(extra_env[i]);

	if (child) {
		snprintf(i_cons, sizeof(i_cons), "CONSOLE=%s", console_dev);
		i_lvl[9]   = thislevel;
		i_prev[10] = prevlevel;
		e[n++] = istrdup(i_shell);
		e[n++] = istrdup(i_lvl);
		e[n++] = istrdup(i_prev);
		e[n++] = istrdup(i_cons);
		e[n++] = istrdup(E_VERSION);
	}

	e[n++] = NULL;

	return e;
}


void init_freeenv(char **e)
{
	int		n;

	for (n = 0; e[n]; n++)
		free(e[n]);
	free(e);
}


/*
 *	Fork and execute.
 *
 *	This function is too long and indents too deep.
 *
 */
static
int spawn(CHILD *ch, int *res)
{
  char *args[16];		/* Argv array */
  char buf[136];		/* Line buffer */
  int f, st, rc;		/* Scratch variables */
  char *ptr;			/* Ditto */
  time_t t;			/* System time */
  int oldAlarm;			/* Previous alarm value */
  char *proc = ch->process;	/* Command line */
  pid_t pid, pgrp;		/* child, console process group. */
  sigset_t nmask, omask;	/* For blocking SIGCHLD */
  struct sigaction sa;

  *res = -1;
  buf[sizeof(buf) - 1] = 0;

  /* Skip '+' if it's there */
  if (proc[0] == '+') proc++;

  ch->flags |= XECUTED;

  if (ch->action == RESPAWN || ch->action == ONDEMAND) {
	/* Is the date stamp from less than 2 minutes ago? */
	time(&t);
	if (ch->tm + TESTTIME > t) {
		ch->count++;
	} else {
		ch->count = 0;
		ch->tm = t;
	}

	/* Do we try to respawn too fast? */
	if (ch->count >= MAXSPAWN) {

	  initlog(L_VB,
		"Id \"%s\" respawning too fast: disabled for %d minutes",
		ch->id, SLEEPTIME / 60);
	  ch->flags &= ~RUNNING;
	  ch->flags |= FAILING;

	  /* Remember the time we stopped */
	  ch->tm = t;

	  /* Try again in 5 minutes */
	  oldAlarm = alarm(0);
	  if (oldAlarm > SLEEPTIME || oldAlarm <= 0) oldAlarm = SLEEPTIME;
	  alarm(oldAlarm);
	  return(-1);
	}
  }

  /* See if there is an "initscript" (except in single user mode). */
  if (access(INITSCRIPT, R_OK) == 0 && runlevel != 'S') {
	/* Build command line using "initscript" */
	args[1] = SHELL;
	args[2] = INITSCRIPT;
	args[3] = ch->id;
	args[4] = ch->rlevel;
	args[5] = "unknown";
	for(f = 0; actions[f].name; f++) {
		if (ch->action == actions[f].act) {
			args[5] = actions[f].name;
			break;
		}
	}
	args[6] = proc;
	args[7] = NULL;
  } else if (strpbrk(proc, "~`!$^&*()=|\\{}[];\"'<>?")) {
  /* See if we need to fire off a shell for this command */
  	/* Give command line to shell */
  	args[1] = SHELL;
  	args[2] = "-c";
  	strcpy(buf, "exec ");
  	strncat(buf, proc, sizeof(buf) - strlen(buf) - 1);
  	args[3] = buf;
  	args[4] = NULL;
  } else {
	/* Split up command line arguments */
	buf[0] = 0;
  	strncat(buf, proc, sizeof(buf) - 1);
  	ptr = buf;
  	for(f = 1; f < 15; f++) {
  		/* Skip white space */
  		while(*ptr == ' ' || *ptr == '\t') ptr++;
  		args[f] = ptr;
  		
		/* May be trailing space.. */
		if (*ptr == 0) break;

  		/* Skip this `word' */
  		while(*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '#')
  			ptr++;
  		
  		/* If end-of-line, break */	
  		if (*ptr == '#' || *ptr == 0) {
  			f++;
  			*ptr = 0;
  			break;
  		}
  		/* End word with \0 and continue */
  		*ptr++ = 0;
  	}
  	args[f] = NULL;
  }
  args[0] = args[1];
  while(1) {
	/*
	 *	Block sigchild while forking.
	 */
	sigemptyset(&nmask);
	sigaddset(&nmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	if ((pid = fork()) == 0) {

		close(0);
		close(1);
		close(2);
		if (pipe_fd >= 0) close(pipe_fd);

  		sigprocmask(SIG_SETMASK, &omask, NULL);

		/*
		 * Update utmp/wtmp file prior to starting
		 * any child.  This MUST be done right here in
		 * the child process in order to prevent a race
		 * condition that occurs when the child
		 * process' time slice executes before the
		 * parent (can and does happen in a uniprocessor
		 * environment).  If the child is a getty and
		 * the race condition happens, then init's utmp
		 * update will happen AFTER the getty runs
		 * and expects utmp to be updated already!
		 *
		 * Do NOT log if process field starts with '+'
		 * FIXME: that's for compatibility with *very*
		 * old getties - probably it can be taken out.
		 */
		if (ch->action == RESPAWN && ch->process[0] != '+')
			write_utmp_wtmp("", ch->id, getpid(), INIT_PROCESS, "");

		/*
		 *	In sysinit, boot, bootwait or single user mode:
		 *	for any wait-type subprocess we _force_ the console
		 *	to be its controlling tty.
		 */
  		if (strchr("*#sS", runlevel) && ch->flags & WAITING) {
			/*
			 *	We fork once extra. This is so that we can
			 *	wait and change the process group and session
			 *	of the console after exit of the leader.
			 */
			setsid();
			if ((f = console_open(O_RDWR|O_NOCTTY)) >= 0) {
				/* Take over controlling tty by force */
				(void)ioctl(f, TIOCSCTTY, 1);
  				dup(f);
  				dup(f);
			}

			/*
			 * 4 Sep 2001, Andrea Arcangeli:
			 * Fix a race in spawn() that is used to deadlock init in a
			 * waitpid() loop: must set the childhandler as default before forking
			 * off the child or the chld_handler could run before the waitpid loop
			 * has a chance to find its zombie-child.
			 */
			SETSIG(sa, SIGCHLD, SIG_DFL, SA_RESTART);
			if ((pid = fork()) < 0) {
  				initlog(L_VB, "cannot fork: %s",
					strerror(errno));
				exit(1);
			}
			if (pid > 0) {
				/*
				 *	Ignore keyboard signals etc.
				 *	Then wait for child to exit.
				 */
				SETSIG(sa, SIGINT, SIG_IGN, SA_RESTART);
				SETSIG(sa, SIGTSTP, SIG_IGN, SA_RESTART);
				SETSIG(sa, SIGQUIT, SIG_IGN, SA_RESTART);

				while ((rc = waitpid(pid, &st, 0)) != pid)
					if (rc < 0 && errno == ECHILD)
						break;

				/*
				 *	Small optimization. See if stealing
				 *	controlling tty back is needed.
				 */
				pgrp = tcgetpgrp(f);
				if (pgrp != getpid())
					exit(0);

				/*
				 *	Steal controlling tty away. We do
				 *	this with a temporary process.
				 */
				if ((pid = fork()) < 0) {
  					initlog(L_VB, "cannot fork: %s",
						strerror(errno));
					exit(1);
				}
				if (pid == 0) {
					setsid();
					(void)ioctl(f, TIOCSCTTY, 1);
					exit(0);
				}
				while((rc = waitpid(pid, &st, 0)) != pid)
					if (rc < 0 && errno == ECHILD)
						break;
				exit(0);
			}

			/* Set ioctl settings to default ones */
			console_stty();

  		} else {
			setsid();
			if ((f = console_open(O_RDWR|O_NOCTTY)) < 0) {
				initlog(L_VB, "open(%s): %s", console_dev,
					strerror(errno));
				f = open("/dev/null", O_RDWR);
			}
			dup(f);
			dup(f);
		}

  		/* Reset all the signals, set up environment */
  		for(f = 1; f < NSIG; f++) SETSIG(sa, f, SIG_DFL, SA_RESTART);
		environ = init_buildenv(1);

		/*
		 *	Execute prog. In case of ENOEXEC try again
		 *	as a shell script.
		 */
  		execvp(args[1], args + 1);
		if (errno == ENOEXEC) {
  			args[1] = SHELL;
  			args[2] = "-c";
  			strcpy(buf, "exec ");
  			strncat(buf, proc, sizeof(buf) - strlen(buf) - 1);
  			args[3] = buf;
  			args[4] = NULL;
			execvp(args[1], args + 1);
		}
  		initlog(L_VB, "cannot execute \"%s\"", args[1]);
  		exit(1);
  	}
	*res = pid;
  	sigprocmask(SIG_SETMASK, &omask, NULL);

	INITDBG(L_VB, "Started id %s (pid %d)", ch->id, pid);

	if (pid == -1) {
		initlog(L_VB, "cannot fork, retry..");
		do_sleep(5);
		continue;
	}
	return(pid);
  }
}

/*
 *	Start a child running!
 */
static
void startup(CHILD *ch)
{
	/*
	 *	See if it's disabled
	 */
	if (ch->flags & FAILING) return;

	switch(ch->action) {

		case SYSINIT:
		case BOOTWAIT:
		case WAIT:
		case POWERWAIT:
		case POWERFAILNOW:
		case POWEROKWAIT:
		case CTRLALTDEL:
			if (!(ch->flags & XECUTED)) ch->flags |= WAITING;
		case KBREQUEST:
		case BOOT:
		case POWERFAIL:
		case ONCE:
			if (ch->flags & XECUTED) break;
		case ONDEMAND:
		case RESPAWN:
  			ch->flags |= RUNNING;
  			(void)spawn(ch, &(ch->pid));
  			break;
	}
}


/*
 *	Read the inittab file.
 */
static
void read_inittab(void)
{
  FILE		*fp;			/* The INITTAB file */
  CHILD		*ch, *old, *i;		/* Pointers to CHILD structure */
  CHILD		*head = NULL;		/* Head of linked list */
#ifdef INITLVL
  struct stat	st;			/* To stat INITLVL */
#endif
  sigset_t	nmask, omask;		/* For blocking SIGCHLD. */
  char		buf[256];		/* Line buffer */
  char		err[64];		/* Error message. */
  char		*id, *rlevel,
		*action, *process;	/* Fields of a line */
  char		*p;
  int		lineNo = 0;		/* Line number in INITTAB file */
  int		actionNo;		/* Decoded action field */
  int		f;			/* Counter */
  int		round;			/* round 0 for SIGTERM, 1 for SIGKILL */
  int		foundOne = 0;		/* No killing no sleep */
  int		talk;			/* Talk to the user */
  int		done = 0;		/* Ready yet? */

#if DEBUG
  if (newFamily != NULL) {
	INITDBG(L_VB, "PANIC newFamily != NULL");
	exit(1);
  }
  INITDBG(L_VB, "Reading inittab");
#endif

  /*
   *	Open INITTAB and real line by line.
   */
  if ((fp = fopen(INITTAB, "r")) == NULL)
	initlog(L_VB, "No inittab file found");

  while(!done) {
	/*
	 *	Add single user shell entry at the end.
	 */
	if (fp == NULL || fgets(buf, sizeof(buf), fp) == NULL) {
		done = 1;
		/*
		 *	See if we have a single user entry.
		 */
		for(old = newFamily; old; old = old->next)
			if (strpbrk(old->rlevel, "S")) break;
		if (old == NULL)
			snprintf(buf, sizeof(buf), "~~:S:wait:%s\n", SULOGIN);
		else
			continue;
	}
	lineNo++;
	/*
	 *	Skip comments and empty lines
	 */
	for(p = buf; *p == ' ' || *p == '\t'; p++)
		;
	if (*p == '#' || *p == '\n') continue;

	/*
	 *	Decode the fields
	 */
	id =      strsep(&p, ":");
	rlevel =  strsep(&p, ":");
	action =  strsep(&p, ":");
	process = strsep(&p, "\n");

	/*
	 *	Check if syntax is OK. Be very verbose here, to
	 *	avoid newbie postings on comp.os.linux.setup :)
	 */
	err[0] = 0;
	if (!id || !*id) strcpy(err, "missing id field");
	if (!rlevel)     strcpy(err, "missing runlevel field");
	if (!process)    strcpy(err, "missing process field");
	if (!action || !*action)
			strcpy(err, "missing action field");
	if (id && strlen(id) > sizeof(utproto.ut_id))
		sprintf(err, "id field too long (max %d characters)",
			(int)sizeof(utproto.ut_id));
	if (rlevel && strlen(rlevel) > 11)
		strcpy(err, "rlevel field too long (max 11 characters)");
	if (process && strlen(process) > 127)
		strcpy(err, "process field too long");
	if (action && strlen(action) > 32)
		strcpy(err, "action field too long");
	if (err[0] != 0) {
		initlog(L_VB, "%s[%d]: %s", INITTAB, lineNo, err);
		INITDBG(L_VB, "%s:%s:%s:%s", id, rlevel, action, process);
		continue;
	}
  
	/*
	 *	Decode the "action" field
	 */
	actionNo = -1;
	for(f = 0; actions[f].name; f++)
		if (strcasecmp(action, actions[f].name) == 0) {
			actionNo = actions[f].act;
			break;
		}
	if (actionNo == -1) {
		initlog(L_VB, "%s[%d]: %s: unknown action field",
			INITTAB, lineNo, action);
		continue;
	}

	/*
	 *	See if the id field is unique
	 */
	for(old = newFamily; old; old = old->next) {
		if(strcmp(old->id, id) == 0 && strcmp(id, "~~")) {
			initlog(L_VB, "%s[%d]: duplicate ID field \"%s\"",
				INITTAB, lineNo, id);
			break;
		}
	}
	if (old) continue;

	/*
	 *	Allocate a CHILD structure
	 */
	ch = imalloc(sizeof(CHILD));

	/*
	 *	And fill it in.
	 */
	ch->action = actionNo;
	strncpy(ch->id, id, sizeof(utproto.ut_id) + 1); /* Hack for different libs. */
	strncpy(ch->process, process, sizeof(ch->process) - 1);
	if (rlevel[0]) {
		for(f = 0; f < (int)sizeof(rlevel) - 1 && rlevel[f]; f++) {
			ch->rlevel[f] = rlevel[f];
			if (ch->rlevel[f] == 's') ch->rlevel[f] = 'S';
		}
		strncpy(ch->rlevel, rlevel, sizeof(ch->rlevel) - 1);
	} else {
		strcpy(ch->rlevel, "0123456789");
		if (ISPOWER(ch->action))
			strcpy(ch->rlevel, "S0123456789");
	}
	/*
	 *	We have the fake runlevel '#' for SYSINIT  and
	 *	'*' for BOOT and BOOTWAIT.
	 */
	if (ch->action == SYSINIT) strcpy(ch->rlevel, "#");
	if (ch->action == BOOT || ch->action == BOOTWAIT)
		strcpy(ch->rlevel, "*");

	/*
	 *	Now add it to the linked list. Special for powerfail.
	 */
	if (ISPOWER(ch->action)) {

		/*
		 *	Disable by default
		 */
		ch->flags |= XECUTED;

		/*
		 *	Tricky: insert at the front of the list..
		 */
		old = NULL;
		for(i = newFamily; i; i = i->next) {
			if (!ISPOWER(i->action)) break;
			old = i;
		}
		/*
		 *	Now add after entry "old"
		 */
		if (old) {
			ch->next = i;
			old->next = ch;
			if (i == NULL) head = ch;
		} else {
			ch->next = newFamily;
			newFamily = ch;
			if (ch->next == NULL) head = ch;
		}
	} else {
		/*
		 *	Just add at end of the list
		 */
		if (ch->action == KBREQUEST) ch->flags |= XECUTED;
		ch->next = NULL;
		if (head)
			head->next = ch;
		else
			newFamily = ch;
		head = ch;
	}

	/*
	 *	Walk through the old list comparing id fields
	 */
	for(old = family; old; old = old->next)
		if (strcmp(old->id, ch->id) == 0) {
			old->new = ch;
			break;
		}
  }
  /*
   *	We're done.
   */
  if (fp) fclose(fp);

  /*
   *	Loop through the list of children, and see if they need to
   *	be killed. 
   */

  INITDBG(L_VB, "Checking for children to kill");
  for(round = 0; round < 2; round++) {
    talk = 1;
    for(ch = family; ch; ch = ch->next) {
	ch->flags &= ~KILLME;

	/*
	 *	Is this line deleted?
	 */
	if (ch->new == NULL) ch->flags |= KILLME;

	/*
	 *	If the entry has changed, kill it anyway. Note that
	 *	we do not check ch->process, only the "action" field.
	 *	This way, you can turn an entry "off" immediately, but
	 *	changes in the command line will only become effective
	 *	after the running version has exited.
	 */
	if (ch->new && ch->action != ch->new->action) ch->flags |= KILLME;

	/*
	 *	Only BOOT processes may live in all levels
	 */
	if (ch->action != BOOT &&
	    strchr(ch->rlevel, runlevel) == NULL) {
		/*
		 *	Ondemand procedures live always,
		 *	except in single user
		 */
		if (runlevel == 'S' || !(ch->flags & DEMAND))
			ch->flags |= KILLME;
	}

	/*
	 *	Now, if this process may live note so in the new list
	 */
	if ((ch->flags & KILLME) == 0) {
		ch->new->flags  = ch->flags;
		ch->new->pid    = ch->pid;
		ch->new->exstat = ch->exstat;
		continue;
	}


	/*
	 *	Is this process still around?
	 */
	if ((ch->flags & RUNNING) == 0) {
		ch->flags &= ~KILLME;
		continue;
	}
	INITDBG(L_VB, "Killing \"%s\"", ch->process);
	switch(round) {
		case 0: /* Send TERM signal */
			if (talk)
				initlog(L_CO,
					"Sending processes the TERM signal");
			kill(-(ch->pid), SIGTERM);
			foundOne = 1;
			break;
		case 1: /* Send KILL signal and collect status */
			if (talk)
				initlog(L_CO,
					"Sending processes the KILL signal");
			kill(-(ch->pid), SIGKILL);
			break;
	}
	talk = 0;
	
    }
    /*
     *	See if we have to wait 5 seconds
     */
    if (foundOne && round == 0) {
	/*
	 *	Yup, but check every second if we still have children.
	 */
	for(f = 0; f < sltime; f++) {
		for(ch = family; ch; ch = ch->next) {
			if (!(ch->flags & KILLME)) continue;
			if ((ch->flags & RUNNING) && !(ch->flags & ZOMBIE))
				break;
		}
		if (ch == NULL) {
			/*
			 *	No running children, skip SIGKILL
			 */
			round = 1;
			foundOne = 0; /* Skip the sleep below. */
			break;
		}
		do_sleep(1);
	}
    }
  }

  /*
   *	Now give all processes the chance to die and collect exit statuses.
   */
  if (foundOne) do_sleep(1);
  for(ch = family; ch; ch = ch->next)
	if (ch->flags & KILLME) {
		if (!(ch->flags & ZOMBIE))
		    initlog(L_CO, "Pid %d [id %s] seems to hang", ch->pid,
				ch->id);
		else {
		    INITDBG(L_VB, "Updating utmp for pid %d [id %s]",
				ch->pid, ch->id);
		    ch->flags &= ~RUNNING;
		    if (ch->process[0] != '+')
		    	write_utmp_wtmp("", ch->id, ch->pid, DEAD_PROCESS, NULL);
		}
	}

  /*
   *	Both rounds done; clean up the list.
   */
  sigemptyset(&nmask);
  sigaddset(&nmask, SIGCHLD);
  sigprocmask(SIG_BLOCK, &nmask, &omask);
  for(ch = family; ch; ch = old) {
	old = ch->next;
	free(ch);
  }
  family = newFamily;
  for(ch = family; ch; ch = ch->next) ch->new = NULL;
  newFamily = NULL;
  sigprocmask(SIG_SETMASK, &omask, NULL);

#ifdef INITLVL
  /*
   *	Dispose of INITLVL file.
   */
  if (lstat(INITLVL, &st) >= 0 && S_ISLNK(st.st_mode)) {
	/*
	 *	INITLVL is a symbolic link, so just truncate the file.
	 */
	close(open(INITLVL, O_WRONLY|O_TRUNC));
  } else {
	/*
	 *	Delete INITLVL file.
	 */
  	unlink(INITLVL);
  }
#endif
#ifdef INITLVL2
  /*
   *	Dispose of INITLVL2 file.
   */
  if (lstat(INITLVL2, &st) >= 0 && S_ISLNK(st.st_mode)) {
	/*
	 *	INITLVL2 is a symbolic link, so just truncate the file.
	 */
	close(open(INITLVL2, O_WRONLY|O_TRUNC));
  } else {
	/*
	 *	Delete INITLVL2 file.
	 */
  	unlink(INITLVL2);
  }
#endif
}

/*
 *	Walk through the family list and start up children.
 *	The entries that do not belong here at all are removed
 *	from the list.
 */
static
void start_if_needed(void)
{
	CHILD *ch;		/* Pointer to child */
	int delete;		/* Delete this entry from list? */

	INITDBG(L_VB, "Checking for children to start");

	for(ch = family; ch; ch = ch->next) {

#if DEBUG
		if (ch->rlevel[0] == 'C') {
			INITDBG(L_VB, "%s: flags %d", ch->process, ch->flags);
		}
#endif

		/* Are we waiting for this process? Then quit here. */
		if (ch->flags & WAITING) break;

		/* Already running? OK, don't touch it */
		if (ch->flags & RUNNING) continue;

		/* See if we have to start it up */
		delete = 1;
		if (strchr(ch->rlevel, runlevel) ||
		    ((ch->flags & DEMAND) && !strchr("#*Ss", runlevel))) {
			startup(ch);
			delete = 0;
		}

		if (delete) {
			/* FIXME: is this OK? */
			ch->flags &= ~(RUNNING|WAITING);
			if (!ISPOWER(ch->action) && ch->action != KBREQUEST)
				ch->flags &= ~XECUTED;
			ch->pid = 0;
		} else
			/* Do we have to wait for this process? */
			if (ch->flags & WAITING) break;
	}
	/* Done. */
}

/*
 *	Ask the user on the console for a runlevel
 */
static
int ask_runlevel(void)
{
	const char	prompt[] = "\nEnter runlevel: ";
	char		buf[8];
	int		lvl = -1;
	int		fd;

	console_stty();
	fd = console_open(O_RDWR|O_NOCTTY);

	if (fd < 0) return('S');

	while(!strchr("0123456789S", lvl)) {
  		write(fd, prompt, sizeof(prompt) - 1);
		buf[0] = 0;
  		read(fd, buf, sizeof(buf));
  		if (buf[0] != 0 && (buf[1] == '\r' || buf[1] == '\n'))
			lvl = buf[0];
		if (islower(lvl)) lvl = toupper(lvl);
	}
	close(fd);
	return lvl;
}

/*
 *	Search the INITTAB file for the 'initdefault' field, with the default
 *	runlevel. If this fails, ask the user to supply a runlevel.
 */
static
int get_init_default(void)
{
	CHILD *ch;
	int lvl = -1;
	char *p;

	/*
	 *	Look for initdefault.
	 */
	for(ch = family; ch; ch = ch->next)
		if (ch->action == INITDEFAULT) {
			p = ch->rlevel;
			while(*p) {
				if (*p > lvl) lvl = *p;
				p++;
			}
			break;
		}
	/*
	 *	See if level is valid
	 */
	if (lvl > 0) {
		if (islower(lvl)) lvl = toupper(lvl);
		if (strchr("0123456789S", lvl) == NULL) {
			initlog(L_VB,
				"Initdefault level '%c' is invalid", lvl);
			lvl = 0;
		}
	}
	/*
	 *	Ask for runlevel on console if needed.
	 */
	if (lvl <= 0) lvl = ask_runlevel();

	/*
	 *	Log the fact that we have a runlevel now.
	 */
	return lvl;
}


/*
 *	We got signaled.
 *
 *	Do actions for the new level. If we are compatible with
 *	the "old" INITLVL and arg == 0, try to read the new
 *	runlevel from that file first.
 */
static
int read_level(int arg)
{
	CHILD		*ch;			/* Walk through list */
	unsigned char	foo = 'X';		/* Contents of INITLVL */
	int		ok = 1;
#ifdef INITLVL
	FILE		*fp;
	struct stat	stt;
	int		st;
#endif

	if (arg) foo = arg;

#ifdef INITLVL
	ok = 0;

	if (arg == 0) {
		fp = NULL;
		if (stat(INITLVL, &stt) != 0 || stt.st_size != 0L)
			fp = fopen(INITLVL, "r");
#ifdef INITLVL2
		if (fp == NULL &&
		    (stat(INITLVL2, &stt) != 0 || stt.st_size != 0L))
			fp = fopen(INITLVL2, "r");
#endif
		if (fp == NULL) {
			/* INITLVL file empty or not there - act as 'init q' */
			initlog(L_SY, "Re-reading inittab");
  			return(runlevel);
		}
		ok = fscanf(fp, "%c %d", &foo, &st);
		fclose(fp);
	} else {
		/* We go to the new runlevel passed as an argument. */
		foo = arg;
		ok = 1;
	}
	if (ok == 2) sltime = st;

#endif /* INITLVL */

	if (islower(foo)) foo = toupper(foo);
	if (ok < 1 || ok > 2 || strchr("QS0123456789ABCU", foo) == NULL) {
 		initlog(L_VB, "bad runlevel: %c", foo);
  		return runlevel;
	}

	/* Log this action */
	switch(foo) {
		case 'S':
  			initlog(L_VB, "Going single user");
			break;
		case 'Q':
			initlog(L_SY, "Re-reading inittab");
			break;
		case 'A':
		case 'B':
		case 'C':
			initlog(L_SY,
				"Activating demand-procedures for '%c'", foo);
			break;
		case 'U':
			initlog(L_SY, "Trying to re-exec init");
			return 'U';
		default:
		  	initlog(L_VB, "Switching to runlevel: %c", foo);
	}

	if (foo == 'Q') {
#if defined(SIGINT_ONLYONCE) && (SIGINT_ONLYONCE == 1)
		/* Re-enable signal from keyboard */
		struct sigaction sa;
		SETSIG(sa, SIGINT, signal_handler, 0);
#endif
		return runlevel;
	}

	/* Check if this is a runlevel a, b or c */
	if (strchr("ABC", foo)) {
		if (runlevel == 'S') return(runlevel);

		/* Read inittab again first! */
		read_inittab();

  		/* Mark those special tasks */
		for(ch = family; ch; ch = ch->next)
			if (strchr(ch->rlevel, foo) != NULL ||
			    strchr(ch->rlevel, tolower(foo)) != NULL) {
				ch->flags |= DEMAND;
				ch->flags &= ~XECUTED;
				INITDBG(L_VB,
					"Marking (%s) as ondemand, flags %d",
					ch->id, ch->flags);
			}
  		return runlevel;
	}

	/* Store both the old and the new runlevel. */
	wrote_utmp_rlevel = 0;
	wrote_wtmp_rlevel = 0;
	write_utmp_wtmp("runlevel", "~~", foo + 256*runlevel, RUN_LVL, "~");
	thislevel = foo;
	prevlevel = runlevel;
	return foo;
}


/*
 *	This procedure is called after every signal (SIGHUP, SIGALRM..)
 *
 *	Only clear the 'failing' flag if the process is sleeping
 *	longer than 5 minutes, or inittab was read again due
 *	to user interaction.
 */
static
void fail_check(void)
{
	CHILD	*ch;			/* Pointer to child structure */
	time_t	t;			/* System time */
	time_t	next_alarm = 0;		/* When to set next alarm */

	time(&t);

	for(ch = family; ch; ch = ch->next) {

		if (ch->flags & FAILING) {
			/* Can we free this sucker? */
			if (ch->tm + SLEEPTIME < t) {
				ch->flags &= ~FAILING;
				ch->count = 0;
				ch->tm = 0;
			} else {
				/* No, we'll look again later */
				if (next_alarm == 0 ||
				    ch->tm + SLEEPTIME > next_alarm)
					next_alarm = ch->tm + SLEEPTIME;
			}
		}
	}
	if (next_alarm) {
		next_alarm -= t;
		if (next_alarm < 1) next_alarm = 1;
		alarm(next_alarm);
	}
}

/* Set all 'Fail' timers to 0 */
static
void fail_cancel(void)
{
	CHILD *ch;

	for(ch = family; ch; ch = ch->next) {
		ch->count = 0;
		ch->tm = 0;
		ch->flags &= ~FAILING;
	}
}

/*
 *	Start up powerfail entries.
 */
static
void do_power_fail(int pwrstat)
{
	CHILD *ch;

	/*
	 *	Tell powerwait & powerfail entries to start up
	 */
	for (ch = family; ch; ch = ch->next) {
		if (pwrstat == 'O') {
			/*
		 	 *	The power is OK again.
		 	 */
			if (ch->action == POWEROKWAIT)
				ch->flags &= ~XECUTED;
		} else if (pwrstat == 'L') {
			/*
			 *	Low battery, shut down now.
			 */
			if (ch->action == POWERFAILNOW)
				ch->flags &= ~XECUTED;
		} else {
			/*
			 *	Power is failing, shutdown imminent
			 */
			if (ch->action == POWERFAIL || ch->action == POWERWAIT)
				ch->flags &= ~XECUTED;
		}
	}
}

/*
 *	Check for state-pipe presence
 */
static
int check_pipe(int fd)
{
	struct timeval	t;
	fd_set		s;
	char		signature[8];

	FD_ZERO(&s);
	FD_SET(fd, &s);
	t.tv_sec = t.tv_usec = 0;

	if (select(fd+1, &s, NULL, NULL, &t) != 1)
		return 0;
	if (read(fd, signature, 8) != 8)
		 return 0;
	return strncmp(Signature, signature, 8) == 0;
}

/*
 *	 Make a state-pipe.
 */
static
int make_pipe(int fd)
{
	int fds[2];

	pipe(fds);
	dup2(fds[0], fd);
	close(fds[0]);
	fcntl(fds[1], F_SETFD, 1);
	fcntl(fd, F_SETFD, 0);
	write(fds[1], Signature, 8);

	return fds[1];
}

/*
 *	Attempt to re-exec.
 */
static
void re_exec(void)
{
	CHILD		*ch;
	sigset_t	mask, oldset;
	pid_t		pid;
	char		**env;
	int		fd;

	if (strchr("S0123456",runlevel) == NULL)
		return;

	/*
	 *	Reset the alarm, and block all signals.
	 */
	alarm(0);
	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &oldset);

	/*
	 *	construct a pipe fd --> STATE_PIPE and write a signature
	 */
	fd = make_pipe(STATE_PIPE);

	/* 
	 * It's a backup day today, so I'm pissed off.  Being a BOFH, however, 
	 * does have it's advantages...
	 */
	fail_cancel();
	close(pipe_fd);
	pipe_fd = -1;
	DELSET(got_signals, SIGCHLD);
	DELSET(got_signals, SIGHUP);
	DELSET(got_signals, SIGUSR1);

	/*
	 *	That should be cleaned.
	 */
	for(ch = family; ch; ch = ch->next)
	    if (ch->flags & ZOMBIE) {
		INITDBG(L_VB, "Child died, PID= %d", ch->pid);
		ch->flags &= ~(RUNNING|ZOMBIE|WAITING);
		if (ch->process[0] != '+')
			write_utmp_wtmp("", ch->id, ch->pid, DEAD_PROCESS, NULL);
	    }

	if ((pid = fork()) == 0) {
		/*
		 *	Child sends state information to the parent.
		 */
		send_state(fd);
		exit(0);
	}

	/*
	 *	The existing init process execs a new init binary.
	 */
	env = init_buildenv(0);
	execle(myname, myname, "--init", NULL, env);

	/*
	 *	We shouldn't be here, something failed. 
	 *	Bitch, close the state pipe, unblock signals and return.
	 */
	close(fd);
	close(STATE_PIPE);
	sigprocmask(SIG_SETMASK, &oldset, NULL);
	init_freeenv(env);
	initlog(L_CO, "Attempt to re-exec failed");
}

/*
 *	Redo utmp/wtmp entries if required or requested
 *	Check for written records and size of utmp
 */
static
void redo_utmp_wtmp(void)
{
	struct stat ustat;
	const int ret = stat(UTMP_FILE, &ustat);

	if ((ret < 0) || (ustat.st_size == 0))
		wrote_utmp_rlevel = wrote_utmp_reboot = 0;

	if ((wrote_wtmp_reboot == 0) || (wrote_utmp_reboot == 0))
		write_utmp_wtmp("reboot", "~~", 0, BOOT_TIME, "~");

	if ((wrote_wtmp_rlevel == 0) || (wrote_wtmp_rlevel == 0))
		write_utmp_wtmp("runlevel", "~~", thislevel + 256 * prevlevel, RUN_LVL, "~");
}

/*
 *	We got a change runlevel request through the
 *	init.fifo. Process it.
 */
static
void fifo_new_level(int level)
{
#if CHANGE_WAIT
	CHILD	*ch;
#endif
	int	oldlevel;

	if (level == runlevel) return;

#if CHANGE_WAIT
	/* Are we waiting for a child? */
	for(ch = family; ch; ch = ch->next)
		if (ch->flags & WAITING) break;
	if (ch == NULL)
#endif
	{
		/* We need to go into a new runlevel */
		oldlevel = runlevel;
		runlevel = read_level(level);
		if (runlevel == 'U') {
			runlevel = oldlevel;
			re_exec();
		} else {
			if (oldlevel != 'S' && runlevel == 'S') console_stty();
			if (runlevel == '6' || runlevel == '0' ||
			    runlevel == '1') console_stty();
			if (runlevel  > '1' && runlevel  < '6') redo_utmp_wtmp();
			read_inittab();
			fail_cancel();
			setproctitle("init [%c]", (int)runlevel);
		}
	}
}


/*
 *	Set/unset environment variables. The variables are
 *	encoded as KEY=VAL\0KEY=VAL\0\0. With "=VAL" it means
 *	setenv, without it means unsetenv.
 */
static
void initcmd_setenv(char *data, int size)
{
	char		*env, *p, *e, *eq;
	int		i, sz;

	e = data + size;

	while (*data && data < e) {
		eq = NULL;
		for (p = data; *p && p < e; p++)
			if (*p == '=') eq = p;
		if (*p) break;
		env = data;
		data = ++p;

		sz = eq ? (eq - env) : (p - env);

		/*initlog(L_SY, "init_setenv: %s, %s, %d", env, eq, sz);*/

		/*
		 *	We only allow INIT_* to be set.
		 */
		if (strncmp(env, "INIT_", 5) != 0)
			continue;

		/* Free existing vars. */
		for (i = 0; i < NR_EXTRA_ENV; i++) {
			if (extra_env[i] == NULL) continue;
			if (!strncmp(extra_env[i], env, sz) &&
			    extra_env[i][sz] == '=') {
				free(extra_env[i]);
				extra_env[i] = NULL;
			}
		}

		/* Set new vars if needed. */
		if (eq == NULL) continue;
		for (i = 0; i < NR_EXTRA_ENV; i++) {
			if (extra_env[i] == NULL) {
				extra_env[i] = istrdup(env);
				break;
			}
		}
	}
}


/*
 *	Read from the init FIFO. Processes like telnetd and rlogind can
 *	ask us to create login processes on their behalf.
 *
 *	FIXME:	this needs to be finished. NOT that it is buggy, but we need
 *		to add the telnetd/rlogind stuff so people can start using it.
 *		Maybe move to using an AF_UNIX socket so we can use
 *		the 2.2 kernel credential stuff to see who we're talking to.
 *	
 */
static
void check_init_fifo(void)
{
  struct init_request	request;
  struct timeval	tv;
  struct stat		st, st2;
  fd_set		fds;
  int			n;
  int			quit = 0;

  /*
   *	First, try to create /dev/initctl if not present.
   */
  if (stat(INIT_FIFO, &st2) < 0 && errno == ENOENT)
	(void)mkfifo(INIT_FIFO, 0600);

  /*
   *	If /dev/initctl is open, stat the file to see if it
   *	is still the _same_ inode.
   */
  if (pipe_fd >= 0) {
	fstat(pipe_fd, &st);
	if (stat(INIT_FIFO, &st2) < 0 ||
	    st.st_dev != st2.st_dev ||
	    st.st_ino != st2.st_ino) {
		close(pipe_fd);
		pipe_fd = -1;
	}
  }

  /*
   *	Now finally try to open /dev/initctl
   */
  if (pipe_fd < 0) {
	if ((pipe_fd = open(INIT_FIFO, O_RDWR|O_NONBLOCK)) >= 0) {
		fstat(pipe_fd, &st);
		if (!S_ISFIFO(st.st_mode)) {
			initlog(L_VB, "%s is not a fifo", INIT_FIFO);
			close(pipe_fd);
			pipe_fd = -1;
		}
	}
	if (pipe_fd >= 0) {
		/*
		 *	Don't use fd's 0, 1 or 2.
		 */
		(void) dup2(pipe_fd, PIPE_FD);
		close(pipe_fd);
		pipe_fd = PIPE_FD;

		/*
		 *	Return to caller - we'll be back later.
		 */
	}
  }

  /* Wait for data to appear, _if_ the pipe was opened. */
  if (pipe_fd >= 0) while(!quit) {

	/* Do select, return on EINTR. */
	FD_ZERO(&fds);
	FD_SET(pipe_fd, &fds);
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	n = select(pipe_fd + 1, &fds, NULL, NULL, &tv);
	if (n <= 0) {
		if (n == 0 || errno == EINTR) return;
		continue;
	}

	/* Read the data, return on EINTR. */
	n = read(pipe_fd, &request, sizeof(request));
	if (n == 0) {
		/*
		 *	End of file. This can't happen under Linux (because
		 *	the pipe is opened O_RDWR - see select() in the
		 *	kernel) but you never know...
		 */
		close(pipe_fd);
		pipe_fd = -1;
		return;
	}
	if (n <= 0) {
		if (errno == EINTR) return;
		initlog(L_VB, "error reading initrequest");
		continue;
	}

	/*
	 *	This is a convenient point to also try to
	 *	find the console device or check if it changed.
	 */
	console_init();

	/*
	 *	Process request.
	 */
	if (request.magic != INIT_MAGIC || n != sizeof(request)) {
		initlog(L_VB, "got bogus initrequest");
		continue;
	}
	switch(request.cmd) {
		case INIT_CMD_RUNLVL:
			sltime = request.sleeptime;
			fifo_new_level(request.runlevel);
			quit = 1;
			break;
		case INIT_CMD_POWERFAIL:
			sltime = request.sleeptime;
			do_power_fail('F');
			quit = 1;
			break;
		case INIT_CMD_POWERFAILNOW:
			sltime = request.sleeptime;
			do_power_fail('L');
			quit = 1;
			break;
		case INIT_CMD_POWEROK:
			sltime = request.sleeptime;
			do_power_fail('O');
			quit = 1;
			break;
		case INIT_CMD_SETENV:
			initcmd_setenv(request.i.data, sizeof(request.i.data));
			break;
		default:
			initlog(L_VB, "got unimplemented initrequest.");
			break;
	}
  }

  /*
   *	We come here if the pipe couldn't be opened.
   */
  if (pipe_fd < 0) pause();

}


/*
 *	This function is used in the transition
 *	sysinit (-> single user) boot -> multi-user.
 */
static
void boot_transitions()
{
  CHILD		*ch;
  static int	newlevel = 0;
  static int	warn = 1;
  int		loglevel;
  int		oldlevel;

  /* Check if there is something to wait for! */
  for( ch = family; ch; ch = ch->next )
	if ((ch->flags & RUNNING) && ch->action != BOOT) break;
     
  if (ch == NULL) {
	/* No processes left in this level, proceed to next level. */
	loglevel = -1;
	oldlevel = 'N';
	switch(runlevel) {
		case '#': /* SYSINIT -> BOOT */
			INITDBG(L_VB, "SYSINIT -> BOOT");

			/* Write a boot record. */
			wrote_utmp_reboot = 0;
			wrote_wtmp_reboot = 0;
			write_utmp_wtmp("reboot", "~~", 0, BOOT_TIME, "~");

  			/* Get our run level */
  			newlevel = dfl_level ? dfl_level : get_init_default();
			if (newlevel == 'S') {
				runlevel = newlevel;
				/* Not really 'S' but show anyway. */
				setproctitle("init [S]");
			} else
				runlevel = '*';
			break;
		case '*': /* BOOT -> NORMAL */
			INITDBG(L_VB, "BOOT -> NORMAL");
			if (runlevel != newlevel)
				loglevel = newlevel;
			runlevel = newlevel;
			did_boot = 1;
			warn = 1;
			break;
		case 'S': /* Ended SU mode */
		case 's':
			INITDBG(L_VB, "END SU MODE");
			newlevel = get_init_default();
			if (!did_boot && newlevel != 'S')
				runlevel = '*';
			else {
				if (runlevel != newlevel)
					loglevel = newlevel;
				runlevel = newlevel;
				oldlevel = 'S';
			}
			warn = 1;
			for(ch = family; ch; ch = ch->next)
			    if (strcmp(ch->rlevel, "S") == 0)
				ch->flags &= ~(FAILING|WAITING|XECUTED);
			break;
		default:
			if (warn)
			  initlog(L_VB,
				"no more processes left in this runlevel");
			warn = 0;
			loglevel = -1;
			if (got_signals == 0)
				check_init_fifo();
			break;
	}
	if (loglevel > 0) {
		initlog(L_VB, "Entering runlevel: %c", runlevel);
		wrote_utmp_rlevel = 0;
		wrote_wtmp_rlevel = 0;
		write_utmp_wtmp("runlevel", "~~", runlevel + 256 * oldlevel, RUN_LVL, "~");
		thislevel = runlevel;
		prevlevel = oldlevel;
		setproctitle("init [%c]", (int)runlevel);
	}
  }
}

/*
 *	Init got hit by a signal. See which signal it is,
 *	and act accordingly.
 */
static
void process_signals()
{
  CHILD		*ch;
  int		pwrstat;
  int		oldlevel;
  int		fd;
  char		c;

  if (ISMEMBER(got_signals, SIGPWR)) {
	INITDBG(L_VB, "got SIGPWR");
	/* See _what_ kind of SIGPWR this is. */
	pwrstat = 0;
	if ((fd = open(PWRSTAT, O_RDONLY)) >= 0) {
		c = 0;
		read(fd, &c, 1);
		pwrstat = c;
		close(fd);
		unlink(PWRSTAT);
	}
	do_power_fail(pwrstat);
	DELSET(got_signals, SIGPWR);
  }

  if (ISMEMBER(got_signals, SIGINT)) {
#if defined(SIGINT_ONLYONCE) && (SIGINT_ONLYONCE == 1)
	/* Ignore any further signal from keyboard */
	struct sigaction sa;
	SETSIG(sa, SIGINT, SIG_IGN, SA_RESTART);
#endif
	INITDBG(L_VB, "got SIGINT");
	/* Tell ctrlaltdel entry to start up */
	for(ch = family; ch; ch = ch->next)
		if (ch->action == CTRLALTDEL)
			ch->flags &= ~XECUTED;
	DELSET(got_signals, SIGINT);
  }

  if (ISMEMBER(got_signals, SIGWINCH)) {
	INITDBG(L_VB, "got SIGWINCH");
	/* Tell kbrequest entry to start up */
	for(ch = family; ch; ch = ch->next)
		if (ch->action == KBREQUEST)
			ch->flags &= ~XECUTED;
	DELSET(got_signals, SIGWINCH);
  }

  if (ISMEMBER(got_signals, SIGALRM)) {
	INITDBG(L_VB, "got SIGALRM");
	/* The timer went off: check it out */
	DELSET(got_signals, SIGALRM);
  }

  if (ISMEMBER(got_signals, SIGCHLD)) {
	INITDBG(L_VB, "got SIGCHLD");
	/* First set flag to 0 */
	DELSET(got_signals, SIGCHLD);

	/* See which child this was */
	for(ch = family; ch; ch = ch->next)
	    if (ch->flags & ZOMBIE) {
		INITDBG(L_VB, "Child died, PID= %d", ch->pid);
		ch->flags &= ~(RUNNING|ZOMBIE|WAITING);
		if (ch->process[0] != '+')
			write_utmp_wtmp("", ch->id, ch->pid, DEAD_PROCESS, NULL);
	    }

  }

  if (ISMEMBER(got_signals, SIGHUP)) {
	INITDBG(L_VB, "got SIGHUP");
#if CHANGE_WAIT
	/* Are we waiting for a child? */
	for(ch = family; ch; ch = ch->next)
		if (ch->flags & WAITING) break;
	if (ch == NULL)
#endif
	{
		/* We need to go into a new runlevel */
		oldlevel = runlevel;
#ifdef INITLVL
		runlevel = read_level(0);
#endif
		if (runlevel == 'U') {
			runlevel = oldlevel;
			re_exec();
		} else {
			if (oldlevel != 'S' && runlevel == 'S') console_stty();
			if (runlevel == '6' || runlevel == '0' ||
			    runlevel == '1') console_stty();
			read_inittab();
			fail_cancel();
			setproctitle("init [%c]", (int)runlevel);
			DELSET(got_signals, SIGHUP);
		}
	}
  }
  if (ISMEMBER(got_signals, SIGUSR1)) {
	/*
	 *	SIGUSR1 means close and reopen /dev/initctl
	 */
	INITDBG(L_VB, "got SIGUSR1");
	close(pipe_fd);
	pipe_fd = -1;
	DELSET(got_signals, SIGUSR1);
  }
}

/*
 *	The main loop
 */ 
static
void init_main(void)
{
  CHILD			*ch;
  struct sigaction	sa;
  sigset_t		sgt;
  pid_t			rc;
  int			f, st;

  if (!reload) {
  
#if INITDEBUG
	/*
	 * Fork so we can debug the init process.
	 */
	if ((f = fork()) > 0) {
		static const char killmsg[] = "PRNT: init killed.\r\n";
		pid_t rc;

		while((rc = wait(&st)) != f)
			if (rc < 0 && errno == ECHILD)
				break;
		write(1, killmsg, sizeof(killmsg) - 1);
		while(1) pause();
	}
#endif

#ifdef __linux__
	/*
	 *	Tell the kernel to send us SIGINT when CTRL-ALT-DEL
	 *	is pressed, and that we want to handle keyboard signals.
	 */
	init_reboot(BMAGIC_SOFT);
	if ((f = open(VT_MASTER, O_RDWR | O_NOCTTY)) >= 0) {
		(void) ioctl(f, KDSIGACCEPT, SIGWINCH);
		close(f);
	} else
		(void) ioctl(0, KDSIGACCEPT, SIGWINCH);
#endif

	/*
	 *	Ignore all signals.
	 */
	for(f = 1; f <= NSIG; f++)
		SETSIG(sa, f, SIG_IGN, SA_RESTART);
  }

  SETSIG(sa, SIGALRM,  signal_handler, 0);
  SETSIG(sa, SIGHUP,   signal_handler, 0);
  SETSIG(sa, SIGINT,   signal_handler, 0);
  SETSIG(sa, SIGCHLD,  chld_handler, SA_RESTART);
  SETSIG(sa, SIGPWR,   signal_handler, 0);
  SETSIG(sa, SIGWINCH, signal_handler, 0);
  SETSIG(sa, SIGUSR1,  signal_handler, 0);
  SETSIG(sa, SIGSTOP,  stop_handler, SA_RESTART);
  SETSIG(sa, SIGTSTP,  stop_handler, SA_RESTART);
  SETSIG(sa, SIGCONT,  cont_handler, SA_RESTART);
  SETSIG(sa, SIGSEGV,  (void (*)(int))segv_handler, SA_RESTART);

  console_init();

  if (!reload) {
	int fd;

  	/* Close whatever files are open, and reset the console. */
	close(0);
	close(1);
	close(2);
  	console_stty();
  	setsid();

  	/*
	 *	Set default PATH variable.
	 */
  	setenv("PATH", PATH_DEFAULT, 1 /* Overwrite */);

  	/*
	 *	Initialize /var/run/utmp (only works if /var is on
	 *	root and mounted rw)
	 */
	if ((fd = open(UTMP_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644)) >= 0)
		close(fd);

  	/*
	 *	Say hello to the world
	 */
  	initlog(L_CO, bootmsg, "booting");

  	/*
	 *	See if we have to start an emergency shell.
	 */
	if (emerg_shell) {
		SETSIG(sa, SIGCHLD, SIG_DFL, SA_RESTART);
		if (spawn(&ch_emerg, &f) > 0) {
			while((rc = wait(&st)) != f)
				if (rc < 0 && errno == ECHILD)
					break;
		}
  		SETSIG(sa, SIGCHLD,  chld_handler, SA_RESTART);
  	}

  	/*
	 *	Start normal boot procedure.
	 */
  	runlevel = '#';
  	read_inittab();
  
  } else {
	/*
	 *	Restart: unblock signals and let the show go on
	 */
	initlog(L_CO, bootmsg, "reloading");
	sigfillset(&sgt);
	sigprocmask(SIG_UNBLOCK, &sgt, NULL);

  	/*
	 *	Set default PATH variable.
	 */
  	setenv("PATH", PATH_DEFAULT, 0 /* Don't overwrite */);
  }
  start_if_needed();

  while(1) {

     /* See if we need to make the boot transitions. */
     boot_transitions();
     INITDBG(L_VB, "init_main: waiting..");

     /* Check if there are processes to be waited on. */
     for(ch = family; ch; ch = ch->next)
	if ((ch->flags & RUNNING) && ch->action != BOOT) break;

#if CHANGE_WAIT
     /* Wait until we get hit by some signal. */
     while (ch != NULL && got_signals == 0) {
	if (ISMEMBER(got_signals, SIGHUP)) {
		/* See if there are processes to be waited on. */
		for(ch = family; ch; ch = ch->next)
			if (ch->flags & WAITING) break;
	}
	if (ch != NULL) check_init_fifo();
     }
#else /* CHANGE_WAIT */
     if (ch != NULL && got_signals == 0) check_init_fifo();
#endif /* CHANGE_WAIT */

     /* Check the 'failing' flags */
     fail_check();

     /* Process any signals. */
     process_signals();

     /* See what we need to start up (again) */
     start_if_needed();
  }
  /*NOTREACHED*/
}

/*
 * Tell the user about the syntax we expect.
 */
static
void usage(char *s)
{
	fprintf(stderr, "Usage: %s {-e VAR[=VAL] | [-t SECONDS] {0|1|2|3|4|5|6|S|s|Q|q|A|a|B|b|C|c|U|u}}\n", s);
	exit(1);
}

static
int telinit(char *progname, int argc, char **argv)
{
#ifdef TELINIT_USES_INITLVL
	FILE			*fp;
#endif
	struct init_request	request;
	struct sigaction	sa;
	int			f, fd, l;
	char			*env = NULL;

	memset(&request, 0, sizeof(request));
	request.magic     = INIT_MAGIC;

	while ((f = getopt(argc, argv, "t:e:")) != EOF) switch(f) {
		case 't':
			sltime = atoi(optarg);
			break;
		case 'e':
			if (env == NULL)
				env = request.i.data;
			l = strlen(optarg);
			if (env + l + 2 > request.i.data + sizeof(request.i.data)) {
				fprintf(stderr, "%s: -e option data "
					"too large\n", progname);
				exit(1);
			}
			memcpy(env, optarg, l);
			env += l;
			*env++ = 0;
			break;
		default:
			usage(progname);
			break;
	}

	if (env) *env++ = 0;

	if (env) {
		if (argc != optind)
			usage(progname);
		request.cmd = INIT_CMD_SETENV;
	} else {
		if (argc - optind != 1 || strlen(argv[optind]) != 1)
			usage(progname);
		if (!strchr("0123456789SsQqAaBbCcUu", argv[optind][0]))
			usage(progname);
		request.cmd = INIT_CMD_RUNLVL;
		request.runlevel  = env ? 0 : argv[optind][0];
		request.sleeptime = sltime;
	}

	/* Change to the root directory. */
	chdir("/");

	/* Open the fifo and write a command. */
	/* Make sure we don't hang on opening /dev/initctl */
	SETSIG(sa, SIGALRM, signal_handler, 0);
	alarm(3);
	if ((fd = open(INIT_FIFO, O_WRONLY)) >= 0) {
		ssize_t p = 0;
		size_t s  = sizeof(request);
		void *ptr = &request;

		while (s > 0) {
			p = write(fd, ptr, s);
			if (p < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				break;
			}
			ptr += p;
			s -= p;
		}
		close(fd);
		alarm(0);
		return 0;
	}

#ifdef TELINIT_USES_INITLVL
	if (request.cmd == INIT_CMD_RUNLVL) {
		/* Fallthrough to the old method. */

		/* Now write the new runlevel. */
		if ((fp = fopen(INITLVL, "w")) == NULL) {
			fprintf(stderr, "%s: cannot create %s\n",
				progname, INITLVL);
			exit(1);
		}
		fprintf(fp, "%s %d", argv[optind], sltime);
		fclose(fp);

		/* And tell init about the pending runlevel change. */
		if (kill(INITPID, SIGHUP) < 0) perror(progname);

		return 0;
	}
#endif

	fprintf(stderr, "%s: ", progname);
	if (ISMEMBER(got_signals, SIGALRM)) {
		fprintf(stderr, "timeout opening/writing control channel %s\n",
			INIT_FIFO);
	} else {
		perror(INIT_FIFO);
	}
	return 1;
}

/*
 * Main entry for init and telinit.
 */
int main(int argc, char **argv)
{
	char			*p;
	int			f;
	int			isinit;
#ifdef WITH_SELINUX
	int			enforce = 0;
#endif

	/* Get my own name */
	if ((p = strrchr(argv[0], '/')) != NULL)
  		p++;
	else
  		p = argv[0];

	/* Common umask */
	umask(022);

	/* Quick check */
	if (geteuid() != 0) {
		fprintf(stderr, "%s: must be superuser.\n", p);
		exit(1);
	}

	/*
	 *	Is this telinit or init ?
	 */
	isinit = (getpid() == 1);
	for (f = 1; f < argc; f++) {
		if (!strcmp(argv[f], "-i") || !strcmp(argv[f], "--init")) {
			isinit = 1;
			break;
		}
	}
	if (!isinit) exit(telinit(p, argc, argv));

	/*
	 *	Check for re-exec
	 */ 	
	if (check_pipe(STATE_PIPE)) {

		receive_state(STATE_PIPE);

		myname = istrdup(argv[0]);
		argv0 = argv[0];
		maxproclen = 0;
		for (f = 0; f < argc; f++)
			maxproclen += strlen(argv[f]) + 1;
		reload = 1;
		setproctitle("init [%c]", (int)runlevel);

		init_main();
	}

  	/* Check command line arguments */
	maxproclen = strlen(argv[0]) + 1;
  	for(f = 1; f < argc; f++) {
		if (!strcmp(argv[f], "single") || !strcmp(argv[f], "-s"))
			dfl_level = 'S';
		else if (!strcmp(argv[f], "-a") || !strcmp(argv[f], "auto"))
			putenv("AUTOBOOT=YES");
		else if (!strcmp(argv[f], "-b") || !strcmp(argv[f],"emergency"))
			emerg_shell = 1;
		else if (!strcmp(argv[f], "-z")) {
			/* Ignore -z xxx */
			if (argv[f + 1]) f++;
		} else if (strchr("0123456789sS", argv[f][0])
			&& strlen(argv[f]) == 1)
			dfl_level = argv[f][0];
		/* "init u" in the very beginning makes no sense */
		if (dfl_level == 's') dfl_level = 'S';
		maxproclen += strlen(argv[f]) + 1;
	}

#ifdef WITH_SELINUX
	if (getenv("SELINUX_INIT") == NULL) {
	  const int rc = mount("proc", "/proc", "proc", 0, 0);
	  if (is_selinux_enabled() > 0) {
	    putenv("SELINUX_INIT=YES");
	    if (rc == 0) umount2("/proc", MNT_DETACH);
	    if (selinux_init_load_policy(&enforce) == 0) {
	      execv(myname, argv);
	    } else {
	      if (enforce > 0) {
		/* SELinux in enforcing mode but load_policy failed */
		/* At this point, we probably can't open /dev/console, so log() won't work */
		fprintf(stderr,"Unable to load SELinux Policy. Machine is in enforcing mode. Halting now.\n");
		exit(1);
	      }
	    }
	  }
	  if (rc == 0) umount2("/proc", MNT_DETACH);
	}
#endif  
	/* Start booting. */
	argv0 = argv[0];
	argv[1] = NULL;
	setproctitle("init boot");
	init_main();

	/*NOTREACHED*/
	return 0;
}
