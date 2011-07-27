/*
 * sulogin	This program gives Linux machines a reasonable
 *		secure way to boot single user. It forces the
 *		user to supply the root password before a
 *		shell is started.
 *
 *		If there is a shadow password file and the
 *		encrypted root password is "x" the shadow
 *		password will be used.
 *
 * Version:	@(#)sulogin 2.85-3 23-Apr-2003 miquels@cistron.nl
 *
 * Copyright (C) 1998-2003 Miquel van Smoorenburg.
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

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <shadow.h>
#include <termios.h>
#include <sys/ttydefaults.h>
#include <errno.h>
#include <sys/ioctl.h>
#if defined(__GLIBC__)
#  include <crypt.h>
#  define dovoid(f)		if ((f)){}
#endif
#ifdef __linux__
#  include <sys/statfs.h>
#  include <sys/mount.h>
#  include <linux/fs.h>
#  include <linux/magic.h>
#  include <linux/major.h>
#  ifndef TMPFS_MAGIC
#    define TMPFS_MAGIC		0x01021994
#  endif
#  ifndef MNT_DETACH
#    define MNT_DETACH		2
#  endif
#endif

#define BS  CTRL('h')
#define NL  CTRL('j')
#define CR  CTRL('m')

#ifdef WITH_SELINUX
#  include <selinux/selinux.h>
#  include <selinux/get_context_list.h>
#endif

#include "consoles.h"
#define CONMAX		16

#define CHECK_DES	1
#define CHECK_MD5	1

#define F_PASSWD	"/etc/passwd"
#define F_SHADOW	"/etc/shadow"
#define BINSH		"/bin/sh"
#define STATICSH	"/bin/sash"

char *Version = "@(#)sulogin 2.85-3 23-Apr-2003 miquels@cistron.nl";

static int timeout;
static int profile;
static volatile uint32_t openfd;		/* Remember higher file descriptors */
static volatile uint32_t *usemask;

static sighandler_t saved_sigint  = SIG_DFL;
static sighandler_t saved_sigtstp = SIG_DFL;
static sighandler_t saved_sigquit = SIG_DFL;
static sighandler_t saved_sighup  = SIG_DFL;

static volatile sig_atomic_t alarm_rised;
static volatile sig_atomic_t sigchild;

#ifndef IUCLC
#  define IUCLC	0
#endif

/*
 *	Fix the tty modes and set reasonable defaults.
 */
static
void tcinit(struct console *con)
{
	int serial, flags;
	struct termios *tio = &con->tio;
	int fd = con->fd;

	/* Expected error */
	serial = errno = 0;

	/* Get line attributes */
	if (tcgetattr(fd, tio) < 0) {
		con->flags |= CON_NOTTY;
		return;
	}

	/* Handle serial lines here */
	if (ioctl (fd, TIOCMGET, (char*)&serial) == 0) {
		speed_t ispeed, ospeed;
		struct winsize ws;

		/* this is a modem line */
		con->flags |= CON_SERIAL;

		/* Flush input and output queues on modem lines */
		(void) tcflush(fd, TCIOFLUSH);

		ispeed = cfgetispeed(tio);
		ospeed = cfgetospeed(tio);
		
		if (!ispeed) ispeed = TTYDEF_SPEED;
		if (!ospeed) ospeed = TTYDEF_SPEED;

		tio->c_iflag = tio->c_lflag = tio->c_oflag = 0;
		tio->c_cflag = CREAD | CS8 | HUPCL | (tio->c_cflag & CLOCAL);

		cfsetispeed(tio, ispeed);
		cfsetospeed(tio, ospeed);

		tio->c_line         = 0;
		tio->c_cc[VTIME]    = 0;
		tio->c_cc[VMIN]     = 1;

		if (ioctl(fd, TIOCGWINSZ, &ws) == 0) {
			int set = 0;
			if (ws.ws_row == 0) {
				ws.ws_row = 24;
				set++;
			}
			if (ws.ws_col == 0) {
				ws.ws_col = 80;
				set++;
			}
			(void)ioctl(fd, TIOCSWINSZ, &ws);
		}

		goto setattr;
	}
#if defined(SANE_TIO) && (SANE_TIO == 1)
	/*
	 * Use defaults of <sys/ttydefaults.h> for base settings
	 * of a local terminal line like a virtual console.
	 */
	tio->c_iflag |= TTYDEF_IFLAG;
	tio->c_oflag |= TTYDEF_OFLAG;
	tio->c_lflag |= TTYDEF_LFLAG;
# ifdef CBAUD
	tio->c_lflag &= ~CBAUD;
# endif
	tio->c_cflag |= (B38400 | TTYDEF_CFLAG);

	/* Sane setting, allow eight bit characters, no carriage return delay
	 * the same result as `stty sane cr0 pass8'
	 */
	tio->c_iflag |=  (BRKINT | ICRNL | IMAXBEL);
	tio->c_iflag &= ~(IGNBRK | INLCR | IGNCR | IXOFF | IUCLC | IXANY | INPCK | ISTRIP);
	tio->c_oflag |=  (OPOST | ONLCR | NL0 | CR0 | TAB0 | BS0 | VT0 | FF0);
	tio->c_oflag &= ~(OLCUC | OCRNL | ONOCR | ONLRET | OFILL | OFDEL |\
			 NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY);
	tio->c_lflag |=  (ISIG | ICANON | IEXTEN | ECHO|ECHOE|ECHOK|ECHOKE);
	tio->c_lflag &= ~(ECHONL|ECHOCTL|ECHOPRT | NOFLSH | XCASE | TOSTOP);
	tio->c_cflag |=  (CREAD | CS8 | HUPCL);
	tio->c_cflag &= ~(PARODD | PARENB);

	/*
	 * VTIME and VMIN can overlap with VEOF and VEOL since they are
	 * only used for non-canonical mode. We just set the at the
	 * beginning, so nothing bad should happen.
	 */
	tio->c_cc[VTIME]    = 0;
	tio->c_cc[VMIN]     = CMIN;
	tio->c_cc[VINTR]    = CINTR;
	tio->c_cc[VQUIT]    = CQUIT;
	tio->c_cc[VERASE]   = CERASE; /* ASCII DEL (0177) */
	tio->c_cc[VKILL]    = CKILL;
	tio->c_cc[VEOF]     = CEOF;
# ifdef VSWTC
	tio->c_cc[VSWTC]    = _POSIX_VDISABLE;
# else
	tio->c_cc[VSWTCH]   = _POSIX_VDISABLE;
# endif
	tio->c_cc[VSTART]   = CSTART;
	tio->c_cc[VSTOP]    = CSTOP;
	tio->c_cc[VSUSP]    = CSUSP;
	tio->c_cc[VEOL]     = _POSIX_VDISABLE;
	tio->c_cc[VREPRINT] = CREPRINT;
	tio->c_cc[VDISCARD] = CDISCARD;
	tio->c_cc[VWERASE]  = CWERASE;
	tio->c_cc[VLNEXT]   = CLNEXT;
	tio->c_cc[VEOL2]    = _POSIX_VDISABLE;
#endif
setattr:
	/* Set line attributes */
	tcsetattr(fd, TCSANOW, tio);

	/* Enable blocking mode for read and write */
	if ((flags = fcntl(fd, F_GETFL, 0)) != -1)
		(void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}


/*
 *	Finalize the tty modes on modem lines.
 */
static
void tcfinal(struct console *con)
{
	int serial;
	struct termios *tio = &con->tio;
	int fd = con->fd;

	/* Expected error */
	serial = errno = 0;

	if ((con->flags & CON_SERIAL) == 0) {
#ifdef __linux__
		setenv("TERM", "linux", 1);
#else
		setenv("TERM", "vt100", 1);
#endif
		return;
	}
	if (con->flags & CON_NOTTY)
		return;
	setenv("TERM", "vt100", 1);

	tio->c_iflag |= (IXON | IXOFF);
	tio->c_lflag |= (ICANON | ISIG | ECHO|ECHOE|ECHOK|ECHOKE);
	tio->c_oflag |= OPOST;

	tio->c_cc[VINTR]    = CINTR;
	tio->c_cc[VQUIT]    = CQUIT;
	tio->c_cc[VERASE]   = con->cp.erase;
	tio->c_cc[VKILL]    = con->cp.kill;
	tio->c_cc[VEOF]     = CEOF;
#ifdef VSWTC
	tio->c_cc[VSWTC]    = _POSIX_VDISABLE;
#else
	tio->c_cc[VSWTCH]   = _POSIX_VDISABLE;
#endif
	tio->c_cc[VSTART]   = CSTART;
	tio->c_cc[VSTOP]    = CSTOP;
	tio->c_cc[VSUSP]    = CSUSP;
	tio->c_cc[VEOL]     = _POSIX_VDISABLE;

	if (con->cp.eol == CR) {
		tio->c_iflag |= ICRNL;
		tio->c_iflag &= ~(INLCR|IGNCR);
		tio->c_oflag |= ONLCR;
		tio->c_oflag &= ~(OCRNL|ONLRET);
	}

	switch (con->cp.parity) {
	default:
	case 0:
		tio->c_cflag &= ~(PARODD | PARENB);
		tio->c_iflag &= ~(INPCK | ISTRIP);
		break;
	case 1:				/* odd parity */
		tio->c_cflag |= PARODD;
		/* fall through */
	case 2:				/* even parity */
		tio->c_cflag |= PARENB;
		tio->c_iflag |= (INPCK | ISTRIP);
		/* fall through */
	case (1 | 2):			/* no parity bit */
		tio->c_cflag &= ~CSIZE;
		tio->c_cflag |= CS7;
		break;
	}

	/* Set line attributes */
	(void)tcsetattr(fd, TCSANOW, tio);
}

/*
 *	Called at timeout.
 */
static
# ifdef __GNUC__
__attribute__((__noinline__))
void alrm_handler(int sig __attribute__((unused)))
# else
void alrm_handler(int sig)
# endif
{
	alarm_rised++;
}

/*
 *	Called at timeout.
 */
static
# ifdef __GNUC__
__attribute__((__noinline__))
void chld_handler(int sig __attribute__((unused)))
# else
void chld_handler(int sig)
# endif
{
	sigchild++;
}

/*
 *	See if an encrypted password is valid. The encrypted
 *	password is checked for traditional-style DES and
 *	FreeBSD-style MD5 encryption.
 */
static
int valid(const char *pass)
{
	const char *s;
	char id[5];
	size_t len;
	off_t off;

	if (pass[0] == 0) return 1;
#if CHECK_MD5
	if (pass[0] != '$') goto check_des;

	/*
	 *	up to 4 bytes for the signature e.g. $1$
	 */
	for(s = pass+1; *s && *s != '$'; s++)
		;
	if (*s++ != '$') return 0;
	if ((off = (off_t)(s-pass)) > 4 || off < 3) return 0;

	memset(id, '\0', sizeof(id));
	strncpy(id, pass, off);

	/*
	 *	up to 16 bytes for the salt
	 */
	for(; *s && *s != '$'; s++)
		;
	if (*s++ != '$') return 0;
	if ((off_t)(s-pass) > 16) return 0;
	len = strlen(s);

	/*
	 *	the MD5 hash (128 bits or 16 bytes) encoded in base64 = 22 bytes
	 */
	if ((strcmp(id, "$1$") == 0) && (len < 22 || len > 24)) return 0;

	/*
	 *	the SHA-256 hash 43 bytes
	 */
	if ((strcmp(id, "$5$") == 0) && (len < 42 || len > 44)) return 0;

	/*
	 *      the SHA-512 hash 86 bytes
	 */
	if ((strcmp(id, "$6$") == 0) && (len < 85 || len > 87)) return 0;

	/*
	 *	e.g. Blowfish hash
	 */
	return 1;
check_des:
#endif
#if CHECK_DES
	if (strlen(pass) != 13) return 0;
	for (s = pass; *s; s++) {
		if ((*s < '0' || *s > '9') &&
		    (*s < 'a' || *s > 'z') &&
		    (*s < 'A' || *s > 'Z') &&
		    *s != '.' && *s != '/') return 0;
	}
#endif
	return 1;
}

/*
 *	Set a variable if the value is not NULL.
 */
static
void set(char **var, char *val)
{
	if (val) *var = val;
}

/*
 *	Get the root password entry.
 */
static
struct passwd *getrootpwent(int try_manually)
{
	static struct passwd pwd;
	struct passwd *pw;
	struct spwd *spw;
	FILE *fp;
	static char line[256];
	static char sline[256];
	char *p;

	/*
	 *	First, we try to get the password the standard
	 *	way using normal library calls.
	 */
	if ((pw = getpwnam("root")) &&
	    !strcmp(pw->pw_passwd, "x") &&
	    (spw = getspnam("root")))
		pw->pw_passwd = spw->sp_pwdp;
	if (pw || !try_manually) return pw;

	/*
	 *	If we come here, we could not retrieve the root
	 *	password through library calls and we try to
	 *	read the password and shadow files manually.
	 */
	pwd.pw_name = "root";
	pwd.pw_passwd = "";
	pwd.pw_gecos = "Super User";
	pwd.pw_dir = "/";
	pwd.pw_shell = "";
	pwd.pw_uid = 0;
	pwd.pw_gid = 0;

	if ((fp = fopen(F_PASSWD, "r")) == NULL) {
		perror(F_PASSWD);
		return &pwd;
	}

	/*
	 *	Find root in the password file.
	 */
	while((p = fgets(line, 256, fp)) != NULL) {
		if (strncmp(line, "root:", 5) != 0)
			continue;
		p += 5;
		set(&pwd.pw_passwd, strsep(&p, ":"));
		(void)strsep(&p, ":");
		(void)strsep(&p, ":");
		set(&pwd.pw_gecos, strsep(&p, ":"));
		set(&pwd.pw_dir, strsep(&p, ":"));
		set(&pwd.pw_shell, strsep(&p, "\n"));
		p = line;
		break;
	}
	fclose(fp);

	/*
	 *	If the encrypted password is valid
	 *	or not found, return.
	 */
	if (p == NULL) {
		fprintf(stderr, "sulogin: %s: no entry for root\n\r", F_PASSWD);
		return &pwd;
	}
	if (valid(pwd.pw_passwd)) return &pwd;

	/*
	 *	The password is invalid. If there is a
	 *	shadow password, try it.
	 */
	strcpy(pwd.pw_passwd, "");
	if ((fp = fopen(F_SHADOW, "r")) == NULL) {
		fprintf(stderr, "sulogin: %s: root password garbled\n\r", F_PASSWD);
		return &pwd;
	}
	while((p = fgets(sline, 256, fp)) != NULL) {
		if (strncmp(sline, "root:", 5) != 0)
			continue;
		p += 5;
		set(&pwd.pw_passwd, strsep(&p, ":"));
		break;
	}
	fclose(fp);

	/*
	 *	If the password is still invalid,
	 *	NULL it, and return.
	 */
	if (p == NULL) {
		fprintf(stderr, "sulogin: %s: no entry for root\n\r", F_SHADOW);
		strcpy(pwd.pw_passwd, "");
	}
	if (!valid(pwd.pw_passwd)) {
		fprintf(stderr, "sulogin: %s: root password garbled\n\r", F_SHADOW);
		strcpy(pwd.pw_passwd, ""); }
	return &pwd;
}

/*
 *	Ask by prompt for the password.
 */
static
void doprompt(const char *crypted, struct console *con)
{
	struct termios tty;

	if (con->flags & CON_SERIAL) {
		tty = con->tio;
		/*
		 * For prompting: map NL in output to CR-NL
		 * otherwise we may see stairs in the output.
		 */
		tty.c_oflag |= (ONLCR | OPOST);
		(void) tcsetattr(con->fd, TCSADRAIN, &tty);
	}
	if (con->file == (FILE*)0) {
		if  ((con->file = fdopen(con->fd, "r+")) == (FILE*)0)
			goto err;
	}
#if defined(USE_ONELINE)
	if (crypted[0])
		fprintf(con->file, "Give root password for login: ");
	else
		fprintf(con->file, "Press enter for login: ");
#else
	if (crypted[0])
		fprintf(con->file, "Give root password for maintenance\n\r");
	else
		fprintf(con->file, "Press enter for maintenance");
	fprintf(con->file, "(or type Control-D to continue): ");
#endif
	fflush(con->file);
err:
	if (con->flags & CON_SERIAL)
		(void) tcsetattr(con->fd, TCSADRAIN, &con->tio);
}

/*
 * Make sure to have an own session and controlling terminal
 */
static
void setup(struct console *con)
{
	pid_t pid, pgrp, ppgrp, ttypgrp;
	int fd;

	if (con->flags & CON_NOTTY)
		return;
	fd = con->fd;

	/*
	 *	Only go through this trouble if the new
	 *	tty doesn't fall in this process group.
	 */
	pid = getpid();
	pgrp = getpgid(0);
	ppgrp = getpgid(getppid());
	ttypgrp = tcgetpgrp(fd);

	if (pgrp != ttypgrp && ppgrp != ttypgrp) {
		if (pid != getsid(0)) {
			if (pid == getpgid(0))
				setpgid(0, getpgid(getppid()));
			setsid();
		}

		signal(SIGHUP, SIG_IGN);
		if (ttypgrp > 0)
			ioctl(0, TIOCNOTTY, (char *)1);
		signal(SIGHUP, saved_sighup);
		if (fd > 0) close(0);
		if (fd > 1) close(1);
		if (fd > 2) close(2);

		ioctl(fd, TIOCSCTTY, (char *)1);
		tcsetpgrp(fd, ppgrp);
	}
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	con->fd = 0;

	for (fd = 3; fd < 32; fd++) {
		if (openfd & (1<<fd)) {
			close(fd);
			openfd &= ~(1<<fd);
		}
	}
}

/*
 *	Fetch the password. Note that there is no
 *	default timeout as we normally skip this during boot.
 */
static
char *getpasswd(struct console *con)
{
	static char pass[128], *ptr;
	struct sigaction sa;
	struct chardata *cp;
	struct termios tty;
	char *ret = pass;
	unsigned char tc;
	char c, ascval;
	int eightbit;
	int fd;

	if (con->flags & CON_NOTTY)
		goto out;
	fd = con->fd;
	cp = &con->cp;

	tty = con->tio;
	tty.c_iflag &= ~(IUCLC|IXON|IXOFF|IXANY);
	tty.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL|TOSTOP|ISIG);
	tc = (tcsetattr(fd, TCSAFLUSH, &tty) == 0);

	sa.sa_handler = alrm_handler;
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL);
	if (timeout) alarm(timeout);

	ptr = &pass[0];
	cp->eol = *ptr = '\0';

	eightbit = ((con->flags & CON_SERIAL) == 0 || (tty.c_cflag & (PARODD|PARENB)) == 0);
	while (cp->eol == '\0') {
		if (read(fd, &c, 1) < 1) {
			if (errno == EINTR || errno == EAGAIN) {
				usleep(1000);
				continue;
			}
			ret = (char*)0;
			switch (errno) {
			case 0:
			case EIO:
			case ESRCH:
			case EINVAL:
			case ENOENT:
				break;
			default:
				fprintf(stderr, "sulogin: read(%s): %m\n\r", con->tty);
				break;
			}
			goto quit;
		}

		if (eightbit)
			ascval = c;
		else if (c != (ascval = (c & 0177))) {
			uint32_t bits, mask;
			for (bits = 1, mask = 1; mask & 0177; mask <<= 1) {
				if (mask & ascval)
					bits++;
			}
			cp->parity |= ((bits & 1) ? 1 : 2);
		}

		switch (ascval) {
		case 0:
			*ptr = '\0';
			goto quit; 
		case CR:
		case NL:
			*ptr = '\0';
			cp->eol = ascval;
			break;
		case BS:
		case CERASE:
			cp->erase = ascval;
			if (ptr > &pass[0])
				ptr--;
			break;
		case CKILL:
			cp->kill = ascval;
			while (ptr > &pass[0])
				ptr--;
			break;
		case CEOF:
			goto quit;		
		default:
			if ((size_t)(ptr - &pass[0]) >= (sizeof(pass) -1 )) {
				 fprintf(stderr, "sulogin: input overrun at %s\n\r", con->tty);
				 ret = (char*)0;
				 goto quit;
			}
			*ptr++ = ascval;
			break;
		}
	}
quit:
	alarm(0);
	if (tc)
		(void)tcsetattr(fd, TCSAFLUSH, &con->tio);
	if (ret && *ret != '\0')
		tcfinal(con);
	printf("\r\n");
out:
	return ret;
}

/*
 *	Password was OK, execute a shell.
 */
static
void sushell(struct passwd *pwd)
{
	char shell[128];
	char home[128];
	char *p;
	char *sushell;

	/*
	 *	Set directory and shell.
	 */
	if (chdir(pwd->pw_dir) < 0) {
		if (chdir("/") < 0)
			fprintf(stderr, "sulogin: change of working directory failed: %m\n\r");
	}
	if ((p = getenv("SUSHELL")) != NULL)
		sushell = p;
	else if ((p = getenv("sushell")) != NULL)
		sushell = p;
	else {
		if (pwd->pw_shell[0])
			sushell = pwd->pw_shell;
		else
			sushell = BINSH;
	}
	if ((p = strrchr(sushell, '/')) == NULL)
		p = sushell;
	else
		p++;
	snprintf(shell, sizeof(shell), profile ? "-%s" : "%s", p);

	/*
	 *	Set some important environment variables.
	 */
	if (getcwd(home, sizeof(home)) == (char*)0)
		strcpy(home, "/");
	setenv("HOME", home, 1);
	setenv("LOGNAME", "root", 1);
	setenv("USER", "root", 1);
	if (!profile)
		setenv("SHLVL","0",1);

	/*
	 *	Try to execute a shell.
	 */
	setenv("SHELL", sushell, 1);
	signal(SIGINT,  saved_sigint);
	signal(SIGTSTP, saved_sigtstp);
	signal(SIGQUIT, saved_sigquit);
	signal(SIGHUP,  SIG_DFL);
#ifdef WITH_SELINUX
	if (is_selinux_enabled() > 0) {
		security_context_t scon=NULL;
		char *seuser=NULL;
		char *level=NULL;
		if (getseuserbyname("root", &seuser, &level) == 0)
			if (get_default_context_with_level(seuser, level, 0, &scon) == 0) {
				if (setexeccon(scon) != 0) 
					fprintf(stderr, "sulogin: setexeccon failed\n\r");
				freecon(scon);
			}
		free(seuser);
		free(level);
	}
#endif
	execl(sushell, shell, NULL);
	perror(sushell);

	setenv("SHELL", BINSH, 1);
	execl(BINSH, profile ? "-sh" : "sh", NULL);
	perror(BINSH);

	/* Fall back to staticly linked shell if both the users shell
	   and /bin/sh failed to execute. */
	setenv("SHELL", STATICSH, 1);
	execl(STATICSH, STATICSH, NULL);
	perror(STATICSH);
}

#ifdef __linux__
/*
 * Make C library standard calls like ttyname(3) work.
 */
static uint32_t mounts;
#define MNT_PROCFS	0x0001
#define MNT_DEVTMPFS	0x0002

static __attribute__((__noinline__))
void putmounts(void)
{
	if (mounts & MNT_DEVTMPFS)
		umount2("/dev", MNT_DETACH);
	if (mounts & MNT_PROCFS)
		umount2("/proc", MNT_DETACH);
}

static __attribute__((__constructor__))
void getmounts(void)
{
	struct statfs st;
	if (statfs("/proc", &st) == 0 && st.f_type != PROC_SUPER_MAGIC) {
		if (mount("proc", "/proc", "proc", MS_RELATIME, NULL) == 0)
			mounts |= MNT_PROCFS;
	}
	if (statfs("/dev", &st) == 0 && st.f_type != TMPFS_MAGIC) {
		if (mount("devtmpfs", "/dev", "devtmpfs", MS_RELATIME, "mode=0755,nr_inodes=0") == 0) {
			mounts |= MNT_DEVTMPFS;
			(void)mknod("/dev/console", S_IFCHR|S_IRUSR|S_IWUSR, makedev(TTYAUX_MAJOR, 1));
			if (symlink("/proc/self/fd", "/dev/fd") == 0) {
				dovoid(symlink("fd/0", "/dev/stdin"));
				dovoid(symlink("fd/1", "/dev/stdout"));
				dovoid(symlink("fd/2", "/dev/stderr"));
			}
		}
	}
	if (mounts) atexit(putmounts);
}
#endif

static
void usage(void)
{
	fprintf(stderr, "Usage: sulogin [-e] [-p] [-t timeout] [tty device]\n\r");
}

int main(int argc, char **argv)
{
	char *tty = NULL;
	struct passwd *pwd;
	int c, status = 0;
	int reconnect = 0;
	int opt_e = 0;
	struct console *con;
	pid_t pid;

	/*
	 * We are init. We hence need to set uo a session.
	 */
	if ((pid = getpid()) == 1) {
		setsid();
		(void)ioctl(0, TIOCSCTTY, (char *)1);
	}

	/*
	 * See if we have a timeout flag.
	 */
	opterr = 0;
	while((c = getopt(argc, argv, "ept:")) != EOF) switch(c) {
		case 't':
			timeout = atoi(optarg);
			break;
		case 'p':
			profile = 1;
			break;
		case 'e':
			opt_e = 1;
			break;
		default:
			usage();
			/* Do not exit! */
			break;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "sulogin: only root can run sulogin.\n\r");
		exit(1);
	}

	saved_sigint  = signal(SIGINT,  SIG_IGN);
	saved_sigquit = signal(SIGQUIT, SIG_IGN);
	saved_sigtstp = signal(SIGTSTP, SIG_IGN);
	saved_sighup  = signal(SIGHUP,  SIG_IGN);

	/*
	 * See if we need to open an other tty device.
	 */
	if (optind < argc)
		tty = argv[optind];
	if (!tty || *tty == '\0') 
		tty = getenv("CONSOLE");

	/*
	 * Detect possible consoles, use stdin as fallback.
	 * If an optional tty is given, reconnect it to stdin.
	 */
	reconnect = detect_consoles(tty, 0);

	/*
	 * Should not happen
	 */
	if (!consoles) {
		if (!errno)
			errno = ENOMEM;
		fprintf(stderr, "sulogin: cannot open console: %m\n\r");
		exit(1);
	}

	/*
	 * If previous stdin was not the speified tty and therefore reconnected
	 * to the specified tty also reconnect stdout and stderr.
	 */
	if (reconnect) {
		if (isatty(1) == 0)
			dup2(0, 1);
		if (isatty(2) == 0)
			dup2(0, 2);
	}

	/*
	 *	Get the root password.
	 */
	if ((pwd = getrootpwent(opt_e)) == NULL) {
		fprintf(stderr, "sulogin: cannot open password database!\n\r");
		sleep(2);
	}

	/*
	 * Prompt for input on the consoles
	 */
	for (con = consoles; con && con->id < CONMAX; con = con->next) {
		if (con->fd >= 0) {
			openfd |= (1<<con->fd);
			tcinit(con);
			continue;
		}
		if ((con->fd = open(con->tty, O_RDWR | O_NOCTTY | O_NONBLOCK)) < 0)
			continue;
		openfd |= (1<<con->fd);
		tcinit(con);
	}
	con = consoles;
	usemask = (uint32_t*)mmap(NULL, sizeof(uint32_t), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);

	if (con->next == (struct console*)0)
		goto nofork;

	signal(SIGCHLD, chld_handler);
	do {
		switch ((con->pid = fork())) {
		case 0:
			signal(SIGCHLD,  SIG_DFL);
			/* fall through */
		nofork:
			setup(con);
			while (1) {
				char *passwd = pwd->pw_passwd;
				char *answer;
				int failed = 0;

				doprompt(passwd, con);
				if ((answer = getpasswd(con)) == NULL)
					break;

				if (passwd[0] == '\0' ||
				    strcmp(crypt(answer, passwd), passwd) == 0) {
					*usemask |= (1<<con->id);
					sushell(pwd);
					*usemask &= ~(1<<con->id);
					failed++;
				}
				signal(SIGQUIT, SIG_IGN);
				signal(SIGTSTP, SIG_IGN);
				signal(SIGINT,  SIG_IGN);

				if (failed) {
					fprintf(stderr, "sulogin: can not execute su shell.\n\r");
					break;
				}
				fprintf(stderr, "Login incorrect.\n\r");
				sleep(3);
			}
			if (alarm_rised) {
				tcfinal(con);
				printf("Timed out.\n\r");
			}
			/*
			 *	User may pressed Control-D.
			 */
			exit(0);
		case -1:
			fprintf(stderr, "sulogin: can not fork: %m\n\r");
			/* fall through */
		default:
			break;
		}
	} while ((con = con->next) && (con->id < CONMAX));

	while ((pid = wait(&status))) {
		if (errno == ECHILD)
			break;
		if (pid < 0)
			continue;
		for (con = consoles; con && con->id < CONMAX; con = con->next) {
			if (con->pid == pid) {
				*usemask &= ~(1<<con->id);
				continue;
			}
			if (kill(con->pid, 0) < 0) {
				*usemask &= ~(1<<con->id);
				continue;
			}
			if (*usemask & (1<<con->id))
				continue;
			kill(con->pid, SIGHUP);
			usleep(5000);
			kill(con->pid, SIGKILL);
		}
	}
	signal(SIGCHLD,  SIG_DFL);

	return 0;
}
