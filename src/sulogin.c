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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <shadow.h>
#include <termios.h>
#include <errno.h>
#include <sys/ioctl.h>
#if defined(__GLIBC__)
#  include <crypt.h>
#endif

#ifdef WITH_SELINUX
#  include <selinux/selinux.h>
#  include <selinux/get_context_list.h>
#endif

#define CHECK_DES	1
#define CHECK_MD5	1

#define F_PASSWD	"/etc/passwd"
#define F_SHADOW	"/etc/shadow"
#define BINSH		"/bin/sh"
#define STATICSH	"/bin/sash"

char *Version = "@(#)sulogin 2.85-3 23-Apr-2003 miquels@cistron.nl";

int timeout = 0;
int profile = 0;

#ifndef IUCLC
#  define IUCLC	0
#endif

#if 0
/*
 *	Fix the tty modes and set reasonable defaults.
 *	(I'm not sure if this is needed under Linux, but..)
 */
void fixtty(void)
{
	struct termios tty;

	tcgetattr(0, &tty);

	/*
	 *	Set or adjust tty modes.
	 */
	tty.c_iflag &= ~(INLCR|IGNCR|IUCLC);
	tty.c_iflag |= ICRNL;
	tty.c_oflag &= ~(OCRNL|OLCUC|ONOCR|ONLRET|OFILL);
	tty.c_oflag |= OPOST|ONLCR;
	tty.c_cflag |= CLOCAL;
	tty.c_lflag  = ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE;

	/*
	 *	Set the most important characters */
	 */
	tty.c_cc[VINTR]  = 3;
	tty.c_cc[VQUIT]  = 28;
	tty.c_cc[VERASE] = 127;
	tty.c_cc[VKILL]  = 24;
	tty.c_cc[VEOF]   = 4;
	tty.c_cc[VTIME]  = 0;
	tty.c_cc[VMIN]   = 1;
	tty.c_cc[VSTART] = 17;
	tty.c_cc[VSTOP]  = 19;
	tty.c_cc[VSUSP]  = 26;
 
	tcsetattr(0, TCSANOW, &tty);
}
#endif


/*
 *	Called at timeout.
 */
void alrm_handler()
{
}

/*
 *	See if an encrypted password is valid. The encrypted
 *	password is checked for traditional-style DES and
 *	FreeBSD-style MD5 encryption.
 */
int valid(char *pass)
{
	char *s;
	int len;

	if (pass[0] == 0) return 1;
#if CHECK_MD5
	/*
	 *	3 bytes for the signature $1$
	 *	up to 8 bytes for the salt
	 *	$
	 *	the MD5 hash (128 bits or 16 bytes) encoded in base64 = 22 bytes
	 */
	if (strncmp(pass, "$1$", 3) == 0) {
		for(s = pass + 3; *s && *s != '$'; s++)
			;
		if (*s++ != '$') return 0;
		len = strlen(s);
		if (len < 22 || len > 24) return 0;

		return 1;
	}
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
void set(char **var, char *val)
{
	if (val) *var = val;
}

/*
 *	Get the root password entry.
 */
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
		fprintf(stderr, "%s: no entry for root\n", F_PASSWD);
		return &pwd;
	}
	if (valid(pwd.pw_passwd)) return &pwd;

	/*
	 *	The password is invalid. If there is a
	 *	shadow password, try it.
	 */
	strcpy(pwd.pw_passwd, "");
	if ((fp = fopen(F_SHADOW, "r")) == NULL) {
		fprintf(stderr, "%s: root password garbled\n", F_PASSWD);
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
		fprintf(stderr, "%s: no entry for root\n", F_SHADOW);
		strcpy(pwd.pw_passwd, "");
	}
	if (!valid(pwd.pw_passwd)) {
		fprintf(stderr, "%s: root password garbled\n", F_SHADOW);
		strcpy(pwd.pw_passwd, ""); }
	return &pwd;
}

/*
 *	Ask for the password. Note that there is no
 *	default timeout as we normally skip this during boot.
 */
char *getpasswd(char *crypted)
{
	struct sigaction sa;
	struct termios old, tty;
	static char pass[128];
	char *ret = pass;
	int i;

	if (crypted[0])
		printf("Give root password for maintenance\n");
	else
		printf("Press enter for maintenance\n");
	printf("(or type Control-D to continue): ");
	fflush(stdout);

	tcgetattr(0, &old);
	tcgetattr(0, &tty);
	tty.c_iflag &= ~(IUCLC|IXON|IXOFF|IXANY);
	tty.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL|TOSTOP);
	tcsetattr(0, TCSANOW, &tty);

	pass[sizeof(pass) - 1] = 0;

	sa.sa_handler = alrm_handler;
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL);
	if (timeout) alarm(timeout);

	if (read(0, pass, sizeof(pass) - 1) <= 0)
		ret = NULL;
	else {
		for(i = 0; i < sizeof(pass) && pass[i]; i++)
			if (pass[i] == '\r' || pass[i] == '\n') {
				pass[i] = 0;
				break;
			}
	}
	alarm(0);
	tcsetattr(0, TCSANOW, &old);
	printf("\n");

	return ret;
}

/*
 *	Password was OK, execute a shell.
 */
void sushell(struct passwd *pwd)
{
	char shell[128];
	char home[128];
	char *p;
	char *sushell;

	/*
	 *	Set directory and shell.
	 */
	(void)chdir(pwd->pw_dir);
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
	getcwd(home, sizeof(home));
	setenv("HOME", home, 1);
	setenv("LOGNAME", "root", 1);
	setenv("USER", "root", 1);
	if (!profile)
		setenv("SHLVL","0",1);

	/*
	 *	Try to execute a shell.
	 */
	setenv("SHELL", sushell, 1);
	signal(SIGINT, SIG_DFL);
	signal(SIGTSTP, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
#ifdef WITH_SELINUX
	if (is_selinux_enabled > 0) {
	  security_context_t scon=NULL;
	  char *seuser=NULL;
	  char *level=NULL;
	  if (getseuserbyname("root", &seuser, &level) == 0)
		  if (get_default_context_with_level(seuser, level, 0, &scon) > 0) {
			  if (setexeccon(scon) != 0) 
				  fprintf(stderr, "setexeccon faile\n");
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

void usage(void)
{
	fprintf(stderr, "Usage: sulogin [-e] [-p] [-t timeout] [tty device]\n");
}

int main(int argc, char **argv)
{
	char *tty = NULL;
	char *p;
	struct passwd *pwd;
	int c, fd = -1;
	int opt_e = 0;
	pid_t pid, pgrp, ppgrp, ttypgrp;

	/*
	 *	See if we have a timeout flag.
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
		fprintf(stderr, "sulogin: only root can run sulogin.\n");
		exit(1);
	}

	/*
	 *	See if we need to open an other tty device.
	 */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	if (optind < argc) tty = argv[optind];
	if (tty) {
		if ((fd = open(tty, O_RDWR)) < 0) {
			perror(tty);
		} else if (!isatty(fd)) {
			fprintf(stderr, "%s: not a tty\n", tty);
			close(fd);
		} else {

			/*
			 *	Only go through this trouble if the new
			 *	tty doesn't fall in this process group.
			 */
			pid = getpid();
			pgrp = getpgid(0);
			ppgrp = getpgid(getppid());
			ioctl(fd, TIOCGPGRP, &ttypgrp);

			if (pgrp != ttypgrp && ppgrp != ttypgrp) {
				if (pid != getsid(0)) {
					if (pid == getpgid(0))
						setpgid(0, getpgid(getppid()));
					setsid();
				}

				signal(SIGHUP, SIG_IGN);
				ioctl(0, TIOCNOTTY, (char *)1);
				signal(SIGHUP, SIG_DFL);
				close(0);
				close(1);
				close(2);
				close(fd);
				fd = open(tty, O_RDWR);
				ioctl(0, TIOCSCTTY, (char *)1);
				dup(fd);
				dup(fd);
			} else
				close(fd);
		}
	} else if (getpid() == 1) {
		/* We are init. We hence need to set a session anyway */
		setsid();
		if (ioctl(0, TIOCSCTTY, (char *)1))
			perror("ioctl(TIOCSCTTY)");
	}

	/*
	 *	Get the root password.
	 */
	if ((pwd = getrootpwent(opt_e)) == NULL) {
		fprintf(stderr, "sulogin: cannot open password database!\n");
		sleep(2);
	}

	/*
	 *	Ask for the password.
	 */
	while(pwd) {
		if ((p = getpasswd(pwd->pw_passwd)) == NULL) break;
		if (pwd->pw_passwd[0] == 0 ||
		    strcmp(crypt(p, pwd->pw_passwd), pwd->pw_passwd) == 0)
			sushell(pwd);
		printf("Login incorrect.\n");
	}

	/*
	 *	User pressed Control-D.
	 */
	return 0;
}

