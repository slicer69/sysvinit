/*
 * shutdown.c	Shut the system down.
 *
 * Usage:	shutdown [-krhfnc] time [warning message]
 *		  -k: don't really shutdown, only warn.
 *		  -r: reboot after shutdown.
 *		  -h: halt after shutdown.
 *		  -f: do a 'fast' reboot (skip fsck).
 *		  -F: Force fsck on reboot.
 *		  -n: do not go through init but do it ourselves.
 *		  -c: cancel an already running shutdown.
 *		  -t secs: delay between SIGTERM and SIGKILL for init.
 *
 * Author:	Miquel van Smoorenburg, miquels@cistron.nl
 *
 * Version:	@(#)shutdown  2.86-1  31-Jul-2004  miquels@cistron.nl
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h> 
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <utmp.h>
#include <syslog.h>
#include "paths.h"
#include "reboot.h"
#include "initreq.h"
#include "init.h"


char *Version = "@(#) shutdown 2.86-1 31-Jul-2004 miquels@cistron.nl";

#define MESSAGELEN	256

int dontshut = 0;	/* Don't shutdown, only warn	*/
char down_level[2];	/* What runlevel to go to.	*/
int dosync = 1;		/* Sync before reboot or halt	*/
int fastboot = 0;	/* Do a 'fast' reboot		*/
int forcefsck = 0;	/* Force fsck on reboot		*/
char message[MESSAGELEN];	/* Warning message	*/
char *sltime = 0;	/* Sleep time			*/
char newstate[64];	/* What are we gonna do		*/
int doself = 0;		/* Don't use init		*/
int got_alrm = 0;

char *clean_env[] = {
	"HOME=/",
	"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
	"TERM=dumb",
	"SHELL=/bin/sh",
	NULL,
};

/* From "utmp.c" */
extern void write_wtmp(char *user, char *id, int pid, int type, char *line);

/*
 *	Sleep without being interrupted.
 */
void hardsleep(int secs)
{
	struct timespec ts, rem;

	ts.tv_sec = secs;
	ts.tv_nsec = 0;

	while(nanosleep(&ts, &rem) < 0 && errno == EINTR)
		ts = rem;
}

/*
 *	Break off an already running shutdown.
 */
void stopit(int sig)
{
	unlink(NOLOGIN);
	unlink(FASTBOOT);
	unlink(FORCEFSCK);
	unlink(SDPID);
	printf("\r\nShutdown cancelled.\r\n");
	exit(0);
}

/*
 *	Show usage message.
 */
void usage(void)
{
	fprintf(stderr,
	"Usage:\t  shutdown [-akrhPHfFnc] [-t sec] time [warning message]\n"
	"\t\t  -a:      use /etc/shutdown.allow\n"
	"\t\t  -k:      don't really shutdown, only warn.\n"
	"\t\t  -r:      reboot after shutdown.\n"
	"\t\t  -h:      halt after shutdown.\n"
	"\t\t  -P:      halt action is to turn off power.\n"
	"\t\t  -H:      halt action is to just halt.\n"
	"\t\t  -f:      do a 'fast' reboot (skip fsck).\n"
	"\t\t  -F:      Force fsck on reboot.\n"
	"\t\t  -n:      do not go through \"init\" but go down real fast.\n"
	"\t\t  -c:      cancel a running shutdown.\n"
	"\t\t  -t secs: delay between warning and kill signal.\n"
	"\t\t  ** the \"time\" argument is mandatory! (try \"now\") **\n");
	exit(1);
}


void alrm_handler(int sig)
{
	got_alrm = sig;
}


/*
 *	Set environment variables in the init process.
 */
int init_setenv(char *name, char *value)
{
	struct init_request	request;
	struct sigaction	sa;
	int			fd;
	int			nl, vl;

	memset(&request, 0, sizeof(request));
	request.magic = INIT_MAGIC;
	request.cmd = INIT_CMD_SETENV;
	nl = strlen(name);
	vl = value ? strlen(value) : 0;

	if (nl + vl + 3 >= (int)sizeof(request.i.data))
		return -1;

	memcpy(request.i.data, name, nl);
	if (value) {
		request.i.data[nl] = '=';
		memcpy(request.i.data + nl + 1, value, vl);
	}

        /*
	 *	Open the fifo and write the command.
         *	Make sure we don't hang on opening /dev/initctl
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = alrm_handler;
	sigaction(SIGALRM, &sa, NULL);
	got_alrm = 0;
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
                                                                                
	fprintf(stderr, "shutdown: ");
	if (got_alrm) {
		fprintf(stderr, "timeout opening/writing control channel %s\n",
			INIT_FIFO);
	} else {
		perror(INIT_FIFO);
	}
	return -1;
}


/*
 *	Tell everyone the system is going down in 'mins' minutes.
 */
void warn(int mins)
{
	char buf[MESSAGELEN + sizeof(newstate)];
	int len;

	buf[0] = 0;
	strncat(buf, message, sizeof(buf) - 1);
	len = strlen(buf);

	if (mins == 0)
		snprintf(buf + len, sizeof(buf) - len,
			"\rThe system is going down %s NOW!\r\n",
			newstate);
	else
  		snprintf(buf + len, sizeof(buf) - len,
			"\rThe system is going DOWN %s in %d minute%s!\r\n",
				newstate, mins, mins == 1 ? "" : "s");
	wall(buf, 0);
}

/*
 *	Create the /etc/nologin file.
 */
void donologin(int min)
{
	FILE *fp;
	time_t t;

	time(&t);
	t += 60 * min;

	if ((fp = fopen(NOLOGIN, "w")) != NULL) {
  		fprintf(fp, "\rThe system is going down on %s\r\n", ctime(&t));
  		if (message[0]) fputs(message, fp);
  		fclose(fp);
	}
}

/*
 *	Spawn an external program.
 */
int spawn(int noerr, char *prog, ...)
{
	va_list	ap;
	pid_t	pid, rc;
	int	i;
	char	*argv[8];

	i = 0;
	while ((pid = fork()) < 0 && i < 10) {
		perror("fork");
		sleep(5);
		i++;
	}

	if (pid < 0) return -1;

	if (pid > 0) {
		while((rc = wait(&i)) != pid)
			if (rc < 0 && errno == ECHILD)
				break;
		return (rc == pid) ? WEXITSTATUS(i) : -1;
	}

	if (noerr) fclose(stderr);

	argv[0] = prog;
	va_start(ap, prog);
	for (i = 1; i < 7 && (argv[i] = va_arg(ap, char *)) != NULL; i++)
		;
	argv[i] = NULL;
	va_end(ap);

	chdir("/");
	environ = clean_env;

	execvp(argv[0], argv);
	perror(argv[0]);
	exit(1);

	/*NOTREACHED*/
	return 0;
}

/*
 *	Kill all processes, call /etc/init.d/halt (if present)
 */
void fastdown()
{
	int do_halt = (down_level[0] == '0');
	int i;
#if 0
	char cmd[128];
	char *script;

	/*
	 *	Currently, the halt script is either init.d/halt OR rc.d/rc.0,
	 *	likewise for the reboot script. Test for the presence
	 *	of either.
	 */
	if (do_halt) {
		if (access(HALTSCRIPT1, X_OK) == 0)
			script = HALTSCRIPT1;
		else
			script = HALTSCRIPT2;
	} else {
		if (access(REBOOTSCRIPT1, X_OK) == 0)
			script = REBOOTSCRIPT1;
		else
			script = REBOOTSCRIPT2;
	}
#endif

	/* First close all files. */
	for(i = 0; i < 3; i++)
		if (!isatty(i)) {
			close(i);
			open("/dev/null", O_RDWR);
		}
	for(i = 3; i < 20; i++) close(i);
	close(255);

	/* First idle init. */
	if (kill(1, SIGTSTP) < 0) {
		fprintf(stderr, "shutdown: can't idle init.\r\n");
		exit(1);
	}

	/* Kill all processes. */
	fprintf(stderr, "shutdown: sending all processes the TERM signal...\r\n");
	kill(-1, SIGTERM);
	sleep(sltime ? atoi(sltime) : 3);
	fprintf(stderr, "shutdown: sending all processes the KILL signal.\r\n");
	(void) kill(-1, SIGKILL);

#if 0
	/* See if we can run /etc/init.d/halt */
	if (access(script, X_OK) == 0) {
		spawn(1, cmd, "fast", NULL);
		fprintf(stderr, "shutdown: %s returned - falling back "
				"on default routines\r\n", script);
	}
#endif

	/* script failed or not present: do it ourself. */
	sleep(1); /* Give init the chance to collect zombies. */

	/* Record the fact that we're going down */
	write_wtmp("shutdown", "~~", 0, RUN_LVL, "~~");

	/* This is for those who have quota installed. */
	spawn(1, "accton", NULL);
	spawn(1, "quotaoff", "-a", NULL);

	sync();
	fprintf(stderr, "shutdown: turning off swap\r\n");
	spawn(0, "swapoff", "-a", NULL);
	fprintf(stderr, "shutdown: unmounting all file systems\r\n");
	spawn(0, "umount", "-a", NULL);

	/* We're done, halt or reboot now. */
	if (do_halt) {
		fprintf(stderr, "The system is halted. Press CTRL-ALT-DEL "
				"or turn off power\r\n");
		init_reboot(BMAGIC_HALT);
		exit(0);
	}

	fprintf(stderr, "Please stand by while rebooting the system.\r\n");
	init_reboot(BMAGIC_REBOOT);
	exit(0);
}

/*
 *	Go to runlevel 0, 1 or 6.
 */
void shutdown(char *halttype)
{
	char	*args[8];
	int	argp = 0;
	int	do_halt = (down_level[0] == '0');

	/* Warn for the last time */
	warn(0);
	if (dontshut) {
		hardsleep(1);
		stopit(0);
	}
	openlog("shutdown", LOG_PID, LOG_USER);
	if (do_halt)
  		syslog(LOG_NOTICE, "shutting down for system halt");
	else
		syslog(LOG_NOTICE, "shutting down for system reboot");
	closelog();

	/* See if we have to do it ourself. */
	if (doself) fastdown();

	/* Create the arguments for init. */
	args[argp++] = INIT;
	if (sltime) {
		args[argp++] = "-t";
		args[argp++] = sltime;
	}
	args[argp++] = down_level;
	args[argp]   = (char *)NULL;

	unlink(SDPID);
	unlink(NOLOGIN);

	/* Now execute init to change runlevel. */
	sync();
	init_setenv("INIT_HALT", halttype);
	execv(INIT, args);

	/* Oops - failed. */
	fprintf(stderr, "\rshutdown: cannot execute %s\r\n", INIT);
	unlink(FASTBOOT);
	unlink(FORCEFSCK);
	init_setenv("INIT_HALT", NULL);
	openlog("shutdown", LOG_PID, LOG_USER);
	syslog(LOG_NOTICE, "shutdown failed");
	closelog();
	exit(1);
}

/*
 *	returns if a warning is to be sent for wt
 */
static int needwarning(int wt)
{
	int ret;

	if (wt < 10)
		ret = 1;
	else if (wt < 60)
		ret = (wt % 15 == 0);
	else if (wt < 180)
		ret = (wt % 30 == 0);
	else
		ret = (wt % 60 == 0);

	return ret;
}

/*
 *	Main program.
 *	Process the options and do the final countdown.
 */
int main(int argc, char **argv)
{
	FILE			*fp;
	extern int		getopt();
	extern int		optind; 
	struct sigaction	sa;
	struct tm		*lt;
	struct stat		st;
	struct utmp		*ut;
	time_t			t;
	uid_t			realuid;
	char			*halttype;
	char			*downusers[32];
	char			buf[128];
	char			term[UT_LINESIZE + 6];
	char			*sp;
	char			*when = NULL;
	int			c, i, wt;
	int			hours, mins;
	int			didnolog = 0;
	int			cancel = 0;
	int			useacl = 0;
	int			pid = 0;
	int			user_ok = 0;

	/* We can be installed setuid root (executable for a special group) */
	realuid = getuid();
	setuid(geteuid());

	if (getuid() != 0) {
  		fprintf(stderr, "shutdown: you must be root to do that!\n");
		usage();
  		exit(1);
	}
	strcpy(down_level, "1");
	halttype = NULL;

	/* Process the options. */
	while((c = getopt(argc, argv, "HPacqkrhnfFyt:g:i:")) != EOF) {
  		switch(c) {
			case 'H':
				halttype = "HALT";
				break;
			case 'P':
				halttype = "POWERDOWN";
				break;
			case 'a': /* Access control. */
				useacl = 1;
				break;
			case 'c': /* Cancel an already running shutdown. */
				cancel = 1;
				break;
  			case 'k': /* Don't really shutdown, only warn.*/
  				dontshut = 1;
  				break;
  			case 'r': /* Automatic reboot */
				down_level[0] = '6';
  				break;
  			case 'h': /* Halt after shutdown */
				down_level[0] = '0';
  				break;
  			case 'f': /* Don't perform fsck after next boot */
  				fastboot = 1;
  				break;
  			case 'F': /* Force fsck after next boot */
  				forcefsck = 1;
  				break;
			case 'n': /* Don't switch runlevels. */
				doself = 1;
				break;
			case 't': /* Delay between TERM and KILL */
				sltime = optarg;
				break;
			case 'y': /* Ignored for sysV compatibility */
				break;
			case 'g': /* sysv style to specify time. */
				when = optarg;
				break;
			case 'i': /* Level to go to. */
				if (!strchr("0156aAbBcCsS", optarg[0])) {
					fprintf(stderr,
					"shutdown: `%s': bad runlevel\n",
					optarg);
					exit(1);
				}
				down_level[0] = optarg[0];
				break;
  			default:
  				usage();
  				break;	
  		}
	}

	if (NULL != halttype && down_level[0] != '0') {
		fprintf(stderr, "shutdown: -H and -P flags can only be used along with -h flag.\n");
		usage();
  		exit(1);
	}

	/* Do we need to use the shutdown.allow file ? */
	if (useacl && (fp = fopen(SDALLOW, "r")) != NULL) {

		/* Read /etc/shutdown.allow. */
		i = 0;
		while(fgets(buf, 128, fp)) {
			if (buf[0] == '#' || buf[0] == '\n') continue;
			if (i > 31) continue;
			for(sp = buf; *sp; sp++) if (*sp == '\n') *sp = 0;
			downusers[i++] = strdup(buf);
		}
		if (i < 32) downusers[i] = 0;
		fclose(fp);

		/* Now walk through /var/run/utmp to find logged in users. */
		while(!user_ok && (ut = getutent()) != NULL) {

			/* See if this is a user process on a VC. */
			if (ut->ut_type != USER_PROCESS) continue;
			sprintf(term, "/dev/%.*s", UT_LINESIZE, ut->ut_line);
			if (stat(term, &st) < 0) continue;
#ifdef major /* glibc */
			if (major(st.st_rdev) != 4 ||
			    minor(st.st_rdev) > 63) continue;
#else
			if ((st.st_rdev & 0xFFC0) != 0x0400) continue;
#endif
			/* Root is always OK. */
			if (strcmp(ut->ut_user, "root") == 0) {
				user_ok++;
				break;
			}

			/* See if this is an allowed user. */
			for(i = 0; i < 32 && downusers[i]; i++)
				if (!strncmp(downusers[i], ut->ut_user,
				    UT_NAMESIZE)) {
					user_ok++;
					break;
				}
		}
		endutent();

		/* See if user was allowed. */
		if (!user_ok) {
			if ((fp = fopen(CONSOLE, "w")) != NULL) {
				fprintf(fp, "\rshutdown: no authorized users "
						"logged in.\r\n");
				fclose(fp);
			}
			exit(1);
		}
	}

	/* Read pid of running shutdown from a file */
	if ((fp = fopen(SDPID, "r")) != NULL) {
		fscanf(fp, "%d", &pid);
		fclose(fp);
	}

	/* Read remaining words, skip time if needed. */
	message[0] = 0;
	for(c = optind + (!cancel && !when); c < argc; c++) {
		if (strlen(message) + strlen(argv[c]) + 4 > MESSAGELEN)
			break;
  		strcat(message, argv[c]);
  		strcat(message, " ");
	}
	if (message[0]) strcat(message, "\r\n");

	/* See if we want to run or cancel. */
	if (cancel) {
		if (pid <= 0) {
			fprintf(stderr, "shutdown: cannot find pid "
					"of running shutdown.\n");
			exit(1);
		}
		init_setenv("INIT_HALT", NULL);
		if (kill(pid, SIGINT) < 0) {
			fprintf(stderr, "shutdown: not running.\n");
			exit(1);
		}
		if (message[0]) wall(message, 0);
		exit(0);
	}
  
	/* Check syntax. */
	if (when == NULL) {
		if (optind == argc) usage();
		when = argv[optind++];
	}

	/* See if we are already running. */
	if (pid > 0 && kill(pid, 0) == 0) {
		fprintf(stderr, "\rshutdown: already running.\r\n");
		exit(1);
	}

	/* Extra check. */
	if (doself && down_level[0] != '0' && down_level[0] != '6') {
		fprintf(stderr,
		"shutdown: can use \"-n\" for halt or reboot only.\r\n");
		exit(1);
	}

	/* Tell users what we're gonna do. */
	switch(down_level[0]) {
		case '0':
			strcpy(newstate, "for system halt");
			break;
		case '6':
			strcpy(newstate, "for reboot");
			break;
		case '1':
			strcpy(newstate, "to maintenance mode");
			break;
		default:
			sprintf(newstate, "to runlevel %s", down_level);
			break;
	}

	/* Create a new PID file. */
	unlink(SDPID);
	umask(022);
	if ((fp = fopen(SDPID, "w")) != NULL) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	} else if (errno != EROFS)
		fprintf(stderr, "shutdown: warning: cannot open %s\n", SDPID);

	/*
	 *	Catch some common signals.
	 */
	signal(SIGQUIT, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP,  SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stopit;
	sigaction(SIGINT, &sa, NULL);

	/* Go to the root directory */
	chdir("/");
	if (fastboot)  close(open(FASTBOOT,  O_CREAT | O_RDWR, 0644));
	if (forcefsck) close(open(FORCEFSCK, O_CREAT | O_RDWR, 0644));

	/* Alias now and take care of old '+mins' notation. */
	if (!strcmp(when, "now")) strcpy(when, "0");
	if (when[0] == '+') when++;

	/* Decode shutdown time. */
	for (sp = when; *sp; sp++) {
		if (*sp != ':' && (*sp < '0' || *sp > '9'))
			usage();
	}
	if (strchr(when, ':') == NULL) {
		/* Time in minutes. */
		wt = atoi(when);
		if (wt == 0 && when[0] != '0') usage();
	} else {
		/* Time in hh:mm format. */
		if (sscanf(when, "%d:%2d", &hours, &mins) != 2) usage();
		if (hours > 23 || mins > 59) usage();
		time(&t);
		lt = localtime(&t);
		wt = (60*hours + mins) - (60*lt->tm_hour + lt->tm_min);
		if (wt < 0) wt += 1440;
	}
	/* Shutdown NOW if time == 0 */
	if (wt == 0) shutdown(halttype);

	/* Give warnings on regular intervals and finally shutdown. */
	if (wt < 15 && !needwarning(wt)) warn(wt);
	while(wt) {
		if (wt <= 5 && !didnolog) {
			donologin(wt);
			didnolog++;
		}
		if (needwarning(wt)) warn(wt);
		hardsleep(60);
		wt--;
	}
	shutdown(halttype);

	return 0; /* Never happens */
}
