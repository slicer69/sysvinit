/*
 * powerd	Monitor the DCD line of a serial port connected to
 *		an UPS. If the power goes down, notify init.
 *		If the power comes up again, notify init again.
 *		As long as the power is OK, the DCD line should be
 *		"HIGH". When the power fails, DCD should go "LOW".
 *		Powerd keeps DTR high so that you can connect
 *		DCD and DTR with a resistor of 10 Kilo Ohm and let the
 *		UPS or some relais pull the DCD line to ground.
 *		You also need to connect DTR and DSR together. This
 *		way, powerd can check now and then if DSR is high
 *		so it knows the UPS is connected!!
 *
 * Usage:	powerd /dev/cua4 (or any other serial device).
 *
 * Author:	Miquel van Smoorenburg, <miquels@drinkel.cistron.nl>.
 *
 * Version:	1.31,  29-Feb-1996.
 *
 *		This program was originally written for my employer,
 *			** Cistron Electronics **
 *		who has given kind permission to release this program
 *		for general puppose.
 *
 *		Copyright (C) 1991-1996 Cistron Electronics.
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

/* Use the new way of communicating with init. */
#define NEWINIT

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include "paths.h"
#ifdef NEWINIT
#include "initreq.h"
#endif

#ifndef SIGPWR
#  define SIGPWR SIGUSR1
#endif

#ifdef NEWINIT
void alrm_handler()
{
}
#endif

/* Tell init the power has either gone or is back. */
void powerfail(ok)
int ok;
{
  int fd;
#ifdef NEWINIT
  struct init_request req;

  /* Fill out the request struct. */
  memset(&req, 0, sizeof(req));
  req.magic = INIT_MAGIC;
  req.cmd   = ok ? INIT_CMD_POWEROK : INIT_CMD_POWERFAIL;

  /* Open the fifo (with timeout) */
  signal(SIGALRM, alrm_handler);
  alarm(3);
  if ((fd = open(INIT_FIFO, O_WRONLY)) >= 0
		&& write(fd, &req, sizeof(req)) == sizeof(req)) {
	close(fd);
	return;
  }
  /* Fall through to the old method.. */
#endif

  /* Create an info file for init. */
  unlink(PWRSTAT);
  if ((fd = open(PWRSTAT, O_CREAT|O_WRONLY, 0644)) >= 0) {
	if (ok)
		write(fd, "OK\n", 3);
	else
		write(fd, "FAIL\n", 5);
	close(fd);
  }
  kill(1, SIGPWR);
}

/* Main program. */
int main(int argc, char **argv)
{
  int fd;
  int dtr_bit = TIOCM_DTR;
  int flags;
  int status, oldstat = -1;
  int count = 0;
  int tries = 0;

  if (argc < 2) {
	fprintf(stderr, "Usage: powerd <device>\n");
	exit(1);
  }

  /* Start syslog. */
  openlog("powerd", LOG_CONS|LOG_PERROR, LOG_DAEMON);

  /* Open monitor device. */
  if ((fd = open(argv[1], O_RDWR | O_NDELAY)) < 0) {
	syslog(LOG_ERR, "%s: %s", argv[1], sys_errlist[errno]);
	closelog();
	exit(1);
  }

  /* Line is opened, so DTR is high. Force it anyway to be sure. */
  ioctl(fd, TIOCMBIS, &dtr_bit);

  /* Daemonize. */
  switch(fork()) {
	case 0: /* Child */
		closelog();
		setsid();
		break;
	case -1: /* Error */
		syslog(LOG_ERR, "can't fork.");
		closelog();
		exit(1);
	default: /* Parent */
		closelog();
		exit(0);
  }

  /* Restart syslog. */
  openlog("powerd", LOG_CONS, LOG_DAEMON);

  /* Now sample the DCD line. */
  while(1) {
	/* Get the status. */
	ioctl(fd, TIOCMGET, &flags);

	/* Check the connection: DSR should be high. */
	tries = 0;
	while((flags & TIOCM_DSR) == 0) {
		/* Keep on trying, and warn every two minutes. */
		if ((tries % 60) == 0)
		    syslog(LOG_ALERT, "UPS connection error");
		sleep(2);
		tries++;
  		ioctl(fd, TIOCMGET, &flags);
	}
	if (tries > 0)
		syslog(LOG_ALERT, "UPS connection OK");

	/* Calculate present status. */
	status = (flags & TIOCM_CAR);

	/* Did DCD drop to zero? Then the power has failed. */
	if (oldstat != 0 && status == 0) {
		count++;
		if (count > 3)
			powerfail(0);
		else {
			sleep(1);
			continue;
		}
	}
	/* Did DCD come up again? Then the power is back. */
	if (oldstat == 0 && status > 0) {
		count++;
		if (count > 3)
			powerfail(1);
		else {
			sleep(1);
			continue;
		}
	}
	/* Reset count, remember status and sleep 2 seconds. */
	count = 0;
	oldstat = status;
	sleep(2);
  }
  /* Never happens */
  return(0);
}
