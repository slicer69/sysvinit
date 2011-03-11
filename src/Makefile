#
# Makefile	Makefile for the systemV init suite.
#		Targets:   all      compiles everything
#		           install  installs the binaries (not the scripts)
#                          clean    cleans up object files
#			   clobber  really cleans up
#
# Version:	@(#)Makefile  2.85-13  23-Mar-2004  miquels@cistron.nl
#

CPPFLAGS =
CFLAGS	?= -ansi -O2 -fomit-frame-pointer
override CFLAGS += -W -Wall -D_GNU_SOURCE
STATIC	=

# For some known distributions we do not build all programs, otherwise we do.
BIN	=
SBIN	= init halt shutdown runlevel killall5 fstab-decode
USRBIN	= last mesg

MAN1	= last.1 lastb.1 mesg.1
MAN5	= initscript.5 inittab.5
MAN8	= halt.8 init.8 killall5.8 pidof.8 poweroff.8 reboot.8 runlevel.8
MAN8	+= shutdown.8 telinit.8 fstab-decode.8

ifeq ($(DISTRO),)
BIN	+= mountpoint
SBIN	+= sulogin bootlogd
USRBIN	+= utmpdump wall
MAN1	+= utmpdump.1 mountpoint.1 wall.1
MAN8	+= sulogin.8 bootlogd.8
endif

ifeq ($(DISTRO),Debian)
CPPFLAGS+= -DACCTON_OFF
BIN	+= mountpoint
SBIN	+= sulogin bootlogd
MAN1	+= mountpoint.1
MAN8	+= sulogin.8 bootlogd.8
endif

ifeq ($(DISTRO),Owl)
USRBIN	+= wall
MAN1	+= wall.1
endif

ifeq ($(DISTRO),SuSE)
CPPFLAGS+= -DUSE_SYSFS -DSANE_TIO -DSIGINT_ONLYONCE -DUSE_ONELINE
BIN	+= mountpoint
SBIN	+= sulogin
USRBIN	+= utmpdump
MAN1	+= utmpdump.1 mountpoint.1
MAN8	+= sulogin.8
endif

ID		= $(shell id -u)
BIN_OWNER	= root
BIN_GROUP	= root
BIN_COMBO	= $(BIN_OWNER):$(BIN_GROUP)
ifeq ($(ID),0)
  INSTALL_EXEC	= install -o $(BIN_OWNER) -g $(BIN_GROUP) -m 755
  INSTALL_DATA	= install -o $(BIN_OWNER) -g $(BIN_GROUP) -m 644
else
  INSTALL_EXEC	= install -m 755
  INSTALL_DATA	= install -m 644
endif
INSTALL_DIR	= install -m 755 -d
MANDIR		= /usr/share/man

ifeq ($(WITH_SELINUX),yes)
  SELINUX_DEF	=  -DWITH_SELINUX
  INITLIBS	+= -lsepol -lselinux
  SULOGINLIBS	= -lselinux	
else
  SELINUX_DEF	=
  INITLIBS	=
  SULOGINLIBS	=
endif

# Additional libs for GNU libc.
ifneq ($(wildcard /usr/lib*/libcrypt.a),)
  SULOGINLIBS	+= -lcrypt
endif

all:		$(BIN) $(SBIN) $(USRBIN)

#%: %.o
#	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
#%.o: %.c
#	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^ -o $@

init:		LDLIBS += $(INITLIBS) $(STATIC)
init:		init.o init_utmp.o

halt:		halt.o ifdown.o hddown.o utmp.o

last:		last.o

mesg:		mesg.o

mountpoint:	mountpoint.o

utmpdump:	utmpdump.o

runlevel:	runlevel.o

sulogin:	LDLIBS += $(SULOGINLIBS) $(STATIC)
sulogin:	sulogin.o

wall:		dowall.o wall.o

shutdown:	dowall.o shutdown.o utmp.o

bootlogd:	LDLIBS += -lutil
bootlogd:	bootlogd.o

sulogin.o:	CPPFLAGS += $(SELINUX_DEF)
sulogin.o:	sulogin.c 

init.o:		CPPFLAGS += $(SELINUX_DEF)
init.o:		init.c init.h initreq.h paths.h reboot.h set.h

utmp.o:		

init_utmp.o:	CPPFLAGS += -DINIT_MAIN
init_utmp.o:	utmp.c init.h initreq.h paths.h
		$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

utmpdump.o:	utmpdump.c oldutmp.h

shutdown.o:	shutdown.c paths.h reboot.h initreq.h init.h

halt.o:		halt.c reboot.h

last.o:		last.c oldutmp.h

consoles.o:	consoles.c consoles.h

cleanobjs:
		rm -f *.o *.bak

clean:		cleanobjs
		@echo Type \"make clobber\" to really clean up.

clobber:	cleanobjs
		rm -f $(BIN) $(SBIN) $(USRBIN)

distclean:	clobber

install:
		$(INSTALL_DIR) $(ROOT)/bin/ $(ROOT)/sbin/
		$(INSTALL_DIR) $(ROOT)/usr/bin/
		for i in $(BIN); do \
			$(INSTALL_EXEC) $$i $(ROOT)/bin/ ; \
		done
		for i in $(SBIN); do \
			$(INSTALL_EXEC) $$i $(ROOT)/sbin/ ; \
		done
		for i in $(USRBIN); do \
			$(INSTALL_EXEC) $$i $(ROOT)/usr/bin/ ; \
		done
		# $(INSTALL_DIR) $(ROOT)/etc/
		# $(INSTALL_EXEC) initscript.sample $(ROOT)/etc/
		ln -sf halt $(ROOT)/sbin/reboot
		ln -sf halt $(ROOT)/sbin/poweroff
		ln -sf init $(ROOT)/sbin/telinit
		ln -sf /sbin/killall5 $(ROOT)/bin/pidof
		if [ ! -f $(ROOT)/usr/bin/lastb ]; then \
			ln -sf last $(ROOT)/usr/bin/lastb; \
		fi
		$(INSTALL_DIR) $(ROOT)/usr/include/
		$(INSTALL_DATA) initreq.h $(ROOT)/usr/include/
		$(INSTALL_DIR) $(ROOT)$(MANDIR)/man1/
		$(INSTALL_DIR) $(ROOT)$(MANDIR)/man5/
		$(INSTALL_DIR) $(ROOT)$(MANDIR)/man8/
		for i in $(MAN1); do \
			$(INSTALL_DATA) ../man/$$i $(ROOT)$(MANDIR)/man1/; \
		done
		for i in $(MAN5); do \
			$(INSTALL_DATA) ../man/$$i $(ROOT)$(MANDIR)/man5/; \
		done
		for i in $(MAN8); do \
			$(INSTALL_DATA) ../man/$$i $(ROOT)$(MANDIR)/man8/; \
		done
ifeq ($(ROOT),)
		#
		# This part is skipped on Debian systems, the
		# debian.preinst script takes care of it.
		@if [ ! -p /dev/initctl ]; then \
		 echo "Creating /dev/initctl"; \
		 rm -f /dev/initctl; \
		 mknod -m 600 /dev/initctl p; fi
endif
