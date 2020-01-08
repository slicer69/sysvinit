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
CFLAGS  ?= -O2
override CFLAGS += -ansi -fomit-frame-pointer -fstack-protector-strong -W -Wall -Wunreachable-code -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -D_XOPEN_SOURCE -D_GNU_SOURCE -DVERSION=\"$(VERSION)\"
override CFLAGS += $(shell getconf LFS_CFLAGS)
STATIC	=
MANDB	:= s@^\('\\\\\"\)[^\*-]*-\*- coding: [^[:blank:]]\+ -\*-@\1@

#
# Leave empty if the mountpoint(1) command from util-linux 2.20
# and above should be used, otherwise set it to yes.
#
MNTPOINT=

# For some known distributions we do not build all programs, otherwise we do.
BIN	=
SBIN	= init halt shutdown runlevel killall5 fstab-decode logsave
USRBIN	= last mesg readbootlog

MAN1	= last.1 lastb.1 mesg.1 readbootlog.1
MAN5	= initscript.5 inittab.5 initctl.5
MAN8	= halt.8 init.8 killall5.8 pidof.8 poweroff.8 reboot.8 runlevel.8
MAN8	+= shutdown.8 telinit.8 fstab-decode.8 logsave.8

ifeq ($(DISTRO),)
SBIN	+= sulogin bootlogd
USRBIN	+= utmpdump wall
MAN1	+= utmpdump.1 wall.1
MAN8	+= sulogin.8 bootlogd.8
endif

ifeq ($(DISTRO),Debian)
CPPFLAGS+= -DACCTON_OFF
SBIN	+= sulogin bootlogd
MAN8	+= sulogin.8 bootlogd.8
MANDB	:=
endif

ifeq ($(DISTRO),Owl)
USRBIN	+= wall
MAN1	+= wall.1
MANDB	:=
endif

ifeq ($(DISTRO),SuSE)
CPPFLAGS+= -DUSE_SYSFS -DSANE_TIO -DSIGINT_ONLYONCE -DUSE_ONELINE
SBIN	+= sulogin
USRBIN	+= utmpdump
MAN1	+= utmpdump.1
MAN8	+= sulogin.8
MANDB	:=
endif

ifeq ($(MNTPOINT),yes)
BIN	+= mountpoint
MAN1	+= mountpoint.1
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
  INITLIBS	+= -lselinux
  SULOGINLIBS	= -lselinux	
else
  SELINUX_DEF	=
  INITLIBS	=
  SULOGINLIBS	=
endif

# Additional libs for GNU libc.
ifneq ($(wildcard $(ROOT)/usr/lib*/libcrypt.*),)
  SULOGINLIBS	+= -lcrypt
endif

# Additional libs for GNU libc / multiarch on Debian based systems.
ifneq ($(wildcard $(ROOT)/usr/lib/*/libcrypt.*),)
ifneq ($(findstring -lcrypt, $(SULOGINLIBS)), -lcrypt)
  SULOGINLIBS	+= -lcrypt
endif
endif

all:		$(BIN) $(SBIN) $(USRBIN)

#%: %.o
#	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
#%.o: %.c
#	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^ -o $@

init:		LDLIBS += $(INITLIBS) $(STATIC)
init:		init.o init_utmp.o runlevellog.o

halt:		LDLIBS += $(STATIC)
halt:		halt.o ifdown.o hddown.o utmp.o runlevellog.o

last:		LDLIBS += $(STATIC)
last:		last.o

logsave:	LDLIBS += $(STATIC)
logsave:	logsave.o

mesg:		LDLIBS += $(STATIC)
mesg:		mesg.o

mountpoint:	LDLIBS += $(STATIC)
mountpoint:	mountpoint.o

utmpdump:	LDLIBS += $(STATIC)
utmpdump:	utmpdump.o

runlevel:	LDLIBS += $(STATIC)
runlevel:	runlevel.o runlevellog.o

sulogin:	LDLIBS += $(SULOGINLIBS) $(STATIC)
sulogin:	sulogin.o consoles.o

wall:		LDLIBS += $(STATIC)
wall:		dowall.o wall.o

shutdown:	LDLIBS += $(STATIC)
shutdown:	dowall.o shutdown.o utmp.o

bootlogd:	LDLIBS += -lutil $(STATIC)
bootlogd:	bootlogd.o

readbootlog:	LDLIBS += $(STATIC)
readbootlog:	readbootlog.o 

fstab-decode:	LDLIBS += $(STATIC)
fstab-decode:	fstab-decode.o

sulogin.o:	CPPFLAGS += $(SELINUX_DEF)
sulogin.o:	sulogin.c 

runlevellog.o:	runlevellog.h runlevellog.c paths.h

init.o:		CPPFLAGS += $(SELINUX_DEF)
init.o:		init.c init.h initreq.h paths.h reboot.h runlevellog.h runlevellog.c set.h 

utmp.o:		

init_utmp.o:	CPPFLAGS += -DINIT_MAIN
init_utmp.o:	utmp.c init.h initreq.h paths.h
		$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

bootlogd.o:	bootlogd.c bootlogd.h

readbootlog.o:	readbootlog.c
 
utmpdump.o:	utmpdump.c oldutmp.h

shutdown.o:	shutdown.c paths.h reboot.h initreq.h init.h

halt.o:		halt.c reboot.h paths.h runlevellog.c runlevellog.h

last.o:		last.c oldutmp.h

logsave.o:	logsave.c

consoles.o:	consoles.c consoles.h

cleanobjs:
		rm -f *.o *.bak

clean:		cleanobjs clobber

clobber:	cleanobjs
		rm -f $(BIN) $(SBIN) $(USRBIN)

distclean:	clobber

install:	all
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
		$(INSTALL_DIR) $(ROOT)/etc/inittab.d
		# $(INSTALL_EXEC) ../doc/initscript.sample $(ROOT)/etc/
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
		for man in $(MAN1); do \
			$(INSTALL_DATA) ../man/$$man $(ROOT)$(MANDIR)/man1/; \
			sed -i "1{ $(MANDB); }" $(ROOT)$(MANDIR)/man1/$$man ; \
		done
		for man in $(MAN5); do \
			$(INSTALL_DATA) ../man/$$man $(ROOT)$(MANDIR)/man5/; \
			sed -i "1{ $(MANDB); }" $(ROOT)$(MANDIR)/man5/$$man ; \
		done
		for man in $(MAN8); do \
			$(INSTALL_DATA) ../man/$$man $(ROOT)$(MANDIR)/man8/; \
			sed -i "1{ $(MANDB); }" $(ROOT)$(MANDIR)/man8/$$man ; \
		done
ifeq ($(ROOT),)
		#
		# This part is skipped on Debian systems, the
		# debian.preinst script takes care of it.
		@if [ ! -p /run/initctl ]; then \
		 echo "Creating /run/initctl"; \
		 rm -f /run/initctl; \
		 mknod -m 600 /run/initctl p; fi
endif
