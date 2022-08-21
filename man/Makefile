MANPAGES=bootlogd.8 fstab-decode.8 halt.8 init.8 initctl.5 initscript.5 inittab.5 \
killall5.8 last.1 lastb.1 logsave.8 mesg.1 mountpoint.1 pidof.8 poweroff.8 \
readbootlog.1 reboot.8 runlevel.8 shutdown.8 sulogin.8 telinit.8 utmpdump.1 \
wall.1

PO4A := $(shell command -v po4a 2> /dev/null)

PO4A_OPTS = --previous --srcdir po/ --destdir ./ --no-backups --stamp \
            --package-name sysvinit --package-version $(VERSION) \
            --msgid-bugs-address "Jesse <jsmith@resonatingmedia.com>"

all:
	sed --in-place=.orig --separate 's/\@VERSION\@/$(VERSION)/g' $(MANPAGES)
ifdef PO4A
	po4a $(PO4A_OPTS) po/po4a.cfg
else
	@echo 'Install po4a to build translated manpages'
endif

# Installation recipes are in ../src/Makefile
install: all

clean distclean:
	for man in $(MANPAGES) ; do \
	   if [ -f "$$man.orig" ] ; then mv "$$man.orig" "$$man" ; fi \
	done
	for lang in $(LANGUAGES) ; do rm -rf "$$lang" "$$lang.po" ; done

