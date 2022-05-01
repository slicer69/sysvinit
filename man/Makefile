MANPAGES=bootlogd.8 fstab-decode.8 halt.8 init.8 initctl.5 initscript.5 inittab.5 \
killall5.8 last.1 lastb.1 logsave.8 mesg.1 mountpoint.1 pidof.8 poweroff.8 \
readbootlog.1 reboot.8 runlevel.8 shutdown.8 sulogin.8 telinit.8 utmpdump.1 \
wall.1

LANGUAGES_DIST =`sed -ne 's/^.*\[po4a_langs\] \(.*\)$/\1/p' po/po4a.cfg`
LANGUAGES=$(LANGUAGES_DIST)
LANGUAGES=de es fi fr hu id pl

VERSION?=1.2.3

PO4A_OPTS = --previous --srcdir po/ --destdir po/ --no-backups \
            --package-name sysvinit --package-version $(VERSION) \
            --msgid-bugs-address "Your Bugmail <mail@example.com>"

translated:
	po4a $(PO4A_OPTS) po/po4a.cfg

all install: translated
	sed --in-place=.orig --separate 's/\@VERSION\@/$(VERSION)/g' $(MANPAGES)

clean distclean:
	for man in $(MANPAGES) ; do \
	   if [ -f "$$man.orig" ] ; then mv "$$man.orig" "$$man" ; fi \
	done  
	for lang in $(LANGUAGES) ; do rm -rf "po/$$lang" ; done

