MANPAGES=bootlogd.8 fstab-decode.8 halt.8 init.8 initctl.5 initscript.5 inittab.5 \
killall5.8 last.1 lastb.1 logsave.8 mesg.1 mountpoint.1 pidof.8 poweroff.8 \
readbootlog.1 reboot.8 runlevel.8 shutdown.8 sulogin.8 telinit.8 utmpdump.1 \
wall.1

all install:
	sed --in-place=.orig --separate 's/\@VERSION\@/$(VERSION)/g' $(MANPAGES)

clean distclean:
	for man in $(MANPAGES) ; do \
	   if [ -f "$$man.orig" ] ; then mv "$$man.orig" "$$man" ; fi \
	done

