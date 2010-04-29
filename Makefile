all install clean distclean:
	$(MAKE) -C src $@

PACKAGE=sysvinit
VERSION=$(shell sed -rn '1s/.*[[:blank:]]\((.*)\)[[:blank:]].*/\1/p' doc/Changelog)
SVLOGIN=$(shell svn info | sed -rn '/Repository Root:/{ s|.*//(.*)\@.*|\1|p }')
ifeq (,$(findstring dsf,$(VERSION)))
	override VERSION := $(VERSION)dsf
endif
override TMP:=$(shell mktemp -d $(VERSION).XXXXXXXX)
override TARBALL:=$(TMP)/$(PACKAGE)-$(VERSION).tar.bz2
override SFTPBATCH:=$(TMP)/$(VERSION)-sftpbatch

upload: $(SFTPBATCH)
	@sftp -b $< $(SVLOGIN)@dl.sv.nongnu.org:/releases/$(PACKAGE)
	rm -rf $(TMP)

$(SFTPBATCH): $(TARBALL).sig
	@echo progress > $@
	@echo put $(TARBALL) >> $@
	@echo chmod 664 $(notdir $(TARBALL)) >> $@
	@echo put $(TARBALL).sig >> $@
	@echo chmod 664 $(notdir $(TARBALL)).sig >> $@
	@echo rm  $(PACKAGE)-latest.tar.bz2 >> $@
	@echo symlink $(notdir $(TARBALL)) $(PACKAGE)-latest.tar.bz2 >> $@
	@echo quit >> $@

$(TARBALL).sig: $(TARBALL)
	@gpg -q -ba --use-agent -o $@ $<

$(TARBALL): $(TMP)/$(PACKAGE)-$(VERSION)
	@tar --bzip2 --owner=nobody --group=nobody -cf $@ -C $(TMP) $(PACKAGE)-$(VERSION)

$(TMP)/$(PACKAGE)-$(VERSION): .svn
	svn export . $@
	@chmod -R a+r,u+w,og-w $@
	@find $@ -type d | xargs -r chmod a+rx,u+w,og-w
