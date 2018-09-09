PACKAGE=sysvinit
VERSION=$(shell sed -rn '1s/.*[[:blank:]]\((.*)\)[[:blank:]].*/\1/p' doc/Changelog)

all install clean distclean:
	@rm -f $(PACKAGE)-$(VERSION).tar.xz $(PACKAGE)-$(VERSION).tar.xz.sig
	$(MAKE) VERSION=$(VERSION) -C src $@

GITLOGIN=$(shell git remote -v | head -n 1 | cut -f 1 -d '@' | sed 's/origin\t//g')
override TMP:=$(shell mktemp -du $(VERSION).XXXXXXXX)
override TARBALL:=$(TMP)/$(PACKAGE)-$(VERSION).tar.xz
override SFTPBATCH:=$(TMP)/$(VERSION)-sftpbatch
SOURCES=contrib  COPYING  COPYRIGHT  doc  Makefile  man  README  src

dist: $(TARBALL).sig
	@cp $(TARBALL) .
	@cp $(TARBALL).sig .
	@echo "tarball $(PACKAGE)-$(VERSION).tar.xz ready"
	rm -rf $(TMP)

upload: $(SFTPBATCH)
	echo @sftp -b $< $(GITLOGIN)@dl.sv.nongnu.org:/releases/$(PACKAGE)
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
	@tar --exclude=.git --owner=nobody --group=nogroup -cJf $@ -C $(TMP) $(PACKAGE)-$(VERSION)

$(TMP)/$(PACKAGE)-$(VERSION): distclean
	@mkdir -p $(TMP)/$(PACKAGE)-$(VERSION)
	@cp -R $(SOURCES) $(TMP)/$(PACKAGE)-$(VERSION)/ 
	@chmod -R a+r,u+w,og-w $@
	@find $@ -type d | xargs -r chmod a+rx,u+w,og-w
