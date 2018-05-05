all install clean distclean:
	$(MAKE) -C src $@

PACKAGE=sysvinit
VERSION=$(shell git describe --tags --abbrev=0 HEAD 2>/dev/null)
GITLOGIN=$(shell git remote -v | head -n 1 | cut -f 1 -d '@' | sed 's/origin\t//g')
override TARBALL=$(PACKAGE)-$(VERSION).tar.xz
override TARBALL_LATEST=$(PACKAGE)-latest.tar.xz
override SFTPBATCH=upload-$(VERSION)-sftpbatch

dist: $(TARBALL)
	@echo "tarball $(TARBALL) ready"

upload: $(SFTPBATCH)
	echo @sftp -b $< $(GITLOGIN)@dl.sv.nongnu.org:/releases/$(PACKAGE)

$(SFTPBATCH): $(TARBALL).sig
	@echo progress > $@
	@echo put $(TARBALL) >> $@
	@echo chmod 664 $(notdir $(TARBALL)) >> $@
	@echo put $(TARBALL).sig >> $@
	@echo chmod 664 $(notdir $(TARBALL)).sig >> $@
	@echo rm  $(TARBALL_LATEST) >> $@
	@echo symlink $(notdir $(TARBALL)) $(TARBALL_LATEST) >> $@
	@echo quit >> $@

$(TARBALL).sig: $(TARBALL)
	@gpg -q -ba --use-agent -o $@ $<

$(TARBALL): .git
	@git archive --prefix=$(PACKAGE)-$(VERSION)/ $(VERSION) -o $(TARBALL)
