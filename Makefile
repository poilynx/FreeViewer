all clean:
	cd libpunch; $(MAKE) $@
	cd punchd; $(MAKE) $@
	cd libvncview; qmake; $(MAKE) $@
	cd test; $(MAKE) $@

.PHONY: all clean


