SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	version \
	ChangeLog \
	COPYING.MIT \
	pop3-profile.conf \
	profile.conf

if MAINTAINER_MODE
ChangeLog: .git/index
	git log > ChangeLog
endif

version:
	$(AM_V_GEN)$(top_srcdir)/build-aux/git-version-gen > $@
