SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	ChangeLog \
	COPYING.MIT \
	profile.conf

if MAINTAINER_MODE
ChangeLog: .hg/dirstate
	hg log --style=changelog > ChangeLog
endif
