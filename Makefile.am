SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	ChangeLog \
	COPYING.MIT

if MAINTAINER_MODE
ChangeLog: .hg/dirstate
	hg log --style=changelog > ChangeLog
endif
