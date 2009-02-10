bin_PROGRAMS = imaptest

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(dovecot_incdir)/src/lib-mail \
	-I$(dovecot_incdir)/src/lib-imap

imaptest_SOURCES = \
	checkpoint.c \
	client.c \
	client-state.c \
	commands.c \
	imaptest.c \
	mailbox.c \
	mailbox-source.c \
	mailbox-state.c \
	search.c \
	test-exec.c \
	test-parser.c

noinst_HEADERS = \
	checkpoint.h \
	client.h \
	client-state.h \
	commands.h \
	mailbox.h \
	mailbox-source.h \
	mailbox-state.h \
	search.h \
	settings.h \
	test-exec.h \
	test-parser.h

imaptest_LDADD = \
	$(LIBICONV) \
	$(RAND_LIBS) \
	$(dovecotdir)/src/lib-imap/libimap.a \
	$(dovecotdir)/src/lib-mail/libmail.a \
	$(dovecotdir)/src/lib-charset/libcharset.a \
	$(dovecotdir)/src/lib/liblib.a

EXTRA_DIST = \
	tests/append \
	tests/close \
	tests/copy \
	tests/default.mbox \
	tests/expunge \
	tests/expunge2 \
	tests/fetch \
	tests/fetch-body \
	tests/fetch-envelope \
	tests/fetch-envelope.mbox \
	tests/list \
	tests/listext \
	tests/search-addresses \
	tests/search-addresses.mbox \
	tests/search-body \
	tests/search-body.mbox \
	tests/search-context-update \
	tests/search-context-update2 \
	tests/search-date \
	tests/search-date.mbox \
	tests/search-flags \
	tests/search-header \
	tests/search-header.mbox \
	tests/search-intdate \
	tests/search-intdate.mbox \
	tests/search-sets \
	tests/search-size \
	tests/search-size.mbox \
	tests/select \
	tests/select.mbox \
	tests/sort-addresses \
	tests/sort-addresses.mbox \
	tests/sort-arrival \
	tests/sort-arrival.mbox \
	tests/sort-date \
	tests/sort-date.mbox \
	tests/sort-size \
	tests/sort-size.mbox \
	tests/sort-subject \
	tests/sort-subject.mbox \
	tests/store \
	tests/subscribe \
	tests/thread \
	tests/thread2 \
	tests/thread2.mbox \
	tests/thread3 \
	tests/thread3.mbox \
	tests/thread4 \
	tests/thread4.mbox \
	tests/thread5 \
	tests/thread5.mbox \
	tests/thread6 \
	tests/thread6.mbox \
	tests/thread7 \
	tests/thread7.mbox \
	tests/thread8 \
	tests/thread8.mbox \
	tests/thread.mbox
