bin_PROGRAMS = imaptest

AM_CPPFLAGS = $(LIBDOVECOT_INCLUDE) $(LIBDOVECOT_SMTP_INCLUDE)

imaptest_SOURCES = \
	checkpoint.c \
	client.c \
	client-state.c \
	commands.c \
	imap-client.c \
	imaptest.c \
	imaptest-lmtp.c \
	mailbox.c \
	mailbox-source.c \
	mailbox-source-mbox.c \
	mailbox-source-random.c \
	mailbox-state.c \
	pop3-client.c \
	profile.c \
	profile-parse.c \
	search.c \
	test-exec.c \
	test-parser.c \
	user.c

noinst_HEADERS = \
	checkpoint.h \
	client.h \
	client-state.h \
	commands.h \
	imap-client.h \
	imaptest-lmtp.h \
	mailbox.h \
	mailbox-source.h \
	mailbox-source-private.h \
	mailbox-state.h \
	pop3-client.h \
	profile.h \
	search.h \
	settings.h \
	test-exec.h \
	test-parser.h \
	user.h

imaptest_CFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
imaptest_LDADD = $(LIBDOVECOT_SMTP) $(LIBDOVECOT) $(LIBDOVECOT_SSL) -lm $(BINARY_LDFLAGS) -lcurl
imaptest_DEPENDENCIES = $(LIBDOVECOT_SMTP_DEPS) $(LIBDOVECOT_DEPS) $(LIBDOVECOT_SSL_DEPS)

EXTRA_DIST = \
	tests/append \
	tests/close \
	tests/copy \
	tests/default.mbox \
	tests/expunge \
	tests/expunge2 \
	tests/fetch \
	tests/fetch-body \
	tests/fetch-body.mbox \
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
	tests/broken/search-intdate \
	tests/broken/search-intdate.mbox \
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
