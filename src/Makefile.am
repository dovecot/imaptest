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
	imap-args.c \
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
	imap-args.h \
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
	