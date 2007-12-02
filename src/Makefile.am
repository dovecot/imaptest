bin_PROGRAMS = imaptest

AM_CPPFLAGS = \
	-I$(dovecot_incdir) \
	-I$(dovecot_incdir)/src/lib \
	-I$(dovecot_incdir)/src/lib-mail \
	-I$(dovecot_incdir)/src/lib-imap

imaptest_SOURCES = \
	imaptest.c

imaptest_LDADD = \
	$(LIBICONV) \
	$(RAND_LIBS) \
	$(dovecotdir)/src/lib-storage/index/mbox/mbox-from.o \
	$(dovecotdir)/src/lib-imap/libimap.a \
	$(dovecotdir)/src/lib-mail/libmail.a \
	$(dovecotdir)/src/lib-charset/libcharset.a \
	$(dovecotdir)/src/lib/liblib.a
	