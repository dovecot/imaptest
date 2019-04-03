IMAP Server Tester
==================

ImapTest is a generic IMAP server compliancy tester that works with all IMAP servers. It supports:

 - Stress testing with state tracking. ImapTest sends random commands to the server and verifies that server's output looks correct.
 - Scripted testing where it runs a list of predefined scripted tests and verifies that server returns expected output.
 - Benchmarking

BUILD:

The current version of Imaptest requires dovecot 2.3 libraries to link successfully. To transfer the imaptest binary to a testserver it is
recommend to build the dovecot without shared libaries. 
If you want to use smtp instead of LMTP, it is recommend to apply the dovecot_patches/smtp_syntax.patch if your dovecot server version is < 2.3.

git checkout --recursive https://github.com/ceph-dovecot/imaptest.git

dovecot build:

cd core

git apply ../dovecot_patches/smtp_syntax.patch

./autogen.sh && ./configure --enable-maintainer-mode --without-shared-libs
make install

imaptest build:

./autogen.sh && ./configure --enable-maintainer-mode --with-dovecot=./core
make install

Please see https://imapwiki.org/ImapTest/ for more information.
