#
# spec file for package dovecot22-rados-plugins
#
# Copyright (c) 2017-2018 Tallence AG and the authors
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License version 2.1, as published by the Free Software
# Foundation.  See file COPYING.

%{!?lib_curl: %define lib_curl libcurl4}
%{!?dovecot_src: %define dovecot_src core}

Name:		imaptest
Summary:	Imaptest fork
Version:	0.0.2
Release:	0%{?dist}
URL:		https://github.com/ceph-dovecot/imaptest
Group:		Productivity/Networking/Email/Servers
License:	LGPL-2.1
Source:		%{name}_%{version}-%{release}.tar.gz
Provides:	imaptest = %{version}-%{release}
Conflicts:	otherproviders(imaptest)

BuildRoot:	%{buildroot}
BuildRequires:	%lib_curl
BuildRequires:	git
BuildRequires:	gcc
BuildRequires:	libtool
BuildRequires:	pkg-config
BuildRequires:  libtool
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  wget

%description

ImapTest is a fork of a generic IMAP server compliancy tester that works with all IMAP servers. It supports:

-    Stress testing with state tracking. ImapTest sends random commands to the server and verifies that server's output looks correct.
-    Scripted testing where it runs a list of predefined scripted tests and verifies that server returns expected output.
-    Benchmarking

Please see https://imapwiki.org/ImapTest/ for more information.

%prep
%setup -q

%build
export CFLAGS="%{optflags}"
export CFLAGS="$CFLAGS -fpic -DPIC"

git submodule update --init
#build dovecot with static libs
cd core
# apply dovecot patch
git apply ../dovecot_patches/smtp_syntax.patch

./autogen.sh
%configure \
        --enable-maintainer-mode \
        --without-shared-libs
%{__make}
cd ..
./autogen.sh
PANDOC=FALSE %configure \
	--enable-maintainer-mode \
	--with-dovecot=%{dovecot_src}
%{__make}

%install
%makeinstall

# clean up unused files
find src -type f -name \*.la -delete
find src -type f -name \*.a -delete
find src -type f -name \*.o -delete

#%clean
#%makeclean

%files
%defattr(-,root,root)
/usr/bin/imaptest


%changelog

