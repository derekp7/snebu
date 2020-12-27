Name:		snebu
Version:	_VERSION_
Release:	_RELEASE_%{?dist}
Summary:	Simple Network Backup Utility

Group:		Applications/System
License:	GPLv3
URL:		https://www.snebu.com
Source0:	https://github.com/derekp7/snebu/releases/download/v1.1.0/snebu-1.1.0.tar.gz
Requires:	lzop
BuildRequires:	lzo-devel openssl-devel sqlite-devel gcc systemd-rpm-macros


%description
Snebu is a backup utility which is designed to be easy to setup and use,
yet provide many features that are usually only found on high-end backup
programs.  Features a client-server architecture built around standard
tools (find, tar, ssh), file-level de-duplication and compression, and
a backup catalog stored in an SQLite database file.

%global debug_package %{nil}

%prep
%setup -q


%build
make %{?_smp_mflags}


%pre
grep '^snebu:' /etc/passwd || useradd -r -U -d /var/lib/snebu snebu

%install
mkdir -p %{buildroot}/usr/bin
make install PREFIX=/usr DESTDIR=%{buildroot}
mkdir -p %{buildroot}/var/lib/snebu/vault
mkdir -p %{buildroot}/var/lib/snebu/catalog


%files
/usr/bin/snebu-client
/usr/bin/tarcrypt
%config /etc/snebu.conf
%attr(4750, snebu, snebu) /usr/bin/snebu
%doc /usr/share/doc/snebu/readme.md
%doc /usr/share/doc/snebu/snebu.adoc
%doc /usr/share/doc/snebu/COPYING.txt
/usr/share/man/man1/*
/usr/share/man/man5/*
%attr(0750, snebu, snebu) /var/lib/snebu


%changelog
* Sat Dec 26 2020 Derek Pressnall <dspgh@needcaffeine.net> - 1.1.0
- Updated to release 1.1.0
* Mon Sep 9 2019 Derek Pressnall <dspgh@needcaffeine.net> - 1.04
- Updated to release 1.04
