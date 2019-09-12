Name:		snebu
Version:	_VERSION_
Release:	_RELEASE_%{?dist}
Summary:	Simple Network Backup Utility

Group:		Applications/System
License:	GPLv3
URL:		http://www.snebu.com
Source0:	snebu-%{version}.tar.gz
Requires:	lzop


%description
Snebu is a backup utility which is designed to be easy to setup and use,
yet provide many features that are usually only found on high-end backup
programs.  Features a client-server architecture built around standard
tools (find, tar, ssh), file-level deduplication and compression, and
a backup catalog stored in an SQLite datbase file.


%prep
%setup -q


%build
make %{?_smp_mflags}


%install
mkdir -p %{buildroot}/usr/bin
make install PREFIX=/usr DESTDIR=%{buildroot}


%files
/usr/bin/snebu-client
%config /etc/snebu.conf
%attr(4550, snebu, snebu) /usr/bin/snebu
%doc readme.md COPYING.txt

%pre
grep '^snebu:' /etc/passwd || useradd --system -m snebu

%changelog
* Mon Sep 9 2019 Derek Pressnall <dspgh@needcaffeine.net>
- Updated to release 1.04
