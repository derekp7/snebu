Name:		snebu
Version:	_VERSION_
Release:	_RELEASE_%{?dist}
Summary:	Simple Network Backup Utility

Group:		Applications/System
License:	GPLv3
URL:		http://www.snebu.com
Source0:	snebu-%{version}.tar.gz
Patch1:		Makefile-Fedora.patch


%description
Snebu is a backup utility which is designed to be easy to setup and use,
yet provide many features that are usually only found on high-end backup
programs.  Features a client-server architecture built around standard
tools (find, tar, ssh), file-level deduplication and compression, and
a backup catalog stored in an SQLite datbase file.


%prep
%setup -q
%patch1 -p1 -b .Makefile


%build
make %{?_smp_mflags}


%install
mkdir -p %{buildroot}/usr/bin
make install DESTDIR=%{buildroot}


%files
/usr/bin/snebu
/usr/bin/snebu-client
%doc readme.md readme-snebu-client.txt COPYING.txt

%changelog

