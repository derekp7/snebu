CC=gcc
PKGNAME=snebu
PROGS=snebu tarcrypt
SCRIPTS=snebu-client
CONFIGS=snebu.conf
SOWNER=snebu
SGROUP=snebu
MAN1=snebu.1 snebu-client.1 snebu-client-backup.1 snebu-client-listbackups.1 snebu-client-restore.1 snebu-client-validate.1 snebu-expire.1 snebu-listbackups.1 snebu-newbackup.1 snebu-permissions.1 snebu-purge.1 snebu-restore.1 snebu-submitfiles.1 tarcrypt.1
MAN5=snebu-client.conf.5 snebu-client-plugin.5
DOC=readme.md snebu*.adoc
LICENSE=COPYING.txt
PREFIX=/usr/local
DATADIR=${PREFIX}/share
BINDIR=$(PREFIX)/bin
MANDIR=$(DATADIR)/man
DOCDIR=$(DATADIR)/doc
ETCDIR=/etc
all: $(PROGS)
%.o: %.c
	$(CC) -D_GNU_SOURCE -std=c99 -c $< -o $@ -Wall $(CFLAGS)
tarlib.o: tarlib.h
tarcrypt.o: tarlib.h
snebu-submitfiles.o: tarlib.h
snebu-restore.o: tarlib.h

snebu: snebu-main.o snebu-newbackup.o tarlib.o snebu-submitfiles.o snebu-restore.o snebu-listbackups.o snebu-expire-purge.o snebu-permissions.o
	$(CC) -D_GNU_SOURCE -std=c99 $^ -o $@ -l sqlite3 -l crypto -l lzo2 -Wall $(CFLAGS) $(LDFLAGS)
tarcrypt: tarcrypt.o tarlib.o
	$(CC) -D_GNU_SOURCE -std=c99 $^ -o $@ -l crypto -l ssl -l lzo2 -Wall $(CFLAGS) $(LDFLAGS)
install: $(PROGS) $(SCRIPTS) $(CONFIGS)
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(ETCDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)$(DOCDIR)/$(PKGNAME)
	install -p -m 755 $(PROGS) $(SCRIPTS) $(DESTDIR)$(BINDIR)/
	install -p -m 644  $(CONFIGS) $(DESTDIR)$(ETCDIR)/
	install -p -m 644 $(addprefix docs/,$(MAN1)) $(DESTDIR)$(MANDIR)/man1
	install -p -m 644 $(addprefix docs/,$(MAN5)) $(DESTDIR)$(MANDIR)/man5
	install -p -m 644 $(addprefix docs/,$(DOC)) $(DESTDIR)$(DOCDIR)/$(PKGNAME)
	cd ..

clean:
	rm -f $(PROGS) snebu-main.o snebu-newbackup.o tarlib.o snebu-submitfiles.o snebu-restore.o snebu-listbackups.o snebu-expire-purge.o snebu-permissions.o tarcrypt.o

