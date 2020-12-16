CC=gcc
PROGS=snebu tarcrypt
SCRIPTS=snebu-client
CONFIGS=snebu.conf
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man
ETCDIR=/etc
all: $(PROGS)
%.o: %.c
	gcc -D_GNU_SOURCE -std=c99 -c $< -o $@ -Wall
tarlib.o: tarlib.h
tarcrypt.o: tarlib.h
snebu-submitfiles.o: tarlib.h
snebu-restore.o: tarlib.h

snebu: snebu-main.o snebu-newbackup.o tarlib.o snebu-submitfiles.o snebu-restore.o snebu-listbackups.o snebu-expire-purge.o snebu-permissions.o
	$(CC) -D_GNU_SOURCE -std=c99 $^ -o $@ -l sqlite3 -l crypto -l lzo2 -Wall
tarcrypt: tarcrypt.o tarlib.o
	$(CC) -D_GNU_SOURCE -std=c99 $^ -o $@ -l crypto -l ssl -l lzo2 -Wall
install: $(PROGS) $(SCRIPTS) $(CONFIGS)
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(ETCDIR)
	grep '^snebu:' /etc/passwd || useradd --system -m snebu
	cp -f $(PROGS) $(SCRIPTS) $(DESTDIR)$(BINDIR)/
	cp -f $(CONFIGS) $(DESTDIR)$(ETCDIR)/
	cp -f snebu.1 snebu-*.1 tarcrypt.1 $(MANDIR)/man1/

clean:
	rm -f $(PROGS) snebu-main.o snebu-newbackup.o tarlib.o snebu-submitfiles.o snebu-restore.o snebu-listbackups.o snebu-expire-purge.o snebu-permissions.o tarcrypt.o

