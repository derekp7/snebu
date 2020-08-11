CC=gcc
PROGS=snebu tarcrypt
SCRIPTS=snebu-client
CONFIGS=snebu.conf
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
ETCDIR=/etc
all: $(PROGS)
%.o: %.c
	gcc -pg -c $< -o $@ -Wall
tarlib.o: tarlib.h
tarcrypt.o: tarlib.h
snebu-submitfiles.o: tarlib.h
snebu-restore.o: tarlib.h

snebu: snebu-main.o snebu-newbackup.o tarlib.o snebu-submitfiles.o snebu-restore.o snebu-listbackups.o snebu-expire-purge.o snebu-permissions.o
	$(CC) $^ -o $@ -l sqlite3 -l crypto -l lzo2 -Wall
tarcrypt: tarcrypt.o tarlib.o
	$(CC) $^ -o $@ -l crypto -l ssl -l lzo2 -Wall
install: $(PROGS) $(SCRIPTS) $(CONFIGS)
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(ETCDIR)
	grep '^snebu:' /etc/passwd || useradd --system -m snebu
	cp -f $(PROGS) $(SCRIPTS) $(DESTDIR)$(BINDIR)/
	cp -f $(CONFIGS) $(DESTDIR)$(ETCDIR)/

clean:
	rm -f $(PROGS)

