CC=gcc
PROGS=snebu
SCRIPTS=snebu-client
CONFIGS=snebu.conf
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
ETCDIR=/etc
all: $(PROGS)
snebu: snebu.c
	$(CC) $< -o $@ -l sqlite3 -l crypto -l lzo2 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall
install: $(PROGS) $(SCRIPTS) $(CONFIGS)
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(ETCDIR)
	grep '^snebu:' /etc/passwd || useradd --system snebu
	cp -f $(PROGS) $(SCRIPTS) $(DESTDIR)$(BINDIR)/
	cp -f $(CONFIGS) $(DESTDIR)$(ETCDIR)/

clean:
	rm -f $(PROGS)

