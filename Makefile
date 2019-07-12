CC=gcc
PROGS=snebu
SCRIPTS=snebu-client
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
all: $(PROGS)
snebu: snebu.c
	$(CC) $< -o $@ -l sqlite3 -l crypto -l lzo2 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
install: $(PROGS) $(SCRIPTS)
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f $(PROGS) $(SCRIPTS) $(DESTDIR)$(BINDIR)/
clean:
	rm -f $(PROGS)

