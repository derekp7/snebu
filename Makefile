CC=gcc
PROGS=snebu
SCRIPTS=snebu-client
CONFIGS=snebu.conf
PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
ETCDIR=/etc
all: $(PROGS)
%.o: %.c
	gcc -c $< -o $@ -Wall
tarlib.o: tarlib.h
tarcrypt.o: tarlib.h
snebu: snebu.o
	$(CC) $< -o $@ -l sqlite3 -l crypto -l lzo2 -Wall
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

