CC=gcc
PROGS=snebu
SCRIPTS=snebu-client
all: $(PROGS)
snebu: snebu.c
	$(CC) -o $@ -l sqlite3 -l crypto -l lzo2 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE $<
install: $(PROGS)
	cp -p $(PROGS) $(SCRIPTS) /usr/local/bin/
clean:
	rm -f $(PROGS)

