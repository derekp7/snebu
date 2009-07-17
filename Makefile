CC=gcc
PROGS=bklist_encode bklist_decode tarburst gentar
SCRIPTS=snebu.sh sbackup.sh
all: $(PROGS)
bklist_encode: bklist_encode.c
	$(CC) -o $@ $<
bklist_decode: bklist_decode.c
	$(CC) -o $@ $<
tarburst: tarburst.c
	$(CC) -o $@ -l ssl -D_FILE_OFFSET_BITS=64 $<
gentar: gentar.c
	$(CC) -o $@ -l ssl -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE $<
install: $(PROGS)
	cp -p $(PROGS) $(SCRIPTS) /usr/local/bin/
clean:
	rm -f $(PROGS)
