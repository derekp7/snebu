#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <time.h>
#include <getopt.h>
#include <sqlite3.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "tarlib.h"

int submitfiles2(int out);
char *stresc(char *src, char **target);
char *strescb(char *src, char **target, int len);
char *strunesc(char *src, char **target);
void stresc_free(char **target);
struct ringbuf *rbinit(size_t s);
size_t rbwrite(void *buf, size_t b, size_t c, struct ringbuf *r);
size_t rbread(void *buf, size_t b, size_t c, struct ringbuf *r);
size_t rbrewind(struct ringbuf *r, size_t c);
size_t rbsize(struct ringbuf *r);
size_t rbused(struct ringbuf *r);
size_t rbavail(struct ringbuf *r);
void rbfree(struct ringbuf *r);
int pipebuf(int *in,  int *out);
void usage();
int checkperm(sqlite3 *bkcatalog, char *action, char *backupname);
extern sqlite3 *bkcatalog;
extern struct {
    char *vault;
    char *meta;
} config;
char *EncodeBlock2(char *out, char *in, int m, int *n);
char *DecodeBlock2(char *out, char *in, int m, int *n);
double ftime();
int flush_received_files(sqlite3 *bkcatalog, int verbose, int bkid,
    unsigned long long est_size,  unsigned long long *bytes_read);
int submitfiles_tmptables(sqlite3 *bkcatalog, int bkid);
sqlite3 *opendb();
long int strtoln(char *nptr, char **endptr, int base, int len);
void update_status(unsigned long long total_bytes_received, unsigned long long est_size, char *cur_filename, time_t cur_time, time_t start_time, char indicator);

void *safe_malloc(size_t size);
#define malloc(SIZE) safe_malloc(SIZE)

struct {
    unsigned long long unit;
    char *label;
} display_units [] = {
    { 1, "B" },
    { 1000, "KB" },
    { 1000000, "MB" },
    { 1000000000, "GB" },
    { 1000000000000, "TB" },
};

int submitfiles(int argc, char **argv)
{
    int in = -1;
    int out = -1;
    char *inbuf = NULL;
    size_t len = 0;
    int optc;
    char bkname[128];
    char datestamp[128];
    int foundopts = 0;
    int verbose = 0;
    FILE *metadata;
    char **mdfields = NULL;
    char *sqlstmt = NULL;
    sqlite3_stmt *sqlres;
    char *sqlerr = NULL;
    sqlite3_stmt *inbfrec;
    long cipherid = 0;
    char *xattru = NULL;
    int xattrn;
    char *paxdata;
    int paxdatalen;
    int cipher_record;
    char *filenameu = NULL;
    char *linknameu = NULL;
    unsigned long long linkedfiles_bytes = 0;
    char *eprvkeyu = NULL;
    char *pubkeyu = NULL;
    char *commentu = NULL;

    struct option longopts[] = {
        { "name", required_argument, NULL, 'n' },
        { "datestamp", required_argument, NULL, 'd' },
        { "verbose", no_argument, NULL, 'v' },
        { NULL, no_argument, NULL, 0 }
    };

    struct cryptinfo_s {
	int keynum;
	char *hmac;
    };
    char *keygroups = NULL;
    char **keygroupsp = NULL;

    int longoptidx;
    int numkeys = 0;
    struct cryptinfo_s *cryptinfo = NULL;
    int cryptinfo_n = 0;
    char xattr_varstring[1024];
    int bkid;
    unsigned long long est_size = 0;
    int est_files = 0;
    int tot_files = 0;

    while ((optc = getopt_long(argc, argv, "n:d:v", longopts, &longoptidx)) >= 0)
        switch (optc) {
            case 'n':
                strncpy(bkname, optarg, 127);
                bkname[127] = 0;
                foundopts |= 1;
                break;
            case 'd':
                strncpy(datestamp, optarg, 127);
                datestamp[127] = 0;
                foundopts |= 2;
                break;
            case 'v':
                verbose += 1;
                foundopts |= 4;
                break;
            default:
                usage();
                return(1);
        }
    if ((foundopts & 3) != 3) {
        fprintf(stderr, "Didn't find all arguments %d\n", foundopts);
        usage();
        return(1);
    }

    pipebuf(&in, &out);
    submitfiles2(in);
    opendb(bkcatalog);

    if (checkperm(bkcatalog, "backup", bkname)) {
        sqlite3_close(bkcatalog);
        return(1);
    }

    sqlite3_prepare_v2(bkcatalog,
        (sqlstmt = sqlite3_mprintf("select backupset_id from backupsets  "
            "where name = '%q' and serial = '%q'",
            bkname, datestamp)), -1, &sqlres, 0);
    if (sqlite3_step(sqlres) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
    }
    else {
        fprintf(stderr, "bkid not found 1: %s\n", sqlstmt);
        return(1);
    }
    sqlite3_free(sqlstmt);
    sqlite3_finalize(sqlres);

    sqlite3_prepare_v2(bkcatalog,
        (sqlstmt = sqlite3_mprintf("select sum(size)  "
            "from needed_file_entities where backupset_id = %d",
            bkid)), -1, &sqlres, 0);
    sqlite3_free(sqlstmt);
    if (sqlite3_step(sqlres) == SQLITE_ROW) {
        est_size = sqlite3_column_int64(sqlres, 0);
    }
    else
        est_size = 0;
    sqlite3_finalize(sqlres);

    sqlite3_prepare_v2(bkcatalog,
        (sqlstmt = sqlite3_mprintf("select count(*)  "
            "from needed_file_entities where backupset_id = %d",
            bkid)), -1, &sqlres, 0);
    sqlite3_free(sqlstmt);
    if (sqlite3_step(sqlres) == SQLITE_ROW) {
        est_files = sqlite3_column_int64(sqlres, 0);
    }
    sqlite3_finalize(sqlres);

    int b_total_unit = 0;
    for (int i = 0; i < sizeof(display_units) / sizeof(*display_units); i++)
	if (est_size >= display_units[i].unit)
	    b_total_unit = i;

    submitfiles_tmptables(bkcatalog, bkid);
    metadata = fdopen(out, "r");

    sqlstmt = sqlite3_mprintf(
        "insert or replace into received_file_entities_t  "
        "(backupset_id, ftype, permission, user_name, user_id,  "
        "group_name, group_id, size, sha1, datestamp, filename, extdata, xheader)  "
        "values (@bkid, @ftype, @mode, @auid, @nuid, @agid,  "
        "@ngid, @filesize, @sha1, @modtime, @filename, @linktarget, @xheader)");

    sqlite3_prepare_v2(bkcatalog, sqlstmt, -1, &inbfrec, 0);
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog,
        "create temporary table if not exists temp_cipher_detail "
        "as select * from cipher_detail where 0", 0, 0, &sqlerr);
    if (sqlerr != 0) {
        fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
        sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
        "create temporary table if not exists temp_key_map ( "
	"keyposition	integer, "
	"id		integer, "
	"constraint temp_key_map_c1 unique ( "
	"keyposition, id))", 0, 0, &sqlerr);
    if (sqlerr != 0) {
        fprintf(stderr, "%s\n", sqlerr);
        sqlite3_free(sqlerr);
    }

    int inlen = 0;
    unsigned long long  total_bytes_received = 0;
    double start_time = ftime();
    double lastupdate_time = 0;
    double lastflush_time = start_time;
    double curtime = ftime();

    if (verbose >= 1)
	fprintf(stderr, "Transfering files\n");
    if (verbose >= 1)
	fprintf(stderr, "Estimated backup size: %6.2f %s\n\n",
	    (double) est_size / display_units[b_total_unit].unit,
	    display_units[b_total_unit].label);

    while ((inlen = getline(&inbuf, &len, metadata)) > 0) {
	for (int i = inlen - 1; i > 0; i--)
	    if (inbuf[i] == '\n') {
		inbuf[i] = '\0';
		break;
	    }
	parse(inbuf, &mdfields, '\t');
	// Record encryption key data from global header
	if (strcmp(mdfields[0], "0") == 0) {
	    if (strtol(mdfields[1], NULL, 10) + 1 > numkeys)
		numkeys = strtol(mdfields[1], NULL, 10) + 1;
	    strunesc(mdfields[3], &eprvkeyu);
	    strunesc(mdfields[4], &pubkeyu);
	    strunesc(mdfields[6], &commentu);
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into cipher_master (pkfp, eprivkey, pubkey, hmackeyhash, comment) "
		"values ('%q', '%q', '%q', '%q', '%q')", mdfields[2], eprvkeyu, pubkeyu,
		mdfields[5], commentu)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	    // get the primary key (cipherid) of recorded key data
	    if (sqlite3_prepare_v2(bkcatalog,
		sqlstmt = sqlite3_mprintf("select cipherid from cipher_master "
		"where pkfp = '%q' and eprivkey = '%q' and pubkey = '%q' "
		"and hmackeyhash = '%q' and comment = '%q'", mdfields[2], eprvkeyu, pubkeyu,
		mdfields[5], commentu), -1, &sqlres, 0) == SQLITE_OK) {
		sqlite3_free(sqlstmt);
		if (sqlite3_step(sqlres) == SQLITE_ROW) {
		    cipherid = sqlite3_column_int(sqlres, 0);
		}
		else {
		    fprintf(stderr, "Cipher key recording failure\n");
		    exit(1);
		}
		sqlite3_finalize(sqlres);
	    }
	    // temporary map of inbound key number and recorded key
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into temp_key_map (keyposition, id)"
		"values (%d, %d)", strtol(mdfields[1], NULL, 10), cipherid)), 0, 0, 0);
	    sqlite3_free(sqlstmt);
	    if (numkeys > cryptinfo_n) {
		if (cryptinfo == NULL)
		    cryptinfo = malloc(sizeof(struct cryptinfo_s) * numkeys);
		else
		    cryptinfo = realloc(cryptinfo, sizeof(struct cryptinfo_s) * numkeys);
		for (int i = cryptinfo_n; i < numkeys; i++) {
		    cryptinfo[i].hmac = NULL;
		}
		cryptinfo_n = numkeys;
	    }
	}
	else if (strcmp(mdfields[0], "1") == 0) {
	    if (xattru == NULL)
		xattru = dmalloc((int) (strlen(mdfields[13]) * 3 / 4));
	    else
		if (dmalloc_size(xattru) < ((int) (strlen(mdfields[13]) * 3 / 4)))
		    xattru = drealloc(xattru, (int) (strlen(mdfields[13]) * 3 / 4));
	    DecodeBlock2(xattru, mdfields[13], strlen(mdfields[13]), &xattrn);
	    cipher_record = 0;
	    if (getpaxvar(xattru, xattrn, "TC.cipher", &paxdata, &paxdatalen) == 0) {
		cipher_record = 1;
		cpypaxvarstr(xattru, xattrn, "TC.keygroup", &keygroups);
		parse(keygroups, &keygroupsp, '|');
		for (int i = 0; keygroupsp[i] != NULL; i++) {
		    int n = strtol(keygroupsp[i], NULL, 10);
		    if (n < numkeys) {
			cryptinfo[n].keynum = n;
			if (numkeys > 1)
			    snprintf(xattr_varstring, 1024, "TC.hmac.%d", n);
			else
			    snprintf(xattr_varstring, 1024, "TC.hmac");
			cpypaxvarstr(xattru, xattrn, xattr_varstring, &(cryptinfo[n].hmac));
			delpaxvar(&xattru, &xattrn, xattr_varstring);
		    }
		}
	    }
	    delpaxvar(&xattru, &xattrn, "atime");
	    delpaxvar(&xattru, &xattrn, "TC.segmented.header");
            sqlite3_bind_int(inbfrec, 1, bkid);
            sqlite3_bind_text(inbfrec, 2, mdfields[1], -1, SQLITE_STATIC);
            sqlite3_bind_text(inbfrec, 3, mdfields[2], -1, SQLITE_STATIC);
            sqlite3_bind_text(inbfrec, 4, mdfields[3], -1, SQLITE_STATIC);
            sqlite3_bind_int(inbfrec, 5, strtol(mdfields[4], NULL, 10));
            sqlite3_bind_text(inbfrec, 6, mdfields[5], -1, SQLITE_STATIC);
            sqlite3_bind_int(inbfrec, 7, strtol(mdfields[6], NULL, 10));
            sqlite3_bind_int64(inbfrec, 8, atoll(mdfields[7]));
            sqlite3_bind_text(inbfrec, 9, mdfields[8], -1, SQLITE_STATIC);
            sqlite3_bind_int(inbfrec, 10, strtol(mdfields[9], NULL, 10));
            strunesc(mdfields[10], &filenameu);
            sqlite3_bind_text(inbfrec, 11, filenameu, -1, SQLITE_STATIC);
            strunesc(mdfields[11], &linknameu);
            sqlite3_bind_text(inbfrec, 12, linknameu, -1, SQLITE_STATIC);
            sqlite3_bind_blob(inbfrec, 13, xattru, xattrn, SQLITE_STATIC);
            if (! sqlite3_step(inbfrec)) {
                fprintf(stderr, "Error inserting metadata record into temporary table\n"); ;
                exit(1);
            }
	    sqlite3_int64 fileid = sqlite3_last_insert_rowid(bkcatalog);
	    total_bytes_received += atoll(mdfields[7]);
	    tot_files++;

            sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
                "insert or ignore into diskfiles_t (sha1, extension)  "
                "values ('%q', '%q')", mdfields[8], strcmp(mdfields[1], "E") == 0 ? "enc" : strcmp(mdfields[1], "0") == 0 || strcmp(mdfields[1], "S") == 0 ? "lzo" : "" )), 0, 0, &sqlerr);
            if (sqlerr != 0) {
                fprintf(stderr, "%s\n", sqlerr);
                sqlite3_free(sqlerr);
            }
	    sqlite3_free(sqlstmt);
	    if (cipher_record == 1) {
		for (int i = 0; keygroupsp[i] != NULL; i++) {
		    int n = strtol(keygroupsp[i], NULL, 10);
		    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
			"insert or ignore into temp_cipher_detail (file_id, keynum, hmac) "
			"values (%d, %d, '%q')", fileid,  cryptinfo[n].keynum,
			cryptinfo[n].hmac)), 0, 0, &sqlerr);
		    if (sqlerr != 0) {
			fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
			sqlite3_free(sqlerr);
		    }
		    sqlite3_free(sqlstmt);
		}
	    }
            sqlite3_reset(inbfrec);
	    // Update status line

	    if ((curtime = ftime()) > lastupdate_time + 1 || lastupdate_time == 0) {
		lastupdate_time = curtime;
		if ((curtime = ftime()) > lastflush_time + 5) {
		    if (verbose >= 1)
			update_status(total_bytes_received, est_size, mdfields[10], curtime, start_time, '*');
		    flush_received_files(bkcatalog, verbose, bkid, est_size, &linkedfiles_bytes);
		    total_bytes_received += linkedfiles_bytes;
		    lastflush_time = curtime;
		}
		if (verbose >= 1)
		    update_status(total_bytes_received, est_size, mdfields[10], curtime, start_time, ' ');
	    }
	}
	else if (strcmp(mdfields[0], "2") == 0) {
	    if ((curtime = ftime()) > lastupdate_time + 1 || lastupdate_time == 0) {
		lastupdate_time = curtime;
		    if (verbose >= 1)
			update_status(total_bytes_received + atoll(mdfields[2]), est_size, mdfields[1], curtime, start_time, '+');
	    }
	}
	inbuf[0] = '\0';
    }


    free(inbuf);
    dfree(keygroups);
    dfree(keygroupsp);
    dfree(mdfields);
    dfree(eprvkeyu);
    dfree(pubkeyu);
    dfree(commentu);
    for (int i = 0; i < numkeys; i++) {
	dfree(cryptinfo[i].hmac);
    }
    free(cryptinfo);
    dfree(xattru);
    dfree(filenameu);
    dfree(linknameu);
    sqlite3_finalize(inbfrec);
    if (verbose >= 1)
	update_status(total_bytes_received, est_size, "Completed", curtime, start_time, '*');
    flush_received_files(bkcatalog, verbose, bkid, est_size, &linkedfiles_bytes);
    total_bytes_received += linkedfiles_bytes;
    if (verbose >= 1) {
	update_status(total_bytes_received, est_size, "Completed", curtime, start_time, ' ');
	fprintf(stderr, "\n");
    }
    if (verbose >= 1)
	fprintf(stderr, "%6.2f %s in %d files requested,\n",
	    (double) est_size / display_units[b_total_unit].unit,
	    display_units[b_total_unit].label, est_files);
    int b_received_unit = 0;
    for (int i = 0; i < sizeof(display_units) / sizeof(*display_units); i++)
        if (total_bytes_received >= display_units[i].unit)
            b_received_unit = i;

    if (verbose >= 1)
	fprintf(stderr, "%6.2f %s in %d files received.\n",
	    (double) total_bytes_received / display_units[b_received_unit].unit,
	    display_units[b_received_unit].label, tot_files);
    fclose(metadata);
    sqlite3_close(bkcatalog);


    return(0);
}

int submitfiles2(int out_h)
{
    struct filespec fs;
    char *tmpfiledir = config.vault;
    char *destdir = config.vault;
    char destdir2[3];
    char tmpfilepath[1024];
    char targetdir[1024];
    char targetpath[1024];
    struct stat tmpfstat;
    size_t sizeremaining;
    char *paxdata;
    int paxdatalen;
    int curtmpfile;
    FILE *curfile;
    struct tarsplit_file *tsf;
    size_t c;
    size_t bufsize = 256 * 1024;
    char databuf[bufsize];
    int padding;
    char *escfname = NULL;
    char *esclname = NULL;
    char *escxheader = NULL;
    struct lzop_file *lzf;
    struct sha1_file *s1f;
    unsigned char cfsha1[SHA_DIGEST_LENGTH];
    unsigned char cfsha1x[SHA_DIGEST_LENGTH * 2 + 1];
    int use_hmac = 0;
    unsigned char hmac[EVP_MAX_MD_SIZE * 2 + 1];
    int wrote_file = 0;
    pid_t child;
    int numkeys = 0;
    char paxhdr_varstring[256];


    if ((child = fork()) == 0) {
	FILE *out = fdopen(out_h, "w");
	char *sparsetext = NULL;
	char *ciphertype = NULL;

	fsinit(&fs);
	while (tar_get_next_hdr(&fs)) {
	    use_hmac = 0;
	    wrote_file = 0;
		if (fs.ftype == 'g') {
		char *paxdatacpy = NULL;
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.version", &paxdata, &paxdatalen) == 0) {
		    struct key_st *keys;
		    char *esceprvkey = NULL;
		    char *escpubkey = NULL;
		    char *esccomment= NULL;
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.numkeys", &paxdata, &paxdatalen) == 0) {
			strncpya0(&paxdatacpy, paxdata, paxdatalen);
			numkeys = strtol(paxdatacpy, NULL, 10);
		    }
		    else
			numkeys = 1;
		    keys = malloc(sizeof(struct key_st) * numkeys);
		    for (int i = 0; i < numkeys; i++) {
			keys[i].fingerprint = NULL;
			keys[i].eprvkey = NULL;
			keys[i].pubkey = NULL;
			keys[i].hmac_hash_b64 = NULL;
			keys[i].comment = NULL;
		    }
		    for (int i = 0; i < numkeys; i++) {
			if (numkeys > 1) {
			    snprintf(paxhdr_varstring, 1024, "TC.pubkey.fingerprint.%d", i);
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, paxhdr_varstring, &(keys[i].fingerprint));
			    snprintf(paxhdr_varstring, 1024, "TC.eprivkey.%d", i);
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, paxhdr_varstring, &(keys[i].eprvkey));
			    snprintf(paxhdr_varstring, 1024, "TC.pubkey.%d", i);
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, paxhdr_varstring, &(keys[i].pubkey));
			    snprintf(paxhdr_varstring, 1024, "TC.hmackeyhash.%d", i);
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, paxhdr_varstring, &(keys[i].hmac_hash_b64));
			    snprintf(paxhdr_varstring, 1024, "TC.keyfile.comment.%d", i);
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, paxhdr_varstring, &(keys[i].comment));
			}
			else {
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, "TC.pubkey.fingerprint", &(keys[0].fingerprint));
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, "TC.eprivkey", &(keys[0].eprvkey));
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, "TC.pubkey",&(keys[0].pubkey));
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, "TC.hmackeyhash", &(keys[0].hmac_hash_b64));
			    cpypaxvarstr(fs.xheader, fs.xheaderlen, "TC.keyfile.comment", &(keys[0].comment));
			}

		    }
		    for (int i = 0; i < numkeys; i++) {
			fprintf(out, "0\t%d\t%s\t%s\t%s\t%s\t%s\t\n", i,
			    keys[i].fingerprint, stresc(keys[i].eprvkey, &esceprvkey), stresc(keys[i].pubkey, &escpubkey),
			    keys[i].hmac_hash_b64, stresc(keys[i].comment, &esccomment));
		    }
		    if (numkeys > 0) {
			for (int i = 0; i < numkeys; i++) {
			    dfree(keys[i].comment);
			    dfree(keys[i].fingerprint);
			    dfree(keys[i].hmac_hash_b64);
			    dfree(keys[i].eprvkey);
			    dfree(keys[i].pubkey);
			}
			free(keys);
		    }
		    dfree(esceprvkey);
		    dfree(escpubkey);
		    dfree(esccomment);
		}
		dfree(paxdatacpy);

	    }
	    else if (fs.ftype == '5' && getpaxvar(fs.xheader, fs.xheaderlen, "TC.segmented.header",
		&paxdata, &paxdatalen) == 0) {

		snprintf(tmpfilepath, 1024, "%s/tbXXXXXX", tmpfiledir);
		curtmpfile = mkstemp(tmpfilepath);
		curfile = fdopen(curtmpfile, "w");
		tsf = tarsplit_init_r(fread, stdin, numkeys);
		if (ciphertype != NULL)
		    ciphertype[0] = '\0';
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.compression", &paxdata, &paxdatalen) == 0) {
		    strncata0(&ciphertype, paxdata, paxdatalen - 1);
		}
		strncata0(&ciphertype, "|", 1);
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.cipher", &paxdata, &paxdatalen) == 0) {
		    strncata0(&ciphertype, paxdata, paxdatalen - 1);
		}
		fprintf(curfile, "%s\n", ciphertype);

		double curtime = ftime();
		double lastupdate_time = curtime;
		size_t tot_size = 0;
		while ((c = tarsplit_read(databuf, 1, bufsize, tsf)) > 0) {
		    fwrite(databuf, 1, c, curfile);
		    tot_size += c;
		    if ((curtime = ftime()) > lastupdate_time + 1) {
			fprintf(out, "2\t%s\t%lu\n", stresc(fs.filename, &escfname), tot_size);
		    }
		}
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.cipher", &paxdata, &paxdatalen) == 0) {
		   for (int i = 0; i < numkeys; i++) {
			if ((tsf->hmac[i])[0] != '\0') {
			    strncata0(&ciphertype, (char *) (tsf->hmac[i]), EVP_MAX_MD_SIZE * 2);
			    use_hmac = 1;
			}
		   }
		   if (use_hmac == 1) {
			unsigned char *tmphash;
			strncpy0((char *) hmac, (char *) (tmphash = sha256_hex(ciphertype)),SHA_DIGEST_LENGTH * 2 + 1);
			free(tmphash);
		   }
#if 0
		    if ((tsf->hmac[0])[0] != '\0') {
			strncpy((char *) hmac, (char *) (tsf->hmac[0]), EVP_MAX_MD_SIZE * 2);
			hmac[EVP_MAX_MD_SIZE * 2] = '\0';
			if (hmac[strlen((char *) hmac) - 1] == '\n')
			    hmac[strlen((char *) hmac) - 1] = '\0';
			use_hmac = 1;
		    }
#endif
		   if (numkeys > 1) {
			for (int i = 0; i < numkeys; i++) {
			    snprintf(paxhdr_varstring, 1024, "TC.hmac.%d", i);
			    setpaxvar(&(fs.xheader), &(fs.xheaderlen), paxhdr_varstring, (char *) tsf->hmac[i], strlen((char *) tsf->hmac[i]));
			}
		    }
		    else {
			setpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.hmac", (char *) tsf->hmac[0], strlen((char *) tsf->hmac[0]));
		    }
		}
		if (escxheader == NULL)
		    escxheader = dmalloc(((int)((fs.xheaderlen + 2) / 3)) * 4 + 1);
		else
		    if (dmalloc_size(escxheader) < ((int)((fs.xheaderlen + 2) / 3)) * 4 + 1)
			escxheader = drealloc(escxheader, ((int)((fs.xheaderlen + 2) / 3)) * 4 + 1);

		unsigned long long int filesize = fs.filesize;

		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.original.size", &paxdata, &paxdatalen) == 0) {
		    filesize = strtoull(paxdata, 0, 10);
		}

		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.sparse.original.size", &paxdata, &paxdatalen) == 0) {
		    filesize = strtoull(paxdata, 0, 10);
		}

		fprintf(out, "1\t%c\t%4.4o\t%s\t%d\t%s\t%d\t%lld\t%s\t%lu\t%s\t%s\t%d\t%s\n",
		    'E', fs.mode, fs.auid, fs.nuid, fs.agid, fs.ngid, filesize,
			use_hmac == 0 ? cfsha1x : hmac, fs.modtime, stresc(fs.filename, &escfname),
			stresc(fs.linktarget == 0 ? "" : fs.linktarget, &esclname), fs.xheaderlen,
			fs.xheaderlen == 0 ? "" : EncodeBlock2(escxheader, fs.xheader, fs.xheaderlen, NULL)
		    );
		tarsplit_finalize_r(tsf);
		fclose(curfile);
		wrote_file = 1;
	    }
	    else if (fs.filesize > 0 || fs.n_sparsedata > 0) {
		int is_ciphered = 0;
		size_t (*c_fwrite)();
		void *c_handle;
		unsigned long long int filesize = fs.filesize;

		snprintf(tmpfilepath, 1024, "%s/tbXXXXXX", tmpfiledir);
		curtmpfile = mkstemp(tmpfilepath);
		curfile = fdopen(curtmpfile, "w");
		if (ciphertype != NULL)
                    ciphertype[0] = '\0';
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.compression", &paxdata, &paxdatalen) == 0) {
		    strncata0(&ciphertype, paxdata, paxdatalen - 1);
		}
		strncata0(&ciphertype, "|", 1);
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.cipher", &paxdata, &paxdatalen) == 0) {
		    strncata0(&ciphertype, paxdata, paxdatalen - 1);
		    is_ciphered = 1;
		}
		if (is_ciphered == 1)
		    fprintf(curfile, "%s\n", ciphertype);
		sizeremaining = fs.filesize;
		padding = 512 - ((fs.filesize - 1) % 512 + 1);
		if (is_ciphered == 1) {
		    is_ciphered = 1;
		    if (numkeys > 1)
			for (int i = 0; i < numkeys; i++) {
			    snprintf(paxhdr_varstring, 1024, "TC.hmac.%d", i);
			    if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0) {
				strncata0(&ciphertype, paxdata, paxdatalen - 1);
				use_hmac = 1;
			    }
			}
		    else {
			if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.hmac", &paxdata, &paxdatalen) == 0) {
			    strncata0(&ciphertype, paxdata, paxdatalen - 1);
			    use_hmac = 1;
			}
		    }
		    if (use_hmac == 1) {
			unsigned char *tmphash;
			strcpy((char *) hmac, (char *) (tmphash = sha256_hex(ciphertype)));
			free(tmphash);
		    }
		}
		s1f = sha1_file_init_w(fwrite, curfile);
		c_fwrite = sha1_file_write;
		c_handle = s1f;
		if (use_hmac == 0) {
		    lzf = lzop_init_w(sha1_file_write, s1f);
		    c_fwrite = lzop_write;
		    c_handle = lzf;
		}
		if (fs.n_sparsedata > 0) {
		    int stlen;
		    if (sparsetext != NULL)
			sparsetext[0] = '\0';
		    stlen = gen_sparse_data_string(&fs, &sparsetext);
		    c_fwrite(sparsetext, 1, stlen, c_handle);
		    filesize = fs.sparse_realsize;
		}
		double curtime = ftime();
		double lastupdate_time = curtime;
		size_t tot_size = 0;
		while (sizeremaining > 0) {
		    c = fread(databuf, 1, sizeremaining < bufsize ? sizeremaining : bufsize, stdin);
		    c_fwrite(databuf, 1, c, c_handle);
		    sizeremaining -= c;
		    tot_size += c;
		    if ((curtime = ftime()) > lastupdate_time + 1) {
			fprintf(out, "2\t%s\t%lu\n", stresc(fs.filename, &escfname), tot_size);
		    }
		}
		if (use_hmac == 0)
		    lzop_finalize_w(lzf);
		sha1_finalize_w(s1f, cfsha1);
		encode_block_16(cfsha1x, cfsha1, SHA_DIGEST_LENGTH);
		fclose(curfile);
		while (padding > 0)
		    padding -= fread(databuf, 1, padding < bufsize ? padding : bufsize, stdin);
		if (escxheader == NULL)
		    escxheader = dmalloc(((int)((fs.xheaderlen + 2) / 3)) * 4 + 1);
		else
		    if (dmalloc_size(escxheader) < ((int)((fs.xheaderlen + 2) / 3)) * 4 + 1)
			escxheader = drealloc(escxheader, ((int)((fs.xheaderlen + 2) / 3)) * 4 + 1);


		if (is_ciphered == 1) { 
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.original.size", &paxdata, &paxdatalen) == 0) {
			filesize = strtoull(paxdata, 0, 10);
		    }

		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.sparse.original.size", &paxdata, &paxdatalen) == 0) {
			filesize = strtoull(paxdata, 0, 10);
		    }
		}

		fprintf(out, "1\t%c\t%4.4o\t%s\t%d\t%s\t%d\t%lld\t%s\t%lu\t%s\t%s\t%d\t%s\n",
		    is_ciphered == 1 ? 'E' : fs.n_sparsedata > 0 ? 'S' : fs.ftype, fs.mode,
		    fs.auid, fs.nuid, fs.agid, fs.ngid, filesize, use_hmac == 0 ? cfsha1x : hmac,
		    fs.modtime, stresc(fs.filename, &escfname),
		    stresc(fs.linktarget == 0 ? "" : fs.linktarget, &esclname), fs.xheaderlen,
		    fs.xheaderlen == 0 ? "" : EncodeBlock2(escxheader, fs.xheader, fs.xheaderlen, NULL)
		);
		wrote_file = 1;
	    }
	    else {
		if (escxheader == NULL)
		    escxheader = dmalloc(((int)((fs.xheaderlen + 2) / 3)) * 4 + 1);
		else
		    if (dmalloc_size(escxheader) < ((int)((fs.xheaderlen + 2) / 3)) * 4 + 1)
			escxheader = drealloc(escxheader, ((int)((fs.xheaderlen + 2) / 3)) * 4 + 1);
		if (fs.ftype == '5' && strlen(fs.filename) > 0 && fs.filename[strlen(fs.filename) - 1] == '/') {
		    fs.filename[strlen(fs.filename) - 1] = '\0';
		}
		fprintf(out, "1\t%c\t%4.4o\t%s\t%d\t%s\t%d\t%lld\t%s\t%lu\t%s\t%s\t%d\t%s\n",
		    fs.ftype, fs.mode, fs.auid, fs.nuid, fs.agid, fs.ngid,
			fs.filesize, "0", fs.modtime, stresc(fs.filename, &escfname),
			stresc(fs.linktarget == 0 ? "" : fs.linktarget, &esclname), fs.xheaderlen,
			fs.xheaderlen == 0 ? "" : EncodeBlock2(escxheader, fs.xheader, fs.xheaderlen, NULL)
		    );
	    }

	    fsclear(&fs);
	    if (wrote_file == 1) {
		if (use_hmac == 0) {
		    strncpy(destdir2, (char *) cfsha1x, 2);
		    destdir2[2] = '\0';
		    snprintf(targetdir, 1024, "%s/%s", destdir, destdir2);
		    snprintf(targetpath, 1024, "%s/%s/%s.lzo", destdir, destdir2, cfsha1x + 2);
		}
		else {
		    strncpy(destdir2, (char *) hmac, 2);
		    destdir2[2] = '\0';
		    snprintf(targetdir, 1024, "%s/%s", destdir, destdir2);
		    snprintf(targetpath, 1024, "%s/%s/%s.enc", destdir, destdir2, hmac + 2);
		}
		if (stat(targetdir, &tmpfstat) != 0) {
		    if (mkdir(targetdir, 0770) != 0) {
			fprintf(stderr, "Error creating directory %s\n", targetdir);
			exit(1);
		    }
		}
		if (stat(targetpath, &tmpfstat) != 0 || utime(targetpath, NULL) != 0) {
		    rename(tmpfilepath, targetpath);
		}
		else {
		    unlink(tmpfilepath);
		}
	    }
	    fsclear(&fs);
	}

	fsfree(&fs);
	if (escfname != NULL)
	    stresc_free(&escfname);
	if (esclname != NULL)
	    stresc_free(&esclname);
	dfree(escxheader);
	fflush(out);
	fclose(out);
	close(out_h);
	free(config.vault);
	free(config.meta);
	dfree(ciphertype);
	dfree(sparsetext);
	exit(0);
    }
    else {
	close(out_h);
    }
    return(0);
}

int pipebuf(int *in, int *out)
{
    int pipein[2];
    int pipeout[2];
    pid_t child;

    if (*in < 0)
	pipe(pipein);
    if (*out < 0)
	pipe(pipeout);

    if ((child = fork()) > 0) {
	if (*in < 0) {
	    close(pipein[0]);
	    *in = pipein[1];
	}
	if (*out < 0) {
	    close(pipeout[1]);
	    *out = pipeout[0];
	}
	return(0);
    }
    else {
	struct ringbuf *r;

	struct timeval s_tm;

	int bufsize = 4096;
	char buf[bufsize];
	ssize_t n;
	ssize_t o;
	int ateof = 0;
	fclose(stdout);
	if (*in < 0)
	    close(pipein[1]);
	else
	    pipein[0] = *in;
	if (*out < 0)
	    close(pipeout[0]);
	else
	    pipeout[1] = *out;

	r = rbinit(1024 * 1024 * 1024);
	fd_set s_in;
	fd_set s_out;
	free(config.vault);
	free(config.meta);

//	fcntl(pipein[0], F_SETFL, O_NONBLOCK);
//	fcntl(pipeout[1], F_SETFL, O_NONBLOCK);
	while (1) {
	    if (rbused(r) == 0 && ateof == 1) {
		rbfree(r);
		exit(0);
	    }
	    // if the buffer is empty, then wait for input and see if output will block
	    if (rbused(r) == 0 && ateof == 0) {
		FD_ZERO(&s_in);
		FD_SET(pipein[0], &s_in);
		select(1024, &s_in, NULL, NULL, NULL);

		s_tm.tv_sec = 0;
		s_tm.tv_usec = 0;
		FD_ZERO(&s_out);
		FD_SET(pipeout[1], &s_out);
		select(1024, NULL, &s_out, NULL, &s_tm);

		n = read(pipein[0], buf, bufsize);
		if (n <= 0) {
		    ateof = 1;
		}
		if (FD_ISSET(pipeout[1], &s_out)) {
		    o = write(pipeout[1], buf, n);
		    if (o < n) {
			fprintf(stderr, "Short write a of %lu, wanted %lu, putting %lu bytes back in buffer\n", o, n, n - o);
			rbrewind(r, n - o);
		    }
		}
		else {
		    rbwrite(buf, 1, n, r);
		}
	    }
	    // if there is room in the buffer, wait for either input or output
	    else if (rbavail(r) > bufsize && ateof == 0) {
		FD_ZERO(&s_in);
		FD_SET(pipein[0], &s_in);
		FD_ZERO(&s_out);
		FD_SET(pipeout[1], &s_out);
		select(1024, &s_in, &s_out, NULL, NULL);

		// flush ring buffer until output blocks
		while (FD_ISSET(pipeout[1], &s_out) && rbused(r) > 0) {
		    n = rbread(buf, 1, bufsize, r);
		    if (n <= 0)
			fprintf(stderr, "Error 1 -- n is %lu\n", n);
		    o = write(pipeout[1], buf, n);
		    // if not all written, put remainder back in ring buffer
		    if (o < n) {
			fprintf(stderr, "Short write b of %lu, wanted %lu, putting %lu bytes back in buffer\n", o, n, n - o);
			rbrewind(r, n - o);
		    }
		    s_tm.tv_sec = 0;
		    s_tm.tv_usec = 0;
		    FD_ZERO(&s_out);
		    FD_SET(pipeout[1], &s_out);
		    select(1024, NULL, &s_out, NULL, &s_tm);
		}
		if (ateof == 0) {
		    n = read(pipein[0], buf, bufsize);
		    if (n <= 0) {
			ateof = 1;
		    }
		    if (rbused(r) == 0) {
			o = write(pipeout[1], buf, n);
			if (o < n) {
			    fprintf(stderr, "Short write c of %lu, wanted %lu, putting %lu bytes back in buffer\n", o, n, n - o);
			    rbrewind(r, n - o);
			}
		    }
		    else {
			rbwrite(buf, 1, n, r);
		    }
		}
	    }
	    // otherwise, buffer is full, wait for output
	    else {
		FD_ZERO(&s_out);
		FD_SET(pipeout[1], &s_out);
		select(1024, NULL, &s_out, NULL, NULL);

		// flush ring buffer until output blocks
		while (FD_ISSET(pipeout[1], &s_out) && rbused(r) > 0) {
		    n = rbread(buf, 1, bufsize, r);
		    if (n <= 0)
			fprintf(stderr, "Error 1 -- n is %lu\n", n);
		    o = write(pipeout[1], buf, n);
		    // if not all written, put remainder back in ring buffer
		    if (o < n) {
			fprintf(stderr, "Short write d of %lu, wanted %lu, putting %lu bytes back in buffer\n", o, n, n - o);
			rbrewind(r, n - o);
		    }
		    FD_ZERO(&s_out);
		    FD_SET(pipeout[1], &s_out);
		    select(1024, NULL, &s_out, NULL, NULL);
		}
	    }
	}
	exit(0);
    }
}

void update_status(unsigned long long total_bytes_received, unsigned long long est_size, char *cur_filename, time_t curtime, time_t start_time, char indicator)
{
    //figure out display unit (KB, MB, etc)
    int b_received_unit = sizeof(display_units) / sizeof(*display_units) - 1;
    int BPS_unit = 0;
    double BPS = (curtime - start_time) == 0 ? 0 : (double) total_bytes_received / (curtime - start_time);
    char statusline_fmtstr[128];
    int curbytes_len;
    int fname_len;
    char statusline[256];
    char curbytes[128];
    char pct_str[16];
    int pctstr_len;
    int dots_before;
    int dots_after;
    int pct;
    int scalelen = 20;
    char progress_scale[21];

    b_received_unit = 0;
    for (int i = 0; i < sizeof(display_units) / sizeof(*display_units); i++)
	if (total_bytes_received >= display_units[i].unit)
	    b_received_unit = i;
    BPS_unit = 0;
    for (int i = 0; i < sizeof(display_units) / sizeof(*display_units); i++)
	if (BPS >= display_units[i].unit)
	    BPS_unit = i;

    pct = (int) est_size == 0 ? 100 : (((double) total_bytes_received / est_size) * 100 + .5);
    pctstr_len = snprintf(pct_str, 16, "%d%%", pct);
    dots_before = (int) ((scalelen - pctstr_len) * ((double) pct / 100));
    dots_after = scalelen - pctstr_len - dots_before;
    progress_scale[0] = '\0';
    for (int j = 0; j < dots_before; j++)
	strcat(progress_scale, ".");
    strcat(progress_scale, pct_str);
    for (int j = 0; j < dots_after; j++)
	strcat(progress_scale, ".");

    snprintf(curbytes, 128, "[%s] %6.2f%c / %6.2f %s/s", progress_scale, (double) total_bytes_received /
	display_units[b_received_unit].unit, *(display_units[b_received_unit].label), 
	(double) BPS / display_units[BPS_unit].unit, display_units[BPS_unit].label);

    curbytes_len = strlen(curbytes);
    fname_len = 76 - curbytes_len;
    snprintf(statusline_fmtstr, 128, "%%-%d.%ds %%s\r", fname_len, fname_len);
    snprintf(statusline, 256, statusline_fmtstr, cur_filename, curbytes);
    fprintf(stderr, "%c %s", indicator, statusline);
    fflush(stderr);
}


char *stresc(char *src, char **target)
{
    int i;
    int j;
    int e = 0;
    int len;

    len = strlen(src);
    for (i = 0; i < len; i++)
        if (src[i] <= 32 || src[i] >= 127 || src[i] == 92)
            e++;
    if (*target == NULL)
	*target = dmalloc(len + e * 4 + 1);
    else {
	if (len + e * 4 + 1 > dmalloc_size(*target)) {
	    *target = drealloc(*target, len + e * 4 + 1);
	}
    }
    (*target)[0] = 0;
    i = 0;
    while (i < len) {
        for (j = i; i < len && src[i] > 32 &&
            src[i] < 127 && src[i] != 92; i++)
            ;
        strncat(*target, src + j, i - j);
        if (i < len) {
            snprintf((*target) + strlen(*target), 5, "\\%3.3o",
                (unsigned char) src[i]);
            i++;
        }
    }
    return(*target);
}

char *strescb(char *src, char **target, int len)
{
    int i;
    int j;
    int e = 0;

    for (i = 0; i < len; i++)
        if (src[i] <= 32 || src[i] >= 127 || src[i] == 92)
            e++;
    if (*target == 0)
	*target = dmalloc(len + e * 4 + 1);
    else
	if (len + e * 4 + 1 > dmalloc_size(*target))
	    *target = drealloc(*target, len + e * 4 + 1);
    (*target)[0] = 0;
    i = 0;
    char *p = *target;
    while (i < len) {
        for (j = i; i < len && src[i] > 32 &&
            src[i] < 127 && src[i] != 92; i++)
            ;
        strncat(p, src + j, i - j);
        if (i < len) {
            p += strlen(p);
            snprintf((p), 5, "\\%3.3o",
                (unsigned char) src[i]);
            p += 4;
            i++;
        }
    }
    return(*target);
}
char *strunesc(char *src, char **target)
{
    char b;
    int i = 0, j = 0, k = 0;

    if (*target == NULL)
	*target = dmalloc(strlen(src) + 1);
    else if (dmalloc_size(*target) < strlen(src) + 1)
	*target = drealloc(*target, strlen(src) + 1);
    (*target)[0] = 0;
    while (i < strlen(src)) {
        for (; i < strlen(src) && src[i] != 92; i++)
            ;
	memcpyao((void **) target, src + k, i - k, j);
	j += (i - k);
        if (i < strlen(src)) {
	    i++;
            b = (char) strtoln(src + i, NULL, 8, 3);
	    memcpyao((void **) target, &b, 1, j);
            i += 3;
	    k = i;
	    j += 1;
        }
    }
    memcpyao((void **) target, "\0", 1, j);
    return(*target);
}

void stresc_free(char **target)
{
    dfree(*target);
}

double ftime()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return(t.tv_sec + (double) t.tv_usec / 1000000);
}

struct ringbuf {
    void *buf;	// buffer
    void *h;	// head
    void *t;	// tail
    size_t s;	// size
    int w;	// wrap
};

struct ringbuf *rbinit(size_t s)
{
    struct ringbuf *r;
    
    r = malloc(sizeof(struct ringbuf));
    r->buf = malloc(s);
    r->s = s;
    r->h = r->buf;
    r->t = r->buf;
    r->w = 0;
    return(r);
}

size_t rbwrite(void *buf, size_t b, size_t c, struct ringbuf *r)
{
    size_t n = b * c;
    size_t a = 0;

    if (r->t > r->h || (r->t == r->h && r->w == 0)) {
	if (r->buf + r->s - r->t >= n) {
	    memcpy(r->t, buf, n);
	    r->t += n;
	    a += n;
	    buf += n;
	    n -= n;
	}
	else {
	    memcpy(r->t, buf, r->buf + r->s - r->t);
	    a += r->buf + r->s - r->t;
	    buf += r->buf + r->s - r->t;
	    n -= r->buf + r->s - r->t;
	    r->t = r->buf;
	    r->w = 1;
	}
    }
    if (r->t < r->h) {
	if (r->h - r->t >= n) {
	    memcpy(r->t, buf, n);
	    r->t += n;
	    a += n;
	    buf += n;
	    n -= n;
	}
	else {
	    memcpy(r->t, buf, r->h - r->t);
	    a += r->h - r->t;
	    buf += r->h - r->t;
	    n -= r->h - r->t;
	    r->t = r->h;
	}
    }
    return(a);
}
size_t rbread(void *buf, size_t b, size_t c, struct ringbuf *r)
{
    size_t n = b * c;
    size_t a = 0;
    if (r->t < r->h || (r->t == r->h && r->w == 1)) {
	if (r->buf + r->s - r->h >= n) {
	    memcpy(buf, r->h, n);
	    r->h += n;
	    a += n;
	    buf += n;
	    n -= n;
	    if (r->h > r->buf + r->s) {
		r->h = r->buf;
		r->w = 0;
	    }

	}
	else {
	    memcpy(buf, r->h, r->buf + r->s - r->h);
	    a += r->buf + r->s - r->h;
	    buf += r->buf + r->s - r->h;
	    n -= r->buf + r->s - r->h;
	    r->h = r->buf;
	    r->w = 0;
	}
    }
    if (r->t > r->h) {
	if (r->t - r->h >= n) {
	    memcpy(buf, r->h, n);
	    r->h += n;
	    a += n;
	    buf += n;
	    n -= n;
	}
	else {
	    memcpy(buf, r->h, r->t - r->h);
	    a += r->t - r->h;
	    buf += r->t - r->h;
	    n -= r->t - r->h;
	    r->h = r->t;
	    if (r->h == r->buf  + r->s)
		r->h = r->t = r->buf;
	}
    }
    return(a);
}
size_t rbrewind(struct ringbuf *r, size_t c)
{
    size_t n = 0;
    if (rbavail(r) > c) {
	if (r->w == 0) {
	    n = (r->h - r->buf >= c ? c : r->h - r->buf);
	    if (n == c)
		r->h -= c;
	    else {
		r->h -= n;
		r->w = 1;
		n = c - n;
		r->h = r->buf + r->s - n;
	    }
	}
	else {
	    r->h -= c;
	}
	return(c);
    }
    else
	return(0);
}

size_t rbavail(struct ringbuf *r)
{
    return(r->w == 0 ? (r->buf + r->s - r->t) + (r->h - r->buf) : (r->h - r->t));
}

size_t rbused(struct ringbuf *r)
{
    return(r->w == 0 ?  r->s - ((r->buf + r->s - r->t) + (r->h - r->buf)) : (r->s - (r->h - r->t)));
}

size_t rbsize(struct ringbuf *r)
{
    return(r->s);
}

void rbfree(struct ringbuf *r)
{
    free(r->buf);
    free(r);
}

char *EncodeBlock2(char *out, char *in, int m, int *n)
{
    int x;
    x = EVP_EncodeBlock((unsigned char *) out, (unsigned char *) in, m);
    if (n != NULL)
        *n = x;
    return(out);
}

char *DecodeBlock2(char *out, char *in, int m, int *n)
{
    *n = EVP_DecodeBlock((unsigned char *) out, (unsigned char *) in, m);
    if (in[m - 1] == '=') {
        if (in[m - 2] == '=') {
            *n -= 2;
	}
        else {
            *n -= 1;
	}
    }
    return(out);
}

int flush_received_files(sqlite3 *bkcatalog, int verbose, int bkid,
    unsigned long long est_size,  unsigned long long *bytes_read)
{
    char *sqlerr;
    sqlite3_stmt *sqlres;
    char *sqlstmt = 0;
    int x;
//    static unsigned long long bytes_read_l = 0;


//  Populate diskfiles table from temporary diskfiles_t

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into diskfiles select * from diskfiles_t"
    )), 0, 0, &sqlerr);
//    fprintf(stderr, "%s\n", sqlstmt);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    sqlite3_exec(bkcatalog, "delete from diskfiles_t", 0, 0, 0);


//  Populate temporary table file_entities_t with received files

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities_t "
	"(file_id, ftype, permission, device_id, inode, "
        "user_name, user_id, group_name, group_id, size, sha1, cdatestamp, "
	"datestamp, filename, extdata, xheader) "
	"select r.file_id, r.ftype, r.permission, n.device_id, n.inode, "
	"r.user_name, r.user_id, r.group_name, r.group_id, r.size, "
	"r.sha1, n.cdatestamp, r.datestamp, n.filename, r.extdata, r.xheader "
	"from received_file_entities_t r "
	"join needed_file_entities n "
	"on r.filename = n.infilename "
	"where r.ftype != 1 "
	"and n.backupset_id = %d", bkid
    )), 0, 0, &sqlerr);
//    fprintf(stderr, "%s\n", sqlstmt);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);


//  And now transfer to permanent file_entitities table

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities "
	"(ftype, permission, device_id, inode, "
	"user_name, user_id, group_name, group_id, size, sha1, cdatestamp, "
	"datestamp, filename, extdata, xheader) "
	"select ftype, permission, device_id, inode, "
	"user_name, user_id, group_name, group_id, size, sha1, cdatestamp, "
	"datestamp, filename, extdata, xheader "
	"from file_entities_t"
    )), 0, 0, &sqlerr);
    if (sqlerr != 0) {
        fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
        sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);


//  Take care of cipher_detail

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into cipher_detail ( "
	"file_id, keynum, hmac) "
	"select f.file_id, id, hmac "
	"from temp_cipher_detail c "
	"join temp_key_map m "
	"on c.keynum = m.keyposition "
	"join file_entities_t t on c.file_id = t.file_id "
	"join file_entities f "
	"on f.ftype = t.ftype and f.permission = t.permission "
	"and f.device_id = t.device_id and f.inode = t.inode "
	"and f.user_name = t.user_name and f.user_id = t.user_id "
	"and f.group_name = t.group_name and f.group_id = t.group_id "
	"and f.size = t.size and f.sha1 = t.sha1 and f.cdatestamp = t.cdatestamp "
	"and f.datestamp = t.datestamp and f.filename = t.filename "
	"and f.extdata = t.extdata and f.xheader = t.xheader "
	"and f.cdatestamp = t.cdatestamp; "
    )), 0, 0, &sqlerr);

    if (sqlerr != 0) {
        fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
        sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

#if 0
    if (verbose >= 1) {
	x = sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "select sum(size) from file_entities_t")), -1, &sqlres, 0);
	if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
	    bytes_read_l = sqlite3_column_int64(sqlres, 0);
	    *bytes_read = bytes_read_l;
	}
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
    }
#endif


//  Create records in backupset_detail

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupset_detail (backupset_id, file_id) "
	"select %d, f.file_id from file_entities f "
	"join file_entities_t t "
	"on f.ftype = t.ftype and f.permission = t.permission "
	"and f.device_id = t.device_id and f.inode = t.inode "
	"and f.user_name = t.user_name and f.user_id = t.user_id "
	"and f.group_name = t.group_name and f.group_id = t.group_id "
	"and f.size = t.size and f.sha1 = t.sha1 and f.cdatestamp = t.cdatestamp "
	"and f.datestamp = t.datestamp and f.filename = t.filename "
	"and f.extdata = t.extdata and f.xheader = t.xheader "
	"and f.cdatestamp = t.cdatestamp ", bkid
    )), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);


//  Clear out file_entities_t for next step
    sqlite3_exec(bkcatalog, "delete from file_entities_t", 0, 0, 0);


//  Handle hard link files

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities_t "
	"(file_id, ftype, permission, device_id, inode, "
        "user_name, user_id, group_name, group_id, size, sha1, cdatestamp, "
	"datestamp, filename, extdata, xheader) "
	"select f.file_id, f.ftype, f.permission, f.device_id, f.inode, "
	"f.user_name, f.user_id, f.group_name, f.group_id, f.size, "
	"f.sha1, f.cdatestamp, f.datestamp, r.filename, f.extdata, f.xheader "
	"from file_entities f "
	"join backupset_detail d "
	"on f.file_id = d.file_id "
	"join received_file_entities_t r "
	"on r.extdata = f.filename "
	"where r.ftype = 1 "
	"and d.backupset_id = %d", bkid
    )), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities "
	"(ftype, permission, device_id, inode, "
	"user_name, user_id, group_name, group_id, size, sha1, cdatestamp, "
	"datestamp, filename, extdata, xheader) "
	"select ftype, permission, device_id, inode, "
	"user_name, user_id, group_name, group_id, size, sha1, cdatestamp, "
	"datestamp, filename, extdata, xheader "
	"from file_entities_t"
    )), 0, 0, &sqlerr);
    if (sqlerr != 0) {
        fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
        sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);


//  Cipher details again for hardlink files

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into cipher_detail ( "
	"file_id, keynum, hmac) "
	"select f.file_id, keynum, hmac "
	"from cipher_detail c "
	"join file_entities_t t on c.file_id = t.file_id "
	"join file_entities f "
	"on f.ftype = t.ftype and f.permission = t.permission "
	"and f.device_id = t.device_id and f.inode = t.inode "
	"and f.user_name = t.user_name and f.user_id = t.user_id "
	"and f.group_name = t.group_name and f.group_id = t.group_id "
	"and f.size = t.size and f.sha1 = t.sha1 and f.cdatestamp = t.cdatestamp "
	"and f.datestamp = t.datestamp and f.filename = t.filename "
	"and f.extdata = t.extdata and f.xheader = t.xheader "
	"and f.cdatestamp = t.cdatestamp; "
    )), 0, 0, &sqlerr);
    sqlite3_free(sqlstmt);


// Backupset details for hardlinks

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupset_detail (backupset_id, file_id) "
	"select %d, f.file_id from file_entities f "
	"join file_entities_t t "
	"on f.ftype = t.ftype and f.permission = t.permission "
	"and f.device_id = t.device_id and f.inode = t.inode "
	"and f.user_name = t.user_name and f.user_id = t.user_id "
	"and f.group_name = t.group_name and f.group_id = t.group_id "
	"and f.size = t.size and f.sha1 = t.sha1 and f.cdatestamp = t.cdatestamp "
	"and f.datestamp = t.datestamp and f.filename = t.filename "
	"and f.extdata = t.extdata and f.xheader = t.xheader "
	"and f.cdatestamp = t.cdatestamp ", bkid
    )), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

//  Get sum of bytes in hardlinked files for status reporting   
    x = sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"select sum(size) from file_entities_t")), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
	*bytes_read = sqlite3_column_int64(sqlres, 0);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);


    sqlite3_exec(bkcatalog, "delete from received_file_entities_t", 0, 0, 0);
    sqlite3_exec(bkcatalog, "delete from file_entities_t", 0, 0, 0);
    sqlite3_exec(bkcatalog, "delete from temp_cipher_detail", 0, 0, 0);
    return(0);
}
int submitfiles_tmptables(sqlite3 *bkcatalog, int bkid)
{
    char *sqlerr;

    sqlite3_exec(bkcatalog,
        "create temporary table if not exists received_file_entities_t (  \n"
        "    file_id       integer primary key,  \n"
        "    backupset_id  integer,  \n"
        "    ftype         char,  \n"
        "    permission    char,  \n"
        "    user_name     char,  \n"
        "    user_id       integer,  \n"
        "    group_name    char,  \n"
        "    group_id      integer,  \n"
        "    size          integer,  \n"
        "    sha1          char,  \n"
        "    datestamp     integer,  \n"
        "    filename      char,  \n"
        "    extdata       char default '',  \n"
        "    xheader       blob default '',  \n"
        "unique (  \n"
            "backupset_id,  \n"
            "ftype,  \n"
            "permission,  \n"
            "user_name,  \n"
            "user_id,  \n"
            "group_name,  \n"
            "group_id,  \n"
            "size,  \n"
            "sha1,  \n"
            "datestamp,  \n"
            "filename,  \n"
            "extdata,  \n"
            "xheader ))", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog,
	"create temporary table if not exists file_entities_t "
	"as select * from file_entities where 0", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog,
    "create index if not exists received_file_entities_t_i1 on received_file_entities_t (  \n"
    "    filename)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n\n\n",sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
    "create index if not exists received_file_entities_t_i2 on received_file_entities_t (  \n"
    "    extdata)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n\n\n",sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
	"create temporary table if not exists diskfiles_t "
	"as select * from diskfiles where 0", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
	
    return(0);
}
