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

#include "tarlib.h"

int restore(int argc, char **argv);
int help(char *topic);
void usage();
extern sqlite3 *bkcatalog;
extern struct {
    char *vault;
    char *meta;
} config;

char *strunesc(char *src, char **target);


int restore(int argc, char **argv)
{

    char bkname[128];
    char datestamp[128];
    char retention[128];

    char graftfilename[8192];
    int optc;
    int foundopts = 0;
    int i;
    int sqlite_result;

    unsigned int lendian = 1;	// Little endian?

    char *sqlstmt = 0;
    sqlite3_stmt *sqlres;
    sqlite3_stmt *sqlres2;
    int sqlres2_result;
 
//    sqlite3 *bkcatalog;
//    char *bkcatalogp = NULL;
    char *filespec = 0;
    int filespeclen;
    char *sqlerr;
    int use_pax_header = 0;
//    int verbose = 0;
    char *(*graft)[2] = 0;
    int numgrafts = 0;
    int maxgrafts = 0;
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "pax", no_argument, NULL, 0 },
	{ "graft", required_argument, NULL, 0 },
	{ "verbose", no_argument, NULL, 'v' },
	{ "files-from", required_argument, NULL, 'T' },
	{ "null", no_argument, NULL, 0 },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
    time_t bdatestamp;
    time_t edatestamp;
    char *range;
    FILE *FILES_FROM = NULL;
    char *files_from_fname = malloc(4097);
    char *files_from_fnameu = malloc(4097);
    char files_from_0 = 0;
    size_t files_from_fname_len = 4096;
    char *join_files_from_sql = NULL;

    lendian = (unsigned int) (((unsigned char *)(&lendian))[0]); // little endian test

    while ((optc = getopt_long(argc, argv, "n:d:T:", longopts, &longoptidx)) >= 0) {
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
	    case 'r':
		strncpy(retention, optarg, 127);
		retention[127] = 0;
		foundopts |= 4;
		break;
	    case 'v':
//		verbose = 1;
		foundopts |= 4;
		break;
	    case 0:
		if (strcmp("pax", longopts[longoptidx].name) == 0)
                    use_pax_header = 1;
		if (strcmp("graft", longopts[longoptidx].name) == 0) {
		    char *grafteqptr;
		    if (numgrafts + 1>= maxgrafts) {
			maxgrafts += 16;
			graft = realloc(graft, sizeof(*graft) * maxgrafts);
		    }
		    if ((grafteqptr = strchr(optarg, '=')) == 0) {
			help("restore");
			exit(1);
		    }
		    graft[numgrafts][0] = optarg;
		    graft[numgrafts][1] = grafteqptr + 1;
		    *grafteqptr = 0;
		    grafteqptr--;
		    while (grafteqptr > graft[numgrafts][0] &&
			*grafteqptr == ' ')
			*(grafteqptr--) = 0;
		    grafteqptr = graft[numgrafts][1];
		    while (*grafteqptr != 0 && *grafteqptr == ' ')
			*(grafteqptr++) = 0;
		    numgrafts++;
		}
		if (strcmp("null", longopts[longoptidx].name) == 0)
                    files_from_0 = 1;
		break;
	    case 'T':
		if (strcmp(optarg, "-") == 0)
		    FILES_FROM = stdin;
		else
		    if ((FILES_FROM = fopen(optarg, "r")) == NULL) {
			fprintf(stderr, "Error opening file %s\n", optarg);
			return(1);
		    }
		break;
	    default:
		usage();
		return(1);
	}
    }
    if (foundopts != 3) {
	fprintf(stderr, "Didn't find all arguments\n");
        usage();
        return(1);
    }

    if (argc > optind) {
	filespeclen = 4;
	for (i = optind; i < argc; i++)
    	    filespeclen += strlen(argv[i]) + 22;
       	filespec = malloc(filespeclen);
	filespec[0] = 0;
	for (i = optind; i < argc; i++) {
	    if (i == optind)
		strcat(filespec, " and (filename glob ");
	    else
		strcat(filespec, " or filename glob ");
	    strcat(filespec, (sqlstmt = sqlite3_mprintf("'%q'", argv[i])));
	    sqlite3_free(sqlstmt);
	  
	}
	strcat(filespec, ")");
    }



    range = strchr(datestamp, '-');
    if (range != NULL) {
	*range = '\0';
	if (*datestamp != '\0')
	    bdatestamp = atoi(datestamp);
	else
	    bdatestamp = 0;
	if (*(range + 1) != '\0')
	    edatestamp = atoi(range + 1);
	else
	    edatestamp = INT32_MAX;
    }
    else {
	bdatestamp = atoi(datestamp);
	edatestamp = atoi(datestamp);
    }

    if (FILES_FROM != NULL) {
	sqlite3_exec(bkcatalog, sqlstmt =
	    "create temporary table if not exists files_from ( "
	    "filename char, "
	    "constraint files_existc1 unique ( "
	    "    filename))", 0, 0, 0);
	sqlite3_free(sqlstmt);
	while ((files_from_0 == 0 ?
	    getline(&files_from_fname, &files_from_fname_len, FILES_FROM) :
	    getdelim(&files_from_fname, &files_from_fname_len, 0, FILES_FROM)) > -1) {
	    if (files_from_fname[strlen(files_from_fname) - 1] == '\n')
		files_from_fname[strlen(files_from_fname) - 1] = '\0';
	    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(
		"insert or ignore into files_from "
		"(filename) values ('%q')", files_from_0 != 0 ? files_from_fname :
		strunesc(files_from_fname, &files_from_fnameu)), 0, 0, &sqlerr);
	    sqlite3_free(sqlstmt);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n\n\n",sqlerr);
		sqlite3_free(sqlerr);
	    }
	}
	join_files_from_sql = "join files_from r on f.filename = r.filename";

    }
    sqlite3_exec(bkcatalog, 
	"create temporary table if not exists restore_file_entities (  \n"
//	"create table if not exists restore_file_entities (  \n"
	"file_id       integer, \n"
	"ftype         char,  \n"
	"permission    char,  \n"
	"device_id     char,  \n"
	"inode         char,  \n"
	"user_name     char,  \n"
	"user_id       integer,  \n"
	"group_name    char,  \n"
	"group_id      integer,  \n"
	"size          integer,  \n"
	"sha1           char,  \n"
	"datestamp     integer,  \n"
	"filename      char,  \n"
	"extdata       char default '',  \n"
	"xheader       blob default '',  \n"
	"serial        char, \n"
    "constraint restore_file_entitiesc1 unique (  \n"
	"ftype,  \n"
	"permission,  \n"
	"device_id,  \n"
	"inode,  \n"
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
	
    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(
	"insert or ignore into restore_file_entities  "
	"(file_id, ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, datestamp, filename, extdata, xheader, serial)  "
	"select file_id, ftype, permission, device_id, inode, user_name, user_id,  group_name, "
	"group_id, size, sha1, datestamp, f.filename, extdata, xheader, f.serial "
	"from ( "
	"select filename, max(serial) as serial "
	"from file_entities_bd "
	"%s "
	"where %sname = '%q' "
	"and %sserial >= %d and serial <= %d"
	"%s "
	"group by filename) as f "
	"inner join file_entities_bd as m "
	"on m.filename = f.filename "
	"and m.serial = f.serial ",
	join_files_from_sql != NULL ? join_files_from_sql : "",
	filespec != NULL ? "+" : "",
	bkname, filespec != NULL ? "+" : "",
	bdatestamp, edatestamp, filespec != 0 ?  filespec : ""), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    sqlite3_exec(bkcatalog,
        "create index if not exists restore_file_entitiesi1 on restore_file_entities (  \n"
        "    file_id)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n\n\n",sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
        "create index if not exists restore_file_entitiesi2 on restore_file_entities (  \n"
        "    filename)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n\n\n",sqlerr);
	sqlite3_free(sqlerr);
    }

// Create temp db to tar key ID map
    sqlite3_exec(bkcatalog,
        "create temporary table if not exists temp_keymap ( "
//        "create table if not exists temp_keymap ( "
        "tar_keynum     integer primary key, "
        "db_keynum      integer "
        ")", 0, 0, &sqlerr);
    if (sqlerr != 0) {
        fprintf(stderr, "%s\n", sqlerr);
        sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog,
	"insert into temp_keymap (db_keynum) "
	"select distinct keynum from cipher_detail "
	"join restore_file_entities "
	"on cipher_detail.file_id = restore_file_entities.file_id "
	"order by 1",
        0, 0, &sqlerr);
    if (sqlerr != 0) {
        fprintf(stderr, "%s\n", sqlerr);
        sqlite3_free(sqlerr);
    }

// Get list of keygroups for encrypted header
    sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"select group_concat(keygroup, ',') keygroups from "
	"( "
	"select distinct group_concat(tar_keynum - 1, '|') keygroup from cipher_detail c "
	"join restore_file_entities r "
	"on c.file_id = r.file_id "
	"join temp_keymap on keynum = db_keynum "
	"group by c.file_id "
	"order by 1 "
	") ")), -1, &sqlres, 0);

    sqlite3_free(sqlstmt);
    char *keygroups = NULL;
    sqlite_result = sqlite3_step(sqlres);
    if (sqlite_result == SQLITE_ROW && sqlite3_column_text(sqlres, 0) != NULL) {
	strncpya0(&keygroups, (char *) sqlite3_column_text(sqlres, 0), 0);
    }
    sqlite3_finalize(sqlres);

    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(
	"create temporary view hardlink_file_entities  "
	"as select min(file_id) as file_id, ftype, permission, device_id,  "
	"inode, user_name, user_id, group_name, group_id, size, sha1, datestamp,  "
	"filename, extdata, xheader from restore_file_entities where ftype = '0' or ftype = 'E' group by ftype,  "
	"permission, device_id, inode, user_name, user_id, group_name,  "
	"group_id, size, sha1, datestamp, extdata, xheader having count(*) > 1;"), 0, 0, 0);

    sqlite3_free(sqlstmt);

// Build global header

    int numkeys = 0;
    if (keygroups != NULL && strlen(keygroups) > 0) {
	struct filespec gh;
	struct key_st *keys = NULL;
	fsinit(&gh);
	gh.ftype = 'g';
	strncpya0(&(gh.filename), "././@xheader", 12);
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.version", "1", 1);
	sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "select distinct tar_keynum - 1, pkfp, eprivkey, pubkey, hmackeyhash, comment "
	    "from temp_keymap join cipher_master on "
	    "db_keynum = cipherid order by tar_keynum")), -1, &sqlres, 0);
	sqlite3_free(sqlstmt);
	while (sqlite3_step(sqlres) == SQLITE_ROW) {
	    if (numkeys == 0)
		keys = malloc(sizeof(struct key_st) * (numkeys + 1));
	    else
		keys = realloc(keys, sizeof(struct key_st) * (numkeys + 1));
	    keys[numkeys].fingerprint = NULL;
	    keys[numkeys].comment = NULL;
	    keys[numkeys].eprvkey = NULL;
	    keys[numkeys].pubkey = NULL;
	    keys[numkeys].hmac_hash_b64 = NULL;
	    keys[numkeys].comment = NULL;

	    strcata(&keys[numkeys].fingerprint, (char *) sqlite3_column_text(sqlres, 1));
	    strcata(&keys[numkeys].eprvkey, (char *) sqlite3_column_text(sqlres, 2));
	    strcata(&keys[numkeys].pubkey, (char *) sqlite3_column_text(sqlres, 3));
	    strcata(&keys[numkeys].hmac_hash_b64, (char *) sqlite3_column_text(sqlres, 4));
	    strcata(&keys[numkeys].comment, (char *) sqlite3_column_text(sqlres, 5));
	    numkeys++;
	}
	sqlite3_finalize(sqlres);
	if (numkeys > 1) {
	    char paxhdr_varstring[64];

	    for (int keynum = 0; keynum < numkeys; keynum++) {
		char tmpnumstr[64];
		sprintf(tmpnumstr, "%d", numkeys);
		setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.numkeys", tmpnumstr, strlen(tmpnumstr));
		sprintf(paxhdr_varstring, "TC.pubkey.fingerprint.%d", keynum);
		setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].fingerprint, strlen(keys[keynum].fingerprint));
		sprintf(paxhdr_varstring, "TC.eprivkey.%d", keynum);
		setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].eprvkey, strlen(keys[keynum].eprvkey));
		sprintf(paxhdr_varstring, "TC.pubkey.%d", keynum);
		setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].pubkey, strlen(keys[keynum].pubkey));
		sprintf(paxhdr_varstring, "TC.hmackeyhash.%d", keynum);
		setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].hmac_hash_b64, strlen(keys[keynum].hmac_hash_b64));
		sprintf(paxhdr_varstring, "TC.keyfile.comment.%d", keynum);
		setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].comment, strlen(keys[keynum].comment));
	    }
	    if (keygroups != NULL) {
		setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.keygroups", keygroups, strlen(keygroups));
		dfree(keygroups);
	    }
	}
	else {
	    int keynum = 0;
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.pubkey.fingerprint", keys[keynum].fingerprint, strlen(keys[keynum].fingerprint));
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.eprivkey", keys[keynum].eprvkey, strlen(keys[keynum].eprvkey));
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.pubkey", keys[keynum].pubkey, strlen(keys[keynum].pubkey));
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.hmackeyhash", keys[keynum].hmac_hash_b64, strlen(keys[keynum].hmac_hash_b64));
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.keyfile.comment", keys[keynum].comment, strlen(keys[keynum].comment));
	}
	tar_write_next_hdr(&gh);
	fsfree(&gh);
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

    }

    sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"select a.file_id, "
	"case when b.file_id not null and a.file_id != b.file_id  "
	"then 1 else a.ftype end,  "
	"a.permission, a.device_id, a.inode, a.user_name, a.user_id,  "
	"a.group_name, a.group_id, case when b.file_id not null and a.file_id != b.file_id then 0 else a.size end, a.sha1, a.datestamp, a.filename,  "
	"case when b.file_id not null and a.file_id != b.file_id  "
	"then b.filename else a.extdata end, a.xheader, c.keygroup "
	"from restore_file_entities a left join hardlink_file_entities b  "
	"on a.ftype = b.ftype and a.permission = b.permission  "
	"and a.device_id = b.device_id and a.inode = b.inode  "
	"and a.user_name = b.user_name and a.user_id = b.user_id  "
	"and a.group_name = b.group_name and a.group_id = b.group_id  "
	"and a.size = b.size and a.sha1 = b.sha1 and a.datestamp = b.datestamp  "
	"and a.extdata = b.extdata and a.xheader = b.xheader "
	"left join "

	"(select cd.file_id, group_concat(tar_keynum - 1, '|') keygroup from cipher_detail cd "
	"join restore_file_entities f "
	"on cd.file_id = f.file_id "
	"join temp_keymap on keynum = db_keynum "
	"group by cd.file_id "
	"order by 1) c "
	"on a.file_id = c.file_id order by 1"
	)), -1, &sqlres, 0);
    sqlite3_free(sqlstmt);
    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf(
	"select f.file_id, c.hmac, m.tar_keynum - 1 "
	"from restore_file_entities f join cipher_detail c "
	"on f.file_id = c.file_id join temp_keymap m "
	"on c.keynum = m.db_keynum order by 1, 3")), -1, &sqlres2, 0);

    sqlite3_free(sqlstmt);

    sqlres2_result = sqlite3_step(sqlres2);
    struct filespec fs;
    fsinit(&fs);
    char buf[512];
    char *sha1filepath = NULL;
    char *c_hdrbuf = NULL;
    size_t c_hdrbuf_alloc = 0;
    char *paxdata = NULL;
    int paxdatalen = 0;
    while (sqlite3_step(sqlres) == SQLITE_ROW) {
	char in_ftype = (sqlite3_column_text(sqlres, 1))[0];
	FILE *sha1file;
	size_t (*backing_fread)();
	void *backing_f_handle;
	size_t bytestoread;
	size_t blockpad;
	char tmpfsstring[32];

	if (in_ftype == 'E')
	    fs.ftype = '0';
	else
	    fs.ftype = (sqlite3_column_text(sqlres, 1))[0];
	fs.mode = strtoll((char *) sqlite3_column_text(sqlres, 2), 0, 8);

	strncpy(fs.auid, (char *) sqlite3_column_text(sqlres, 5), 32);
        fs.nuid = sqlite3_column_int(sqlres, 6);
        strncpy(fs.agid, (char *) sqlite3_column_text(sqlres, 7), 32);
        fs.ngid = sqlite3_column_int(sqlres, 8);
        fs.filesize = sqlite3_column_int64(sqlres, 9);
        fs.modtime = sqlite3_column_int(sqlres, 11);
	strncpya0(&(fs.filename), (char *) sqlite3_column_text(sqlres, 12), sqlite3_column_bytes(sqlres, 12));
	strncpya0(&(fs.linktarget), (char *) sqlite3_column_text(sqlres, 13), sqlite3_column_bytes(sqlres, 13));
	memcpya((void **) &(fs.xheader), (void *) sqlite3_column_blob(sqlres, 14), sqlite3_column_bytes(sqlres, 14));
	fs.xheaderlen = sqlite3_column_bytes(sqlres, 14);
	    
	// Process graft filenames
	for (i = 0; i < numgrafts; i++) {
	    if (strncmp(fs.filename, graft[i][0], strlen(graft[i][0])) == 0) {
		snprintf(graftfilename, 8192, "%s%s", graft[i][1], fs.filename + strlen(graft[i][0]));
		strncpya0(&fs.filename, graftfilename, 0);
		break;
	    }
	}

	if (((in_ftype == '0' || in_ftype == 'S') && fs.filesize > 0) || in_ftype == 'E' ||
	    getpaxvar(fs.xheader, fs.xheaderlen, "TC.sparse", &paxdata, &paxdatalen) == 0) {
	    if (sha1filepath != NULL)
		sha1filepath[0] = '\0';
	    strcata(&sha1filepath, config.vault);
	    strcata(&sha1filepath, "/");
	    strncata0(&sha1filepath, (char *) sqlite3_column_text(sqlres, 10), 2);
	    strcata(&sha1filepath, "/");
	    strcata(&sha1filepath, (char *) sqlite3_column_text(sqlres, 10) + 2);
	    if (in_ftype == '0' || in_ftype == 'S' || in_ftype == '1')
		strcata(&sha1filepath, ".lzo");
	    else if (in_ftype == 'E')
		strcata(&sha1filepath, ".enc");

	    sha1file = fopen(sha1filepath, "r");
	    if (sha1file == NULL) {
		perror("restore: open backing file:");
		fprintf(stderr, "ftype: %c Can not restore %s -- missing backing file %s\n", in_ftype, fs.filename, sha1filepath);
		continue;
	    }
	    if (in_ftype == 'E') {
		char paxhdr_varstring[32];
		int sz_c_hdr;
		char *tc_compression;
		char *tc_cipher;

		backing_f_handle = sha1file;
		backing_fread = fread;
		fseek(sha1file, 0L, SEEK_END);
		bytestoread = ftell(sha1file);
		rewind(sha1file);
		sz_c_hdr = getline(&c_hdrbuf, &c_hdrbuf_alloc, sha1file);
		tc_compression = c_hdrbuf;
		tc_cipher = strchr(c_hdrbuf, '|');
		if (tc_cipher != NULL) {
		    tc_cipher[0] = '\0';
		    tc_cipher++;
		    tc_cipher[strlen(tc_cipher) - 1] = '\0';
		}
		bytestoread -= sz_c_hdr;
		sprintf(tmpfsstring, "%llu", fs.filesize);
		setpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.compression", tc_compression, strlen(tc_compression));
		setpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.original.size", tmpfsstring, strlen(tmpfsstring));
		setpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.cipher", tc_cipher, strlen(tc_cipher));
		c_hdrbuf[0] = '\0';
//		setpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.filters", "compression|cipher", 18);
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.keygroup");
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.segmented.header");
		if (numkeys > 1)
		    setpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.keygroup", (char *) sqlite3_column_text(sqlres, 15), sqlite3_column_bytes(sqlres, 15));
		while (sqlres2_result == SQLITE_ROW && sqlite3_column_int(sqlres2, 0) < sqlite3_column_int(sqlres, 0))
		    sqlres2_result = sqlite3_step(sqlres2);
		while (sqlres2_result == SQLITE_ROW && sqlite3_column_int(sqlres2, 0) == sqlite3_column_int(sqlres, 0)) {
		    if (numkeys > 1) {
			sprintf(paxhdr_varstring, "TC.hmac.%d", sqlite3_column_int(sqlres2, 2));
			setpaxvar(&(fs.xheader), &(fs.xheaderlen), paxhdr_varstring, (char *) sqlite3_column_text(sqlres2, 1), strlen((char *)  sqlite3_column_text(sqlres2, 1)));

		    }
		    else
			setpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.hmac", (char *) sqlite3_column_text(sqlres2, 1), strlen((char *) sqlite3_column_text(sqlres2, 1)));
		    sqlres2_result = sqlite3_step(sqlres2);

		}

		fs.filesize = bytestoread;
	    }
	    else {
		backing_f_handle = lzop_init_r(fread, sha1file);
		backing_fread = lzop_read;
		bytestoread = fs.filesize;
	    }
	    if (in_ftype == 'S') {
		char *s_buf = NULL;
		int n;
		char **sparselist = NULL;
		unsigned long int sparsehdrsz;
		c_getline(&s_buf, backing_fread, backing_f_handle);
		n = parse(s_buf, &sparselist, ':');
		if (n <= 1 || n % 2 != 1) {
		    fprintf(stderr, "Sparse data corrupted header %s %d %s\n", sha1filepath, n, fs.filename);
		    continue;
		}
		fs.n_sparsedata = (n - 1) / 2;
		fs.sparse_realsize = fs.filesize;
		fs.filesize = strtoull(sparselist[0], 0, 10);
		bytestoread=fs.filesize;
		if (dmalloc_size(fs.sparsedata) < fs.n_sparsedata * sizeof(struct sparsedata))
		    fs.sparsedata = dmalloc(fs.n_sparsedata * sizeof(struct sparsedata));
		sparsehdrsz = ilog10(fs.n_sparsedata) + 2;
		for (int i = 0; i < (n - 1) / 2; i ++) {
		    ((fs.sparsedata)[i]).offset = strtoull(sparselist[i * 2 + 1], 0, 10);
		    ((fs.sparsedata)[i]).size = strtoull(sparselist[i * 2 + 2], 0, 10);
		    sparsehdrsz += ilog10(fs.sparsedata[i].offset) + 2;
                    sparsehdrsz += ilog10(fs.sparsedata[i].size) + 2;
		}

		sparsehdrsz += (512 - ((sparsehdrsz - 1) % 512 + 1));
		//fs.filesize += sparsehdrsz;
		dfree(sparselist);
		dfree(s_buf);

	    }
	    blockpad = 512 - ((bytestoread - 1) % 512 + 1);

	    if (use_pax_header == 1)
		fs.pax = 1;
	    tar_write_next_hdr(&fs);
	    while (bytestoread > 0) {
		size_t c;
		c = backing_fread(buf, 1, bytestoread > 512 ? 512 : bytestoread, backing_f_handle);
		if (c == 0)
		    break;
		fwrite(buf, 1, c, stdout);
		bytestoread -= c;
	    }
	    memset(buf, 0, 512);
	    fwrite(buf, 1, blockpad, stdout);
	    if (in_ftype != 'E')
	        lzop_finalize_r((struct lzop_file *) backing_f_handle);
	    fclose(sha1file);
	}
	else {
	    tar_write_next_hdr(&fs);
	}

	fsclear(&fs);
    }
    sqlite3_finalize(sqlres);
    sqlite3_finalize(sqlres2);
    fsfree(&fs);
    dfree(sha1filepath);
    memset(buf, 0, 512);
    fwrite(buf, 1, 512, stdout);
    fwrite(buf, 1, 512, stdout);
    if (c_hdrbuf != NULL)
	free(c_hdrbuf);

    if (graft != NULL)
	free(graft);
    free(files_from_fname);
    free(files_from_fnameu);
    return(0);
}
