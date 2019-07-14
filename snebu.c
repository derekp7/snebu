/* Snebu -- Simple Network Backup Utility
 * Copyright 2012, 2013 Derek Pressnall
 * This program may be distributed under the terms of the
 * GNU General Public License (GPL) Version 3.  See the file
 * COPYING.txt for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>

struct {
    char *vault;
    char *meta;
} config;

int initdb(sqlite3 *bkcatalog);
int sqlbusy(void *x, int y);
char *stresc(char *src, char **target);
char *strunesc(char *src, char **target);
long int strtoln(char *nptr, char **endptr, int base, int len);
int parsex(char *instr, char p, char ***b, int max);
int flush_received_files(sqlite3 *bkcatalog, int verbose, int bkid,
    unsigned long long est_size,  unsigned long long bytes_read, unsigned long long bytes_readp);

int logaction(sqlite3 *bkcatalog, int backupset_id, int action, char *message);
int my_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *carg1, char **errmsg);
int my_sqlite3_step(sqlite3_stmt *stmt);
int my_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);

void getconfig(char *configpatharg);
int newbackup(int argc, char **argv);
int submitfiles(int argc, char **argv);
int submitfiles_tmptables(sqlite3 *bkcatalog, int bkid);
int restore(int argc, char **argv);
int listbackups(int argc, char **argv);
int export(int argc, char **argv);
int import(int argc, char **argv);
int expire(int argc, char **argv);
int purge(int argc, char **argv);
int gethelp(int argc, char **argv);
int help(char *topic);

void concurrency_request_signal();
void concurrency_request();
void usage();

int concurrency_sleep_requested = 0;
int in_a_transaction = 0;
#define sqlite3_exec(a, b, c, d, e) my_sqlite3_exec(a, b, c, d, e)
#define sqlite3_step(a) my_sqlite3_step(a)
#define sqlite3_prepare_v2(a, b, c, d, e) my_sqlite3_prepare_v2(a, b, c, d, e)

#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>

#define F_H_FILTER      0x00000800L
struct cfile *cfinit(FILE *outfile);
struct cfile *cfinit_r(FILE *infile);
int cwrite(void *buf, size_t sz, size_t count, struct cfile *cfile);
int cread(void *buf, size_t sz, size_t count, struct cfile *cfile);
int cgetline(char **buf, size_t *sz, struct cfile *cfile);
int cclose(struct cfile *cfile);
int cclose_r(struct cfile *cfile);
uint32_t *htonlp(uint32_t v);
uint16_t *htonsp(uint16_t v);
size_t fwritec(const void *ptr, size_t size, size_t nmemb, FILE *stream, uint32_t *chksum);
int getpaxvar(char *paxdata, int paxlen, char *name, char **rvalue, int *rvaluelen); 
int cmpspaxvar(char *paxdata, int paxlen, char *name, char *invalue);
int setpaxvar(char **paxdata, int *paxlen, char *inname, char *invalue, int invaluelen);
int delpaxvar(char **paxdata, int *paxlen, char *inname);
unsigned int ilog10(unsigned int n);

struct cfile {
    char *buf;
    char *bufp;
    char *cbuf;
    lzo_uint bufsize;
    lzo_uint cbufsize;
    FILE *handle;
    unsigned char *working_memory;
};

struct subfuncs{
    char *funcname;
    int (*target)(int, char **);
};

int main(int argc, char **argv)
{
    struct subfuncs subfuncs[] = {
	{ "newbackup", &newbackup },
	{ "submitfiles", &submitfiles },
	{ "restore", &restore },
	{ "listbackups", &listbackups },
	{ "import", &import },
	{ "export", &export },
	{ "expire", &expire },
	{ "purge", &purge },
	{ "help", &gethelp }
    };
    struct option longopts[] = {
	{ "config", required_argument, NULL, 'c' },
	{ "vault", required_argument, NULL, 'v' },
	{ "catalog", required_argument, NULL, 'm' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
    int optc;
    char *configfile = NULL;
    int i;
    int n;
    char *vaultdir = NULL;
    char *metadir = NULL;
    signal(SIGUSR1, concurrency_request_signal);

    while ((optc = getopt_long(argc, argv, "+c:v:m:", longopts, &longoptidx)) >= 0) {
	switch (optc) {
	    case 'c':
		configfile = optarg;
		break;
	    case 'v':
		vaultdir = optarg;
		break;
	    case 'm':
		metadir = optarg;
		break;
	    default:
		usage();
		exit(1);
	}
    }

    getconfig(configfile);
    if (vaultdir != NULL) {
	asprintf(&(config.vault), "%s", vaultdir);
    }
    if (metadir != NULL) {
	asprintf(&(config.meta), "%s", metadir);
    }

    if (optind < argc) {
	for (i = 0; i < sizeof(subfuncs) / sizeof(*subfuncs); i++) {
	    if (strcmp(argv[optind], subfuncs[i].funcname) == 0) {
		n = optind;
		optind = 1;
		subfuncs[i].target(argc - n, argv + n);
		exit(0);
	    }
	}
    }
    usage();
    return 0;
}
int newbackup(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    char retention[128];
    int foundopts = 0;
    char *filespecs = 0;
    char **filespecsl = NULL;
    size_t filespeclen = 0;
    char *linkspecs = 0;
    size_t linkspeclen = 0;
    struct {
        char ftype;
        int mode;
	char devid[33];
	char inode[33];
        char auid[33];
        int nuid;
        char agid[33];
        int ngid;
        unsigned long long int filesize;
	char sha1[SHA_DIGEST_LENGTH * 2 + 1];
        int cmodtime;
        int modtime;
	char *filename;
	char *linktarget;
    } fs;
    int x;
    char *sqlstmt = 0;
    sqlite3_stmt *sqlres;
    int bkid = 0;
    sqlite3 *bkcatalog;
    char *bkcatalogp;
    char *sqlerr;
    char *(*graft)[2] = 0;
    int numgrafts = 0;
    int maxgrafts = 0;
    int input_terminator = 0;
    int output_terminator = 0;
    int force_full_backup = 0;
    char *escfname = 0;
    char *unescfname = 0;
    char *unescltarget = 0;
    int verbose = 0;
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "retention", required_argument, NULL, 'r' },
	{ "graft", required_argument, NULL, 0 },
	{ "files-from", required_argument, NULL, 'T' },
	{ "null", no_argument, NULL, 0 },
	{ "not-null", no_argument, NULL, 0 },
	{ "null-output", no_argument, NULL, 0 },
	{ "not-null-output", no_argument, NULL, 0 },
	{ "full", no_argument, NULL, 0 },
	{ "verbose", no_argument, NULL, 'v' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
    int i;


    while ((optc = getopt_long(argc, argv, "n:d:r:v", longopts, &longoptidx)) >= 0) {
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
		verbose += 1;
		foundopts |= 8;
		break;
	    case 0:
		if (strcmp("graft", longopts[longoptidx].name) == 0) {
		    char *grafteqptr;
		    if (numgrafts + 1>= maxgrafts) {
			maxgrafts += 16;
			graft = realloc(graft, sizeof(*graft) * maxgrafts);
		    }
		    if ((grafteqptr = strchr(optarg, '=')) == 0) {
			help("newbackup");
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
		    input_terminator = 0;
		if (strcmp("not-null", longopts[longoptidx].name) == 0)
		    input_terminator = 10;
		if (strcmp("null-output", longopts[longoptidx].name) == 0)
		    output_terminator = 0;
		if (strcmp("not-null-output", longopts[longoptidx].name) == 0)
		    output_terminator = 10;
		if (strcmp("full", longopts[longoptidx].name) == 0)
		    force_full_backup = 1;
		break;
	    default:
		usage();
		exit(1);
	    }
	}
    if ((foundopts & 7) != 7) {
	fprintf(stderr, "Didn't find all arguments\n");
        usage();
        exit(1);
    }
    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation error\n");
	exit(1);
    }
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
    x = initdb(bkcatalog);

    x = sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupsets (name, retention, serial)  "
	"values ('%s', '%s', '%s')", bkname, retention, datestamp)), 0, 0, &sqlerr);
    sqlite3_free(sqlstmt);
    x = sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select backupset_id, retention from backupsets  "
	    "where name = '%s' and serial = '%s'",
	    bkname, datestamp)), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
	if (strcmp((char *) sqlite3_column_text(sqlres, 1), retention) != 0) {
	    fprintf(stderr, "A backup already exists for %s/%s, but with retention schedule %s\n", bkname, datestamp, (char *) sqlite3_column_text(sqlres, 1));
	    exit(1);
	}
    }
    else {
	fprintf(stderr, "newbackup: failed to create backup id\n");
	exit(1);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

    logaction(bkcatalog, bkid, 0, "New backup");
    sqlite3_exec(bkcatalog,
	"create temporary table if not exists inbound_file_entities (  \n"
	"    backupset_id     integer,  \n"
	"    ftype         char,  \n"
	"    permission    char,  \n"
	"    device_id     char,  \n"
	"    inode         char,  \n"
	"    user_name     char,  \n"
	"    user_id       integer,  \n"
	"    group_name    char,  \n"
	"    group_id      integer,  \n"
	"    size          integer,  \n"
	"    sha1           char,  \n"
	"    cdatestamp    integer,  \n"
	"    datestamp     integer,  \n"
	"    filename      char,  \n"
	"    extdata       char default '',  \n"
	"    infilename    char,  \n"
	"constraint inbound_file_entitiesc1 unique (  \n"
	"    backupset_id,  \n"
	"    ftype,  \n"
	"    permission,  \n"
	"    device_id,  \n"
	"    inode,  \n"
	"    user_name,  \n"
	"    user_id,  \n"
	"    group_name,  \n"
	"    group_id,  \n"
	"    size,  \n"
	"    sha1,  \n"
	"    cdatestamp,  \n"
	"    datestamp,  \n"
	"    filename,  \n"
	"    extdata, \n"
	"    infilename))", 0, 0, &sqlerr);

	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n\n\n",sqlerr);
	    sqlite3_free(sqlerr);
	}

	sqlite3_exec(bkcatalog,
        "create index if not exists inbound_file_entitiesi1 on inbound_file_entities (  \n"
	"    filename)", 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n\n\n",sqlerr);
	    sqlite3_free(sqlerr);
	}

	sqlite3_exec(bkcatalog,
        "create index if not exists inbound_file_entitiesi2 on inbound_file_entities (  \n"
	"    infilename)", 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n\n\n",sqlerr);
	    sqlite3_free(sqlerr);
	}


    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    if (verbose >= 1)
	fprintf(stderr, "Receiving input file list\n");
    while (getdelim(&filespecs, &filespeclen, input_terminator, stdin) > 0) {
	int pathskip = 0;
	char pathsub[4096];
	parsex(filespecs, '\t', &filespecsl, 13);

	fs.ftype = *(filespecsl[0]);
	fs.mode = (int) strtol(filespecsl[1], NULL, 8);
	strncpy(fs.devid, filespecsl[2], 32);
	strncpy(fs.inode, filespecsl[3], 32);
	strncpy(fs.auid, filespecsl[4], 32);
	fs.nuid = atoi(filespecsl[5]);
	strncpy(fs.agid, filespecsl[6], 32);
	fs.ngid = atoi(filespecsl[7]);
	fs.filesize = strtoull(filespecsl[8], NULL, 10);
	strncpy(fs.sha1, filespecsl[9], 32);
	// Handle input datestamp of xxxxx.xxxxx
	if (strchr(filespecsl[10], '.') != NULL)
	    *(strchr(filespecsl[10], '.')) = '\0';
	fs.cmodtime = atoi(filespecsl[10]);
	if (strchr(filespecsl[11], '.') != NULL)
	    *(strchr(filespecsl[11], '.')) = '\0';
	fs.modtime = atoi(filespecsl[11]);
	fs.filename = filespecsl[12];

	if (fs.filename[strlen(fs.filename) - 1] == '\n')
	    fs.filename[strlen(fs.filename) - 1] = 0;
	// Remove trailing slash from directory names
	if (strlen(fs.filename) > 1 && fs.filename[strlen(fs.filename) - 1] == '/')
	    fs.filename[strlen(fs.filename) - 1] = 0;

	if (fs.ftype == 'l') {
	    if (input_terminator == 10) {
		fs.linktarget = strchr(fs.filename, '\t');
		if (fs.linktarget != 0) {
		    *(fs.linktarget) = 0;
		    fs.linktarget++;
		}
		else
		    fs.linktarget = "";
	    }
	    else if (getdelim(&linkspecs, &linkspeclen, 0, stdin) > 0)
		fs.linktarget = linkspecs;
	    else
		fs.linktarget = "";
	}
	else
	    fs.linktarget = "";
	if (input_terminator == 10) {
	    fs.filename = strunesc(fs.filename, &unescfname);
	    fs.linktarget = strunesc(fs.linktarget, &unescltarget);
	}

	if (fs.ftype == 'f')
	    fs.ftype = '0';
	else if (fs.ftype == 'l') {
	    fs.ftype = '2';
	    fs.filesize = 0;
	}
	else if (fs.ftype == 'd') {
	    fs.ftype = '5';
	    fs.filesize = 0;
	}
	pathskip=0;
	*pathsub='\0';
	for (i = 0; i < numgrafts; i++) {
	    int pathskipt = strlen(graft[i][0]);
	    if (fs.ftype == '5' && *(graft[i][0] + pathskipt - 1) == '/') {
	        pathskipt--;
	    }

	    if (strncmp(fs.filename, graft[i][0], pathskipt) == 0) {
		pathskip = pathskipt;
		strncpy(pathsub, graft[i][1], 4096);
		if (fs.ftype == '5' && *(pathsub + strlen(pathsub) - 1) == '/')
		    *(pathsub + strlen(pathsub) - 1) = '\0';
		break;
	    }
	}

	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "insert or ignore into inbound_file_entities "
	    "(backupset_id, ftype, permission, device_id, inode, user_name, user_id, group_name,  "
	    "group_id, size, sha1, cdatestamp, datestamp, filename, extdata, infilename)  "
	    "values ('%d', '%c', '%4.4o', '%s', '%s', '%s', '%d', '%s', '%d', '%llu', '%s', '%d', '%d', '%q%q', '%q', '%q')",
	    bkid, fs.ftype, fs.mode, fs.devid, fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid,
	    fs.filesize, fs.sha1, fs.cmodtime, fs.modtime, pathsub, fs.filename + pathskip, fs.linktarget, fs.filename)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
//	else
//	    fprintf(stderr, "%s\n", fs.filename);
	sqlite3_free(sqlstmt);
    }
    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
#ifdef PRELOAD_DIRS_AND_SYMLINKS
// This code will create entries for any directories / symlinks in input
// file list, so they don't have to be submitted by submitfiles() tar
    if (verbose == 1)
	fprintf(stderr, "Pre-loading directory and symlink entries\n");
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities  "
	"(ftype, permission, device_id, inode, user_name, user_id, group_name,  "
	"group_id, size, sha1, cdatestamp, datestamp, filename, extdata)  "
	"select i.ftype, permission, device_id, inode, user_name, user_id, group_name,  "
	"group_id, size, sha1, cdatestamp, datestamp, filename, extdata from inbound_file_entities i  "
	"where backupset_id = '%d' and (i.ftype = '5' or i.ftype = '2')", bkid)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
#endif

    if (verbose >= 2)
	fprintf(stderr, "Generating required files list\n");

    if (force_full_backup == 1) {
	if (verbose >= 1)
	    fprintf(stderr, "Forced full backup\n");
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "insert or ignore into needed_file_entities  "
	    "(backupset_id, device_id, inode, filename, infilename, size, cdatestamp)  "
	    "select backupset_id, device_id, inode, filename, infilename, size, cdatestamp from inbound_file_entities")), 0, 0, &sqlerr);
    }
    else {

	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "create temporary table thishost_file_ids as "
	    "select distinct file_id from backupsets b "
	    "join backupset_detail d "
	    "on b.backupset_id = d.backupset_id and name = '%q'", bkname)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
	sqlite3_free(sqlstmt);

	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "create temporary table thishost_file_details as "
	    "select t.file_id, ftype, permission, device_id, inode, user_name, user_id, "
	    "group_name, group_id, size, sha1, cdatestamp, datestamp, "
	    "filename, extdata from thishost_file_ids t join file_entities f "
	    "on t.file_id = f.file_id")), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
	sqlite3_free(sqlstmt);

	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "create index thishost_file_details_i1 on thishost_file_details (sha1)")), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "create index thishost_file_details_i2 on thishost_file_details (filename)")), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
        sqlite3_free(sqlstmt);

	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "insert or ignore into needed_file_entities  "
	    "(backupset_id, device_id, inode, filename, infilename, size, cdatestamp)  "
	    "select distinct %d, i.device_id, i.inode, i.filename, i.infilename, "
	    "i.size, i.cdatestamp from inbound_file_entities i  "
	    "left join thishost_file_details f on  "
	    "i.ftype = case when f.ftype = 'S' then '0' else f.ftype end  "
	    "and i.permission = f.permission  "
	    "and i.device_id = f.device_id and i.inode = f.inode  "
	    "and i.user_name = f.user_name and i.user_id = f.user_id  "
	    "and i.group_name = f.group_name and i.group_id = f.group_id  "
	    "and i.size = f.size and i.cdatestamp = f.cdatestamp and i.datestamp = f.datestamp  "
	    "and i.filename = f.filename and ((i.ftype = '0' and f.ftype = 'S')  "
	    "or i.extdata = f.extdata)  "
	    "left join diskfiles d "
	    "on f.sha1 = d.sha1  where "
	    "(f.file_id is null or "
	    "(d.sha1 is null and (i.ftype = '0' or i.ftype = 'S')))", bkid)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
	sqlite3_free(sqlstmt);

	if (verbose >= 2)
	    fprintf(stderr, "Loading existing files into backupset detail\n");
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "insert or ignore into backupset_detail  "
	    "(backupset_id, file_id)  "
	    "select %d, f.file_id from thishost_file_details f  "
	    "join inbound_file_entities i  "
	    "on i.ftype = case when f.ftype = 'S' then '0' else f.ftype end  "
	    "and i.permission = f.permission  "
	    "and i.device_id = f.device_id and i.inode = f.inode  "
	    "and i.user_name = f.user_name and i.user_id = f.user_id  "
	    "and i.group_name = f.group_name and i.group_id = f.group_id  "
	    "and i.size = f.size and i.cdatestamp = f.cdatestamp and i.datestamp = f.datestamp  "
	    "and i.filename = f.filename and ((i.ftype = '0' and f.ftype = 'S')  "
	    "or i.extdata = f.extdata)", bkid)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
	sqlite3_free(sqlstmt);
    }
    logaction(bkcatalog, bkid, 1, "Finished processing snapshot manifest");
    if (verbose >= 1)
	fprintf(stderr, "Returning list of required files\n");
    sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"select n.infilename from needed_file_entities n "
	"join inbound_file_entities i "
	"on n.infilename = i.infilename "
	"where n.backupset_id = '%d'", bkid)), -1, &sqlres, 0);
    while (sqlite3_step(sqlres) == SQLITE_ROW)
	if (output_terminator == 0) {
	    printf("%s", sqlite3_column_text(sqlres, 0));
	    fwrite("\000", 1, 1, stdout);
	}
	else
	    printf("%s\n", stresc((char *) sqlite3_column_text(sqlres, 0), &escfname));

    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);
    logaction(bkcatalog, bkid, 3, "Finished generating incremental manifest");

//    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
	
    sqlite3_close(bkcatalog);
    return(0);
}
int initdb(sqlite3 *bkcatalog)
{
    int err = 0;
    char *sqlerr = 0;
    int dbversion = -1;
    sqlite3_stmt *sqlres;

//    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);

// Set DB version if uninitialized

    if (sqlite3_prepare_v2(bkcatalog,
        ("select count(*) from sqlite_master"), -1, &sqlres, 0) == SQLITE_OK) {
	if (sqlite3_step(sqlres) == SQLITE_ROW) {
	    if (sqlite3_column_int(sqlres, 0) == 0) {
		sqlite3_exec(bkcatalog, "PRAGMA user_version = 0", 0, 0, 0);
	    }
	}
    }
    sqlite3_finalize(sqlres);

// Get the current DB version
    if (sqlite3_prepare_v2(bkcatalog,
        ("PRAGMA user_version "), -1, &sqlres, 0) == SQLITE_OK) {
	if (sqlite3_step(sqlres) == SQLITE_ROW) {
	    dbversion = sqlite3_column_int(sqlres, 0);
	}
    }
    if (dbversion == -1) {
        fprintf(stderr, "Error getting to database\n");
        return(1);
    }
    sqlite3_finalize(sqlres);

//  Will need this when tape library support is added.

#ifdef commented_out
    err = sqlite3_exec(bkcatalog,
	"    create table if not exists storagefiles (  \n"
	"    sha1           char,  \n"
	"    volume        char,  \n"
	"    segment       char,  \n"
	"    location      char,  \n"
	"constraint storagefilesc1 unique (  \n"
	"    sha1,  \n"
	"    volume,  \n"
	"    segment,  \n"
	"    location ))", 0, 0, 0);
#endif
    err = sqlite3_exec(bkcatalog,
	"create table if not exists diskfiles ( \n"
	"    sha1          char, \n"
	"constraint diskfilesc1 unique ( \n"
	"    sha1))", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "Create table diskfiles: %s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
	"create table if not exists file_entities (  \n"
	"    file_id       integer primary key,  \n"
	"    ftype         char,  \n"
	"    permission    char,  \n"
	"    device_id     char,  \n"
	"    inode         char,  \n"
	"    user_name     char,  \n"
	"    user_id       integer,  \n"
	"    group_name    char,  \n"
	"    group_id      integer,  \n"
	"    size          integer,  \n"
	"    sha1           char,  \n"
	"    cdatestamp    integer,  \n"
	"    datestamp     integer,  \n"
	"    filename      char,  \n"
	"    extdata       char default '',  \n"
	"    xheader       blob default '',  \n"
	"constraint file_entities_c1 unique (  \n"
	"    ftype,  \n"
	"    permission,  \n"
	"    device_id,  \n"
	"    inode,  \n"
	"    user_name,  \n"
	"    user_id,  \n"
	"    group_name,  \n"
	"    group_id,  \n"
	"    size,  \n"
	"    sha1,  \n"
	"    cdatestamp,  \n"
	"    datestamp,  \n"
	"    filename,  \n"
	"    extdata,  \n"
	"    xheader ))", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "Create table file_entities: %s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
	"create table if not exists received_file_entities (  \n"
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
	"foreign key(backupset_id) references backupsets(backupset_id),  \n"
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
	    "xheader ))", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
	"create table if not exists needed_file_entities (  \n"
	    "backupset_id  integer,  \n"
    	    "device_id     char,  \n"
       	    "inode         char,  \n"
	    "filename      char,  \n"
	    "infilename    char,  \n"
	    "size          integer,  \n"
	    "cdatestamp    integer,  \n"
	"foreign key(backupset_id) references backupsets(backupset_id),  \n"
	"unique (  \n"
	    "backupset_id,  \n"
	    "filename, \n"
	    "infilename ))", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
	"create table if not exists purgelist (  \n"
	    "datestamp      integer,  \n"
	    "sha1            char,  \n"
	"unique (  \n"
	    "datestamp,  \n"
	    "sha1 ))", 0, 0, 0);

    err = sqlite3_exec(bkcatalog,
	    "create table if not exists backupsets (  \n"
	    "backupset_id  integer primary key,  \n"
	    "name          char,  \n"
	    "retention     char,  \n"
	    "serial        char,  \n"
	"constraint backupsetsc1 unique (  \n"
	    "name,  \n"
	    "serial ))", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
	"create table if not exists log ( \n"
	"    backupset_id	integer, \n"
	"    logdate		integer, \n"
	"    action		integer, \n"
	"    message		char)", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
	    "create table if not exists backupset_detail (  \n"
	    "backupset_id  integer,  \n"
	    "file_id       integer,  \n"
	"unique (backupset_id, file_id)  \n"
	"foreign key(backupset_id) references backupsets(backupset_id),  \n"
	"foreign key(file_id) references file_entities(file_id) )", 0, 0, 0);
    if (err != 0)
	return(err);

// file_entities with backupsets and backupset_detail view
    err = sqlite3_exec(bkcatalog,
	"create view if not exists \n"
	"    file_entities_bd \n"
	"as select \n"
	"    f.file_id, ftype, permission, device_id, inode, user_name, \n"
	"    user_id, group_name, group_id, size, sha1, cdatestamp, \n"
	"    datestamp, filename, extdata, xheader, b.backupset_id, \n"
	"    name, retention, serial \n"
	"from file_entities f join backupset_detail d \n"
	"on f.file_id = d.file_id join backupsets b \n"
	"on d.backupset_id = b.backupset_id \n", 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "create view file_entities_bd %s\n", sqlerr);
	sqlite3_free(sqlerr);
    }

    err = sqlite3_exec(bkcatalog,
	"    create index if not exists needed_file_entitiesi1 on needed_file_entities (  \n"
	"    backupset_id, filename, infilename)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists needed_file_entitiesi2 on needed_file_entities (  \n"
	"    backupset_id, infilename, filename)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists needed_file_entitiesi3 on needed_file_entities (  \n"
	"    infilename, filename)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists needed_file_entitiesi4 on needed_file_entities (  \n"
	"    filename, infilename)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists backupset_detaili1 on backupset_detail (  \n"
	"    file_id, backupset_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists backupset_detaili2 on backupset_detail (  \n"
	"    backupset_id, file_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists file_entitiesi1 on file_entities (  \n"
	"    filename, file_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists file_entitiesi2 on file_entities (  \n"
	"    sha1)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists file_entitiesi3 on file_entities (  \n"
	"    file_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists received_file_entitiesi1 on received_file_entities (  \n"
	"    filename)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists received_file_entitiesi2 on received_file_entities (  \n"
	"    extdata)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists received_file_entitiesi3 on received_file_entities (  \n"
	"    backupset_id, filename)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists received_file_entitiesi4 on received_file_entities (  \n"
	"    backupset_id, extdata)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog,
	"    create index if not exists received_file_entitiesi5 on received_file_entities (  \n"
	"    sha1, filename)", 0, 0, 0);
    return(0);
}

void usage()
{
    printf(
	    "Usage: snebu [-c | --config filepath ] [ subcommand ] [ options ]\n"
	    "  where \"subcommand\" is one of the following:\n"
	    "    newbackup -n backupname -d datestamp -r schedule\n"
	    "\n"
	    "    submitfiles -n backupname -d datestamp\n"
	    "\n"
	    "    restore -n backupname -d datestamp [ file_list... ]\n"
	    "\n"
	    "    listbackups [ -n hostname [ -d datestamp ]] [ file_list... ]\n"
	    "\n"
	    "    expire [ -n hostname -d datestamp ] or [ -a days -r schedule [ -n hostname ]]\n"
	    "\n"
	    "    purge\n"
	    "\n"
	    "    help [ subcommand ]\n"
	    "\n"
	    " The \"snebu\" command is a backup tool which manages storing data from\n"
	    " backup sessions on disk-based storage, utilizing a simple database\n"
	    " for tracking backup sets and meta data.  Typically it is called via a\n"
	    " front end script (such as the included \"snebu-client\" shell script). \n"
	    " Documentation is provided here if you need to create a custom backup\n"
	    " client script.  The subcommands are listed below along with the most\n"
	    " common options.  Details on each command are given in each command's\n"
	    " help section.\n"
    );
}

int gethelp(int argc, char **argv) {
    if (argc > 1)
	help(argv[1]);
    else
	usage();
    return(0);
}

int help(char *topic)
{
    if (strcmp(topic, "newbackup") == 0)
	printf(
	    "Usage: snebu newbackup -n backupname -d datestamp -r schedule\n"
	    " The \"newbackup\" command creates a new backup set, by consuming a\n"
	    " tab-delimited list of file names (along with associated meta data) to\n"
	    " include in the backup.  It then compares this list to the backup\n"
	    " catalog database to determine which files are new, and which ones are\n"
	    " already contained on the backup media.  A list of new / changed files\n"
	    " is returned, which can then be passed along to \"tar\" to generate a\n"
	    "\n"
	    "Options:\n"
	    " -n, --name backupname      Name of the backup.  Usually set to the server\n"
	    "                            name that you are backing up.\n"
	    "\n"
	    " -d, --date datestamp       Date stamp for this backup set.  The format is in\n"
	    "                            time_t format, sames as the output of the \"date\n"
	    "                            +%%s\" command.\n"
	    "\n"
	    " -r, --retention schedule   Retention schedule for this backup set.  Typical\n"
	    "                            values are \"daily\", \"weekly\", \"monthly\", \"yearly\".\n"
	    "\n"
	    " -T, --files-from FILE      Read list of filenames (with meta data) to backup\n"
	    "                            from the named file, instead of standard input.\n"
	    "\n"
	    "     --null                 Inbound file backup list (-T, or standard input)\n"
	    "                            is null terminated\n"
	    "\n"
	    "     --not-null             Inbound file backup list (-T, or standard input)\n"
	    "                            is newline terminated\n"
	    "\n"
	    "     --null-output          Generate include-file-list with null terminated\n"
	    "                            lines.\n"
	    "\n"
	    "     --not-null-output      Generate include-file-list with newline\n"
	    "                            terminated lines.\n"
	    "\n"
	    " -f, --force-full           Force a full backup\n"
	    "\n"
	    "     --graft /path/name/=/new/name/ \n"
	    "                            Re-write path names beginning with \"/path/name/\"\n"
	    "                            to \"/new/name/\"\n"
	    "\n"
	    " -v,                        Verbose output\n"
	);
    if (strcmp(topic, "submitfiles") == 0)
	printf(
	    "Usage: snebu submitfiles -n backupname -d datestamp\n"
	    " The \"submitfiles\" command is called after newbackup, and is used to\n"
	    " submit a tar file containing the list of filest that newbackup\n"
	    " returned.\n"
	    "\n"
	    "Options:\n"
	    " -n, --name backupname      Name of the backup.  Usually set to the server\n"
	    "                            name that you are backing up.\n"
	    "\n"
	    " -d, --date datestamp       Date stamp for this backup set.  The format is in\n"
	    "                            time_t format, sames as the output of the \"date\n"
	    "                            +%%s\" command.\n"
	    "\n"
	    " -v,                        Verbose output\n"
	);
    if (strcmp(topic, "restore") == 0)
	printf(
	    "Usage: snebu restore -n backupname -d datestamp [ file_list... ]\n"
	    " Generates a tar file containing files from a given backup set.  Pipe\n"
	    " the output of this command into a tar command to actually restore\n"
	    " files.\n"
	    "\n"
	    "Options:\n"
	    " -n, --name backupname      Name of the backup.  Usually set to the server\n"
	    "                            name that you are backing up.\n"
	    "\n"
	    " -d, --date datestamp       Date stamp for this backup set.  The format is in\n"
	    "                            time_t format, sames as the output of the \"date\n"
	    "                            +%%s\" command.\n"
	    "     --graft /path/name/=/new/name/ \n"
	    "                            Re-write path names beginning with \"/path/name/\"\n"
	    "                            to \"/new/name/\"\n"
	);
    if (strcmp(topic, "listbackups") == 0)
	printf(
	    "Usage: snebu listbackups [ -n hostname [ -d datestamp ]] [ file_list... ]\n"
	    " With no arguments specified, \"listbackups\" will return a list of all\n"
	    " systems that are contained in the backup catalog.  Otherwise, when\n"
	    " specifying the -n parameter, a list of backup sets for that host is\n"
	    " returned.\n"
	    "\n"
	    "Options:\n"
	    " -n, --name backupname      Name of the backup.  Usually set to the server\n"
	    "                            name that you are backing up.\n"
	    "\n"
	    " -d, --date datestamp       Date stamp for this backup set.  The format is in\n"
	    "                            time_t format, sames as the output of the \"date\n"
	    "                            +%%s\" command.\n"
	);
    if (strcmp(topic, "expire") == 0)
	printf(
	    "Usage: snebu expire [ -n hostname -d datestamp ] or [ -a days -r schedule [ -n hostname ]]\n"
	    " Removes backup sessions from the snebu backup catalog database.  A\n"
	    " specific backup session can be purged by providing the \"-n\" and \"-d\"\n"
	    " options, or all backups that are part of a given retention schedule\n"
	    " (specified with \"-r\", and optionally from a given host, with the \"-n\"\n"
	    " option) that are older than a given number of days (\"-a\") are removed.\n"
	    "\n"
	    "Options:\n"
	    " -n, --name backupname      Name of the backup.  Usually set to the server\n"
	    "                            name that you are backing up.\n"
	    "\n"
	    " -d, --date datestamp       Date stamp for this backup set.  The format is in\n"
	    "                            time_t format, sames as the output of the \"date\n"
	    "                            +%%s\" command.\n"
	    "\n"
	    " -r, --retention schedule   Retention schedule for this backup set.  Typical\n"
	    "                            values are \"daily\", \"weekly\", \"monthly\", \"yearly\"."
	    "\n"
	    " -a, --age #days            Expire backups older than #days.\n"
	    "\n"
	    " -m, --min-keep #           When expiring with the \"-a\" flag, keep at least\n"
	    "                            this many of the most recent backups for a given\n"
	    "                            hostname/retention level.\n"
	);
    if (strcmp(topic, "purge") == 0)
	printf(
	    "Usage: snebu purge\n"
	    " Permanantly removes files from disk storage that are no longer\n"
	    " referenced by any backups. Run this command after running \"snebu\n"
	    " expire\".\n"
	);
    if (strcmp(topic, "help") == 0)
	printf(
	    "Usage: snebu help [ subcommand ]\n"
	    " Displays help text\n"
	);
    return(0);
}

int submitfiles(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    int foundopts = 0;
    struct {
        char filename[100];    //   0 - 99
        char mode[8];                   // 100 - 107
        char nuid[8];                   // 108 - 115
        char ngid[8];                   // 116 - 123
        char size[12];                  // 124 - 135
        char modtime[12];               // 136 - 147
        char chksum[8];                 // 148 - 155
        char ftype[1];                  // 156
        char linktarget[100];  // 157 - 256
        char ustar[6];                  // 257 - 262
        char ustarver[2];               // 263 - 264
        char auid[32];                  // 265 - 296
        char agid[32];                  // 297 - 328
        char devmaj[8];                 // 329 - 336
        char devmin[8];                 // 337 - 344
        union {
            char fileprefix[155];       // 345 - 499
            struct {
                char reserved1[41];     // 345 - 385
                struct {
                    char offset[12];    // 386 - 397, 410 - 421, ...
                    char size[12];      // 398 - 409, 422 - 431, ...
                } sd[4];                // 386 - 481
                char isextended;        // 482
                char realsize[12];      // 483 - 494
                char reserved2[5];      // 495 - 499
            } sph;   // sparse header   // 345 - 499
        } u;
        char reserved[12];              // 500 - 511
    } tarhead;
    struct {
        struct {
            char offset[12];
            char size[12];
        } sd[21];                       // 0 - 503
        char isextended;                // 504
        char reserved[8];               // 505 - 512
    } speh;  // sparse extended header

    struct filespec {
        char ftype;
        int mode;
	char devid[33];
	char inode[33];
        char auid[33];
        int nuid;
        char agid[33];
        int ngid;
        unsigned long long int filesize;
	char sha1[SHA_DIGEST_LENGTH * 2 + 1];
        int modtime;
	char *filename;
	char *linktarget;
	char *extdata;
	char *xheader;
	int xheaderlen;
    } fs;
    int count;
    int tcount;
    int bytestoread;
    int blockpad;
    char curblock[512];
    char junk[512];
    int i;
    unsigned long long int fullblocks;
    unsigned long long int blockstoread;
    int partialblock;
    char *tmpfilepath;
    char *tmpfiledir;
    int curtmpfile;
    struct cfile *curfile;
    char *destdir = config.vault;
    char *destfilepath;
    char *destfilepathm;
    SHA_CTX cfsha1ctl; // current file's sha1 sum
    unsigned char cfsha1[SHA_DIGEST_LENGTH];
    char cfsha1a[SHA_DIGEST_LENGTH * 2 + 10];
    char cfsha1d[SHA_DIGEST_LENGTH * 2 + 10];
    char cfsha1f[SHA_DIGEST_LENGTH * 2 + 10];
    int bkid = 0;
    int x;
    char *sqlstmt = 0;
    sqlite3_stmt *sqlres;
    struct stat tmpfstat;
    sqlite3 *bkcatalog;
    sqlite3_stmt *inbfrec;
    char *sqlerr;
    char *bkcatalogp;
    fd_set input_s;
    struct {
        unsigned long long int offset;
        unsigned long long int size;
    } *sparsedata;
    unsigned long long int s_realsize;
    char s_isextended;
    int n_sparsedata;
    int n_esparsedata;
    int m_sparsedata = 20;
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
    unsigned long long est_size = 0;
    unsigned long long bytes_read = 0;
    unsigned long long bytes_readp = 0;
    int verbose = 0;
    char statusline[80];
    char *paxpath = NULL;
    char *paxlinkpath = NULL;
    int paxpathlen = 0;
    int paxlinkpathlen = 0;
    char *paxsize = NULL;
    int paxsizelen = 0;
    int usepaxsize = 0;
    int paxsparse = 0;
    char *paxsparsename = 0;
    int paxsparsenamelen = 0;
    char *paxsparsesize = 0;
    int paxsparsesizelen = 0;
    char *paxsparsesegt = malloc(64);
    size_t paxsparsesegtn = 0;
    int paxsparsenseg = 0;
    int paxsparsehdrsz = 0;
    int blocksize;
    char *mp1;
    char *mp2;
    char *sparsefilep = NULL;

    fs.filename = 0;
    fs.linktarget = 0;
    fs.extdata = 0;
    fs.xheader = 0;
    fs.xheaderlen = 0;
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
    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation error\n");
	exit(1);
    }
    FD_SET(0, &input_s);
    select(1, &input_s, 0, 0, 0);
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
//    x = initdb(bkcatalog);

    x = sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select backupset_id from backupsets  "
	    "where name = '%q' and serial = '%q'",
	    bkname, datestamp)), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
    }
    else {
	fprintf(stderr, "bkid not found 1: %d %s\n", x, sqlstmt);
	return(1);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

    tmpfiledir = config.vault;
//    TODO: Enable this option when --faster flag is specified
//    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    in_a_transaction = 1;
    sparsedata = malloc(m_sparsedata * sizeof(*sparsedata));

    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select sum(size)  "
	    "from needed_file_entities where backupset_id = %d",
	    bkid)), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        est_size = sqlite3_column_int64(sqlres, 0);
    }
    else {
	fprintf(stderr, "%d: No data from %s\n", x, sqlstmt);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);


    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create temporary table if not exists current_backup_set_submitted_files_t "
	"as select filename, size from file_entities_bd where "
	"backupset_id = %d", bkid)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create temporary table if not exists current_backup_set_needed_files_t "
	"as select filename, size from needed_file_entities where "
	"backupset_id = %d", bkid)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    sqlite3_exec(bkcatalog, 
	"create index if not exists cbssfti on current_backup_set_submitted_files_t ( "
	"filename) ", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog, 
	"create index if not exists cbsnfti on current_backup_set_needed_files_t ( "
	"filename) ", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }

    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select sum(a.size)  "
	    "from current_backup_set_needed_files_t a "
	    "join current_backup_set_submitted_files_t b "
	    "on a.filename = b.filename")),
	    -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        bytes_readp = sqlite3_column_int64(sqlres, 0);
    }
    else {
	fprintf(stderr, "%d: No data from %s\n", x, sqlstmt);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

    if (verbose >= 1)
	fprintf(stderr, "Receiving files\n");

    submitfiles_tmptables(bkcatalog, bkid);
    sqlstmt = sqlite3_mprintf(
	"insert or ignore into received_file_entities_t  "
	"(backupset_id, ftype, permission, user_name, user_id,  "
	"group_name, group_id, size, sha1, datestamp, filename, extdata, xheader)  "
	"values (@bkid, @ftype, @mode, @auid, @nuid, @agid,  "
	"@ngid, @filesize, @sha1, @modtime, @filename, @linktarget, @xheader)");

    sqlite3_prepare_v2(bkcatalog, sqlstmt, -1, &inbfrec, 0);
    sqlite3_free(sqlstmt);

    logaction(bkcatalog, bkid, 4, "Begin receiving files");

    // Read TAR file from std input
    while (1) {
        // Read tar 512 byte header into tarhead structure
        count = fread(&tarhead, 1, 512, stdin);
        if (count < 512) {
                fprintf(stderr, "tar short read\n");
		flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);
                return (1);
        }
        if (tarhead.filename[0] == 0) {	// End of TAR archive

//	    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
	    logaction(bkcatalog, bkid, 5, "End receiving files");
	    flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);

	    logaction(bkcatalog, bkid, 7, "End post processing received files");

            sqlite3_close(bkcatalog);

            return(0);
        }

        // A file type of "L" means a long (> 100 character) filename.  File name begins in next block.
        if (*(tarhead.ftype) == 'L') {
            bytestoread=strtoull(tarhead.size, 0, 8);
	    blockpad = 512 - ((bytestoread - 1) % 512 + 1);
            fs.filename = malloc(bytestoread + 1);
            count = fread(fs.filename, 1, bytestoread, stdin);
            if (count < bytestoread) {
                printf("tar short read\n");
		flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);
                return(1);
            }
            count = fread(junk, 1, blockpad, stdin);
            if (count < blockpad) {
                printf("tar short read\n");
		flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);
                return(1);
            }
            fs.filename[bytestoread] = 0;
            continue;
        }
        // A file type of "K" means a long (> 100 character) link target.
        if (*(tarhead.ftype) == 'K') {
            bytestoread=strtoull(tarhead.size, 0, 8);
	    blockpad = 512 - ((bytestoread - 1) % 512 + 1);
            fs.linktarget = malloc(bytestoread + 1);
            tcount = 0;
            while (bytestoread - tcount > 0) {
                count = fread(fs.linktarget + tcount, 1, bytestoread - tcount, stdin);
                tcount += count;
            }
            tcount = 0;
            while (blockpad - tcount > 0) {
                count = fread(junk, 1, blockpad - tcount, stdin);
                tcount += count;
            }
            fs.linktarget[bytestoread] = 0;
            continue;
        }
	// File type "x" is an extended header for the following file
	if (*(tarhead.ftype) == 'x') {
            bytestoread=strtoull(tarhead.size, 0, 8);
	    fs.xheaderlen = bytestoread;
	    blockpad = 512 - ((bytestoread - 1) % 512 + 1);
//            fs.xheader = malloc(bytestoread + 1);
            fs.xheader = malloc(bytestoread);
            tcount = 0;
            while (bytestoread - tcount > 0) {
                count = fread(fs.xheader + tcount, 1, bytestoread - tcount, stdin);
                tcount += count;
            }
            tcount = 0;
            while (blockpad - tcount > 0) {
                count = fread(junk, 1, blockpad - tcount, stdin);
                tcount += count;
            }
//	    fs.xheader[bytestoread] = 0;
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "path", &paxpath, &paxpathlen) == 0) {
		fs.filename = malloc(paxpathlen);
		strncpy(fs.filename, paxpath, paxpathlen);
		fs.filename[paxpathlen - 1] = '\0';
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "path");
	    }
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "linkpath", &paxlinkpath, &paxlinkpathlen) == 0) {
		fs.linktarget = malloc(paxlinkpathlen);
		strncpy(fs.linktarget, paxlinkpath, paxlinkpathlen);
		fs.linktarget[paxlinkpathlen - 1] = '\0';
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "linkpath");
	    }
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "size", &paxsize, &paxsizelen) == 0) {
		fs.filesize = strtoull(paxsize, 0, 10);
		usepaxsize = 1;
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "size");
	    }
	    if (cmpspaxvar(fs.xheader, fs.xheaderlen, "GNU.sparse.major", "1") == 0 &&
		cmpspaxvar(fs.xheader, fs.xheaderlen, "GNU.sparse.minor", "0") == 0) {
		paxsparse=1;
		getpaxvar(fs.xheader, fs.xheaderlen, "GNU.sparse.name", &paxsparsename, &paxsparsenamelen); //TODO handle error status
		getpaxvar(fs.xheader, fs.xheaderlen, "GNU.sparse.realsize", &paxsparsesize, &paxsparsesizelen); //TODO handle error status
		s_realsize = strtoull(paxsparsesize, 0, 10);
		fs.filename = malloc(paxsparsenamelen);
		strncpy(fs.filename, paxsparsename, paxsparsenamelen - 1);
		fs.filename[paxsparsenamelen - 1] = '\0';
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "GNU.sparse.major");
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "GNU.sparse.minor");
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "GNU.sparse.name");
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "GNU.sparse.realsize");

	    }
//	    delpaxvar(&(fs.xheader), &(fs.xheaderlen), "mtime");
//	    delpaxvar(&(fs.xheader), &(fs.xheaderlen), "ctime");

            continue;
	}
	// Process TAR header
	if (usepaxsize == 0) {
	    fs.filesize = 0;
	    if ((unsigned char) tarhead.size[0] == 128)
		for (i = 0; i < 8; i++)
		    fs.filesize += (( ((unsigned long long) ((unsigned char) (tarhead.size[11 - i]))) << (i * 8)));
	    else
		fs.filesize=strtoull(tarhead.size, 0, 8);
	}
	else {
	    usepaxsize = 0;
	}
	if (paxsparse == 1)
	    fs.ftype = 'S';
	else
	    fs.ftype = *tarhead.ftype;

        fs.nuid=strtol(tarhead.nuid, 0, 8);
        fs.ngid=strtol(tarhead.ngid, 0, 8);
        fs.modtime=strtol(tarhead.modtime, 0, 8);
        fs.mode=strtol(tarhead.mode + 2, 0, 8);
        fullblocks = (fs.filesize / 512);
        partialblock = fs.filesize % 512;
	blockstoread = fullblocks + (partialblock > 0 ? 1 : 0);
	blocksize = 512;

        if (strlen(tarhead.auid) == 0)
            sprintf(tarhead.auid, "%d", fs.nuid);
        if (strlen(tarhead.agid) == 0)
            sprintf(tarhead.agid, "%d", fs.ngid);
	strncpy(fs.auid, tarhead.auid, 32);
	fs.auid[32] = 0;
	strncpy(fs.agid, tarhead.agid, 32);
	fs.agid[32] = 0;

        if (fs.filename == 0) {
            strncpy((fs.filename = malloc(101)), tarhead.filename, 100);
            fs.filename[100] = 0;
        }
        if (fs.linktarget == 0) {
            strncpy((fs.linktarget = malloc(101)), tarhead.linktarget, 100);
            fs.linktarget[100] = 0;
        }
	    // Commit transaction if in the middle of a large file
	if (fs.filesize > 200000000) {
//	    fprintf(stderr, "submitfiles: large file, suspending transaction\n");
//	    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
	    in_a_transaction = 0;
	}
        // If this is a regular file (type 0)
        if (*(tarhead.ftype) == '0' || *(tarhead.ftype) == 'S') {

            // Handle sparse files
            if (*(tarhead.ftype) == 'S') {
                s_isextended = tarhead.u.sph.isextended;
                n_sparsedata = 0;
                if ((unsigned char) tarhead.u.sph.realsize[0] == 128)
                    for (i = 0; i < 8; i++)
                        s_realsize  += (( ((unsigned long long) ((unsigned char) (tarhead.u.sph.realsize[11 - i]))) << (i * 8)));
                else
                    s_realsize = strtoull(tarhead.u.sph.realsize, 0, 8);

                for (n_sparsedata = 0; n_sparsedata < 4 && tarhead.u.sph.sd[n_sparsedata].offset[0] != 0; n_sparsedata++) {
                    sparsedata[n_sparsedata].offset = 0;
                    sparsedata[n_sparsedata].size = 0;
                    if (n_sparsedata >= m_sparsedata - 1) {
                        sparsedata = realloc(sparsedata, sizeof(*sparsedata) * (m_sparsedata += 20));
                    }
                    if ((unsigned char) tarhead.u.sph.sd[n_sparsedata].offset[0] == 128)
                        for (i = 0; i < 8; i++) {
                            sparsedata[n_sparsedata].offset  += (( ((unsigned long long) ((unsigned char) (tarhead.u.sph.sd[n_sparsedata].offset[11 - i]))) << (i * 8)));
			}
                    else
                        sparsedata[n_sparsedata].offset = strtoull(tarhead.u.sph.sd[n_sparsedata].offset, 0, 8);
                    if ((unsigned char) tarhead.u.sph.sd[n_sparsedata].size[0] == 128)
                        for (i = 0; i < 8; i++) {
                            sparsedata[n_sparsedata].size += (( ((unsigned long long) ((unsigned char) (tarhead.u.sph.sd[n_sparsedata].size[11 - i]))) << (i * 8)));
			}
                    else
                        sparsedata[n_sparsedata].size = strtoull(tarhead.u.sph.sd[n_sparsedata].size, 0, 8);
                }
                while (s_isextended == 1) {
                    count = fread(&speh, 1, 512, stdin);
                    if (count < 512) {
                        printf("tar short read\n");
			flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);
                        return(1);
                    }
                    s_isextended = speh.isextended;

                    for (n_esparsedata = 0; n_esparsedata < 21 && speh.sd[n_esparsedata].offset[0] != 0; n_esparsedata++, n_sparsedata++) {
                        if (n_sparsedata >= m_sparsedata - 1) {
                            sparsedata = realloc(sparsedata, sizeof(*sparsedata) * (m_sparsedata += 20));
                        }
                        sparsedata[n_sparsedata].offset = 0;
                        sparsedata[n_sparsedata].size = 0;
                        if ((unsigned char) speh.sd[n_esparsedata].offset[0] == 128)
                            for (i = 0; i < 8; i++)
                                sparsedata[n_sparsedata].offset  += (( ((unsigned long long) ((unsigned char) (speh.sd[n_esparsedata].offset[11 - i]))) << (i * 8)));
                        else
                            sparsedata[n_sparsedata].offset = strtoull(speh.sd[n_esparsedata].offset, 0, 8);
                        if ((unsigned char) speh.sd[n_esparsedata].size[0] == 128)
                            for (i = 0; i < 8; i++)
                                sparsedata[n_sparsedata].size += (( ((unsigned long long) ((unsigned char) (speh.sd[n_esparsedata].size[11 - i]))) << (i * 8)));
                        else
                            sparsedata[n_sparsedata].size = strtoull(speh.sd[n_esparsedata].size, 0, 8);
                    }
                }
            } //  End sparse file handling

	    if (paxsparse == 1 && *(tarhead.ftype) == '0') {
		paxsparsehdrsz = 0;
		paxsparsehdrsz += getline(&paxsparsesegt, &paxsparsesegtn, stdin);
		paxsparsenseg = atoi(paxsparsesegt);
		n_sparsedata = 0;
		while (paxsparsenseg-- > 0) {
		    if (n_sparsedata >= m_sparsedata - 1)
			sparsedata = realloc(sparsedata, sizeof(*sparsedata) * (m_sparsedata += 20));
		    paxsparsehdrsz += getline(&paxsparsesegt, &paxsparsesegtn, stdin);
		    sparsedata[n_sparsedata].offset = strtoull(paxsparsesegt, 0, 10);
		    paxsparsehdrsz += getline(&paxsparsesegt, &paxsparsesegtn, stdin);
		    sparsedata[n_sparsedata].size = strtoull(paxsparsesegt, 0, 10);
		    n_sparsedata++;
		}
		paxsparsehdrsz += fread(junk, 1, 512 - paxsparsehdrsz % 512, stdin);
		fullblocks = (fs.filesize / 512) - (int) (paxsparsehdrsz / 512);
		fs.filesize -= paxsparsehdrsz;
		blockstoread -= (int) paxsparsehdrsz / 512;
		blocksize = 512 - paxsparsehdrsz % 512;
	    }


	    // Set up temporary file to write out to.
            tmpfilepath = malloc(strlen(tmpfiledir) + 10);
            sprintf(tmpfilepath, "%s/tbXXXXXX", tmpfiledir);
            curtmpfile = mkstemp(tmpfilepath);
            if (curtmpfile == -1) {
                fprintf(stderr, "Error opening temp file %s\n", tmpfilepath);
		flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);
                return(1);
            }
	    curfile = cfinit(fdopen(curtmpfile, "w"));
            SHA1_Init(&cfsha1ctl);

            if (*(tarhead.ftype) == 'S' || paxsparse == 1) {
		for (i = 0; i < n_sparsedata; i++) {
		    if (i == 0) {
			if (asprintf(&sparsefilep, "%llu:%llu:%llu", fs.filesize, sparsedata[i].offset, sparsedata[i].size) < 0) {
			    fprintf(stderr, "Memory allocation error\n");
			    exit(0);
			}
			cwrite(sparsefilep, strlen(sparsefilep), 1, curfile);
			SHA1_Update(&cfsha1ctl, sparsefilep, strlen(sparsefilep));
		    }
		    else {
			if (asprintf(&sparsefilep, ":%llu:%llu", sparsedata[i].offset, sparsedata[i].size) < 0) {
			    fprintf(stderr, "Memory allocation failure\n");
			    exit(1);
			}
			cwrite(sparsefilep, strlen(sparsefilep), 1, curfile);
			SHA1_Update(&cfsha1ctl, sparsefilep, strlen(sparsefilep));
		    }
		}
		if (asprintf(&sparsefilep, "\n") < 0) {
		    fprintf(stderr, "Memory allocation failure\n");
		    exit(1);
		}
                cwrite(sparsefilep, strlen(sparsefilep), 1, curfile);
                SHA1_Update(&cfsha1ctl, sparsefilep, strlen(sparsefilep));
	    }

            for (i = 1; i <= blockstoread; i++) {
                count = fread(curblock, 1, blocksize, stdin);
                if (count < blocksize) {
                    printf("tar short read\n");
		    flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);
                    return(1);
                }

                if (i == blockstoread) {
                    if (partialblock > 0) {
                        cwrite(curblock, 1, partialblock, curfile);
                        SHA1_Update(&cfsha1ctl, curblock, partialblock);
                        break;
                    }
                }
                cwrite(curblock, blocksize, 1, curfile);
                SHA1_Update(&cfsha1ctl, curblock, blocksize);
		blocksize=512;
            }

	    cclose(curfile);
	    if (in_a_transaction == 0) {
//		sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
		in_a_transaction = 1;
	    }
            SHA1_Final(cfsha1, &cfsha1ctl);
            for (i = 0; i < SHA_DIGEST_LENGTH; i++)
                sprintf(cfsha1a + i * 2, "%2.2x", (unsigned int) cfsha1[i]);
            cfsha1a[i * 2] = 0;
            for (i = 0; i < 1; i++)
                sprintf(cfsha1d + i * 2, "%2.2x", (unsigned int) cfsha1[i]);
            cfsha1d[i * 2] = 0;
            for (i = 1; i < SHA_DIGEST_LENGTH; i++)
                sprintf(cfsha1f + (i - 1) * 2, "%2.2x", (unsigned int) cfsha1[i]);
            cfsha1f[(i - 1) * 2] = 0;
	    strcpy(fs.sha1, cfsha1a);

            sprintf((destfilepath = malloc(strlen(destdir) + strlen(cfsha1a) + 7)), "%s/%s/%s.lzo", destdir, cfsha1d, cfsha1f);
            sprintf((destfilepathm = malloc(strlen(destdir) + 4)), "%s/%s", destdir, cfsha1d);

//	    Will need this when tape library support is added.  For now
//	    it is more efficient to leave it out.

#ifdef commented_out
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into storagefiles (sha1, volume, segment, location)  "
		"values ('%s', 0, 0, '%q/%q.lzo')", cfsha1a, cfsha1d, cfsha1f)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n", sqlerr);
		sqlite3_free(sqlerr);
	    }
#endif
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into diskfiles_t (sha1)  "
		"values ('%s')", cfsha1a)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n", sqlerr);
		sqlite3_free(sqlerr);
	    }


	    if (stat(destfilepathm, &tmpfstat) == 0) // If the directory exists
		rename(tmpfilepath, destfilepath);   // move temp file to directory
	    else {
		if (mkdir(destfilepathm, 0770) == 0) { // else make the directory first
		    rename(tmpfilepath, destfilepath);
		}
		else if (stat(destfilepathm, &tmpfstat) == 0) {
		    rename(tmpfilepath, destfilepath);   // move temp file to directory
		}
		else {
		    fprintf(stderr, "Error creating directory %s\n", destfilepath);
		    flush_received_files(bkcatalog, verbose, bkid, est_size, bytes_read, bytes_readp);
		    return(1);
		}
	    }

	    sqlite3_bind_int(inbfrec, 1, bkid);
	    sqlite3_bind_text(inbfrec, 2, (mp1 = sqlite3_mprintf("%c", fs.ftype)), -1, SQLITE_STATIC);
	    sqlite3_bind_text(inbfrec, 3, (mp2 = sqlite3_mprintf("%4.4o", fs.mode)), -1, SQLITE_STATIC);
	    sqlite3_bind_text(inbfrec, 4, fs.auid, -1, SQLITE_STATIC);
	    sqlite3_bind_int(inbfrec, 5, fs.nuid);
	    sqlite3_bind_text(inbfrec, 6, fs.agid, -1, SQLITE_STATIC);
	    sqlite3_bind_int(inbfrec, 7, fs.ngid);
	    sqlite3_bind_int64(inbfrec, 8, fs.ftype == 'S' || paxsparse == 1 ? s_realsize : fs.filesize);
	    sqlite3_bind_text(inbfrec, 9, fs.sha1, -1, SQLITE_STATIC);
	    sqlite3_bind_int(inbfrec, 10, fs.modtime);
	    sqlite3_bind_text(inbfrec, 11, fs.filename, -1, SQLITE_STATIC);
	    sqlite3_bind_text(inbfrec, 12, fs.extdata == 0 ? "" : fs.extdata, -1, SQLITE_STATIC);
	    sqlite3_bind_blob(inbfrec, 13, fs.xheaderlen == 0 ? "" : fs.xheader, fs.xheaderlen, SQLITE_STATIC);
	    if ( ! sqlite3_step(inbfrec)) {
		fprintf(stderr, "sqlite3_step error\n");
		exit(1);
	    }
	    sqlite3_reset(inbfrec);
	    sqlite3_free(mp1);
	    sqlite3_free(mp2);
	    paxsparse = 0;
	
            free(tmpfilepath);
            free(destfilepath);
            free(destfilepathm);
        }

        // Hard link (type 1) or sym link (type 2)
	else if (*(tarhead.ftype) == '1' || *(tarhead.ftype) == '2' || *(tarhead.ftype) == '5') {

	    if (*(tarhead.ftype) == '5')
		if (fs.filename[strlen(fs.filename) - 1] == '/')
		    fs.filename[strlen(fs.filename) - 1] = 0;

	    sqlite3_bind_int(inbfrec, 1, bkid);
	    sqlite3_bind_text(inbfrec, 2, (mp1 = sqlite3_mprintf("%c", fs.ftype)), -1, SQLITE_STATIC);
	    sqlite3_bind_text(inbfrec, 3, (mp2 = sqlite3_mprintf("%4.4o", fs.mode)), -1, SQLITE_STATIC);
	    sqlite3_bind_text(inbfrec, 4, fs.auid, -1, SQLITE_STATIC);
	    sqlite3_bind_int(inbfrec, 5, fs.nuid);
	    sqlite3_bind_text(inbfrec, 6, fs.agid, -1, SQLITE_STATIC);
	    sqlite3_bind_int(inbfrec, 7, fs.ngid);
	    sqlite3_bind_int64(inbfrec, 8, fs.filesize);
	    sqlite3_bind_text(inbfrec, 9, "0", -1, SQLITE_STATIC);
	    sqlite3_bind_int(inbfrec, 10, fs.modtime);
	    sqlite3_bind_text(inbfrec, 11, fs.filename, -1, SQLITE_STATIC);
	    sqlite3_bind_text(inbfrec, 12, fs.linktarget == 0 ? "" : fs.linktarget, -1, SQLITE_STATIC);
	    sqlite3_bind_blob(inbfrec, 13, fs.xheaderlen == 0 ? "" : fs.xheader, fs.xheaderlen, SQLITE_STATIC);
	    if (! sqlite3_step(inbfrec)) {
	        fprintf(stderr, "sqlite3_step error\n"); ;
		exit(1);
	    }
	    sqlite3_reset(inbfrec);
	    sqlite3_free(mp1);
	    sqlite3_free(mp2);

	}
	bytes_read += fs.filesize;
	if (verbose >= 1) {
	    sprintf(statusline, "%llu/%llu bytes, %.0f %%", (bytes_read + bytes_readp), est_size, est_size != 0 ? ((double) (bytes_read + bytes_readp) / (double) est_size * 100) : 0) ;
	    fprintf(stderr, "\r%45s", statusline);
	}

	if (fs.filename != 0)
	    free(fs.filename);
	fs.filename = 0;
	if (fs.linktarget != 0)
	    free(fs.linktarget);
	fs.linktarget = 0;
	if (fs.extdata != 0)
	    free(fs.extdata);
	fs.extdata = 0;
	if (fs.xheader != 0)
	    free(fs.xheader);
	fs.xheader = 0;
	fs.xheaderlen = 0;
    }

}

struct tarhead {
        char filename[100];
        char mode[8];
        char nuid[8];
        char ngid[8];
        char size[12];
        char modtime[12];
        char chksum[8];
        char ftype[1];
        char linktarget[100];
        char ustar[6];
        char ustarver[2];
        char auid[32];
        char agid[32];
        char devmaj[8];
        char devmin[8];
        union {
            char fileprefix[155];       // 345 - 499
            struct {
                char reserved1[41];     // 345 - 385
		char item[8][12];
//                struct {
//                    char offset[12];    // 386 - 397, 410 - 421, ...
//                    char size[12];      // 398 - 409, 422 - 431, ...
//                } sd[4];                // 386 - 481
                char isextended;        // 482
                char realsize[12];      // 483 - 494
                char reserved2[5];      // 495 - 499
            } sph;   // sparse header   // 345 - 499
        } u;
        char reserved[12];
};
struct speh {		// sparse extended header
    char item[42][12];
//    struct {
//        char offset[12];
//        char size[12];
//    } sd[21];                       // 0 - 503
    char isextended;                // 504
    char reserved[7];               // 505 - 511
}; 


int restore(int argc, char **argv)
{

    struct tarhead tarhead;
    struct tarhead longtarhead;
    struct tarhead xtarhead;
    struct speh speh;
    char bkname[128];
    char datestamp[128];
    char retention[128];

    char *srcdir = 0;
//    FILE *curfile;
    struct cfile *curfile;
    const unsigned char *sha1;
    const char *sfilename = 0;
    char *filename;
    char graftfilename[8192];
    char *linktarget = 0;
    const char *xheader_d = 0;
    char *xheader = 0;
    int xheaderlen = 0;
    int optc;
    int foundopts = 0;
    int i, j;
    char *p;
    unsigned int tmpchksum;
    char *sha1filepath;
    int sha1file;
    unsigned long long bytestoread;
    int count;
    char curblock[512];
    int paxsparsehdrsz = 0;

    struct {
	char ftype;
	int mode;
	char auid[33];
	char agid[33];
	int nuid;
	int ngid;
	int modtime;
        unsigned long long int filesize;
    } t;
    long long int tblocks;
    unsigned int lendian = 1;	// Little endian?
    int blocksize;

    char *ssparseinfo = 0;
    size_t ssparseinfosz;
    long long int *sparseinfo;
    char *sparsefilepath = 0;
    int nsi;
    int msi;
    char *sqlstmt = 0;
    sqlite3_stmt *sqlres;
    sqlite3 *bkcatalog;
    char *bkcatalogp;
    char *filespec = 0;
    int filespeclen;
    char *sqlerr;
    int use_pax_header = 0;
    int no_use_pax_header = 0;
    int verbose = 0;
    char *(*graft)[2] = 0;
    int numgrafts = 0;
    int maxgrafts = 0;
    char pax_size[64];
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "pax", no_argument, NULL, 0 },
	{ "nopax", no_argument, NULL, 0 },
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
    msi = 256;
    sparseinfo = malloc(msi * sizeof(*sparseinfo));

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
		verbose = 1;
		foundopts |= 4;
		break;
	    case 0:
		if (strcmp("pax", longopts[longoptidx].name) == 0)
                    use_pax_header = 1;
		if (strcmp("nopax", longopts[longoptidx].name) == 0)
                    no_use_pax_header = 1;
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
		strcat(filespec, " and (f.filename glob ");
	    else
		strcat(filespec, " or f.filename glob ");
	    strcat(filespec, sqlite3_mprintf("'%q'", argv[i]));
	}
	strcat(filespec, ")");
    }


    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation failure\n");
	exit(1);
    }
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
//    x = initdb(bkcatalog);

    if (srcdir == 0)
	srcdir = config.vault;

    sha1filepath = malloc(strlen(srcdir) + 48);

    // Zero out tar header
    for (i = 0; i < sizeof(tarhead); i++) {
	(((unsigned char *) (&tarhead)))[i] = 0;
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
	while ((files_from_0 == 0 ?
	    getline(&files_from_fname, &files_from_fname_len, FILES_FROM) :
	    getdelim(&files_from_fname, &files_from_fname_len, 0, FILES_FROM)) > -1) {
	    if (files_from_fname[strlen(files_from_fname) - 1] == '\n')
		files_from_fname[strlen(files_from_fname) - 1] = '\0';
	    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(
		"insert or ignore into files_from "
		"(filename) values ('%q')", files_from_0 != 0 ? files_from_fname :
		strunesc(files_from_fname, &files_from_fnameu)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n\n\n",sqlerr);
		sqlite3_free(sqlerr);
	    }
	}
	join_files_from_sql = "join files_from r on f.filename = r.filename";

    }
    sqlite3_exec(bkcatalog, sqlstmt = "  "
    "create temporary table if not exists restore_file_entities (  \n"
	"file_id       integer primary key,  \n"
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
	"xheader ))", 0, 0, 0);
	

    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(
	"insert or ignore into restore_file_entities  "
	"(ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, datestamp, filename, extdata, xheader, serial)  "
	"select ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, datestamp, f.filename, extdata, xheader, "
	"MAX(serial) from file_entities_bd f %s where name = '%q' and serial >= %d "
	"and serial <= %d%s group by f.filename order by f.filename, serial",
	join_files_from_sql != NULL ? join_files_from_sql : "",
	bkname, bdatestamp, edatestamp, filespec != 0 ?  filespec : ""), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n\n\n",sqlerr);
	    sqlite3_free(sqlerr);
	}
#if 0
    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(
	"insert or ignore into restore_file_entities  "
	"(ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, datestamp, filename, extdata, xheader)  "
	"select ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, datestamp, filename, extdata, xheader  "
	"from file_entities f join backupset_detail d  "
	"on f.file_id = d.file_id where backupset_id = '%d'%s order by filename, datestamp",
	bkid, filespec != 0 ?  filespec : ""), 0, 0, 0);
#endif
    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(
	"create temporary view hardlink_file_entities  "
	"as select min(file_id) as file_id, ftype, permission, device_id,  "
	"inode, user_name, user_id, group_name, group_id, size, sha1, datestamp,  "
	"filename, extdata, xheader from restore_file_entities where ftype = 0 group by ftype,  "
	"permission, device_id, inode, user_name, user_id, group_name,  "
	"group_id, size, sha1, datestamp, extdata, xheader having count(*) > 1;"), 0, 0, 0);

    sqlite3_free(sqlstmt);
    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf(
	"select  "
	"case when b.file_id not null and a.file_id != b.file_id  "
	"then 1 else a.ftype end,  "
	"a.permission, a.device_id, a.inode, a.user_name, a.user_id,  "
	"a.group_name, a.group_id, a.size, a.sha1, a.datestamp, a.filename,  "
	"case when b.file_id not null and a.file_id != b.file_id  "
	"then b.filename else a.extdata end, a.xheader  "
	"from restore_file_entities a left join hardlink_file_entities b  "
	"on a.ftype = b.ftype and a.permission = b.permission  "
	"and a.device_id = b.device_id and a.inode = b.inode  "
	"and a.user_name = b.user_name and a.user_id = b.user_id  "
	"and a.group_name = b.group_name and a.group_id = b.group_id  "
	"and a.size = b.size and a.sha1 = b.sha1 and a.datestamp = b.datestamp  "
	"and a.extdata = b.extdata and a.xheader = b.xheader")), 2000, &sqlres, 0);

    while (sqlite3_step(sqlres) == SQLITE_ROW) {
	t.ftype = *sqlite3_column_text(sqlres, 0);
	t.mode = strtol((char *) sqlite3_column_text(sqlres, 1), 0, 8);
	strncpy(t.auid, (char *) sqlite3_column_text(sqlres, 4), 32); t.auid[32] = 0;
	t.nuid = sqlite3_column_int(sqlres, 5);
	strncpy(t.agid, (char *) sqlite3_column_text(sqlres, 6), 32); t.agid[32] = 0;
	t.ngid = sqlite3_column_int(sqlres, 7);
	t.filesize = sqlite3_column_int64(sqlres, 8);
	sha1 = sqlite3_column_text(sqlres, 9);
	t.modtime = sqlite3_column_int(sqlres, 10);
	sfilename = (char *) sqlite3_column_text(sqlres, 11);
	linktarget = 0;

	sprintf(sha1filepath, "%s/%c%c/%s.lzo", srcdir, sha1[0], sha1[1], sha1 + 2);
	filename = (char *) sfilename;

	if (t.ftype == '0' || t.ftype == 'S') {
	    sha1file = open(sha1filepath, O_RDONLY);
	    if (sha1file == -1) {
		perror("restore: open backing file:");
		fprintf(stderr, "Can not restore %s -- missing backing file %s\n", sfilename, sha1filepath);
		sfilename = 0;
		linktarget = 0;
		continue;
	    }
	    curfile = cfinit_r(fdopen(sha1file, "r"));
	    if (t.ftype == 'S') {
		if (cgetline(&ssparseinfo, &ssparseinfosz, curfile) <= 0) {
		    fprintf(stderr, "Failed top read sparse file %s\n", sparsefilepath);
		    return(1);
		}
	    }
	}
	for (i = 0; i < numgrafts; i++) {
	    if (strncmp(filename, graft[i][0], strlen(graft[i][0])) == 0) {
		snprintf(graftfilename, 8192, "%s%s", graft[i][1], filename + strlen(graft[i][0]));
		filename = graftfilename;
		break;
	    }
	}

	if (t.ftype == '1' || t.ftype == '2') {
	    linktarget = (char *) sqlite3_column_text(sqlres, 12);
	    t.filesize = 0;
	}
/*
	else if (t.ftype == 'S') {
	    asprintf(&sparsefilepath, "%s/%.2s/%s.s", destdir, sha1, sha1 + 2);
	    sparsefileh = fopen(sparsefilepath, "r");
	    if (getline(&ssparseinfo, &ssparseinfosz, sparsefileh) <= 0) {
		fprintf(stderr, "Failed top read sparse file %s\n", sparsefilepath);
		return(1);
	    }
	    free(sparsefilepath);
	}
*/
	xheader_d = sqlite3_column_blob(sqlres, 13);
	xheaderlen = sqlite3_column_bytes(sqlres, 13);
	if (xheaderlen > 0 && no_use_pax_header == 0) {
	    xheader = realloc(xheader, xheaderlen); // make a private copy of xheader
	    memcpy(xheader, xheader_d, xheaderlen);
	    use_pax_header = 1;
	}


	if (linktarget != 0) {
	    if (strlen(linktarget) > 100) {
		if (use_pax_header == 0) {
		    for (i = 0; i < sizeof(longtarhead); i++)
			(((unsigned char *) (&longtarhead)))[i] = 0;
		    strcpy(longtarhead.filename, "././@LongLink");
		    *(longtarhead.ftype) = 'K';
		    strcpy(longtarhead.nuid, "0000000");
		    strcpy(longtarhead.ngid, "0000000");
		    strcpy(longtarhead.mode, "0000000");
		    sprintf(longtarhead.size, "%11.11o", (unsigned int) strlen(linktarget));
		    strcpy(longtarhead.modtime, "00000000000");
		    strncpy(longtarhead.ustar, "ustar ", 6);
		    strcpy(longtarhead.auid, "root");
		    strcpy(longtarhead.agid, "root");
		    memcpy(longtarhead.chksum, "        ", 8);
		    for (tmpchksum = 0, p = (char *) (&longtarhead), i = 512;
			i != 0; --i, ++p)
			tmpchksum += 0xFF & *p;
		    sprintf(longtarhead.chksum, "%6o", tmpchksum);
		    fwrite(&longtarhead, 1, 512, stdout); // write out long symlink header
		    tblocks++;
		    for (i = 0; i < strlen(linktarget); i += 512) {
			for (j = 0; j < 512; j++)
			    curblock[j] = 0;
			memcpy(curblock, linktarget + i, strlen(linktarget) - i >= 512 ? 512 :
			    (strlen(linktarget) - i));
			fwrite(curblock, 1, 512, stdout); // write out long link 
			tblocks++;
		    }
		}
		else {
		    setpaxvar(&xheader, &xheaderlen, "linkpath", (char *) linktarget, strlen(linktarget));
		}
	    }
	}
	if (strlen(filename) > 100) {
	    if (use_pax_header == 0) {
		for (i = 0; i < sizeof(longtarhead); i++)
		    (((unsigned char *) (&longtarhead)))[i] = 0;
		strcpy(longtarhead.filename, "././@LongLink");
		*(longtarhead.ftype) = 'L';
		strcpy(longtarhead.nuid, "0000000");
		strcpy(longtarhead.ngid, "0000000");
		strcpy(longtarhead.mode, "0000000");
		sprintf(longtarhead.size, "%11.11o", (unsigned int) strlen(filename));
		strcpy(longtarhead.modtime, "00000000000");
		strncpy(longtarhead.ustar, "ustar ", 6);
		strcpy(longtarhead.auid, "root");
		strcpy(longtarhead.agid, "root");
		memcpy(longtarhead.chksum, "        ", 8);
		for (tmpchksum = 0, p = (char *) (&longtarhead), i = 512;
		    i != 0; --i, ++p)
		    tmpchksum += 0xFF & *p;
		sprintf(longtarhead.chksum, "%6.6o", tmpchksum);
		fwrite(&longtarhead, 1, 512, stdout);  // write out long file name header
		tblocks++;
		for (i = 0; i < strlen(filename); i += 512) {
		    for (j = 0; j < 512; j++)
			curblock[j] = 0;
		    memcpy(curblock, filename + i, strlen(filename) - i >= 512 ? 512 :
			(strlen(filename) - i));
		    fwrite(curblock, 1, 512, stdout); // write out long file name data
		    tblocks++;
		}
	    }
	    else {
		if (t.ftype != 'S')
		    setpaxvar(&xheader, &xheaderlen, "path", (char *) filename, strlen(filename));
	    }
	}
	if (t.ftype == 'S') {
	    nsi = 0;
	    p = ssparseinfo;
	    for (nsi = 0, p = ssparseinfo, i = 0; ssparseinfo[i] != '\0'; i++) {
		if (ssparseinfo[i] == ':') {
		    ssparseinfo[i] = '\0';
		    if (nsi >= msi - 1) {
			msi += 64;
			sparseinfo = realloc(sparseinfo, msi * sizeof(*sparseinfo));
		    }
		    sparseinfo[nsi++] = atoll(p);
		    p = ssparseinfo + i + 1;
		}
	    }
	    if (i > 0) {
		sparseinfo[nsi++] = atoll(p);
	    }

	    sparseinfo[0] ^= t.filesize;
	    t.filesize ^= sparseinfo[0];
	    sparseinfo[0] ^= t.filesize;
	    if (use_pax_header == 1) {
		sprintf(pax_size, "%lld", sparseinfo[0]);
		setpaxvar(&xheader, &xheaderlen, "GNU.sparse.major", "1", 1);
		setpaxvar(&xheader, &xheaderlen, "GNU.sparse.minor", "0", 1);
		setpaxvar(&xheader, &xheaderlen, "GNU.sparse.name", (char *) filename, strlen(filename));
		setpaxvar(&xheader, &xheaderlen, "GNU.sparse.realsize", pax_size, strlen(pax_size));

	    }
	}
	bytestoread = t.filesize;
	if (use_pax_header == 1 && t.filesize > 0xFFFFFFFFULL) {
	    sprintf(pax_size, "%lld", t.filesize);
	    setpaxvar(&xheader, &xheaderlen, "size", pax_size, strlen(pax_size));
	}

	if (xheader != 0 && xheaderlen > 0) {
	    for (i = 0; i < sizeof(xtarhead); i++)
		(((unsigned char *) (&xtarhead)))[i] = 0;
	    strcpy(xtarhead.filename, "././@xheader");
	    *(xtarhead.ftype) = 'x';
	    strcpy(xtarhead.nuid, "0000000");
	    strcpy(xtarhead.ngid, "0000000");
	    strcpy(xtarhead.mode, "0000000");
	    sprintf(xtarhead.size, "%11.11o", xheaderlen);
	    strcpy(xtarhead.modtime, "00000000000");
	    sprintf(xtarhead.ustar, "ustar");
	    strncpy(xtarhead.ustarver, "00", 2);
	    strcpy(xtarhead.auid, "root");
	    strcpy(xtarhead.agid, "root");
	    memcpy(xtarhead.chksum, "        ", 8);
	    for (tmpchksum = 0, p = (char *) (&xtarhead), i = 512;
		i != 0; --i, ++p)
		tmpchksum += 0xFF & *p;
	    sprintf(xtarhead.chksum, "%6o", tmpchksum);
	    fwrite(&xtarhead, 1, 512, stdout);  // write out pax header
	    tblocks++;
	    for (i = 0; i < xheaderlen; i += 512) {
		for (j = 0; j < 512; j++)
		    curblock[j] = 0;
		memcpy(curblock, xheader+ i, xheaderlen - i >= 512 ? 512 :
		    (xheaderlen - i));
		fwrite(curblock, 1, 512, stdout);  // write out pax data
		tblocks++;
	    }
	}

	strncpy(tarhead.filename, filename, 100);
	if (linktarget != 0)
	    strncpy(tarhead.linktarget, linktarget, 100);

	if (xheader == 0) {
	    strncpy(tarhead.ustar, "ustar ", 6);
	    sprintf(tarhead.ustarver, " ");
	}
	else {
	    sprintf(tarhead.ustar, "ustar");
	    strncpy(tarhead.ustarver, "00", 2);
	}
	*(tarhead.ftype) = t.ftype;
	sprintf(tarhead.mode, "%7.7o", t.mode);
	strncpy(tarhead.auid, t.auid, 32);
	sprintf(tarhead.nuid, "%7.7o", t.nuid);
	strncpy(tarhead.agid, t.agid, 32);
	sprintf(tarhead.ngid, "%7.7o", t.ngid);
	sprintf(tarhead.modtime, "%11.11o", t.modtime);


	if (t.ftype == 'S') {
	    if (use_pax_header == 0) {

		if (sparseinfo[0] <= 077777777777LL)
		    sprintf(tarhead.u.sph.realsize, "%11.11o", (unsigned int) sparseinfo[0]);
		else {
		    tarhead.u.sph.realsize[0] = 0x80;
		    for (i = 0; i < sizeof(sparseinfo[0]); i++)
			if (lendian)
			    tarhead.u.sph.realsize[11 - i] = ((char *) (&(sparseinfo[0])))[i];
			else
			    tarhead.u.sph.realsize[11 - sizeof(sparseinfo[0]) + i] = ((char *) (&(sparseinfo[0])))[i];
		}
		for (i = 1; i < nsi && i < 9; i++) {
		    if (sparseinfo[i] <= 077777777777LL) {
			sprintf(tarhead.u.sph.item[i - 1], "%11.11o", (unsigned int) sparseinfo[i]);
		    }
		    else {
			tarhead.u.sph.item[i][0] = 0x80;
			for (j = 0; j < sizeof(sparseinfo[i]); j++)
			    if (lendian)
				tarhead.u.sph.item[i - 1][11 - j] = ((char *) (&(sparseinfo[i])))[j];
			    else
				tarhead.u.sph.item[i - 1][11 - sizeof(sparseinfo[i]) + j] = ((char *) (&(sparseinfo[0])))[j];
		    }
		}
		if (nsi > 9) {
		    tarhead.u.sph.isextended = 1;
		}
		else {
		    tarhead.u.sph.isextended = 0;
		}
		strncpy(tarhead.ustar, "ustar ", 6);
		strncpy(tarhead.ustarver, " ", 2);
	    }
	    else {
		*(tarhead.ftype) = '0';
		strncpy(tarhead.ustarver, "00", 2);
		paxsparsehdrsz = 0;
		paxsparsehdrsz += ilog10(nsi) + 2;
		for (i = 1; i < nsi; i++) {
		    paxsparsehdrsz += ilog10(sparseinfo[i]) + 2;
		}
		t.filesize += 512 * ((int) paxsparsehdrsz / 512 + (paxsparsehdrsz % 512 == 0 ? 0 : 1));
	    }
	}

	if (use_pax_header == 1 && t.filesize > 0xFFFFFFFFULL)
	    sprintf(tarhead.size, "%11.11llo", 0LL);
	else {
	    if (t.filesize <= 077777777777LL) {
		sprintf(tarhead.size, "%11.11llo", t.filesize);
	    }
	    else {
		tarhead.size[0] = 0x80;
		for (i = 0; i < sizeof(t.filesize); i++) {
		    if (lendian)
			tarhead.size[11 - i] = ((char *) (&t.filesize))[i];
		    else
			tarhead.size[11 - sizeof(t.filesize)+ i] = ((char *) (&t.filesize))[i];
		}
	    }
	}

	memcpy(tarhead.chksum, "        ", 8);
	for (tmpchksum = 0, p = (char *) (&tarhead), i = 512;
	    i != 0; --i, ++p)
	    tmpchksum += 0xFF & *p;
	sprintf(tarhead.chksum, "%6.6o", tmpchksum);

	fwrite(&tarhead, 1, 512, stdout);
	tblocks++;
	if (tarhead.u.sph.isextended == 1) {
	    for (i = 0; i < sizeof(speh); i++)
		((unsigned char *) &speh)[i] = 0;
	    for (i = 9; i < nsi; i++) {
		if (sparseinfo[i] <= 077777777777LL)
		    sprintf(speh.item[(i - 9) % 42], "%11.11o", (unsigned int) sparseinfo[i]);
		else {
		    speh.item[(i - 9) % 42][0] = 0x80;
		    for (j = 0; i < sizeof(sparseinfo[i]); j++)
			if (lendian)
			    speh.item[(i - 9) % 42][11 - j] = ((char *) (&(sparseinfo[i])))[j];
			else
			    speh.item[(i - 9) % 42][11 - sizeof(sparseinfo[i]) + j] = ((char *) (&(sparseinfo[0])))[j];
		}
		if ((i - 9) % 42 == 41) {
		    if (i < nsi - 1) {
			speh.isextended = 1;
		    }
		    else {
			speh.isextended = 0;
		    }
		    fwrite(&speh, 1, 512, stdout);
		    tblocks++;
		    for (j = 0; j < sizeof(speh); j++)
			((unsigned char *) &speh)[j] = 0;
		}
	    }
	    if ((i - 9) % 42 != 0) {
		fwrite(&speh, 1, 512, stdout);
		tblocks++;
	    }
	}
	if (t.ftype == '0' || t.ftype == 'S') {
	    if (use_pax_header == 1 && t.ftype == 'S') {
		paxsparsehdrsz = 0;
		paxsparsehdrsz += (fprintf(stdout, "%u\n", (unsigned int) ((nsi - 1) / 2)));
		for (i = 1; i < nsi; i++) {
		    paxsparsehdrsz += (fprintf(stdout, "%llu\n", sparseinfo[i]));
		}
		memset(curblock, '\0', 512);
		paxsparsehdrsz += fwrite(curblock, 1, 512 - paxsparsehdrsz % 512, stdout);

	    }
	    tblocks += (int) ((t.filesize - bytestoread) / 512);
	    blocksize = 512 - ((t.filesize - bytestoread) % 512);
	    if (blocksize == 0)
		blocksize = 512;
	    while (bytestoread > 512ull) {
		count = cread(curblock, 1, blocksize, curfile);
		if (count < blocksize) {
		    fprintf(stderr, "file short read %s %s %llu %llu %d\n", sfilename, sha1filepath, t.filesize, bytestoread, count);
		    exit(1);
		}
		fwrite(curblock, 1, blocksize, stdout);
		tblocks++;
		bytestoread -= blocksize;
		blocksize = 512;
	    }
	    if (bytestoread > 0) {
		for (i = 0; i < 512; i++)
		    curblock[i] = 0;
		count = cread(curblock, 1, 512, curfile);
		fwrite(curblock, 1, 512, stdout);
		tblocks++;
	    }
	    cclose_r(curfile);
	    for (i = 0; i < sizeof(tarhead); i++)
		((unsigned char *) &tarhead)[i] = 0;
	}
	filename = 0;
	linktarget = 0;
    }
    for (i = 0; i < 512; i++)
	curblock[i] = 0;
    for (i = 0; i < 20 - (tblocks % 20) ; i++)
	fwrite(curblock, 1, 512, stdout);
    return(0);
}
void getconfig(char *configpatharg)
{
    char *configline = 0;
    size_t configlinesz = 0;
    struct stat tmpfstat;
    char configpath[256];
    FILE *configfile;
    char *configvar;
    char *configvalue;
    char **configlinel = NULL;
    int i;
    int j;

    config.vault = 0;
    config.meta = 0;
    if (configpatharg == NULL)
	snprintf(configpath, 256, "%s/.snebu.conf", getenv("HOME"));
    else {
	strncpy(configpath, configpatharg, 255);
	configpath[255] = 0;
    }
    if (stat(configpath, &tmpfstat) != 0)
	snprintf(configpath, 256, "/etc/snebu.conf");
    if (stat(configpath, &tmpfstat) != 0)
	snprintf(configpath, 256, "/etc/snebu/snebu.conf");
    if (stat(configpath, &tmpfstat) == 0) {
	configfile = fopen(configpath, "r");
	while (getline(&configline, &configlinesz, configfile) > 0) {
	    if ((j = parsex(configline, '=', &configlinel, 2) == 2)) {
		configvar = configlinel[0];
		configvalue = configlinel[1];
		while (strchr(" \t\r\n", *configvar)  && *configvar != '\0')
		    configvar++;
		while (strchr(" \t\r\n", *configvalue) && *configvalue != '\0')
		    configvalue++;
		for (i = strlen(configvar) - 1; i >= 0 && strchr(" \t\r\n", configvar[i]); i--)
		    configvar[i] = '\0';
		for (i = strlen(configvalue) - 1; i >= 0 && strchr(" \t\r\n", configvalue[i]); i--)
		    configvalue[i] = '\0';
		if (strcmp(configvar, "vault") == 0)
		    if (asprintf(&(config.vault), "%s", configvalue) < 0) {
			fprintf(stderr, "Memory allocation failure\n");
			exit(1);
		    }
		if (strcmp(configvar, "meta") == 0)
		    if (asprintf(&(config.meta), "%s", configvalue) < 0) {
			fprintf(stderr, "Memory allocation failure\n");
			exit(1);
		    }
	    }
	}
    }
    else
	fprintf(stderr, "Can't find %s, using defaults\n", configpath);
    if (config.vault == 0)
	config.vault = "/var/backup/vault";
    if (config.meta == 0)
	config.meta= "/var/backup/meta";
}

int sqlbusy(void *x, int y)
{
//    fprintf(stderr, "Busy %d\n", y);
    usleep(100000);
    return(1);
}

int listbackups(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    char *filespec = 0;
    int filespeclen;
    int foundopts = 0;
    sqlite3 *bkcatalog;
    sqlite3_stmt *sqlres;
    char *bkcatalogp;
    char *sqlstmt = 0;
    int i;
    time_t bktime;
    char *bktimes;
    int rowcount;
    char *dbbkname;
    char oldbkname[128];
    time_t oldbktime;
    time_t bdatestamp;
    time_t edatestamp;
    char *range;
    int err;
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "long", no_argument, NULL, 'l' },
	{ "long0", no_argument, NULL, '0' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
/* Future functionality */
//    int longoutput = 0;
//    int long0output = 0;


    while ((optc = getopt_long(argc, argv, "n:d:l0", longopts, &longoptidx)) >= 0) {
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
/*
	    case 'l':
		longoutput = 1;
		foundopts |= 4;
		break;
	    case '0':
		long0output = 1;
		foundopts |= 8;
		break;
*/
	    default:
		usage();
		return(1);
	}
    }
    if (foundopts != 0 && foundopts != 1 && foundopts != 3 /* && foundopts != 7 && foundopts != 15 */) {
	printf("foundopts = %d\n", foundopts);
        usage();
        return(1);
    }

    if (argc > optind) {
	filespeclen = 4;
	for (i = optind; i < argc; i++)
    	    filespeclen += strlen(argv[i]) + 20;
       	filespec = malloc(filespeclen);
	filespec[0] = 0;
	for (i = optind; i < argc; i++) {
	    if (i == optind)
		strcat(filespec, " and (filename glob ");
	    else
		strcat(filespec, " or filename glob ");
	    strcat(filespec, sqlite3_mprintf("'%q'", argv[i]));
	}
	strcat(filespec, ")");
    }
    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation failure\n");
	exit(1);
    }
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);

    if (foundopts == 0) {

	if (filespec == 0) {
	    err = sqlite3_prepare_v2(bkcatalog,
		(sqlstmt = sqlite3_mprintf(
		"select distinct name from backupsets order by name")), -1, &sqlres, 0);
	    rowcount = 0;
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		rowcount++;
		printf("%s\n", sqlite3_column_text(sqlres, 0));
	    }
	    if (rowcount == 0) {
	        printf("No backups found %s %d\n", sqlstmt, err);
		exit(1);
	    }
	    sqlite3_finalize(sqlres);
	    sqlite3_free(sqlstmt);
	}
	else {

	    sqlite3_prepare_v2(bkcatalog,
		(sqlstmt = sqlite3_mprintf(
		"select distinct b.name, b.serial, f.filename from backupsets b  "
		"join backupset_detail d on b.backupset_id = d.backupset_id  "
		"join file_entities f on d.file_id = f.file_id where 1"
		"%s", filespec)), -1, &sqlres, 0);
	    rowcount = 0;
	    oldbkname[0] = 0;
	    oldbktime = 0;
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		rowcount++;
		dbbkname = (char *) sqlite3_column_text(sqlres, 0);
		bktime = sqlite3_column_int(sqlres, 1);
		bktimes = ctime(&bktime);
		bktimes[strlen(bktimes) - 1] = 0;
		if (strcmp(dbbkname, oldbkname) != 0)
		    printf("%s:\n", dbbkname);
		if (bktime != oldbktime)
		    printf("    %-10lu %s:\n", bktime, bktimes);
		printf("        %s\n", sqlite3_column_text(sqlres, 2));
		strncpy(oldbkname, dbbkname, 127);
		oldbkname[127] = 0;
		oldbktime = bktime;
	    }
	    if (rowcount == 0) {
		printf("No backups found for %s\n", sqlstmt);
		exit(1);
	    }
	    sqlite3_finalize(sqlres);
	    sqlite3_free(sqlstmt);
	}

    }
    else if (foundopts == 1) {
	sqlite3_prepare_v2(bkcatalog,
    	    (sqlstmt = sqlite3_mprintf(
	    "select distinct retention, serial from backupsets "
	    "where name = '%q' order by serial, name", bkname)),
	    -1, &sqlres, 0);
	rowcount = 0;
	printf("%s\n", bkname);
	while (sqlite3_step(sqlres) == SQLITE_ROW) {
	    rowcount++;
	    bktime = sqlite3_column_int(sqlres, 1),
	    bktimes = ctime(&bktime);
	    bktimes[strlen(bktimes) - 1] = 0;
	    printf("    %lu / %s / %s\n",
		bktime, sqlite3_column_text(sqlres, 0), bktimes);

	}
	if (rowcount == 0) {
	    printf("No backups found\n");
	    exit(1);
	}
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
    }
    else if (foundopts == 3) {
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
	sqlite3_prepare_v2(bkcatalog,
	    (sqlstmt = sqlite3_mprintf("select distinct serial, filename "
		"from file_entities_bd where name = '%q' and serial >= %d "
		"and serial <= %d%s", bkname, bdatestamp, edatestamp, filespec != 0 ? filespec : "")),
		-1, &sqlres, 0);

	if (bdatestamp == edatestamp)
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		printf("%s\n", sqlite3_column_text(sqlres, 1));
	    }
	else
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		printf("%10d %s\n", sqlite3_column_int(sqlres, 0),
		sqlite3_column_text(sqlres, 1));
	    }
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
    }
    else if (foundopts == 7) {
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
	sqlite3_prepare_v2(bkcatalog,
	    (sqlstmt = sqlite3_mprintf("select distinct serial, ftype, \n"
		"permission, device_id, inode, user_name, user_id, \n"
		"group_name, group_id, size, sha1, cdatestamp, datestamp, \n"
		"filename, extdata \n"
		"from file_entities_bd where name = '%q' and serial >= %d "
		"and serial <= %d%s", bkname, bdatestamp, edatestamp, filespec != 0 ? filespec : "")),
		-1, &sqlres, 0);

	if (bdatestamp == edatestamp)
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		printf("%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%Ld\t%s\t%d\t%d\t%s\t%s\n",

		strcmp((char *)sqlite3_column_text(sqlres, 1), "0") == 0 ? "f" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "2") == 0 ? "l" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "5") == 0 ? "d" :
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "S") == 0 ? "f" : "u",
		sqlite3_column_text(sqlres, 2),
		sqlite3_column_text(sqlres, 3),
		sqlite3_column_text(sqlres, 4),
		sqlite3_column_text(sqlres, 5),
		sqlite3_column_int(sqlres, 6),
		sqlite3_column_text(sqlres, 7),
		sqlite3_column_int(sqlres, 8),
		sqlite3_column_int64(sqlres, 9),
		sqlite3_column_text(sqlres, 10),
		sqlite3_column_int(sqlres, 11),
		sqlite3_column_int(sqlres, 12),
		sqlite3_column_text(sqlres, 13),
		sqlite3_column_text(sqlres, 14));
	    }
	else
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		printf("%10d %s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%Ld\t%s\t%d\t%d\t%s\t%s\n",
		sqlite3_column_int(sqlres, 0),
		strcmp((char *)sqlite3_column_text(sqlres, 1), "0") == 0 ? "f" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "2") == 0 ? "l" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "5") == 0 ? "d" :
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "S") == 0 ? "f" : "u",
		sqlite3_column_text(sqlres, 2),
		sqlite3_column_text(sqlres, 3),
		sqlite3_column_text(sqlres, 4),
		sqlite3_column_text(sqlres, 5),
		sqlite3_column_int(sqlres, 6),
		sqlite3_column_text(sqlres, 7),
		sqlite3_column_int(sqlres, 8),
		sqlite3_column_int64(sqlres, 9),
		sqlite3_column_text(sqlres, 10),
		sqlite3_column_int(sqlres, 11),
		sqlite3_column_int(sqlres, 12),
		sqlite3_column_text(sqlres, 13),
		sqlite3_column_text(sqlres, 14));
	    }
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
    }
    else if (foundopts == 15) {
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
	sqlite3_prepare_v2(bkcatalog,
	    (sqlstmt = sqlite3_mprintf("select distinct serial, ftype, \n"
		"permission, device_id, inode, user_name, user_id, \n"
		"group_name, group_id, size, sha1, cdatestamp, datestamp, \n"
		"filename, extdata \n"
		"from file_entities_bd where name = '%q' and serial >= %d "
		"and serial <= %d%s", bkname, bdatestamp, edatestamp, filespec != 0 ? filespec : "")),
		-1, &sqlres, 0);

	if (bdatestamp == edatestamp) {
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		printf("%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%Ld\t%s\t%d\t%d\t%s%c",

		strcmp((char *)sqlite3_column_text(sqlres, 1), "0") == 0 ? "f" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "2") == 0 ? "l" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "5") == 0 ? "d" :
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "S") == 0 ? "f" : "u",
		sqlite3_column_text(sqlres, 2),
		sqlite3_column_text(sqlres, 3),
		sqlite3_column_text(sqlres, 4),
		sqlite3_column_text(sqlres, 5),
		sqlite3_column_int(sqlres, 6),
		sqlite3_column_text(sqlres, 7),
		sqlite3_column_int(sqlres, 8),
		sqlite3_column_int64(sqlres, 9),
		sqlite3_column_text(sqlres, 10),
		sqlite3_column_int(sqlres, 11),
		sqlite3_column_int(sqlres, 12),
		sqlite3_column_text(sqlres, 13),
		'\0');
		if (strcmp((char *)sqlite3_column_text(sqlres, 1), "2") == 0)
		    printf("%s%c", sqlite3_column_text(sqlres, 14), '\0');
	    }
	}
	else {
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		printf("%10d %s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%Ld\t%s\t%d\t%d\t%s%c",
		sqlite3_column_int(sqlres, 0),
		strcmp((char *)sqlite3_column_text(sqlres, 1), "0") == 0 ? "f" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "2") == 0 ? "l" : 
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "5") == 0 ? "d" :
		    strcmp((char *)sqlite3_column_text(sqlres, 1), "S") == 0 ? "f" : "u",
		sqlite3_column_text(sqlres, 2),
		sqlite3_column_text(sqlres, 3),
		sqlite3_column_text(sqlres, 4),
		sqlite3_column_text(sqlres, 5),
		sqlite3_column_int(sqlres, 6),
		sqlite3_column_text(sqlres, 7),
		sqlite3_column_int(sqlres, 8),
		sqlite3_column_int64(sqlres, 9),
		sqlite3_column_text(sqlres, 10),
		sqlite3_column_int(sqlres, 11),
		sqlite3_column_int(sqlres, 12),
		sqlite3_column_text(sqlres, 13),
		'\0');
		if (strcmp((char *)sqlite3_column_text(sqlres, 1), "2") == 0)
		    printf("%s%c", sqlite3_column_text(sqlres, 14), '\0');
	    }
	}
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
    }
    
    return(0);
}

char *stresc(char *src, char **target)
{
    int i;
    int j;
    int e = 0;
    int len;
    static int tlen = 16384;

    if (*target == 0)
	*target = malloc(tlen);
    len = strlen(src);
    for (i = 0; i < len; i++)
	if (src[i] <= 32 || src[i] >= 127 || src[i] == 92)
	    e++;
//    *target = realloc(*target, len  + e * 4 + 1);
    (*target)[0] = 0;
    i = 0;
    while (i < len) {
	for (j = i; i < len && src[i] > 32 &&
	    src[i] < 127 && src[i] != 92; i++)
	    ;
	strncat(*target, src + j, i - j);
	if (i < len) {
	    sprintf((*target) + strlen(*target), "\\%3.3o",
		(unsigned char) src[i]);
	    i++;
	}
    }
    return(*target);
}
char *strunesc(char *src, char **target)
{
    int i;
    int j;

    *target = realloc(*target, strlen(src) + 1);
    (*target)[0] = 0;
    memset(*target, 0, (size_t) strlen(src) + 1);
    i = 0;
    while (i < strlen(src)) {
	for (j = i; i < strlen(src) && src[i] != 92; i++)
	    ;
	strncat(*target, src + j, i - j);
	if (i < strlen(src)) {
	    (*target)[strlen(*target)] = (char) strtoln(src + ++i, NULL, 8, 3);
	    i += 3;
	}
    }
    return(realloc(*target, strlen(*target) + 1));
}

long int strtoln(char *nptr, char **endptr, int base, int len)
{
    char scratch[20];
    strncpy(scratch, nptr, len);
    scratch[len] = (char) 0;
    return(strtol((scratch), endptr, base));
}

int import(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    char retention[128];
    char *filespec = 0;
    int filespeclen;
    int foundopts = 0;
    sqlite3 *bkcatalog;
    sqlite3_stmt *sqlres;
    char *bkcatalogp;
    char *sqlstmt = 0;
    char *sqlerr;
    int bkid;
    int i;
    char catalogpath[512];
    FILE *catalog;
    char *instr = 0;
    size_t instrlen = 0;
    char *destdir = config.vault;
    char *sparsefilepath = 0;
    FILE *sparsefileh;
    char *filename = 0;
    char *efilename = 0;
    char *linktarget = 0;
    char *elinktarget = 0;
    char sha1[SHA_DIGEST_LENGTH * 2 + 1];
    struct {
        char ftype[2];
        int mode;
	char devid[33];
	char inode[33];
        char auid[33];
        char agid[33];
        int nuid;
        int ngid;
        int cmodtime;
        int modtime;
        unsigned long long int filesize;
    } t;
    int count;
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "retention", required_argument, NULL, 'r' },
	{ "file", required_argument, NULL, 'f' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;

    while ((optc = getopt_long(argc, argv, "n:d:r:f:", longopts, &longoptidx)) >= 0) {
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
	    case 'f':
		strncpy(catalogpath, optarg, 127);
		catalogpath[127] = 0;
		foundopts |= 8;
		break;
	    default:
		usage();
		return(1);
	}
    }
    if (foundopts != 15) {
        usage();
        return(1);
    }

    if (argc > optind) {
	filespeclen = 4;
	for (i = optind; i < argc; i++)
    	    filespeclen += strlen(argv[i]) + 20;
       	filespec = malloc(filespeclen);
	filespec[0] = 0;
	for (i = optind; i < argc; i++) {
	    if (i == optind)
		strcat(filespec, " and (filename glob ");
	    else
		strcat(filespec, " or filename glob ");
	    strcat(filespec, sqlite3_mprintf("'%q'", argv[i]));
	}
	strcat(filespec, ")");
    }
    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation failure\n");
	exit(1);
    }
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
//    sqlite3_exec(bkcatalog, "PRAGMA temp_store = 2", 0, 0, 0);
// TODO These two should be set via command line options
//    sqlite3_exec(bkcatalog, "PRAGMA synchronous = OFF", 0, 0, 0);
//    sqlite3_exec(bkcatalog, "PRAGMA journal_mode = MEMORY", 0, 0, 0);
//    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);
    initdb(bkcatalog);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupsets (name, retention, serial)  "
	"values ('%s', '%s', '%s')", bkname, retention, datestamp)), 0, 0, 0);
    sqlite3_free(sqlstmt);
    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select backupset_id from backupsets  "
	    "where name = '%s' and retention = '%s' and serial = '%s'",
	    bkname, retention, datestamp)), -1, &sqlres, 0);
    if ((sqlite3_step(sqlres)) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

    if (strcmp(catalogpath, "-") == 0)
	catalog = stdin;
    else
	catalog = fopen(catalogpath, "r");
    if (catalog == 0) {
	fprintf(stderr, "Error %s opening catalog file %s\n", strerror(errno), catalogpath);
	exit(1);
    }
    sqlite3_exec(bkcatalog,
	"create temporary table if not exists inbound_file_entities (  \n"
       	    "backupset_id     integer,  \n"
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
	    "cdatestamp     integer,  \n"
	    "datestamp     integer,  \n"
	    "filename      char,  \n"
	    "extdata       char default '',  \n"
	"constraint inbound_file_entitiesc1 unique (  \n"
	    "backupset_id,  \n"
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
	    "cdatestamp,  \n"
	    "datestamp,  \n"
	    "filename,  \n"
	    "extdata ))", 0, 0, 0);
    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    sqlstmt = sqlite3_mprintf(
	"insert or ignore into inbound_file_entities "
	"(backupset_id, ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, cdatestamp, datestamp, filename, extdata)  "
	"values (@bkid, @ftype, @mode, @devid, @inode, @auid, @nuid, @agid,  "
	"@ngid, @filesize, @sha1, @cmodtime, @modtime, @filename, @linktarget)");

    sqlite3_prepare_v2(bkcatalog, sqlstmt, -1, &sqlres, 0);

    t.ftype[1] = 0;
    count = 0;
    linktarget=malloc(1);
    *linktarget = '\0';
    while (getline(&instr, &instrlen, catalog) > 0) {
	count++;
	char *fptr;
	char *endfptr;
	char *lptr;
	char *endlptr;
	int fnstart;
	char *ascmode;
	sscanf(instr, "%c\t%o\t%32s\t%32s\t%32s\t%d\t%32s\t%d\t%Ld\t%40s\t%d\n%d\t%n",
	    t.ftype, &t.mode, t.devid, t.inode, t.auid, &t.nuid, t.agid, &t.ngid,
	    &(t.filesize), sha1, &t.cmodtime, &t.modtime, &fnstart);
	fptr = instr + fnstart;
	endfptr = strstr(fptr, "\t");
	if (endfptr == 0) {
	    endfptr = strlen(fptr) + fptr;
	}
	efilename = realloc(efilename, endfptr - fptr + 1);
	strncpy(efilename, fptr, endfptr - fptr);
	efilename[endfptr - fptr] = 0;
	    strunesc(efilename, &filename);

	if (*(t.ftype) == '2' || *(t.ftype) == '1') {
	    lptr = endfptr + 1;
	    endlptr = strstr(lptr, "\n");
	    elinktarget = realloc(elinktarget, endlptr - lptr + 1);
	    strncpy(elinktarget, lptr, endlptr - lptr);
	    elinktarget[endlptr - lptr] = 0;
	    strunesc(elinktarget, &linktarget);
	}
	if (*(t.ftype) == 'S') {
	    lptr = endfptr + 1;
	    endlptr = strstr(lptr, "\n");
	    elinktarget = realloc(elinktarget, endlptr - lptr + 1);
	    strncpy(elinktarget, lptr, endlptr - lptr);
	    elinktarget[endlptr - lptr] = 0;

	    if (asprintf(&sparsefilepath, "%s/%.2s/%s.s", destdir, sha1, sha1 + 2) < 0) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	    }
	    sparsefileh = fopen(sparsefilepath, "w");
	    fprintf(sparsefileh, "%s", elinktarget);
	    fclose(sparsefileh);
	}

	if (*(t.ftype) != '1' && *(t.ftype) != '2' && linktarget != 0)
	    *linktarget = 0;
	if (filename != 0 && strlen(filename) > 1 && filename[(strlen(filename) - 1)] == '/')
	    filename[strlen(filename) - 1] = 0;

	ascmode = sqlite3_mprintf("%4.4o", t.mode);
	sqlite3_bind_int(sqlres, 1, bkid);
	sqlite3_bind_text(sqlres, 2, t.ftype, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 3, ascmode, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 4, t.devid, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 5, t.inode, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 6, t.auid, -1, SQLITE_STATIC);
	sqlite3_bind_int(sqlres, 7, t.nuid);
	sqlite3_bind_text(sqlres, 8, t.agid, -1, SQLITE_STATIC);
	sqlite3_bind_int(sqlres, 9, t.ngid);
	sqlite3_bind_int64(sqlres, 10, t.filesize);
	sqlite3_bind_text(sqlres, 11, sha1, -1, SQLITE_STATIC);
	sqlite3_bind_int(sqlres, 12, t.cmodtime);
	sqlite3_bind_int(sqlres, 13, t.modtime);
	sqlite3_bind_text(sqlres, 14, filename, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 15, linktarget, -1, SQLITE_STATIC);
	sqlite3_step(sqlres);
//	sqlite3_clear_bindings(sqlres);
	sqlite3_reset(sqlres);
    }
    fprintf(stderr, "Inserted %d records\n", count);
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities  "
	"(ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, cdatestamp, datestamp, filename, extdata)  "
	"select ftype, permission, device_id, inode, user_name, user_id,  "
	"group_name, group_id, size, sha1, cdatestamp, datestamp, filename, extdata  "
	"from inbound_file_entities")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    fprintf(stderr, "Copied records to file_entities\n");

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupset_detail  "
	"(backupset_id, file_id)  "
	"select i.backupset_id, f.file_id from file_entities f  "
	"join inbound_file_entities i  "
	"on i.ftype = f.ftype and i.permission = f.permission  "
	"and i.device_id = f.device_id and i.inode = f.inode  "
	"and i.user_name = f.user_name and i.user_id = f.user_id  "
	"and i.group_name = f.group_name and i.group_id = f.group_id  "
	"and i.size = f.size and i.cdatestamp = f.cdatestamp and i.datestamp = f.datestamp  "
	"and i.filename = f.filename and i.extdata = f.extdata  "
	"where i.backupset_id = '%d'", bkid)), 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    fprintf(stderr, "Created backupset_detail entries\n");

    sqlite3_exec(bkcatalog, "END", 0, 0, 0);

    return(0);
}

int export(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    char retention[128];
    char *filespec = 0;
    int filespeclen;
    int foundopts = 0;
    sqlite3 *bkcatalog;
    sqlite3_stmt *sqlres;
    char *bkcatalogp;
    char *sqlstmt = 0;
    int bkid;
    int i;
    char catalogpath[512];
    FILE *catalog;
    char *efilename = 0;
    char *eextdata= 0;
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "retention", required_argument, NULL, 'r' },
	{ "file", required_argument, NULL, 'f' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;

    while ((optc = getopt_long(argc, argv, "n:d:r:f:", longopts, &longoptidx)) >= 0) {
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
	    case 'f':
		strncpy(catalogpath, optarg, 127);
		catalogpath[127] = 0;
		foundopts |= 8;
		break;
	    default:
		usage();
		return(1);
	}
    }
    if (foundopts != 15) {
        usage();
        return(1);
    }

    if (argc > optind) {
	filespeclen = 4;
	for (i = optind; i < argc; i++)
	    filespeclen += strlen(argv[i]) + 20;
	filespec = malloc(filespeclen);
	filespec[0] = 0;
	for (i = optind; i < argc; i++) {
	    if (i == optind)
		strcat(filespec, " and (filename glob ");
	    else
		strcat(filespec, " or filename glob ");
	    strcat(filespec, sqlite3_mprintf("'%q'", argv[i]));
	}
	strcat(filespec, ")");
    }
    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation falure\n");
	exit(1);
    }
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
//    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);
//    initdb(bkcatalog);

    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select distinct backupset_id  "
	    "from backupsets  where name = '%q' and serial = '%q'",
	    bkname, datestamp)), -1, &sqlres, 0);
    if ((sqlite3_step(sqlres)) == SQLITE_ROW) {
	bkid = sqlite3_column_int(sqlres, 0);
    }
    else {
	printf("Backup not found for %s\n", sqlstmt);
	exit(1);
    }
    sqlite3_free(sqlstmt);

    if (strcmp(catalogpath, "-") == 0)
	catalog = stdout;
    else
	catalog = fopen(catalogpath, "w");
    if (catalog == 0) {
	fprintf(stderr, "Error %s opening catalog file %s\n", strerror(errno), catalogpath);
	exit(1);
    }

    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf(
	"select ftype, permission, device_id, inode, user_name, user_id, "
	"  group_name, group_id, size, sha1, cdatestamp, datestamp, filename, extdata "
	"  from file_entities f "
	"  join backupset_detail d on "
	"  f.file_id = d.file_id "
	"  where d.backupset_id = '%d' ", bkid)), -1, &sqlres, 0);
    while (sqlite3_step(sqlres) == SQLITE_ROW) {
	fprintf(catalog, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%Ld\t%s\t%d\t%d\t%s\t%s\n",
	sqlite3_column_text(sqlres, 0),
	sqlite3_column_text(sqlres, 1),
	sqlite3_column_text(sqlres, 2),
	sqlite3_column_text(sqlres, 3),
	sqlite3_column_text(sqlres, 4),
	sqlite3_column_int(sqlres, 5),
	sqlite3_column_text(sqlres, 6),
	sqlite3_column_int(sqlres, 7),
	sqlite3_column_int64(sqlres, 8),
	sqlite3_column_text(sqlres, 9),
	sqlite3_column_int(sqlres, 10),
	sqlite3_column_int(sqlres, 11),
	stresc((char *) sqlite3_column_text(sqlres, 12), &efilename),
	stresc((char *) sqlite3_column_text(sqlres, 13), &eextdata));
    }
    sqlite3_free(sqlstmt);
    fclose(catalog);
    return(0);
}

int expire(int argc, char **argv)
{
    int optc;
    char retention[128];
    char bkname[128];
    char datestamp[128];
    int age;
    int bkid;
    int min = 3;
    int foundopts = 0;
    sqlite3 *bkcatalog;
    sqlite3_stmt *sqlres;
    char *bkcatalogp;
    char *sqlstmt = 0;
    char *sqlstmt_tmp = 0;
    char *sqlerr;
    time_t cutoffdate;
    bkname[0] = 0;
    struct option longopts[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "datestamp", required_argument, NULL, 'd' },
	{ "age", required_argument, NULL, 'a' },
	{ "min-keep", required_argument, NULL, 'm' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;

    *datestamp = 0;
    while ((optc = getopt_long(argc, argv, "r:n:a:k:m:d:", longopts, &longoptidx)) >= 0) {
	switch (optc) {
	    case 'r':
		strncpy(retention, optarg, 127);
		retention[127] = 0;
		foundopts |= 1;
		break;
	    case 'n':
		strncpy(bkname, optarg, 127);
		bkname[127] = 0;
		foundopts |= 2;
		break;
	    case 'a':
		age = atoi(optarg);
		foundopts |= 4;
		break;
	    case 'm':
		min = atoi(optarg);
		foundopts |= 8;
		break;
	    case 'd':
		strncpy(datestamp, optarg, 127);
		datestamp[127] = 0;
		foundopts |= 16;
		break;
	    default:
		usage();
		return(1);
	}
    }
    if ((foundopts & 5) != 5 && (foundopts & 7) != 7 && (foundopts & 18) != 18) {
        fprintf(stderr, "foundopts = %d\n", foundopts);
        usage();
        return(1);
    }
    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation error\n");
	exit(1);
    }
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
//    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);

    cutoffdate = time(0) - (age * 60 * 60 * 24);

    if (*datestamp != 0) {
	sqlite3_prepare_v2(bkcatalog,
	    (sqlstmt = sqlite3_mprintf("select backupset_id from backupsets  "
		"where name = '%s' and serial = '%s'",
		bkname, datestamp)), -1, &sqlres, 0);
	if ((sqlite3_step(sqlres)) == SQLITE_ROW) {
	    bkid = sqlite3_column_int(sqlres, 0);
	}
        else {
	    fprintf(stderr, "Can't find specified backupset\n");
	    exit(1);
	}
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
	sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
	fprintf(stderr, "Deleting %d from received_file_entities\n", bkid);
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from received_file_entities where backupset_id = %d ",
	    bkid)), 0, 0, &sqlerr);
	fprintf(stderr, "Deleting %d from needed_file_entities\n", bkid);
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from needed_file_entities where backupset_id = %d ",
	    bkid)), 0, 0, &sqlerr);
	fprintf(stderr, "Deleting %d from backupset_detail\n", bkid);
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from backupset_detail where backupset_id = %d ",
	    bkid)), 0, 0, &sqlerr);
	fprintf(stderr, "Deleting %d from backupsets\n", bkid);
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from backupsets where backupset_id = %d ",
	    bkid)), 0, 0, &sqlerr);
	sqlite3_exec(bkcatalog, "END", 0, 0, 0);
	exit(0);
    }

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create temporary table if not exists expirelist ( "
	"backupset_id integer primary key )"
	)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    if (strlen(bkname) > 0)
	sqlstmt_tmp = sqlite3_mprintf(" and e.name = %Q", bkname);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into expirelist   "
	"select e.backupset_id from backupsets as e  "
	"left join (  "
	"  select c.backupset_id, d.ranknum  "
	"  from backupsets as c  "
	"    inner join (  "
	"      select a.backupset_id, count(*) as ranknum  "
	"      from backupsets as a  "
	"	 inner join backupsets as b on (a.name = b.name) "
	"          and (a.retention = b.retention) "
	"          and (a.serial <= b.serial) "
	"      group by a.backupset_id  "
	"      having ranknum <= %d  "
	"    ) as d on (c.backupset_id = d.backupset_id)  "
	"  order by c.name, d.ranknum  "
	") as f on e.backupset_id = f.backupset_id  "
	"where f.backupset_id is null and e.retention = '%q' and e.serial < %d%s ",
	min, retention, cutoffdate,
	strlen(bkname) > 0 ? sqlstmt_tmp : "")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    if (strlen(bkname) > 0)
        sqlite3_free(sqlstmt_tmp);
    
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from received_file_entities where backupset_id in ( "
	"select backupset_id from expirelist)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from needed_file_entities where backupset_id in ("
	"select backupset_id from expirelist)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from backupset_detail where backupset_id in ("
	"select backupset_id from expirelist)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from backupsets where backupset_id in ("
	"select backupset_id from expirelist)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from log where backupset_id in ("
	"select backupset_id from expirelist)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    return(0);
}
int purge(int argc, char **argv)
{
    sqlite3 *bkcatalog;
    sqlite3_stmt *sqlres;
    char *bkcatalogp;
    char *sqlstmt = 0;
    char *sqlerr;
    time_t purgedate;
    char *destdir = config.vault;
    struct stat tmpfstat;
    const char *sha1;
    char *destfilepath;
    char *destfilepathd;

    if (asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog") < 0) {
	fprintf(stderr, "Memory allocation error\n");
	exit(1);
    }
    if (sqlite3_open(bkcatalogp, &bkcatalog) != SQLITE_OK) {
	fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
	exit(1);
    }
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
//    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);

    purgedate = time(0);

    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    // If any backups are in progress, use the start time as the newest allowed purge date
    sqlite3_prepare_v2(bkcatalog,
        (sqlstmt = sqlite3_mprintf(

	    "SELECT c.logdate "
	    "FROM log AS c "
	    "  INNER JOIN ( "
	    "    SELECT a.rowid, COUNT(*) AS ranknum "
	    "    FROM log AS a "
	    "      INNER JOIN log AS b ON (a.backupset_id = b.backupset_id) AND (a.logdate <= b.logdate) "
	    "       AND (a.action <= b.action) AND a.rowid <= b.rowid "
	    "    GROUP BY a.rowid "
	    "    HAVING ranknum <= 1 "
	    "  ) AS d ON (c.rowid = d.rowid) "
	    "where c.action < 6 and c.action >= 4 and c.logdate >= date('now', '-3 days') ORDER BY c.logdate limit 1")), -1, &sqlres, 0);
    if ((sqlite3_step(sqlres)) == SQLITE_ROW) {
        purgedate = sqlite3_column_int(sqlres, 0);
    }

    fprintf(stderr, "Creating purge list 1\n");
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create temporary table if not exists purgelist1 ( \n"
	"    file_id	integer primary key, "
	"    sha1	char)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert into purgelist1 (file_id, sha1) "
	"select f.file_id, f.sha1 from file_entities f "
	"left join backupset_detail d "
	"on f.file_id = d.file_id "
	"where d.file_id is null")),
    0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    fprintf(stderr, "Purging from file_entities\n");
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from file_entities where file_id in ( "
	"select file_id from purgelist1) ")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    fprintf(stderr, "Creating final purge list\n");
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert into purgelist (datestamp, sha1) "
	"select %d, d.sha1 from diskfiles d "
	"left join file_entities f "
	"on d.sha1 = f.sha1 "
	"where f.sha1 is null ", purgedate)), 0, 0, &sqlerr);
#if 0
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert into purgelist (datestamp, sha1)  "
	"select %d, p1.sha1 from ( "
	"select distinct p.sha1 from purgelist1 p "
	"left join file_entities f "
	"on p.sha1 = f.sha1 "
	"where f.sha1 is null "
	") p1 "
	"left join received_file_entities r "
	"on p1.sha1 = r.sha1 "
	"where  r.sha1 is null and p1.sha1 != '0'", purgedate)), 0, 0, &sqlerr);
#endif
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    fprintf(stderr, "Removing files\n");
    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select sha1, datestamp from purgelist")),
	-1, &sqlres, 0);
    while (sqlite3_step(sqlres) == SQLITE_ROW) {

	sha1 = (char *) sqlite3_column_text(sqlres, 0);
	sprintf((destfilepath = malloc(strlen(destdir) + strlen(sha1) + 7)), "%s/%2.2s/%s.lzo", destdir, sha1, sha1 + 2);
	sprintf((destfilepathd = malloc(strlen(destdir) + strlen(sha1) + 9)), "%s/%2.2s/%s.lzo.d", destdir, sha1, sha1 + 2);
	if (rename(destfilepath, destfilepathd) == 0) {
	    if (stat(destfilepathd, &tmpfstat) == 0 && tmpfstat.st_mtime < sqlite3_column_int(sqlres, 1)) {
		fprintf(stderr, "Removing %s\n", destfilepath);
		remove(destfilepathd);
		sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		    "delete from diskfiles where sha1 = '%s'", sha1)), 0, 0, &sqlerr);
	    }
	    else {
		fprintf(stderr, "    Restoring %s\n", destfilepath);
		rename(destfilepathd, destfilepath);
	    }
	}
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from purgelist where sha1 = '%s'", sha1)), 0, 0, &sqlerr);
    }
    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
    return(0);
}


// Compression version of fopen/fclose/fread/fwrite (lzo / lzop version)

// Write lzop header to open file and initialize cfile structure
struct cfile *cfinit(FILE *outfile)
{
    struct cfile *cfile;
    char magic[] = {  0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };
    uint32_t chksum = 1;

    cfile = malloc(sizeof(*cfile));
    cfile->bufsize = 256 * 1024;
    cfile->buf = malloc(cfile->bufsize);
    cfile->cbuf = malloc(256 * 1024 + 256 * 64 + 64 + 3);
    cfile->bufp = cfile->buf;
    cfile->working_memory = malloc(LZO1X_1_MEM_COMPRESS);
    {
	cfile->handle = outfile;
	fwrite(magic, 1, sizeof(magic), cfile->handle);
	fwritec(htonsp(0x1030), 1, 2, cfile->handle, &chksum);
	fwritec(htonsp(lzo_version()), 1, 2, cfile->handle, &chksum);
	fwritec(htonsp(0x0940), 1, 2, cfile->handle, &chksum);
	fwritec("\001", 1, 1, cfile->handle, &chksum);
	fwritec("\005", 1, 1, cfile->handle, &chksum);
	fwritec(htonlp(0x300000d), 1, 4, cfile->handle, &chksum);
	fwritec(htonlp(0x0), 1, 4, cfile->handle, &chksum);
	fwritec(htonlp(0x0), 1, 4, cfile->handle, &chksum);
	fwritec(htonlp(0x0), 1, 4, cfile->handle, &chksum);
	fwritec("\000", 1, 1, cfile->handle, &chksum);
	fwritec(htonlp(chksum), 1, 4, cfile->handle, &chksum);
    }
    return(cfile);
}

// Read lzop header from open file and initialize cfile structure
struct cfile *cfinit_r(FILE *infile)
{
    struct cfile *cfile;
    char magic[] = {  0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };
    uint16_t tmp16;
    uint32_t tmp32;
    struct {
	char magic[sizeof(magic)];
	uint16_t version;
	uint16_t libversion;
	uint16_t minversion;
	unsigned char compmethod;
	unsigned char level;
	uint32_t flags;
	uint32_t filter;
	uint32_t mode;
	uint32_t mtime_low;
	uint32_t mtime_high;
	unsigned char filename_len;
	char filename[256];
	uint32_t chksum;
    } lzop_header;

    cfile = malloc(sizeof(*cfile));
    cfile->bufsize = 0;
    cfile->buf = malloc(256 * 1024);
    cfile->cbuf = malloc(256 * 1024 + 256 * 64 + 64 + 3);
    cfile->bufp = cfile->buf;
//    cfile->working_memory = malloc(LZO1X_1_MEM_COMPRESS);
    cfile->handle = infile;

    // Process header
    fread(&(lzop_header.magic), 1, sizeof(magic), infile);
    fread(&tmp16, 1, 2, infile);
    lzop_header.version = ntohs(tmp16);
    fread(&tmp16, 1, 2, infile);
    lzop_header.libversion = ntohs(tmp16);
    if (lzop_header.version >= 0x0940) {
	fread(&tmp16, 1, 2, infile);
	lzop_header.minversion = ntohl(tmp16);
    }
    fread(&(lzop_header.compmethod), 1, 1, infile);
    if (lzop_header.version >= 0x0940)
	fread(&(lzop_header.level), 1, 1, infile);
    fread(&tmp32, 1, 4, infile);
    lzop_header.flags = ntohl(tmp32);
    if (lzop_header.flags & F_H_FILTER) {
	fread(&tmp32, 1, 4, infile);
	lzop_header.filter = ntohl(tmp32);
    }
    fread(&tmp32, 1, 4, infile);
    lzop_header.mode = ntohl(tmp32);
    fread(&tmp32, 1, 4, infile);
    lzop_header.mtime_low = ntohl(tmp32);
    fread(&tmp32, 1, 4, infile);
    lzop_header.mtime_high = ntohl(tmp32);
    fread(&(lzop_header.filename_len), 1, 1, infile);
    if (lzop_header.filename_len > 0)
	fread(&(lzop_header.filename), 1, lzop_header.filename_len, infile);
    fread(&tmp32, 1, 4, infile);
    lzop_header.chksum = ntohl(tmp32);
    return(cfile);
}

// write lzo compressed data (lzop format)
int cwrite(void *buf, size_t sz, size_t count, struct cfile *cfile)
{
    size_t bytesin = sz * count;
    uint32_t chksum;

    do {
	if (bytesin <= cfile->bufsize - (cfile->bufp - cfile->buf)) {
	    memcpy(cfile->bufp, buf, bytesin);
	    cfile->bufp += bytesin;
	    bytesin = 0;
	}
	else {
	    memcpy(cfile->bufp, buf, cfile->bufsize - (cfile->bufp - cfile->buf));
	    bytesin -= (cfile->bufsize - (cfile->bufp - cfile->buf));
	    buf += (cfile->buf + cfile->bufsize - cfile->bufp);
	    // compress cfile->buf, write out

	    // write uncompressed block size
	    fwrite(htonlp(cfile->bufsize), 1, 4, cfile->handle);
	    chksum = lzo_adler32(1, (unsigned char *) cfile->buf, cfile->bufsize);
	    lzo1x_1_compress((unsigned char *) cfile->buf, cfile->bufsize, (unsigned char *) cfile->cbuf, &(cfile->cbufsize), cfile->working_memory);
	    // write compressed block size
	    if (cfile->cbufsize < cfile->bufsize)
		fwrite(htonlp(cfile->cbufsize), 1, 4, cfile->handle);
	    else
		fwrite(htonlp(cfile->bufsize), 1, 4, cfile->handle);
	    // write checksum
	    fwrite(htonlp(chksum), 1, 4, cfile->handle);
	    //write compressed data
	    if (cfile->cbufsize < cfile->bufsize)
		fwrite(cfile->cbuf, 1, cfile->cbufsize, cfile->handle);
	    else
		fwrite(cfile->buf, 1, cfile->bufsize, cfile->handle);
	    cfile->bufp = cfile->buf;
	}
    } while (bytesin > 0);
    return(0);
}

int cread(void *buf, size_t sz, size_t count, struct cfile *cfile)
{
    size_t bytesin = sz * count;
    uint32_t tchksum;
    uint32_t chksum;
    uint32_t tucblocksz;
    uint32_t tcblocksz;
    uint32_t ucblocksz;
    uint32_t cblocksz;
    size_t orig_bytesin = bytesin;

    do {
	if (bytesin <= cfile->buf + cfile->bufsize - cfile->bufp) {
	    memcpy(buf, cfile->bufp, bytesin);
	    cfile->bufp += bytesin;
	    bytesin = 0;
	}
	else {
	    memcpy(buf, cfile->bufp, cfile->buf + cfile->bufsize - cfile->bufp);
	    bytesin -= (cfile->buf + cfile->bufsize - cfile->bufp);
	    buf += (cfile->buf + cfile->bufsize - cfile->bufp);
	    fread(&tucblocksz, 1, 4, cfile->handle);
	    ucblocksz = ntohl(tucblocksz);
	    if (ucblocksz == 0)
		return(cfile->buf + cfile->bufsize - cfile->bufp);
	    fread(&tcblocksz, 1, 4, cfile->handle);
	    cblocksz = ntohl(tcblocksz);
	    fread(&tchksum, 1, 4, cfile->handle);
	    chksum = ntohl(tchksum);
	    fread(cfile->cbuf, 1, cblocksz, cfile->handle);
	    if (cblocksz < ucblocksz) {
		lzo1x_decompress((unsigned char *) cfile->cbuf, cblocksz, (unsigned char *) cfile->buf, &(cfile->bufsize), NULL);
	    }
	    else {
		memcpy(cfile->buf, cfile->cbuf, cblocksz);
	    }
	    if (chksum != lzo_adler32(1, (unsigned char *) cfile->buf, ucblocksz)) {
		fprintf(stderr, "Checksum error reading compressed lzo file\n");
	    }
	    cfile->bufp = cfile->buf;
	    cfile->bufsize = ucblocksz;
	}
    } while (bytesin > 0);
    return(orig_bytesin);
}

int cgetline(char **buf, size_t *sz, struct cfile *cfile)
{
    uint32_t tchksum;
    uint32_t chksum;
    uint32_t tucblocksz;
    uint32_t tcblocksz;
    uint32_t ucblocksz;
    uint32_t cblocksz;
    int n = 0;

    if (*buf == NULL) {
        *sz = 64;
        *buf = malloc(*sz);
    }

    do {
        while (cfile->buf + cfile->bufsize - cfile->bufp > 0 && *(cfile->bufp) != '\n') {
            if (n + 4 >= *sz) {
                (*sz) += 64;
                *buf = realloc(*buf, *sz);
            }
            (*buf)[n++] = *(cfile->bufp++);
        }
        if (*(cfile->bufp) == '\n') {
            (*buf)[n++] = *(cfile->bufp++);
            (*buf)[n] = '\0';
            return(n);
        }
        {
            fread(&tucblocksz, 1, 4, cfile->handle);
            ucblocksz = ntohl(tucblocksz);
            if (ucblocksz == 0) {
                *(buf[n]) = '\0';
                return(n);
            }
            fread(&tcblocksz, 1, 4, cfile->handle);
            cblocksz = ntohl(tcblocksz);
            fread(&tchksum, 1, 4, cfile->handle);
            chksum = ntohl(tchksum);
            fread(cfile->cbuf, 1, cblocksz, cfile->handle);
            if (cblocksz < ucblocksz) {
                lzo1x_decompress((unsigned char *) cfile->cbuf, cblocksz, (unsigned char *) cfile->buf, &(cfile->bufsize), NULL);
            }
            else {
                memcpy(cfile->buf, cfile->cbuf, cblocksz);
            }
	    if (chksum != lzo_adler32(1, (unsigned char *) cfile->buf, ucblocksz)) {
		fprintf(stderr, "Checksum error reading compressed lzo file\n");
	    }
            cfile->bufp = cfile->buf;
            cfile->bufsize = ucblocksz;
        }
    } while (1);
}

// Close lzop file
int cclose(struct cfile *cfile)
{
    uint32_t chksum;

    if (cfile->bufp - cfile->buf > 0) {
	fwrite(htonlp(cfile->bufp - cfile->buf), 1, 4, cfile->handle);
	chksum = lzo_adler32(1, (unsigned char *) cfile->buf, cfile->bufp - cfile->buf);
	lzo1x_1_compress((unsigned char *) cfile->buf, cfile->bufp - cfile->buf, (unsigned char *) cfile->cbuf, &(cfile->cbufsize), cfile->working_memory);
	if (cfile->cbufsize < (cfile->bufp - cfile->buf))
	    fwrite(htonlp(cfile->cbufsize), 1, 4, cfile->handle);
	else
	    fwrite(htonlp(cfile->bufp - cfile->buf), 1, 4, cfile->handle);
	fwrite(htonlp(chksum), 1, 4, cfile->handle);
	if (cfile->cbufsize < (cfile->bufp - cfile->buf))
	    fwrite(cfile->cbuf, 1, cfile->cbufsize, cfile->handle);
	else
	    fwrite(cfile->buf, 1, (cfile->bufp - cfile->buf), cfile->handle);
    }
    fwrite(htonlp(0), 1, 4, cfile->handle);
    fclose(cfile->handle);
    free(cfile->buf);
    free(cfile->cbuf);
    free(cfile->working_memory);
    free(cfile);
    return(0);
}
int cclose_r(struct cfile *cfile)
{
    free(cfile->buf);
    free(cfile->cbuf);
//    free(cfile->working_memory);
    fclose(cfile->handle);
    free(cfile);
    return(0);
}

uint32_t *htonlp(uint32_t v)
{
    static uint32_t r;
    r = htonl(v);
    return(&r);
}
uint16_t *htonsp(uint16_t v)
{
    static uint16_t r;
    r = htons(v);
    return(&r);
}

size_t fwritec(const void *ptr, size_t size, size_t nmemb, FILE *stream, uint32_t *chksum)
{
    size_t r;
    r = fwrite(ptr, size, nmemb, stream);
    *chksum = lzo_adler32(*chksum, ptr, size * nmemb);
    return(r);
}

// Parses inbound instr, splitting it on character p
// Returns number of fields, replacing instance of p with null
int parsex(char *instr, char p, char ***b, int max)
{
    int i = 0;
    char *a[256];
    a[i] = instr;
    while (*instr != '\0' && i < max) {
	if (*instr == p) {
	    *instr = '\0';
	    a[++i] = instr + 1;
	}
	instr++;
    }
    i++;
    *b = realloc(*b, i * sizeof(char *));
    memcpy(*b, a, i * sizeof(char *));
    return(i);
}

int getpaxvar(char *paxdata, int paxlen, char *name, char **rvalue, int *rvaluelen) {
    char *nvp = paxdata;
    int nvplen;
    char *cname;
    int cnamelen;
    char *value;
    int valuelen;

    while (nvp < paxdata + paxlen) {
	nvplen = strtol(nvp, &cname, 10);
	cname++;
	value = strchr(cname, '=');
	cnamelen = value - cname;
	value++;
	valuelen = nvp + nvplen - value;
	if (strncmp(name, cname, cnamelen) == 0) {
	    *rvalue = value;
	    *rvaluelen = valuelen;
	    return(0);
	}
	nvp += nvplen;
    }
    return(1);
}

int cmpspaxvar(char *paxdata, int paxlen, char *name, char *invalue) {
    char *nvp = paxdata;
    int nvplen;
    char *cname;
    int cnamelen;
    char *value;
    int valuelen;

    while (nvp < paxdata + paxlen) {
	nvplen = strtol(nvp, &cname, 10);
	cname++;
	value = strchr(cname, '=');
	cnamelen = value - cname;
	value++;
	valuelen = nvp + nvplen - value;
	if (strncmp(name, cname, cnamelen) == 0) {
	    return(strncmp(value, invalue, valuelen - 1));
	}
	nvp += nvplen;
    }
    return(1);
}

int setpaxvar(char **paxdata, int *paxlen, char *inname, char *invalue, int invaluelen) {
    char *cnvp = *paxdata;
    int cnvplen;
    char *cname;
    int cnamelen;
    char *cvalue;
    int innamelen = strlen(inname);
    int innvplen;
    static char *nvpline = NULL;
    int foundit=0;

    innvplen = innamelen + invaluelen + 3 + (ilog10(innamelen + invaluelen + 3 + (ilog10( innamelen + invaluelen + 3)) + 1)) + 1;
    nvpline = realloc(nvpline, innvplen + 1);
    sprintf(nvpline, "%d %s=%s\n", innvplen, inname, invalue);


    while (cnvp < *paxdata + *paxlen) {
        cnvplen = strtol(cnvp, &cname, 10);
        cname++;
        cvalue = strchr(cname, '=');
        cnamelen = cvalue - cname;
        cvalue++;
        if (strncmp(inname, cname, cnamelen) == 0) {
            if (innvplen > cnvplen) {
                *paxlen = *paxlen + (innvplen - cnvplen);
                *paxdata = realloc(*paxdata, *paxlen);
                memmove(cnvp + innvplen, cnvp + cnvplen, (*paxdata + *paxlen) - (cnvp + cnvplen));
                memcpy(cnvp, nvpline, innvplen);
            }
            else if (innvplen < cnvplen) {
                memmove(cnvp + innvplen, cnvp + cnvplen, (*paxdata + *paxlen) - (cnvp + cnvplen));
                memcpy(cnvp, nvpline, innvplen);
                *paxlen = *paxlen + (innvplen - cnvplen);
                *paxdata = realloc(*paxdata, *paxlen);
            }
            else {
                memcpy(cnvp, nvpline, innvplen);
            }
            foundit = 1;
            break;
        }
        cnvp += cnvplen;
    }
    if (foundit == 0) {
        *paxdata = realloc(*paxdata, *paxlen + innvplen);
        memcpy(*paxdata + *paxlen, nvpline, innvplen);
        *paxlen = *paxlen + innvplen;
    }
    return(0);
}
int delpaxvar(char **paxdata, int *paxlen, char *inname) {
    char *cnvp = *paxdata;
    int cnvplen;
    char *cname;
    int cnamelen;
    char *cvalue;

    while (cnvp < *paxdata + *paxlen) {
        cnvplen = strtol(cnvp, &cname, 10);
        cname++;
        cvalue = strchr(cname, '=');
        cnamelen = cvalue - cname;
        cvalue++;
        if (strncmp(inname, cname, cnamelen) == 0) {
            memmove(cnvp, cnvp + cnvplen, (*paxdata + *paxlen) - (cnvp + cnvplen));
            *paxlen = *paxlen - cnvplen;
            *paxdata = realloc(*paxdata, *paxlen);
            break;
        }
        cnvp += cnvplen;
    }
    return(0);
}
unsigned int ilog10(unsigned int n) {
    static int lt[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000, 0xffffffff };

    int min = 0;
    int max = sizeof(lt) / sizeof(*lt) - 1;
    int mid;

    if (n == 0)
	return(0);
    while (max >= min) {
	mid = (int) (((min + max) / 2));
	if (n >= lt[min]  && n < lt[mid]) {
	    if (min + 1 == mid)
		return(min);
	    else
		max = mid;
	}
	else if (n >= lt[mid] && (n < 0xffffffff ? n < lt[max] : n <= lt[max])) {
	    if (mid + 1 == max)
		return(mid);
	    else
		min = mid;
	}
    }
    return(0);
}


int flush_received_files(sqlite3 *bkcatalog, int verbose, int bkid,
    unsigned long long est_size,  unsigned long long bytes_read, unsigned long long bytes_readp)
{
    char *sqlerr;
    sqlite3_stmt *sqlres;
    char *sqlstmt = 0;
    int x;
    char statusline[80];

	    in_a_transaction = 0;
	    if (verbose > 1)
		fprintf(stderr, "\n");

	    if (verbose >= 2)
		fprintf(stderr, "Finished receiving files\n");

	    logaction(bkcatalog, bkid, 5, "Copying entries to diskfiles");
	    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into diskfiles select * from diskfiles_t"
	    )), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }

	    logaction(bkcatalog, bkid, 5, "Copying entries to needed_file_entities_current");
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert into needed_file_entities_current "
		"    select device_id, inode, filename, infilename, size, cdatestamp "
		"    from needed_file_entities "
		"    where backupset_id = %d; ", bkid
	    )), 0, 0, &sqlerr);
    
	    if (sqlerr != 0) {
		fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);

	    logaction(bkcatalog, bkid, 5, "Merging hardlink file metadata");
	    if (verbose >= 2)
		fprintf(stderr, "Merging hardlink file metadata\n");
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert into received_file_entities_ldi_t "
		"    select rr.ftype, rr.permission, n.device_id, n.inode, "
		"    rr.user_name, rr.user_id, rr.group_name, rr.group_id, rr.size, "
		"    rr.sha1, n.cdatestamp, rr.datestamp, n.filename, rr.extdata, rr.xheader"
		"  from received_file_entities_t rr "
		"    join received_file_entities_t rl "
		"    on rl.extdata = rr.filename "
		"    join needed_file_entities_current n "
		"    on rl.filename = n.infilename "
		"    where rl.ftype = 1"
	    )), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
		
	    logaction(bkcatalog, bkid, 5, "Adding regular files, directories, and symlinks");
	    if (verbose >= 2)
		fprintf(stderr, "Adding regular files, directories, and symlinks\n");
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into received_file_entities_ldi_t "
		"    select r.ftype, r.permission, n.device_id, n.inode, "
		"    r.user_name, r.user_id, r.group_name, r.group_id, r.size, "
		"    r.sha1, n.cdatestamp, r.datestamp, n.filename, r.extdata, r.xheader "
		" from received_file_entities_t r "
		"    join needed_file_entities_current n "
		"    on r.filename = n.infilename "
		"    where r.ftype != 1"
	    )), 0, 0, &sqlerr);

	    if (sqlerr != 0) {
		fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	    if (verbose >= 1) {
		x = sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
		    "select sum(size) from received_file_entities_ldi_t")), -1, &sqlres, 0);
		if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
		    bytes_read = sqlite3_column_int64(sqlres, 0);
		    sprintf(statusline, "%llu/%llu bytes, %.0f %%", bytes_read + bytes_readp, est_size, est_size != 0 ? ((double) (bytes_read + bytes_readp) / (double) est_size * 100) : 0) ;
		    if (verbose == 1)
			fprintf(stderr, "\r");
		    fprintf(stderr, "%45s\n", statusline);
		}
		sqlite3_finalize(sqlres);
		sqlite3_free(sqlstmt);
	    }
	    logaction(bkcatalog, bkid, 5, "Copying to file_entities");
	    if (verbose >= 2)
		fprintf(stderr, "Copying to file_entities\n");
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into file_entities (ftype, permission, device_id, inode,  "
		"user_name, user_id, group_name, group_id, size, sha1, cdatestamp, datestamp, filename, extdata, xheader)  "
		"select ftype, permission, device_id, inode, user_name, user_id, group_name,  "
		"group_id, size, sha1, cdatestamp, datestamp, filename, extdata, xheader from received_file_entities_ldi_t  "
		)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);

	    logaction(bkcatalog, bkid, 5, "Creating backupset_detail");
	    if (verbose >= 2)
		fprintf(stderr, "Creating backupset_detail\n");
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into backupset_detail (backupset_id, file_id) select %d,"
		"f.file_id from file_entities f join received_file_entities_ldi_t r  "
		"on f.ftype = r.ftype and f.permission = r.permission  "
		"and f.device_id = r.device_id and f.inode = r.inode  "
		"and f.user_name = r.user_name and f.user_id = r.user_id  "
		"and f.group_name = r.group_name and f.group_id = r.group_id  "
		"and f.size = r.size and f.sha1 = r.sha1 and f.cdatestamp = r.cdatestamp and f.datestamp = r.datestamp  "
		"and f.filename = r.filename and f.extdata = r.extdata and f.xheader = r.xheader  ",
		bkid)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	    sqlite3_exec(bkcatalog, "END", 0, 0, 0);

	    return(0);
}

int submitfiles_tmptables(sqlite3 *bkcatalog, int bkid)
{
    char *sqlerr;
    char *sqlstmt = 0;
    sqlite3_exec(bkcatalog,
	"create temporary table if not exists received_file_entities_ldi_t (  \n"
	"    ftype         char,  \n"
	"    permission    char,  \n"
	"    device_id     char,  \n"
	"    inode         char,  \n"
	"    user_name     char,  \n"
	"    user_id       integer,  \n"
	"    group_name    char,  \n"
	"    group_id      integer,  \n"
	"    size          integer,  \n"
	"    sha1           char,  \n"
	"    cdatestamp    integer,  \n"
	"    datestamp     integer,  \n"
	"    filename      char,  \n"
	"    extdata       char default '',  \n"
	"    xheader       blob default '',  \n"
	"constraint received_file_entities_ldi_t_c1 unique (  \n"
	"    ftype,  \n"
	"    permission,  \n"
	"    device_id,  \n"
	"    inode,  \n"
	"    user_name,  \n"
	"    user_id,  \n"
	"    group_name,  \n"
	"    group_id,  \n"
	"    size,  \n"
	"    sha1,  \n"
	"    cdatestamp,  \n"
	"    datestamp,  \n"
	"    filename,  \n"
	"    extdata,  \n"
	"    xheader ))", 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog,
	"create temporary table if not exists received_file_entities_ldi_t1 (  \n"
	"    ftype         char,  \n"
	"    permission    char,  \n"
	"    user_name     char,  \n"
	"    user_id       integer,  \n"
	"    group_name    char,  \n"
	"    group_id      integer,  \n"
	"    size          integer,  \n"
	"    sha1           char,  \n"
	"    datestamp     integer,  \n"
	"    filename      char,  \n"
	"    extdata       char default '',  \n"
	"    xheader       blob default '',  \n"
	"constraint received_file_entities_ldi_t_c1 unique (  \n"
	"    ftype,  \n"
	"    permission,  \n"
	"    user_name,  \n"
	"    user_id,  \n"
	"    group_name,  \n"
	"    group_id,  \n"
	"    size,  \n"
	"    sha1,  \n"
	"    datestamp,  \n"
	"    filename,  \n"
	"    extdata,  \n"
	"    xheader ))", 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
	"create index if not exists "
	"received_file_entities_ldi_t1_i1 "
	"on received_file_entities_ldi_t1 ( "
	"extdata, filename)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
	"create index if not exists "
	"received_file_entities_ldi_t1_i2 "
	"on received_file_entities_ldi_t1 ( "
	"filename, extdata)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog,
	"create temporary table if not exists needed_file_entities_current ( "
	"    device_id     char, "
	"    inode         char, "
	"    filename      char, "
	"    infilename    char, "
	"    size          integer, "
	"    cdatestamp    integer, "
	"unique ( "
	"    filename, "
	"    infilename ))", 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog,
	"create index if not exists "
	"needed_file_entities_current_i1 "
	"on needed_file_entities_current ( "
	"infilename)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
	"create index if not exists "
	"needed_file_entities_current_i2 "
	"on needed_file_entities_current ( "
	"filename)", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog,
	"create temporary table if not exists received_file_entities_t "
	"as select * from received_file_entities where 0", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
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
	fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
	
    return(0);
}
int logaction(sqlite3 *bkcatalog, int backupset_id, int action, char *message)
{
    char *sqlstmt = 0;
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert into log (backupset_id, logdate, action, message) "
	"values ('%d', '%d', '%d', '%q')", backupset_id, time(0), action, message)), 0, 0, 0);
    sqlite3_free(sqlstmt);
    return(0);
}

#undef sqlite3_exec
#undef sqlite3_step
#undef sqlite3_prepare_v2
int my_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *carg1, char **errmsg)
{
    int r = 0;
    if (concurrency_sleep_requested == 1) {
	concurrency_sleep_requested = 0;
	fprintf(stderr, "sqlite3_exec pausing by request\n");
	if (in_a_transaction == 1) {
	    in_a_transaction = 0;
	    my_sqlite3_exec(db, "END", 0, 0, 0);
	    sleep(2);
	    concurrency_sleep_requested = 0;
	    my_sqlite3_exec(db, "BEGIN", 0, 0, 0);
	    in_a_transaction = 1;
	}
	else
	    sleep(2);
    }
    do {
        r = sqlite3_exec(db, sql, callback, carg1, errmsg);
	if (r == 5) {
	    usleep(100000);
	}
    } while (r == 5);
    if (r != 0)
	fprintf(stderr, "sqlite3_exec_return: %d\n", r);
    return(r);
}
int my_sqlite3_step(sqlite3_stmt *stmt)
{
    int r = 0;
    if (concurrency_sleep_requested == 1) {
	fprintf(stderr, "sqlite3_step pausing by request\n");
	sleep(2);
	concurrency_sleep_requested = 0;
    }
    do {
        r = sqlite3_step(stmt);
	if (r == 5) {
	    usleep(100000);
	}
    } while (r == 5);
    return(r);
}
int my_sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail)
{
    int r = 0;
    if (concurrency_sleep_requested == 1) {
	fprintf(stderr, "sqlite3_prepare_v2 pausing by request\n");
	if (in_a_transaction == 1) {
	    my_sqlite3_exec(db, "END", 0, 0, 0);
	    sleep(2);
	    my_sqlite3_exec(db, "BEGIN", 0, 0, 0);
	}
	else
	    sleep(2);
	concurrency_sleep_requested = 0;
    }
    do {
	r = sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
	if (r == 5) {
	    usleep(100000);
	}
    } while (r == 5);
    return(r);
}

//Handler function for signal USR1
void concurrency_request_signal()
{
    concurrency_sleep_requested = 1;
    fprintf(stderr, "Setting concurrency_sleep flag\n");
    signal(SIGUSR1, concurrency_request_signal);
}

// Send a signal USR1 to all other processes named "snebu",
// requesting them to pause for a couple seconds and commit
// current trasaction, therefore allowing us to sneak in a
// database transaction.
void concurrency_request()
{
    FILE *pgrep_output;
    int numproclist = 20;
    pid_t *proclist = malloc(numproclist * sizeof(*proclist));
    char *instr = 0;
    size_t instrlen = 0;
    int numpid = 0;
    pid_t mypid;
    int i;

    fprintf(stderr, "Requesting concurrency\n");
    mypid = getpid();
    pgrep_output = popen("pgrep -x snebu", "r");
    while (getline(&instr, &instrlen, pgrep_output) > 0) {
	if (numpid >= numproclist) {
	    numproclist += 20;
	    proclist = realloc(proclist, numproclist * sizeof(*proclist));
	}
	if (atoi(instr) != mypid) {
	    proclist[numpid] = atoi(instr);
	    numpid++;
	}
    }
    for (i = 0; i < numpid; i++)
	kill(proclist[i], SIGUSR1);

}
