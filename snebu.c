#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

struct {
    char *vault;
    char *meta;
} config;

int initdb(sqlite3 *bkcatalog);
int sqlbusy(void *x, int y);
char *stresc(char *src, unsigned char **target);
char *strunesc(char *src, unsigned char **target);
long int strtoln(char *nptr, char **endptr, int base, int len);
int main(int argc, char **argv)
{
    sqlite3 *bkcatalog;
    int err;
    char *subfunc;
    

    if (argc > 1)
	subfunc = argv[1];
    else {
	usage();
	exit(1);
    }
    getconfig();

    if (strcmp(subfunc, "newbackup") == 0)
	newbackup(argc - 1, argv + 1);
    else if (strcmp(subfunc, "submitfiles") == 0)
	submitfiles(argc - 1, argv + 1);
    else if (strcmp(subfunc, "restore") == 0)
	restore(argc - 1, argv + 1);
    else if (strcmp(subfunc, "listbackups") == 0)
	listbackups(argc - 1, argv + 1);
    else if (strcmp(subfunc, "import") == 0)
	import(argc - 1, argv + 1);
    else if (strcmp(subfunc, "expire") == 0)
	expire(argc - 1, argv + 1);
    else {
	usage();
	exit(1);
    }

    return 0;
}
newbackup(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    char retention[128];
    int foundopts = 0;
    char *filespecs = 0;
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
	char md5[33];
        int modtime;
	char *filename;
	char *linktarget;
    } fs;
    int flen1;
    int x;
    char *sqlstmt = 0;
    char *sqlstmt2 = 0;
    sqlite3_stmt *sqlres;
    int bkid = 0;
    int fileid;
    sqlite3 *bkcatalog;
    char *bkcatalogp;
    char *sqlerr;


    while ((optc = getopt(argc, argv, "n:d:r:")) >= 0) 
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
	    default:
		usage();
		exit(1);
	}
    if (foundopts != 7) {
	fprintf(stderr, "Didn't find all arguments\n");
        usage();
        exit(1);
    }
    asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog");
    x = sqlite3_open(bkcatalogp, &bkcatalog);
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
    x = initdb(bkcatalog);

    x = sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupsets (name, retention, serial) \
	values ('%s', '%s', '%s')", bkname, retention, datestamp)), 0, 0, 0);
    sqlite3_free(sqlstmt);
    x = sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select backupset_id from backupsets \
	    where name = '%s' and retention = '%s' and serial = '%s'",
	    bkname, retention, datestamp)), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
    }
    else
	fprintf(stdout, "newbackup: failed to create backup id %d\n", bkid);
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, " \
	create temporary table if not exists inbound_file_entities ( \
       	    backupset_id     integer, \
       	    ftype         char, \
	    permission    char, \
    	    device_id     char, \
       	    inode         char, \
	    user_name     char, \
	    user_id       integer, \
	    group_name    char, \
	    group_id      integer, \
	    size          integer, \
	    md5           char, \
	    datestamp     integer, \
	    filename      char, \
	    extdata       char default '', \
	constraint inbound_file_entitiesc1 unique ( \
	    backupset_id, \
	    ftype, \
	    permission, \
	    device_id, \
	    inode, \
	    user_name, \
	    user_id, \
	    group_name, \
	    group_id, \
	    size, \
	    md5, \
	    datestamp, \
	    filename, \
	    extdata ))", 0, 0, &sqlerr);


//    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    while (getdelim(&filespecs, &filespeclen, 0, stdin) > 0) {
        flen1 = 0;
	x = sscanf(filespecs, "%c\t%o\t%32s\t%32s\t%32s\t%d\t%32s\t%d\t%llu\t%32s\t%d.%*d\t%n",
	    &fs.ftype, &fs.mode, fs.devid,
	    fs.inode, fs.auid, &fs.nuid, fs.agid,
	    &fs.ngid, &fs.filesize, fs.md5,
	    &fs.modtime, &flen1);
	if (flen1 == 0)
	    x = sscanf(filespecs, "%c\t%o\t%32s\t%32s\t%32s\t%d\t%32s\t%d\t%llu\t%32s\t%d\t%n",
		&fs.ftype, &fs.mode, &fs.devid,
		fs.inode, fs.auid, &fs.nuid, fs.agid,
		&fs.ngid, &fs.filesize, fs.md5,
		&fs.modtime, &flen1);
	fs.filename = filespecs + flen1;
	if (fs.ftype == 'l') {
	    if (getdelim(&linkspecs, &linkspeclen, 0, stdin) > 0)
		fs.linktarget = linkspecs;
	}
	else
	    fs.linktarget = "";

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
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "insert or ignore into inbound_file_entities \
	    (backupset_id, ftype, permission, device_id, inode, user_name, user_id, group_name, \
	    group_id, size, md5, datestamp, filename, extdata) \
	    values ('%d', '%c', '%4.4o', '%s', '%s', '%s', '%d', '%s', '%d', '%llu', '%s', '%d', '%q', '%q')",
	    bkid, fs.ftype, fs.mode, fs.devid, fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid,
	    fs.filesize, fs.md5, fs.modtime, fs.filename, fs.linktarget)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
//	else
//	    fprintf(stderr, "%s\n", fs.filename);
	sqlite3_free(sqlstmt);

    }

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities \
	(ftype, permission, device_id, inode, user_name, user_id, group_name, \
	group_id, size, md5, datestamp, filename, extdata) \
	select i.ftype, permission, device_id, inode, user_name, user_id, group_name, \
	group_id, size, md5, datestamp, filename, extdata from inbound_file_entities i \
	where backupset_id = '%d' and (i.ftype = '5' or i.ftype = '2')", bkid)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into needed_file_entities \
	(backupset_id, device_id, inode, filename) \
	select backupset_id, i.device_id, i.inode, i.filename from inbound_file_entities i \
	left join file_entities f on \
	i.ftype = case when f.ftype = 'S' then '0' else f.ftype end \
	and i.permission = f.permission \
	and i.device_id = f.device_id and i.inode = f.inode \
	and i.user_name = f.user_name and i.user_id = f.user_id \
	and i.group_name = f.group_name and i.group_id = f.group_id \
	and i.size = f.size and i.datestamp = f.datestamp \
	and i.filename = f.filename and ((i.ftype = '0' and f.ftype = 'S') \
        or i.extdata = f.extdata) \
	where i.backupset_id = '%d' and f.file_id is null", bkid)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupset_detail \
	(backupset_id, file_id) \
	select i.backupset_id, f.file_id from file_entities f \
	join inbound_file_entities i \
	on i.ftype = case when f.ftype = 'S' then '0' else f.ftype end \
	and i.permission = f.permission \
	and i.device_id = f.device_id and i.inode = f.inode \
	and i.user_name = f.user_name and i.user_id = f.user_id \
	and i.group_name = f.group_name and i.group_id = f.group_id \
	and i.size = f.size and i.datestamp = f.datestamp \
	and i.filename = f.filename and ((i.ftype = '0' and f.ftype = 'S') \
	or i.extdata = f.extdata) \
	where i.backupset_id = '%d'", bkid)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
      
    sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf( "\
	select filename from needed_file_entities \
	where backupset_id = '%d'", bkid)), -1, &sqlres, 0);
    while (sqlite3_step(sqlres) == SQLITE_ROW)
	printf("%s\n", sqlite3_column_text(sqlres, 0));
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

//    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
	
    sqlite3_close(bkcatalog);
    return(0);
}
int initdb(sqlite3 *bkcatalog)
{
    int err = 0;
    char *sqlerr;

    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);
    err = sqlite3_exec(bkcatalog, " \
	    create table if not exists storagefiles ( \
	    md5           char, \
	    volume        char, \
	    segment       char, \
	    location      char, \
	constraint storagefilesc1 unique ( \
	    md5, \
	    volume, \
	    segment, \
	    location ))", 0, 0, 0);

    err = sqlite3_exec(bkcatalog, " \
	create table if not exists file_entities ( \
    	    file_id       integer primary key, \
       	    ftype         char, \
	    permission    char, \
    	    device_id     char, \
       	    inode         char, \
	    user_name     char, \
	    user_id       integer, \
	    group_name    char, \
	    group_id      integer, \
	    size          integer, \
	    md5           char, \
	    datestamp     integer, \
	    filename      char, \
	    extdata       char default '', \
	constraint file_entities_c1 unique ( \
	    ftype, \
	    permission, \
	    device_id, \
	    inode, \
	    user_name, \
	    user_id, \
	    group_name, \
	    group_id, \
	    size, \
	    md5, \
	    datestamp, \
	    filename, \
	    extdata ))", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "Create table file_entities: %s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog, " \
	create table if not exists received_file_entities ( \
    	    file_id       integer primary key, \
	    backupset_id  integer, \
       	    ftype         char, \
	    permission    char, \
	    user_name     char, \
	    user_id       integer, \
	    group_name    char, \
	    group_id      integer, \
	    size          integer, \
	    md5           char, \
	    datestamp     integer, \
	    filename      char, \
	    extdata       char default '', \
	unique ( \
	    ftype, \
	    backupset_id, \
	    permission, \
	    user_name, \
	    user_id, \
	    group_name, \
	    group_id, \
	    size, \
	    md5, \
	    datestamp, \
	    filename, \
	    extdata ))", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog, " \
	create table if not exists needed_file_entities ( \
	    backupset_id  integer, \
    	    device_id     char, \
       	    inode         char, \
	    filename      char, \
	foreign key(backupset_id) references backupsets(backupset_id), \
	unique ( \
	    backupset_id, \
	    filename ))", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog, " \
	    create table if not exists backupsets ( \
	    backupset_id  integer primary key, \
	    name          char, \
	    retention     char, \
	    serial        char, \
	constraint backupsetsc1 unique ( \
	    name, \
	    serial ))", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog, " \
	    create table if not exists backupset_detail ( \
	    backupset_id  integer, \
	    file_id       integer, \
	unique (backupset_id, file_id) \
	foreign key(backupset_id) references backupsets(backupset_id), \
	foreign key(file_id) references file_entities(file_id) )", 0, 0, 0);
    if (err != 0)
	return(err);

// Received file list with device_id and inode merged in
    err = sqlite3_exec(bkcatalog, "\
	create view if not exists \
	    received_file_entities_di \
	as select \
	    file_id, \
	    r.backupset_id, \
	    ftype, \
	    permission, \
	    n.device_id, \
	    n.inode, \
	    user_name, \
	    user_id, \
	    group_name, \
	    group_id, \
	    size, \
	    md5, \
	    datestamp, \
	    r.filename, \
	    r.extdata \
	from \
	    received_file_entities r \
	join \
	    needed_file_entities n \
	on \
	    r.filename = n.filename \
	    and r.backupset_id = n.backupset_id", 0, 0, 0);

    err = sqlite3_exec(bkcatalog, "\
        create view if not exists \
            received_file_entities_ldi \
        as select \
            l.file_id, \
            r.backupset_id, \
            r.ftype, \
            r.permission, \
            r.device_id, \
            r.inode, \
            r.user_name, \
            r.user_id, \
            r.group_name, \
            r.group_id, \
            r.size, \
            r.md5, \
            r.datestamp, \
            l.filename, \
            r.extdata \
        from \
            received_file_entities_di r \
        join \
            received_file_entities_di l \
        on \
            l.extdata = r.filename \
            and r.backupset_id = l.backupset_id \
        where \
            l.ftype = 1 \
        union select \
            file_id, \
            backupset_id, \
            ftype, \
            permission, \
            device_id, \
            inode, \
            user_name, \
            user_id, \
            group_name, \
            group_id, \
            size, \
            md5, \
            datestamp, \
            filename, \
            extdata \
            from \
            received_file_entities_di \
        where \
            ftype != '1'", 0, 0, 0);

    err = sqlite3_exec(bkcatalog, " \
	    create index needed_file_entitiesi1 on file_entities ( \
	    filename, file_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog, " \
	    create index backupset_detaili1 on file_entities ( \
	    backupset_id, file_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog, " \
	    create index file_entitiesi1 on file_entities ( \
	    filename, file_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog, " \
	    create index received_file_entitiesi1 on received_file_entities ( \
	    filename, file_id)", 0, 0, 0);
    err = sqlite3_exec(bkcatalog, " \
	    create index storagefilesi1 on storagefiles ( \
	    md5)", 0, 0, 0);
    return(0);
}

usage()
{
    printf("Usage:\n");
}

int submitfiles(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    char retention[128];
    int foundopts = 0;
    struct {
        unsigned char filename[100];    //   0 - 99
        char mode[8];                   // 100 - 107
        char nuid[8];                   // 108 - 115
        char ngid[8];                   // 116 - 123
        char size[12];                  // 124 - 135
        char modtime[12];               // 136 - 147
        char chksum[8];                 // 148 - 155
        char ftype[1];                  // 156
        unsigned char linktarget[100];  // 157 - 256
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
	char md5[33];
        int modtime;
	char *filename;
	char *linktarget;
	char *extdata;
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
    FILE *curfile;
    char *destdir = config.vault;
    char *destfilepath;
    char *destfilepathm;
    MD5_CTX cfmd5ctl; // current file's md5 sum
    unsigned char cfmd5[MD5_DIGEST_LENGTH];
    char cfmd5a[MD5_DIGEST_LENGTH * 2 + 10];
    char cfmd5d[MD5_DIGEST_LENGTH * 2 + 10];
    char cfmd5f[MD5_DIGEST_LENGTH * 2 + 10];
    int zin[2]; // input pipe for compression
    int zout[2]; // output pipe for compression
    pid_t cprocess;
    int bkid = 0;
    int fileid = 0;
    int x;
    char *sqlstmt = 0;
    char *sqlstmt2 = 0;
    sqlite3_stmt *sqlres;
    struct stat tmpfstat;
    sqlite3 *bkcatalog;
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
    char *tsparsedata = 0;

    

    fs.filename = 0;
    fs.linktarget = 0;
    fs.extdata = 0;
    while ((optc = getopt(argc, argv, "n:d:r:")) >= 0) 
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
	    default:
		usage();
		return(1);
	}
    if (foundopts != 7) {
	fprintf(stderr, "Didn't find all arguments\n");
        usage();
        return(1);
    }
    asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog");
    FD_SET(0, &input_s);
    select(1, &input_s, 0, 0, 0);
    x = sqlite3_open(bkcatalogp, &bkcatalog);
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
//    x = initdb(bkcatalog);

    x = sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select backupset_id from backupsets \
	    where name = '%s' and retention = '%s' and serial = '%s'",
	    bkname, retention, datestamp)), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
    }
    else
	fprintf(stderr, "bkid not found: %s\n", sqlstmt);
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

    tmpfiledir = config.vault;
    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    sparsedata = malloc(m_sparsedata * sizeof(*sparsedata));

    // Read TAR file from std input
    while (1) {
        // Read tar 512 byte header into tarhead structure
        count = fread(&tarhead, 1, 512, stdin);
        if (count < 512) {
                fprintf(stderr, "tar short read\n");
                return (1);
        }
        if (tarhead.filename[0] == 0) {	// End of TAR archive
// TODO cleanup code here

	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(" \
		insert or ignore into file_entities (ftype, permission, device_id, inode, \
		user_name, user_id, group_name, group_id, size, md5, datestamp, filename, extdata) \
		select ftype, permission, device_id, inode, user_name, user_id, group_name, \
		group_id, size, md5, datestamp, filename, extdata from received_file_entities_ldi \
		where backupset_id = '%d'", bkid)), 0, 0, 0);
	    sqlite3_free(sqlstmt);

	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(" \
		insert or ignore into backupset_detail (backupset_id, file_id) select backupset_id, \
		f.file_id from file_entities f join received_file_entities_ldi r \
		on f.ftype = r.ftype and f.permission = r.permission \
		and f.device_id = r.device_id and f.inode = r.inode \
		and f.user_name = r.user_name and f.user_id = r.user_id \
		and f.group_name = r.group_name and f.group_id = r.group_id \
		and f.size = r.size and f.md5 = r.md5 and f.datestamp = r.datestamp \
		and f.filename = r.filename and f.extdata = r.extdata \
		where backupset_id = '%d'", bkid)), 0, 0, 0);
	    sqlite3_free(sqlstmt);

	    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
            sqlite3_close(bkcatalog);
            return(0);
        }

        // A file type of "L" means a long (> 100 character) filename.  File name begins in next block.
        if (*(tarhead.ftype) == 'L') {
            bytestoread=strtoull(tarhead.size, 0, 8);
            blockpad = 512 - (bytestoread % 512);
            fs.filename = malloc(bytestoread + 1);
            count = fread(fs.filename, 1, bytestoread, stdin);
            if (count < bytestoread) {
                printf("tar short read\n");
                return(1);
            }
            count = fread(junk, 1, blockpad, stdin);
            if (count < blockpad) {
                printf("tar short read\n");
                return(1);
            }
            fs.filename[bytestoread] = 0;
            continue;
        }
        // A file type of "K" means a long (> 100 character) link target.
        if (*(tarhead.ftype) == 'K') {
            bytestoread=strtoull(tarhead.size, 0, 8);
            blockpad = 512 - (bytestoread % 512);
            fs.linktarget = malloc(bytestoread);
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
            continue;
        }
	// Process TAR header
        fs.filesize = 0;
        if ((unsigned char) tarhead.size[0] == 128)
            for (i = 0; i < 8; i++)
                fs.filesize += (( ((unsigned long long) ((unsigned char) (tarhead.size[11 - i]))) << (i * 8)));
        else
            fs.filesize=strtoull(tarhead.size, 0, 8);
	fs.ftype = *tarhead.ftype;
        fs.nuid=strtol(tarhead.nuid, 0, 8);
        fs.ngid=strtol(tarhead.ngid, 0, 8);
        fs.modtime=strtol(tarhead.modtime, 0, 8);
        fs.mode=strtol(tarhead.mode + 2, 0, 8);
        fullblocks = (fs.filesize / 512);
        partialblock = fs.filesize - (fullblocks * 512);

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
            if (partialblock > 0)
                blockpad = 512 - partialblock;
            else
                blockpad = 0;

	    // Set up temporary file to write out to.
            tmpfilepath = malloc(strlen(tmpfiledir) + 10);
            sprintf(tmpfilepath, "%s/tbXXXXXX", tmpfiledir);
            curtmpfile = mkstemp(tmpfilepath);
            if (curtmpfile == -1) {
                fprintf(stderr, "Error opening temp file %s\n", tmpfilepath);
                return(1);
            }

	    // Set up a pipe to run file through a compressor.
            pipe(zin);
            if ((cprocess = fork()) == 0) {
                close(zin[1]);
                dup2(zin[0], 0);
                dup2(curtmpfile, 1);
                execlp("lzop", "lzop", (char *) NULL);
                printf("Error\n");
                return(1);
            }
            close(zin[0]);
            curfile = fdopen(zin[1], "w");

            blockstoread = fullblocks + (partialblock > 0 ? 1 : 0);
            MD5_Init(&cfmd5ctl);
            for (i = 1; i <= blockstoread; i++) {
                count = fread(curblock, 1, 512, stdin);
                if (count < 512) {
                    printf("tar short read\n");
                    return(1);
                }

                if (i == blockstoread) {
                    if (partialblock > 0) {
                        fwrite(curblock, 1, partialblock, curfile);
                        MD5_Update(&cfmd5ctl, curblock, partialblock);
                        break;
                    }
                }
                fwrite(curblock, 512, 1, curfile);
                MD5_Update(&cfmd5ctl, curblock, 512);
            }

            fflush(curfile);
            fclose(curfile);
            waitpid(cprocess, NULL, 0);
            close(curtmpfile);
            MD5_Final(cfmd5, &cfmd5ctl);
            for (i = 0; i < MD5_DIGEST_LENGTH; i++)
                sprintf(cfmd5a + i * 2, "%2.2x", (unsigned int) cfmd5[i]);
            cfmd5a[i * 2] = 0;
            for (i = 0; i < 1; i++)
                sprintf(cfmd5d + i * 2, "%2.2x", (unsigned int) cfmd5[i]);
            cfmd5d[i * 2] = 0;
            for (i = 1; i < MD5_DIGEST_LENGTH; i++)
                sprintf(cfmd5f + (i - 1) * 2, "%2.2x", (unsigned int) cfmd5[i]);
            cfmd5f[(i - 1) * 2] = 0;
	    strcpy(fs.md5, cfmd5a);

            sprintf((destfilepath = malloc(strlen(destdir) + strlen(cfmd5a) + 7)), "%s/%s/%s.lzo", destdir, cfmd5d, cfmd5f);
            sprintf((destfilepathm = malloc(strlen(destdir) + 4)), "%s/%s", destdir, cfmd5d);

	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(" \
		insert or ignore into storagefiles (md5, volume, segment, location) \
		values ('%s', 0, 0, '%q/%q.lzo')", cfmd5a, cfmd5d, cfmd5f)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n", sqlerr);
		sqlite3_free(sqlerr);
	    }

            if (stat(destfilepath, &tmpfstat) == 0) {
                remove(tmpfilepath);
	    }
            else {
                if (stat(destfilepathm, &tmpfstat) == 0)
                    rename(tmpfilepath, destfilepath);
                else {
                    if (mkdir(destfilepathm, 0770) == 0)
                        rename(tmpfilepath, destfilepath);
                    else {
                        fprintf(stderr, "Error creating directory %s\n", destfilepath);
                        return(1);
                    }
                }
	    }
#ifdef notdef
            if (*(tarhead.ftype) == 'S') {
                fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\t%llu",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, s_realsize, cfmd5a, modtime, efilename, filesize);
                for (i = 0; i < n_sparsedata; i++)
                    fprintf(manifest,":%llu:%llu", sparsedata[i].offset, sparsedata[i].size);
                fprintf(manifest, "\n");
            }
            else
                fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\n",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, filesize, cfmd5a, modtime, efilename);

            fflush(manifest);
#endif

            if (*(tarhead.ftype) == 'S') {
		tsparsedata = 0;
		fs.extdata = 0;
		for (i = 0; i < n_sparsedata; i++) {
		    if (i == 0)
			asprintf(&tsparsedata, "%llu:%llu:%llu", fs.filesize, sparsedata[i].offset, sparsedata[i].size);
		    else
			asprintf(&tsparsedata, ":%llu:%llu", sparsedata[i].offset, sparsedata[i].size);
		    if (fs.extdata == 0) {
			fs.extdata = malloc(strlen(tsparsedata) + 1);
			fs.extdata[0] = 0;
		    }
		    else
			fs.extdata = realloc(fs.extdata, strlen(tsparsedata) + strlen(fs.extdata) + 1);
		    strcat(fs.extdata, tsparsedata);
		    free(tsparsedata);
		}
	    }

	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into received_file_entities \
		(backupset_id, ftype, permission, user_name, user_id, group_name, \
		group_id, size, md5, datestamp, filename, extdata) \
		values ('%d', '%c', '%4.4o', '%s', '%d', '%s', '%d', '%llu', '%s', '%d', '%q', '%s')",
		bkid, fs.ftype, fs.mode, fs.auid, fs.nuid, fs.agid, fs.ngid,
		fs.ftype == 'S' ? s_realsize : fs.filesize, fs.md5, fs.modtime, fs.filename, fs.extdata)), 0, 0, 0);
	    sqlite3_free(sqlstmt);

            free(tmpfilepath);
            free(destfilepath);
            free(destfilepathm);
        }

        // Hard link (type 1) or sym link (type 2)
	else if (*(tarhead.ftype) == '1' || *(tarhead.ftype) == '2' || *(tarhead.ftype) == '5') {

	    if (*(tarhead.ftype) == '5')
		if (fs.filename[strlen(fs.filename) - 1] == '/')
		    fs.filename[strlen(fs.filename) - 1] = 0;
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into received_file_entities \
		(backupset_id, ftype, permission, user_name, user_id, group_name, \
		group_id, size, md5, datestamp, filename, extdata) \
		values ('%d', '%c', '%4.4o', '%s', '%d', '%s', '%d', '%llu', '%q', '%d', '%q', '%q')",
		bkid, fs.ftype, fs.mode, fs.auid, fs.nuid, fs.agid, fs.ngid,
		fs.filesize, "0", fs.modtime, fs.filename, fs.linktarget)), 0, 0, 0);
	    sqlite3_free(sqlstmt);

	}
#ifdef notdef
	else if (*(tarhead.ftype) == '2') {
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into file_entities \
		(ftype, permission, device_id, inode, user_name, user_id, group_name, \
		group_id, size, md5, datestamp, filename, extdata) \
		values ('%c', '%4.4o', '%s', '%s', '%s', '%d', '%s', '%d', '%llu', '%s', '%d', '%q', '%q')",
		fs.ftype, fs.mode, fs.devid, fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid,
		fs.filesize, "0", fs.modtime, fs.filename, fs.linktarget)), 0, 0, 0);
	    sqlite3_free(sqlstmt);

	    sqlite3_prepare_v2(bkcatalog,
		(sqlstmt = sqlite3_mprintf("select file_id from file_entities \
		    where ftype = '%c' and permission = '%4.4o' and device_id = '%s' \
		    and inode = '%s' and user_name = '%s' and user_id = '%d' \
		    and group_name = '%s' and group_id = '%d' and size = '%llu' \
		    and md5 = '%s' and datestamp = '%d' and filename = '%q' \
		    and linktarget = '%q'", fs.ftype, fs.mode, fs.devid,
		    fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid, fs.filesize,
		    "0", fs.modtime, fs.filename, fs.linktarget)), -1, &sqlres, 0);
	    if (sqlite3_step(sqlres) == SQLITE_ROW) {
		fileid = sqlite3_column_int(sqlres, 0);
		sqlite3_exec(bkcatalog, (sqlstmt2 = sqlite3_mprintf(
		    "insert or ignore into backupset_detail \
		    (backupset_id, file_id) values ('%d', '%d')",
		    bkid, fileid)), 0, 0, 0);
		sqlite3_free(sqlstmt2);
	    }
	    sqlite3_finalize(sqlres);
	    sqlite3_free(sqlstmt);
	}
	else if (*(tarhead.ftype) == '5') {
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"insert or ignore into file_entities \
		(ftype, permission, device_id, inode, user_name, user_id, group_name, \
		group_id, size, md5, datestamp, filename) \
		values ('%c', '%4.4o', '%s', '%s', '%s', '%d', '%s', '%d', '%llu', '%s', '%d', '%q')",
		fs.ftype, fs.mode, fs.devid, fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid,
		fs.filesize, "0", fs.modtime, fs.filename)), 0, 0, 0);
	    sqlite3_free(sqlstmt);

	    sqlite3_prepare_v2(bkcatalog,
		(sqlstmt = sqlite3_mprintf("select file_id from file_entities \
		    where ftype = '%c' and permission = '%4.4o' and device_id = '%s' \
		    and inode = '%s' and user_name = '%s' and user_id = '%d' \
		    and group_name = '%s' and group_id = '%d' and size = '%llu' \
		    and md5 = '%s' and datestamp = '%d' and filename = '%q'",
		    fs.ftype, fs.mode, fs.devid, fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid,
		    fs.filesize, "0", fs.modtime, fs.filename)), -1, &sqlres, 0);
	    if (sqlite3_step(sqlres) == SQLITE_ROW) {
		fileid = sqlite3_column_int(sqlres, 0);
		sqlite3_exec(bkcatalog, (sqlstmt2 = sqlite3_mprintf(
		    "insert or ignore into backupset_detail \
		    (backupset_id, file_id) values ('%d', '%d')",
		    bkid, fileid)), 0, 0, 0);
		sqlite3_free(sqlstmt2);
	    }
	    sqlite3_finalize(sqlres);
	    sqlite3_free(sqlstmt);
	}
#endif

#ifdef notdef
        else if (*(tarhead.ftype) == '1' || *(tarhead.ftype) == '2') {
            fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\t%s\n",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, filesize, "0", modtime, efilename, elinktarget );
        }
        // Directory entry (type 5)
        else if (*(tarhead.ftype) == '5') {
            fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\n",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, filesize, "0", modtime, efilename);
        }
#endif
//	fprintf(stdout, "'%c', '%4.4o', '%s', '%s', '%s', '%d', '%s', '%d', '%llu', '%s', '%d', '%s'\n",
//		fs.ftype, fs.mode, fs.devid, fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid,
//		fs.filesize, fs.md5, fs.modtime, fs.filename);
	if (fs.filename != 0)
	    free(fs.filename);
	fs.filename = 0;
	if (fs.linktarget != 0)
	    free(fs.linktarget);
	fs.linktarget = 0;
	if (fs.extdata != 0)
	    free(fs.extdata);
	fs.extdata = 0;
    }

}

struct tarhead {
        unsigned char filename[100];
        char mode[8];
        char nuid[8];
        char ngid[8];
        char size[12];
        char modtime[12];
        char chksum[8];
        char ftype[1];
        unsigned char linktarget[100];
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
    struct speh speh;
    char bkname[128];
    char datestamp[128];
    char retention[128];

    char *srcdir = 0;
    char *manifestpath = 0;
    FILE *manifest;
    FILE *curfile;
    const unsigned char *md5;
    const unsigned char *filename = 0;
    const unsigned char *linktarget = 0;
    int optc;
    int foundopts = 0;
    int i, j;
    char *p;
    unsigned long tmpchksum;
    char *md5filepath;
    int zin[2];
    pid_t cprocess;
    int md5file;
    unsigned long long bytestoread;
    int count;
    char curblock[512];
    char *instr = 0;
    size_t instrlen = 0;

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

    struct {
        unsigned long long int offset;
        unsigned long long int size;
    } *sparsedata;
    unsigned long long int s_realsize;
    char s_isextended;
    int n_sparsedata;
    int n_esparsedata;
    int m_sparsedata = 20;
    char *ssparseinfo;
    long long int *sparseinfo;
    int nsi;
    int msi;
    int x;
    char *sqlstmt = 0;
    sqlite3_stmt *sqlres;
    int bkid;
    sqlite3 *bkcatalog;
    char *bkcatalogp;
    char *restore_filename = 0;
    char *filespec = 0;
    int filespeclen;
    char *sqlerr;

    lendian = (unsigned int) (((unsigned char *)(&lendian))[0]); // little endian test
    msi = 256;
    sparseinfo = malloc(msi * sizeof(*sparseinfo));

    while ((optc = getopt(argc, argv, "n:d:r:")) >= 0) {
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
	    default:
		usage();
		return(1);
	}
    }
    if (foundopts != 7) {
	fprintf(stderr, "Didn't find all arguments\n");
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


    asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog");
    x = sqlite3_open(bkcatalogp, &bkcatalog);
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
    x = initdb(bkcatalog);

    if (srcdir == 0)
	srcdir = config.vault;

    md5filepath = malloc(strlen(srcdir) + 39);

    x = sqlite3_prepare_v2(bkcatalog,
        (sqlstmt = sqlite3_mprintf("select backupset_id from backupsets \
            where name = '%q' and retention = '%q' and serial = '%q'",
            bkname, retention, datestamp)), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
    }
    else {
        fprintf(stderr, "bkid not found: %s\n", sqlstmt);
	return(1);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);


    // Zero out tar header
    for (i = 0; i < sizeof(tarhead); i++) {
	(((unsigned char *) (&tarhead)))[i] = 0;
    }

//  
    sqlite3_exec(bkcatalog, sqlstmt = " \
	create temporary table if not exists restore_file_entities ( \
    	    file_id       integer primary key, \
       	    ftype         char, \
	    permission    char, \
    	    device_id     char, \
       	    inode         char, \
	    user_name     char, \
	    user_id       integer, \
	    group_name    char, \
	    group_id      integer, \
	    size          integer, \
	    md5           char, \
	    datestamp     integer, \
	    filename      char, \
	    extdata       char default '', \
	constraint restore_file_entitiesc1 unique ( \
	    ftype, \
	    permission, \
	    device_id, \
	    inode, \
	    user_name, \
	    user_id, \
	    group_name, \
	    group_id, \
	    size, \
	    md5, \
	    datestamp, \
	    filename, \
	    extdata ))", 0, 0, 0);
	
    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(" \
	insert or ignore into restore_file_entities \
	(ftype, permission, device_id, inode, user_name, user_id, \
	group_name, group_id, size, md5, datestamp, filename, extdata) \
	select ftype, permission, device_id, inode, user_name, user_id, \
	group_name, group_id, size, md5, datestamp, filename, extdata \
	from file_entities f join backupset_detail d \
	on f.file_id = d.file_id where backupset_id = '%d'%s",
	bkid, filespec != 0 ?  filespec : ""), 0, 0, 0);

    sqlite3_exec(bkcatalog, sqlstmt = sqlite3_mprintf(" \
	create temporary view hardlink_file_entities \
	as select min(file_id) as file_id, ftype, permission, device_id, \
	inode, user_name, user_id, group_name, group_id, size, md5, datestamp, \
	filename, extdata from restore_file_entities where ftype = 0 group by ftype, \
	permission, device_id, inode, user_name, user_id, group_name, \
	group_id, size, md5, datestamp, extdata having count(*) > 1;"), 0, 0, 0);

    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf(" \
	select \
	case when b.file_id not null and a.file_id != b.file_id \
	then 1 else a.ftype end, \
	a.permission, a.device_id, a.inode, a.user_name, a.user_id, \
	a.group_name, a.group_id, a.size, a.md5, a.datestamp, a.filename, \
	case when b.file_id not null and a.file_id != b.file_id \
	then b.filename else a.extdata end \
	from restore_file_entities a left join hardlink_file_entities b \
	on a.ftype = b.ftype and a.permission = b.permission \
	and a.device_id = b.device_id and a.inode = b.inode \
	and a.user_name = b.user_name and a.user_id = b.user_id \
	and a.group_name = b.group_name and a.group_id = b.group_id \
	and a.size = b.size and a.md5 = b.md5 and a.datestamp = b.datestamp \
	and a.extdata = b.extdata")), 2000, &sqlres, 0);

    while (sqlite3_step(sqlres) == SQLITE_ROW) {
	t.ftype = *sqlite3_column_text(sqlres, 0);
	t.mode = strtol(sqlite3_column_text(sqlres, 1), 0, 8);
	strncpy(t.auid, sqlite3_column_text(sqlres, 4), 32); t.auid[32] = 0;
	t.nuid = sqlite3_column_int(sqlres, 5);
	strncpy(t.agid, sqlite3_column_text(sqlres, 6), 32); t.agid[32] = 0;
	t.ngid = sqlite3_column_int(sqlres, 7);
	t.filesize = sqlite3_column_int64(sqlres, 8);
	md5 = sqlite3_column_text(sqlres, 9);
	t.modtime = sqlite3_column_int(sqlres, 10);
	filename = sqlite3_column_text(sqlres, 11);
	linktarget = 0;
	if (t.ftype == '1' || t.ftype == '2') {
	    linktarget = sqlite3_column_text(sqlres, 12);
	    t.filesize = 0;
	}
	else if (t.ftype == 'S') {
	    ssparseinfo = malloc(strlen(sqlite3_column_text(sqlres, 12)));
	    strcpy(ssparseinfo, sqlite3_column_text(sqlres, 12));
	}

	if (linktarget != 0) {
    	    if (strlen(linktarget) > 100) {
    		for (i = 0; i < sizeof(longtarhead); i++)
    		    (((unsigned char *) (&longtarhead)))[i] = 0;
    		strcpy(longtarhead.filename, "././@LongLink");
    		*(longtarhead.ftype) = 'K';
    		strcpy(longtarhead.nuid, "0000000");
    		strcpy(longtarhead.ngid, "0000000");
    		strcpy(longtarhead.mode, "0000000");
    		sprintf(longtarhead.size, "%11.11o", strlen(linktarget));
    		strcpy(longtarhead.modtime, "00000000000");
    		strcpy(longtarhead.ustar, "ustar  ");
    		strcpy(longtarhead.auid, "root");
    		strcpy(longtarhead.agid, "root");
    		memcpy(longtarhead.chksum, "        ", 8);
    		for (tmpchksum = 0, p = (unsigned char *) (&longtarhead), i = 512;
    		    i != 0; --i, ++p)
    		    tmpchksum += 0xFF & *p;
    		sprintf(longtarhead.chksum, "%6o", tmpchksum);
    		fwrite(&longtarhead, 1, 512, stdout);
		tblocks++;
    		for (i = 0; i < strlen(linktarget); i += 512) {
    		    for (j = 0; j < 512; j++)
    			curblock[j] = 0;
    		    memcpy(curblock, linktarget + i, strlen(linktarget) - i >= 512 ? 512 :
    			(strlen(linktarget) - i));
		    fwrite(curblock, 1, 512, stdout);
		    tblocks++;
    		}
    	    }
	}
	if (strlen(filename) > 100) {
	    for (i = 0; i < sizeof(longtarhead); i++)
		(((unsigned char *) (&longtarhead)))[i] = 0;
	    strcpy(longtarhead.filename, "././@LongLink");
	    *(longtarhead.ftype) = 'L';
	    strcpy(longtarhead.nuid, "0000000");
	    strcpy(longtarhead.ngid, "0000000");
	    strcpy(longtarhead.mode, "0000000");
	    sprintf(longtarhead.size, "%11.11o", strlen(filename));
	    strcpy(longtarhead.modtime, "00000000000");
	    strcpy(longtarhead.ustar, "ustar  ");
	    strcpy(longtarhead.auid, "root");
	    strcpy(longtarhead.agid, "root");
	    memcpy(longtarhead.chksum, "        ", 8);
	    for (tmpchksum = 0, p = (unsigned char *) (&longtarhead), i = 512;
		i != 0; --i, ++p)
		tmpchksum += 0xFF & *p;
	    sprintf(longtarhead.chksum, "%6.6o", tmpchksum);
	    fwrite(&longtarhead, 1, 512, stdout);
	    tblocks++;
	    for (i = 0; i < strlen(filename); i += 512) {
		for (j = 0; j < 512; j++)
		    curblock[j] = 0;
		memcpy(curblock, filename + i, strlen(filename) - i >= 512 ? 512 :
		    (strlen(filename) - i));
		fwrite(curblock, 1, 512, stdout);
		tblocks++;
	    }
	}

	strncpy(tarhead.filename, filename, 100);
	if (linktarget != 0)
	    strncpy(tarhead.linktarget, linktarget, 100);

	sprintf(tarhead.ustar, "ustar  ");
	*(tarhead.ftype) = t.ftype;
	sprintf(tarhead.mode, "%7.7o", t.mode);
	strncpy(tarhead.auid, t.auid, 32);
	sprintf(tarhead.nuid, "%7.7o", t.nuid);
	strncpy(tarhead.agid, t.agid, 32);
	sprintf(tarhead.ngid, "%7.7o", t.ngid);
	sprintf(tarhead.modtime, "%11.11o", t.modtime);


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

	    if (sparseinfo[0] <= 99999999999LL)
		sprintf(tarhead.u.sph.realsize, "%11.11o", sparseinfo[0]);
	    else {
		tarhead.u.sph.realsize[0] = 0x80;
		for (i = 0; i < sizeof(sparseinfo[0]); i++)
		    if (lendian)
			tarhead.u.sph.realsize[11 - i] = ((char *) (&(sparseinfo[0])))[i];
		    else
			tarhead.u.sph.realsize[11 - sizeof(sparseinfo[0]) + i] = ((char *) (&(sparseinfo[0])))[i];
	    }
	    for (i = 1; i < nsi && i < 9; i++) {
		if (sparseinfo[i] <= 99999999999LL) {
		    sprintf(tarhead.u.sph.item[i - 1], "%11.11o", sparseinfo[i]);
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
	}

	if (t.filesize <= 99999999999LL)
	    sprintf(tarhead.size, "%11.11llo", t.filesize);
	else {
	    tarhead.size[0] = 0x80;
	    for (i = 0; i < sizeof(t.filesize); i++)
		if (lendian)
		    tarhead.size[11 - i] = ((char *) (&t.filesize))[i];
		else
		    tarhead.size[11 - sizeof(t.filesize)+ i] = ((char *) (&t.filesize))[i];
	}

	memcpy(tarhead.chksum, "        ", 8);
	for (tmpchksum = 0, p = (unsigned char *) (&tarhead), i = 512;
	    i != 0; --i, ++p)
	    tmpchksum += 0xFF & *p;
	sprintf(tarhead.chksum, "%6.6o", tmpchksum);
	sprintf(md5filepath, "%s/%c%c/%s.lzo", srcdir, md5[0], md5[1], md5 + 2);
	fwrite(&tarhead, 1, 512, stdout);
	tblocks++;
	if (tarhead.u.sph.isextended == 1) {
	    for (i = 0; i < sizeof(speh); i++)
		((unsigned char *) &speh)[i] = 0;
	    for (i = 9; i < nsi; i++) {
		if (sparseinfo[i] <= 99999999999LL)
		    sprintf(speh.item[(i - 9) % 42], "%11.11o", sparseinfo[i]);
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
	    pipe(zin);
	    if ((cprocess = fork()) == 0) {
		close(zin[0]);
		md5file = open(md5filepath, O_RDONLY);
		if (md5file == -1) {
		    fprintf(stderr, "Can not open %s\n", md5filepath);
		    exit(1);
		}
		dup2(zin[1], 1);
		dup2(md5file, 0);
		execlp("lzop", "lzop", "-d", (char *) NULL);
		fprintf(stderr, "Error\n");
		exit(1);
	    }
	    close(zin[1]);
	    curfile = fdopen(zin[0], "r");
	    bytestoread = t.filesize;
	    while (bytestoread > 512ull) {
		count = fread(curblock, 1, 512, curfile);
		if (count < 512) {
		    fprintf(stderr, "file short read\n");
		    exit(1);
		}
		fwrite(curblock, 1, 512, stdout);
		tblocks++;
		bytestoread -= 512;
	    }
	    if (bytestoread > 0) {
		for (i = 0; i < 512; i++)
		    curblock[i] = 0;
		count = fread(curblock, 1, 512, curfile);
		fwrite(curblock, 1, 512, stdout);
		tblocks++;
	    }
	    kill(cprocess, 9);
	    waitpid(cprocess, NULL, 0);
	    fclose(curfile);
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
}
int getconfig()
{
    char *configline = 0;
    size_t configlinesz;
    struct stat tmpfstat;
    char configpath[256];
    FILE *configfile;
    char configvar[256];
    char configvalue[256];

    config.vault = 0;
    config.meta = 0;
    snprintf(configpath, 256, "%s/.snebu.conf", getenv("HOME"));
    if (stat(configpath, &tmpfstat) != 0)
	snprintf(configpath, 256, "/etc/snebu.conf");
    if (stat(configpath, &tmpfstat) == 0) {
	configfile = fopen(configpath, "r");
	while (getline(&configline, &configlinesz, configfile) > 0) {
	    sscanf(configline, "%s = %s", configvar, configvalue);
	    if (strcmp(configvar, "vault") == 0)
		asprintf(&(config.vault), configvalue);
	    if (strcmp(configvar, "meta") == 0)
		asprintf(&(config.meta), configvalue);
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
    fprintf(stderr, "Busy %d\n", y);
    sleep(1);
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
    int bkid;
    int i;
    time_t bktime;
    char *bktimes;
    int rowcount;
    char *dbbkname;
    char oldbkname[128];
    time_t oldbktime;
    int err;

    while ((optc = getopt(argc, argv, "n:d:")) >= 0) {
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
	    default:
		usage();
		return(1);
	}
    }
    if (foundopts != 0 && foundopts != 1 && foundopts != 3) {
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
		strcat(filespec, " (filename glob ");
	    else
		strcat(filespec, " or filename glob ");
	    strcat(filespec, sqlite3_mprintf("'%q'", argv[i]));
	}
	strcat(filespec, ")");
    }
    asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog");
    sqlite3_open(bkcatalogp, &bkcatalog);
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);

    if (foundopts == 0) {

	if (filespec == 0) {
	    err = sqlite3_prepare_v2(bkcatalog,
		(sqlstmt = sqlite3_mprintf(" \
		select distinct name from backupsets")), -1, &sqlres, 0);
	    rowcount = 0;
	    while (sqlite3_step(sqlres) == SQLITE_ROW) {
		rowcount++;
		printf("%s\n", sqlite3_column_text(sqlres, 0));
	    }
	    rowcount == 0 && printf("No backups found %s %d\n", sqlstmt, err);
	    sqlite3_finalize(sqlres);
	    sqlite3_free(sqlstmt);
	}
	else {

	    sqlite3_prepare_v2(bkcatalog,
		(sqlstmt = sqlite3_mprintf(" \
		select distinct b.name, b.serial, f.filename from backupsets b \
		join backupset_detail d on b.backupset_id = d.backupset_id \
		join file_entities f on d.file_id = f.file_id where \
		%s", filespec )), -1, &sqlres, 0);
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
		    printf("    %-10d %s:\n", bktime, bktimes);
		printf("        %s\n", sqlite3_column_text(sqlres, 2));
		strncpy(oldbkname, dbbkname, 127);
		oldbkname[127] = 0;
		oldbktime = bktime;
	    }
	    rowcount == 0 && printf("No backups found for %s\n", sqlstmt);
	    sqlite3_finalize(sqlres);
	    sqlite3_free(sqlstmt);
	}

    }
    else if (foundopts == 1) {
	sqlite3_prepare_v2(bkcatalog,
    	    (sqlstmt = sqlite3_mprintf(" \
    	    select distinct retention, serial from backupsets \
	    where name = '%q'", bkname)),
	    -1, &sqlres, 0);
	rowcount = 0;
	printf("%s\n", bkname);
	while (sqlite3_step(sqlres) == SQLITE_ROW) {
	    rowcount++;
	    bktime = sqlite3_column_int(sqlres, 1),
	    bktimes = ctime(&bktime);
	    bktimes[strlen(bktimes) - 1] = 0;
	    printf("    %d / %s / %s\n",
		bktime, sqlite3_column_text(sqlres, 0), bktimes);

	}
	rowcount == 0 && printf("No backups found\n");
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
    }
    else if (foundopts == 3) {
	sqlite3_prepare_v2(bkcatalog,
	    (sqlstmt = sqlite3_mprintf("select distinct backupset_id \
		from backupsets  where name = '%q' and serial = '%q'",
		bkname, datestamp)), -1, &sqlres, 0);
	if ((sqlite3_step(sqlres)) == SQLITE_ROW) {
	    bkid = sqlite3_column_int(sqlres, 0);
	}
	else {
	    printf("Backup not found for %s\n", sqlstmt);
	    exit(1);
	}
	sqlite3_prepare_v2(bkcatalog,
	    (sqlstmt = sqlite3_mprintf(" \
	    select filename from file_entities f \
	    join backupset_detail d on f.file_id = d.file_id \
	    where backupset_id = '%d'", bkid)),
	    -1, &sqlres, 0);
	rowcount = 0;
	bktime = (time_t) strtoll(datestamp, 0, 10);
	bktimes = ctime(&bktime);
	bktimes[strlen(bktimes) - 1] = 0;
	printf("%s %s\n", bkname, bktimes);
	while (sqlite3_step(sqlres) == SQLITE_ROW) {
	    rowcount++;
	    bktime = sqlite3_column_int(sqlres, 1),
	    bktimes = ctime(&bktime);
	    bktimes[strlen(bktimes) - 1] = 0;
	    printf("%s\n", sqlite3_column_text(sqlres, 0));
	}
	rowcount == 0 && printf("No files found for %s\n", sqlstmt);
	sqlite3_finalize(sqlres);
	sqlite3_free(sqlstmt);
    }
}

char *stresc(char *src, unsigned char **target)
{
    int i;
    int j;
    int e = 0;

    for (i = 0; i < strlen(src); i++)
	if (src[i] <= 32 || src[i] >= 127 || src[i] == 92)
	    e++;
    *target = realloc(*target, strlen(src) + e * 4 + 1);
    (*target)[0] = 0;
    i = 0;
    while (i < strlen(src)) {
	for (j = i; i < strlen(src) && src[i] > 32 &&
	    src[i] < 127 && src[i] != 92; i++)
	    ;
	strncat(*target, src + j, i - j);
	if (i < strlen(src)) {
	    sprintf((*target) + strlen(*target), "\\%3.3o",
		(unsigned char) src[i]);
	    i++;
	}
    }
    return(*target);
}
char *strunesc(char *src, unsigned char **target)
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
    int fileid;
    int i;
    char catalogpath[512];
    FILE *catalog;
    char *instr = 0;
    size_t instrlen = 0;
    unsigned char *filename = 0;
    unsigned char *efilename = 0;
    unsigned char *linktarget = 0;
    unsigned char *elinktarget = 0;
    char md5[33];
    struct {
        char ftype[2];
        int mode;
	char devid[33];
	char inode[33];
        char auid[33];
        char agid[33];
        int nuid;
        int ngid;
        int modtime;
        unsigned long long int filesize;
    } t;
    int count;



    while ((optc = getopt(argc, argv, "n:d:r:f:")) >= 0) {
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
    asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog");
    sqlite3_open(bkcatalogp, &bkcatalog);
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
    sqlite3_exec(bkcatalog, "PRAGMA temp_store = 2", 0, 0, 0);
// TODO These two should be set via command line options
    sqlite3_exec(bkcatalog, "PRAGMA synchronous = OFF", 0, 0, 0);
    sqlite3_exec(bkcatalog, "PRAGMA journal_mode = MEMORY", 0, 0, 0);
    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);
    initdb(bkcatalog);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupsets (name, retention, serial) \
	values ('%s', '%s', '%s')", bkname, retention, datestamp)), 0, 0, 0);
    sqlite3_free(sqlstmt);
    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select backupset_id from backupsets \
	    where name = '%s' and retention = '%s' and serial = '%s'",
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
    sqlite3_exec(bkcatalog, " \
	create temporary table if not exists inbound_file_entities ( \
       	    backupset_id     integer, \
       	    ftype         char, \
	    permission    char, \
    	    device_id     char, \
       	    inode         char, \
	    user_name     char, \
	    user_id       integer, \
	    group_name    char, \
	    group_id      integer, \
	    size          integer, \
	    md5           char, \
	    datestamp     integer, \
	    filename      char, \
	    extdata       char default '', \
	constraint inbound_file_entitiesc1 unique ( \
	    backupset_id, \
	    ftype, \
	    permission, \
	    device_id, \
	    inode, \
	    user_name, \
	    user_id, \
	    group_name, \
	    group_id, \
	    size, \
	    md5, \
	    datestamp, \
	    filename, \
	    extdata ))", 0, 0, 0);
    sqlite3_exec(bkcatalog, " \
	    create index inbound_file_entitiesi1 on inbound_file_entities ( \
	    file_id, permission, device_id, inode, user_name, user_id, group_name, group_id, size, md5, datestamp, filename, extdata)", 0, 0, 0);
    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    sqlstmt = sqlite3_mprintf(
	"insert or ignore into inbound_file_entities \
	(backupset_id, ftype, permission, device_id, inode, user_name, user_id, \
	group_name, group_id, size, md5, datestamp, filename, extdata) \
	values (@bkid, @ftype, @mode, @devid, @inode, @auid, @nuid, @agid, \
	@ngid, @filesize, @md5, @modtime, @filename, @linktarget)");

    sqlite3_prepare_v2(bkcatalog, sqlstmt, -1, &sqlres, 0);

    t.ftype[1] = 0;
    count = 0;
    while (getline(&instr, &instrlen, catalog) > 0) {
	count++;
	char *fptr;
	char *endfptr;
	char *lptr;
	char *endlptr;
	int fnstart;
	char *ascmode;
	sscanf(instr, "%c\t%o\t%32s\t%32s\t%32s\t%d\t%32s\t%d\t%Ld\t%32s\t%d\t%n",
	    t.ftype, &t.mode, t.devid, t.inode, t.auid, &t.nuid, t.agid, &t.ngid,
	    &(t.filesize), md5, &t.modtime, &fnstart);
	fptr = instr + fnstart;
	endfptr = strstr(fptr, "\t");
	efilename = realloc(efilename, endfptr - fptr + 1);
	strncpy(efilename, fptr, endfptr - fptr);
	efilename[endfptr - fptr] = 0;
	    strunesc(efilename, &filename);

	if (*(t.ftype) == '2' || *(t.ftype) == '1' || *(t.ftype) == 'S') {
	    lptr = endfptr + 1;
	    endlptr = strstr(lptr, "\n");
	    elinktarget = realloc(elinktarget, endlptr - lptr + 1);
	    strncpy(elinktarget, lptr, endlptr - lptr);
	    elinktarget[endlptr - lptr] = 0;
	    strunesc(elinktarget, &linktarget);
	}
	fflush(stderr);

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
	sqlite3_bind_text(sqlres, 11, md5, -1, SQLITE_STATIC);
	sqlite3_bind_int(sqlres, 12, t.modtime);
	sqlite3_bind_text(sqlres, 13, filename, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 14, linktarget, -1, SQLITE_STATIC);
	fflush(stderr);
	sqlite3_step(sqlres);
	fflush(stderr);
//	sqlite3_clear_bindings(sqlres);
	sqlite3_reset(sqlres);
    }
    fprintf(stderr, "Inserted %d records\n", count);
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into file_entities \
	(ftype, permission, device_id, inode, user_name, user_id, \
	group_name, group_id, size, md5, datestamp, filename, extdata) \
	select ftype, permission, device_id, inode, user_name, user_id, \
	group_name, group_id, size, md5, datestamp, filename, extdata \
	from inbound_file_entities")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    fprintf(stderr, "Copied records to file_entities\n");

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupset_detail \
	(backupset_id, file_id) \
	select i.backupset_id, f.file_id from file_entities f \
	join inbound_file_entities i \
	on i.ftype = f.ftype and i.permission = f.permission \
	and i.device_id = f.device_id and i.inode = f.inode \
	and i.user_name = f.user_name and i.user_id = f.user_id \
	and i.group_name = f.group_name and i.group_id = f.group_id \
	and i.size = f.size and i.datestamp = f.datestamp \
	and i.filename = f.filename and i.extdata = f.extdata \
	where i.backupset_id = '%d'", bkid)), 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "%s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    fprintf(stderr, "Created backupset_detail entries\n");

    sqlite3_exec(bkcatalog, "END", 0, 0, 0);

}

int expire(int argc, char **argv)
{
    int optc;
    char retention[128];
    char bkname[128];
    int age;
    int min = 3;
    int foundopts = 0;
    sqlite3 *bkcatalog;
    sqlite3_stmt *sqlres;
    char *bkcatalogp;
    char *sqlstmt = 0;
    char *sqlerr;
    int i;
    char catalogpath[512];
    time_t cutoffdate;
    bkname[0] = 0;

    while ((optc = getopt(argc, argv, "r:n:a:k:")) >= 0) {
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
	    default:
		usage();
		return(1);
	}
    }
    if ((foundopts & 5) != 5 && (foundopts & 7) != 7) {
        usage();
        return(1);
    }
    asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog");
    sqlite3_open(bkcatalogp, &bkcatalog);
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);

    cutoffdate = time(0) - (age * 60 * 60 * 24);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf( " \
	delete from needed_file_entities where backupset_id in ( \
	select e.backupset_id from backupsets as e \
	left join ( \
	  select c.backupset_id, d.ranknum \
	  from backupsets as c \
	    inner join ( \
	      select a.backupset_id, count(*) as ranknum \
	      from backupsets as a \
		inner join backupsets as b on (a.name = b.name) and (a.serial <= b.serial) \
		where a.retention = '%q' and b.retention = '%q' \
	      group by a.backupset_id \
	      having ranknum <= 3 \
	    ) as d on (c.backupset_id = d.backupset_id) \
	  where c.retention = '%q' \
	  order by c.name, d.ranknum \
	) as f on e.backupset_id = f.backupset_id \
	where f.backupset_id is null and e.retention = '%q' and e.serial < '%d'%s%Q \
	)", retention, retention, retention, retention, cutoffdate,
	strlen(bkname) > 0 ? " and e.name = " : "",
	strlen(bkname) > 0 ? bkname : "")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf( " \
	delete from backupset_detail where backupset_id in ( \
	select e.backupset_id from backupsets as e \
	left join ( \
	  select c.backupset_id, d.ranknum \
	  from backupsets as c \
	    inner join ( \
	      select a.backupset_id, count(*) as ranknum \
	      from backupsets as a \
		inner join backupsets as b on (a.name = b.name) and (a.serial <= b.serial) \
		where a.retention = '%q' and b.retention = '%q' \
	      group by a.backupset_id \
	      having ranknum <= 3 \
	    ) as d on (c.backupset_id = d.backupset_id) \
	  where c.retention = '%q' \
	  order by c.name, d.ranknum \
	) as f on e.backupset_id = f.backupset_id \
	where f.backupset_id is null and e.retention = '%q' and e.serial < '%d'%s%Q\
	)", retention, retention, retention, retention, cutoffdate,
	strlen(bkname) > 0 ? " and e.name = " : "",
	strlen(bkname) > 0 ? bkname : "")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf( " \
	delete from backupsets where backupset_id in ( \
	select e.backupset_id from backupsets as e \
	left join ( \
	  select c.backupset_id, d.ranknum \
	  from backupsets as c \
	    inner join ( \
	      select a.backupset_id, count(*) as ranknum \
	      from backupsets as a \
		inner join backupsets as b on (a.name = b.name) and (a.serial <= b.serial) \
		where a.retention = '%q' and b.retention = '%q' \
	      group by a.backupset_id \
	      having ranknum <= 3 \
	    ) as d on (c.backupset_id = d.backupset_id) \
	  where c.retention = '%q' \
	  order by c.name, d.ranknum \
	) as f on e.backupset_id = f.backupset_id \
	where f.backupset_id is null and e.retention = '%q' and e.serial < '%d'%s%Q\
	)", retention, retention, retention, retention, cutoffdate,
	strlen(bkname) > 0 ? " and e.name = " : "",
	strlen(bkname) > 0 ? bkname : "")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
}
