/* Copyright 2009 - 2021 Derek Pressnall
 *
 * This file is part of Snebu, the Simple Network Encrypting Backup Utility
 *
 * Snebu is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 3
 * as published by the Free Software Foundation.
 *
 * Snebu is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Snebu.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include "tarlib.h"

extern struct {
    char *vault;
    char *meta;
} config;

extern sqlite3 *bkcatalog;

extern char *SHN;

int newbackup(int argc, char **argv);
int help(char *topic);
void usage();
int logaction(sqlite3 *bkcatalog, int backupset_id, int action, char *message);
char *stresc(char *src, char **target);
char *strescb(char *src, char **target, int len);
char *strunesc(char *src, char **target);
int checkperm(sqlite3 *bkcatalog, char *action, char *backupname);
int flush_inbound_files(sqlite3 *bkcatalog, int bkid, int force_full_backup, int output_terminator);

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
	char sha1[EVP_MAX_MD_SIZE * 2 + 1];
        int cmodtime;
        int modtime;
	char *filename;
	char *linktarget;
    } fs;
    int x;
    char *sqlstmt = 0;
    sqlite3_stmt *sqlres;
    int bkid = 0;
    char *sqlerr;
    char *(*graft)[2] = 0;
    int numgrafts = 0;
    int maxgrafts = 0;
    int input_terminator = 0;
    int output_terminator = 0;
    int force_full_backup = 0;
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
    int filecount = 0;


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
			return(1);
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
		return(1);
	    }
	}
    if ((foundopts & 7) != 7) {
	fprintf(stderr, "Didn't find all arguments\n");
        usage();
        return (1);
    }

    if (checkperm(bkcatalog, "backup", bkname)) {
        sqlite3_close(bkcatalog);
        exit(1);
    }
/*
    sqlite3_exec(bkcatalog,
        "create temporary table if not exists temp_needed_file_entities "
        "as select * from needed_file_entities where 0", 0, 0, &sqlerr);
    if (sqlerr != 0) {
        fprintf(stderr, "%s %s\n", sqlerr, sqlstmt);
        sqlite3_free(sqlerr);
    }
*/

    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
    x = sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert or ignore into backupsets (name, retention, serial)  "
	"values ('%q', '%q', '%q')", bkname, retention, datestamp)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n", sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    else {
	sqlite3_free(sqlstmt);
    }
    x = sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select backupset_id, retention from backupsets  "
	    "where name = '%q' and serial = '%q'",
	    bkname, datestamp)), -1, &sqlres, 0);
    if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
        bkid = sqlite3_column_int(sqlres, 0);
	if (strcmp((char *) sqlite3_column_text(sqlres, 1), retention) != 0) {
	    fprintf(stderr, "A backup already exists for %s/%s, but with retention schedule %s\n", bkname, datestamp, (char *) sqlite3_column_text(sqlres, 1));
	    return(1);
	}
    }
    else {
	fprintf(stderr, "newbackup: failed to create backup id\n");
        logaction(bkcatalog, bkid, 2, "failed to create backup id");
	return(1);
    }
    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);

    logaction(bkcatalog, bkid, 0, "New backup");
    sqlite3_exec(bkcatalog,
        "create temporary table if not exists inbound_file_entities (  \n"
//      "create table if not exists inbound_file_entities (  \n"
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
        "    hash           char,  \n"
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
        "    hash,  \n"
        "    cdatestamp,  \n"
        "    datestamp,  \n"
        "    filename,  \n"
        "    extdata, \n"
        "    infilename))", 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "%s\n\n\n",sqlerr);
	sqlite3_free(sqlerr);
    }   

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
	"group_name, group_id, size, %s hash, cdatestamp, datestamp, "
	"filename, extdata from thishost_file_ids t join file_entities f "
	"on t.file_id = f.file_id", SHN)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);


    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create index if not exists thishost_file_details_i1 on thishost_file_details (hash)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create index if not exists thishost_file_details_i2 on thishost_file_details (filename)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);


    if (verbose >= 1)
	fprintf(stderr, "Gathering full snapshot file manifest\n");

    time_t curtime = time(NULL);

    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf(
            "insert or ignore into inbound_file_entities "
            "(backupset_id, ftype, permission, device_id, inode, user_name, user_id, group_name,  "
            "group_id, size, hash, cdatestamp, datestamp, filename, extdata, infilename)  "
	    "values (@bkid, @ftype, @mode, @devid, @inode, @auid, @nuid, @agid, @ngid, @filesize, @hash, @cmodtime, @modtime, @pathsub, @linktarget, @filename)")),
	    -1, &sqlres, 0);

        
    char *tmppathsub = NULL;
    int fib1 = 0;
    int fib2 = 1;
    int fib3 = 1;

    time_t starttime = time(NULL);
    time_t laststattime = time(NULL);
    while (getdelim(&filespecs, &filespeclen, input_terminator, stdin) > 0) {
	int pathskip = 0;
	char pathsub[4097];
	char tmpmodestr[32];
	parse(filespecs, &filespecsl, '\t');
	if (filecount < 1) {
	    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
	    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);
	}
	filecount++;

	fs.ftype = *(filespecsl[0]);
	fs.mode = (int) strtol(filespecsl[1], NULL, 8);
	strncpy(fs.devid, filespecsl[2], 32);
	strncpy(fs.inode, filespecsl[3], 32);
	strncpy(fs.auid, filespecsl[4], 32);
	fs.nuid = atoi(filespecsl[5]);
	strncpy(fs.agid, filespecsl[6], 32);
	fs.ngid = atoi(filespecsl[7]);
	fs.filesize = strtoull(filespecsl[8], NULL, 10);
	strncpy(fs.sha1, filespecsl[9], EVP_MAX_MD_SIZE * 2);
	fs.sha1[EVP_MAX_MD_SIZE * 2] = '\0';
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
	sqlite3_bind_int(sqlres, 1, bkid);
	sqlite3_bind_text(sqlres, 2, &fs.ftype, 1, SQLITE_STATIC);
	sprintf(tmpmodestr, "%4.4o", fs.mode);
	sqlite3_bind_text(sqlres, 3, tmpmodestr, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 4, fs.devid, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 5, fs.inode, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 6, fs.auid, -1, SQLITE_STATIC);
	sqlite3_bind_int(sqlres, 7, fs.nuid);
	sqlite3_bind_text(sqlres, 8, fs.agid, -1, SQLITE_STATIC);
	sqlite3_bind_int(sqlres, 9, fs.ngid);
	sqlite3_bind_int64(sqlres, 10, fs.filesize);
	sqlite3_bind_text(sqlres, 11, fs.sha1, -1, SQLITE_STATIC);
	sqlite3_bind_int(sqlres, 12, fs.cmodtime);
	sqlite3_bind_int(sqlres, 13, fs.modtime);
	strncpya0(&tmppathsub, pathsub, 0);
	strcata(&tmppathsub, fs.filename + pathskip);
	sqlite3_bind_text(sqlres, 14, tmppathsub, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 15, fs.linktarget, -1, SQLITE_STATIC);
	sqlite3_bind_text(sqlres, 16, fs.filename, -1, SQLITE_STATIC);

	sqlite3_step(sqlres);
	sqlite3_reset(sqlres);
#if 0
        sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
            "insert or ignore into inbound_file_entities "
            "(backupset_id, ftype, permission, device_id, inode, user_name, user_id, group_name,  "
            "group_id, size, hash, cdatestamp, datestamp, filename, extdata, infilename)  "
            "values ('%d', '%c', '%4.4o', '%q', '%q', '%q', '%d', '%q', '%d', '%llu', '%q', '%d', '%d', '%q%q', '%q', '%q')",
            bkid, fs.ftype, fs.mode, fs.devid, fs.inode, fs.auid, fs.nuid, fs.agid, fs.ngid,
            fs.filesize, fs.sha1, fs.cmodtime, fs.modtime, pathsub, fs.filename + pathskip, fs.linktarget, fs.filename)), 0, 0, &sqlerr);
        if (sqlerr != 0) {
            fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
            sqlite3_free(sqlerr);
        }
        sqlite3_free(sqlstmt);
#endif
        if (verbose > 0) {
	    if ((curtime = time(NULL)) > laststattime + 2) {
		fprintf(stderr, " Processed %d files              \r", filecount);
		laststattime = curtime;
	    }
	}
	if ((curtime = time(NULL)) > starttime + fib3) {
	    fib1 = fib2;
	    fib2 = fib3;
	    fib3 = fib1 + fib2;

	    if (verbose > 0) {
		fprintf(stderr, "*\r");
	    }
	    flush_inbound_files(bkcatalog, bkid, force_full_backup, output_terminator);
	}
    }
    sqlite3_finalize(sqlres);
    dfree(filespecsl);
    if (filecount == 0) {
	fprintf(stderr, "Empty manifest submitted, aborting backup\n");
        sqlite3_exec(bkcatalog, "ROLLBACK", 0, 0, 0);
        sqlite3_close(bkcatalog);
	exit(1);
    }
    if (verbose > 0) {
	fprintf(stderr, "*\r");
	flush_inbound_files(bkcatalog, bkid, force_full_backup, output_terminator);
	fprintf(stderr, " Processed %d files              \n", filecount);
    }
    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
    logaction(bkcatalog, bkid, 3, "Finished generating incremental manifest");

    return(0);
}
int flush_inbound_files(sqlite3 *bkcatalog, int bkid, int force_full_backup, int output_terminator)
{
    static int first_flush = 0;
    char *escfname = 0;
    sqlite3_stmt *sqlres;
    char *sqlstmt = 0;
    char *sqlerr;

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

    if (force_full_backup == 1) {
	if (first_flush == 0) {
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"delete from needed_file_entities where backupset_id = '%d' ",
		bkid)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	    first_flush = 1;
	}
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "insert or ignore into needed_file_entities  "
	    "(backupset_id, device_id, inode, filename, infilename, size, cdatestamp)  "
	    "select %d, device_id, inode, filename, infilename, size, cdatestamp from inbound_file_entities", bkid)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
    }
    else {
	if (first_flush == 0) {
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"delete from needed_file_entities where backupset_id = '%d' ",
		bkid)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	    first_flush = 1;
	}
        sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from inbound_file_entities "
	    "where exists (select * from needed_file_entities "
	    "where needed_file_entities.filename = inbound_file_entities.filename "
	    "and needed_file_entities.backupset_id = %d)" , bkid)),0, 0, &sqlerr);
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
            "i.ftype = case when f.ftype = 'S' or f.ftype = 'E' then '0' else f.ftype end  "
            "and i.permission = f.permission  "
            "and i.device_id = f.device_id and i.inode = f.inode  "
            "and i.user_name = f.user_name and i.user_id = f.user_id  "
            "and i.group_name = f.group_name and i.group_id = f.group_id  "
            "and i.size = f.size and i.cdatestamp = f.cdatestamp and i.datestamp = f.datestamp  "
            "and i.filename = f.filename and ((i.ftype = '0' and (f.ftype = 'S' or f.ftype = 'E'))  "
            "or i.extdata = f.extdata)  "
            "where f.file_id is null ",
            bkid)), 0, 0, &sqlerr);
        if (sqlerr != 0) {
            fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
            sqlite3_free(sqlerr);
        }   
        sqlite3_free(sqlstmt);

        sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
            "insert or ignore into backupset_detail  "
            "(backupset_id, file_id)  "
            "select %d, f.file_id from thishost_file_details f  "
            "join inbound_file_entities i  "
            "on i.ftype = case when f.ftype = 'S' or f.ftype = 'E' then '0' else f.ftype end  "
            "and i.permission = f.permission  "
            "and i.device_id = f.device_id and i.inode = f.inode  "
            "and i.user_name = f.user_name and i.user_id = f.user_id  "
            "and i.group_name = f.group_name and i.group_id = f.group_id  "
            "and i.size = f.size and i.cdatestamp = f.cdatestamp and i.datestamp = f.datestamp  "
            "and i.filename = f.filename and ((i.ftype = '0'  and (f.ftype = 'S' or f.ftype = 'E'))  "
            "or i.extdata = f.extdata)", bkid)), 0, 0, &sqlerr);
        if (sqlerr != 0) {
            fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
            sqlite3_free(sqlerr);
        }
        sqlite3_free(sqlstmt);
    }
    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
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
    fflush(stdout);

    sqlite3_finalize(sqlres);
    sqlite3_free(sqlstmt);


    sqlite3_exec(bkcatalog, "BEGIN", 0, 0, 0);

    sqlite3_exec(bkcatalog,
    "drop index inbound_file_entitiesi1", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n\n\n",sqlerr);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog,
    "drop index inbound_file_entitiesi2", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n\n\n",sqlerr);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from inbound_file_entities"
	)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    return(0);
}
