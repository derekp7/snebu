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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sqlite3.h>
#include <errno.h>

#include "tarlib.h"

int expire(int argc, char **argv);
int purge(int argc, char **argv);
int help(char *topic);
void usage();
int checkperm(sqlite3 *bkcatalog, char *action, char *backupname);

extern sqlite3 *bkcatalog;
extern struct {
    char *vault;
    char *meta;
    int hash;
} config;
extern char *SHN;

int expire(int argc, char **argv)
{
    int optc;
    char retention[128];
    char bkname[128];
    char datestamp[128];
    int age = 0;
    int bkid;
    int min = 3;
    int foundopts = 0;
    sqlite3_stmt *sqlres;
    char *sqlstmt = NULL;
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

    *datestamp = *bkname = *retention = '\0';
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

    if (checkperm(bkcatalog, "expire", bkname)) {
	sqlite3_close(bkcatalog);
	return(1);
    }
//    sqlite3_busy_handler(bkcatalog, &sqlbusy, 0);

    cutoffdate = time(0) - (age * 60 * 60 * 24);

    if (*datestamp != 0) {
	int sqlite_result;
	sqlite3_prepare_v2(bkcatalog,
	    (sqlstmt = sqlite3_mprintf("select backupset_id from backupsets  "
		"where name = '%q' and serial = '%q'",
		bkname, datestamp)), -1, &sqlres, 0);

	if ((sqlite_result = (sqlite3_step(sqlres))) == SQLITE_ROW) {
	    bkid = sqlite3_column_int(sqlres, 0);
	}
        else {
	    fprintf(stderr, "Can't find specified backupset %s %s, result: %d\n", bkname, datestamp, sqlite_result);
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
	fprintf(stderr, "Deleting %d from log\n", bkid);
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from log where backupset_id = %d ",
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
    sqlite3_stmt *sqlres;
    char *sqlstmt = NULL;
    char *sqlerr;
    time_t purgedate;
    char *destdir = config.vault;
    struct stat tmpfstat;
    const char *sha1;
    char *destfilepath = NULL;
    char *destfilepathd = NULL;
    int verbose = 0;

    int optc;
    int longoptidx;

    struct option longopts[] = {
	{ "verbose", no_argument, NULL, 'v' },
	{ "quiet", no_argument, NULL, 'q' },
	{ NULL, no_argument, NULL, 0 }
    };

    if (isatty(2))
	verbose = 1;
    while ((optc = getopt_long(argc, argv, "nv", longopts, &longoptidx)) >= 0)
        switch (optc) {
            case 'v':
                verbose = 1;
                break;
            case 'q':
                verbose = 0;
                break;
            default:
		usage();
                exit(1);
        }

    if (checkperm(bkcatalog, "purge", NULL)) {
	sqlite3_close(bkcatalog);
	return(1);
    }

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

    if (verbose > 0)
	fprintf(stderr, "Creating temporary tables\n");
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create temporary table if not exists purgelist1 ( \n"
	"    file_id	integer primary key, "
	"    hash	char)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"create temporary table if not exists diskfiles_purged ( \n"
	"    hash	char)")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert into purgelist1 (file_id, hash) "
	"select f.file_id, f.%s from file_entities f "
	"left join backupset_detail d "
	"on f.file_id = d.file_id "
	"where d.file_id is null", SHN)),
    0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    if (verbose > 0)
	fprintf(stderr, "Purging from file_entities\n");
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from file_entities where file_id in ( "
	"select file_id from purgelist1) ")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    if (verbose > 0)
	fprintf(stderr, "Creating final purge list\n");
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"insert into purgelist (datestamp, %s) "
	"select %d, d.%s from diskfiles d "
	"left join file_entities f "
	"on d.%s = f.%s "
	"where f.%s is null ", SHN, purgedate, SHN, SHN, SHN, SHN)), 0, 0, &sqlerr);

    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }

    if (verbose > 0)
	fprintf(stderr, "Removing files\n");
    sqlite3_prepare_v2(bkcatalog,
	(sqlstmt = sqlite3_mprintf("select %s, datestamp from purgelist", SHN)),
	-1, &sqlres, 0);
    int rows_purged = 0;
    while (sqlite3_step(sqlres) == SQLITE_ROW) {

	sha1 = (char *) sqlite3_column_text(sqlres, 0);
	strncpya0(&destfilepath, destdir, 0);
	strcata(&destfilepath, "/");
	strncata0(&destfilepath, sha1, 2);
	strcata(&destfilepath, "/");
	strcata(&destfilepath, sha1 + 2);
	if (strlen(sha1) > 40)
	    strcata(&destfilepath, ".enc");
	else
	    strcata(&destfilepath, ".lzo");

	strncpya0(&destfilepathd, destfilepath, 0);
	strcata(&destfilepathd, ".d");
//	fprintf(stderr, "Renaming %s to %s\n", destfilepath, destfilepathd);

	if (rename(destfilepath, destfilepathd) == 0) {
	    if (stat(destfilepathd, &tmpfstat) == 0 && tmpfstat.st_mtime < sqlite3_column_int(sqlres, 1)) {
//		fprintf(stderr, "Removing %s\n", destfilepath);
		remove(destfilepathd);
		sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		    "insert into diskfiles_purged (hash) values ('%s')", sha1)), 0, 0, &sqlerr);
		if (sqlerr != 0) {
		    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
		    sqlite3_free(sqlerr);
		}
		sqlite3_free(sqlstmt);
		rows_purged++;
	    }
	    else {
		fprintf(stderr, "    Restoring %s\n", destfilepath);
		rename(destfilepathd, destfilepath);
		sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		    "delete from purgelist where %s = '%q'", SHN, sha1)), 0, 0, &sqlerr);
		if (sqlerr != 0) {
		    fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
		    sqlite3_free(sqlerr);
		}
		sqlite3_free(sqlstmt);
	    }
	}
	if (rows_purged % 1000 == 0) {
	    if (verbose > 0)
		fprintf(stderr, "Purged %d files          \r", rows_purged);
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"delete from purgelist where %s in (select hash from diskfiles_purged)", SHN)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"delete from diskfiles where %s in (select hash from diskfiles_purged)", SHN)), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
		"delete from diskfiles_purged")), 0, 0, &sqlerr);
	    if (sqlerr != 0) {
		fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
		sqlite3_free(sqlerr);
	    }
	    sqlite3_free(sqlstmt);
	}
    }
    if (verbose > 0)
	fprintf(stderr, "Purged %d files\n", rows_purged);
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from purgelist where %s in (select hash from diskfiles_purged)", SHN)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from diskfiles where %s in (select hash from diskfiles_purged)", SHN)), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);
    sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	"delete from diskfiles_purged")), 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "%s\n%s\n\n",sqlerr, sqlstmt);
	sqlite3_free(sqlerr);
    }
    sqlite3_free(sqlstmt);

    sqlite3_exec(bkcatalog, "END", 0, 0, 0);
    return(0);
}
