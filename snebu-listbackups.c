#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sqlite3.h>
#include <time.h>
#include <stdint.h>

extern struct {
    char *vault;
    char *meta;
} config;

extern sqlite3 *bkcatalog;

int listbackups(int argc, char **argv);
void usage();
int checkperm(sqlite3 *bkcatalog, char *action, char *backupname);

int listbackups(int argc, char **argv)
{
    int optc;
    char bkname[128];
    char datestamp[128];
    char *filespec = 0;
    int filespeclen;
    int foundopts = 0;
    sqlite3_stmt *sqlres;
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
    int longoutput = 0;
    int long0output = 0;


    *bkname = *datestamp = '\0';
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
	    case 'l':
		longoutput = 1;
		foundopts |= 4;
		break;
	    case '0':
		long0output = 1;
		foundopts |= 8;
		break;
	    default:
		usage();
		return(1);
	}
    }
    if (foundopts != 0 && foundopts != 1 && foundopts != 3 && foundopts != 7 && foundopts != 15) {
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
    if (checkperm(bkcatalog, "listbackups", bkname)) {
	sqlite3_close(bkcatalog);
	return(1);
    }


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
		bdatestamp = strtol(datestamp, NULL, 10);
	    else
		bdatestamp = 0;
	    if (*(range + 1) != '\0')
		edatestamp = strtol(range + 1, NULL, 10);
	    else
		edatestamp = INT32_MAX;
	}
	else {
	    bdatestamp = strtol(datestamp, NULL, 10);
	    edatestamp = strtol(datestamp, NULL, 10);
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
    else if (longoutput == 1 && long0output == 0) {
	range = strchr(datestamp, '-');
	if (range != NULL) {
	    *range = '\0';
	    if (*datestamp != '\0')
		bdatestamp = strtol(datestamp, NULL, 10);
	    else
		bdatestamp = 0;
	    if (*(range + 1) != '\0')
		edatestamp = strtol(range + 1, NULL, 10);
	    else
		edatestamp = INT32_MAX;
	}
	else {
	    bdatestamp = strtol(datestamp, NULL, 10);
	    edatestamp = strtol(datestamp, NULL, 10);
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
    else if (long0output == 1) {
	range = strchr(datestamp, '-');
	if (range != NULL) {
	    *range = '\0';
	    if (*datestamp != '\0')
		bdatestamp = strtol(datestamp, NULL, 10);
	    else
		bdatestamp = 0;
	    if (*(range + 1) != '\0')
		edatestamp = strtol(range + 1, NULL, 10);
	    else
		edatestamp = INT32_MAX;
	}
	else {
	    bdatestamp = strtol(datestamp, NULL, 10);
	    edatestamp = strtol(datestamp, NULL, 10);
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
