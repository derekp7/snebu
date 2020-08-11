#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <time.h>
#include <getopt.h>
#include <sqlite3.h>
#include <errno.h>

int restore(int argc, char **argv);
int help(char *topic);
void usage();
extern sqlite3 *bkcatalog;
int permissions(int argc, char **argv);

int permissions(int argc, char **argv)
{
    int optc;
    char *sqlerr;
    sqlite3_stmt *sqlres;
    char *sqlstmt = 0;
    char *sqlstmt2 = 0;
    char *sqlstmt3 = 0;
    char *sqlstmt4 = 0;
    int foundopts = 0;
    char *action = "";
    char user[128];
    char bkname[128];
    char command[128];
    struct option longopts[] = {
	{ "list", no_argument, NULL, 'l' },
	{ "add", no_argument, NULL, 'a' },
	{ "remove", no_argument, NULL, 'r' },
        { "command", required_argument, NULL, 'c' },
        { "name", required_argument, NULL, 'n' },
	{ "user", required_argument, NULL, 'u' },
        { NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
    int sargs = 0;

    *command = *bkname = *user = '\0';
    while ((optc = getopt_long(argc, argv, "larc:n:u:", longopts, &longoptidx)) >= 0) {
        switch (optc) {
	    case 'l':
		action = "list";
		foundopts |= 1;
		break;
	    case 'a':
		action = "add";
		foundopts |= 2;
		break;
	    case 'r':
		action = "remove";
		foundopts |= 4;
		break;
           case 'c':
                strncpy(command, optarg, 127);
                command[127] = 0;
                foundopts |= 8;
                break;
           case 'n':
                strncpy(bkname, optarg, 127);
                bkname[127] = 0;
                foundopts |= 16;
                break;
           case 'u':
                strncpy(user, optarg, 127);
                user[127] = 0;
                foundopts |= 32;
                break;
            default:
                usage();
                exit(1);
	}
    }

    if (strcmp(action, "list") == 0) {
	sqlstmt2 = strlen(user) > 0 ? sargs++, sqlite3_mprintf(" where username = '%q'", user) : sqlite3_mprintf("");
	sqlstmt3 = strlen(command) > 0 ? sargs++, sqlite3_mprintf(" %s command = '%q'", (sargs < 2 ? "where" : "and"), command) : sqlite3_mprintf("");
	sqlstmt4 = strlen(bkname) > 0 ? sargs++, sqlite3_mprintf(" %s backupname = '%q'", (sargs < 2 ? "where" : "and"), bkname) : sqlite3_mprintf("");
	sqlite3_prepare_v2(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "select username, command, backupname from userpermissions%s%s%s",
	    sqlstmt2, sqlstmt3, sqlstmt4)), -1, &sqlres, 0);
	while (sqlite3_step(sqlres) == SQLITE_ROW) {
	printf("%s %s %s\n",
	    sqlite3_column_text(sqlres, 0),
	    sqlite3_column_text(sqlres, 1),
	    sqlite3_column_text(sqlres, 2));
	}
	if (sqlstmt4 != NULL)
	    sqlite3_free(sqlstmt4);
	if (sqlstmt3 != NULL)
	    sqlite3_free(sqlstmt3);
	if (sqlstmt2 != NULL)
	    sqlite3_free(sqlstmt2);
	sqlite3_free(sqlstmt);
    }
    if (strcmp(action, "add") == 0) {
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "insert into userpermissions (username, command, backupname) "
	    "values ('%q', '%q', '%q')", user, command, bkname)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n", sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
	sqlite3_free(sqlstmt);
    }
    if (strcmp(action, "remove") == 0) {
	sqlite3_exec(bkcatalog, (sqlstmt = sqlite3_mprintf(
	    "delete from userpermissions where username = '%q' and "
	    "command = '%q' and backupname = '%q'",
	     user, command, bkname)), 0, 0, &sqlerr);
	if (sqlerr != 0) {
	    fprintf(stderr, "%s\n%s\n\n", sqlerr, sqlstmt);
	    sqlite3_free(sqlerr);
	}
	sqlite3_free(sqlstmt);
    }
    return(0);
}
