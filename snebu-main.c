#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#include <sqlite3.h>
#include "tarlib.h"

int initdb(sqlite3 *bkcatalog);
void usage();
int gethelp(int argc, char **argv);
int help(char *topic);
int newbackup(int argc, char **argv);
int submitfiles(int argc, char **argv);
int restore(int argc, char **argv);
int listbackups(int argc, char **argv);
int expire(int argc, char **argv);
int purge(int argc, char **argv);
int logaction(sqlite3 *bkcatalog, int backupset_id, int action, char *message);
char *stresc(char *src, char **target);
char *strescb(char *src, char **target, int len);
char *strunesc(char *src, char **target);
long int strtoln(char *nptr, char **endptr, int base, int len);
sqlite3 *opendb();
int permissions(int argc, char **argv);
int checkperm(sqlite3 *bkcatalog, char *action, char *backupname);
int busy_retry(void *userdata, int count);

void getconfig(char *configpatharg);

sqlite3 *bkcatalog;

struct subfuncs{
    char *funcname;
    int (*target)(int, char **);
    int initdb;
};


struct {
    char *vault;
    char *meta;
} config;

int main(int argc, char **argv)
{
    struct subfuncs subfuncs[] = {
	{ "newbackup", &newbackup, 1 },
	{ "submitfiles", &submitfiles, 0 },
	{ "listbackups", &listbackups, 1 },
	{ "restore", &restore, 1 },
	{ "expire", &expire, 1 },
	{ "purge", &purge, 1 },
	{ "permissions", &permissions, 1},
	{ "help", &gethelp, 0 }/*,
	{ "import", &import, 1 },
	{ "export", &export, 1 } */
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
		if (subfuncs[i].initdb == 1)
		    opendb(bkcatalog);
		subfuncs[i].target(argc - n, argv + n);
		if (subfuncs[i].initdb == 1)
		    sqlite3_close(bkcatalog);
		if (config.vault != NULL)
		    free(config.vault);
		if (config.meta != NULL)
		    free(config.meta);
		exit(0);
	    }
	}
    }
    if (config.vault != NULL)
	free(config.vault);
    if (config.meta != NULL)
	free(config.meta);
    usage();
    return 0;
}

void getconfig(char *configpatharg)
{
    char *configline = NULL;
    size_t configlinesz = 0;
    struct stat tmpfstat;
    char configpath[256];
    FILE *configfile;
    char *configvar;
    char *configvalue;
    char **configlinel = NULL;
    int i;
    int j;

    config.vault = NULL;
    config.meta = NULL;
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
            if ((j = parse(configline, &configlinel, '=') == 2)) {
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
	dfree(configlinel);
	free(configline);
	fclose(configfile);
    }
    else
        fprintf(stderr, "Can't find %s, using defaults\n", configpath);
    if (config.vault == 0)
        config.vault = "/var/backup/vault";
    if (config.meta == 0)
        config.meta= "/var/backup/meta";
}

sqlite3 *opendb()
{
    char *bkcatalogp = NULL;
    int x;

    asprintf(&bkcatalogp, "%s/%s.db", config.meta, "snebu-catalog");
    if ((x = sqlite3_open(bkcatalogp, &bkcatalog)) != SQLITE_OK) {
        fprintf(stderr, "Error: could not open catalog at %s\n", bkcatalogp);
        exit(1);
    }
    sqlite3_busy_handler(bkcatalog, busy_retry, NULL);
    sqlite3_exec(bkcatalog, "PRAGMA foreign_keys = ON", 0, 0, 0);
    sqlite3_exec(bkcatalog, "PRAGMA journal_mode = WAL", 0, 0, 0);
    free(bkcatalogp);
    x = initdb(bkcatalog);
    return(bkcatalog);

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
        fprintf(stderr, "Error getting to database 2\n");
        return(1);
    }
    sqlite3_finalize(sqlres);

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
	"create table if not exists userpermissions ( \n"
	"    username		char, \n"
	"    command		char, \n"
	"    backupname		char, \n"
	"constraint userpermissionsc1 unique ( \n"
	"    username, \n"
	"    command, \n"
	"    backupname))", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
	"create table if not exists grouppermissions ( \n"
	"    groupname		char, \n"
	"    action		char, \n"
	"    backupname		char)", 0, 0, 0);
    if (err != 0)
	return(err);

    err = sqlite3_exec(bkcatalog,
        "create table if not exists cipher_master ( \n"
        "    cipherid            integer primary key, \n"
        "    pkfp                char, \n"
        "    eprivkey            char, \n"
        "    pubkey              char, \n"
        "    hmackeyhash         char, \n"
        "    comment             char, \n"
        "constraint cipher_master_c1 unique ( \n"
        "    pkfp, \n"
        "    eprivkey, \n"
        "    pubkey, \n"
        "    hmackeyhash, \n"
        "    comment)) ", 0, 0, 0);
    if (err != 0)
        return(err);

    err = sqlite3_exec(bkcatalog,
        "create table if not exists cipher_detail ( \n"
        "    file_id		integer, \n"
        "    keynum             integer, \n"
//        "    compression        char, \n"
//        "    cipher             char, \n"
//        "    filters            char, \n"
        "    hmac               char, \n"
        "constraint cipher_detail_c1 unique ( \n"
        "    file_id, \n"
        "    keynum) \n"
	"foreign key(file_id) references file_entities(file_id))", 0, 0, &sqlerr);
    if (sqlerr != 0) {
	fprintf(stderr, "create table cipher_detail %s\n", sqlerr);
	sqlite3_free(sqlerr);
    }
    if (err != 0) {
	fprintf(stderr, "Error: %d\n", err);
        return(err);
    }

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
	    "    expire [ -n hostname -d datestamp ] or [ -a days -r schedule\n"
	    "      [ -n hostname ]]\n"
	    "\n"
	    "    purge\n"
	    "\n"
	    "    permissions [ -l | -a | -r ] -c command -n hostname -u user\n"
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
	    "Usage: snebu expire [ -n hostname -d datestamp ] or [ -a days -r schedule\n"
	    "  [ -n hostname ]]\n"
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
    if (strcmp(topic, "permissions") == 0)
	printf(
            "Usage: snebu permissions [ -l | -a | -r ] -c command -n hostname -u user\n"
            " The \"permissions\" command lists, adds, or removes user permissions.  These\n"
            " permissions are applied when the \"snebu\" command is installed setuid, and run\n"
            " by a OS different user.\n"
            "\n"
            "Options:\n"
            " -l, --list                Lists all installed permissions.  If the -c, -n, or\n"
            "                           -u options are given, this list is restricted to\n"
            "                           those subcommands, hostnames, or users respectively.\n"
            "\n"
            " -a, --add                 Adds permissions for the specified subcommand [-c],\n"
            "                           hostname [-n], and user [-u].\n"
            "\n"
            " -r, --remove              Removes permissions for the specified subcommand\n"
            "                           [-c], hostname [-n], and user [-u].\n"
            "\n"
            " Available subcomands that work with permissions are:\n"
            "  backup (covers both newbackup and submitfiles functions)\n"
            "  restore\n"
            "  listbackups\n"
            "  expire\n"
            "  purge\n"
            "  permissions\n"
            "\n"
            "Note, that since the purge subcommand doesn't take a list of hostnames, along\n"
	    "with the permissions subcommand, and the expire subcommand when run with the\n"
	    "--age option, you must specify the hostname '*' to give access to a specific\n"
	    "user.\n"
	    "\n"
	    "To grant permissions, a this command must be run as the user that snebu is\n"
	    "installed under, or the user must be granted access to the permissions\n"
	    "subcommand\n"
	);
    if (strcmp(topic, "help") == 0)
	printf(
	    "Usage: snebu help [ subcommand ]\n"
	    " Displays help text\n"
	);
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
#if 0
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
char *strescb(char *src, char **target, int len)
{
    int i;
    int j;
    int e = 0;
    static int tlen = 16384;

    if (*target == 0)
        *target = malloc(tlen);
    for (i = 0; i < len; i++)
        if (src[i] <= 32 || src[i] >= 127 || src[i] == 92)
            e++;
//    *target = realloc(*target, len  + e * 4 + 1);
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
            sprintf((p), "\\%3.3o",
                (unsigned char) src[i]);
            p += 4;
            i++;
        }
    }
    return(*target);
}
char *strunesc(char *src, char **target)
{
    int i;
    int j;
    char *p;

    *target = realloc(*target, strlen(src) + 1);
    (*target)[0] = 0;
    memset(*target, 0, (size_t) strlen(src) + 1);
    i = 0;
    p = *target;
    while (i < strlen(src)) {
        for (j = i; i < strlen(src) && src[i] != 92; i++)
            ;
        strncat(p, src + j, i - j);
        if (i < strlen(src)) {
            p += strlen(p);
            *p++ = (char) strtoln(src + ++i, NULL, 8, 3);
            i += 3;
        }
    }
    return((*target = realloc(*target, strlen(*target) + 1)));
}
#endif
long int strtoln(char *nptr, char **endptr, int base, int len)
{
    char scratch[20];
    strncpy(scratch, nptr, len);
    scratch[len] = (char) 0;
    return(strtol((scratch), endptr, base));
}

int checkperm(sqlite3 *bkcatalog, char *action, char *backupname)
{
    int num_matches = 0;
    struct passwd *passwd;
    char *sqlstmt = 0;
    sqlite3_stmt *sqlres;
    int x;

    if (getuid() != geteuid()) {
        passwd = getpwuid(getuid());

        x = sqlite3_prepare_v2(bkcatalog,
            (sqlstmt = sqlite3_mprintf("select count(*)  "
                "from userpermissions where "
                "(command = '%q' or command = '*') and username = '%q' and (backupname = '%q' or backupname = '*')",
                action, passwd->pw_name, backupname == NULL || strlen(backupname) == 0 ? "*" : backupname)),
                -1, &sqlres, 0);
        if ((x = sqlite3_step(sqlres)) == SQLITE_ROW) {
            num_matches = sqlite3_column_int(sqlres, 0);
            if (num_matches > 0) {
                sqlite3_finalize(sqlres);
                sqlite3_free(sqlstmt);
                return(0);
            }
        }
        sqlite3_finalize(sqlres);
        sqlite3_free(sqlstmt);
        fprintf(stderr, "User %s not permitted to run %s on %s\n",
            passwd->pw_name, action, backupname == NULL || strlen(backupname) == 0 ? "*" : backupname);
        return(1);
    }
    else
        return(0);
}

int busy_retry(void *userdata, int count)
{
    usleep(100000);
    return 1;
}
