Usage: snebu-client [ subcommand ] [ options ]
 snebu-client is the client front end for snebu.  Use it to easily
 back up a local or remote host, to either local a local storage
 device, or to a remote backup server.  Use it with one of the
 following subcommands.


Documentation on the individual sub commands are as follows:

Usage: snebu-client backup [ -n backupname ] [ -d datestamp ] [ -r schedule ]
 Initiates a system backup.  By default, it will back up the local
 host to a local snebu install.  You can also use this command to back
 up to a remote backup server, back up a remote host to either a local
 snebu instalation, or back up a remote host to another remote backup
 server, depending on which options are chosen.

Options:
 -c, --config config_file   Name of the configuration file.  Default is
                            /etc/snebu-client.conf.

 -n, --name backupname      Name of the backup.  Usually set to the server
                            name that you are backing up.

 -d, --date datestamp       Date stamp for this backup set.  The format is in
                            time_t format, sames as the output of the "date
                            +%s" command.

 -r, --retention schedule   Retention schedule for this backup set.  Typical
                            values are "daily", "weekly", "monthly", "yearly".

     --remote-client hostname 
                            Host name / IP address of remote server.  Used to
                            backup a remote server to local host.

     --backup-server hostname 
                            Host name / IP address of backup server.  Used to
                            backup to a remote server.

 -f, --force-full           Force a full backup

 -C, --changedir path       Changes to the given directory path before
                            backing up or restoring.

     --graft /path/name/=/new/name/ 
                            Re-write path names beginning with "/path/name/"
                            to "/new/name/"

     --plugin scriptname    Specifies an optional plug in script.  Usually
                            used to perform database-specific operations
                            (such as enabling hot backup mode) for systems
                            with a DB installed.


Usage: snebu-client restore [ -n backupname ] [ -d datestamp ]
 Restores a given backup session identified by "-n" and "-d"
 parameters.  Use the "listbackups" subcommand to get a list of
 available backup sessions.

Options:
 -c, --config config_file   Name of the configuration file.  Default is
                            /etc/snebu-client.conf.

 -n, --name backupname      Name of the backup.  Usually set to the server
                            name that you are backing up.

 -d, --date datestamp       Date stamp for this backup set.  The format is in
                            time_t format, sames as the output of the "date
                            +%s" command.

 -C, --changedir path       Changes to the given directory path before
                            backing up or restoring.


Usage: snebu-client listbackups [ -n hostname [ -d datestamp ]] [ file_list... ]
 With no arguments specified, "listbackups" will return a list of all
 systems that are contained in the backup catalog.  Otherwise, when
 specifying the -n parameter, a list of backup sets for that host is
 returned.

Options:
 -c, --config config_file   Name of the configuration file.  Default is
                            /etc/snebu-client.conf.

 -n, --name backupname      Name of the backup.  Usually set to the server
                            name that you are backing up.

 -d, --date datestamp       Date stamp for this backup set.  The format is in
                            time_t format, sames as the output of the "date
                            +%s" command.


Usage: snebu help [ topic ]
 Displays help text [on the given topic].
