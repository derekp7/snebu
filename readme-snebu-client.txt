The snebu-client script is a simple front-end to the snebu program.  It takes care of finding files to back up, sending the files to snebu, along with restoring files and listing available backups.  Usage is fairly straight forward.  The first argument is the sub-module to call (backup, restore, listbackups).  The remaining arguments are as follows:

snebu-client backup
Executes a backup operation.  The options are as follows:
    -n | --name backupname)
        This is the name of a given backup.  Defaults to the current host name.

    -d | --datestamp date)
        The date/time for the backup -- given as a number representing the number of seconds since Jan 1 1970.  Can be generated with the `date +%s` command.  This functions as a serial number for the current backup.  Defaults to the current date/time.  Note, that if you use the same host name and datestamp from a previous backup, that backup will be appended to.  This is useful, for example, if you need to execute a command between groups of files (such as putting a database in hot backup mode).
	
    -r | --retention schedule_name)
        The name of the retention schedule.  Typical schedules are `monthly`, `weekly`, and `daily`.  This is used to specify a group of backups when executing an expiration operation.  If not specified, a default is chosen as follows:  The first of the month specifies a monthly retention schedule, Saturday specifies a weekly retention schedule, and any other day specifies a daily retention schedule.
    [ file list ]
        include list of files.  This can override the default specified in the config file, or the built-in default consisting of all mounted file systems.

snebu-client listbackups
Lists available backups to restore.  Specify either --name or both --name and --datestamp parameters.

    -n | --name backupname
        This is the name of a given backup.  Defaults to the current host name.  Specify "all" to get a list of all hosts that have been backed up.  Otherwise, a list of backups for the given host (or current host, if not specified) are displayed.

    -d | --datestamp date)
        The date/time (serial number) for the backup -- given as a number representing the number of seconds since Jan 1 1970.  Pick one that is given with the output of the "-n" parameter.

        If only "-n" is specified, you get a list of backups for the given host.  If both "-n" and "-d" are specified, a list of files for that specific backup set is given.

snebu-client restore
Restores files from a given backup set.  Requires both the --n and -d parameters.

    -n | --name backupname
        Host name of backup to restore

    -d | --datestamp date
        Date stamp of backup to restore

    -C --directory DIR
        Changes to the given directory before starting restore.

    [ file list ]
        Optional list of files to restore.  The default is all files in this backup set.
