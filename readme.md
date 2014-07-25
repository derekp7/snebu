Introduction
====

Snebu is an efficient incremental snapshot style client/server disk-based backup system for Unix / Linux systems.  Efficiency is provided by transferring only the needed files to complete a given backup set, along with compression and file-level de-duplication.  This de-duplication is effective for any files with the same contents, whether they come from the same backup instance, or are duplicated across past backups, or even across  multiple systems.  Therefore you can backup the full OS on multiple servers using only minimal additional storage space.

Audience
----

Snebu is for those who either have no current backup strategy, and want to get something going quickly (either to a locally attached external drive, or to some storage on another server), or if you are currently using a simpler backup scheme (such as one of the rsync-based backup methods) and need to have some of the features of the more heavy weight backup systems (such as a compression, de-duplication, backup catalog DB, and scheduled data expiration).

Features
====

Benefits:

* Easy to set up  
  There system consists of two programs:  
  `snebu-client` - This is a simple shell script for interacting with the backend process, along with gathering   the files to include in a given backup set.  
  `snebu` -- This is the backend process which stores backup files in a disk-based vault, maintaining metadata    about the files and backup sets in an SQLite-based backup catalog.

  There are no complicated daemons to configure, or heavy database systems that need to be installed.  All the core logic is self-contained in the snebu binary.

* Suitable for backing up a single system to an attached external disk, backing up to a separate network server,  or backing up a number of hosts with backups initiated from the central backup server.

* No client software installation required.  If backups are initiated from a central backup server, then          communications to the clients are preformed over SSH.  The only requirements are that the backup account on the   server is permitted appropriate access to the client (via ssh keys), and the client have the minimal versions of  GNU find and tar installed (this is only a concern with ancient Linux installations, or Unix systems).

* Works similar to rsync-based backup tools (by providing snapshot incremental-forever backups), but provides     compression and a self-contained database-backed (SQLite) backup catalog.  One of the many benefits of having a   separate backup catalog is this allows the backend to execute under a regular (non-root) utility account.

* File-level de-duplication is supported, including de-duplication of files across backup sets, and across        multiple backup clients.

* Built using standard tools and protocols.  File metadata gathering is provided by the "find" command (GNU find  is required), files are transfered using "tar" format, the backup catalog is in an SQLite database file, and      files are stored in the disk-based vault compressed with the LZO library, and compatible with the "lzop"          compression program.


Quick-start guide
====

Concepts
----

The Snebu backup system is composed of a backend process, `snebu`, and a front-end client called `snebu-client`.  The client gathers a list of files to back up (using the `find` command), sends this list to the backend, and gets back a list of files that are needed to complete an incremental backup.  These files are then sent to the backend using the Unix `tar` format.

Backups are stored in backup sets.  A backup set is uniquely identified by the backup name (typically the host name getting backed up), and a datestamp in the form of a Unix time_t value (essentially, a count of the number of seconds since Jan 1, 1970).  This value functions as a serial number.

Each backup set has a retention schedule attached to it, specified by the `-r` flag.  The retention schedule is used by the expiration process to, for example, expire all daily backups older than 10 days, or all monthly backups older than 6 months.  Anything can be used for for a schedule name, but typical values are `daily`, `weekly`, `monthly`, `yearly`, and `archive`.  If not specified, then the `snebu-client` script will automatically pick a retention schedule based on the date (Sunday through Friday are daily, Saturday is weekly, and the 1st of the month is monthly).

When a backup is requested, the backend will determine which files it already has (by comparing meta data such as file name, size, last modification time, and various other attributes).  A list of files that are already on the backup server is added to the current backup set.  The remaining files are then requested, and are added to the backup set when they are received.

File contents are stored and referenced by using the SHA1 hash of the file contents.  Therefore, file level de-duplication is achieved across all backups stored on the backup server.  In addition, files are stored compressed in an lzop compatible format.  This allows for recovery of files even outside of the backup utility.

Setting up a local backup
----

This procedure assumes that both `snebu` and `snebu-client` are installed, and you will be backing up to a drive that is mounted under /media/backups.  These steps will be run as the root user.  In the examples, the host name that is getting backed up is called `zeus`  The backup retention schedules are automatically determined in these examples (use `-r` to override)

1) Create a file `/etc/snebu.conf` with the following:

    meta=/media/backups/meta
    vault=/media/backups/vault

The meta directory is where the backup catalog is stored (in an SQLite DB).  The vault directory contains all the backup file contents.

2) Create the directories from the previous step:

    mkdir -p /media/backups/meta
    mkdir -p /media/backups/vault

3) Create a file `/etc/snebu-client.conf` with the following:

    EXCLUDE=( /tmp /var/tmp /mnt /media/backups )

By default, the files to be backed up included all mounted Linux filesystems of the types ext2, ext3, ext4, btrfs, xfs.  This is the same as specifying the following line in the `snebu-client.conf` file:

    INCLUDE=( $(mount |egrep "ext[234]|btrfs" |awk '{print $3}') )

If you want to list specific directories to backup, list them in an INCLUDE line in the `/etc/snebu-client.conf` file:

    INCLUDE=( /dir1 /dir2 /dir3 )

Or, if you want to add to the default include:

    INCLUDE=( "${INCLUDE[@]}" /dir1 /dir2 /dir3 )

4) Run a test backup:

    snebu-client backup -v

Note, you can also override the default INCLUDE list on the `snebu-client` command line:

    snebu-client backup -v /dir1 /dir2

See the `snebu-client` detailed documentation for the list of available parameters.  Specifically, look at the `-r` (retention schedule), and `-n` (backup name) parameters.

5) Once the backup is completed, you can use the following to list the backups:

    snebu-client listbackups -v

Which should output the names of the backups that are available:

    zeus
        1389677695 / daily / Mon Jan 13 23:34:55 2014

7) To get a list of files that are included:

    snebu-client listbackups --name zeus --datestamp 1389677695 |more

8) To restore a given file, pick one from the list generated in the step above, and:

    snebu-client restore --name zeus --datestamp 1389677695 '/path/to/file'

Or, to restore a directory,

    snebu-client restore --name zeus --datestamp 1389677695 '/path/to/directory/*'

This will by default place the files starting in the directory you are currently sitting in.  So, if you are in /tmp, and restore /home/bob/resume.txt, it will be placed in /tmp/home/bob/resume.txt.  See the detailed documentation section for additional parameters, such as `-C` which will specify an alternate target directory, or `--graft` which will allow you to rename parts of the file path.


Backing up to a remote server
----

When backing up to a remote server, it is preferable to use a non-privliged user account, such as `backup`, instead of `root`.  In this section, the backup server will be called `jupiter`, and the client is `zeus`.  The backup server will have the target backup media mounted under /media/backups, which will be owned by `backup`.  The program `snebu` is assumed to be installed on `jupiter`, and the `snebu-client` script is on the client `zeus`.

1) Create a backup user:

    useradd backup
    passwd backup

2) Create a file `/etc/snebu.conf` with the following:

    meta=/media/backups/meta
    vault=/media/backups/vault

3) After mounting the backup media, create the directories from the previous step, and make everything owned by backup:

    mkdir -p /media/backups/meta
    mkdir -p /media/backups/vault
    chown -R backup /media/backups

4) On the client (`zeus`), create an ssh key pair if one doesn't exist for the root user, and copy it to the `backup` user's authorized-keys file on `jupiter`:

    ssh-keygen -t rsa -N ""
    ssh-copy-id backup@jupiter

5) On the client, create the `/etc/snebu-client.conf` file with proper INCLUDE and EXCLUDE parameters, as specified in the previous (local backup) section.

6) Make sure you can (as root on `zeus`) ssh into the backup user on `jupiter`

    ssh backup@jupiter uname -a

7) Run a test backup as before, but with an additional parameter:

    snebu-client backup --backup-server jupiter -v

The --backup-server parameter will also apply to all the other comands, such as listbackups and restore.  An alternative to specifying this each time is to add the following to `/etc/snebu-client.conf`:

    bksvrname=jupiter


Backing up remote clients from a backup server
----

If you have a number of systems to back up, it may be better to initiate all backups from the backup server.  In this model, the `backup` user account on the backup server will need SSH permissions to access root on the clients.  This may be preferable, as it avoids having to give each client remote access to the backup server.  However, that means the clients have to trust the backup server with root access.  The good part, though, is there is nothing to install on the clients, other than inserting a key into root's authorized_keys file.

1) Set up the backup server, `jupiter` as discussed in the previous section (steps 1 through 3)

2) Also, on the server (`jupiter`), create an SSH key pair for the `backup` user

    ssh-keygen -t rsa -N ""

3) Copy the public key file to the clients to be backed up.  Newer versions of OpenSSH include a utility to make this easier:

    ssh-copy-id root@zeus

4) Initiate a test backup from the `backup` user on `jupiter`:

    snebu-client backup --remote-client zeus -v


Daily and periodic maintenance tasks
----

### Expiring old backups

Periodically cleaning out old backups is essential for keeping the target storage device from running out of space.  Typical data retention schedules are:

* daily -- keep all daily backups for 2 weeks
* weekly -- keep all weekly (Saturday) backups for 6 weeks
* monthly -- keep all monthly backups for 12 months

To accomplish this, run the following commands on the backup server:

    snebu expire -a 14 -r daily
    snebu expire -a 42 -r weekly
    snebu expire -a 365 -r monthly

Note, that there is a safety valve built into the expire command, where it will keep (by default) the most recent 3 backup sets for a given system.  This can be adjusted with the `-m` flag (i.e., `-m 7` will keep the most recent 7 backups, or `-m 0` disables this safety check).

Another form of the expire command will remove a given backup set, useful if you have a partial or a redundant backup that needs to be cleaned out:

    snebu expire -n name -d datestamp

After the expiration jobs are finished (which removes the backups from the backup catalog), you will need to remove the actual file contents from the vault:

    snebu purge

The purge process can take some time to execute, so typically it would be run on a weekly basis, and the expire jobs run daily after the backups have completed.


Advanced usage
====

Creating a custom snebu-client script
----

Typically, direct usage of the `snebu` command is used for maintenance purposes.  Submitting backups and restoring is driven by the snebu-client command.  However, if needed, you can create a custom client for advanced purposes (such as performing live database backups, which typically involve placing the DB in backup mode, and querying the DB for which files to back up).  The process of submitting a backup requires two parts:

* snebu newbackup  
  This subcommand expects an input list of files as a tab-delimited list consisting of:  
    File Type, Mode, Device, Inode, Owner, Owner#, Group, Group#, Size, SHA1, Inode Mod Time, File Mod Date, Filename, Symlink Target

  This list can be generated with GNU find command, with the following `-printf` arguments added:

        \( -type f -o -type d \) \
            -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%C@\t%T@\t%p\0" \
            -o -type l \
            -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%C@\t%T@\t%p\0%l\0"

  (Note, that currently the SHA1 field (field number 10) isn't used, so the above puts a 0 as a placeholder.  This is intended to be an additional indicator of if a file needs to be transfered to the backup server's vault, or if it is already there.)

* snebu submitfiles  
  The output of the `snebu newbackup` command is a list of files that need to be backed up to complete the backup set (anything not on this list is already on the backup server, and gets linked to the current backup set).  This list is then used to generate a `tar` file, which gets submitted to the submitfiles target as standard input.

See the detailed documentation section for additional command line arguments that are required.  Also, the included snebu-client shell script can be referenced for more details.


Changing file locations
----

One parameter to `snebu-client` (or `snebu`, if writing your own client) is the `--graft` option.  This allows you to re-write the directory path from one location to another.  This is useful when backing up a filesystem snapshot.  If the snapshot of `/srv/database` is mounted under `/mnt/snapshots/database`, you can specify `--graft /mnt/snapshots/database/=/srv/database/` so that the backup will record the file locations as if they were backed up under their original location.

Another usage for `--graft` is when restoring a single file to a different location.  For example: `--graft /home/bob/budget.doc=/home/bob/restore/budget.doc` will allow restoring the file without overwriting the version that is currently in place.


Forcing a full backup
----

Snebu uses the file meta data (file name, last mod date, size, permissions, etc.) to determine if a file has been modified since the last backup.  If a file gets modified, keeps the same size, and the mod date is manually set to the original, this can cause the file to be skipped during incremental backups.  Therefore, it may be desirable to periodically force a full backup with the `-f` flag.  This will cause all included files to get transfered, although de-duplication is still accomplished on the back end.  The main drawback of `-f` is that it increases the backup time and network usage.


Plugins
----

A plugin architecture is currently under development, which allows the `snebu-client` script to perform additional steps before and after a backup.  This can be used to create and mount snapshots of file systems, or to put a database into backup mode.

Command reference
====

snebu-client
----
    Usage: snebu-client [ subcommand ] [ options ]
     snebu-client is the client front end for snebu.  Use it to easily
     back up a local or remote host, to either local a local storage
     device, or to a remote backup server.  Use it with one of the
     following subcommands.
    
     Sub commands are as follows:
        backup  [ -n backupname ] [ -d datestamp ] [ -r schedule ]
    
        restore [ -n backupname ] [ -d datestamp ]
    
        listbackups [ -n backupname [ -d datestamp ]] [ file_list... ]
    
        help [subcommand]

### snebu-client backup
    Usage: snebu-client backup [ -n backupname ] [ -d datestamp ] [ -r schedule ]
        [ file-list ]
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
    
     [ file-list ]              List of files to backup -- overrides default

### snebu-client restore
    Usage: snebu-client restore [ -n backupname ] [ -d datestamp ] [ file-list ]
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
    
         --remote-client hostname
                                Host name / IP address of remote server.  Used to
                                backup a remote server to local host.
    
         --backup-server hostname
                                Host name / IP address of backup server.  Used to
                                backup to a remote server.
    
     [ file-list ]              List of files to restore.  Defaults to all.

### snebu-client listbackups
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

snebu
----

    Usage: snebu [ subcommand ] [ options ]
      where "subcommand" is one of the following:
        newbackup -n backupname -d datestamp -r schedule
    
        submitfiles -n backupname -d datestamp
    
        restore -n backupname -d datestamp [ file_list... ]
    
        listbackups [ -n hostname [ -d datestamp ]] [ file_list... ]
    
        expire [ -n hostname -d datestamp ] or [ -a days -r schedule [ -n hostname ]]
    
        purge
    
        help [ subcommand ]
    
     The "snebu" command is a backup tool which manages storing data from
     backup sessions on disk-based storage, utilizing a simple database
     for tracking backup sets and meta data.  Typically it is called via a
     front end script (such as the included "snebu-client" shell script). 
     Documentation is provided here if you need to create a custom backup
     client script.  The subcommands are listed below along with the most
     common options.  Details on each command are given in each command's
     help section.

### snebu newbackup
    Usage: snebu newbackup -n backupname -d datestamp -r schedule
     The "newbackup" command creates a new backup set, by consuming a
     tab-delimited list of file names (along with associated meta data) to
     include in the backup.  It then compares this list to the backup
     catalog database to determine which files are new, and which ones are
     already contained on the backup media.  A list of new / changed files
     is returned, which can then be passed along to "tar" to generate a
    
    Options:
     -c, --config config_file   Name of the configuration file.  Default is
                                /etc/snebu.conf.
    
     -n, --name backupname      Name of the backup.  Usually set to the server
                                name that you are backing up.
    
     -d, --date datestamp       Date stamp for this backup set.  The format is in
                                time_t format, sames as the output of the "date
                                +%s" command.
    
     -r, --retention schedule   Retention schedule for this backup set.  Typical
                                values are "daily", "weekly", "monthly", "yearly".
    
     -T, --files-from FILE      Read list of filenames (with meta data) to backup
                                from the named file, instead of standard input.
    
         --null                 Inbound file backup list (-T, or standard input)
                                is null terminated
    
         --not-null             Inbound file backup list (-T, or standard input)
                                is newline terminated
    
         --null-output          Generate include-file-list with null terminated
                                lines.
    
         --not-null-output      Generate include-file-list with newline
                                terminated lines.
    
     -f, --force-full           Force a full backup
    
         --graft /path/name/=/new/name/ 
                                Re-write path names beginning with "/path/name/"
                                to "/new/name/"
    
     -v,                        Verbose output

### snebu submitfiles
    Usage: snebu submitfiles -n backupname -d datestamp
     The "submitfiles" command is called after newbackup, and is used to
     submit a tar file containing the list of filest that newbackup
     returned.
    
    Options:
     -c, --config config_file   Name of the configuration file.  Default is
                                /etc/snebu.conf.
    
     -n, --name backupname      Name of the backup.  Usually set to the server
                                name that you are backing up.
    
     -d, --date datestamp       Date stamp for this backup set.  The format is in
                                time_t format, sames as the output of the "date
                                +%s" command.
    
     -v,                        Verbose output

### snebu restore
    Usage: snebu restore -n backupname -d datestamp [ file_list... ]
     Generates a tar file containing files from a given backup set.  Pipe
     the output of this command into a tar command to actually restore
     files.
    
    Options:
     -c, --config config_file   Name of the configuration file.  Default is
                                /etc/snebu.conf.
    
     -n, --name backupname      Name of the backup.  Usually set to the server
                                name that you are backing up.
    
     -d, --date datestamp       Date stamp for this backup set.  The format is in
                                time_t format, sames as the output of the "date
                                +%s" command.
         --graft /path/name/=/new/name/ 
                                Re-write path names beginning with "/path/name/"
                                to "/new/name/"

### snebu listbackups
    Usage: snebu listbackups [ -n hostname [ -d datestamp ]] [ file_list... ]
     With no arguments specified, "listbackups" will return a list of all
     systems that are contained in the backup catalog.  Otherwise, when
     specifying the -n parameter, a list of backup sets for that host is
     returned.
    
    Options:
     -c, --config config_file   Name of the configuration file.  Default is
                                /etc/snebu.conf.
    
     -n, --name backupname      Name of the backup.  Usually set to the server
                                name that you are backing up.
    
     -d, --date datestamp       Date stamp for this backup set.  The format is in
                                time_t format, sames as the output of the "date
                                +%s" command.

### snebu expire
    Usage: snebu expire [ -n hostname -d datestamp ] or [ -a days -r schedule [ -n hostname ]]
     Removes backup sessions from the snebu backup catalog database.  A
     specific backup session can be purged by providing the "-n" and "-d"
     options, or all backups that are part of a given retention schedule
     (specified with "-r", and optionally from a given host, with the "-n"
     option) that are older than a given number of days ("-a") are removed.
    
    Options:
     -c, --config config_file   Name of the configuration file.  Default is
                                /etc/snebu.conf.
    
     -n, --name backupname      Name of the backup.  Usually set to the server
                                name that you are backing up.
    
     -d, --date datestamp       Date stamp for this backup set.  The format is in
                                time_t format, sames as the output of the "date
                                +%s" command.
    
     -r, --retention schedule   Retention schedule for this backup set.  Typical
                                values are "daily", "weekly", "monthly", "yearly".
     -a, --age #days            Expire backups older than #days.
    
     -m, --min-keep #           When expiring with the "-a" flag, keep at least
                                this many of the most recent backups for a given
                                hostname/retention level.

### snebu purge
    Usage: snebu purge
     Permanently removes files from disk storage that are no longer
     referenced by any backups. Run this command after running "snebu
     expire".

