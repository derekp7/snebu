Introduction
====

Snebu -- the Simple Network Backup Utility, Systems Nominal, Everything's Backed Up

Snebu is an efficient, incremental, snapshot-style, de-duplicating, compressing, encrypting, database-backed, multi-host, client/server, simple, secure, disk-based backup system for Unix / Linux systems.

Super-quick setup
----
* After creating or editing `/etc/snebu.conf` and `/etc/snebu-client.conf` as specified below...
* And, if using encryption, generate a key
  ```tarcrypt genkey -f myhost.key```

* If backing up to a local resource (locally attached storage):
  ```
  snebu-client backup -v -k myhost.key /home/mydir
  ```

* If backing up to a remote server:
  ```
  snebu-client backup -v --remote-server central-backup-server -k myhost.key \
    -k corporate-skeleton.key
  ```

* Or, if in a larger environment and you want to centrally manager backups from the backup server, write a script on the server and schedule it via cron with commands such as:
  ```
  snebu-client backup --remote-client host1.example.com -k key1.key -k corp.key
  snebu-client backup --remote-client host2.example.com -k key2.key -k corp.key
  ```

The optional `-k` parameters above specify encryption keys.  These key files contain an RSA key pair, with the private key encrypted.  The key data is stored on the backup server, and during a restore operation you will be prompted for the passphrase protecting the private key.  The key file does not need to be present on the target client during a restore operation.

You can specify more than one key, in which case the passphrase for any of the keys can be used during restore.

If you don't specifiy a directory to back up, default include/exclude lists are processesed as specified in /etc/snebu-client.conf.

See the quick start guide below for more details.  As you can see, you can back up a single host to some attached media, or to a remote host (even something simple as a Rapsberry Pi).  Or you can 

Features
----

* Efficient  
  Incremental -- transfers only modified data across the network.  
  Snapshot-style -- Each backup represents the complete state of the system.  
  De-duplicating  -- File-level de-duplication and compression, including de-dup across multiple hosts.  

* Compresed/encrypted -- Uses built-in lzo based encryption, with optional RSA public key based encryption.  With public key encryption, you don't have to be concerned with leaving a plain text encryption key on the client, or losing the encryption key.  The encryption also utilizes an HMAC key to provide authenticity of the backup, and to allow for de-duplication of encrypted backups (including across multiple hosts, as long as the same key file is used on that group of hosts).

* Database-backed -- Metadata information is stored in an SQLite database.

* Multi-host -- Multiple systems can be backed up to a central target.

* Client-server -- Hosts can either push backups to a central backup server, or the server can pull backups from individual clients.

* Simple -- System consists of a single compiled binary, `snebu`, plus a front-end client, `snebu-client` written in Bash shell script.  If used with multiple hosts, communications all happen over ssh, and there are no agent programs that need to be installed on remote hosts.  Backed up files are stored in a "vault" directory, with the metadata in a light weight SQLite database file.  (SQLite requires no database server processes, all functionality is built into the SQLite library linked against the main `snebu` binary).

* Secure -- Backup server can pull backups from hosts, or clients can push backups to the central backup server using minimal permission accounts (i.e., you can configure an account to be able to submit, but not delete backups, or restrict restores to only specific backup sets).
Encryption is also provided by a separate isolated process, `tarcrypt`, which acts as a filter for tar files, compressing/encrypting the data contents while allowing the metadata to be processed and indexed by the backup server database.

Audience
----

Snebu is intended primarily for Linux based systems, or any Unix style system with GNU tar, GNU find, and ssh.  Also works well under Windows with Cygwin.

Other Benefits
====

* Easy to set up  
  There system consists of two programs:  
  `snebu-client` - This is a simple shell script for interacting with the backend process, along with gathering the files to include in a given backup set.  
  `snebu` -- This is the backend process which stores backup files in a disk-based vault, maintaining metadata about the files and backup sets in an SQLite-based backup catalog.

  There are no complicated daemons to configure, or heavy database systems that need to be installed.  All the core logic is self-contained in the snebu binary.

* Suitable for backing up a single system to an attached external disk, backing up to a separate network server, or backing up a number of hosts with backups initiated from the central backup server.

* No client software installation required.  If backups are initiated from a central backup server, then communications to the clients are preformed over SSH.  The only requirements are that the backup account on the   server is permitted appropriate access to the client (via ssh keys), and the client have the minimal versions of  GNU find and tar installed (this is only a concern with ancient Linux installations, or Unix systems without GNU tools installed).

* Works similar to rsync-based backup tools (by providing snapshot incremental-forever backups), but provides compression and a self-contained database-backed (SQLite) backup catalog.  One of the many benefits of having a separate backup catalog is this allows the backend to execute under a regular (non-root) utility account.

* File-level de-duplication is supported, including de-duplication of files across backup sets, and across multiple backup clients.

* Built using standard tools and protocols.  File metadata gathering is provided by the "find" command (GNU find  is required), files are transfered using "tar" format, the backup catalog is in an SQLite database file, and files are stored in the disk-based vault compressed with the LZO library, and compatible with the "lzop" compression program.


Quick-start guide
====

Concepts
----

The Snebu backup system is composed of a backend process, `snebu`, and a front-end client called `snebu-client`.  The client gathers a list of files to back up (using the `find` command), sends this list to the backend, and gets back a list of files that are needed to complete an incremental backup.  These files are then sent to the backend using the Unix `tar` format.

Backups are stored in backup sets.  A backup set is uniquely identified by the backup name (typically the host name getting backed up), and a datestamp in the form of a Unix time_t value (essentially, a count of the number of seconds since Jan 1, 1970).  This value functions as a serial number, and is used by the expiration process for purging old backups.

Each backup set has a retention schedule attached to it, specified by the `-r` flag.  The retention schedule is used by the expiration process to, for example, expire all daily backups older than 10 days, or all monthly backups older than 6 months.  Anything can be used for for a schedule name, but typical values are `daily`, `weekly`, `monthly`, `yearly`, and `archive`.  If not specified, then the `snebu-client` script will automatically pick a retention schedule based on the date (Sunday through Friday are daily, Saturday is weekly, and the 1st of the month is monthly).

When a backup is requested, the backend will determine which files it already has (by comparing meta data such as file name, size, last modification time, and various other attributes).  A list of files that are already on the backup server is added to the current backup set.  The remaining files are then requested, and are added to the backup set when they are received.

File contents are stored and referenced by using the SHA1 hash of the file contents.  Therefore, file level de-duplication is achieved across all backups stored on the backup server.  In addition, files are stored compressed in an lzop compatible format.  This allows for recovery of files even outside of the backup utility.

Setting up a local backup
----

This procedure assumes that both `snebu` and `snebu-client` are installed, and you will be backing up to a drive that is mounted under /media/snebu.  These steps will be run as the root user.  In the examples, the host name that is getting backed up is called `zeus`  The backup retention schedules are automatically determined in these examples (use `-r` to override)

1) Create a user `snebu`, belonging to the group `snebu`.

2) Install the `snebu` package, or run `make; make install` from the source directory to install the system.

    This should install `snebu` in `/usr/bin`, or `/usr/local/bin`, with it owned by user:group `snebu:snebu`, and with file mode 4550.

3) Mount a drive under /media/snebu

4) Verify or create the configuration file `/etc/snebu.conf` with the following:

        meta=/media/snebu/catalog
        vault=/media/snebu/vault

    The meta directory is where the backup catalog is stored (in an SQLite DB).  The vault directory contains all the backup file contents.

    Note: During operation, the backup catalog database receives a large number of random I/O operations.  Therefore, if it is residing on a slower device, such as a 2.5" low-powered USB drive, the performance may be unacceptably slow.  For this situation, better performance can be achieved by mounting an SSD on the catalog directory.

4) Create the directories from the `snebu.conf` file, and give ownership to the snebu user and group.

        mkdir -p /media/snebu/meta
        mkdir -p /media/snebu/vault
        chown -R snebu:snebu /media/snebu/

5) Create a file `/etc/snebu-client.conf` with the following:

        EXCLUDE=( /tmp /var/tmp /mnt /media/snebu )

    By default, the files to be backed up included all mounted Linux filesystems of the types ext2, ext3, ext4, btrfs, xfs.  This is the same as specifying the following line in the `snebu-client.conf` file:

        INCLUDE=( $(mount |egrep "ext[234]|btrfs" |awk '{print $3}') )

    If you want to list specific directories to backup, list them in an INCLUDE line in the `/etc/snebu-client.conf` file:

        INCLUDE=( /dir1 /dir2 /dir3 )

    Or, if you want to add to the default include:

        INCLUDE=( "${INCLUDE[@]}" /dir1 /dir2 /dir3 )

6) Change user to `snebu`, and set up user permissions for root

        snebu permissions -a -c '*' -n '*' -u root

7) Run a test backup:

        snebu-client backup -v

    You should see some status messages.  The first will indicate that the system is gathering a file manifest, followed by a line indicating the current number of bytes transferred along with percentage completed.

    If you see any error messages related to being unable to open the backup catalog file, check to make sure the `snebu` user has read/write permissions to the file / directory.

    Note, you can also override the default INCLUDE list on the `snebu-client` command line:

    snebu-client backup -v /dir1 /dir2

    See the `snebu-client` detailed documentation for the list of available parameters.  Specifically, look at the `-r` (retention schedule), and `-n` (backup name) parameters.

8) Once the backup is completed, you can use the following to list the backups:

        snebu-client listbackups -v

    Which should output the names of the backups that are available:

        zeus
            1389677695 / daily / Mon Jan 13 23:34:55 2014

9) To get a list of files that are included:

        snebu-client listbackups --name zeus --datestamp 1389677695 |more

10) To restore a given file, pick one from the list generated in the step above, and:

        snebu-client restore --name zeus --datestamp 1389677695 '/path/to/file'

    Or, to restore a directory and all contents underneath,

        snebu-client restore --name zeus --datestamp 1389677695 '/path/to/directory/*'

    And, to specify a target directory to restore to, use the -C parameter

        snebu-client restore --name zeus --datestamp 1389677695 \
	    -C /tmp '/path/to/directory/*'


Backing up to a remote server
----

This section will describe how to back up a client, in this case called `zeus`, to a remote backup server, called `jupiter`.

1) On the backup server, follow steps 1 thru 4 from above (Set up a `snebu` user, install the software, create the config file, and set up the backup target directories for the vault and backup catalog locations).  Then follow step 5, create a snebu-client.conf file in /etc, on the client system.

2) On the backup server `jupiter`, create a user for the client, `zeus`, adding it to the snebu user group.
For security purposes, we will only allow clients specific access to the server, by creating a dedicated account for each client host.

        useradd zeus -G snebu

3) Now add permissions this user in `snebu`

        su - snebu
        snebu permissions --add -u zeus -c backup -n zeus
        snebu permissions --add -u zeus -c restore -n zeus
        snebu permissions --add -u zeus -c listbackups -n zeus

    This will give the user `zeus` permission to submit backups, request restores, and list backups for backups named `zeus`.

4) Add root's ssh public key from the client, to the target user on the backup server.  This involves generating a key pair as root on `zeus` if it doesn't already exist:

        ssh-keygen -t rsa

    then adding the key to the `/home/zeus/.ssh/authorized_keys` file on `jupiter`.  Test this out by running ssh from root on `zeus`, to `zeus@jupiter`.  Consult your ssh documentation for any troubleshooting tips on using key-based authentication if you are having any issues.

5) Place a copy of ssh-client on the client, in a convenient location, such as /usr/local/bin.

6) On the client, run the command:

        snebu-backup -n zeus --backup-server jupiter --backup-user zeus -v

    Just as in the previous section, you should see output indicating the current status of the backup operation.

7) To list backups, run:

        snebu-client listbackups --backup-server jupiter \
            --backup-user zeus --name zeus

    Which should output the names of the backups that are available:

        zeus
            1389677695 / daily / Mon Jan 13 23:34:55 2014

8) To restore a given file to a given location (such as `/tmp/`:

        snebu-client restore --backup-server jupiter --backup-user zeus \
            --name zeus --datestamp 1389677695 -C /tmp '/path/to/file'


Backing up remote clients from a backup server
----

If you have a number of systems to back up, it may be desirable to initiate all backups from the backup server.  In this model, the `snebu` user account on the backup server will need SSH permissions to access root on the clients.  This may be preferable, as it avoids having to give each client remote access to the backup server.  However, that means the clients have to trust the backup server with root access.  Another benefit is there is nothing to install on the clients, other than inserting a key into root's `authorized_keys` file.

Note, you can also specify a non-privileged account on the target clients, by allowing that account to sudo to root to access the files to backup or restore.  This is the method used in the following example.

This section will describe how to back up a remote host, in this case called `zeus`, initiated from the backup server, called `jupiter`.  Access from `snebu` on `jupiter` will be via the account `backup` on `zeus`, which is listed in /etc/sudoers on `zeus`

1)  Follow steps 1 thru 5 from the section `Setting up a local backup`, on the backup server `jupiter`.  (Set up a `snebu` user, install the software, create the config file, and set up the backup target directories for the vault and backup catalog locations, and create a `snebu-client.conf` file in `/etc`, on the backup server).

2) As the user `snebu` on the backup server `jupiter`, create an SSH key pair if it doesn't already exist

        ssh-keygen -t rsa -N ""

3) Create a user `backup` on the remote host `zeus`

        useradd backup

4) Add the contents of the public key file belonging `snebu` on `jupiter` (`/home/snebu/.ssh/id_rsa.pub`), to the `authorized_keys` file belonging to `backup` on `zeus` (`/home/backup/.ssh/authorized_keys`).  Make sure the `authorized_keys` file, and `.ssh` directory is owned by `backup`, and has the appropriate permissions (consult your local `ssh` documentation if needed).

5) On `zeus`, add `backup` to /etc/sudoers giving it access to root, with a line similar to below:

        backup  ALL=(ALL)       NOPASSWD: ALL

6) Test that this works.  From the `snebu` user on `jupiter`, run the following:

        ssh backup@zeus

    Then, assuming the logon to `zeus` worked, run the following from `backup` on `zeus` to see if it can access root:

        sudo id

7) Initiate a test backup from the `backup` user on `jupiter`:

        snebu-client backup --remote-client zeus --sudo backup -v


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
    
        validate [ -n backupname ] [ -d datestamp ]
    
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

     -k, --encryption-key       Turns on encryption, and specifies encryption
                                key location.  May be specified more than once to
                                encrypt with multiple keys.
                                
                                The program "tarcrypt" needs to be present on the
                                client for this option.  Keys are generated with
                                the command:

                                  tarcrypt genkey -f keyname

     -C, --changedir path       Changes to the given directory path before
                                backing up or restoring.
    
         --graft /path/name/=/new/name/
                                Re-write path names beginning with "/path/name/"
                                to "/new/name/"
    
     -f, --force-full           Force a full backup
    
         --remote-client hostname
                                Host name / IP address of remote host.  Used to
                                backup a remote host to local backup server.
    
         --remote-user userid
                                User ID for remote remote-client.  Defaults to
                                root.
    
         --sudo userid
                                Initial login User ID for remote remote-client.
                                This ID uses sudo to switch to remote-user once
                                logged in.
    
         --backup-server hostname
                                Host name / IP address of backup server.  Used to
                                backup to a remote server.
    
         --backup-user userid
                                User ID for remote backup-server.
    
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
    
         --decrypt              Turns on decryption.  Requires "tarcrypt" to be
                                on the client.  Password(s) will be promted for
                                during restore.

     -C, --changedir path       Changes to the given directory path before
                                backing up or restoring.
    
         --graft /path/name/=/new/name/
                                Re-write path names beginning with "/path/name/"
                                to "/new/name/"
    
         --remote-client hostname
                                Host name / IP address of remote host.  Used to
                                backup a remote host to local backup server.
    
         --remote-user userid
                                User ID for remote remote-client.  Defaults to
        root.
    
         --sudo userid
                                Initial login User ID for remote remote-client.
                                This ID uses sudo to switch to remote-user once
                                logged in.
    
         --backup-server hostname
                                Host name / IP address of backup server.  Used to
                                backup to a remote server.
    
         --backup-user userid
                                User ID for remote backup-server.
    
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

### snebu-client validate
    Usage: snebu-client validate [ -n backupname ] [ -d datestamp ] [ file-list ]
     Compares the contents a given backup session identified by "-n" and "-d"
     parameters, to what is on the client.  Use the "listbackups" subcommand to
     get a list of available
     backup sessions.
    
    Options:
     -c, --config config_file   Name of the configuration file.  Default is
                                /etc/snebu-client.conf.
    
     -n, --name backupname      Name of the backup.  Usually set to the server
                                name that you are backing up.
    
     -d, --date datestamp       Date stamp for this backup set.  The format is in
                                time_t format, sames as the output of the "date
                                +%s" command.
    
     -C, --changedir path       Changes to the given directory path before
                                validating
    
         --remote-client hostname
                                Host name / IP address of remote host.  Used to
                                backup a remote host to local backup server.
    
         --remote-user userid
                                User ID for remote remote-client.  Defaults to
                                root.
    
         --sudo userid
                                Initial login User ID for remote remote-client.
                                This ID uses sudo to switch to remote-user once
                                logged in.
    
         --backup-server hostname
                                Host name / IP address of backup server.  Used to
                                backup to a remote server.
    
         --backup-user userid
                                User ID for remote backup-server.
    
     [ file-list ]              List of files to validate.  Defaults to all.

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


