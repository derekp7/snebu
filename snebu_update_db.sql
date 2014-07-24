alter table file_entities rename to file_entities_old;
alter table received_file_entities rename to received_file_entities_old;
alter table needed_file_entities rename to needed_file_entities_old;

create table if not exists file_entities ( 
    file_id       integer primary key, 
    ftype         char, 
    permission    char, 
    device_id     char, 
    inode         char, 
    user_name     char, 
    user_id       integer, 
    group_name    char, 
    group_id      integer, 
    size          integer, 
    sha1           char, 
    cdatestamp    integer, 
    datestamp     integer, 
    filename      char, 
    extdata       char default '', 
    xheader       blob default '', 
constraint file_entities_c1 unique ( 
    ftype, 
    permission, 
    device_id, 
    inode, 
    user_name, 
    user_id, 
    group_name, 
    group_id, 
    size, 
    sha1, 
    cdatestamp, 
    datestamp, 
    filename, 
    extdata, 
    xheader ));

create table if not exists received_file_entities ( 
    file_id       integer primary key, 
    backupset_id  integer, 
    ftype         char, 
    permission    char, 
    user_name     char, 
    user_id       integer, 
    group_name    char, 
    group_id      integer, 
    size          integer, 
    sha1          char, 
    datestamp     integer, 
    filename      char, 
    extdata       char default '', 
    xheader       blob default '', 
foreign key(backupset_id) references backupsets(backupset_id), 
    unique ( 
    backupset_id, 
    ftype, 
    permission, 
    user_name, 
    user_id, 
    group_name, 
    group_id, 
    size, 
    sha1, 
    datestamp, 
    filename, 
    extdata, 
    xheader ));

create table if not exists needed_file_entities ( 
backupset_id  integer, 
device_id     char, 
inode         char, 
filename      char, 
infilename    char, 
size          integer, 
cdatestamp    integer, 
foreign key(backupset_id) references backupsets(backupset_id), 
unique ( 
backupset_id, 
filename,
infilename ));


insert into file_entities 
    ( file_id, ftype, permission, device_id, inode, user_name, user_id,
    group_name, group_id, size, sha1, cdatestamp, datestamp, filename,
    extdata, xheader)
    select file_id, ftype, permission, device_id, inode, user_name, user_id,
    group_name, group_id, size, sha1, datestamp, datestamp, filename,
    extdata, '' from file_entities_old;

insert into received_file_entities 
    ( file_id, backupset_id, ftype, permission, user_name, user_id,
    group_name, group_id, size, sha1, datestamp, filename, extdata, xheader)
    select file_id, backupset_id, ftype, permission, user_name, user_id,
    group_name, group_id, size, sha1, datestamp, filename, extdata, ''
    from received_file_entities_old;

insert into needed_file_entities
    (backupset_id, device_id, inode, filename, infilename, size, cdatestamp)
    select backupset_id, device_id, inode, filename, infilename, size, '' 
    from needed_file_entities_old;
