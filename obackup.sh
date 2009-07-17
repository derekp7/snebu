#!/bin/bash
snebu="ssh -o StrictHostKeyChecking=no backup@backuphost /usr/local/bin/snebu.sh"

if ! args=$(getopt -l "name:,retention:" -o "n:r:d" -- "$@")
then
    exit 1
fi
eval set -- "$args"
while [ -n "$1" ]
do
    case $1 in
	-n|--name) servername=$2; shift; shift;;
	-r|--retention) schedule=$2; shift; shift;;
	-d) dbback=1; shift;;
	--) shift; break;;
    esac
done

[ -z "${servername}" ] && servername=$(uname -n)
[ -z "${schedule}" ] && schedule="daily"
[ -z "${datestamp}" ] && datestamp=$(date +%s)

include="$(mount |grep ext[234] |awk '{print $3}')"
#FIND=/usr/local/bin/gfind
FIND=/bin/find
sql() {
    echo "Executing $1 for $ORACLE_SID" >&2
    su - oracle -c "[ -n \"${ORACLE_SID}\" ] && ORACLE_SID=\"${ORACLE_SID}\"; sqlplus -s / as sysdba" <<-EOT
	set pages 0
	set heading off
	set feedback off
	$1
	exit
	EOT
}
ora_hbb() {
    sql "alter database begin backup;"
}
ora_hbe() {
    sql "alter database end backup;
	alter system archive log current;
       	alter database backup controlfile to '${archlogdest}/control0x.ctl' reuse;"
}

dbfiles() {
dbfilelist=$(sql "select name from v\$datafile;")
archlogdest=$(sql "select destination from v\$archive_dest where destination is not null;")
controlfilelist=$(sql "select name from v\$controlfile;")
loglist=$(sql "select member from v\$logfile;")
spfile=$(sql "select value from v\$parameter where name = 'spfile';");
miscdbf="$ORACLE_HOME/dbs/*${ORACLE_SID}*"
}

for i in $(egrep -v "^$|^#" /etc/oratab |cut -d: -f1)
do
    ORACLE_SID=$i
    dbfiles
    excludefiles="$excludefiles $dbfilelist $loglist $controlfilelist $archlogdest $controlfilelist"
done
unset ORACLE_SID


findnodb() {
$FIND ${include} -xdev $(for i in ${excludefiles}; do echo "-path $i -prune -o"; done)  \( -type f -o -type d \) -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0" -o \( -type l -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0%l\0" \)
}

finddbfiles1() {
$FIND ${include} -xdev \( $(for i in ${dbfilelist}; do echo "-path $i -prune -o"; done) -false \) -a  \( \( -type f -o -type d \) -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0" -o \( -type l -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0%l\0" \) \)
}
finddbfiles2() {
archloglist=$(sql "select name from v\$archived_log where name is not null;")
$FIND ${include} -xdev \( $(for i in ${archloglist} ${controlfilelist} ${miscdbf} ~oracle/dbs/*${sid}*; do echo "-path $i -prune -o"; done) -false \) -a  \( \( -type f -o -type d \) -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0" -o \( -type l -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0%l\0" \) \)
}

egrep -v "^$|^#" /etc/oratab |awk 'BEGIN { FS = ":" }; { print $1, $2 }' |\
while read ORACLE_SID ORACLE_HOME junk
do
    if [ "${dbback}" = 1 ]
    then
	ora_hbb
	tar -P -S --no-recursion --null --files-from <(finddbfiles1 |${snebu} newbackup --name ${servername}-${ORACLE_SID}-db --retention ${schedule} --datestamp ${datestamp}) -cvf - |lzop |\
	$snebu submitfiles --name ${servername}-${ORACLE_SID}-db --retention ${schedule} --datestamp ${datestamp}
	ora_hbe
    fi
    tar -P -S --no-recursion --null --files-from <(finddbfiles2 |${snebu} newbackup --name ${servername}-${ORACLE_SID}-arch --retention ${schedule} --datestamp ${datestamp}) -cvf - |lzop |\
    $snebu submitfiles --name ${servername}-${ORACLE_SID}-arch --retention ${schedule} --datestamp ${datestamp}
done

tar -P -S --no-recursion --null --files-from <(findnodb |${snebu} newbackup --name ${servername} --retention ${schedule} --datestamp ${datestamp}) -cvf - |lzop |\
$snebu submitfiles --name ${servername} --retention ${schedule} --datestamp ${datestamp}
