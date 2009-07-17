#!/bin/bash
# How to launch snebu.sh
snebu="ssh -o StrictHostKeyChecking=no backup@backuphost /usr/local/bin/snebu.sh"
#snebu="/usr/local/bin/snebu.sh"

# Directories to include
include="$(mount |grep ext[234] |awk '{print $3}')"

# Directories to exclude
exclude=( /tmp /var/tmp )

# File patterns to exclude
excludepat=( "*.dbf" )

FIND=/usr/bin/find

if ! args=$(getopt -l "name:,retention:,md5" -o "n:r:m" -- "$@")
then
    exit 1
fi
eval set -- "$args"
while [ -n "$1" ]
do
    case $1 in
	-n|--name) servername=$2; shift; shift;;
	-r|--retention) schedule=$2; shift; shift;;
	-m|--md5) usemd5=1 shift;;
	--) shift; break;;
    esac
done

[ -z "${servername}" ] && servername=$(uname -n)
[ -z "${schedule}" ] && schedule="daily"
[ -z "${datestamp}" ] && datestamp=$(date +%s)

j=0
for i in ${exclude[@]}
do
    findexclude[$((j * 4 + 1))]="-path"
    findexclude[$((j * 4 + 2))]="$i"
    findexclude[$((j * 4 + 3))]="-prune"
    findexclude[$((j * 4 + 4))]="-o"
    ((j++))
done

j=0
for i in ${excludepat[@]}
do
    findexcludepat[$((j * 3 + 1))]="-name"
    findexcludepat[$((j * 3 + 2))]="$i"
    findexcludepat[$((j * 3 + 3))]="-o"
    ((j++))
done


findcmd() {
$FIND ${include} -xdev "${findexclude[@]}" "${findexcludepat[@]}" \( -type f -o -type d \) -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0" -o -type l -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0%l\0"
}
findcmd5() {
$FIND ${include} -xdev "${findexclude[@]}" "${findexcludepat[@]}" -type f -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t" -exec bash -c 'md5sum "{}" | { read a b; echo -e "$a\c"; };' \; -printf "\t%T@\t%p\0" -o  -type d -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0" -o -type l -printf "%y\t%#m\t%D\t%i\t%u\t%U\t%g\t%G\t%s\t0\t%T@\t%p\0%l\0"
}

if [ "${usemd5}" = 1 ]
then
    dofind=findcmd5
else
    dofind=findcmd
fi
tar -P -S --no-recursion --null --files-from <(${dofind} |${snebu} newbackup --name ${servername} --retention ${schedule} --datestamp ${datestamp}) -cvf - |lzop |\
$snebu submitfiles --name ${servername} --retention ${schedule} --datestamp ${datestamp}
