#!/bin/bash

# newbackup
# submitfiles
# finalize

vault=/var/backups/vault
meta=/var/backups/meta

command="$1"
shift

export LANG=C
case "$command" in 
    newbackup|submitfiles|finalize|listbackups|restore|expire)
	case "$command" in
	    newbackup|submitfiles|finalize|listbackups) loptstring="name:,datestamp:,retention:,pattern:"; soptstring="n:d:r:p:";;
	    restore) loptstring="name:,datestamp:,retention:,pattern:"; soptstring="n:d:r:p:";;
	    expire) loptstring="name:,retention:,age:"; soptstring="n:r:a:";;
	esac
	if ! args=$(getopt -l "$loptstring" -o "$soptstring" -- "$@")
	then
	    exit 1
	fi
	eval set -- "$args"
	while [ -n "$1" ]
	do
	    case "$1" in
		-n|--name) svrname=$2; shift; shift;;
		-d|--datestamp) datestamp=$2; shift; shift;;
		-a|--age) age=$2; shift; shift;;
		-r|--retention) schedule=$2; shift; shift;;
		-p|--pattern) pattern=$2; shift; shift;;
		--) shift; break;;
	    esac
	done
	;;
    *)
	cat <<-EOT
	Usage:
	snebu.sh
	    newbackup -n backupname -d datestamp -r retention_schedule

	    submitfiles -n backupname -d datestamp -r retention_schedule

	    listbackups [ -n backupname [ -d datestamp [ -p regex_search_pattern ] ] ]

	    restore -n backupname -d datestamp [ -p regex_search_pattern ]

	    expire -n backupname -r retention_schedule -a age (in days)

	EOT
	exit 1;;
esac
bkname="${svrname}_${schedule}_${datestamp}"
curdatestamp=$(date +%s)

newbackup()
{
    # Convert null terminated lines in input to newline, and escape special characters in file name
    bklist_encode |\
    awk '
    BEGIN { FS = "\t" }
    {
	if ($1 == "d") {
	    filename = sprintf("%s/", $12)
	    filesize = 0
	}
	else if ($1 == "l") {
	    filename = $12
	    filesize = 0
	}
	else {
	    filename = $12
	    filesize = $9
	}
    }
    { split($11, timestamp, ".") }
    {
	printf("%s\t%.4d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5, $6, $7, $8, filesize, $10, timestamp[1], filename, $13)
    }' >${meta}/tmp/${bkname}.input


    # Create list of required files; un-escape special characters in files and convert to null terminated
    join -t$'\t' -j1 1 -j2 1 -v2 -o 2.2 2.3 2.4 2.5 2.6 2.7 2.8 2.9 2.10 2.11 2.12 2.13 2.14 \
    <(
	join -t$'\t' -j1 10 -j2 1 -o 1.1 1.2 1.3 1.4 1.5 1.6 1.7 1.8 1.9 1.10 1.11 1.12 1.13 <(
	    cat ${meta}/${svrname}_*_*.backupset |sort -t$'\t' +9 -10
	) <(
	    find $vault -name "*.lzo" -type f -print |\
	    awk '
	    BEGIN { FS = "/"; printf("0\n") }
	    { printf("%s%s\n", $(NF - 1), substr($NF, 1, length($NF) - 4)) }' |sort
	) |\
        awk 'BEGIN { FS = "\t" }
        {
            ft = $1
            if ($1 == "S") {
                ft = 0
                thirteen=""
	    }
	    else
		thirteen=$13
        }
        {
	    printf("%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s\\%s\n",
	    ft, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, thirteen)
	    printf("%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s\\%s\n",
	    ft, $2, $3, $4, $5, $6, $7, $8, $9, "0", $11, $12, thirteen)
	}' |\
        sort +0 -1 -u 
    ) \
    <(  cat ${meta}/tmp/${bkname}.input |\
        awk 'BEGIN { FS = "\t" }
        {
            if ($1 == "f")
                ft = 0
            else if ($1 == "l")
                ft = 2
            else if ($1 == "d")
                ft = 5
        }
        { printf("%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s\\%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
        ft, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)}' |\
        sort +0 -1 -u 
    ) |
    tee ${meta}/tmp/${bkname}.needed |\
    awk '
    BEGIN { FS = "\t" }
    { printf("%s\n", $12)}' |bklist_decode
}

submitfiles()
{
    # Extract files from input tar stream into MD5 file names, and separate meta data manifest list
    lzop -d |tarburst -d $vault -m $meta/tmp/${bkname}.received.in

    # Process (dereference) hard links in manifest

    for i in 0 2 5 S
    do
      if [ $i = S ]
      then
        joinparams='2.1 2.2 2.3 2.4 2.5 2.6 2.7 2.8 2.9 1.10 2.11'
      else
        joinparams='2.1 2.2 2.3 2.4 2.5 2.6 2.7 2.8 2.9 1.10'
      fi
      join  -t$'\t' -j1 11 -j2 10 -o $joinparams <(
	cat ${meta}/tmp/${bkname}.received.in |\
	grep '^1'$'\t' |\
	sort -t$'\t' +10 -11
      ) <(
	cat ${meta}/tmp/${bkname}.received.in |\
	grep '^'$i$'\t' |\
	sort -t$'\t' +9 -10 
      )
    done >${meta}/tmp/${bkname}.received

    egrep -v '^1'$'\t' <${meta}/tmp/${bkname}.received.in >>${meta}/tmp/${bkname}.received
    finalize

}
finalize()
{
join -t$'\t' -j1 10 -j2 12 -o 1.1 1.2 2.3 2.4 1.3 1.4 1.5 1.6 1.7 1.8 1.9 1.10 1.11 \
    <( cat ${meta}/tmp/${bkname}.received |sort +9 -10 -u) \
    <( cat ${meta}/tmp/${bkname}.input |sort +11 -12 -u) >${meta}/tmp/${bkname}.backupset.1


# Input files that are invault
join -t$'\t' -j1 1 -j2 1 -o 1.2 1.3 1.4 1.5 1.6 1.7 1.8 1.9 1.10 1.11 1.12 1.13 1.14 \
    <(  cat ${meta}/${svrname}_*_*.backupset |\
        awk 'BEGIN { FS = "\t" }
        {
            ft = $1
            if ($1 == "S") {
                ft = 0
                thirteen=""
	    }
	    else
		thirteen=$13
        }
        { printf("%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s\\%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
        ft, $2, $3, $4, $5, $6, $7, $8, $9, "0", $11, $12, thirteen,
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)}' |\
        sort +0 -1 -u
    ) \
    <(  cat ${meta}/tmp/${bkname}.input |\
        awk 'BEGIN { FS = "\t" }
        {
            if ($1 == "f")
                ft = 0
            else if ($1 == "l")
                ft = 2
            else if ($1 == "d")
                ft = 5
        }
        { printf("%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s\\%s\n",
        ft, $2, $3, $4, $5, $6, $7, $8, $9, "0", $11, $12, $13)}' |\
        sort +0 -1 -u
    ) >${meta}/tmp/${bkname}.backupset.2


# Join two backupsets
(
    cat ${meta}/tmp/${bkname}.backupset.1
    join -t$'\t' -j1 12 -j2 12 -v2 -o 2.1 2.2 2.3 2.4 2.5 2.6 2.7 2.8 2.9 2.10 2.11 2.12 2.13 \
        <(  cat ${meta}/tmp/${bkname}.backupset.1 |sort +11 -12 -u ) \
        <(  cat ${meta}/tmp/${bkname}.backupset.2 |sort +11 -12 -u )
) |sort +11 -12 >${meta}/${bkname}.backupset

}

listbackups()
{
    if [ -z "${svrname}" ]
    then
	echo "Server list:"
	for i in $(ls ${meta}/*_*_*.backupset |cut -d_ -f1 |sort -u)
	do
	    basename $i
	done
    elif [ -n "${svrname}" -a -z "${datestamp}" ]
    then
	echo "Backups for ${svrname}"
	printf "%-12s  %-30s\n" "Serial" "Date"
	echo "------------- ------------------------------"
	for i in $(ls ${meta}/${svrname}_*_*.backupset |cut -d_ -f3 |cut -d. -f1 |sort -u)
	do
	    printf "%-12s  %-20s\n" "$i" "$(date -d @$i)"
	done
    else
	cat ${meta}/${svrname}_*_${datestamp}.backupset |cut -d$'\t' -f12 |sort |\
	( [ -n "${pattern}" ] && grep "${pattern}" || cat )
    fi

}
dorestore()
{
    if [ -z "${svrname}" -o -z "${datestamp}" ]
    then
	echo "Requires server and datestamp"
	exit 1
    fi
    backupset=$(ls ${meta}/${svrname}_*_${datestamp}.backupset |tail -1)
    if [ -f "${backupset}" ]
    then
	cat ${backupset} |\
	(
	    if [ -n "${pattern}" ]
	    then
		awk 'BEGIN { FS = "\t" }
		$12 ~ "'"${pattern}"'" { print $0 }'
	    else
		cat
	    fi
	) |\
	sort +2 -4 |awk '
	BEGIN { FS = "\t" }
	{
	    if ($1 == "5")
		printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $5, $6, $7, $8, $9, $10, $11, $12)
	    else if ((($1 == "0" && old_1 == "0") || ($1 == "S" && old_1 == "S")) && $3 == old_3 && $4 == old_4 && $10 == old_10)
		printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", 1, $2, $5, $6, $7, $8, $9, $10, $11, $12, old_12)
	    else if ($1 == "0" || $1 == "S")
		printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	    else if ($1 == "2")
		printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	}
	{
	    old_1 = $1
	    old_3 = $3
	    old_4 = $4
	    old_10 = $10
	    old_12 = $12
	}' |sort -t$'\t' +9 -10 |\
	gentar -m - -d ${vault} |lzop
    fi
}
[ "${command}" = "restore" ] && command="dorestore"

expire()
{
    if [ -z "${svrname}" ]
    then
	echo "Requires server name"
	exit
    fi
    if [ -z "${schedule}" ]
    then
	echo "Requires retention schedule"
	exit
    fi
    if [ -z "${age}" ]
    then
	echo "Requires age"
	exit
    fi
    [ ! -d "${meta}/attic" ] && mkdir "${meta}/attic"
    purgelist=( $(
    ls ${meta}/${svrname}_${schedule}_*.backupset |\
    awk '
    BEGIN {
	cutoff="'"$curdatestamp"'" - ("'"$age"'" * 60 * 60 * 24)
    }
    {
	split($0, p1, ".")
	split(p1[1], p2, "_")
	if (p2[3] < cutoff)
	    print $0
    }'
    ) )
    if [ "${#purgelist[@]}" -gt 0 ]
    then
	echo mv ${purgelist[@]} ${meta}/attic
    fi
}

${command}
