#!/bin/bash

## Examines all backupsets, and compares with list of files in vault,
## generates list of backup files that are expired.
export LANG=C
export vault=/var/backup/vault
export meta=/var/backup/meta

join -j1 1 -j2 1 -v2 -o 2.1 \
    <(cat $meta/*_*_*.backupset |awk 'BEGIN { FS = "\t" }; { print $10 }' |sort -u) \
    <(find ${vault} -name "*.lzo" -print |grep '[0-9a-fA-F]\{2\}/[0-9a-fA-F]\{30\}\.lzo$' |\
    awk '{printf("%s%s\n", substr($1, length($1) - 36, 2), substr($1, length($1) - 33, 30))}' |sort -u ) |\
    awk '{printf("%s/%s/%s.lzo\n", ENVIRON["vault"], substr($1, 1, 2), substr($1, 3, length($1) - 2))}'
