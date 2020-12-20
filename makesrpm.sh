#!/bin/bash
Version=""
Release=""
if [ "$1" = "" ]
then
    tree=HEAD
else
    tree=$1
fi
eval "$(git describe --tags --match='v*' |awk '
BEGIN { FS = "-" }
{
    if (NF == 1)
	printf("Version=%s\nRelease=1\n", substr($1, 2, length($1) - 1));
    else if (NF == 2)
	printf("Version=%s\nRelease=%s\n", substr($1, 2, length($1) - 1), $2);
    else if (NF == 3)
	printf("Version=%s\nRelease=%s.%s%s\n", substr($1, 2, length($1) - 1), $2 + 1, strftime("%Y%m%d"), $3);
    else if (NF == 4)
	printf("Version=%s\nRelease=%s.%sx%s%s\n", substr($1, 2, length($1) - 1), $2, strftime("%Y%m%d"), $3 + 1, $4);

}')"
if [ -z "${Version}" -o -z "${Release}" ]
then
    echo "No version tag found"
    exit 1
fi
rm -rf rpmbuild.tmp
mkdir rpmbuild.tmp
git archive --prefix snebu-"${Version}"/ "${tree}" |gzip >rpmbuild.tmp/snebu-${Version}.tar.gz
git cat-file -p "${tree}":snebu.spec |sed "s/_VERSION_/${Version}/g;s/_RELEASE_/${Release}/g" >rpmbuild.tmp/snebu.spec
git cat-file -p "${tree}":Makefile-Fedora.patch >rpmbuild.tmp/Makefile-Fedora.patch
rpmbuild --define "_sourcedir ./rpmbuild.tmp" --define "_srcrpmdir ./rpmbuild.tmp" -bs rpmbuild.tmp/snebu.spec
