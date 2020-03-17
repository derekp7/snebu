#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ui.h>
#include "tarlib.h"

int tar_get_next_hdr(struct filespec *fs)
{
    struct tarhead tarhead;
    int longfilename = 0;
    int longlinktarget = 0;
    int count;
    int tcount;
    long long unsigned int bytestoread;
    int blockpad;
    char junk[512];
    char *paxpath = NULL;
    char *paxlinkpath = NULL;
    int paxpathlen = 0;
    int paxlinkpathlen = 0;
    char *paxsize = NULL;
    int paxsizelen = 0;
    int usepaxsize = 0;
    int paxsparse = 0;
    char *paxsparsename = 0;
    int paxsparsenamelen = 0;
    char *paxsparsesize = 0;
    int paxsparsesizelen = 0;
    static char *paxsparsesegt = 0;
    size_t paxsparsesegtn = 0;
    int paxsparsenseg = 0;
    int paxsparsehdrsz = 0;
    char s_isextended;
    struct speh speh;

    fsclear(fs);
    while(1) {
	count = fread(&tarhead, 1, 512, stdin);
	if (count <= 0 || tarhead.filename[0] == 0) {     // End of TAR archive
	    return(0);
	}
	// A file type of "L" means a long (> 100 character) file name.
	if (*(tarhead.ftype) == 'L') {
	    longfilename = 1;
	    bytestoread=strtoull(tarhead.size, 0, 8);
	    blockpad = 512 - ((bytestoread - 1) % 512 + 1);
	    if (dmalloc_size(fs->filename) < bytestoread + 1)
		fs->filename = drealloc(fs->filename, bytestoread + 1);

	    tcount = 0;
	    while (bytestoread - tcount > 0) {
		count = fread(fs->filename + tcount, 1, bytestoread - tcount, stdin);
		if (count == 0) {
		    fprintf(stderr, "Error\n");
		    return(0);
		}
		tcount += count;
	    }
	    tcount = 0;
	    while (blockpad - tcount > 0) {
		count = fread(junk, 1, blockpad - tcount, stdin);
		if (count == 0) {
		    fprintf(stderr, "Error\n");
		    return(0);
		}
		tcount += count;
	    }
	    fs->filename[bytestoread] = 0;
	    continue;
	}
	// A file type of "K" means a long (> 100 character) link target.
	if (*(tarhead.ftype) == 'K') {
	    longlinktarget = 1;
	    bytestoread=strtoull(tarhead.size, 0, 8);
	    blockpad = 512 - ((bytestoread - 1) % 512 + 1);
	    if (dmalloc_size(fs->linktarget) < bytestoread + 1)
		fs->linktarget = drealloc(fs->linktarget, bytestoread + 1);
	    tcount = 0;
	    while (bytestoread - tcount > 0) {
		count = fread(fs->linktarget + tcount, 1, bytestoread - tcount, stdin);
		if (count == 0) {
		    fprintf(stderr, "Error\n");
		    return(0);
		}
		tcount += count;
	    }
	    tcount = 0;
	    while (blockpad - tcount > 0) {
		count = fread(junk, 1, blockpad - tcount, stdin);
		if (count == 0) {
		    fprintf(stderr, "Error\n");
		    return(0);
		}
		tcount += count;
	    }
	    fs->linktarget[bytestoread] = 0;
	    continue;
	}
       // File type "x" is an extended header for the following file
	if (*(tarhead.ftype) == 'x' || *(tarhead.ftype) == 'g') {
	    if (*(tarhead.ftype) == 'g')
		fs->ftype = 'g';
	    bytestoread=strtoull(tarhead.size, 0, 8);
	    fs->xheaderlen = bytestoread;
	    blockpad = 512 - ((bytestoread - 1) % 512 + 1);
	    if (dmalloc_size(fs->xheader) < bytestoread)
		fs->xheader = drealloc(fs->xheader, bytestoread);
	    tcount = 0;
	    while (bytestoread - tcount > 0) {
		count = fread(fs->xheader + tcount, 1, bytestoread - tcount, stdin);
		tcount += count;
	    }
	    tcount = 0;
	    while (blockpad - tcount > 0) {
		count = fread(junk, 1, blockpad - tcount, stdin);
		tcount += count;
	    }
	    if (getpaxvar(fs->xheader, fs->xheaderlen, "path", &paxpath, &paxpathlen) == 0) {
		strncpya0(&(fs->filename), paxpath, paxpathlen - 1);
		longfilename = 1;
		delpaxvar(&(fs->xheader), &(fs->xheaderlen), "path");
	    }
	    if (getpaxvar(fs->xheader, fs->xheaderlen, "linkpath", &paxlinkpath, &paxlinkpathlen) == 0) {
		strncpya0(&(fs->linktarget), paxlinkpath, paxlinkpathlen - 1);
		longlinktarget = 1;
		fs->linktarget[paxlinkpathlen - 1] = '\0';
		delpaxvar(&(fs->xheader), &(fs->xheaderlen), "linkpath");
	    }
	    if (getpaxvar(fs->xheader, fs->xheaderlen, "size", &paxsize, &paxsizelen) == 0) {
		fs->filesize = strtoull(paxsize, 0, 10);
		usepaxsize = 1;
		delpaxvar(&(fs->xheader), &(fs->xheaderlen), "size");
	    }
	    if (cmpspaxvar(fs->xheader, fs->xheaderlen, "GNU.sparse.major", "1") == 0 &&
		cmpspaxvar(fs->xheader, fs->xheaderlen, "GNU.sparse.minor", "0") == 0) {
		paxsparse=1;
		getpaxvar(fs->xheader, fs->xheaderlen, "GNU.sparse.name", &paxsparsename, &paxsparsenamelen);
		getpaxvar(fs->xheader, fs->xheaderlen, "GNU.sparse.realsize", &paxsparsesize, &paxsparsesizelen);
		fs->sparse_realsize = strtoull(paxsparsesize, 0, 10);
		strncpya0(&(fs->filename), paxsparsename, paxsparsenamelen - 1);
		longfilename = 1;
		delpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.major");
		delpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.minor");
		delpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.name");
		delpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.realsize");

	    }
	    if (*(tarhead.ftype) == 'g')
		return(1);
	    continue;
	}


       // Process TAR header

	if (*(tarhead.ftype) == '0' || *(tarhead.ftype) == 'S') {
	    fs->ftype = '0';
	    if (longfilename == 0)
		strncpya0(&(fs->filename), tarhead.filename, 100);
	    fs->mode=strtol(tarhead.mode + 2, 0, 8);
	    fs->nuid=strtol(tarhead.nuid, 0, 8);
	    fs->ngid=strtol(tarhead.ngid, 0, 8);
	    if (usepaxsize == 0) {
		fs->filesize = 0;
		if ((unsigned char) tarhead.size[0] == 128)
		    for (int i = 0; i < 8; i++)
			fs->filesize += (( ((unsigned long long) ((unsigned char) (tarhead.size[11 - i]))) << (i * 8)));
		else
		    fs->filesize=strtoull(tarhead.size, 0, 8);
	    }
	    fs->modtime=strtol(tarhead.modtime, 0, 8);
	    if (longlinktarget == 0)
		strncpya0(&(fs->linktarget), tarhead.linktarget, 100);

	    if (strlen(tarhead.auid) == 0)
		sprintf(tarhead.auid, "%d", fs->nuid);
	    if (strlen(tarhead.agid) == 0)
		sprintf(tarhead.agid, "%d", fs->ngid);

	    strncpy(fs->auid, tarhead.auid, 32);
	    fs->auid[32] = 0;
	    strncpy(fs->agid, tarhead.agid, 32);
	    fs->agid[32] = 0;

	    // Handle GNU sparse files
	    if (*(tarhead.ftype) == 'S') {
		s_isextended = tarhead.u.sph.isextended;
		fs->sparse_realsize = g2ulli(tarhead.u.sph.realsize);
		if (dmalloc_size(fs->sparsedata) < 4 * sizeof(struct sparsedata))
		    fs->sparsedata = drealloc(fs->sparsedata, 4 * sizeof(struct sparsedata));
		for (fs->n_sparsedata = 0; fs->n_sparsedata < 4 && tarhead.u.sph.sd[fs->n_sparsedata].offset[0] != 0; fs->n_sparsedata++) {
		    fs->sparsedata[fs->n_sparsedata].offset = g2ulli(tarhead.u.sph.sd[fs->n_sparsedata].offset);
		    fs->sparsedata[fs->n_sparsedata].size= g2ulli(tarhead.u.sph.sd[fs->n_sparsedata].size);
		}
		while (s_isextended == 1) {
		    count = fread(&speh, 1, 512, stdin);
		    if (count < 512) {
			fprintf(stderr, "Error\n");
			return(0);
		    }
		    s_isextended = speh.isextended;
		    if (dmalloc_size(fs->sparsedata) < (fs->n_sparsedata + 21) * sizeof(struct sparsedata))
			fs->sparsedata = drealloc(fs->sparsedata, (fs->n_sparsedata + 21) * sizeof(struct sparsedata));
		    for (int e = 0; e < 21 && speh.sd[e].offset[0] != 0; e++, fs->n_sparsedata++) {
			fs->sparsedata[fs->n_sparsedata].offset = g2ulli(speh.sd[e].offset);
			fs->sparsedata[fs->n_sparsedata].size = g2ulli(speh.sd[e].size);
		    }
		}
	    }
	    if (paxsparse == 1){
		fs->ftype = '0';
		paxsparsehdrsz = 0;
		paxsparsehdrsz += getline(&paxsparsesegt, &paxsparsesegtn, stdin);
		paxsparsenseg = atoi(paxsparsesegt);
		fs->n_sparsedata = 0;
		if (dmalloc_size(fs->sparsedata) < paxsparsenseg * sizeof(struct sparsedata))
		    fs->sparsedata = drealloc(fs->sparsedata, paxsparsenseg * sizeof(struct sparsedata));
		while (paxsparsenseg-- > 0) {
		    paxsparsehdrsz += getline(&paxsparsesegt, &paxsparsesegtn, stdin);
		    fs->sparsedata[fs->n_sparsedata].offset = strtoull(paxsparsesegt, 0, 10);
		    paxsparsehdrsz += getline(&paxsparsesegt, &paxsparsesegtn, stdin);
		    fs->sparsedata[fs->n_sparsedata].size = strtoull(paxsparsesegt, 0, 10);
		    fs->n_sparsedata++;
		}
		if ((paxsparsehdrsz % 512) > 0) {
		    paxsparsehdrsz += fread(junk, 1, 512 - paxsparsehdrsz % 512, stdin);
		}
		fs->filesize -= paxsparsehdrsz;
	    }
	    return(1);
	}
	if (*(tarhead.ftype) == '5' || *(tarhead.ftype) == '1' || *(tarhead.ftype) == '2') {
	    fs->ftype = *(tarhead.ftype);
	    if (longfilename == 0)
		strncpya0(&(fs->filename), tarhead.filename, 100);
	    fs->mode=strtol(tarhead.mode + 2, 0, 8);
	    fs->nuid=strtol(tarhead.nuid, 0, 8);
	    fs->ngid=strtol(tarhead.ngid, 0, 8);
	    if (usepaxsize == 0) {
		fs->filesize = 0;
		if ((unsigned char) tarhead.size[0] == 128)
		    for (int i = 0; i < 8; i++)
			fs->filesize += (( ((unsigned long long) ((unsigned char) (tarhead.size[11 - i]))) << (i * 8)));
		else
		    fs->filesize=strtoull(tarhead.size, 0, 8);
	    }
	    fs->modtime=strtol(tarhead.modtime, 0, 8);
	    if (longlinktarget == 0)
		strncpya0(&(fs->linktarget), tarhead.linktarget, 100);

	    if (strlen(tarhead.auid) == 0)
		sprintf(tarhead.auid, "%d", fs->nuid);
	    if (strlen(tarhead.agid) == 0)
		sprintf(tarhead.agid, "%d", fs->ngid);

	    strncpy(fs->auid, tarhead.auid, 32);
	    fs->auid[32] = 0;
	    strncpy(fs->agid, tarhead.agid, 32);
	    fs->agid[32] = 0;
	}
	return(1);
    }
}

int tar_write_next_hdr(struct filespec *fs) {
    int genpax = 0;
    int paxlongfilename = 0;
    int gnulongfilename = 0;
    int gnulonglinktarget = 0;
    int paxlonglinktarget = 0;
    struct tarhead tarhead;
    char curblock[512];
    char pax_size[16];
    struct speh speh;
    unsigned int tmpchksum;
    char *p;
    int i;
    int paxsparsehdrsz = 0;
    unsigned long long int filesize = fs->filesize;

    if (fs->filename == NULL || fs->filename[0] == 0)
	return(-1);
    if (fs->xheaderlen > 0) {
	genpax = 1;
	fs->pax = 1;
    }
    if (strlen(fs->filename) > 100) {
	if (fs->pax == 1) {
	    genpax = 1;
	    paxlongfilename = 1;
	}
	else
	    gnulongfilename = 1;
    }
    if (strlen(fs->linktarget) > 100) {
	if (fs->pax == 1) {
	    genpax = 1;
	    paxlonglinktarget = 1;
	}
	else
	    gnulonglinktarget = 1;
    }

    if (gnulonglinktarget == 1) {
	// generate and output gnu long filename header
	memset(&tarhead, 0, 512);
	strcpy(tarhead.filename, "././@LongLink");
	*(tarhead.ftype) = 'K';
	strcpy(tarhead.nuid, "0000000");
	strcpy(tarhead.ngid, "0000000");
	strcpy(tarhead.mode, "0000000");
	sprintf(tarhead.size, "%11.11o", (unsigned int) strlen(fs->linktarget));
	strcpy(tarhead.modtime, "00000000000");
	memcpy(tarhead.ustar, "ustar ", 6);
	strcpy(tarhead.auid, "root");
	strcpy(tarhead.agid, "root");
	memcpy(tarhead.chksum, "        ", 8);
	for (tmpchksum = 0, p = (char *) (&tarhead), i = 512;
	    i != 0; --i, ++p)
	    tmpchksum += 0xFF & *p;
	sprintf(tarhead.chksum, "%6.6o", tmpchksum);
	fwrite(&tarhead, 1, 512, stdout);  // write out long file name header
	for (i = 0; i < strlen(fs->linktarget); i += 512) {
	    memset(curblock, 0, 512);
	    memcpy(curblock, fs->linktarget + i, strlen(fs->linktarget) - i >= 512 ? 512 :
		(strlen(fs->linktarget) - i));
	    fwrite(curblock, 1, 512, stdout); // write out long file name data
	}
    }

    if (gnulongfilename == 1) {
	// generate and output gnu long filename header
	memset(&tarhead, 0, 512);
	strcpy(tarhead.filename, "././@LongFilename");
	*(tarhead.ftype) = 'L';
	strcpy(tarhead.nuid, "0000000");
	strcpy(tarhead.ngid, "0000000");
	strcpy(tarhead.mode, "0000000");
	sprintf(tarhead.size, "%11.11o", (unsigned int) strlen(fs->filename));
	strcpy(tarhead.modtime, "00000000000");
	memcpy(tarhead.ustar, "ustar ", 6);
	strcpy(tarhead.auid, "root");
	strcpy(tarhead.agid, "root");
	memcpy(tarhead.chksum, "        ", 8);
	for (tmpchksum = 0, p = (char *) (&tarhead), i = 512;
	    i != 0; --i, ++p)
	    tmpchksum += 0xFF & *p;
	sprintf(tarhead.chksum, "%6.6o", tmpchksum);
	fwrite(&tarhead, 1, 512, stdout);  // write out long file name header
	for (i = 0; i < strlen(fs->filename); i += 512) {
	    memset(curblock, 0, 512);
	    memcpy(curblock, fs->filename + i, strlen(fs->filename) - i >= 512 ? 512 :
		(strlen(fs->filename) - i));
	    fwrite(curblock, 1, 512, stdout); // write out long file name data
	}

    }
    if (paxlonglinktarget == 1)
	setpaxvar(&(fs->xheader), &(fs->xheaderlen), "linkpath", fs->linktarget, strlen(fs->linktarget));
    if (paxlongfilename == 1)
	setpaxvar(&(fs->xheader), &(fs->xheaderlen), "path", fs->filename, strlen(fs->filename));
    if (fs->n_sparsedata > 0 && fs->pax == 1)
	genpax = 1;

    // generate and write pax header
    if (genpax == 1) {
	memset(&tarhead, 0, 512);
	strcpy(tarhead.filename, "././@xheader");
	if (fs->ftype == 'g') {
	    *(tarhead.ftype) = 'g';
	}
	else {
	    *(tarhead.ftype) = 'x';
	}
	strcpy(tarhead.nuid, "0000000");
	strcpy(tarhead.ngid, "0000000");
	strcpy(tarhead.mode, "0000000");
	strcpy(tarhead.modtime, "00000000000");
	sprintf(tarhead.ustar, "ustar");
	memcpy(tarhead.ustarver, "00", 2);
	strcpy(tarhead.auid, "root");
	strcpy(tarhead.agid, "root");
	if (fs->n_sparsedata > 0) {
	    sprintf(pax_size, "%lld", fs->sparse_realsize);
	    setpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.major", "1", 1);
	    setpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.minor", "0", 1);
	    setpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.name", (char *) fs->filename, strlen(fs->filename));
	    setpaxvar(&(fs->xheader), &(fs->xheaderlen), "GNU.sparse.realsize", pax_size, strlen(pax_size));
	}
	sprintf(tarhead.size, "%11.11o", fs->xheaderlen);

	memcpy(tarhead.chksum, "        ", 8);
	for (tmpchksum = 0, p = (char *) (&tarhead), i = 512;
	    i != 0; --i, ++p)
	    tmpchksum += 0xFF & *p;
	sprintf(tarhead.chksum, "%6.6o", tmpchksum);
	fwrite(&tarhead, 1, 512, stdout);  // write out pax header
	for (i = 0; i < fs->xheaderlen; i += 512) {
	    for (int j = 0; j < 512; j++)
		curblock[j] = 0;
	    memcpy(curblock, fs->xheader + i, fs->xheaderlen - i >= 512 ? 512 :
		(fs->xheaderlen - i));
	    fwrite(curblock, 1, 512, stdout);  // write out pax data
	}
	if (fs->ftype == 'g')
	    return(0);
    }

    // Create and write tar file header
    memset(&tarhead, 0, 512);
    memcpy(tarhead.filename, fs->filename, strlen(fs->filename) < 100 ? strlen(fs->filename) : 100);
    if (fs->linktarget != 0)
	memcpy(tarhead.linktarget, fs->linktarget, strlen(fs->linktarget) < 100 ? strlen(fs->linktarget) : 100);

    if (genpax == 0) {
	memcpy(tarhead.ustar, "ustar ", 6);
	sprintf(tarhead.ustarver, " ");
    }
    else {
	sprintf(tarhead.ustar, "ustar");
	memcpy(tarhead.ustarver, "00", 2);
    }
    *(tarhead.ftype) = fs->ftype;
    sprintf(tarhead.mode, "%7.7o", fs->mode);
    memcpy(tarhead.auid, fs->auid, strlen(fs->auid) < 32 ? strlen(fs->auid) : 32);
    sprintf(tarhead.nuid, "%7.7o", fs->nuid);
    memcpy(tarhead.agid, fs->agid, strlen(fs->agid) < 32 ? strlen(fs->agid) : 32);
    sprintf(tarhead.ngid, "%7.7o", fs->ngid);
    sprintf(tarhead.modtime, "%11.11o", (unsigned int) fs->modtime);

    if (genpax == 0 && fs->n_sparsedata > 0) {
	*(tarhead.ftype) = 'S';
	ulli2g(fs->sparse_realsize, tarhead.u.sph.realsize);
	for (int i = 0; i < fs->n_sparsedata && i < 4; i++) {
	    ulli2g(fs->sparsedata[i].offset, tarhead.u.sph.sd[i].offset);
	    ulli2g(fs->sparsedata[i].size, tarhead.u.sph.sd[i].size);

	}
	if (fs->n_sparsedata > 4)
	    tarhead.u.sph.isextended = 1;
    }
    if (genpax == 1 && fs->n_sparsedata > 0) {
	paxsparsehdrsz = 0;
	paxsparsehdrsz += ilog10(fs->n_sparsedata) + 2;
	for (int i = 0; i < fs->n_sparsedata; i++) {
	    if (fs->sparsedata[i].offset != 0)
		paxsparsehdrsz += ilog10(fs->sparsedata[i].offset) + 2;
	    else
		paxsparsehdrsz += 1;
	    if (fs->sparsedata[i].size != 0)
		paxsparsehdrsz += ilog10(fs->sparsedata[i].size) + 2;
	    else
		paxsparsehdrsz += 1;
	    if (i < fs->n_sparsedata)
		paxsparsehdrsz += 2;
	}
	paxsparsehdrsz += 1;
	if ((paxsparsehdrsz % 512) != 0)
	   paxsparsehdrsz += (512 - (paxsparsehdrsz % 512));
	filesize += paxsparsehdrsz;
    }

    ulli2g(filesize, tarhead.size);
    memcpy(tarhead.chksum, "        ", 8);
    for (tmpchksum = 0, p = (char *) (&tarhead), i = 512;
	i != 0; --i, ++p)
	tmpchksum += 0xFF & *p;
    sprintf(tarhead.chksum, "%6.6o", tmpchksum);
    fwrite(&tarhead, 1, 512, stdout);


   // Write out extended GNU sparse header
   if (tarhead.u.sph.isextended == 1) {
	int i;
	memset(&speh, 0, sizeof(speh));
	for (i = 4; i < fs->n_sparsedata; i++) {
	    ulli2g(fs->sparsedata[i].offset, speh.sd[(i - 4) % 21].offset);
	    ulli2g(fs->sparsedata[i].size, speh.sd[(i - 4) % 21].size);
	    if ((i + 1 - 4) % 21 == 0 && i > 4) {
		if (i < fs->n_sparsedata - 1)
		    speh.isextended = 1;
		else {
		    speh.isextended = 0;
		}
		fwrite(&speh, 1, 512, stdout);
		memset(&speh, 0, sizeof(speh));
	    }
	}
	if ((i - 4) % 21 != 0) {
	    fwrite(&speh, 1, 512, stdout);
	    memset(&speh, 0, sizeof(speh));
	}
    }
    if (genpax == 1 && fs->n_sparsedata > 0) {
	paxsparsehdrsz = 0;
	paxsparsehdrsz += fprintf(stdout, "%u\n", (unsigned int) fs->n_sparsedata);
	for (int i = 0; i < fs->n_sparsedata; i++) {
	    paxsparsehdrsz += fprintf(stdout, "%u\n", (unsigned int) fs->sparsedata[i].offset);
	    paxsparsehdrsz += fprintf(stdout, "%u\n", (unsigned int) fs->sparsedata[i].size);
	}
	memset(curblock, '\0', 512);
	if ((paxsparsehdrsz % 512) > 0)
	    paxsparsehdrsz += fwrite(curblock, 1, 512 - paxsparsehdrsz % 512, stdout);
    }
    return(0);
}

int getpaxvar(char *paxdata, int paxlen, char *name, char **rvalue, int *rvaluelen) {
    char *nvp = paxdata;
    int nvplen;
    char *cname;
    int cnamelen;
    char *value;
    int valuelen;

    while (nvp < paxdata + paxlen) {
	nvplen = strtol(nvp, &cname, 10);
	cname++;
	value = strchr(cname, '=');
	cnamelen = value - cname;
	value++;
	valuelen = nvp + nvplen - value;
	if (cnamelen >= strlen(name) && strncmp(name, cname, cnamelen) == 0) {
	    *rvalue = value;
	    *rvaluelen = valuelen;
	    return(0);
	}
	nvp += nvplen;
    }
    return(1);
}
int cmpspaxvar(char *paxdata, int paxlen, char *name, char *invalue) {
    char *nvp = paxdata;
    int nvplen;
    char *cname;
    int cnamelen;
    char *value;
    int namelen = strlen(name);
    int valuelen;

    while (nvp < paxdata + paxlen) {
	nvplen = strtol(nvp, &cname, 10);
	cname++;
	value = strchr(cname, '=');
	cnamelen = value - cname;
	value++;
	valuelen = nvp + nvplen - value;
	if (cnamelen >= namelen && strncmp(name, cname, cnamelen) == 0) {
	    return(strncmp(value, invalue, valuelen - 1));
	}
	nvp += nvplen;
    }
    return(1);
}
int setpaxvar(char **paxdata, int *paxlen, char *inname, char *invalue, int invaluelen) {
    char *cnvp = *paxdata;
    int cnvplen;
    char *cname = NULL;
    int cnamelen;
    char *cvalue;
    int innamelen = strlen(inname);
    int innvplen;
    static char *nvpline = NULL;
    int foundit=0;

    innvplen = innamelen + invaluelen + 3 + (ilog10(innamelen + invaluelen + 3 + (ilog10( innamelen + invaluelen + 3)) + 1)) + 1;
    nvpline = drealloc(nvpline, innvplen + 1);
    sprintf(nvpline, "%d %s=%s\n", innvplen, inname, invalue);


    while (cnvp < *paxdata + *paxlen) {
	cnvplen = strtol(cnvp, &cname, 10);
	cname++;
	cvalue = strchr(cname, '=');
	cnamelen = cvalue - cname;
	cvalue++;
	if (cnamelen >= innamelen && strncmp(inname, cname, cnamelen) == 0) {
	    if (innvplen > cnvplen) {
		*paxlen = *paxlen + (innvplen - cnvplen);
		*paxdata = drealloc(*paxdata, *paxlen);
		memmove(cnvp + innvplen, cnvp + cnvplen, (*paxdata + *paxlen) - (cnvp + cnvplen));
		memcpy(cnvp, nvpline, innvplen);
	    }
	    else if (innvplen < cnvplen) {
		memmove(cnvp + innvplen, cnvp + cnvplen, (*paxdata + *paxlen) - (cnvp + cnvplen));
		memcpy(cnvp, nvpline, innvplen);
		*paxlen = *paxlen + (innvplen - cnvplen);
		*paxdata = drealloc(*paxdata, *paxlen);
	    }
	    else {
		memcpy(cnvp, nvpline, innvplen);
	    }
	    foundit = 1;
	    break;
	}
	cnvp += cnvplen;
    }
    if (foundit == 0) {
	*paxdata = drealloc(*paxdata, *paxlen + innvplen);
	memcpy(*paxdata + *paxlen, nvpline, innvplen);
	*paxlen = *paxlen + innvplen;
    }
    return(0);
}
int delpaxvar(char **paxdata, int *paxlen, char *inname) {
    char *cnvp = *paxdata;
    int cnvplen;
    char *cname;
    int cnamelen;
    char *cvalue;

    while (cnvp < *paxdata + *paxlen) {
	cnvplen = strtol(cnvp, &cname, 10);
	cname++;
	cvalue = strchr(cname, '=');
	cnamelen = cvalue - cname;
	cvalue++;
	if (cnamelen >= strlen(inname) && strncmp(inname, cname, cnamelen) == 0) {
	    memmove(cnvp, cnvp + cnvplen, (*paxdata + *paxlen) - (cnvp + cnvplen));
	    *paxlen = *paxlen - cnvplen;
	    *paxdata = drealloc(*paxdata, *paxlen);
	    break;
	}
	cnvp += cnvplen;
    }
    return(0);
}

// Returns the integer log of n
unsigned int ilog10(unsigned long long int n) {
    static unsigned long long int lt[20];
    static int s = 0;

    int min = 0;
    int max = sizeof(lt) / sizeof(*lt) - 1;
    int mid;
    int i;
    unsigned long long int j = 1;

    if (s == 0) {
	for (i = 1; i <= 19; i++) {
	    lt[i - 1] = j;
	    j *= 10;
	}
	lt[19] = 0xffffffffffffffff;
    }
    s = 1;

    if (n == 0)
	return(0);
    while (max >= min) {
	mid = (int) (((min + max) / 2));
	if (n >= lt[min]  && n < lt[mid]) {
	    if (min + 1 == mid)
		return(min);
	    else
		max = mid;
	}
	else if (n >= lt[mid] && (n < 0xffffffffffffffff ? n < lt[max] : n <= lt[max])) {
	    if (mid + 1 == max)
		return(mid);
	    else
		min = mid;
	}
    }
    return(0);
}

// malloc that records size of allocated memory segment
void *dmalloc(size_t size)
{
    void *b;
    b = malloc(size + sizeof(size_t));
    *(size_t *)b = size;
    return(b + sizeof(size_t));
}

// Matching free function for dmalloc
void dfree(void *b)
{
    if (b != NULL)
	free(b - sizeof(size_t));
}

// Matching realloc function for dmalloc
void *drealloc(void *b, size_t size)
{
    void *r;
    if (b == NULL)
	return(dmalloc(size));
    r = realloc(b - sizeof(size_t), size + sizeof(size_t));
    *(size_t *)r = size;
    return(r + sizeof(size_t));
}

// Returns size of memory allocated by dmalloc
size_t dmalloc_size(void *b)
{
    if (b != NULL)
	return(*((size_t *) (b - sizeof(size_t))));
    return(0);
}

/* auto-allocating version of strncpy
 * always leaves a null terminator
 * *dest must be either NULL, or allocated via dmalloc();
*/
char *strncpya0(char **dest, const char *src, size_t n)
{
    if (*dest == NULL)
	*dest = dmalloc(n + 1);
    if (dmalloc_size(*dest) < n + 1)
	*dest = drealloc(*dest, n + 1);
    strncpy(*dest, src, n);
    (*dest)[n] = '\0';
    return(*dest);
}

char *strcata(char **dest, const char *src)
{
    if (*dest == NULL) {
	*dest = dmalloc(strlen(src) + 1);
	((char *)(*dest))[0] = 0;
    }
    if (dmalloc_size(*dest) < strlen(*dest) + strlen(src) + 1)
	*dest = drealloc(*dest, strlen(*dest) + strlen(src) + 1);
    strcat(*dest, src);
    return(*dest);
}

/* auto-allocating version of memcpy
 * *dest must be either NULL, or allocated via dmalloc();
*/
void *memcpya(void **dest, void *src, size_t n)
{
    if (*dest == NULL)
	*dest = dmalloc(n);
    if (dmalloc_size(*dest) < n)
	*dest = drealloc(*dest, n);
    memcpy(*dest, src, n);
    return(*dest);
}

// Initialize filespec structure
int fsinit(struct filespec *fs, size_t (*c_fread)(), size_t (*c_fwrite)(), void *c_read_handle, void *c_write_handle)
{
    fs->ftype = 0;
    fs->mode = 0;
    fs->devid[0] = 0;
    fs->inode[0] = 0;
    fs->auid[0] = 0;
    fs->nuid = 0;
    fs->agid[0] = 0;
    fs->ngid = 0;
    fs->filesize = 0;
    fs->sparse_realsize = 0;
    fs->modtime = 0;
    fs->filename = dmalloc(100);
    fs->linktarget = dmalloc(100);
    fs->xheader = dmalloc(100);
    fs->xheaderlen = 0;
    fs->sparsedata = dmalloc(sizeof(fs->sparsedata) * 4);
    fs->n_sparsedata = 0;
    fs->pax = 0;
    fs->c_fread = c_fread;
    fs->c_fwrite = c_fwrite;
    fs->c_read_handle = c_read_handle;
    fs->c_write_handle = c_write_handle;
    fsclear(fs);
    return(0);
}

// Zero out filespec structure
int fsclear(struct filespec *fs)
{
    fs->ftype = 0;
    fs->mode = 0;
    fs->devid[0] = 0;
    fs->inode[0] = 0;
    fs->auid[0] = 0;
    fs->nuid = 0;
    fs->agid[0] = 0;
    fs->ngid = 0;
    fs->filesize = 0;
    fs->sparse_realsize = 0;
    fs->modtime = 0;
    if (fs->filename != NULL)
	fs->filename[0] = 0;
    if (fs->linktarget != NULL)
	fs->linktarget[0] = 0;
    if (fs->xheaderlen > 0)
	fs->xheader[0] = 0;
    fs->xheaderlen = 0;
    fs->n_sparsedata = 0;
    fs->pax = 0;
    return(0);
}

// Make a copy of a filespec data structure
int fsdup(struct filespec *tsf, struct filespec *sfs)
{
    tsf->ftype = sfs->ftype;
    tsf->mode = sfs->mode;
    memcpy(tsf->devid, sfs->devid, 33);
    memcpy(tsf->inode, sfs->inode, 33);
    memcpy(tsf->auid, sfs->auid, 33);
    tsf->nuid = sfs->nuid;
    memcpy(tsf->agid, sfs->agid, 33);
    tsf->ngid = sfs->ngid;
    tsf->filesize = sfs->filesize;
    tsf->sparse_realsize = sfs->sparse_realsize;
    tsf->modtime = sfs->modtime;
    memcpy(tsf->agid, sfs->agid, 33);
    strncpya0(&(tsf->filename), sfs->filename, strlen(sfs->filename));
    strncpya0(&(tsf->linktarget), sfs->filename, strlen(sfs->linktarget));
    memcpya((void **) &(tsf->xheader), sfs->xheader, sfs->xheaderlen);
    tsf->xheaderlen = sfs->xheaderlen;
    memcpya((void **) &(tsf->sparsedata), sfs->sparsedata, sizeof(struct sparsedata) * sfs->n_sparsedata);
    tsf->n_sparsedata = sfs->n_sparsedata;
    tsf->pax = sfs->pax;
    return(0);
}

// Free a filespec data structure
int fsfree(struct filespec *fs)
{
    dfree(fs->filename);
    dfree(fs->linktarget);
    dfree(fs->xheader);
    dfree(fs->sparsedata);
    return(0);
}

/* Convert unsigned long long int to GNU TAR octal or binary representation */
char *ulli2g(unsigned long long int v, char *p)
{
    int lendian = 1;
    lendian = (unsigned int) (((unsigned char *)(&lendian))[0]); // little endian test

    if (v <= 077777777777LL)
	sprintf(p, "%11.11llo", (unsigned long long int) v);
    else {
	p[0] = 0x80;
	for (int i = 0; i < sizeof(v); i++)
	    if (lendian)
		p[11 - i] = ((char *) (&(v)))[i];
	    else
		p[11 - sizeof(v) + i] = ((char *) (&(v)))[i];
    }
    return(p);
}

/* Convert GNU TAR octal or binary representation to unsigned long long int */
unsigned long long int g2ulli(char *p)
{
    unsigned long long int r;
    if ((unsigned char) p[0] == 128) {
	r = 0;
	for (int i = 0; i < 8; i++)
	    r += (( ((unsigned long long) ((unsigned char) (p[11 - i]))) << (i * 8)));
    }
    else
	r = strtoull(p, 0, 8);
    return(r);
}

struct lzop_file *lzop_init(size_t (*c_fwrite)(), void *c_handle)
{
    struct lzop_file *cfile;
    char magic[] = {  0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };
    uint32_t chksum = 1;

    cfile = malloc(sizeof(*cfile));
    cfile->bufsize = 256 * 1024;
    cfile->buf = malloc(cfile->bufsize);
    cfile->cbuf = malloc(256 * 1024 + 256 * 64 + 64 + 3);
    cfile->bufp = cfile->buf;
    cfile->working_memory = malloc(LZO1X_1_MEM_COMPRESS);
    cfile->c_fwrite = c_fwrite;
    cfile->c_handle = c_handle;
    {
	cfile->c_fwrite(magic, 1, sizeof(magic), cfile->c_handle);
	fwritec(htonsp(0x1030), 1, 2, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec(htonsp(lzo_version()), 1, 2, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec(htonsp(0x0940), 1, 2, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec("\001", 1, 1, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec("\005", 1, 1, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec(htonlp(0x300000d), 1, 4, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec(htonlp(0x0), 1, 4, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec(htonlp(0x0), 1, 4, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec(htonlp(0x0), 1, 4, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec("\000", 1, 1, cfile->c_fwrite, cfile->c_handle, &chksum);
	fwritec(htonlp(chksum), 1, 4, cfile->c_fwrite, cfile->c_handle, &chksum);
    }
    return(cfile);
}

size_t lzop_write(void *buf, size_t sz, size_t count, struct lzop_file *cfile)
{
    size_t n = sz * count;
    uint32_t chksum;
    size_t bufroom = 0;
    size_t t = 0;
    size_t x;

    do {
	bufroom = cfile->bufsize - (cfile->bufp - cfile->buf);
	if (n <= bufroom) {
	    memcpy(cfile->bufp, buf, n);
	    cfile->bufp += n;
	    t += n;
	    n = 0;
	}
	else {
	    memcpy(cfile->bufp, buf, bufroom);
	    cfile->bufp += bufroom;
	    t += bufroom; 
	    buf += (cfile->buf + cfile->bufsize - cfile->bufp);
	    // compress cfile->buf, write out

	    // write uncompressed block size
	    if (cfile->c_fwrite(htonlp(cfile->bufsize), 1, 4, cfile->c_handle) < 4) {
		return(0);
	    }
	    chksum = lzo_adler32(1, (unsigned char *) cfile->buf, cfile->bufsize);
	    lzo1x_1_compress((unsigned char *) cfile->buf, cfile->bufsize, (unsigned char *) cfile->cbuf, &(cfile->cbufsize), cfile->working_memory);

	    // if compression was beneficial
	    if (cfile->cbufsize < cfile->bufsize) {
		// write compressed block size
		if (cfile->c_fwrite(htonlp(cfile->cbufsize), 1, 4, cfile->c_handle) < 4) {
		    return(0);
		}
	    }
	    else
		// write uncompressed block size again
		if (cfile->c_fwrite(htonlp(cfile->bufsize), 1, 4, cfile->c_handle) < 4) {
		    return(0);
		}
	    // write checksum
	    if (cfile->c_fwrite(htonlp(chksum), 1, 4, cfile->c_handle) < 4) {
		return(0);
	    }
	    // if compression was beneficial
	    if (cfile->cbufsize < cfile->bufsize) {
		//write compressed data
		if ((x = cfile->c_fwrite(cfile->cbuf, 1, cfile->cbufsize, cfile->c_handle)) < cfile->cbufsize) {
		    return(0);
		}
	    }
	    else {
		//write uncompressed data
		if (cfile->c_fwrite(cfile->buf, 1, cfile->bufsize, cfile->c_handle) < cfile->bufsize) {
		    return(0);
		}
	    }
	    cfile->bufp = cfile->buf;
	}
    } while (n > 0);
    return(t);
}
struct lzop_file *lzop_init_r(size_t (*c_fread)(), void *c_handle)
{
    struct lzop_file *cfile;
    char magic[] = {  0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };
    uint16_t tmp16;
    uint32_t tmp32;
    struct {
	char magic[sizeof(magic)];
	uint16_t version;
	uint16_t libversion;
	uint16_t minversion;
	unsigned char compmethod;
	unsigned char level;
	uint32_t flags;
	uint32_t filter;
	uint32_t mode;
	uint32_t mtime_low;
	uint32_t mtime_high;
	unsigned char filename_len;
	char filename[256];
	uint32_t chksum;
    } lzop_header;

    cfile = malloc(sizeof(*cfile));
    cfile->bufsize = 0;
    cfile->buf = malloc(256 * 1024);
    cfile->cbuf = malloc(256 * 1024 + 256 * 64 + 64 + 3);
    cfile->bufp = cfile->buf;
    cfile->c_fread = c_fread;
    cfile->c_handle = c_handle;

    // Process header
    cfile->c_fread(&(lzop_header.magic), 1, sizeof(magic), cfile->c_handle);
    cfile->c_fread(&tmp16, 1, 2, cfile->c_handle);
    lzop_header.version = ntohs(tmp16);
    cfile->c_fread(&tmp16, 1, 2, cfile->c_handle);
    lzop_header.libversion = ntohs(tmp16);
    if (lzop_header.version >= 0x0940) {
	cfile->c_fread(&tmp16, 1, 2, cfile->c_handle);
	lzop_header.minversion = ntohl(tmp16);
    }
    cfile->c_fread(&(lzop_header.compmethod), 1, 1, cfile->c_handle);
    if (lzop_header.version >= 0x0940)
	cfile->c_fread(&(lzop_header.level), 1, 1, cfile->c_handle);
    cfile->c_fread(&tmp32, 1, 4, cfile->c_handle);
    lzop_header.flags = ntohl(tmp32);
    if (lzop_header.flags & F_H_FILTER) {
	cfile->c_fread(&tmp32, 1, 4, cfile->c_handle);
	lzop_header.filter = ntohl(tmp32);
    }
    cfile->c_fread(&tmp32, 1, 4, cfile->c_handle);
    lzop_header.mode = ntohl(tmp32);
    cfile->c_fread(&tmp32, 1, 4, cfile->c_handle);
    lzop_header.mtime_low = ntohl(tmp32);
    cfile->c_fread(&tmp32, 1, 4, cfile->c_handle);
    lzop_header.mtime_high = ntohl(tmp32);
    cfile->c_fread(&(lzop_header.filename_len), 1, 1, cfile->c_handle);
    if (lzop_header.filename_len > 0)
	cfile->c_fread(&(lzop_header.filename), 1, lzop_header.filename_len, cfile->c_handle);
    cfile->c_fread(&tmp32, 1, 4, cfile->c_handle);
    lzop_header.chksum = ntohl(tmp32);
    return(cfile);
}


size_t fwritec(const void *ptr, size_t size, size_t nmemb, size_t (*c_fwrite)(), void *c_handle, uint32_t *chksum)
{
    size_t r;
    r = c_fwrite(ptr, size, nmemb, c_handle);
    *chksum = lzo_adler32(*chksum, ptr, size * nmemb);
    return(r);
}

size_t lzop_read(void *buf, size_t sz, size_t count, struct lzop_file *cfile)
{
    size_t bytesin = sz * count;
    uint32_t tchksum;
    uint32_t chksum;
    uint32_t tucblocksz;
    uint32_t tcblocksz;
    uint32_t ucblocksz;
    uint32_t cblocksz;
    size_t orig_bytesin = bytesin;

    do {
	if (bytesin <= cfile->buf + cfile->bufsize - cfile->bufp) {
	    memcpy(buf, cfile->bufp, bytesin);
	    cfile->bufp += bytesin;
	    bytesin = 0;
	}
	else {
	    memcpy(buf, cfile->bufp, cfile->buf + cfile->bufsize - cfile->bufp);
	    bytesin -= (cfile->buf + cfile->bufsize - cfile->bufp);
	    buf += (cfile->buf + cfile->bufsize - cfile->bufp);
	    cfile->c_fread(&tucblocksz, 1, 4, cfile->c_handle);
	    ucblocksz = ntohl(tucblocksz);
	    if (ucblocksz == 0)
		return(cfile->buf + cfile->bufsize - cfile->bufp);
	    cfile->c_fread(&tcblocksz, 1, 4, cfile->c_handle);
	    cblocksz = ntohl(tcblocksz);
	    cfile->c_fread(&tchksum, 1, 4, cfile->c_handle);
	    chksum = ntohl(tchksum);
	    if (cfile->c_fread(cfile->cbuf, 1, cblocksz, cfile->c_handle) < cblocksz) {
		fprintf(stderr, "lzop_read error: short read\n");
		return(0);
	    }
	    if (cblocksz < ucblocksz) {
		lzo1x_decompress((unsigned char *) cfile->cbuf, cblocksz, (unsigned char *) cfile->buf, &(cfile->bufsize), NULL);
	    }
	    else {
		memcpy(cfile->buf, cfile->cbuf, cblocksz);
	    }
	    if (chksum != lzo_adler32(1, (unsigned char *) cfile->buf, ucblocksz)) {
		fprintf(stderr, "Checksum error reading compressed lzo file\n");
	    }
	    cfile->bufp = cfile->buf;
	    cfile->bufsize = ucblocksz;
	}
    } while (bytesin > 0);
    return(orig_bytesin);
}

int lzop_finalize(struct lzop_file *cfile)
{
    uint32_t chksum = 0;

    if (cfile->bufp - cfile->buf > 0) {
	if (cfile->c_fwrite(htonlp(cfile->bufp - cfile->buf), 1, 4, cfile->c_handle) < 4) {
	    return(EOF);
	}
	chksum = lzo_adler32(1, (unsigned char *) cfile->buf, cfile->bufp - cfile->buf);
	lzo1x_1_compress((unsigned char *) cfile->buf, cfile->bufp - cfile->buf, (unsigned char *) cfile->cbuf, &(cfile->cbufsize), cfile->working_memory);
	if (cfile->cbufsize < (cfile->bufp - cfile->buf)) {
	    if (cfile->c_fwrite(htonlp(cfile->cbufsize), 1, 4, cfile->c_handle) < 4)
		return(EOF);
	}
	else
	    if (cfile->c_fwrite(htonlp(cfile->bufp - cfile->buf), 1, 4, cfile->c_handle) < 4)
		return(EOF);
	if (cfile->c_fwrite(htonlp(chksum), 1, 4, cfile->c_handle) < 4)
	    return(EOF);
	if (cfile->cbufsize < (cfile->bufp - cfile->buf)) {
	    if (cfile->c_fwrite(cfile->cbuf, 1, cfile->cbufsize, cfile->c_handle) < cfile->cbufsize)
		return(EOF);
	}
	else
	    if (cfile->c_fwrite(cfile->buf, 1, (cfile->bufp - cfile->buf), cfile->c_handle) < cfile->bufp - cfile->buf)
		return(EOF);
    }
    if (cfile->c_fwrite(htonlp(0), 1, 4, cfile->c_handle) < 4)
	return(EOF);
    free(cfile->buf);
    free(cfile->cbuf);
    free(cfile->working_memory);
    free(cfile);
    return(0);
}

int lzop_finalize_r(struct lzop_file *cfile)
{
    char padding[512];
    int n;
    while ((n = cfile->c_fread(padding, 1, 512, cfile->c_handle)) > 0) {
	;
    }

    free(cfile->buf);
    free(cfile->cbuf);
    free(cfile);
    return(0);
}

uint32_t *htonlp(uint32_t v)
{
    static uint32_t r;
    r = htonl(v);
    return(&r);
}
uint16_t *htonsp(uint16_t v)
{
    static uint16_t r;
    r = htons(v);
    return(&r);
}

struct tarsplit_file *tarsplit_init(size_t (*c_fwrite)(), void *c_handle, char *basename_path, size_t bufsize, struct filespec *fs)
{
    struct tarsplit_file *tsf;

    tsf = malloc(sizeof(struct tarsplit_file));
    tsf->buf = malloc(bufsize);
    tsf->bufp = tsf->buf;
    tsf->bufsize = bufsize;
    tsf->c_fwrite = c_fwrite;
    tsf->c_handle = c_handle;
    tsf->basename_path = malloc(strlen(basename_path) + 1);
    tsf->segn = 0;
    tsf->orig_fs = fs;
    strcpy(tsf->basename_path, basename_path);
    memset(tsf->buf, 0, bufsize);
    tsf->xheader = dmalloc(100);
    tsf->xheaderlen = 0;
    return tsf;
}

size_t tarsplit_write(void *buf, size_t sz, size_t count, struct tarsplit_file *tsf)
{
    size_t n = sz * count;
    size_t c = 0;
    static struct filespec *fs = 0;
    char seg[20];
    char padding[512];
    char paxdata[128];

    if (fs == 0) {
	fs = malloc(sizeof(struct filespec));
	fsinit(fs, NULL, tsf->c_fwrite, NULL, tsf->c_handle);
    }
    else
	fsclear(fs);

    memset(padding, 0, 512);
    while (n > 0) {
	if (n <= tsf->buf + tsf->bufsize - tsf->bufp) {
	    memcpy(tsf->bufp, buf + c, n);
	    tsf->bufp += n;
	    c += n;
	    n = 0;
	}
	else {
	    memcpy(tsf->bufp, buf + c, tsf->buf + tsf->bufsize - tsf->bufp);
	    c += (tsf->buf + tsf->bufsize - tsf->bufp);
	    n -= (tsf->buf + tsf->bufsize - tsf->bufp);
	    if (n > 0) {
		if (tsf->segn == 0) {
		    sprintf(paxdata, "%llu", tsf->orig_fs->filesize);
		    setpaxvar(&(tsf->orig_fs->xheader), &(tsf->orig_fs->xheaderlen), "SB.segmented.header", "1", 1);
		    setpaxvar(&(tsf->orig_fs->xheader), &(tsf->orig_fs->xheaderlen), "SB.original.size", paxdata, strlen(paxdata));
		    tsf->orig_fs->ftype = '5';
		    tsf->orig_fs->filesize = '5';
		    tar_write_next_hdr(tsf->orig_fs);

		}
		strncpya0(&(fs->filename), tsf->basename_path, strlen(tsf->basename_path));
		sprintf(seg, "%9.9d", (tsf->segn)++);
		strcata(&(fs->filename), "/part.");
		strcata(&(fs->filename), seg);
		fs->filesize = tsf->bufsize;
		fs->ftype = '0';
		tar_write_next_hdr(fs);
		tsf->c_fwrite(tsf->buf, 1, tsf->bufsize, tsf->c_handle);
		tsf->c_fwrite(padding, 1, 512 - ((tsf->bufsize - 1) % 512 + 1),
		    tsf->c_handle);
		tsf->bufp = tsf->buf;
	    }
	}
    }
    if (sz == 0) {
	if (tsf->bufp > tsf->buf) {
	    n = tsf->bufp - tsf->buf;
	    if (tsf->segn > 0) {
		strncpya0(&(fs->filename), tsf->basename_path, strlen(tsf->basename_path));
		sprintf(seg, "%9.9d", (tsf->segn)++);
		strcata(&(fs->filename), "/part.");
		strcata(&(fs->filename), seg);
		fs->filesize = n;
		fs->ftype = '0';
		setpaxvar(&(fs->xheader), &(fs->xheaderlen), "SB.segmented.final", "1", 1);
		setpaxvar(&(fs->xheader), &(fs->xheaderlen), "SB.hmac", (char *) tsf->hmac, strlen((char *) tsf->hmac));
		tar_write_next_hdr(fs);
	    }
	    else {
		sprintf(paxdata, "%llu", tsf->orig_fs->filesize);
		setpaxvar(&(tsf->orig_fs->xheader), &(tsf->orig_fs->xheaderlen), "SB.original.size", paxdata, strlen(paxdata));
		setpaxvar(&(tsf->orig_fs->xheader), &(tsf->orig_fs->xheaderlen), "SB.hmac", (char *) tsf->hmac, strlen((char *) tsf->hmac));
		tsf->orig_fs->filesize = n;
		tar_write_next_hdr(tsf->orig_fs);
	    }
	    tsf->c_fwrite(tsf->buf, 1, n, tsf->c_handle);
	    tsf->c_fwrite(padding, 1, 512 - ((n - 1) % 512 + 1),
		tsf->c_handle);
	    tsf->bufp = tsf->buf;
	}
	return(0);
    }
    return(c);
}

int tarsplit_finalize(struct tarsplit_file *tsf)
{
    tarsplit_write(NULL, 0, 0, tsf);
    free(tsf->buf);
    free(tsf->basename_path);
    dfree(tsf->xheader);
    free(tsf);
    return(0);
}

int tarsplit_finalize_r(struct tarsplit_file *tsf)
{
    char padding[512];

    memset(padding, 0, 512);
    if (tsf->segremaining == 0 && tsf->segsize > 0) {
	tsf->c_fread(padding, 1, 512 - (( tsf->segsize - 1) % 512 + 1),
	    tsf->c_handle);
    }
    free(tsf);
    return(0);
}

struct tarsplit_file *tarsplit_init_r(size_t (*c_fread)(), void *c_handle)
{
    struct tarsplit_file *tsf;

    tsf = malloc(sizeof(struct tarsplit_file));
    tsf->c_fread = c_fread;
    tsf->c_handle = c_handle;
    tsf->segn = 0;
    tsf->finalseg = 0;
    tsf->segremaining = 0;
    tsf->segsize = 0;
    return tsf;
}

size_t tarsplit_read(void *buf, size_t sz, size_t count, struct tarsplit_file *tsf)
{
    size_t n = sz * count;
    size_t c = 0;
    size_t r = 0;
    static struct filespec *fs = 0;
    char padding[512];
    char *paxdata = NULL;
    int paxdatalen = 0;

    if (fs == 0) {
	fs = malloc(sizeof(struct filespec));
	fsinit(fs, tsf->c_fread, NULL, tsf->c_handle, NULL);
    }
    else
	fsclear(fs);

    while (n > 0) {
	if (tsf->segremaining == 0) {
	    if (tsf->finalseg != 1) {
		if (tsf->segsize > 0) {
		    tsf->c_fread(padding, 1, 512 - (( tsf->segsize - 1) % 512 + 1),
			tsf->c_handle);
		}
		tar_get_next_hdr(fs);
		if (getpaxvar(fs->xheader, fs->xheaderlen, "SB.segmented.final", &paxdata, &paxdatalen) == 0) {
		    tsf->finalseg = atoi(paxdata);
		}
		tsf->segsize = tsf->segremaining = fs->filesize;
	    }
	    else {
		return(c);
	    }
	}
	if (n <= tsf->segremaining) {
	    r = tsf->c_fread(buf + c, 1, n, tsf->c_handle);
	    c += r;
	    n -= r;
	    tsf->segremaining -= r;
	}
	else {
	    r = tsf->c_fread(buf + c, 1, tsf->segremaining, tsf->c_handle);
	    c += r;
	    n -= r;
	    tsf->segremaining -= r;
	}
	if (r == 0 && tsf->segremaining > 0) {
	    return(c);
	}
    }
    return(c);
}

int genkey(int argc, char **argv)
{
    struct option longopts[] = {
	{ "filename", required_argument, NULL, 'f' },
	{ "comment", required_argument, NULL, 'c' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
    int optc;
    int foundopts = 0;
    char filename[128];
    char comment[128];
    int opt_filename = 1;
    int opt_comment = 2;
    RSA *rsa_keypair = RSA_new();
    EVP_PKEY *evp_keypair = EVP_PKEY_new();
    BIGNUM *bne = BN_new();
    BIO *rsakeyfile;
    EVP_CIPHER_CTX *ctx = NULL;
    int eklen;
    int eklen_n;
    unsigned char *ek;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char hmac_key[32];
    unsigned char hmac_key_b64[45];
    unsigned char hmac_key_enc[128];
    int hmac_key_enc_sz = 0;
    unsigned char *hmac_key_enc_p = hmac_key_enc;
    unsigned char hmac_key_enc_b64[256];
    struct passwd *pw;
    char hostname[64];

    pw = getpwuid(getuid());
    gethostname(hostname, 63);
    hostname[63] = '\0';
    comment[0] = '\0';

    while ((optc = getopt_long(argc, argv, "f:c:", longopts, &longoptidx)) >= 0) {
	switch (optc) {
	    case 'f':
		strncpy(filename, optarg, 127);
		filename[127] = 0;
		foundopts |= opt_filename;
	       break;
	     case 'c':
		strncpy(comment, optarg, 127);
		comment[127] = 0;
		foundopts |= opt_comment;
		break;
	}
    }
    if (! (foundopts & opt_filename)) {
	printf("Need a filename\n");
	exit(1);
    }
    rsakeyfile = BIO_new_file(filename, "w+");

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    BN_set_word(bne, RSA_F4);
    if (RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL) != 1) {
	fprintf(stderr, "Error generating RSA key pair");
	exit(1);
    }
    EVP_PKEY_set1_RSA(evp_keypair, rsa_keypair);
    PEM_write_bio_PKCS8PrivateKey(rsakeyfile, evp_keypair, EVP_aes_128_cbc(), NULL, 0, 0, NULL);
    PEM_write_bio_PUBKEY(rsakeyfile, evp_keypair);
    RAND_bytes(hmac_key, 32);

    ctx = EVP_CIPHER_CTX_new();

    openssl_err();
    ek = malloc(EVP_PKEY_size(evp_keypair));
    EVP_SealInit(ctx, EVP_aes_256_gcm(), &ek, &eklen, iv, &evp_keypair, 1);
    eklen_n = htonl(eklen);

    memcpy(hmac_key_enc_p, &eklen_n, sizeof(eklen_n));
    hmac_key_enc_p += sizeof(eklen_n);

    memcpy(hmac_key_enc_p, ek, eklen);
    hmac_key_enc_p += sizeof(eklen);

    memcpy(hmac_key_enc_p, iv, EVP_CIPHER_iv_length(EVP_aes_256_gcm()));
    hmac_key_enc_p += sizeof(EVP_CIPHER_iv_length(EVP_aes_256_gcm()));

    EVP_SealUpdate(ctx, hmac_key_enc_p, &hmac_key_enc_sz, hmac_key, 32);
    hmac_key_enc_p += hmac_key_enc_sz;

    EVP_SealFinal(ctx, hmac_key_enc_p, &hmac_key_enc_sz);
    hmac_key_enc_p += hmac_key_enc_sz;

    hmac_key_enc_sz = hmac_key_enc_p - hmac_key_enc;

    EVP_EncodeBlock(hmac_key_b64, hmac_key, 32);
    EVP_EncodeBlock(hmac_key_enc_b64, hmac_key_enc, hmac_key_enc_sz);

    BIO_printf(rsakeyfile, "-----BEGIN HMAC KEY-----\n");
    BIO_printf(rsakeyfile, "%s\n", hmac_key_b64);
    BIO_printf(rsakeyfile, "-----END HMAC KEY-----\n");
    BIO_printf(rsakeyfile, "-----BEGIN ENCRYPTED HMAC KEY-----\n");
    BIO_printf(rsakeyfile, "%s\n", hmac_key_enc_b64);
    BIO_printf(rsakeyfile, "-----END ENCRYPTED HMAC KEY-----\n");
    BIO_printf(rsakeyfile, "-----BEGIN COMMENT-----\n");
    BIO_printf(rsakeyfile, "%s@%s\n", pw->pw_name, hostname);
    if (comment[0] != '\0')
	BIO_printf(rsakeyfile, "%s\n", comment);
    BIO_printf(rsakeyfile, "-----END COMMENT-----\n");
    EVP_CIPHER_CTX_cleanup(ctx);

    return(0);
}

struct rsa_file *rsa_file_init(char mode, EVP_PKEY *evp_keypair, size_t (*c_ffunc)(), void *c_handle)
{
    struct rsa_file *rcf;
    int eklen_n;

    OpenSSL_add_all_algorithms();
    rcf = malloc(sizeof(struct rsa_file));
    rcf->bufsize = 4096;
    rcf->buf = malloc(rcf->bufsize + EVP_MAX_IV_LENGTH);
    rcf->bufp = rcf->buf;
    rcf->outbufsize = rcf->bufsize;
    rcf->outbuf = malloc(rcf->outbufsize + EVP_MAX_IV_LENGTH);
    rcf->inbuf = rcf->outbuf;
    rcf->inbufsize = rcf->outbufsize;
    rcf->bufused = 0;
    rcf->eof = 0;
    rcf->mode = mode;

    rcf->ctx = EVP_CIPHER_CTX_new();
    if (mode == 'w') {
	rcf->c_fwrite = c_ffunc;
	rcf->ek = malloc(EVP_PKEY_size(evp_keypair));
	EVP_SealInit(rcf->ctx, EVP_aes_256_gcm(), &(rcf->ek), &(rcf->eklen), (rcf->iv), &evp_keypair, 1);
	eklen_n = htonl(rcf->eklen);
	c_ffunc(&eklen_n, 1, sizeof(rcf->eklen), c_handle);
	c_ffunc(rcf->ek, 1, rcf->eklen, c_handle);
	c_ffunc(rcf->iv, 1, EVP_CIPHER_iv_length(EVP_aes_256_gcm()), c_handle);
    }
    if (mode == 'r') {
	rcf->c_fread = c_ffunc;

	c_ffunc(&eklen_n, 1, sizeof(eklen_n), c_handle);
	rcf->eklen = ntohl(eklen_n);
	rcf->ek = malloc(EVP_PKEY_size(evp_keypair));
	c_ffunc(rcf->ek, 1, rcf->eklen, c_handle);
	c_ffunc(&(rcf->iv), 1, EVP_CIPHER_iv_length(EVP_aes_256_gcm()), c_handle);
	EVP_OpenInit(rcf->ctx, EVP_aes_256_gcm(), rcf->ek, rcf->eklen, rcf->iv, evp_keypair);
    }
    rcf->c_handle = c_handle;

    return(rcf);
}

size_t rsa_write(void *buf, size_t sz, size_t count, struct rsa_file *rcf)
{
    size_t n = sz * count;
    int w = 0;
    int bufroom = 0;
    size_t t = 0;

    do {
	bufroom = rcf->bufsize - (rcf->bufp - rcf->buf);
	if (n <= bufroom) {
	    memcpy(rcf->bufp, buf, n);
	    rcf->bufp += n;
	    t += n;
	    n = 0;
	}
	else {
	    memcpy(rcf->bufp, buf, bufroom);
	    rcf->bufp += bufroom;
	    t += bufroom;
	    n -= bufroom;
	    buf += bufroom;
	    EVP_SealUpdate(rcf->ctx, rcf->outbuf, &w, rcf->buf, rcf->bufsize);
	    rcf->c_fwrite(rcf->outbuf, 1, w, rcf->c_handle);
	    rcf->bufp = rcf->buf;
	}

    } while (n > 0);
    return(t);
}

int rsa_file_finalize(struct rsa_file *rcf)
{
    int w;
    if (rcf->mode == 'w') {
	if (rcf->bufp > rcf->buf) {
	    EVP_SealUpdate(rcf->ctx, rcf->outbuf, &w, rcf->buf, rcf->bufp - rcf->buf);
	    rcf->c_fwrite(rcf->outbuf, 1, w, rcf->c_handle);
	}
	EVP_SealFinal(rcf->ctx, rcf->outbuf, &w);
	rcf->c_fwrite(rcf->outbuf, 1, w, rcf->c_handle);
    }
    if (rcf->mode == 'r') {
    }
    EVP_CIPHER_CTX_cleanup(rcf->ctx);
    free(rcf->buf);
    free(rcf->outbuf);
    free(rcf->ek);
    free(rcf);
    return(0);
}

size_t rsa_read(void *buf, size_t sz, size_t count, struct rsa_file *rcf)
{
    size_t n = sz * count;
    size_t c = 0;
    int d = 0;
    int t = 0;

    memset(buf, 0, n);
    do {
	if (rcf->buf + rcf->bufused - rcf->bufp == 0 && rcf->eof == 1) {
	    return(t);
	}
	if (rcf->buf + rcf->bufused - rcf->bufp == 0 && rcf->eof != 1) {
	    rcf->bufp = rcf->buf;
	    rcf->bufused = 0;
	    c = rcf->c_fread(rcf->inbuf, 1, rcf->bufsize, rcf->c_handle);
	    if (c > 0) {
		EVP_OpenUpdate(rcf->ctx, rcf->buf, &d, rcf->inbuf, c);
		rcf->bufused += d;
	    }
	    else {
		EVP_OpenFinal(rcf->ctx, rcf->buf, &d);
		rcf->bufused += d;
		rcf->eof = 1;
	    }
	}
	c = (n <= (rcf->buf + rcf->bufused - rcf->bufp) ? n : rcf->buf + rcf->bufused - rcf->bufp);
	if (c == 0 && rcf->eof == 1) {
	    return(t);
	}
	memcpy(buf, rcf->bufp, c);
	rcf->bufp += c;
	buf += c;
	t += c;
	n -= c;
    } while (n > 0);
    return(t);
}

void openssl_err()
{
    int rsaerr;
    char rsaerrs[121];
    ERR_load_crypto_strings();
    while ((rsaerr = ERR_get_error()) > 0) {
	fprintf(stderr, "%s\n", ERR_error_string(rsaerr, rsaerrs));
    }
}

EVP_PKEY *rsa_getkey(char mode, struct key_st *k)
{
    static EVP_PKEY *evp_keypair = NULL;
    BIO *rsa_keydata = NULL;

    OpenSSL_add_all_algorithms();
    if (evp_keypair == NULL) {
	evp_keypair = EVP_PKEY_new();
	if (mode == 'd') {
	    rsa_keydata = BIO_new_mem_buf(k->eprvkey, strlen(k->eprvkey));
	    PEM_read_bio_PrivateKey(rsa_keydata, &evp_keypair, NULL, NULL);
	}
	if (mode == 'e') {
	    rsa_keydata = BIO_new_mem_buf(k->pubkey, strlen(k->pubkey));
	    PEM_read_bio_PUBKEY(rsa_keydata, &evp_keypair, NULL, NULL);
	}
	openssl_err();
	BIO_free(rsa_keydata);
    }
    return(evp_keypair);
}

struct key_st *load_keyfile(char *keyfilename)
{
    FILE *keyfile;
    long keyfile_sz;
    char *keydata;
    struct key_st *key_st;

    keyfile = fopen(keyfilename, "r");
    fseek(keyfile, 0L, SEEK_END);
    keyfile_sz = ftell(keyfile);
    rewind(keyfile);

    keydata = malloc(keyfile_sz + 1);
    key_st = malloc(sizeof(struct key_st));
    fread(keydata, 1, keyfile_sz, keyfile);
    keydata[keyfile_sz] = '\0';
    fclose(keyfile);

    key_st->eprvkey = strstr(keydata, "-----BEGIN ENCRYPTED PRIVATE KEY-----");
    key_st->pubkey = strstr(keydata, "-----BEGIN PUBLIC KEY-----");
    key_st->hmac_key_b64 = strstr(keydata, "-----BEGIN HMAC KEY-----");
    key_st->hmac_key_enc_b64 = strstr(keydata, "-----BEGIN ENCRYPTED HMAC KEY-----");
    key_st->comment = strstr(keydata, "-----BEGIN COMMENT-----");
    *(strchr(strstr(key_st->eprvkey, "-----END ENCRYPTED PRIVATE KEY-----"),
	'\n')) = '\0';
    *(strchr(strstr(key_st->pubkey, "-----END PUBLIC KEY-----"),
	'\n')) = '\0';
    *(strchr(strstr(key_st->hmac_key_b64, "-----END HMAC KEY-----"),
	'\n')) = '\0';
    *(strchr(strstr(key_st->hmac_key_enc_b64, "-----END ENCRYPTED HMAC KEY-----"),
	'\n')) = '\0';
    *(strchr(strstr(key_st->comment, "-----END COMMENT-----"),
	'\n')) = '\0';
    key_st->hmac_key_b64 = (strchr(key_st->hmac_key_b64, '\n') + 1);
    *(strchr(key_st->hmac_key_b64, '\n')) = '\0';
    key_st->hmac_key_enc_b64 = (strchr(key_st->hmac_key_enc_b64, '\n') + 1);
    *(strchr(key_st->hmac_key_enc_b64, '\n')) = '\0';
    key_st->comment = (strchr(key_st->comment, '\n') + 1);
    *(strchr(key_st->comment, '\n')) = '\0';
    return(key_st);
}

unsigned char *sha256_digest(char *msg)
{
    EVP_MD_CTX ctx;
    unsigned char b[EVP_MAX_MD_SIZE];
    unsigned char *d;
    unsigned int sz;

    OpenSSL_add_all_digests();
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, msg, strlen(msg));
    EVP_DigestFinal(&ctx, b, &sz);
    d = malloc(((sz + (3 - 1)) / 3) * 4 + 2);
    EVP_EncodeBlock(d, b, sz);
    return(d);
}

unsigned char *sha256_hex(char *msg)
{
    EVP_MD_CTX ctx;
    unsigned char b[EVP_MAX_MD_SIZE];
    unsigned char *d;
    unsigned int sz;

    OpenSSL_add_all_digests();
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, msg, strlen(msg));
    EVP_DigestFinal(&ctx, b, &sz);
    d = malloc(sz * 2 + 1);
    encode_block_16(d, b, sz);
    return(d);
}

int load_pkey(struct rsa_keys **rsa_keys, char *pubkey_fingerprint, char *eprivkey, char *keycomment)
{
    BIO *rsa_keydata;
    int i = 0;
    char decrypt_message[2048];

    if (*rsa_keys == NULL) {
	*rsa_keys = dmalloc(sizeof(struct rsa_keys));
	(*rsa_keys)->numkeys = 0;
	(*rsa_keys)->keys = NULL;
    }
    for (i = 0; i < (*rsa_keys)->numkeys; i++) {
	if (strcmp((*rsa_keys)->keys[i].fingerprint, pubkey_fingerprint) == 0) {
	    return(0);
	}
    }
    if (i >= (*rsa_keys)->numkeys) {
	(*rsa_keys)->keys = drealloc((*rsa_keys)->keys, sizeof(struct key_st) * (i + 1));
	(*rsa_keys)->keys[i].fingerprint = NULL;
	(*rsa_keys)->keys[i].comment = NULL;
	(*rsa_keys)->keys[i].eprvkey = NULL;
	(*rsa_keys)->keys[i].evp_keypair = EVP_PKEY_new();
	(*rsa_keys)->numkeys = i + 1;
    }

    OpenSSL_add_all_algorithms();
    strncpya0(&((*rsa_keys)->keys[i].fingerprint), pubkey_fingerprint, strlen(pubkey_fingerprint));
    if (keycomment != NULL)
	strncpya0(&((*rsa_keys)->keys[i].comment), keycomment, strlen(keycomment));
    strncpya0(&((*rsa_keys)->keys[i].eprvkey), eprivkey, strlen(eprivkey));
//    rsa_keydata = BIO_new_mem_buf((*rsa_keys)->keys[i].eprvkey, strlen((*rsa_keys)->keys[i].eprvkey));
    rsa_keydata = BIO_new_mem_buf((*rsa_keys)->keys[i].eprvkey, -1);
    if (keycomment != NULL) {
	snprintf(decrypt_message, 1023, "Loading decryption key for:\n%s\nEnter passphrase: ", keycomment);
    }
//    PEM_read_bio_PrivateKey(rsa_keydata, &((*rsa_keys)->keys[i].evp_keypair), NULL, NULL);
    if (PEM_read_bio_PrivateKey(rsa_keydata, &((*rsa_keys)->keys[i].evp_keypair), get_passwd, decrypt_message) == NULL) {
	BIO_free(rsa_keydata);
	rsa_keydata = BIO_new_mem_buf((*rsa_keys)->keys[i].eprvkey, -1);
	snprintf(decrypt_message, 1023, "That didn't work.\nRe-enter passphrase: ");
	while (PEM_read_bio_PrivateKey(rsa_keydata, &((*rsa_keys)->keys[i].evp_keypair), get_passwd, decrypt_message) == NULL) {
	    PEM_read_bio_PrivateKey(rsa_keydata, &((*rsa_keys)->keys[i].evp_keypair), NULL, NULL);
	    BIO_free(rsa_keydata);
	    rsa_keydata = BIO_new_mem_buf((*rsa_keys)->keys[i].eprvkey, -1);
	}
    }
    return(0);
}
int get_passwd(char *buf, int size, int rwflag, void *prompt)
{
    if (UI_UTIL_read_pw(buf, "hello: ", size, prompt, rwflag) == 0)
	return(strlen(buf));
    return(-1);
}
int get_pkey(struct rsa_keys *rsa_keys, char *fp)
{
    int i;
    for (i = 0; i < rsa_keys->numkeys; i++) {
	if (strcmp(rsa_keys->keys[i].fingerprint, fp) == 0)
	    return(i);
    }
    return(-1);
}

struct tar_maxread_st *tar_maxread_init(size_t sz, size_t (*c_ffunc)(), void *c_handle)
{
    struct tar_maxread_st *tmr = malloc(sizeof(struct tar_maxread_st));
    tmr->max = sz;
    tmr->sz = sz;
    tmr->c_fread = c_ffunc;
    tmr->c_handle = c_handle;
    return(tmr);
}

size_t tar_maxread(void *buf, size_t sz, size_t count, struct tar_maxread_st *tmr)
{
    size_t n = sz * count;
    size_t t = 0;
    t = tmr->c_fread(buf, 1, n <= tmr->sz ? n : tmr->sz, tmr->c_handle);
    tmr->sz -= t;
    return(t);
}

int tar_maxread_finalize(struct tar_maxread_st *tmr)
{
    char padding[512];
    size_t n;
    while ((n = tmr->c_fread(padding, 1, tmr->sz >= 512 ? 512 : tmr->sz, tmr->c_handle)) > 0)
	tmr->sz -= n;

    free(tmr);
    return(0);
}

int encode_block_16(unsigned char *r, unsigned char *s, int c)
{
    char *hexchars = "0123456789ABCDEF";

    int i = 0;

    for (i = 0; i < c; i++) {
	r[i * 2] = hexchars[(s[i] & 0xF0) >> 4];
	r[i * 2 + 1] = hexchars[(s[i] & 0xF )];
    }
    r[i * 2] = '\0';
    return(c * 2);
}

int decode_block_16(unsigned char *r, unsigned char *s, int c)
{
    unsigned char H;
    unsigned char L;
    int i = 0;
    int n = 0;
    for (i = 0; i < c; i++) {
	H = (s[i] >= '0' && s[i] <= '9' ? s[i] - '0' : s[i] >= 'A' && s[i] <= 'F' ? s[i] - 'A' + 10 : 0);
	i++;
	L = (s[i] >= '0' && s[i] <= '9' ? s[i] - '0' : s[i] >= 'A' && s[i] <= 'F' ? s[i] - 'A' + 10 : 0);
	r[n] = (H << 4) | L;
	n++;
    }
    r[n] = '\0';
    return(c / 2);
}

int gen_sparse_data_string(struct filespec *fs, char **sparsetext)
{
    char sparsetextp[128];

    if (*sparsetext != NULL) {
	(*sparsetext)[0] = '\0';
    }
    sprintf(sparsetextp, "%llu", (unsigned long long int) fs->n_sparsedata);
    strcata(sparsetext, sparsetextp);
    for (int i = 0; i < fs->n_sparsedata; i++) {
	sprintf(sparsetextp, ":%llu:%llu", (unsigned long long int) fs->sparsedata[i].offset, (unsigned long long int) fs->sparsedata[i].size);
	strcata(sparsetext, sparsetextp);
    }
    strcata(sparsetext, "\n");
    return(strlen(*sparsetext));
}
int c_fread_sparsedata(size_t (*c_ffunc)(), void *c_handle, struct filespec *fs)
{
    int i = 0;
    char tmpbuf[16];
    char *tmpbufp = tmpbuf;
    char *sparsetext = NULL;
    int sparsetext_len = 0;
    char *tokenp;
    int sparsetext_leni = 0;

    for (i = 0; i < 15; i++) {
	if (c_ffunc(tmpbufp, 1, 1, c_handle) == 1) {
	    if (*tmpbufp == ':') {
		*tmpbufp = '\0';
		break;
	    }
	    tmpbufp++;
	}
	else {
	    return(i);
	}
    }
    sparsetext_len = atoi(tmpbuf);
    sparsetext_leni = strlen(tmpbuf) + 1;
    sparsetext = malloc(sparsetext_len);
    c_ffunc(sparsetext, 1, sparsetext_len, c_handle);
    if (sparsetext[sparsetext_len - 1] == '\n')
	sparsetext[sparsetext_len - 1] = '\0';
    tokenp = strtok(sparsetext, ":");
    if (tokenp == NULL) {
	fprintf(stderr, "Sparse file header corrupted\n");
	if (sparsetext != NULL)
	    free(sparsetext);
	return(sparsetext_len + sparsetext_leni);
    }
    fs->n_sparsedata = atoi(tokenp);
    fs->sparsedata = drealloc(fs->sparsedata, fs->n_sparsedata * sizeof(struct sparsedata));
    i = 0;
    while ((tokenp = strtok(NULL, ":")) != NULL) {
	if ((int) (i / 2) >= fs->n_sparsedata)
	    break;
	if (i % 2 == 0)
	    fs->sparsedata[(int) (i / 2)].offset = atoi(tokenp);
	else
	    fs->sparsedata[(int) (i / 2)].size= atoi(tokenp);
	i++;
    }
    if (sparsetext != NULL)
	free(sparsetext);
    return(sparsetext_len + sparsetext_leni);
}
