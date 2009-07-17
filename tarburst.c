#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <openssl/md5.h>
main(int argc, char **argv)
{
    int count;
    int tcount;
    struct {
	unsigned char filename[100];	//   0 - 99
	char mode[8];			// 100 - 107
	char nuid[8];			// 108 - 115
	char ngid[8];			// 116 - 123
	char size[12];			// 124 - 135
	char modtime[12];		// 136 - 147
	char chksum[8];			// 148 - 155
	char ftype[1];			// 156
	unsigned char linktarget[100];	// 157 - 256
	char ustar[6];			// 257 - 262
	char ustarver[2];		// 263 - 264
	char auid[32];			// 265 - 296
	char agid[32];			// 297 - 328
	char devmaj[8];			// 329 - 336
	char devmin[8];			// 337 - 344
	union {
	    char fileprefix[155];	// 345 - 499
	    struct {
		char reserved1[41];	// 345 - 385
		struct {
		    char offset[12];	// 386 - 397, 410 - 421, ...
		    char size[12];	// 398 - 409, 422 - 431, ...
		} sd[4];		// 386 - 481
		char isextended;	// 482
		char realsize[12];	// 483 - 494
		char reserved2[5];	// 495 - 499
	    } sph;   // sparse header	// 345 - 499
	} u;
	char reserved[12];		// 500 - 511
    } tarhead;
    struct {
	struct {
	    char offset[12];
	    char size[12];
	} sd[21];			// 0 - 503
	char isextended;		// 504
	char reserved[8];		// 505 - 512
    } speh;  // sparse extended header

    char *filename = 0;
    char *efilename = 0;
    char *linktarget = 0;
    char *elinktarget = 0;
    int echars;

    char junk[512];
    unsigned long long int filesize;
    int i, j;
    unsigned long long int fullblocks;
    int partialblock;
    int blockpad;
    int nuid, ngid, modtime, mode;
    int bytestoread;
    unsigned long long int blockstoread;
    int curfilenum = 0;
    char curblock[512];
    int curtmpfile;
    FILE *curfile;
    char *destdir = 0;
    char *destfilepath = 0;
    char *destfilepathm = 0;
    char *manifestpath = 0;
    char *tmpfiledir = 0;
    char *tmpfilepath;
    MD5_CTX cfmd5ctl; // current file's md5 sum
    unsigned char cfmd5[MD5_DIGEST_LENGTH];
    char cfmd5a[MD5_DIGEST_LENGTH * 2 + 10];
    char cfmd5d[MD5_DIGEST_LENGTH * 2 + 10];
    char cfmd5f[MD5_DIGEST_LENGTH * 2 + 10];
    int zin[2]; // input pipe for compression
    int zout[2]; // output pipe for compression
    pid_t cprocess;
    int opt;
    FILE *manifest;
    struct {
	unsigned long long int offset;
	unsigned long long int size;
    } *sparsedata;
    unsigned long long int s_realsize;
    char s_isextended;
    int n_sparsedata;
    int n_esparsedata;
    int m_sparsedata = 20;
    struct stat fs;

    while ((opt = getopt(argc, argv, "d:m:t:")) != -1) {
	switch (opt) {
	case 'd':
	    destdir = optarg;
	    break;
	case 'm':
	    manifestpath = optarg;
	    break;
	case 't':
	    tmpfiledir = optarg;
	    break;
	}
    }
    if (destdir == 0)
	destdir = ".";
    if (tmpfiledir == 0)
	tmpfiledir = destdir;
    if (manifestpath == 0)
	sprintf((manifestpath = malloc(strlen(destdir) + 10)), "%s/manifest", destdir);
    
    sparsedata = malloc(m_sparsedata * sizeof(*sparsedata));

    manifest = fopen(manifestpath, "w");
    while (1) {
        // Read tar 512 byte header into tarhead structure
    	count = fread(&tarhead, 1, 512, stdin);
    	if (count < 512) {
    		printf("tar short read\n");
    		exit (1);
       	}
	if (tarhead.filename[0] == 0) {
//	    printf("End of tar file\n");
	    exit(0);
	}
    
	// A file type of "L" means a long (> 100 character) filename.  File name begins in next block.
	if (*(tarhead.ftype) == 'L') {
	    bytestoread=strtoull(tarhead.size, 0, 8);
	    blockpad = 512 - (bytestoread % 512);
	    filename = malloc(bytestoread + 1);
	    count = fread(filename, 1, bytestoread, stdin);
	    if (count < bytestoread) {
		printf("tar short read\n");
		exit(1);
	    }
	    count = fread(junk, 1, blockpad, stdin);
	    if (count < blockpad) {
		printf("tar short read\n");
		exit(1);
	    }
	    filename[bytestoread] = 0;
	    continue;
	}
	// A file type of "K" means a long (> 100 character) link target.
	if (*(tarhead.ftype) == 'K') {
	    bytestoread=strtoull(tarhead.size, 0, 8);
	    blockpad = 512 - (bytestoread % 512);
	    linktarget = malloc(bytestoread);
	    tcount = 0;
	    while (bytestoread - tcount > 0) {
		count = fread(linktarget + tcount, 1, bytestoread - tcount, stdin);
		tcount += count;
	    }
	    tcount = 0;
	    while (blockpad - tcount > 0) {
		count = fread(junk, 1, blockpad - tcount, stdin);
		tcount += count;
	    }
	    continue;
	}

	filesize = 0;
	if ((unsigned char) tarhead.size[0] == 128)
	    for (i = 0; i < 8; i++)
		filesize += (( ((unsigned long long) ((unsigned char) (tarhead.size[11 - i]))) << (i * 8)));
	else
	    filesize=strtoull(tarhead.size, 0, 8);
	nuid=strtol(tarhead.nuid, 0, 8);
	ngid=strtol(tarhead.ngid, 0, 8);
	modtime=strtol(tarhead.modtime, 0, 8);
	mode=strtol(tarhead.mode + 2, 0, 8);
	fullblocks = (filesize / 512);
	partialblock = filesize - (fullblocks * 512);

	if (strlen(tarhead.auid) == 0)
	    sprintf(tarhead.auid, "%d", nuid);
	if (strlen(tarhead.agid) == 0)
	    sprintf(tarhead.agid, "%d", ngid);

	if (filename == 0) {
	    strncpy((filename = malloc(101)), tarhead.filename, 100);
	    filename[100] = 0;
	}
	if (linktarget == 0) {
	    strncpy((linktarget = malloc(101)), tarhead.linktarget, 100);
	    linktarget[100] = 0;
	}
	echars = 0;
	for (i = 0; i < strlen(filename); i++)
	    if (filename[i] <= 32 || filename[i] >= 127 || filename[i] == 92)
		echars++;
	efilename = malloc(strlen(filename) + echars * 4 + 1);
	*efilename = 0;
	i = 0;
	while (i < strlen(filename)) {
	    for (j = i; i < strlen(filename) && filename[i] > 32 && filename[i] < 127 &&
		filename[i] != 92; i++)
		;
	    strncat(efilename, filename + j, i - j);
	    if (i < strlen(filename)) {
		sprintf(efilename + strlen(efilename), "\\%3.3o", (unsigned char) filename[i]);
		i++;
	    }
	}
	echars = 0;
	for (i = 0; i < strlen(linktarget); i++)
	    if (linktarget[i] <= 32 || linktarget[i] >= 127 || linktarget[i] == 92)
		echars++;
	elinktarget = malloc(strlen(linktarget) + echars * 3 + 1);
	*elinktarget = 0;
	i = 0;
	while (i < strlen(linktarget)) {
	    for (j = i; i < strlen(linktarget) && linktarget[i] > 32 && linktarget[i] < 127 &&
		linktarget[i] != 92; i++)
		;
	    strncat(elinktarget, linktarget + j, i - j);
	    if (i < strlen(linktarget)) {
		sprintf(elinktarget + strlen(elinktarget), "\\%3.3o", (unsigned char) linktarget[i]);
		i++;
	    }
	}

	// If this is a regular file (type 0)
        if (*(tarhead.ftype) == '0' || *(tarhead.ftype) == 'S') {
	    // Handle sparse files
	    if (*(tarhead.ftype) == 'S') {
		s_isextended = tarhead.u.sph.isextended;
		n_sparsedata = 0;
	        if ((unsigned char) tarhead.u.sph.realsize[0] == 128)
		    for (i = 0; i < 8; i++)
		        s_realsize  += (( ((unsigned long long) ((unsigned char) (tarhead.u.sph.realsize[11 - i]))) << (i * 8)));
		else
		    s_realsize = strtoull(tarhead.u.sph.realsize, 0, 8);

		for (n_sparsedata = 0; n_sparsedata < 4 && tarhead.u.sph.sd[n_sparsedata].offset[0] != 0; n_sparsedata++) {
		    sparsedata[n_sparsedata].offset = 0;
		    sparsedata[n_sparsedata].size = 0;
		    if (n_sparsedata >= m_sparsedata - 1) {
			sparsedata = realloc(sparsedata, sizeof(*sparsedata) * (m_sparsedata += 20));
		    }
	            if ((unsigned char) tarhead.u.sph.sd[n_sparsedata].offset[0] == 128)
			for (i = 0; i < 8; i++)
			    sparsedata[n_sparsedata].offset  += (( ((unsigned long long) ((unsigned char) (tarhead.u.sph.sd[n_sparsedata].offset[11 - i]))) << (i * 8)));
		    else
			sparsedata[n_sparsedata].offset = strtoull(tarhead.u.sph.sd[n_sparsedata].offset, 0, 8);
	            if ((unsigned char) tarhead.u.sph.sd[n_sparsedata].size[0] == 128)
			for (i = 0; i < 8; i++)
			    sparsedata[n_sparsedata].size += (( ((unsigned long long) ((unsigned char) (tarhead.u.sph.sd[n_sparsedata].size[11 - i]))) << (i * 8)));
		    else
			sparsedata[n_sparsedata].size = strtoull(tarhead.u.sph.sd[n_sparsedata].size, 0, 8);
		}

		while (s_isextended == 1) {
		    count = fread(&speh, 1, 512, stdin);
		    if (count < 512) {
			printf("tar short read\n");
			exit(1);
		    }
		    s_isextended = speh.isextended;

    		    for (n_esparsedata = 0; n_esparsedata < 21 && speh.sd[n_esparsedata].offset[0] != 0; n_esparsedata++, n_sparsedata++) {
			if (n_sparsedata >= m_sparsedata - 1) {
			    sparsedata = realloc(sparsedata, sizeof(*sparsedata) * (m_sparsedata += 20)); 
			}
			sparsedata[n_sparsedata].offset = 0;
			sparsedata[n_sparsedata].size = 0;
			if ((unsigned char) speh.sd[n_esparsedata].offset[0] == 128)
			    for (i = 0; i < 8; i++)
				sparsedata[n_sparsedata].offset  += (( ((unsigned long long) ((unsigned char) (speh.sd[n_esparsedata].offset[11 - i]))) << (i * 8)));
			else
			    sparsedata[n_sparsedata].offset = strtoull(speh.sd[n_esparsedata].offset, 0, 8);
			if ((unsigned char) speh.sd[n_esparsedata].size[0] == 128)
			    for (i = 0; i < 8; i++)
				sparsedata[n_sparsedata].size += (( ((unsigned long long) ((unsigned char) (speh.sd[n_esparsedata].size[11 - i]))) << (i * 8)));
			else
			    sparsedata[n_sparsedata].size = strtoull(speh.sd[n_esparsedata].size, 0, 8);
		    }
		}
	    }

	    if (partialblock > 0)
		blockpad = 512 - partialblock;
	    else
		blockpad = 0;

	    tmpfilepath = malloc(strlen(tmpfiledir) + 10);
	    sprintf(tmpfilepath, "%s/tbXXXXXX", tmpfiledir);
	    curtmpfile = mkstemp(tmpfilepath);
	    if (curtmpfile == -1) {
		fprintf(stderr, "Error opening temp file\n");
		exit(1);
	    }

	    pipe(zin);
	    if ((cprocess = fork()) == 0) {
		close(zin[1]);
		dup2(zin[0], 0);
		dup2(curtmpfile, 1);
		execlp("lzop", "lzop", (char *) NULL);
		printf("Error\n");
		exit(1);
	    }
	    close(zin[0]);
	    curfile = fdopen(zin[1], "w");

	    blockstoread = fullblocks + (partialblock > 0 ? 1 : 0);
//	printf("File contains %d 512-byte blocks and a final %d block\n", blockstoread, partialblock);
	    MD5_Init(&cfmd5ctl);
	    for (i = 1; i <= blockstoread; i++) {
		count = fread(curblock, 1, 512, stdin);
		if (count < 512) {
		    printf("tar short read\n");
		    exit(1);
		}

		if (i == blockstoread) {
		    if (partialblock > 0) {
    //		    printf("Writing out partial block %d\n", partialblock);
			fwrite(curblock, 1, partialblock, curfile);
			MD5_Update(&cfmd5ctl, curblock, partialblock);
			break;
		    }
		}
//	    printf("Writing out block number %d of %d to %d\n", i, blockstoread, curfile);
		fwrite(curblock, 512, 1, curfile);
		MD5_Update(&cfmd5ctl, curblock, 512);
	    }
	    fflush(curfile);
	    fclose(curfile);
	    waitpid(cprocess, NULL, 0);
	    close(curtmpfile);
	    MD5_Final(cfmd5, &cfmd5ctl);
	    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(cfmd5a + i * 2, "%2.2x", (unsigned int) cfmd5[i]);
	    cfmd5a[i * 2] = 0;
	    for (i = 0; i < 1; i++)
		sprintf(cfmd5d + i * 2, "%2.2x", (unsigned int) cfmd5[i]);
	    cfmd5d[i * 2] = 0;
	    for (i = 1; i < MD5_DIGEST_LENGTH; i++)
		sprintf(cfmd5f + (i - 1) * 2, "%2.2x", (unsigned int) cfmd5[i]);
	    cfmd5f[(i - 1) * 2] = 0;

	    sprintf((destfilepath = malloc(strlen(destdir) + strlen(cfmd5a) + 7)), "%s/%s/%s.lzo", destdir, cfmd5d, cfmd5f);
	    sprintf((destfilepathm = malloc(strlen(destdir) + 4)), "%s/%s", destdir, cfmd5d);
	    if (stat(destfilepath, &fs) == 0)
		remove(tmpfilepath);
	    else
		if (stat(destfilepathm, &fs) == 0)
		    rename(tmpfilepath, destfilepath);
		else {
		    if (mkdir(destfilepathm, 0770) == 0)
			rename(tmpfilepath, destfilepath);
		    else {
			fprintf(stderr, "Error creating directory %s\n", destfilepath);
			exit(1);
		    }
		}
	    if (*(tarhead.ftype) == 'S') {
		fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\t%llu",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, s_realsize, cfmd5a, modtime, efilename, filesize);
		for (i = 0; i < n_sparsedata; i++)
		    fprintf(manifest,":%llu:%llu", sparsedata[i].offset, sparsedata[i].size);
		fprintf(manifest, "\n");
	    }
	    else
		fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\n",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, filesize, cfmd5a, modtime, efilename);

	    fflush(manifest);
	    free(tmpfilepath);
	    free(destfilepath);
	    free(destfilepathm);
	}
	// Hard link (type 1) or sym link (type 2)
	else if (*(tarhead.ftype) == '1' || *(tarhead.ftype) == '2') {
	    fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\t%s\n",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, filesize, "0", modtime, efilename, elinktarget );
	}
	// Directory entry (type 5)
	else if (*(tarhead.ftype) == '5') {
	    fprintf(manifest, "%c\t%4.4o\t%s\t%d\t%s\t%d\t%llu\t%s\t%d\t%s\n",*(tarhead.ftype), mode, tarhead.auid, nuid, tarhead.agid, ngid, filesize, "0", modtime, efilename);
	}


	if (filename == 0)
	    free(filename);
	filename = 0;
	free(efilename);
	efilename = 0;
	if (linktarget != 0)
	    free(linktarget);
	linktarget = 0;
	if (elinktarget != 0)
	    free(elinktarget);
	linktarget = 0;
    }
}
