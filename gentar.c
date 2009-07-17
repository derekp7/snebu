#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

long int strtoln(char *nptr, char **endptr, int base, int len);

struct tarhead {
        unsigned char filename[100];
        char mode[8];
        char nuid[8];
        char ngid[8];
        char size[12];
        char modtime[12];
        char chksum[8];
        char ftype[1];
        unsigned char linktarget[100];
        char ustar[6];
        char ustarver[2];
        char auid[32];
        char agid[32];
        char devmaj[8];
        char devmin[8];
        union {
            char fileprefix[155];       // 345 - 499
            struct {
                char reserved1[41];     // 345 - 385
		char item[8][12];
//                struct {
//                    char offset[12];    // 386 - 397, 410 - 421, ...
//                    char size[12];      // 398 - 409, 422 - 431, ...
//                } sd[4];                // 386 - 481
                char isextended;        // 482
                char realsize[12];      // 483 - 494
                char reserved2[5];      // 495 - 499
            } sph;   // sparse header   // 345 - 499
        } u;
        char reserved[12];
};
struct speh {		// sparse extended header
    char item[42][12];
//    struct {
//        char offset[12];
//        char size[12];
//    } sd[21];                       // 0 - 503
    char isextended;                // 504
    char reserved[7];               // 505 - 511
}; 


main(int argc, char **argv)
{

    struct tarhead tarhead;
    struct tarhead longtarhead;
    struct speh speh;

    char *srcdir = 0;
    char *manifestpath = 0;
    FILE *manifest;
    FILE *curfile;
    char md5[33];
    unsigned char *filename = 0;
    unsigned char *efilename = 0;
    unsigned char *linktarget = 0;
    unsigned char *elinktarget = 0;
    int opt;
    int i, j;
    char *p;
    unsigned long tmpchksum;
    char *md5filepath;
    int zin[2];
    pid_t cprocess;
    int md5file;
    unsigned long long bytestoread;
    int count;
    char curblock[512];
    char *instr = 0;
    size_t instrlen = 0;

    struct {
	char ftype;
	int mode;
	char auid[33];
	char agid[33];
	int nuid;
	int ngid;
	int modtime;
        unsigned long long int filesize;
    } t;
    long long int tblocks;
    unsigned int lendian = 1;	// Little endian?

    struct {
        unsigned long long int offset;
        unsigned long long int size;
    } *sparsedata;
    unsigned long long int s_realsize;
    char s_isextended;
    int n_sparsedata;
    int n_esparsedata;
    int m_sparsedata = 20;
    char *ssparseinfo;
    long long int *sparseinfo;
    int nsi;
    int msi;

    lendian = (unsigned int) (((unsigned char *)(&lendian))[0]); // little endian test
    msi = 256;
    sparseinfo = malloc(msi * sizeof(*sparseinfo));

    while ((opt = getopt(argc, argv, "d:m:")) != -1) {
        switch (opt) {
        case 'd':
            srcdir = optarg;
//	    fprintf(stderr, "Setting srcdir to %s\n", optarg);
            break;
        case 'm':
            manifestpath = optarg;
//	    fprintf(stderr, "Setting manifest to %s\n", optarg);
            break;
        }
    }
    if (srcdir == 0)
	srcdir = ".";
    if (manifestpath == 0)
	sprintf(manifestpath = malloc(strlen(srcdir) + 10), "%s/%s", srcdir, "manifest");

    md5filepath = malloc(strlen(srcdir) + 39);
    if (strcmp(manifestpath, "-") == 0)
	manifest = stdin;
    else
	manifest = fopen(manifestpath, "r");

    if (manifest == 0) {
	fprintf(stderr, "Error %d opening manifest\n", errno);
	exit(1);
    }

    for (i = 0; i < sizeof(tarhead); i++) {
	(((unsigned char *) (&tarhead)))[i] = 0;
    }

//    while (fgets(instr, 4000000, manifest) > 0) {
    while (getline(&instr, &instrlen, manifest) > 0) {
	sscanf(instr, "%c\t", &(t.ftype));
	if (t.ftype == '1' || t.ftype == '2') {
	    sscanf(instr, "%c\t%o\t%32s\t%d\t%32s\t%d\t%Ld\t%32s\t%d\t%as\t%as\n",
		&(t.ftype), &t.mode, t.auid, &t.nuid, t.agid, &t.ngid, &(t.filesize),
		md5, &t.modtime, &efilename, &elinktarget);
	    t.filesize = 0;
	}
	else if (t.ftype == 'S') {
	    sscanf(instr, "%c\t%o\t%32s\t%d\t%32s\t%d\t%Ld\t%32s\t%d\t%as\t%as\n",
		&(t.ftype), &t.mode, t.auid, &t.nuid, t.agid, &t.ngid, &(t.filesize),
		md5, &t.modtime, &efilename, &ssparseinfo);
	}
	else {
	    i = sscanf(instr, "%c\t%o\t%32s\t%d\t%32s\t%d\t%Ld\t%32s\t%d\t%as\n",
		&(t.ftype), &t.mode, t.auid, &t.nuid, t.agid, &t.ngid, &(t.filesize),
		md5, &t.modtime, &efilename);

	}
	filename = malloc(strlen(efilename) + 1);
	for (i = 0; i < strlen(efilename) + 1; i++)
	    filename[i] = 0;
	i = 0;
	while (i < strlen(efilename)) {
	    for (j = i; i < strlen(efilename) && efilename[i] != 92; i++)
	        ;
//	    fwrite(efilename + j, 1, i - j, stderr);
//	    fwrite("\n", 1, 1, stderr);
	    strncat(filename, efilename + j, i - j);
	    if (i < strlen(efilename)) {
		filename[strlen(filename)] = (char) strtoln(efilename + ++i, NULL, 8, 3);
		i += 3;
	    }
	}
	if (elinktarget != 0) {
	    linktarget = malloc(strlen(elinktarget) + 1);
	    for (i = 0; i < strlen(elinktarget) + 1; i++)
		linktarget[i] = 0;
	    i = 0;
	    while (i < strlen(elinktarget)) {
		for (j = i; i < strlen(elinktarget) && elinktarget[i] != 92; i++)
		    ;
		strncat(linktarget, elinktarget + j, i - j);
		if (i < strlen(elinktarget)) {
		    linktarget[strlen(linktarget)] = (char) strtoln(elinktarget+ ++i, NULL, 8, 3);
		    i += 3;
		}
	    }
    	    if (strlen(linktarget) > 100) {
    		for (i = 0; i < sizeof(longtarhead); i++)
    		    (((unsigned char *) (&longtarhead)))[i] = 0;
    		strcpy(longtarhead.filename, "././@LongLink");
    		*(longtarhead.ftype) = 'K';
    		strcpy(longtarhead.nuid, "0000000");
    		strcpy(longtarhead.ngid, "0000000");
    		strcpy(longtarhead.mode, "0000000");
    		sprintf(longtarhead.size, "%11.11o", strlen(linktarget));
    		strcpy(longtarhead.modtime, "00000000000");
    		strcpy(longtarhead.ustar, "ustar  ");
    		strcpy(longtarhead.auid, "root");
    		strcpy(longtarhead.agid, "root");
    		memcpy(longtarhead.chksum, "        ", 8);
    		for (tmpchksum = 0, p = (unsigned char *) (&longtarhead), i = 512;
    		    i != 0; --i, ++p)
    		    tmpchksum += 0xFF & *p;
    		sprintf(longtarhead.chksum, "%6o", tmpchksum);
    		fwrite(&longtarhead, 1, 512, stdout);
		tblocks++;
    		for (i = 0; i < strlen(linktarget); i += 512) {
    		    for (j = 0; j < 512; j++)
    			curblock[j] = 0;
    		    memcpy(curblock, linktarget + i, strlen(linktarget) - i >= 512 ? 512 :
    			(strlen(linktarget) - i));
		    fwrite(curblock, 1, 512, stdout);
		    tblocks++;
    		}
    	    }
	}
	if (strlen(filename) > 100) {
	    for (i = 0; i < sizeof(longtarhead); i++)
		(((unsigned char *) (&longtarhead)))[i] = 0;
	    strcpy(longtarhead.filename, "././@LongLink");
	    *(longtarhead.ftype) = 'L';
	    strcpy(longtarhead.nuid, "0000000");
	    strcpy(longtarhead.ngid, "0000000");
	    strcpy(longtarhead.mode, "0000000");
	    sprintf(longtarhead.size, "%11.11o", strlen(filename));
	    strcpy(longtarhead.modtime, "00000000000");
	    strcpy(longtarhead.ustar, "ustar  ");
	    strcpy(longtarhead.auid, "root");
	    strcpy(longtarhead.agid, "root");
	    memcpy(longtarhead.chksum, "        ", 8);
	    for (tmpchksum = 0, p = (unsigned char *) (&longtarhead), i = 512;
		i != 0; --i, ++p)
		tmpchksum += 0xFF & *p;
	    sprintf(longtarhead.chksum, "%6.6o", tmpchksum);
	    fwrite(&longtarhead, 1, 512, stdout);
	    tblocks++;
	    for (i = 0; i < strlen(filename); i += 512) {
		for (j = 0; j < 512; j++)
		    curblock[j] = 0;
		memcpy(curblock, filename + i, strlen(filename) - i >= 512 ? 512 :
		    (strlen(filename) - i));
		fwrite(curblock, 1, 512, stdout);
		tblocks++;
	    }
	}

	{
	    strncpy(tarhead.filename, filename, 100);
	    if (linktarget != 0)
		strncpy(tarhead.linktarget, linktarget, 100);

	    sprintf(tarhead.ustar, "ustar  ");
	    *(tarhead.ftype) = t.ftype;
	    sprintf(tarhead.mode, "%7.7o", t.mode);
	    strncpy(tarhead.auid, t.auid, 32);
	    sprintf(tarhead.nuid, "%7.7o", t.nuid);
	    strncpy(tarhead.agid, t.agid, 32);
	    sprintf(tarhead.ngid, "%7.7o", t.ngid);
	    sprintf(tarhead.modtime, "%11.11o", t.modtime);


	    if (t.ftype == 'S') {
		nsi = 0;
		p = ssparseinfo;
		for (nsi = 0, p = ssparseinfo, i = 0; ssparseinfo[i] != '\0'; i++) {
		    if (ssparseinfo[i] == ':') {
			ssparseinfo[i] = '\0';
			if (nsi >= msi - 1) {
			    msi += 64;
			    sparseinfo = realloc(sparseinfo, msi * sizeof(*sparseinfo));
			}
			sparseinfo[nsi++] = atoll(p);
			p = ssparseinfo + i + 1;
		    }
		}
		if (i > 0) {
		    sparseinfo[nsi++] = atoll(p);
		}

		sparseinfo[0] ^= t.filesize;
		t.filesize ^= sparseinfo[0];
		sparseinfo[0] ^= t.filesize;

		if (sparseinfo[0] <= 99999999999LL)
		    sprintf(tarhead.u.sph.realsize, "%11.11o", sparseinfo[0]);
		else {
		    tarhead.u.sph.realsize[0] = 0x80;
		    for (i = 0; i < sizeof(sparseinfo[0]); i++)
			if (lendian)
			    tarhead.u.sph.realsize[11 - i] = ((char *) (&(sparseinfo[0])))[i];
			else
			    tarhead.u.sph.realsize[11 - sizeof(sparseinfo[0]) + i] = ((char *) (&(sparseinfo[0])))[i];
		}
		for (i = 1; i < nsi && i < 9; i++) {
		    if (sparseinfo[i] <= 99999999999LL) {
		       	sprintf(tarhead.u.sph.item[i - 1], "%11.11o", sparseinfo[i]);
		    }
		    else {
			tarhead.u.sph.item[i][0] = 0x80;
			for (j = 0; j < sizeof(sparseinfo[i]); j++)
			    if (lendian)
				tarhead.u.sph.item[i - 1][11 - j] = ((char *) (&(sparseinfo[i])))[j];
			    else
				tarhead.u.sph.item[i - 1][11 - sizeof(sparseinfo[i]) + j] = ((char *) (&(sparseinfo[0])))[j];
		    }
		}
		if (nsi > 9) {
		    tarhead.u.sph.isextended = 1;
		}
		else {
		    tarhead.u.sph.isextended = 0;
		}
	    }

	    if (t.filesize <= 99999999999LL)
		sprintf(tarhead.size, "%11.11llo", t.filesize);
	    else {
		tarhead.size[0] = 0x80;
		for (i = 0; i < sizeof(t.filesize); i++)
		    if (lendian)
			tarhead.size[11 - i] = ((char *) (&t.filesize))[i];
		    else
			tarhead.size[11 - sizeof(t.filesize)+ i] = ((char *) (&t.filesize))[i];
	    }

	    memcpy(tarhead.chksum, "        ", 8);
	    for (tmpchksum = 0, p = (unsigned char *) (&tarhead), i = 512;
		i != 0; --i, ++p)
		tmpchksum += 0xFF & *p;
	    sprintf(tarhead.chksum, "%6.6o", tmpchksum);
	    sprintf(md5filepath, "%s/%c%c/%s.lzo", srcdir, md5[0], md5[1], md5 + 2);
	    fwrite(&tarhead, 1, 512, stdout);
	    tblocks++;
	    if (tarhead.u.sph.isextended == 1) {
		for (i = 0; i < sizeof(speh); i++)
		    ((unsigned char *) &speh)[i] = 0;
		for (i = 9; i < nsi; i++) {
		    if (sparseinfo[i] <= 99999999999LL)
		       	sprintf(speh.item[(i - 9) % 42], "%11.11o", sparseinfo[i]);
		    else {
			speh.item[(i - 9) % 42][0] = 0x80;
			for (j = 0; i < sizeof(sparseinfo[i]); j++)
			    if (lendian)
				speh.item[(i - 9) % 42][11 - j] = ((char *) (&(sparseinfo[i])))[j];
			    else
				speh.item[(i - 9) % 42][11 - sizeof(sparseinfo[i]) + j] = ((char *) (&(sparseinfo[0])))[j];
		    }
		    if ((i - 9) % 42 == 41) {
/*			if (i >= nsi - 2 && nsi > i + 1) { */
			if (i < nsi - 1) {
			    speh.isextended = 1;
			}
			else {
			    speh.isextended = 0;
			}
			fwrite(&speh, 1, 512, stdout);
			tblocks++;
			for (j = 0; j < sizeof(speh); j++)
			    ((unsigned char *) &speh)[j] = 0;
		    }
		}
		if ((i - 9) % 42 != 0) {
		    fwrite(&speh, 1, 512, stdout);
		    tblocks++;
		}
	    }
	    if (t.ftype == '0' || t.ftype == 'S') {
		pipe(zin);
		if ((cprocess = fork()) == 0) {
		    close(zin[0]);
		    md5file = open(md5filepath, O_RDONLY);
		    if (md5file == -1) {
			fprintf(stderr, "Can not open %s\n", md5filepath);
			exit(1);
		    }
		    dup2(zin[1], 1);
		    dup2(md5file, 0);
		    execlp("lzop", "lzop", "-d", (char *) NULL);
		    fprintf(stderr, "Error\n");
		    exit(1);
		}
		close(zin[1]);
		curfile = fdopen(zin[0], "r");
		bytestoread = t.filesize;
		while (bytestoread > 512ull) {
		    count = fread(curblock, 1, 512, curfile);
		    if (count < 512) {
			fprintf(stderr, "file short read\n");
			exit(1);
		    }
		    fwrite(curblock, 1, 512, stdout);
		    tblocks++;
		    bytestoread -= 512;
		}
		if (bytestoread > 0) {
		    for (i = 0; i < 512; i++)
			curblock[i] = 0;
		    count = fread(curblock, 1, 512, curfile);
		    fwrite(curblock, 1, 512, stdout);
		    tblocks++;
		}
		kill(cprocess, 9);
		waitpid(cprocess, NULL, 0);
		fclose(curfile);
		for (i = 0; i < sizeof(tarhead); i++)
		    ((unsigned char *) &tarhead)[i] = 0;
	    }
	}
	if (filename != 0)
	    free(filename);
	if (efilename != 0)
	    free(efilename);
	if (linktarget != 0)
	    free(linktarget);
	if (elinktarget != 0)
	    free(elinktarget);
	filename = 0;
	efilename = 0;
	linktarget = 0;
	elinktarget = 0;
    }
    fclose(manifest);
    for (i = 0; i < 512; i++)
	curblock[i] = 0;
    for (i = 0; i < 20 - (tblocks % 20) ; i++)
	fwrite(curblock, 1, 512, stdout);
}
long int strtoln(char *nptr, char **endptr, int base, int len)
{
    char scratch[20];
    strncpy(scratch, nptr, len);
    scratch[len] = (char) 0;
    return(strtol((scratch), endptr, base));
}
