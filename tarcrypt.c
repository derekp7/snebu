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

int main(int argc, char **argv)
{
    if (argc > 1) {
	if (strcmp(argv[1], "encrypt") == 0)
	    tarencrypt(argc - 1, argv + 1);
	else if (strcmp(argv[1], "decrypt") == 0) {
	    tardecrypt();
	}
	else if (strcmp(argv[1], "genkey") == 0) {
	    genkey(argc - 1, argv + 1);
	}
	else
	    return(1);
    }
    return(0);
}
int tarencrypt(int argc, char **argv)
{
    struct option longopts[] = {
	{ "keyfile", required_argument, NULL, 'k' },
	{ NULL, no_argument, NULL, 0 }
    };
    int longoptidx;
    int optc;
    int foundopts = 0;
    char keyfilename[128];
    int opt_keyfilename = 1;
    struct filespec fs;
    struct filespec fs2;
    struct filespec gh;
    size_t bufsize = 256 * 1024;
    unsigned char databuf[bufsize];
    struct tarsplit_file *tsf;
    size_t sizeremaining;
    size_t padding;
    char padblock[512];
    size_t c;
    struct lzop_file *lzf;
    struct rsa_file *rcf;
    struct key_st *keys;
    EVP_PKEY *evp_keypair = EVP_PKEY_new();
    unsigned char *pubkey_fp;
    HMAC_CTX hctx;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    char *sparsetext = NULL;
    int sparsetext_sz = 0;
    char tmpbuf[512];

    memset(hmac, 0, EVP_MAX_MD_SIZE);
    while ((optc = getopt_long(argc, argv, "k:", longopts, &longoptidx)) >= 0) {
	switch (optc) {
	    case 'k':
		strncpy(keyfilename, optarg, 127);
		keyfilename[127] = 0;
		foundopts |= opt_keyfilename;
		break;
	}
    }
    if (! (foundopts & opt_keyfilename)) {
	printf("Need a key file name\n");
	printf("Specify wity -k filepath option\n");
	exit(1);
    }

    fsinit(&fs, fread, fwrite, stdin, stdout);
    fsinit(&fs2, fread, fwrite, stdin, stdout);
    fsinit(&gh, fread, fwrite, stdin, stdout);

    keys = load_keyfile(keyfilename);
    EVP_DecodeBlock(keys->hmac_key, (unsigned char *) keys->hmac_key_b64, 44);
    evp_keypair = rsa_getkey('e', keys);
    pubkey_fp = sha256_hex(keys->pubkey);
    gh.ftype = 'g';
    strncpya0(&(gh.filename), "././@xheader", 12);

    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "SB.pubkey.fingerprint", (char *) pubkey_fp, strlen((const char *) pubkey_fp));
    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "SB.eprivkey", keys->eprvkey, strlen(keys->eprvkey));
    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "SB.ehmac", keys->hmac_key_enc_b64, strlen(keys->hmac_key_enc_b64));
    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "SB.keyfile.comment", keys->comment, strlen(keys->comment));
    tar_write_next_hdr(&gh);
    fsfree(&gh);
    char foo[256];
    memset(foo, 0, 256);
    while (tar_get_next_hdr(&fs)) {
	if (fs.ftype == '0') {
	    fsclear(&fs2);
	    fsdup(&fs2, &fs);
	    setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.compression", "lzop", 4);
	    setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.cipher", "rsa-aes128-gcm", 14);
	    setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.pubkey.fingerprint", (char *) pubkey_fp, strlen((const char *) pubkey_fp));
	    if (fs.n_sparsedata > 0){
		char sparse_orig_sz[64];
		sparsetext_sz = gen_sparse_data_string(&fs, &sparsetext);
		sprintf(sparse_orig_sz, "%llu", fs.sparse_realsize);
		setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.sparse", "1", 1);
		setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.sparse.original.size", sparse_orig_sz, strlen(sparse_orig_sz));
		fs2.filesize += sparsetext_sz + ilog10(sparsetext_sz) + 2;
		fs2.n_sparsedata = 0;
	    }
	    tsf = tarsplit_init(fwrite, stdout, fs.filename, 1024 * 1024, &fs2);
	    rcf = rsa_file_init('w', evp_keypair, tarsplit_write, tsf);
	    lzf = lzop_init(rsa_write, rcf); 

	    HMAC_CTX_init(&hctx);
	    HMAC_Init_ex(&hctx, keys->hmac_key, 32, EVP_sha256(), NULL);

	    if (fs.n_sparsedata > 0) {
		sprintf(tmpbuf, "%llu:", (unsigned long long int) sparsetext_sz);
		lzop_write(tmpbuf, 1, strlen(tmpbuf), lzf);
		lzop_write(sparsetext, 1, sparsetext_sz, lzf);
		HMAC_Update(&hctx, (unsigned char *) sparsetext, sparsetext_sz);
	    }
	    sizeremaining = fs.filesize;
	    padding = 512 - ((fs.filesize + sparsetext_sz - 1) % 512 + 1);

	    while (sizeremaining > 0) {
		c = fread(databuf, 1, sizeremaining > bufsize ? bufsize : sizeremaining, stdin);
		HMAC_Update(&hctx, databuf, c);
		lzop_write(databuf, 1, c, lzf);
		sizeremaining -= c;
	    }
	    if (padding > 0) {
		c = fread(databuf, 1, padding, stdin);
		sizeremaining -= c;
	    }
	    HMAC_Final(&hctx, hmac, &hmac_len);
	    EVP_EncodeBlock(tsf->hmac, hmac, hmac_len);
	    lzop_finalize(lzf);
	    rsa_file_finalize(rcf);
	    tarsplit_finalize(tsf);
	}
	else {
	    tar_write_next_hdr(&fs);
	    sizeremaining = fs.filesize;
	    padding = 512 - ((fs.filesize - 1) % 512 + 1);
	    while (sizeremaining > 0) {
		c = fread(databuf, 1, sizeremaining < bufsize ? sizeremaining : bufsize, stdin);
		fwrite(databuf, 1, c, stdout);
		sizeremaining -= c;
	    }
	    if (padding > 0) {
		c = fread(padblock, 1, padding, stdout);
		c = fwrite(padblock, 1, padding, stdout);
	    }
	}
	fsclear(&fs);
    }

    fsfree(&fs);
    fsfree(&fs2);
    return(0);
}

#define tf_encoding_ts 1
#define tf_encoding_compression 2
#define tf_encoding_cipher 4
#define tf_encoding_tmr 8
int tardecrypt()
{
    struct filespec fs;
    struct filespec fs2;
    size_t bufsize = 256 * 1024;
    char databuf[bufsize];
    struct tarsplit_file *tsf;
    size_t sizeremaining;
    size_t padding;
    char *padblock[512];
    size_t c;
    struct tar_maxread_st *tmr;
    struct lzop_file *lzf;
    struct rsa_file *rcf;
    char *paxdata;
    int paxdatalen;
    EVP_PKEY *evp_keypair = EVP_PKEY_new();
    struct rsa_keys *rsa_keys = NULL;
    char *cur_fp = NULL;
    int keynum;
    size_t (*next_c_fread)();
    void *next_c_read_handle;
    int tf_encoding = 0;


    fsinit(&fs, fread, fwrite, stdin, stdout);
    fsinit(&fs2, fread, fwrite, stdin, stdout);
    memset(&padblock, 0, 512);
    
    while (tar_get_next_hdr(&fs)) {

	if (fs.ftype == 'g') {
	    char *pubkey_fingerprint = NULL;
	    char *eprivkey = NULL;
	    char *keycomment = NULL;
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.pubkey.fingerprint", &paxdata, &paxdatalen) == 0) {
		strncpya0(&pubkey_fingerprint, paxdata, paxdatalen);
		if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.eprivkey", &paxdata, &paxdatalen) == 0) {
		    strncpya0(&eprivkey, paxdata, paxdatalen);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.keyfile.comment", &paxdata, &paxdatalen) == 0) {
			strncpya0(&keycomment, paxdata, paxdatalen);
		    }
		    load_pkey(&rsa_keys, pubkey_fingerprint, eprivkey, keycomment);
		}
	    }
	    continue;
	}
	if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.segmented.header", &paxdata, &paxdatalen) == 0 ||
	    getpaxvar(fs.xheader, fs.xheaderlen, "SB.cipher", &paxdata, &paxdatalen) == 0 ||
	    getpaxvar(fs.xheader, fs.xheaderlen, "SB.compression", &paxdata, &paxdatalen) == 0) {

	    fsclear(&fs2);
	    fsdup(&fs2, &fs);
	    fs2.ftype = '0';
	    next_c_fread = fread;
	    next_c_read_handle = stdin;

	    if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.original.size", &paxdata, &paxdatalen) == 0) {
		fs2.filesize = strtoull(paxdata, 0, 10);
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.original.size");
	    }
	    else {
		fprintf(stderr, "Error -- missing original size xheader\n");
		exit(1);
	    }

	    if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.segmented.header", &paxdata, &paxdatalen) == 0) {
		tsf = tarsplit_init_r(next_c_fread, next_c_read_handle);
		next_c_fread = tarsplit_read;
		next_c_read_handle = tsf;
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.segmented.header");
		tf_encoding |= tf_encoding_ts;
	    }
	    else {
		tmr = tar_maxread_init(fs.filesize + (512 - ((fs.filesize - 1) % 512 + 1)), next_c_fread, next_c_read_handle);
		next_c_fread = tar_maxread;
		next_c_read_handle = tmr;
		tf_encoding |= tf_encoding_tmr;
	    }
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.cipher", &paxdata, &paxdatalen) == 0) {
		if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.pubkey.fingerprint", &paxdata, &paxdatalen) != 0) {
		    fprintf(stderr, "Error -- ciphered file missing fingerprint header\n");
		    exit(1);
		}
		else
		    strncpya0(&cur_fp, paxdata, paxdatalen);
		keynum = get_pkey(rsa_keys, cur_fp);
		if (keynum < 0) {
		    fprintf(stderr, "Error -- ciphered file missing key\n");
		    exit(1);
		}
		evp_keypair = rsa_keys->keys[keynum].evp_keypair;
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.pubkey.fingerprint");
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.cipher");
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.hmac");
		rcf = rsa_file_init('r', evp_keypair, next_c_fread, next_c_read_handle);
		next_c_fread = rsa_read;
		next_c_read_handle = rcf;
		tf_encoding |= tf_encoding_cipher;

	    }
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.compression", &paxdata, &paxdatalen) == 0) {
		lzf = lzop_init_r(next_c_fread, next_c_read_handle); 
		next_c_fread = lzop_read;
		next_c_read_handle = lzf;
		tf_encoding |= tf_encoding_compression;
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.compression");
	    }

	    if (getpaxvar(fs.xheader, fs.xheaderlen, "SB.sparse", &paxdata, &paxdatalen) == 0) {
		fs2.filesize -= c_fread_sparsedata(next_c_fread, next_c_read_handle, &fs2);
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.sparse");
		getpaxvar(fs.xheader, fs.xheaderlen, "SB.sparse.original.size", &paxdata, &paxdatalen);
		fs2.sparse_realsize = strtoull(paxdata, 0, 10);
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "SB.sparse.original.size");

	    }

	    tar_write_next_hdr(&fs2);
	    padding = 512 - ((fs2.filesize - 1) % 512 + 1);
	    sizeremaining = fs2.filesize;

	    while (sizeremaining > 0) {
		c = next_c_fread(databuf, 1, bufsize, next_c_read_handle);
		fwrite(databuf, 1, c, stdout);
		sizeremaining -= c;
		if (sizeremaining > 0 && c == 0)
		    exit(1);
	    }
	    if (padding > 0) {
		c = fwrite(padblock, 1, padding, stdout);
	    }
	    if ((tf_encoding & tf_encoding_compression) != 0)
		lzop_finalize_r(lzf);
	    if ((tf_encoding & tf_encoding_cipher) != 0)
		rsa_file_finalize(rcf);
	    if ((tf_encoding & tf_encoding_ts) != 0)
		tarsplit_finalize_r(tsf);
	    if ((tf_encoding & tf_encoding_tmr) != 0)
		tar_maxread_finalize(tmr);
	    tf_encoding = 0;
	}
	else {
	    tar_write_next_hdr(&fs);
	    sizeremaining = fs.filesize;
	    padding = 512 - ((fs.filesize - 1) % 512 + 1);
	    while (sizeremaining > 0) {
		c = fread(databuf, 1, sizeremaining < bufsize ? sizeremaining : bufsize, stdin);
		fwrite(databuf, 1, c, stdout);
		sizeremaining -= c;
	    }
	    if (padding > 0) {
		c = fread(padblock, 1, padding, stdout);
		c = fwrite(padblock, 1, padding, stdout);
	    }
	}
	fsclear(&fs);
    }
    fsfree(&fs);
    fwrite(padblock, 1, 512, stdout);
    return(0);
}
