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
#include <sys/time.h>
#include "tarlib.h"

char *itoa(char *s, int n);

int main(int argc, char **argv)
{
# if OPENSSL_API_COMPAT < 0x10100000L
    OpenSSL_add_all_algorithms();
# endif

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
# if OPENSSL_API_COMPAT < 0x10100000L
    EVP_cleanup();
# endif
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
    size_t bufsize = 4096;
    unsigned char databuf[bufsize];
    struct tarsplit_file *tsf;
    size_t sizeremaining;
    size_t padding;
    char padblock[512];
    size_t c;
    struct hmac_file *hmacf;
    struct lzop_file *lzf;
    struct rsa_file *rcf;
    struct key_st *keys = NULL;
    int numkeys = 0;
    EVP_PKEY **evp_keypair;// = EVP_PKEY_new();
    unsigned char *pubkey_fp;
    unsigned char **hmac; //[EVP_MAX_MD_SIZE];
    unsigned int *hmac_len = NULL;
    size_t (*next_c_fwrite)();
    void *next_c_write_handle;
    char *sparsetext = NULL;
    unsigned long long int sparsetext_sz = 0;
    char tmpbuf[512];
    int keynum;
    char *numkeys_string = NULL;
    char itoabuf1[32];
    unsigned char **hmac_keys;
    int *hmac_keysz;

    while ((optc = getopt_long(argc, argv, "k:", longopts, &longoptidx)) >= 0) {
	switch (optc) {
	    case 'k':
		strncpy(keyfilename, optarg, 127);
		keyfilename[127] = 0;
		if (numkeys == 0)
		    keys = malloc(sizeof(struct key_st) * ++numkeys);
		else 
		    keys = realloc(keys, sizeof(struct key_st) * ++numkeys);
		load_keyfile(keyfilename, &(keys[numkeys - 1]));
		foundopts |= opt_keyfilename;
		break;
	}
    }
    if (! (foundopts & opt_keyfilename)) {
	printf("Need a key file name\n");
	printf("Specify wity -k filepath option\n");
	exit(1);
    }

    fsinit(&fs);
    fsinit(&fs2);
    fsinit(&gh);

    gh.ftype = 'g';
    strncpya0(&(gh.filename), "././@xheader", 12);

    setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.version", "1", 1);
    if (numkeys > 1) {
	char paxhdr_varstring[64];
	strncpya0(&numkeys_string, itoa(itoabuf1, numkeys), 0);
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.numkeys", numkeys_string, strlen(numkeys_string));
	numkeys_string[0] = '\0';
	for (keynum = 0; keynum < numkeys; keynum++) {
	    pubkey_fp = sha256_b64(keys[keynum].pubkey);
	    sprintf(paxhdr_varstring, "TC.pubkey.fingerprint.%d", keynum);
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, (char *) pubkey_fp, strlen((const char *) pubkey_fp));
	    sprintf(paxhdr_varstring, "TC.eprivkey.%d", keynum);
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].eprvkey, strlen(keys[keynum].eprvkey));
	    sprintf(paxhdr_varstring, "TC.pubkey.%d", keynum);
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].pubkey, strlen(keys[keynum].pubkey));
	    sprintf(paxhdr_varstring, "TC.hmackeyhash.%d", keynum);
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].hmac_hash_b64, strlen(keys[keynum].hmac_hash_b64));
	    sprintf(paxhdr_varstring, "TC.keyfile.comment.%d", keynum);
	    setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].comment, strlen(keys[keynum].comment));
	    EVP_DecodeBlock(keys[keynum].hmac_key, (unsigned char *) keys[keynum].hmac_key_b64, 44);
	    if (numkeys_string[0] == '\0')
		strncpya0(&numkeys_string, itoa(itoabuf1, keynum), 0);
	    else {
		strcata(&numkeys_string, "|");
		strcata(&numkeys_string, itoa(itoabuf1, keynum));
	    }
	    free(pubkey_fp);
	}
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.keygroups", numkeys_string, strlen(numkeys_string));
    }
    else {
	keynum = 0;
	pubkey_fp = sha256_b64(keys[keynum].pubkey);
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.pubkey.fingerprint", (char *) pubkey_fp, strlen((const char *) pubkey_fp));
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.eprivkey", keys[keynum].eprvkey, strlen(keys[keynum].eprvkey));
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.pubkey", keys[keynum].pubkey, strlen(keys[keynum].pubkey));
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.hmackeyhash", keys[keynum].hmac_hash_b64, strlen(keys[keynum].hmac_hash_b64));
	setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.keyfile.comment", keys[keynum].comment, strlen(keys[keynum].comment));
	EVP_DecodeBlock(keys[keynum].hmac_key, (unsigned char *) keys[keynum].hmac_key_b64, 44);
	free(pubkey_fp);
    }
    evp_keypair = malloc(sizeof(*evp_keypair) * numkeys);
    hmac_keys = malloc(sizeof(char *) * numkeys);
    hmac_keysz = malloc(sizeof(int) * numkeys);
    hmac = malloc(sizeof(unsigned char *) * numkeys);
    hmac_len = malloc(sizeof(int) * numkeys);
    for (int i = 0; i < numkeys; i++) {
	evp_keypair[i] = rsa_getkey('e', keys, i);
	hmac_keys[i] = keys[i].hmac_key;
	hmac_keysz[i] = 32;
	hmac[i] = malloc(EVP_MAX_MD_SIZE);
	memset(hmac[i], 0, EVP_MAX_MD_SIZE);
	hmac_len[i] = EVP_MAX_MD_SIZE;
    }
    tar_write_next_hdr(&gh);
    fsfree(&gh);

    while (tar_get_next_hdr(&fs)) {
	if (fs.ftype == '0') {
	    fsclear(&fs2);
	    fsdup(&fs2, &fs);
	    setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.compression", "lzop", 4);
	    setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.cipher", "rsa-aes256-ctr", 14);
	    if (numkeys_string != NULL)
		setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.keygroup", numkeys_string, strlen(numkeys_string));
	    if (fs.n_sparsedata > 0){
		char sparse_orig_sz[64];
		sparsetext_sz = gen_sparse_data_string(&fs, &sparsetext);
		sprintf(sparse_orig_sz, "%llu", fs.sparse_realsize);
		setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.sparse", "1", 1);
		setpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.sparse.original.size", sparse_orig_sz, strlen(sparse_orig_sz));
		fs2.n_sparsedata = 0;
	    }
	    tsf = tarsplit_init_w(fwrite, stdout, fs.filename, 1024 * 1024, &fs2, numkeys);
	    next_c_write_handle = tsf;
	    next_c_fwrite = tarsplit_write;
	    rcf = rsa_file_init('w', evp_keypair, numkeys, next_c_fwrite, next_c_write_handle);
	    next_c_write_handle = rcf;
	    next_c_fwrite = rsa_write;
	    lzf = lzop_init_w(next_c_fwrite, next_c_write_handle); 
	    next_c_write_handle = lzf;
	    next_c_fwrite = lzop_write;

	    hmacf = hmac_file_init_w(next_c_fwrite, next_c_write_handle, hmac_keys, hmac_keysz, numkeys);
	    next_c_write_handle = hmacf;
	    next_c_fwrite = hmac_file_write;

	    if (fs.n_sparsedata > 0) {
		sprintf(tmpbuf, "%llu:", sparsetext_sz);
		next_c_fwrite(tmpbuf, 1, strlen(tmpbuf), hmacf);
		next_c_fwrite(sparsetext, 1, strlen(sparsetext), hmacf);
	    }
	    sizeremaining = fs.filesize;
	    padding = 512 - ((fs.filesize  - 1) % 512 + 1);

	    while (sizeremaining > 0) {
		c = fread(databuf, 1, sizeremaining > bufsize ? bufsize : sizeremaining, stdin);
		c = next_c_fwrite(databuf, 1, c, next_c_write_handle);
		sizeremaining -= c;
	    }
	    if (padding > 0) {
		c = fread(databuf, 1, padding, stdin);
		sizeremaining -= c;
	    }
	    hmac_finalize_w(hmacf, hmac, hmac_len);

	    for (int i = 0; i < numkeys; i++) {
		encode_block_16(tsf->hmac[i], hmac[i], hmac_len[i]);
	    }
	    lzop_finalize_w(lzf);
	    rsa_file_finalize(rcf);
	    tarsplit_finalize_w(tsf);
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

    dfree(numkeys_string);
    fsfree(&fs);
    fsfree(&fs2);
    for (int i = 0; i < numkeys; i++) {
	free(keys[i].keydata);
	free(hmac[i]);
	EVP_PKEY_free(evp_keypair[i]);
    }
    free(evp_keypair);
    free(hmac_len);
    free(hmac);
    free(keys);
    free(hmac_keys);
    free(hmac_keysz);
    if (sparsetext != NULL)
        dfree(sparsetext);
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
    size_t bufsize = 4096;
    char databuf[bufsize];
    struct tarsplit_file *tsf = NULL;
    size_t sizeremaining;
    size_t padding;
    char padblock[512];
    size_t c;
    struct tar_maxread_st *tmr = NULL;
    struct lzop_file *lzf = NULL;
    struct rsa_file *rcf = NULL;
    struct hmac_file *hmacf;
    char *paxdata;
    int paxdatalen;
    EVP_PKEY *evp_keypair = NULL;
    struct rsa_keys *rsa_keys = NULL;
    char *cur_fp = NULL;
    int keynum = 0;
    size_t (*next_c_fread)();
    void *next_c_read_handle;
    int tf_encoding = 0;
    char *pubkey_fingerprint = NULL;
    char *eprivkey = NULL;
    char *keycomment = NULL;
    char *hmachash = NULL;
    int numkeys = 0;
    char numkeys_a[16];
    char paxhdr_varstring[64];
    char *required_keys_str = NULL;
    char **required_keys_list = NULL;
    char **required_keys_group = NULL;
    unsigned char *hmac_keys;
    int hmac_keysz = 32;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned char *hmacp = hmac;
    unsigned int hmac_len;
    unsigned char hmac_b64[EVP_MAX_MD_SIZE_b64];
    unsigned char in_hmac_b64[EVP_MAX_MD_SIZE_b64];

    fsinit(&fs);
    fsinit(&fs2);
    memset(padblock, 0, 512);
    
    while (tar_get_next_hdr(&fs)) {
	if (fs.ftype == 'g') {
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.numkeys", &paxdata, &paxdatalen) == 0) {
		strncpy(numkeys_a, paxdata, paxdatalen <=15 ? paxdatalen : 15);
		numkeys_a[paxdatalen < 15 ? paxdatalen : 15] = '\0';
		numkeys = atoi(numkeys_a);
		if (rsa_keys != NULL) {
		    if (rsa_keys->keys != NULL)
			free(rsa_keys->keys);
		    free(rsa_keys);
		}
		rsa_keys = malloc(sizeof(struct rsa_keys));
		rsa_keys->numkeys = numkeys;
		rsa_keys->keys = malloc(sizeof(struct key_st) * numkeys);

		for (keynum = 0; keynum < numkeys; keynum++) {
		    rsa_keys->keys[keynum].fingerprint = NULL;
		    rsa_keys->keys[keynum].comment = NULL;
		    rsa_keys->keys[keynum].eprvkey = NULL;
		    rsa_keys->keys[keynum].pubkey = NULL;
		    rsa_keys->keys[keynum].hmac_hash_b64 = NULL;
		    rsa_keys->keys[keynum].evp_keypair = NULL;

		    sprintf(paxhdr_varstring, "TC.pubkey.fingerprint.%d", keynum);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			strncpya0(&(rsa_keys->keys[keynum].fingerprint), paxdata, paxdatalen);
		    sprintf(paxhdr_varstring, "TC.eprivkey.%d", keynum);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			strncpya0(&(rsa_keys->keys[keynum].eprvkey), paxdata, paxdatalen);
		    sprintf(paxhdr_varstring, "TC.pubkey.%d", keynum);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			strncpya0(&(rsa_keys->keys[keynum].pubkey), paxdata, paxdatalen);
		    sprintf(paxhdr_varstring, "TC.hmackeyhash.%d", keynum);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0) {
			strncpya0(&(rsa_keys->keys[keynum].hmac_hash_b64), paxdata, paxdatalen);
		    }
		    sprintf(paxhdr_varstring, "TC.keyfile.comment.%d", keynum);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			strncpya0(&(rsa_keys->keys[keynum].comment), paxdata, paxdatalen);
		}
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.keygroups", &paxdata, &paxdatalen) == 0) {
		    strncpya0(&required_keys_str, paxdata, paxdatalen);
		    parse(required_keys_str, &required_keys_list, ',');
		    for (int i = 0; required_keys_list[i] != NULL; i++) {
			parse(required_keys_list[i], &required_keys_group, '|');
			decode_privkey(rsa_keys, required_keys_group);
		    }
		}
	    }
	    else {
		keynum = 0;
		numkeys = 1;
		rsa_keys = malloc(sizeof(struct rsa_keys));
		rsa_keys->numkeys = 1;
		rsa_keys->keys = malloc(sizeof(struct key_st));
		rsa_keys->keys[keynum].fingerprint = NULL;
		rsa_keys->keys[keynum].comment = NULL;
		rsa_keys->keys[keynum].eprvkey = NULL;
		rsa_keys->keys[keynum].pubkey = NULL;
		rsa_keys->keys[keynum].hmac_hash_b64 = NULL;
		rsa_keys->keys[keynum].evp_keypair = NULL;
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.pubkey.fingerprint", &paxdata, &paxdatalen) == 0) {
		    strncpya0(&(rsa_keys->keys[keynum].fingerprint), paxdata, paxdatalen);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.eprivkey", &paxdata, &paxdatalen) == 0) {
			strncpya0(&(rsa_keys->keys[keynum].eprvkey), paxdata, paxdatalen);
			if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.keyfile.comment", &paxdata, &paxdatalen) == 0) {
			    strncpya0(&(rsa_keys->keys[keynum].comment), paxdata, paxdatalen);
			}
			if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.pubkey", &paxdata, &paxdatalen) == 0) {
			    strncpya0(&(rsa_keys->keys[keynum].pubkey), paxdata, paxdatalen);
			}
			if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.hmackeyhash", &paxdata, &paxdatalen) == 0) {
			    strncpya0(&(rsa_keys->keys[keynum].hmac_hash_b64), paxdata, paxdatalen);
			}
			strncpya0(&required_keys_str, "0", 1);
			parse(required_keys_str, &required_keys_group, '|');
			decode_privkey(rsa_keys, required_keys_group);
		    }
		}
	    }
	    continue;
	}
	if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.segmented.header", &paxdata, &paxdatalen) == 0 ||
	    getpaxvar(fs.xheader, fs.xheaderlen, "TC.cipher", &paxdata, &paxdatalen) == 0 ||
	    getpaxvar(fs.xheader, fs.xheaderlen, "TC.compression", &paxdata, &paxdatalen) == 0) {

	    if (fs.filesize == 0 && fs.ftype != '5') {
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.compression");
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.cipher");
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.original.size");
		delpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.keygroup");
		if (numkeys > 1) {
		    for (int i = 0; i < numkeys; i++) {
			sprintf(paxhdr_varstring, "TC.hmac.%d", i);
			delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), paxhdr_varstring);
		    }
		}
		else
		    delpaxvar(&(fs.xheader), &(fs.xheaderlen), "TC.hmac");

		tar_write_next_hdr(&fs);
		continue;
	    }

	    fsclear(&fs2);
	    fsdup(&fs2, &fs);
	    fs2.ftype = '0';
	    next_c_fread = fread;
	    next_c_read_handle = stdin;

	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.original.size", &paxdata, &paxdatalen) == 0) {
		fs2.filesize = strtoull(paxdata, 0, 10);
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.original.size");
	    }
	    else {
		fprintf(stderr, "Error -- missing original size xheader\n");
		exit(1);
	    }

	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.segmented.header", &paxdata, &paxdatalen) == 0) {
		tsf = tarsplit_init_r(next_c_fread, next_c_read_handle, numkeys);
		next_c_fread = tarsplit_read;
		next_c_read_handle = tsf;
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.segmented.header");
		tf_encoding |= tf_encoding_ts;
	    }
	    else {
		tmr = tar_maxread_init(fs.filesize + (512 - ((fs.filesize - 1) % 512 + 1)), next_c_fread, next_c_read_handle);
		next_c_fread = tar_maxread;
		next_c_read_handle = tmr;
		tf_encoding |= tf_encoding_tmr;
	    }
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.cipher", &paxdata, &paxdatalen) == 0) {
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.keygroup", &paxdata, &paxdatalen) == 0) {
		    strncpya0(&required_keys_str, paxdata, paxdatalen);
		    parse(required_keys_str, &required_keys_group, '|');
		    keynum = -1;
		    for (int i = 0; required_keys_group[i] != NULL; i++) {
			if (rsa_keys->keys[atoi(required_keys_group[i])].evp_keypair != NULL) {
			    keynum = atoi(required_keys_group[i]);
			    break;
			}
		    }

		    if (keynum < 0) {
			fprintf(stderr, "Error -- ciphered file missing fingerprint header\n");
			exit(1);
		    }
		}
		else {
		    if (rsa_keys->keys[0].evp_keypair != NULL)
			keynum = 0;
		}
		if (keynum < 0) {
		    fprintf(stderr, "Error -- ciphered file missing key\n");
		    exit(1);
		}
		memset(in_hmac_b64, 0, EVP_MAX_MD_SIZE_b64);
		if (numkeys > 1) {
		    sprintf(paxhdr_varstring, "TC.hmac.%d", keynum);
		    if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0) {
			strncpy((char *) in_hmac_b64, paxdata, paxdatalen > EVP_MAX_MD_SIZE_b64 - 1 ? EVP_MAX_MD_SIZE_b64 - 1 : paxdatalen);
			in_hmac_b64[EVP_MAX_MD_SIZE_b64 - 1] = '\0';
		    }
		    for (int i = 0; i < numkeys; i++) {
			sprintf(paxhdr_varstring, "TC.hmac.%d", i);
			delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), paxhdr_varstring);
		    }
		    delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.keygroup");
		}
		else {
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.hmac", &paxdata, &paxdatalen) == 0) {
			strncpy((char *) in_hmac_b64, paxdata, paxdatalen > EVP_MAX_MD_SIZE_b64 - 1 ? EVP_MAX_MD_SIZE_b64 - 1 : paxdatalen);
			in_hmac_b64[EVP_MAX_MD_SIZE_b64 - 1] = '\0';
			delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.hmac");
		    }
		}
		for (int i = EVP_MAX_MD_SIZE_b64 - 1; i >= 0; i--) {
		    if (in_hmac_b64[i] == '\n') {
			in_hmac_b64[i] = '\0';
			break;
		    }
		}

		evp_keypair = rsa_keys->keys[keynum].evp_keypair;
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.pubkey.fingerprint");
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.cipher");
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.hmac");
		rcf = rsa_file_init('r', &evp_keypair, 0, next_c_fread, next_c_read_handle);
		next_c_fread = rsa_read;
		next_c_read_handle = rcf;
		tf_encoding |= tf_encoding_cipher;
	    }
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.compression", &paxdata, &paxdatalen) == 0) {
		lzf = lzop_init_r(next_c_fread, next_c_read_handle); 
		next_c_fread = lzop_read;
		next_c_read_handle = lzf;
		tf_encoding |= tf_encoding_compression;
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.compression");
	    }
	    hmac_keys = rsa_keys->keys[keynum].hmac_key;
	    hmacf = hmac_file_init_r(next_c_fread, next_c_read_handle, &hmac_keys, &hmac_keysz, 1);
	    next_c_fread = hmac_file_read;
	    next_c_read_handle = hmacf;

	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.sparse", &paxdata, &paxdatalen) == 0) {
		sizeremaining = c_fread_sparsedata(next_c_fread, next_c_read_handle, &fs2);
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.sparse");
		getpaxvar(fs.xheader, fs.xheaderlen, "TC.sparse.original.size", &paxdata, &paxdatalen);
		fs2.sparse_realsize = strtoull(paxdata, 0, 10);
		delpaxvar(&(fs2.xheader), &(fs2.xheaderlen), "TC.sparse.original.size");

#if 0
		unsigned long int sparsehdrsz;
		sparsehdrsz = ilog10(fs2.n_sparsedata) + 2;
		for (int i = 0; i < fs2.n_sparsedata; i++) {
		    sparsehdrsz += ilog10(fs2.sparsedata[i].offset) + 2;
		    sparsehdrsz += ilog10(fs2.sparsedata[i].size) + 2;
		}
		sparsehdrsz += (512 - ((sparsehdrsz - 1) % 512 + 1));
		fs2.filesize += sparsehdrsz;
#endif

	    }
	    else
		sizeremaining = fs2.filesize;

	    tar_write_next_hdr(&fs2);

	    padding = 512 - ((sizeremaining - 1) % 512 + 1);

	    while (sizeremaining > 0) {
		c = next_c_fread(databuf, 1, sizeremaining < bufsize ? sizeremaining : bufsize, next_c_read_handle);
		fwrite(databuf, 1, c, stdout);
		sizeremaining -= c;
		if (sizeremaining > 0 && c == 0) {
		    fprintf(stderr, "Problem reading\n");
		    exit(1);
		}
	    }
	    if (padding > 0) {
		c = fwrite(padblock, 1, padding, stdout);
	    }
	    hmac_finalize_r(hmacf, &hmacp, &hmac_len);
	    encode_block_16(hmac_b64, hmac, hmac_len);
	    if (strcmp((tf_encoding & tf_encoding_ts) != 0 ? (char *) tsf->hmac[keynum] : (char *) in_hmac_b64, (char *) hmac_b64) != 0)
		fprintf(stderr, "Warning: HMAC failed verification\n%s\n%s\n%s\n", fs2.filename, (tf_encoding & tf_encoding_ts) != 0 ? (char *) tsf->hmac[keynum] : (char *) in_hmac_b64, (char *) hmac_b64);
	    if ((tf_encoding & tf_encoding_compression) != 0)
		lzop_finalize_r(lzf);
	    if ((tf_encoding & tf_encoding_cipher) != 0)
		rsa_file_finalize(rcf);
	    if ((tf_encoding & tf_encoding_ts) != 0) {
		tarsplit_finalize_r(tsf);
	    }
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
		c = fread(padblock, 1, padding, stdin);
		c = fwrite(padblock, 1, padding, stdout);
	    }
	}
    }
    if (rsa_keys != NULL) {
	for (int i = 0; i < rsa_keys->numkeys; i++) {
	    dfree(rsa_keys->keys[i].comment);
	    dfree(rsa_keys->keys[i].fingerprint);
	    dfree(rsa_keys->keys[i].hmac_hash_b64);
	    dfree(rsa_keys->keys[i].eprvkey);
	    dfree(rsa_keys->keys[i].pubkey);
	}
	free(rsa_keys->keys);
	free(rsa_keys);
    }
    fsfree(&fs);
    fsfree(&fs2);
    dfree(pubkey_fingerprint);
    dfree(eprivkey);
    dfree(keycomment);
    dfree(hmachash);
    dfree(cur_fp);
    dfree(required_keys_group);
    dfree(required_keys_list);
    dfree(required_keys_str);
    if (evp_keypair != NULL)
	EVP_PKEY_free(evp_keypair);
    fwrite(padblock, 1, 512, stdout);
    fwrite(padblock, 1, 512, stdout);
    return(0);
}

char *itoa(char *s, int n)
{
    sprintf(s, "%d", n);
    return(s);
}
