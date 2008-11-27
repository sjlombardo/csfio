#ifndef CSFIO_H
#define CSFIO_H

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "csfio.h"

/* #define CIPHER EVP_aes_256_cbc() */
#define CIPHER EVP_aes_256_ecb()

#define MAGIC 0x53414654
#define MAJOR_VER 0
#define MINOR_VER 0

#define HDR_SZ          sizeof(int)

/* 
typedef struct {
        int file_sz;
        int key_sz;
        int block_sz;
        int nid;
} csf_header;
 */

typedef struct {
        int encrypted;
        int key_sz;
        int data_block_sz;
        int block_sz;
        int iv_sz;
        int cmb_block_sz;
        unsigned char *keydata;
} CSF_CFG;

typedef struct {
	int *fh;
        int csf_seek_ptr;
        int file_sz;
        CSF_CFG *cfg;
} CSF_CTX;


/* int sqlite3csf_init(sqlite3 *db, unsigned char *keyd, int len, int data_block_sz); */
int csf_config_init(CSF_CFG **cfg, unsigned char *keyd, int len, int data_block_sz);
int csf_ctx_init(CSF_CTX **ctx, int *fh, CSF_CFG *cfg);
int csf_get_block_start(CSF_CTX *ctx, int offset);
int csf_get_len(CSF_CTX *ctx, int len);
int csf_truncate(CSF_CTX *ctx, int nByte);
int csf_seek(CSF_CTX *ctx, int offset);
int csf_read(CSF_CTX *ctx, void *buf, size_t nbyte);
int csf_write(CSF_CTX *ctx, const void *buf, size_t nbyte);
int csf_read_file_sz(CSF_CTX *ctx);
int csf_write_file_sz(CSF_CTX *ctx, int sz);
void *csf_malloc(int sz);
void *csf_free(void * buf, int sz);
int csf_destroy(CSF_CTX *ctx);
/* int csf_encrypt(unsigned char *in, int inlen, unsigned char *out, int *outlen);
int csf_decrypt(unsigned char *in, int inlen, unsigned char *out, int *outlen); */


/*
static void read64bits(int in , int *out);
static void write64bits(int val, int *out);
*/

#endif

