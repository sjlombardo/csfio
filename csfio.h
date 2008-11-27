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

typedef struct {
	int *fh;
        int seek_ptr;
        int file_sz;
        int encrypted;
        int key_sz;
        int data_sz;
        int block_sz;
        int iv_sz;
        int page_sz;
        unsigned char *keydata;
} CSF_CTX;

int csf_ctx_init(CSF_CTX **ctx_out, int *fh, unsigned char *keydata, int key_sz, int data_sz);
int csf_truncate(CSF_CTX *ctx, int nByte);
int csf_seek(CSF_CTX *ctx, int offset);
int csf_read(CSF_CTX *ctx, void *buf, size_t nbyte);
int csf_write(CSF_CTX *ctx, const void *buf, size_t nbyte);
int csf_ctx_destroy(CSF_CTX *ctx);

#endif

