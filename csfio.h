/* 
** CSFIO - Cryptographically Secure File I/O
** csfio.h developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** Copyright (c) 2008, ZETETIC LLC
** All rights reserved.
** 
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
** 
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**  
*/

#ifndef CSFIO_H
#define CSFIO_H

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "csfio.h"

#define CIPHER EVP_aes_256_cbc()

#define HDR_SZ 0 

typedef struct {
  int *fh;
  off_t seek_ptr;
  off_t file_sz;
  int encrypted;
  int key_sz;
  int data_sz;
  int block_sz;
  int iv_sz;
  int page_header_sz;
  int page_sz;
  unsigned char *key_data;
  unsigned char *page_buffer;
  unsigned char *scratch_buffer;
  unsigned char *csf_buffer;
} CSF_CTX;

typedef struct {
  size_t data_sz; /* index of last byte of data on page */
} CSF_PAGE_HEADER;

int csf_ctx_init(CSF_CTX **ctx_out, int *fh, unsigned char *keydata, int key_sz, int page_sz);
int csf_truncate(CSF_CTX *ctx, int nByte);
off_t csf_seek(CSF_CTX *ctx, off_t offset, int whence);
size_t csf_read(CSF_CTX *ctx, void *buf, size_t nbyte);
size_t csf_write(CSF_CTX *ctx, const void *buf, size_t nbyte);
int csf_ctx_destroy(CSF_CTX *ctx);

#endif
