/* 
** CSFIO - Cryptographically Secure File I/O
** csfio.c developed by Stephen Lombardo (Zetetic LLC) 
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "csfio.h"

/*
  defining CSF_DEBUG will produce copious trace output
  for debugging purposes
*/
#if CSF_DEBUG
#define TRACE1(X)       (printf(X) && fflush(stdout))
#define TRACE2(X,Y)       (printf(X,Y) && fflush(stdout))
#define TRACE3(X,Y,Z)       (printf(X,Y,Z) && fflush(stdout))
#define TRACE4(X,Y,Z,W)       (printf(X,Y,Z,W) && fflush(stdout))
#define TRACE5(X,Y,Z,W,V)       (printf(X,Y,Z,W,V) && fflush(stdout))
#define TRACE6(X,Y,Z,W,V,U)       (printf(X,Y,Z,W,V,U) && fflush(stdout))
#else
#define TRACE1(X)
#define TRACE2(X,Y)
#define TRACE3(X,Y,Z)
#define TRACE4(X,Y,Z,W)
#define TRACE5(X,Y,Z,W,V)
#define TRACE6(X,Y,Z,W,V,U)
#endif

static void *csf_malloc(int sz);
static void csf_free(void * buf, int sz);
static size_t csf_read_page(CSF_CTX *ctx, int pgno, void *data);
static size_t csf_write_page(CSF_CTX *ctx, int pgno, void *data, size_t data_sz); 
static off_t csf_pageno_for_offset(CSF_CTX *ctx, int offset);
static int csf_page_count_for_length(CSF_CTX *ctx, int length);

int csf_ctx_init(CSF_CTX **ctx_out, int *fh, unsigned char *key_data, int key_sz, int page_sz) {
  EVP_CIPHER_CTX ectx;
  CSF_CTX *ctx;

  ctx = csf_malloc(sizeof(CSF_CTX));
  ctx->seek_ptr = ctx->file_sz = 0;
  ctx->fh = fh;

  ctx->key_sz = key_sz;
  ctx->key_data = csf_malloc(ctx->key_sz);
  memcpy(ctx->key_data, key_data, ctx->key_sz);

  EVP_EncryptInit(&ectx, CIPHER, ctx->key_data, NULL);
  ctx->block_sz = EVP_CIPHER_CTX_block_size(&ectx);
  ctx->iv_sz = EVP_CIPHER_CTX_iv_length(&ectx);

  /* the combined page size includes the size of the initialization  
     vector, an integer for the count of bytes on page, and the data block */
  ctx->page_sz = page_sz;

  /* ensure the page header allocation ends on an even block alignment */
  ctx->page_header_sz = (sizeof(CSF_PAGE_HEADER) % ctx->block_sz == 0) ? (sizeof(CSF_PAGE_HEADER) / ctx->block_sz) : (sizeof(CSF_PAGE_HEADER) / ctx->block_sz) + ctx->block_sz;

  /* determine unused space avaliable for data */
  ctx->data_sz = ctx->page_sz - ctx->iv_sz - ctx->page_header_sz;

  assert(ctx->iv_sz %  ctx->block_sz == 0);
  assert(ctx->page_header_sz %  ctx->block_sz == 0);
  assert(ctx->data_sz %  ctx->block_sz == 0);
  assert(ctx->page_sz %  ctx->block_sz == 0);

  ctx->page_buffer = csf_malloc(ctx->page_sz);
  ctx->csf_buffer = csf_malloc(ctx->page_sz);
  ctx->scratch_buffer = csf_malloc(ctx->page_sz);
  
  EVP_CIPHER_CTX_cleanup(&ectx);

  ctx->encrypted=1;

  TRACE6("csf_init() ctx->data_sz=%d, ctx->page_sz=%d, ctx->block_sz=%d, ctx->iv_sz=%d, ctx->key_sz=%d\n", ctx->data_sz, ctx->page_sz, ctx->block_sz, ctx->iv_sz, ctx->key_sz);

  *ctx_out = ctx;

  return 0;  
}

int csf_ctx_destroy(CSF_CTX *ctx) {
  csf_free(ctx->page_buffer, ctx->page_sz);
  csf_free(ctx->csf_buffer, ctx->page_sz);
  csf_free(ctx->scratch_buffer, ctx->page_sz);
  csf_free(ctx->key_data, ctx->key_sz);
  csf_free(ctx, sizeof(CSF_CTX));  
  return 0;
}

static int csf_page_count_for_file(CSF_CTX *ctx) {
  size_t cur_offset = lseek(*ctx->fh, 0, SEEK_CUR);
  size_t count = (lseek(*ctx->fh, 0, SEEK_END) - HDR_SZ) / ctx->page_sz;
  lseek(*ctx->fh, cur_offset, SEEK_SET);
  return count;
}

static off_t csf_pageno_for_offset(CSF_CTX *ctx, int offset) {
  return (offset / ctx->data_sz);
}

static int csf_page_count_for_length(CSF_CTX *ctx, int length) {
  int count = (length / ctx->data_sz);
  if ( (length % ctx->data_sz) != 0 ) {
    count++;
  }
  return count;
}

int csf_truncate(CSF_CTX *ctx, int offset) {
  int true_offset = HDR_SZ + (csf_pageno_for_offset(ctx, offset) * ctx->page_sz);
  TRACE4("csf_truncate(%d,%d), retval = %d\n", *ctx->fh, offset, true_offset);
  return ftruncate(*ctx->fh, true_offset);
}

/* FIXME - what happens when you seek past end of file? */
off_t csf_seek(CSF_CTX *ctx, off_t offset, int whence) {
  off_t csf_seek = 0;
  off_t true_offset;
  off_t target_offset = 0;
  int page_count = csf_page_count_for_file(ctx);
  int target_page = 0;
  size_t data_sz;

  switch(whence) {
    case SEEK_SET:
      target_offset = offset;
      break;
    case SEEK_CUR:
      target_offset = ctx->seek_ptr + offset;
      break;
    case SEEK_END:
      /* FIXME optimize out second seek */
      data_sz = csf_read_page(ctx, page_count-1, ctx->page_buffer);
      target_offset = (((page_count - 1) * ctx->data_sz) + data_sz) + offset;
      break;
  }  
  
  target_page = csf_pageno_for_offset(ctx, target_offset);
  true_offset = HDR_SZ + (target_page * ctx->page_sz);

  if(target_page > page_count) {
    /* this is a seek past end of file. we need to fill in the gaps. */
    int i;

    /* start by rewriting the current end page */
    if(page_count > 0) {
      size_t data_sz = csf_read_page(ctx, page_count-1, ctx->csf_buffer);
      memset(ctx->csf_buffer + data_sz, 0, ctx->data_sz - data_sz); /* back fill an unused data on page with zeros */
      data_sz = csf_write_page(ctx, page_count-1, ctx->csf_buffer, ctx->data_sz);
      assert(data_sz == ctx->data_sz);
    }

    /* loop through the next page on through the n-1 page, fill up with zero data */
    memset(ctx->csf_buffer, 0, ctx->page_sz); // zero out the data!
    for(i = page_count; i < target_page - 1; i++) {
      csf_write_page(ctx, i, ctx->csf_buffer, ctx->data_sz); 
    }

    /* take the last page, and write out the proper number of bytes to reach the target offset */
    csf_write_page(ctx, target_page-1, ctx->csf_buffer, target_offset % ctx->data_sz); 
    
  } else {
      csf_seek = lseek(*ctx->fh, true_offset, SEEK_SET);
      assert(csf_seek == true_offset);
  }

  ctx->seek_ptr = target_offset;

  TRACE5("csf_seek(%d,%d), true_offset = %d, ctx->seek_ptr = %d\n", *ctx->fh, offset, true_offset, ctx->seek_ptr);
  return ctx->seek_ptr;
}

static size_t csf_read_page(CSF_CTX *ctx, int pgno, void *data) {
  off_t start_offset = HDR_SZ + (pgno * ctx->page_sz);
  off_t cur_offset =  lseek(*ctx->fh, 0L, SEEK_CUR);
  int to_read = ctx->page_sz;
  size_t read_sz = 0;
  CSF_PAGE_HEADER header;

  if(cur_offset != start_offset) { /* if not in proper position for page, seek there */
    cur_offset = lseek(*ctx->fh, start_offset, SEEK_SET);
  }
 
  /* FIXME - error handling */
  for(;read_sz < to_read;) {
    size_t bytes_read = read(*ctx->fh, ctx->page_buffer + read_sz, to_read - read_sz);
    read_sz += bytes_read;
    if(bytes_read < 0) {
      return 0;
    }
  }  

  if(ctx->encrypted) {
    EVP_CIPHER_CTX ectx;
    void *out_ptr =  ctx->scratch_buffer;
    int out_sz, cipher_sz = 0;

    EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 0);
    EVP_CIPHER_CTX_set_padding(&ectx, 0);
    EVP_CipherInit(&ectx, NULL, ctx->key_data, ctx->page_buffer, 0);
    EVP_CipherUpdate(&ectx, out_ptr + cipher_sz, &out_sz, ctx->page_buffer + ctx->iv_sz, ctx->page_header_sz + ctx->data_sz);
    cipher_sz += out_sz;
    EVP_CipherFinal(&ectx, out_ptr + cipher_sz, &out_sz);
    cipher_sz += out_sz;
    EVP_CIPHER_CTX_cleanup(&ectx);
    assert(cipher_sz == (ctx->page_header_sz + ctx->data_sz));
  } else {
    memcpy(ctx->scratch_buffer, ctx->page_buffer + ctx->iv_sz, ctx->page_header_sz + ctx->data_sz);
  }

  memcpy(&header, ctx->scratch_buffer, sizeof(header));
  memcpy(data, ctx->scratch_buffer + ctx->page_header_sz, header.data_sz);

  TRACE6("csf_read_page(%d,%d,x), cur_offset=%d, read_sz=%d, return=%d\n", *ctx->fh, pgno, cur_offset, read_sz, data_sz);

  return header.data_sz;
}

static size_t csf_write_page(CSF_CTX *ctx, int pgno, void *data, size_t data_sz) {
  off_t start_offset = HDR_SZ + (pgno * ctx->page_sz);
  off_t cur_offset =  lseek(*ctx->fh, 0L, SEEK_CUR);
  int to_write = ctx->page_sz;
  size_t write_sz = 0;
  CSF_PAGE_HEADER header;

  assert(data_sz <= ctx->data_sz);

  header.data_sz = data_sz;

  if(cur_offset != start_offset) { /* if not in proper position for page, seek there */
    cur_offset = lseek(*ctx->fh, start_offset, SEEK_SET);
  }
  
  RAND_pseudo_bytes(ctx->page_buffer, ctx->iv_sz);

  memcpy(ctx->scratch_buffer, &header, sizeof(header));
  memcpy(ctx->scratch_buffer + ctx->page_header_sz, data, data_sz);

  /* normally this would encrypt here */
  if(ctx->encrypted) {
    EVP_CIPHER_CTX ectx;
    void *out_ptr =  ctx->page_buffer + ctx->iv_sz;
    int out_sz, cipher_sz = 0;

    EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 1);
    EVP_CIPHER_CTX_set_padding(&ectx, 0);
    EVP_CipherInit(&ectx, NULL, ctx->key_data, ctx->page_buffer, 1);
    EVP_CipherUpdate(&ectx, out_ptr + cipher_sz, &out_sz, ctx->scratch_buffer, ctx->page_header_sz + ctx->data_sz);
    cipher_sz += out_sz;
    EVP_CipherFinal(&ectx, out_ptr + cipher_sz, &out_sz);
    cipher_sz += out_sz;
    EVP_CIPHER_CTX_cleanup(&ectx);
    assert(cipher_sz == (ctx->page_header_sz + ctx->data_sz));
  } else {
    memcpy(ctx->page_buffer + ctx->iv_sz, ctx->scratch_buffer, ctx->page_header_sz + ctx->data_sz);
  }

  for(;write_sz < to_write;) { /* FIXME - error handling */ 
    size_t bytes_write = write(*ctx->fh, ctx->page_buffer + write_sz, to_write - write_sz);
    write_sz += bytes_write;
  }  
  
  TRACE6("csf_write_page(%d,%d,x,%d), cur_offset=%d, write_sz= %d\n", *ctx->fh, pgno, data_sz, cur_offset, write_sz);

  return data_sz;
}

size_t csf_read(CSF_CTX *ctx, void *data, size_t nbyte) {
  int start_page = csf_pageno_for_offset(ctx, ctx->seek_ptr);
  int start_offset = ctx->seek_ptr % ctx->data_sz;
  int to_read = nbyte + start_offset;
  int pages_to_read = csf_page_count_for_length(ctx, to_read);
  int i, data_offset = 0;
  int page_count = csf_page_count_for_file(ctx);

  for(i = 0; i < pages_to_read && i < page_count; i++) { /* dont read past end of file */
    int data_sz = (to_read < ctx->data_sz ? to_read : ctx->data_sz);
    int l_data_sz = data_sz - start_offset;
    int bytes_read = csf_read_page(ctx, start_page + i, ctx->csf_buffer);
    memcpy(data + data_offset, ctx->csf_buffer + start_offset, l_data_sz);
    to_read -= bytes_read;
    data_offset += l_data_sz;
    ctx->seek_ptr += l_data_sz;
    start_offset = 0; /* after the first iteration the start offset will always be at the beginning of the page */
    memset(ctx->csf_buffer, 0, ctx->page_sz);
  }

  TRACE6("csf_read(%d,x,%d), pages_to_read = %d, ctx->seek_ptr = %d, return=%d\n", *ctx->fh, nbyte, pages_to_read, ctx->seek_ptr, data_offset);
  return data_offset;
}

size_t csf_write(CSF_CTX *ctx, const void *data, size_t nbyte) {
  int start_page = csf_pageno_for_offset(ctx, ctx->seek_ptr);
  int start_offset = ctx->seek_ptr % ctx->data_sz;
  int to_write = nbyte + start_offset;
  int pages_to_write = csf_page_count_for_length(ctx, to_write);
  int i, data_offset = 0;
  int page_count = csf_page_count_for_file(ctx);

  for(i = 0; i < pages_to_write; i++) {
    int data_sz = (to_write < ctx->data_sz ? to_write : ctx->data_sz);
    int l_data_sz = data_sz - start_offset;
    int bytes_write = 0;
    int cur_page_bytes = 0;

    if(page_count > (start_page + i)) {
      cur_page_bytes = csf_read_page(ctx, start_page + i, ctx->csf_buffer); /* FIXME error hndling */
    } else {
      cur_page_bytes = 0;
    }

    memcpy(ctx->csf_buffer + start_offset, data + data_offset, l_data_sz);

    bytes_write = csf_write_page(ctx, start_page + i, ctx->csf_buffer, (data_sz < cur_page_bytes) ? cur_page_bytes : data_sz); 
    to_write -= bytes_write; /* to_write is already adjusted for start_offset */
    data_offset += l_data_sz; 
    ctx->seek_ptr += l_data_sz;
    start_offset = 0; /* after the first iteration the start offset will always be at the beginning of the page */
    memset(ctx->csf_buffer, 0, ctx->page_sz);
  }

  TRACE6("csf_write(%d,x,%d), pages_to_write = %d, ctx->seek_ptr = %d, return=%d\n", *ctx->fh, nbyte, pages_to_write, ctx->seek_ptr, data_offset);
  return data_offset;
}

/*
  input: size of the buffer to allocate
*/
static void *csf_malloc(int sz) {
  void *buf;
  buf = calloc(sz, 1);
  if(buf == NULL) {
    TRACE2("allocating %d bytes via malloc() in csf_malloc()", sz);
  }
  return buf;
}

/* 
  input: the pointer to the malloc'd memory, and
  the lenght of the buffer to zero out
*/
static void csf_free(void * buf, int sz) {
  memset(buf, 0, sz);
  free(buf);
}

