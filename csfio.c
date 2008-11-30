
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
static void * csf_free(void * buf, int sz);
static size_t csf_read_page(CSF_CTX *ctx, int pgno, void *data);
static size_t csf_write_page(CSF_CTX *ctx, int pgno, void *data, size_t data_sz); 

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
}

static int csf_page_count_for_file(CSF_CTX *ctx) {
  size_t cur_offset = lseek(*ctx->fh, 0, SEEK_CUR);
  size_t count = (lseek(*ctx->fh, 0, SEEK_END) - HDR_SZ) / ctx->page_sz;
  lseek(*ctx->fh, cur_offset, SEEK_SET);
  return count;
}

inline off_t csf_pageno_for_offset(CSF_CTX *ctx, int offset) {
  return (offset / ctx->data_sz);
}

inline int csf_page_count_for_length(CSF_CTX *ctx, int length) {
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

  switch(whence) {
    case SEEK_SET:
      ctx->seek_ptr = offset; /* should this be the offset in the page? */
      true_offset = HDR_SZ + (csf_pageno_for_offset(ctx, ctx->seek_ptr) * ctx->page_sz);
      csf_seek = lseek(*ctx->fh, true_offset, SEEK_SET);
      assert(csf_seek == true_offset);
      break;
    case SEEK_CUR:
      ctx->seek_ptr += offset; /* should this be the offset in the page? */
      true_offset = HDR_SZ + (csf_pageno_for_offset(ctx, ctx->seek_ptr) * ctx->page_sz);
      csf_seek = lseek(*ctx->fh, true_offset, SEEK_SET);
      assert(csf_seek == true_offset);
      break;

    case SEEK_END:
      {
      /* FIXME optimize out second seek */
      int page_count = csf_page_count_for_file(ctx);
      size_t data_sz = csf_read_page(ctx, page_count-1, ctx->page_buffer);
      ctx->seek_ptr = ((page_count - 1) * ctx->data_sz) + data_sz;
      }
      break;
  }  

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

int csf_read(CSF_CTX *ctx, void *data, size_t nbyte) {
  int start_page = csf_pageno_for_offset(ctx, ctx->seek_ptr);
  int start_offset = ctx->seek_ptr % ctx->data_sz;
  int to_read = nbyte + start_offset;
  int pages_to_read = csf_page_count_for_length(ctx, to_read);
  int i, data_offset = 0;

  for(i = 0; i < pages_to_read; i++) {
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

int csf_write(CSF_CTX *ctx, const void *data, size_t nbyte) {
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

#if 0
static int csf_read_file_sz(CSF_CTX *ctx);
static int csf_write_file_sz(CSF_CTX *ctx, int sz);
static int csf_get_len(CSF_CTX *ctx, int len);

/*
  input: desired byte offset in the file
  output: the first logical byte of the block that contains
  the desired offset.
  note: this method does not include the header
*/

inline int csf_get_true_block_start(CSF_CTX *ctx, int sz) {
  return HDR_SZ + ((sz / ctx->data_sz) * ctx->page_sz);
}

inline int csf_get_logical_position(CSF_CTX *ctx, int pos) {
  return ((pos - HDR_SZ) / ctx->page_sz) * ctx->data_sz;  
}

inline int csf_get_logical_block_start(CSF_CTX *ctx, int sz) {
  return (sz - (sz % ctx->data_sz));
}

/*
  input: length of the data block to write
  
  output: the number of bytes (blocks * block size)
  necessary to accomodate the data
  TEST AND FIXME
*/
int csf_get_len(CSF_CTX *ctx, int len) {
  /* * calculate base size by dividing
       the input lenght by block size (to round down)
     * multiply by page size
     * account for an overflow page if necessary
  */  
  int size = (len / ctx->data_sz) * ctx->page_sz;
  if ( (len % ctx->data_sz) != 0 ) {
    size += ctx->page_sz;
  }
  return size;
}

int csf_truncate(CSF_CTX *ctx, int nByte) {
  int retval;
  retval = HDR_SZ + csf_get_len(ctx, nByte);
  csf_write_file_sz(ctx, nByte);
  TRACE4("csf_truncate(%d,%d), retval = %d\n", *ctx->fh, nByte, retval);
  return ftruncate(*ctx->fh, retval);
}

/*
  input: logical byte offset to seek to
*/  
int csf_seek(CSF_CTX *ctx, int offset) {
  int csf_seek = 0;
  int pos = 0;
  int l_pos = 0;
  
  TRACE3("csf_seek(%d,%d)\n", *ctx->fh, offset);

  /* get the block start, and seek to that position
     adjusted for the header size */
  csf_seek = csf_get_true_block_start(ctx,offset);
  pos = lseek(*ctx->fh, csf_seek, SEEK_SET);
  l_pos = csf_get_logical_block_start(ctx, offset);
  
  /* set the csf_seek pointer to the "overlap". After
     the seek the file pointer will be at the beginning
     of the block, but the requested location may be further
     into the file */
  ctx->seek_ptr = offset - l_pos;

  TRACE3("csf_seek = %d, pos = %d\n", csf_seek, pos);
  TRACE5("csf_seek(%d,%d), retval = %d, ctx->seek_ptr = %d\n", *ctx->fh, offset, pos, ctx->seek_ptr);

  /* return the seeked to postion, adjusted down to account for the header */
  return l_pos;
}

/*
  read the specified number of bytes from the file into
  the buffer.
*/
int csf_read(CSF_CTX *ctx, void *buf, size_t nbyte) {
  int sz;
  int csz = 0;
  int rd_sz = 0;
  int l_rd_sz = 0;
  int cur_pos; /* actual seek position */
  int cur_csf_seek; /* logical seek position */ 
  
  int tmp_nbyte;
  int out_off;

  TRACE3("csf_read(%d,x,%d)\n", *ctx->fh, nbyte);
  
  cur_pos = lseek(*ctx->fh, 0L, SEEK_CUR);
  cur_csf_seek = ctx->seek_ptr;
  TRACE3("cur_pos=%d, cur_csf_seek=%d\n", cur_pos, cur_csf_seek);
  assert(((cur_pos - HDR_SZ) % ctx->page_sz) == 0);
  //assert(cur_pos > cur_csf_seek);

  /* determing the size of the chunk to read from the file 
     this will be a multiple of the block size */
  sz = csf_get_len(ctx, nbyte + ctx->seek_ptr);

  TRACE2("sz=%d\n", sz);
  
  tmp_nbyte = nbyte;
  out_off = 0;

  for(;rd_sz < sz ;) {
    int tmp_rd_sz = 0;
    int tmp_cur_csf_seek = 0;
    int to_write = 0;
    
    tmp_rd_sz = read(*ctx->fh, ctx->page_buffer, ctx->page_sz);
  
    if(tmp_rd_sz != ctx->page_sz) {
      TRACE3("reading %d bytes via read() in csf_read(), rd_sz = %d\n", ctx->page_sz, tmp_rd_sz);
    }
    
    if(tmp_rd_sz <= 0) {
      break;  
    }
  
    // FIXME
    tmp_cur_csf_seek = cur_csf_seek - l_rd_sz;

    if(tmp_cur_csf_seek < 0) {
      tmp_cur_csf_seek = 0;  
    }
    
    TRACE3("rd_sz = %d, tmp_rd_sz = %d\n", rd_sz, tmp_rd_sz);
    
    if(tmp_cur_csf_seek < ctx->data_sz) {
      int oct;
      EVP_CIPHER_CTX ectx;
      unsigned char * oPtr;
      unsigned char * iPtr;

      to_write = ctx->data_sz - tmp_cur_csf_seek;
      to_write = tmp_nbyte < to_write ? tmp_nbyte : to_write;
      
      /* decrypt the data read in from the file. note that the 
        rd_sz might be less than sz, particularly
        if the read size exceeded the end of the file */
    
      oPtr =   ctx->csf_buffer;
      iPtr = ctx->page_buffer + ctx->iv_sz;
  
      EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 0);
            EVP_CIPHER_CTX_set_padding(&ectx, 0);
            EVP_CipherInit(&ectx, NULL, ctx->key_data, ctx->page_buffer, 0);

      //EVP_CipherUpdate(&ctx, oPtr, &oct, iPtr, tmp_rd_sz);
      EVP_CipherUpdate(&ectx, oPtr, &oct, iPtr, ctx->data_sz);
      csz = oct;  
      oPtr += oct;
      EVP_CipherFinal(&ectx, oPtr, &oct);
      csz += oct;
      EVP_CIPHER_CTX_cleanup(&ectx);
    
      assert(ctx->data_sz == csz);
  
      /* copy the decrypted data from the buffer into the output
        array */
      memcpy(buf + out_off, ctx->csf_buffer + tmp_cur_csf_seek, to_write);
      out_off += to_write;
      tmp_nbyte -= to_write;
    }
    
    rd_sz += tmp_rd_sz;
    l_rd_sz += tmp_rd_sz - ctx->iv_sz ;
  }

        if(rd_sz != sz) {
    /* if rd_sz is not equal sz, then the read request passed the
       end of file. therefore the file pointer is at the end of file
       and there is no overlap */
    ctx->seek_ptr = 0;
  } else if(nbyte + cur_csf_seek < ctx->data_sz) {
    /* if the number of bytes to read and the current overlap offset 
       are less than the block size, then adjust the csf_seek overlap
       and rewind to teh original position. That is to say that the next
       read should occur in the same block as this read */
      ctx->seek_ptr += nbyte;
    lseek(*ctx->fh, cur_pos, SEEK_SET);
  } else {
    /* otherwise adjust the offset pointer to the new overlap. If there is
       an overlap, the file pointer should be rewound by one block. */
    ctx->seek_ptr = (nbyte + cur_csf_seek) % ctx->data_sz;
    if(ctx->seek_ptr > 0) {
      lseek(*ctx->fh, ctx->page_sz * -1, SEEK_CUR);
    }
  }

  TRACE5("csf_read(%d,x,%d), cur_pos = %d, ctx->seek_ptr = %d\n", *ctx->fh, nbyte, cur_pos, ctx->seek_ptr);

  assert(l_rd_sz - cur_csf_seek >= 0);

  /* if all the data couldnt be read, then determine and return the amout of data that
     was actually read and copied into the output buffer */
  if(rd_sz < sz) {
    if( l_rd_sz - cur_csf_seek < 0) {
      return 0;
    } else {
      return l_rd_sz - cur_csf_seek;
    }
  } else {
    return nbyte;
  }
}

int _write(int h, void *buffer, int sz) {
  int wr_sz;
  int amt = sz;
  void *wPtr = buffer;

  while( amt>0 && (wr_sz = write(h, wPtr, amt))>0 ){
    amt -= wr_sz;
    wPtr = &((char*)wPtr)[wr_sz];
  }
  
  return sz - amt;
}

/* 
  write the specified number of bytes of data into the file
*/
int csf_write(CSF_CTX *ctx, const void *buf, size_t nbyte) {
  int sz;
  int csz = 0;
  int wr_sz = 0;
  int l_wr_sz = 0;
  int cur_pos;
  void *wPtr;
  int w_off;
  int f_sz;
  int cur_csf_seek;

  int tmp_nbyte;
  int in_off;
  
  TRACE3("csf_write(%d,x,%d)\n", *ctx->fh, nbyte);

  cur_pos = lseek(*ctx->fh, 0L, SEEK_CUR);

  /* determing the current overlap */
  cur_csf_seek = ctx->seek_ptr;
  
  /* if the current seek pointer is before the first page
     seek to the first page */  
  if(cur_pos < HDR_SZ) {
    csf_seek(ctx, 0);
    cur_pos = lseek(*ctx->fh, 0L, SEEK_CUR);
  }  

  assert(cur_pos >= HDR_SZ);

  sz = csf_get_len(ctx, nbyte + ctx->seek_ptr);

  tmp_nbyte = nbyte;
  in_off = 0;
  
  for(;wr_sz < sz ;) {
    int tmp_wr_sz = 0;
    int tmp_rd_sz = 0;
    int tmp_cur_csf_seek = 0;
    int to_write = 0;

    tmp_rd_sz = read(*ctx->fh, ctx->page_buffer, ctx->page_sz);
  
    if(tmp_rd_sz != ctx->page_sz) {
      TRACE4("Error reading %d bytes via read() in csf_write() from cur_pos %d. rd_sz = %d\n", sz, cur_pos, tmp_rd_sz);
    }
  
    //FIXME
    tmp_cur_csf_seek = cur_csf_seek - l_wr_sz;
    //tmp_cur_csf_seek = cur_csf_seek - wr_sz;

    if(tmp_cur_csf_seek < 0) {
      tmp_cur_csf_seek = 0;  
    }
    
    if(tmp_cur_csf_seek < ctx->data_sz) {
       int oct;
                        EVP_CIPHER_CTX ectx;
                        unsigned char * oPtr;
                        unsigned char * iPtr;
        
      to_write = ctx->data_sz - tmp_cur_csf_seek;
      to_write = tmp_nbyte < to_write ? tmp_nbyte : to_write;

      //assert(ctx->seek_ptr + nbyte <= sz);
    
      //csf_decrypt(ctx->page_buffer, tmp_rd_sz, ctx->csf_buffer, &csz);
      iPtr = ctx->page_buffer + ctx->iv_sz;
      oPtr =  ctx->csf_buffer;
                        EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 0);
                        EVP_CIPHER_CTX_set_padding(&ectx, 0);
                        EVP_CipherInit(&ectx, NULL, ctx->key_data, ctx->page_buffer, 0);

                        EVP_CipherUpdate(&ectx, oPtr, &oct, iPtr, ctx->data_sz);
                        csz = oct;
                        oPtr += oct;
                        EVP_CipherFinal(&ectx, oPtr, &oct);
                        csz += oct;
                        EVP_CIPHER_CTX_cleanup(&ectx);
  
      assert(ctx->data_sz==csz);
    
      // FIXME
      memcpy(ctx->csf_buffer + tmp_cur_csf_seek, buf + in_off, to_write);
    
      //csf_encrypt(ctx->csf_buffer, ctx->data_sz, ctx->page_buffer, &csz);
      RAND_pseudo_bytes(ctx->page_buffer, ctx->iv_sz);
                        oPtr =  ctx->page_buffer + ctx->iv_sz;
                        EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 1);
                        EVP_CIPHER_CTX_set_padding(&ectx, 0);
                        EVP_CipherInit(&ectx, NULL, ctx->key_data, ctx->page_buffer, 1);

                        EVP_CipherUpdate(&ectx, oPtr, &oct, ctx->csf_buffer, ctx->data_sz);
                        csz = oct;
                        oPtr += oct;
                        EVP_CipherFinal(&ectx, oPtr, &oct);
                        csz += oct;
                        EVP_CIPHER_CTX_cleanup(&ectx);    
  
      assert(ctx->data_sz==csz);
      
      lseek(*ctx->fh, tmp_rd_sz * -1, SEEK_CUR);
      //FIXME
      tmp_wr_sz = _write(*ctx->fh, ctx->page_buffer, ctx->page_sz);
      
      if(tmp_wr_sz != ctx->page_sz) {
        TRACE2("Error writing %d bytes via write() in csf_write()\n", tmp_wr_sz);
      }
      
      in_off += to_write;
      tmp_nbyte -= to_write;
    }
    
    wr_sz += tmp_wr_sz;
    l_wr_sz += tmp_wr_sz - ctx->iv_sz;
  }
    
  //fprintf(stdout, "wr_sz = %d, sz = %d\n", wr_sz, sz);
  assert(wr_sz == sz);
  assert(tmp_nbyte == 0);
  
  w_off = nbyte + cur_csf_seek;
  
  w_off += csf_get_logical_position(ctx, cur_pos);
  
  if(w_off > csf_read_file_sz(ctx)) csf_write_file_sz(ctx, w_off);

  if(nbyte + ctx->seek_ptr < ctx->data_sz) {
    ctx->seek_ptr += nbyte;
    lseek(*ctx->fh, cur_pos, SEEK_SET);
  } else {
    ctx->seek_ptr = (nbyte + ctx->seek_ptr) % ctx->data_sz;
    //lseek(*ctx->fh, csf_get_block_start(w_off), SEEK_CUR);
    lseek(*ctx->fh, csf_get_true_block_start(ctx, w_off), SEEK_SET);
  }

  TRACE6("csf_write(%d,x,%d), cur_pos = %d, csf_seek = %d, w_off = %d\n", *ctx->fh, nbyte, cur_pos, ctx->seek_ptr, w_off);
  return nbyte - tmp_nbyte;
}


static int csf_write_file_sz(CSF_CTX *ctx, int sz) {
  int cur_pos = 0;
  int end_pos = 0;
  int amt = 0;
  int wr_sz = 0;
  void * wPtr = NULL;

  /* save the current position in the file */
  cur_pos = lseek(*ctx->fh, 0L, SEEK_CUR);

  end_pos = lseek(*ctx->fh, 0L, SEEK_END);

  /* seek to the beginning of the file */
  lseek(*ctx->fh, 0L, SEEK_SET);

//  assert(end_pos >= cur_pos);
//  assert(end_pos >= sz);

  _write(*ctx->fh, &sz, sizeof(sz));
  /* write the file size into the header 
     TODO: encrypt tehe header */
  //write64bits(sz, &conv_sz);

  /* go back to the positon at the start of the method execution */
  lseek(*ctx->fh, cur_pos, SEEK_SET);

  TRACE5("csf_write_file_sz(%d,%d), end_pos = %d, cur_pos = %d\n", *ctx->fh, sz, end_pos, cur_pos);
  
  return sz;
}

/*
  read the logical lenght of the file
  
  NOTE: because data is written to the file in even sized blocks, we must
  store the acutual lenght of the data written into the file for other operations
  like read and write. In this case the file lenght is written into the header
*/
static int csf_read_file_sz(CSF_CTX *ctx) {
  int rd_sz = 0;
  int cur_pos = 0;
  int end_pos = 0;
  int sz = 0;
  int retval = 0;

  /* save the current position in the file */
  cur_pos = lseek(*ctx->fh, 0L, SEEK_CUR);

  //end_pos = lseek(*ctx->fh, 0L, SEEK_END);

  /* seek to the beginning of the file */
  lseek(*ctx->fh, 0L, SEEK_SET);

  /* read the file size from the header 
     TODO: once the header is encrypted this method will
     need to decrypt the header */
  rd_sz = read(*ctx->fh, &sz, sizeof(sz));

  if(rd_sz != sizeof(sz)) {
    TRACE3("reading %d bytes via read() in csf_read_file_sz(). rd_sz = %d\n",sizeof(sz), rd_sz);
  }

  /* go back to the positon at the start of the method execution */
  lseek(*ctx->fh, cur_pos, SEEK_SET);

  if(rd_sz == 0) {
    /* if no data was read, indicate a zero lenght file */
    retval = 0;
  } else {
    
    //read64bits(sz, &conv_sz);
    //////fprintf(stdout,, "after read64bits = sz = %d conv_sz = %d\n", sz, conv_sz);
    retval = sz;
  }

  TRACE5("csf_read_file_sz(%d), cur_pos = %d, end_pos = %d, retval = %d\n", *ctx->fh, cur_pos, end_pos, retval);
  return retval;
}

#endif

/*
  input: size of the buffer to allocate
*/
void *csf_malloc(int sz) {
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
void * csf_free(void * buf, int sz) {
  memset(buf, 0, sz);
  free(buf);
}

