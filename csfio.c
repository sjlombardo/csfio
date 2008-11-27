
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

static int inited = 0;


/*
int sqlite3csf_init(sqlite3 *db, unsigned char *keyd, int len, int data_block_sz) {
	int i;

	csf_config_init(&db->cfg, keyd, len, data_block_sz);
	for(i=0; i<db->nDb; i++){
		struct Db *pDb = &db->aDb[i];
		if( pDb->pBt ){
			btree_set_csf_cfg(pDb->pBt, db->cfg);
		}
	}
}
*/

int csf_config_init(CSF_CFG **cfg_out, unsigned char *keyd, int len, int data_block_sz) {
	EVP_CIPHER_CTX ectx;
	CSF_CFG *cfg;
	cfg = csf_malloc(sizeof(CSF_CFG));
 	if(inited != 1) { 
		OpenSSL_add_all_algorithms();
 		inited = 1;
	}
	
	cfg->key_sz = len;
	cfg->data_block_sz = data_block_sz;
	cfg->keydata = csf_malloc(cfg->key_sz);
	memcpy(cfg->keydata, keyd, cfg->key_sz);

	EVP_EncryptInit(&ectx, CIPHER, cfg->keydata, NULL);
	cfg->block_sz = EVP_CIPHER_CTX_block_size(&ectx);
	cfg->iv_sz = EVP_CIPHER_CTX_iv_length(&ectx);
		
	if(cfg->data_block_sz % cfg->block_sz != 0) {
		printf("FATAL ERROR: Block Size error!\n");
		return 1;
	}
		
	/* the combined block size includes the size of the initialization
	   vector and the data block 
	   FIXME*/

	cfg->cmb_block_sz = cfg->iv_sz + cfg->data_block_sz;
		
	EVP_CIPHER_CTX_cleanup(&ectx);


	TRACE2("csf_init() ctx->cfg->block_sz=%d\n", cfg->block_sz);

	cfg->encrypted=1;
	*cfg_out = cfg;
	return 0;
}

int csf_ctx_init(CSF_CTX **ctx_out, int *fh, CSF_CFG *cfg) {
	CSF_CTX *ctx;
	ctx = csf_malloc(sizeof(CSF_CTX));
	ctx->csf_seek_ptr = 0;
	ctx->file_sz = 0;
	ctx->cfg = cfg;
	ctx->fh = fh;
	*ctx_out = ctx;
	return 0;	
}


int csf_ctx_destroy(CSF_CTX *ctx) {
	ctx->csf_seek_ptr = 0;
	ctx->file_sz = 0;
}

int csf_cfg_destroy(CSF_CFG *cfg) {
	if(cfg) {
		cfg->block_sz = 0;
		cfg->iv_sz = 0;
		cfg->data_block_sz = 0;
		
		cfg->key_sz = 0;
		cfg->cmb_block_sz = 0;
		csf_free(cfg->keydata, cfg->key_sz);
		csf_free(cfg, sizeof(CSF_CTX));	
		cfg = 0;
	}
	return 0;
}

/*
	input: desired byte offset in the file

	output: the first logical byte of the block that contains
	the desired offset.

	note: this method does not include the header
*/


inline int csf_get_true_block_start(CSF_CTX *ctx,int sz) {
	return (sz / ctx->cfg->data_block_sz) * ctx->cfg->cmb_block_sz;
}

inline int csf_get_logical_block_start(CSF_CTX *ctx, int sz) {
	return (sz - (sz % ctx->cfg->data_block_sz));
}

inline int csf_get_logical_position(CSF_CTX *ctx, int pos) {
	return (pos / ctx->cfg->cmb_block_sz) * ctx->cfg->data_block_sz;	
}

/*
	input: length of the data block to write
	
	output: the number of bytes (blocks * block size)
	necessary to accomodate the data
	TEST AND FIXME
*/
int csf_get_len(CSF_CTX *ctx, int len) {
	int size;
	
	/* the base size calcuatled by dividing
	   the lenght by block size to round it down
	   and multiplying it back by block size */
	size = (len / ctx->cfg->data_block_sz) * ctx->cfg->cmb_block_sz;
	
	/* if the lenght is not evenly divisible by the
	   block lenght, add another block to handle the
	   overflow (padding) */
	if ( (len % ctx->cfg->data_block_sz) != 0 ) {
		size += ctx->cfg->cmb_block_sz;
	}
	return size;
}

/*
	input: file and number of bytes to truncate to

	notes: truncate the file, but adjust the size
	to take into account the header at the beginning
	of the file
	
	TEST AND FIXME
*/
int csf_truncate(CSF_CTX *ctx, int nByte) {
	int retval;
	retval = csf_get_len(ctx, nByte) + HDR_SZ;
	TRACE4("csf_truncate(%d,%d), retval = %d\n", *ctx->fh, nByte, retval);
	csf_write_file_sz(ctx, nByte);
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
	pos = lseek(*ctx->fh, csf_seek + HDR_SZ, SEEK_SET);
	l_pos = csf_get_logical_block_start(ctx, offset);
	
	/* set the csf_seek pointer to the "overlap". After
	   the seek the file pointer will be at the beginning
	   of the block, but the requested location may be further
	   into the file */
	ctx->csf_seek_ptr = offset - l_pos;

	TRACE3("csf_seek = %d, pos = %d\n", csf_seek, pos);
	TRACE5("csf_seek(%d,%d), retval = %d, ctx->csf_seek_ptr = %d\n", *ctx->fh, offset, pos - HDR_SZ, ctx->csf_seek_ptr);

	/* return the seeked to postion, adjusted down to account for the header */
	return l_pos;
}

/*
	read the specified number of bytes from the file into
	the buffer.
*/
int csf_read(CSF_CTX *ctx, void *buf, size_t nbyte) {
	void *rd_buffer;
	void *csf_buffer;
	int sz;
	int csz = 0;
	int rd_sz = 0;
	int l_rd_sz = 0;
	int cur_pos;
	int cur_csf_seek;
	
	int tmp_nbyte;
	int out_off;


	TRACE3("csf_read(%d,x,%d)\n", *ctx->fh, nbyte);
	
	/* save the current position in the file */
	cur_pos = lseek(*ctx->fh, 0L, SEEK_CUR);

	/* determing the current overlap */
	cur_csf_seek = ctx->csf_seek_ptr;
	
	TRACE2("cur_pos=%d\n", cur_pos);
	assert(((cur_pos - HDR_SZ) % ctx->cfg->cmb_block_sz) == 0);

	/* determing the size of the chunk to read from the file 
	   this will be a multiple of the block size */
	sz = csf_get_len(ctx, nbyte + ctx->csf_seek_ptr);

	TRACE2("sz=%d\n", sz);
	
	/* allocate memory, and read the data from the file */
	rd_buffer = csf_malloc(ctx->cfg->cmb_block_sz);
	csf_buffer = csf_malloc(ctx->cfg->cmb_block_sz);

	tmp_nbyte = nbyte;
	out_off = 0;

	for(;rd_sz < sz ;) {
		int tmp_rd_sz = 0;
		int tmp_cur_csf_seek = 0;
		int to_write = 0;
		
		tmp_rd_sz = read(*ctx->fh, rd_buffer, ctx->cfg->cmb_block_sz);
	
		if(tmp_rd_sz != ctx->cfg->cmb_block_sz) {
			TRACE3("reading %d bytes via read() in csf_read(), rd_sz = %d\n", ctx->cfg->cmb_block_sz, tmp_rd_sz);
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
		
		if(tmp_cur_csf_seek < ctx->cfg->data_block_sz) {
			int oct;
			EVP_CIPHER_CTX ectx;
			unsigned char * oPtr;
			unsigned char * iPtr;

			to_write = ctx->cfg->data_block_sz - tmp_cur_csf_seek;
			to_write = tmp_nbyte < to_write ? tmp_nbyte : to_write;
			
			/* decrypt the data read in from the file. note that the 
				rd_sz might be less than sz, particularly
				if the read size exceeded the end of the file */
		
			oPtr = 	csf_buffer;
			iPtr = rd_buffer + ctx->cfg->iv_sz;
	
			EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 0);
        		EVP_CIPHER_CTX_set_padding(&ectx, 0);
	        	EVP_CipherInit(&ectx, NULL, ctx->cfg->keydata, rd_buffer, 0);

			//EVP_CipherUpdate(&ctx, oPtr, &oct, iPtr, tmp_rd_sz);
			EVP_CipherUpdate(&ectx, oPtr, &oct, iPtr, ctx->cfg->data_block_sz);
			csz = oct;	
			oPtr += oct;
			EVP_CipherFinal(&ectx, oPtr, &oct);
			csz += oct;
			EVP_CIPHER_CTX_cleanup(&ectx);
		
			assert(ctx->cfg->data_block_sz == csz);
	
			/* copy the decrypted data from the buffer into the output
				array */
			memcpy(buf + out_off, csf_buffer + tmp_cur_csf_seek, to_write);
			out_off += to_write;
			tmp_nbyte -= to_write;
		}
		
		rd_sz += tmp_rd_sz;
		l_rd_sz += tmp_rd_sz - ctx->cfg->iv_sz ;
	}

        if(rd_sz != sz) {
		/* if rd_sz is not equal sz, then the read request passed the
		   end of file. therefore the file pointer is at the end of file
		   and there is no overlap */
		ctx->csf_seek_ptr = 0;
	} else if(nbyte + cur_csf_seek < ctx->cfg->data_block_sz) {
		/* if the number of bytes to read and the current overlap offset 
		   are less than the block size, then adjust the csf_seek overlap
		   and rewind to teh original position. That is to say that the next
		   read should occur in the same block as this read */
		ctx->csf_seek_ptr += nbyte;
		lseek(*ctx->fh, cur_pos, SEEK_SET);
	} else {
		/* otherwise adjust the offset pointer to the new overlap. If there is
		   an overlap, the file pointer should be rewound by one block. */
		ctx->csf_seek_ptr = (nbyte + cur_csf_seek) % ctx->cfg->data_block_sz;
		if(ctx->csf_seek_ptr > 0) {
			lseek(*ctx->fh, ctx->cfg->cmb_block_sz * -1, SEEK_CUR);
		}
	}

	/* wipe the data and free the allocated memory */
	csf_free(rd_buffer, ctx->cfg->cmb_block_sz);
	csf_free(csf_buffer, ctx->cfg->cmb_block_sz);
	
	TRACE5("csf_read(%d,x,%d), cur_pos = %d, ctx->csf_seek_ptr = %d\n", *ctx->fh, nbyte, cur_pos, ctx->csf_seek_ptr);

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
	void *wr_buffer;
	void *csf_buffer;
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
	cur_csf_seek = ctx->csf_seek_ptr;
	
	if(cur_pos < HDR_SZ) {
		csf_seek(ctx, 0);
		cur_pos = lseek(*ctx->fh, 0L, SEEK_CUR);
	}	

	assert(cur_pos >= HDR_SZ);

	sz = csf_get_len(ctx, nbyte + ctx->csf_seek_ptr);

	wr_buffer = csf_malloc(ctx->cfg->cmb_block_sz);
	csf_buffer = csf_malloc(ctx->cfg->cmb_block_sz);
	
	
	tmp_nbyte = nbyte;
	in_off = 0;
	
	for(;wr_sz < sz ;) {
		int tmp_wr_sz = 0;
		int tmp_rd_sz = 0;
		int tmp_cur_csf_seek = 0;
		int to_write = 0;
		

		tmp_rd_sz = read(*ctx->fh, wr_buffer, ctx->cfg->cmb_block_sz);
	
		if(tmp_rd_sz != ctx->cfg->cmb_block_sz) {
			TRACE4("Error reading %d bytes via read() in csf_write() from cur_pos %d. rd_sz = %d\n", sz, cur_pos, tmp_rd_sz);
		}
	
		//FIXME
		tmp_cur_csf_seek = cur_csf_seek - l_wr_sz;
		//tmp_cur_csf_seek = cur_csf_seek - wr_sz;

		if(tmp_cur_csf_seek < 0) {
			tmp_cur_csf_seek = 0;	
		}
		
		if(tmp_cur_csf_seek < ctx->cfg->data_block_sz) {
 			int oct;
                        EVP_CIPHER_CTX ectx;
                        unsigned char * oPtr;
                        unsigned char * iPtr;
				
			to_write = ctx->cfg->data_block_sz - tmp_cur_csf_seek;
			to_write = tmp_nbyte < to_write ? tmp_nbyte : to_write;

			//assert(ctx->csf_seek_ptr + nbyte <= sz);
		
			//csf_decrypt(wr_buffer, tmp_rd_sz, csf_buffer, &csz);
			iPtr = wr_buffer + ctx->cfg->iv_sz;
			oPtr =  csf_buffer;
                        EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 0);
                        EVP_CIPHER_CTX_set_padding(&ectx, 0);
                        EVP_CipherInit(&ectx, NULL, ctx->cfg->keydata, wr_buffer, 0);

                        EVP_CipherUpdate(&ectx, oPtr, &oct, iPtr, ctx->cfg->data_block_sz);
                        csz = oct;
                        oPtr += oct;
                        EVP_CipherFinal(&ectx, oPtr, &oct);
                        csz += oct;
                        EVP_CIPHER_CTX_cleanup(&ectx);
	
			assert(ctx->cfg->data_block_sz==csz);
		
			// FIXME
			memcpy(csf_buffer + tmp_cur_csf_seek, buf + in_off, to_write);
		
			//csf_encrypt(csf_buffer, ctx->cfg->data_block_sz, wr_buffer, &csz);
			RAND_pseudo_bytes(wr_buffer, ctx->cfg->iv_sz);
                        oPtr =  wr_buffer + ctx->cfg->iv_sz;
                        EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 1);
                        EVP_CIPHER_CTX_set_padding(&ectx, 0);
                        EVP_CipherInit(&ectx, NULL, ctx->cfg->keydata, wr_buffer, 1);

                        EVP_CipherUpdate(&ectx, oPtr, &oct, csf_buffer, ctx->cfg->data_block_sz);
                        csz = oct;
                        oPtr += oct;
                        EVP_CipherFinal(&ectx, oPtr, &oct);
                        csz += oct;
                        EVP_CIPHER_CTX_cleanup(&ectx);		
	
			assert(ctx->cfg->data_block_sz==csz);
			
			lseek(*ctx->fh, tmp_rd_sz * -1, SEEK_CUR);
			//FIXME
			tmp_wr_sz = _write(*ctx->fh, wr_buffer, ctx->cfg->cmb_block_sz);
			
			if(tmp_wr_sz != ctx->cfg->cmb_block_sz) {
				TRACE2("Error writing %d bytes via write() in csf_write()\n", tmp_wr_sz);
			}
			
			in_off += to_write;
			tmp_nbyte -= to_write;
		}
		
		wr_sz += tmp_wr_sz;
		l_wr_sz += tmp_wr_sz - ctx->cfg->iv_sz;
	}
		
	//fprintf(stdout, "wr_sz = %d, sz = %d\n", wr_sz, sz);
	assert(wr_sz == sz);
	assert(tmp_nbyte == 0);
	
	w_off = nbyte + cur_csf_seek;
	
	//w_off += (cur_pos > HDR_SZ) ? (cur_pos - HDR_SZ) : 0; 
	w_off += csf_get_logical_position(ctx, cur_pos-HDR_SZ);
	
	if(w_off > csf_read_file_sz(ctx)) csf_write_file_sz(ctx, w_off);

	if(nbyte + ctx->csf_seek_ptr < ctx->cfg->data_block_sz) {
		ctx->csf_seek_ptr += nbyte;
		lseek(*ctx->fh, cur_pos, SEEK_SET);
	} else {
		ctx->csf_seek_ptr = (nbyte + ctx->csf_seek_ptr) % ctx->cfg->data_block_sz;
		//lseek(*ctx->fh, csf_get_block_start(w_off), SEEK_CUR);
		lseek(*ctx->fh, csf_get_true_block_start(ctx, w_off) + HDR_SZ, SEEK_SET);
	}

	csf_free(wr_buffer, ctx->cfg->cmb_block_sz);
	csf_free(csf_buffer, ctx->cfg->cmb_block_sz);

	TRACE6("csf_write(%d,x,%d), cur_pos = %d, csf_seek = %d, w_off = %d\n", *ctx->fh, nbyte, cur_pos, ctx->csf_seek_ptr, w_off);
	return sz - wr_sz;
}


/* FIXME these functions may only be required if NDEBUG is set
#ifndef NDEBUG
*/
int csf_write_file_sz(CSF_CTX *ctx, int sz) {
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

//	assert(end_pos >= cur_pos);
//	assert(end_pos >= sz);

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
int csf_read_file_sz(CSF_CTX *ctx) {
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

/*
	input: size of the buffer to allocate
*/
void *csf_malloc(int sz) {
	void *buf;

	buf = malloc(sz);

	if(buf == NULL) {
		TRACE2("allocating %d bytes via malloc() in csf_malloc()", sz);
	}

	memset(buf, 0, sz);

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

/* 
int csf_crypt(unsigned char *in, int inlen, unsigned char *out, int *outlen, int enc) {
	int oct;
	unsigned char *oPtr;
	EVP_CIPHER_CTX ctx;
	oPtr = out;

	EVP_CipherUpdate(&ctx, oPtr, &oct, in, inlen);
	oPtr += oct;
	*outlen = oct;
	EVP_CipherFinal(&ctx, oPtr, &oct);	
	*outlen+=oct;

	TRACE4("csf_crypt() oct=%d outlen=%d enc=%d\n", oct, *outlen, enc);
	EVP_CIPHER_CTX_cleanup(&ctx);

	return 0;
}

int csf_encrypt(unsigned char *in, int inlen, unsigned char *out, int *outlen) {
	return csf_crypt(in, inlen, out, outlen, 1);
}


int csf_decrypt(unsigned char *in, int inlen, unsigned char *out, int *outlen) {
	return csf_crypt(in, inlen, out, outlen, 0);
}

static void read64bits(int in , int *out){
	int res;
	unsigned char ac[8];
	memcpy(ac,&in, 8);
	res = (ac[0]<<56) | (ac[1]<<48) | (ac[2]<<40) | (ac[3]<<32) | (ac[4]<<24) | (ac[5]<<16) | (ac[6]<<8) | ac[7];
	*out = res;
}

static void write64bits(int val, int *out){
	unsigned char ac[8];
	ac[0] = (val>>56) & 0xff;
	ac[1] = (val>>40) & 0xff;
	ac[2] = (val>>40) & 0xff;
	ac[3] = (val>>32) & 0xff;
	ac[4] = (val>>24) & 0xff;
	ac[5] = (val>>16) & 0xff;
	ac[6] = (val>>8) & 0xff;
	ac[7] =  val & 0xff;
	ac[0] = (val>>56) & 0xff;
	ac[1] = (val>>40) & 0xff;
	ac[2] = (val>>40) & 0xff;
	ac[3] = (val>>32) & 0xff;
	ac[4] = (val>>24) & 0xff;
	ac[5] = (val>>16) & 0xff;
	ac[6] = (val>>8) & 0xff;
	ac[7] =  val & 0xff;

	memcpy(out, ac, 8);
}
*/

