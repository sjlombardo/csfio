
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "csfio.h"

int main(int argc, char **argv) {
  int iter = 100;
  int buffer_sz_max = 100*1024;
  int i,j,k;
  CSF_CTX *csf_ctx;
  unsigned char *key;
  int key_len;
  int fd0, fd1;
  ssize_t sz0, sz1;
  ssize_t tmp_sz0, tmp_sz1;
  ssize_t pos0, pos1;
  unsigned char *buffer0, *buffer1;
  char *test_buffer = "1";
  printf("RAND_MAX = %u\n", RAND_MAX); 

  printf("preparing random key\n");
  key_len = 256;
  key = calloc(key_len, 1);
  RAND_pseudo_bytes(key, key_len);

  printf("testing seek past end of file\n");
  fd0 = open("./testfile.raw", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  fd1 = open("./testfile.csf", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
 
  csf_ctx_init(&csf_ctx, &fd1, key, key_len, 512);

  printf("testing 0, SEEK_SET\n");
  lseek(fd0, 0, SEEK_SET);
  write(fd0, test_buffer, 1);
  assert(lseek(fd0, 0, SEEK_END) == 1);

  csf_seek(csf_ctx, 0, SEEK_SET);
  csf_write(csf_ctx, test_buffer, 1);
  assert(csf_seek(csf_ctx, 0, SEEK_END) == 1);

  printf("testing seek past EOF with SEEK_SET\n");

  lseek(fd0, 6000, SEEK_SET);
  write(fd0, test_buffer, 1);
  assert(lseek(fd0, 0, SEEK_END) == 6001);

  csf_seek(csf_ctx, 6000, SEEK_SET);
  csf_write(csf_ctx, test_buffer, 1);
  assert(csf_seek(csf_ctx, 0, SEEK_END) == 6001);

  printf("testing seek past EOF with SEEK_CUR\n");

  lseek(fd0, 6000, SEEK_CUR);
  write(fd0, test_buffer, 1);
  assert(lseek(fd0, 0, SEEK_END) == 12002);

  csf_seek(csf_ctx, 6000, SEEK_CUR);
  csf_write(csf_ctx, test_buffer, 1);
  assert(csf_seek(csf_ctx, 0, SEEK_END) == 12002);

  printf("rewind with with SEEK_SET\n");

  assert(lseek(fd0, 4000, SEEK_SET) == 4000);
  assert(csf_seek(csf_ctx, 4000, SEEK_SET) == 4000);

  printf("testing seek past EOF with SEEK_END\n");

  lseek(fd0, 3000, SEEK_END);
  write(fd0, test_buffer, 1);
  printf("lseek = %d\n", lseek(fd0, 0, SEEK_END) );
  assert(lseek(fd0, 0, SEEK_END) == 15003);

  csf_seek(csf_ctx, 3000, SEEK_END);
  csf_write(csf_ctx, test_buffer, 1);
  assert(csf_seek(csf_ctx, 0, SEEK_END) == 15003);

  close(fd0);
  close(fd1);

  csf_ctx_destroy(csf_ctx);

  printf("testing randomized file writes\n");
  for(i = 0; i < iter; i++) {
    
    fd0 = open("./testfile.raw", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    fd1 = open("./testfile.csf", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    csf_ctx_init(&csf_ctx, &fd1, key, key_len, 512);

    srand(i);

    sz0 = sz1 = rand() % buffer_sz_max;
  
    buffer0 = calloc(sz0, 1);
    RAND_pseudo_bytes(buffer0, sz0);
    buffer1 = calloc(sz1, 1);
    memcpy(buffer1, buffer0, sz1);

    tmp_sz0 = write(fd0, buffer0, sz0);
    //tmp_sz1 = write(fd1, buffer1, sz1);
    tmp_sz1 = csf_write(csf_ctx, buffer1, sz1);
  
    assert(tmp_sz0 == tmp_sz1);
    
    for(j = 0; j < iter; j++) {
      int offset = rand() % sz0;
      int len = rand() % (sz0 - offset);
      RAND_pseudo_bytes(buffer0, len);
      //memset(buffer0, 0, sz0);  
      memcpy(buffer1, buffer0, len);
      
      lseek(fd0, offset, SEEK_SET);
      //lseek(fd1, offset, SEEK_SET);
      csf_seek(csf_ctx, offset, SEEK_SET);

      tmp_sz0 = write(fd0, buffer0, len);
      //tmp_sz1 = write(fd1, buffer1, len);
      tmp_sz1 = csf_write(csf_ctx, buffer1, len);
      
      assert(tmp_sz0 == tmp_sz1);
      assert(tmp_sz0 == len);

      /* read current location, verify */
      pos0 = lseek(fd0, 0, SEEK_CUR);
      //pos1 = lseek(fd1, 0, SEEK_CUR);
      pos1 = csf_seek(csf_ctx, 0, SEEK_CUR);

      assert(pos0 == pos1);

      /* read back and verify write */
      lseek(fd0, offset, SEEK_SET);
      //lseek(fd1, offset, SEEK_SET);
      csf_seek(csf_ctx, offset, SEEK_SET);

      tmp_sz0 = read(fd0, buffer0, len);
      //tmp_sz1 = read(fd1, buffer1, len);
      tmp_sz1 = csf_read(csf_ctx, buffer1, len);

      assert(tmp_sz0 == tmp_sz1);
      assert(tmp_sz0 == len);

      assert(memcmp(buffer0, buffer1, len) == 0);
    } 

    /* read back the entire file and verify front to back */
    lseek(fd0, 0, SEEK_SET);
    //lseek(fd1, 0, SEEK_SET);
    csf_seek(csf_ctx, 0, SEEK_SET);

    tmp_sz0 = read(fd0, buffer0, sz0);
    //tmp_sz1 = read(fd1, buffer1, sz1);
    tmp_sz1 = csf_read(csf_ctx, buffer1, sz1);
   
    assert(tmp_sz0 == sz0);
    assert(tmp_sz1 == sz1);
    assert(tmp_sz0 == tmp_sz1);
  
    assert(memcmp(buffer0, buffer1, sz0) == 0);

  
    /* read file size, verify */
    pos0 = lseek(fd0, 0, SEEK_END);
    //pos1 = lseek(fd1, 0, SEEK_END);
    pos1 = csf_seek(csf_ctx, 0, SEEK_END);

    assert(pos0 == pos1);
    assert(pos0 == sz0);
  
    printf("iteraton %d: wrote %d bytes, read %d bytes\n", i, sz0, sz0); 
    
    free(buffer0);
    free(buffer1);

    csf_ctx_destroy(csf_ctx);
    memset(key, 0, key_len);

    close(fd0);
    close(fd1);
  }
  free(key);
}


