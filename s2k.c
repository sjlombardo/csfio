

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "s2k.h"
#include "hex2bin.h"

int s2k(int count, unsigned char *key, int key_sz, unsigned char *salt,
	char *password) {

	unsigned char *keydata;
	unsigned char *saltpass;
	int pass_sz;
	EVP_MD_CTX mdctx;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_sz, i, j, k;
	int saltpass_sz;
	int times;
	int tcount;
	int remain;
	char null='\0';
	
	OpenSSL_add_all_digests();
		
	pass_sz = strlen(password);
	
	md_sz = EVP_MD_size(DIGEST);
	
	if (salt==NULL) return -1;
	saltpass_sz = pass_sz + SALT_SZ;
	
	if((saltpass = calloc(1, saltpass_sz)) == NULL) return -1;
	
	memcpy( saltpass, salt, SALT_SZ);
	memcpy( &saltpass[SALT_SZ], password, pass_sz);
	

	times = key_sz / md_sz;
	if (key_sz % md_sz != 0) times++;
	
	if ( (keydata=calloc(1, times * md_sz)) == NULL) {
	   free(saltpass);
	   return -1;
        }

	/* 
	 FIX unsigned int size
	*/
	tcount = ((unsigned long) 16 + (count & 15)) << ((count >> 4) + EXPBIAS);
	count = (tcount / saltpass_sz);
	remain = tcount % saltpass_sz;
	
	if (tcount < saltpass_sz) {
		count++;
		remain = 0;
	}
	
	printf("tcount: %d count: %d remain: %d\n", tcount, count, remain);
	
	for (i=0;i<times;i++) {
		EVP_MD_CTX_init(&mdctx);
		EVP_DigestInit_ex(&mdctx, DIGEST, NULL);
		
		for (j=0;j<i;j++)
			EVP_DigestUpdate(&mdctx, &null, 1);

		for (k=0;k<count;k++) {
			EVP_DigestUpdate(&mdctx, saltpass, saltpass_sz);
		}
		
		EVP_DigestUpdate(&mdctx, saltpass, remain);
		EVP_DigestFinal_ex(&mdctx, md_value, &md_sz);
		
		memcpy( &keydata[i * md_sz], md_value, md_sz);
		
		EVP_MD_CTX_cleanup(&mdctx);
		memset(md_value, 0, md_sz);
		
	}
	
	memcpy(key, keydata, key_sz);
	memset(keydata, 0, key_sz);
	memset(md_value, 0, md_sz);
	memset(saltpass, 0, saltpass_sz);
	
	free(keydata);
	free(saltpass);

	return 0;
}

#ifdef TEST
#define keylen 256

int main(int argc, char **argv) {
	
	int len;
	char *pass = "my voice is my password";
	char *salt = "abcdefgh";
	char hout[1024];
	unsigned char bout[keylen];

	printf("Password:  %s\n", pass);
	s2k(96, bout, keylen, salt, pass);
	
	bin2hex(bout, hout, keylen);
	printf("Key: %s\n", hout);

}

#endif
