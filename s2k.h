#ifndef S2K_H
#define S2K_H

#define DIGEST EVP_sha1()
#define SALT_SZ 8
#define EXPBIAS 6

int s2k(int count, unsigned char *key, int key_sz, unsigned char *salt, char *password); 

#endif
