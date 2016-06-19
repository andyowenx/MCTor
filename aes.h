#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#define BYTES_SIZE 16
#define KEY_SIZE 128


unsigned char iv[BYTES_SIZE];
struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};



int init_ctr(struct ctr_state *state, const unsigned char iv[BYTES_SIZE]);
void aesctr_encrypt(unsigned char *indata,unsigned char *outdata ,int bytes_read);
