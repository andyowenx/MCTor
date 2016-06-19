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
unsigned char ckey[] =  "abcdefghijklmnop"; // It is 128bits though..

AES_KEY key;

int init_ctr(struct ctr_state *state, const unsigned char iv[BYTES_SIZE]){
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec+BYTES_SIZE , 0, BYTES_SIZE);
	memcpy(state->ivec, iv, BYTES_SIZE);
}
// encrypt twice  == decrypt

void encrypt(unsigned char *indata,unsigned char *outdata ,int bytes_read){

	int i=0;
	int mod_len=0;

	AES_set_encrypt_key(ckey, KEY_SIZE, &key);

	if( bytes_read < BYTES_SIZE){
		struct ctr_state state;
		init_ctr(&state, iv);
		AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
		return;
	}
	// loop block size  = [ BYTES_SIZE ]
	for(i=BYTES_SIZE; i <= bytes_read ;i+=BYTES_SIZE){
		struct ctr_state state;
		init_ctr(&state, iv);
		AES_ctr128_encrypt(indata, outdata, BYTES_SIZE, &key, state.ivec, state.ecount, &state.num);
		indata+=BYTES_SIZE;
		outdata+=BYTES_SIZE;
	}

	mod_len = bytes_read % BYTES_SIZE;
	if( mod_len != 0 ){
		struct ctr_state state;
		init_ctr(&state, iv);
		AES_ctr128_encrypt(indata, outdata, mod_len, &key, state.ivec, state.ecount, &state.num);
	}

}

/*
int main(int argc, char *argv[]){
	int i=0;
	unsigned char fs[5000] , out[5000];

	for (i=0;i<BYTES_SIZE;i++){
		iv[i]=0;
	}

	for (i=0;i<5000;i++)
		fs[i]='1';

	printf("plain :[%s]\n",fs);

	encrypt(fs ,out ,5000);
	printf("encode:[%s]\n",out);

	encrypt(out ,fs ,5000);
	printf("decode:[%s]\n",fs);
	return 0;
}*/
