/*
 * Advanced Encryption Standard
 */
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"
#include "aesae.h"

int main(int argc, char *argv[]) {

	uint8_t i;
	uint8_t *state[5];
	uint8_t key[] = {
	   0x2b, 0x7e, 0x15, 0x16,
	   0x28, 0xae, 0xd2, 0xa6,
	   0xab, 0xf7, 0x15, 0x88,
	   0x09, 0xcf, 0x4f, 0x3c };
	//明文
	uint8_t plaintext[] = {
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff };
	uint8_t in[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00 };

	//=====================================

	for (uint8_t i = 0; i < 5; i++)
		state[i] = new uint8_t[16];
	//for (uint8_t i = 0; i < 5; i++) {
	//	for (uint8_t j = 0; j < 16; j++)
	//		state[i][j] = 0x00;

	//}
	//state_update128(state, key);
	//for (uint8_t i = 0; i < 5; i++) {
	//	for (uint8_t j = 0; j < 16; j++)
	//		printf("%x", state[i][j]);
	//	printf("\n");
	//}
	//=====================================

	//密文

	uint8_t out[16]; // 128
	uint8_t ciphertext[16];
	uint8_t temp[16];

	//==========加密算法========

	uint8_t *w; // expanded key

	w = aes_init(sizeof(key));

	aes_key_expansion(key, w);
	printf("Plaintext message:\n");
	for (i = 0; i < 4; i++) {
		printf("%x %x %x %x ", plaintext[4 * i + 0], plaintext[4 * i + 1], plaintext[4 * i + 2], plaintext[4 * i + 3]);
	}
	printf("\n");

	aes_cipher(plaintext /* in */, ciphertext /* out */, w /* expanded key */);

	printf("Ciphered message:\n");
	for (i = 0; i < 4; i++) {
		printf("%x %x %x %x ", ciphertext[4 * i + 0], ciphertext[4 * i + 1], ciphertext[4 * i + 2], ciphertext[4 * i + 3]);
	}
	printf("\n");

	aes_inv_cipher(ciphertext, temp, w);

	printf("Original message (after inv cipher):\n");
	for (i = 0; i < 4; i++) {
		printf("%x %x %x %x ", temp[4 * i + 0], temp[4 * i + 1], temp[4 * i + 2], temp[4 * i + 3]);
	}

	printf("\n");

	free(w);
	
	//=====================================

	printf("Plaintext message:\n");
	for (i = 0; i < 4; i++) {
		printf("%x %x %x %x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	}
	printf("\n");
	printf("\n");
	initialization(state);

	printf("\ninitialization\n");
	for (int i = 0; i < 5; i++) {    
		for (int j = 0; j < 16; j++)
			printf("%x ",state[i][j]);
		printf("\n");
	}
	encryption(state, in, out);
	printf("\nCiphered message:\n");
	for (i = 0; i < 4; i++) {
		printf("%x %x %x %x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
	}

	printf("\n");

	

	printf("Original message (after inv cipher):\n");
	for (i = 0; i < 4; i++) {
		printf("%x %x %x %x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	}

	printf("\n");


	exit(0);
}
