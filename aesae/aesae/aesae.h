#pragma once
#include "aes.h"

void fuzhi(uint8_t *k);
void state_update128(uint8_t *state[5], uint8_t *m);
void initialization(uint8_t *state[5]);
void encryption(uint8_t *state[5], uint8_t *plaintext, uint8_t *ciphertext);
uint8_t *AESRound(uint8_t *state, uint8_t *w);