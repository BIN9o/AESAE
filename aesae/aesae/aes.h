#pragma once
/*
 * Advanced Encryption Standard
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


void sub_bytes(uint8_t *state);

void shift_rows(uint8_t *state);

void mix_columns(uint8_t *state);

void add_round_key(uint8_t *state, uint8_t *w, uint8_t r);

uint8_t *aes_init(size_t key_size);

void aes_key_expansion(uint8_t *key, uint8_t *w);

void aes_inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w);

void aes_cipher(uint8_t *in, uint8_t *out, uint8_t *w);

void round_funtion(uint8_t *state, uint8_t *w, uint8_t r);