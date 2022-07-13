#ifndef SNOWV_H
#define SNOWV_H

#include <string.h>
#include <stdint.h>
#include <stdio.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// SNOW-V Cypher
void aes_enc_round(u32 *result, u32 *state, u32 *roundKey);

u16 mul_x(u16 v, u16 c);
u16 mul_x_inv(u16 v, u16 d);
void permute_sigma(u32 *state);

void fsm_update(void);
void lfsr_update(void);

void keystream(u8 *z);
void keyiv_setup(u8 *key, u8 *iv, int is_aead_mode, u8* out);


// AEAD-Mode
void snowv_gcm_encrypt(u8 *A, u8 *ciphertext, u8 *plaintext, u64 plaintext_sz,\
                       u8 *aad, u64 aad_sz, u8 *key32, u8 *iv16);

void snowv_gcm_decrypt(u8 *A, u8 *ciphertext, u8 *plaintext, u64 ciphertext_sz,\
                       u8 *aad, u64 aad_sz, u8 *key32, u8 *iv16);

#endif