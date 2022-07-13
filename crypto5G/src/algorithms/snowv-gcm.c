// AEAD mode: SNOW-V-GCM in C (Endianness-free)
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SNOWV.h"
#include "ghash.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

void snowv_gcm_encrypt(u8 *A, u8 *ciphertext, u8 *plaintext, u64 plaintext_sz,\
                       u8 *aad, u64 aad_sz, u8 *key32, u8 *iv16)
{
    u8 Hkey[16], endPad[16], out[256];
    memset(A, 0, 16);
    keyiv_setup(key32, iv16, 1, out);
    keystream(Hkey);
    keystream(endPad);
    ghash_update(Hkey, A, aad, aad_sz);

    for (u64 i = 0; i < plaintext_sz; i += 16)
    {
        u8 key_stream[16];
        keystream(key_stream);
        for(u8 j = 0; j < min(16, plaintext_sz - i); j++)
            ciphertext[i + j] = key_stream[j] ^ plaintext[i + j];
    }

    ghash_update(Hkey, A, ciphertext, plaintext_sz);
    ghash_final(Hkey, A, aad_sz, plaintext_sz, endPad);
}

void snowv_gcm_decrypt(u8 *A, u8 *ciphertext, u8 *plaintext, u64 ciphertext_sz,\
                       u8 *aad, u64 aad_sz, u8 *key32, u8 *iv16)
{
    u8 Hkey[16], endPad[16], auth[16] = {0x00}, out[256];
    keyiv_setup(key32, iv16, 1, out);
    keystream(Hkey);
    keystream(endPad);
    ghash_update(Hkey, auth, aad, aad_sz);
    ghash_update(Hkey, auth, ciphertext, ciphertext_sz);
    ghash_final(Hkey, auth, aad_sz, ciphertext_sz, endPad);
    
    for(int i = 0; i < 16; i++)
    {
        if(auth[i] != A[i])
        { 
            printf("Authentication Failed!");
            exit(1);
        }
    }

    for (u64 i = 0; i < ciphertext_sz; i += 16)
    { 
        u8 key_stream[16];
        keystream(key_stream);
        for(u8 j = 0; j < min(16, ciphertext_sz - i); j++)
            plaintext[i + j] = key_stream[j] ^ ciphertext[i + j];
    }
}