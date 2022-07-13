// Informative: an exampled implementation of GHASH core (C++)

#include <string.h>
#include "ghash.h"

#define XOR2x64(dst, src) ((u64*)(dst))[0] ^= ((u64*)(src))[0], \
((u64*)(dst))[1] ^= ((u64*)(src))[1]

#define XOR3x64(dst, src1, src2) ((u64*)(dst))[0] = ((u64*)(src1))[0] ^ ((u64*)(src2))[0], \
((u64*)(dst))[1] = ((u64*)(src1))[1] ^ ((u64*)(src2))[1]

void ghash_mult(u8 *out, const u8 *x, const u8 *y)
{
    char tmp[17];
    u64 c0, c1, u0 = ((u64*)y)[0], u1 = ((u64*)y)[1];
    memset(out, 0, 16);
    for (int i = 0; i < 16; i++)
        for (int j = 7; j >= 0; j--)
        {
            if ((x[i] >> j) & 1) ((u64*) out)[0] ^= u0, ((u64*) out)[1] ^= u1;
            c0 = (u0 << 7) & 0x8080808080808080ULL;
            c1 = (u1 << 7) & 0x8080808080808080ULL;
            u0 = (u0 >> 1) & 0x7f7f7f7f7f7f7f7fULL;
            u1 = (u1 >> 1) & 0x7f7f7f7f7f7f7f7fULL;
            ((u64*) (tmp + 1))[0] = c0;
            ((u64*) (tmp + 1))[1] = c1;
            tmp[0] = (tmp[16] >> 7) & 0xe1;
            u0 ^= ((u64*) tmp)[0];
            u1 ^= ((u64*) tmp)[1];
        }
}

void ghash_update(const u8 *H, u8 *A, const u8 *data, long long length)
{
    u8 tmp[16];
    for( ;length >= 16; length -=16, data += 16)
    {
        XOR3x64(tmp, data, A);
        ghash_mult(A, tmp, H);
    }

    if(!length) return;
    memset(tmp, 0, 16);
    memcpy(tmp, data, length);
    XOR2x64(tmp, A);
    ghash_mult(A, tmp, H);
}

void ghash_final(const u8 *H, u8 *A, u64 lenAAD, u64 lenC, const u8 *maskingBlock)
{
    u8 tmp[16];
    lenAAD <<= 3;
    lenC <<= 3;
    for(int i=0; i<8; ++i)
    {
        tmp[7-i] = (u8)(lenAAD >> (8 * i));
        tmp[15-i] = (u8)(lenC >> (8 * i));
    }
    XOR2x64(tmp, A);
    ghash_mult(A, tmp, H);
    XOR2x64(A, maskingBlock); /* The resulting AuthTag is in A[] */
}

int main()
{
    return 0;
}