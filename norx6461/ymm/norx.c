/*
   NORX reference source code package - reference C implementations

   Written in 2014 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#if defined(SUPERCOP)
#   include "crypto_aead.h"
#endif

#include "config.h"

#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
  #include <intrin.h>
#else
  #if defined(__XOP__)
    #include <x86intrin.h>
  #else
    #include <immintrin.h>
  #endif
#endif

typedef enum tag__
{
    HEADER_TAG  = 1 << 0,
    PAYLOAD_TAG = 1 << 1,
    TRAILER_TAG = 1 << 2,
    FINAL_TAG   = 1 << 3,
    BRANCH_TAG  = 1 << 4,
    MERGE_TAG   = 1 << 5
} tag_t;

#if defined(_MSC_VER)
    #define ALIGN(x) __declspec(align(x))
#else
    #define ALIGN(x) __attribute__((aligned(x)))
#endif

#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (NORX_W-1)) / NORX_W)

#define LOAD(in) _mm256_load_si256((__m256i*)(in))
#define STORE(out, x) _mm256_store_si256((__m256i*)(out), (x))
#define LOADU(in) _mm256_loadu_si256((__m256i*)(in))
#define STOREU(out, x) _mm256_storeu_si256((__m256i*)(out), (x))

#define LOAD128(in) _mm_load_si128((__m128i*)(in))
#define STORE128(out, x) _mm_store_si128((__m128i*)(out), (x))
#define LOADU128(in) _mm_loadu_si128((__m128i*)(in))
#define STOREU128(out, x) _mm_storeu_si128((__m128i*)(out), (x))

#define TO128(x) _mm256_castsi256_si128(x)
#define TO256(x) _mm256_castsi128_si256(x)

#define ROT(X, C)  \
( \
        (C) ==  8 ? _mm256_shuffle_epi8((X), _mm256_set_epi8(8,15,14,13,12,11,10,9, 0,7,6,5,4,3,2,1, 8,15,14,13,12,11,10,9, 0,7,6,5,4,3,2,1)) \
    :   (C) == 40 ? _mm256_shuffle_epi8((X), _mm256_set_epi8(12,11,10,9,8,15,14,13, 4,3,2,1,0,7,6,5, 12,11,10,9,8,15,14,13, 4,3,2,1,0,7,6,5)) \
    :   (C) == 63 ? _mm256_or_si256(_mm256_add_epi64((X), (X)), _mm256_srli_epi64((X), 63))           \
    :   /* else */  _mm256_or_si256(_mm256_srli_epi64((X), (C)), _mm256_slli_epi64((X), 64 - (C)))    \
)

#define XOR(A, B) _mm256_xor_si256((A), (B))
#define AND(A, B) _mm256_and_si256((A), (B))
#define ADD(A, B) _mm256_add_epi64((A), (B))

#define XOR128(A, B) _mm_xor_si128((A), (B))
#define AND128(A, B) _mm_and_si128((A), (B))
#define ADD128(A, B) _mm_add_epi64((A), (B))

#define NORX_B (NORX_W * 16)     /* permutation width */
#define NORX_C (NORX_W *  4)     /* capacity */
#define NORX_R (NORX_B - NORX_C) /* rate */

#define  U0 0xE4D324772B91DF79ULL
#define  U1 0x3AEC9ABAAEB02CCBULL
#define  U2 0x9DFBA13DB4289311ULL
#define  U3 0xEF9EB4BF5A97F2C8ULL
#define  U4 0x3F466E92C1532034ULL
#define  U5 0xE6E986626CC405C1ULL
#define  U6 0xACE40F3B549184E1ULL
#define  U7 0xD9CFD35762614477ULL
#define  U8 0xB15E641748DE5E6BULL
#define  U9 0xAA95E955E10F8410ULL
#define U10 0x28D1034441A9DD40ULL
#define U11 0x7F31BBF964E93BF5ULL
#define U12 0xB5E9E22493DFFB96ULL
#define U13 0xB980C852479FAFBDULL
#define U14 0xDA24516BF55EAFD4ULL
#define U15 0x86026AE8536F1501ULL

#define R0  8
#define R1 19
#define R2 40
#define R3 63

/* Implementation */
#if defined(TWEAK_LOW_LATENCY)
    #define G(A, B, C, D)   \
    do                      \
    {                       \
        __m256i t0, t1;     \
                            \
        t0 = XOR( A,  B);   \
        t1 = AND( A,  B);   \
        t1 = ADD(t1, t1);   \
         A = XOR(t0, t1);   \
         D = XOR( D, t0);   \
         D = XOR( D, t1);   \
         D = ROT( D, R0);   \
                            \
        t0 = XOR( C,  D);   \
        t1 = AND( C,  D);   \
        t1 = ADD(t1, t1);   \
         C = XOR(t0, t1);   \
         B = XOR( B, t0);   \
         B = XOR( B, t1);   \
         B = ROT( B, R1);   \
                            \
        t0 = XOR( A,  B);   \
        t1 = AND( A,  B);   \
        t1 = ADD(t1, t1);   \
         A = XOR(t0, t1);   \
         D = XOR( D, t0);   \
         D = XOR( D, t1);   \
         D = ROT( D, R2);   \
                            \
        t0 = XOR( C,  D);   \
        t1 = AND( C,  D);   \
        t1 = ADD(t1, t1);   \
         C = XOR(t0, t1);   \
         B = XOR( B, t0);   \
         B = XOR( B, t1);   \
         B = ROT( B, R3);   \
    } while(0)
#else
  #define G(A, B, C, D)   \
  do                      \
  {                       \
      __m256i t0, t1;     \
                          \
      t0 = XOR( A,  B);   \
      t1 = AND( A,  B);   \
      t1 = ADD(t1, t1);   \
       A = XOR(t0, t1);   \
       D = XOR( D,  A);   \
       D = ROT( D, R0);   \
                          \
      t0 = XOR( C,  D);   \
      t1 = AND( C,  D);   \
      t1 = ADD(t1, t1);   \
       C = XOR(t0, t1);   \
       B = XOR( B,  C);   \
       B = ROT( B, R1);   \
                          \
      t0 = XOR( A,  B);   \
      t1 = AND( A,  B);   \
      t1 = ADD(t1, t1);   \
       A = XOR(t0, t1);   \
       D = XOR( D,  A);   \
       D = ROT( D, R2);   \
                          \
      t0 = XOR( C,  D);   \
      t1 = AND( C,  D);   \
      t1 = ADD(t1, t1);   \
       C = XOR(t0, t1);   \
       B = XOR( B,  C);   \
       B = ROT( B, R3);   \
  } while(0)
#endif


#define DIAGONALIZE(A, B, C, D)                            \
do                                                         \
{                                                          \
    D = _mm256_permute4x64_epi64(D, _MM_SHUFFLE(2,1,0,3)); \
    C = _mm256_permute4x64_epi64(C, _MM_SHUFFLE(1,0,3,2)); \
    B = _mm256_permute4x64_epi64(B, _MM_SHUFFLE(0,3,2,1)); \
} while(0)

#define UNDIAGONALIZE(A, B, C, D)                          \
do                                                         \
{                                                          \
    D = _mm256_permute4x64_epi64(D, _MM_SHUFFLE(0,3,2,1)); \
    C = _mm256_permute4x64_epi64(C, _MM_SHUFFLE(1,0,3,2)); \
    B = _mm256_permute4x64_epi64(B, _MM_SHUFFLE(2,1,0,3)); \
} while(0)

#define F(A, B, C, D)         \
do                            \
{                             \
                              \
    G(A, B, C, D);            \
    DIAGONALIZE(A, B, C, D);  \
    G(A, B, C, D);            \
    UNDIAGONALIZE(A, B, C, D);\
                              \
} while(0)

#define PERMUTE(A, B, C, D)      \
do                               \
{                                \
    int i;                       \
    for(i = 0; i < NORX_L; ++i)  \
    {                            \
        F(A, B, C, D);           \
    }                            \
} while(0)

#define INJECT_DOMAIN_CONSTANT(A, B, C, D, TAG)     \
do                                                  \
{                                                   \
    D = XOR(D, _mm256_set_epi64x(TAG, 0, 0, 0));    \
} while(0)


#define ABSORB_BLOCK(A, B, C, D, BLOCK)             \
do                                                  \
{                                                   \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, HEADER_TAG); \
    PERMUTE(A, B, C, D);                            \
    A = XOR(A, LOADU(BLOCK +  0));                  \
    B = XOR(B, LOADU(BLOCK + 32));                  \
    C = XOR(C, LOADU(BLOCK + 64));                  \
} while(0)

#define ENCRYPT_BLOCK(A, B, C, D, IN, OUT)            \
do                                                    \
{                                                     \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, PAYLOAD_TAG);  \
    PERMUTE(A, B, C, D);                              \
    A = XOR(A, LOADU(IN +  0)); STOREU(OUT +  0, A);  \
    B = XOR(B, LOADU(IN + 32)); STOREU(OUT + 32, B);  \
    C = XOR(C, LOADU(IN + 64)); STOREU(OUT + 64, C);  \
} while(0)

#define DECRYPT_BLOCK(A, B, C, D, IN, OUT)                        \
do                                                                \
{                                                                 \
    __m256i W0, W1, W2;                                           \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, PAYLOAD_TAG);              \
    PERMUTE(A, B, C, D);                                          \
    W0 = LOADU(IN +  0); STOREU(OUT +  0, XOR(A, W0)); A = W0;    \
    W1 = LOADU(IN + 32); STOREU(OUT + 32, XOR(B, W1)); B = W1;    \
    W2 = LOADU(IN + 64); STOREU(OUT + 64, XOR(C, W2)); C = W2;    \
} while(0)

#define DECRYPT_LASTBLOCK(A, B, C, D, IN, INLEN, OUT)                          \
do                                                                             \
{                                                                              \
    __m256i W0, W1, W2;                                                        \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, PAYLOAD_TAG);                           \
    PERMUTE(A, B, C, D);                                                       \
    STOREU(lastblock +   0, A);                                                \
    STOREU(lastblock +  32, B);                                                \
    STOREU(lastblock +  64, C);                                                \
    block_copy(lastblock, IN, INLEN);                                          \
    lastblock[clen] ^= 0x01;                                                   \
    lastblock[BYTES(NORX_R)-1] ^= 0x80;                                        \
    W0 = LOADU(lastblock +  0); STOREU(lastblock +  0, XOR(A, W0)); A = W0;    \
    W1 = LOADU(lastblock + 32); STOREU(lastblock + 32, XOR(B, W1)); B = W1;    \
    W2 = LOADU(lastblock + 64); STOREU(lastblock + 64, XOR(C, W2)); C = W2;    \
    block_copy(OUT, lastblock, INLEN);                                         \
} while(0)

#define INITIALIZE(A, B, C, D, N, K)                                        \
do                                                                          \
{                                                                           \
    A = _mm256_blend_epi32(_mm256_set_epi64x(U3, U2, 0, 0),                 \
                           _mm256_castsi128_si256(N), 0x0F);                \
    B = K;                                                                  \
    C = _mm256_set_epi64x(U11, U10,  U9,  U8);                              \
    D = _mm256_set_epi64x(U15, U14, U13, U12);                              \
    D = XOR(D, _mm256_set_epi64x(NORX_T, NORX_P, NORX_L, NORX_W));          \
    PERMUTE(A, B, C, D);                                                    \
} while(0)

#define FINALIZE(A, B, C, D)                       \
do                                                 \
{                                                  \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, FINAL_TAG); \
    PERMUTE(A, B, C, D);                           \
    PERMUTE(A, B, C, D);                           \
} while(0)

#define PAD(BLOCK, BLOCKLEN, IN, INLEN) \
do                                      \
{                                       \
    memset(BLOCK, 0, BLOCKLEN);         \
    block_copy(BLOCK, IN, INLEN);       \
    BLOCK[INLEN] = 0x01;                \
    BLOCK[BLOCKLEN - 1] |= 0x80;        \
} while(0)

/* inlen <= BYTES(NORX_R) */
static void block_copy(unsigned char *out, const unsigned char *in, const size_t inlen)
{
    if( inlen & 64 )
    {
        STOREU(out +  0, LOADU(in +  0));
        STOREU(out + 32, LOADU(in + 32));
        in += 64; out += 64;
    }
    if( inlen & 32 )
    {
        STOREU(out +  0, LOADU(in +  0));
        in += 32; out += 32;
    }
    if( inlen & 16 )
    {
        STOREU128(out +  0, LOADU128(in +  0));
        in += 16; out += 16;
    }
    if( inlen & 8 )
    {
        memcpy(out, in, 8);
        in += 8; out += 8;
    }
    if( inlen & 4 )
    {
        memcpy(out, in, 4);
        in += 4; out += 4;
    }
    if( inlen & 2 )
    {
        memcpy(out, in, 2);
        in += 2; out += 2;
    }
    if( inlen & 1 )
    {
        memcpy(out, in, 1);
        in += 1; out += 1;
    }
}

int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
    )
{
    ALIGN(64) unsigned char lastblock[BYTES(NORX_R)];
    __m256i A, B, C, D;
    const __m128i N  = LOADU128(npub);
    const __m256i K  = LOADU(k + 0);

    *clen = mlen + NORX_T/8;

    /* Initialization */
    INITIALIZE(A, B, C, D, N, K);

    /* Process header, if exists */
    if( adlen > 0 )
    {
        while(adlen >= BYTES(NORX_R))
        {
            ABSORB_BLOCK(A, B, C, D, ad);
            ad += BYTES(NORX_R);
            adlen -= BYTES(NORX_R);
        }
        PAD(lastblock, sizeof lastblock, ad, adlen);
        ABSORB_BLOCK(A, B, C, D, lastblock);
    }

    /* Encrypt payload */
    if(mlen > 0)
    {
        while( mlen >= BYTES(NORX_R) )
        {
            ENCRYPT_BLOCK(A, B, C, D, m, c);
            mlen -= BYTES(NORX_R);
            m += BYTES(NORX_R);
            c += BYTES(NORX_R);
        }
        /* Handle last block */
        PAD(lastblock, sizeof lastblock, m, mlen);
        ENCRYPT_BLOCK(A, B, C, D, lastblock, lastblock);
        block_copy(c, lastblock, mlen);
        c += mlen;
    }

    /* No trailer in CAESAR API, ignore */

    /* Finalize, and output tag */
    FINALIZE(A, B, C, D);
    STOREU(c + 0, A);
    return 0;
}


int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
    )
{
    ALIGN(64) unsigned char lastblock[BYTES(NORX_R)];
    __m256i A, B, C, D;
    const __m128i N  = LOADU128(npub);
    const __m256i K  = LOADU(k + 0);

    if(clen < NORX_T/8)
        return -1;

    clen -= NORX_T/8;
    *mlen = clen;

    /* Initialization */
    INITIALIZE(A, B, C, D, N, K);

    /* Process header, if exists */
    if( adlen > 0 )
    {
        while(adlen >= BYTES(NORX_R))
        {
            ABSORB_BLOCK(A, B, C, D, ad);
            ad += BYTES(NORX_R);
            adlen -= BYTES(NORX_R);
        }
        PAD(lastblock, sizeof lastblock, ad, adlen);
        ABSORB_BLOCK(A, B, C, D, lastblock);
    }

    /* Decrypt payload */
    if(clen > 0)
    {
        while(clen >= BYTES(NORX_R))
        {
            DECRYPT_BLOCK(A, B, C, D, c, m);
            c += BYTES(NORX_R);
            m += BYTES(NORX_R);
            clen -= BYTES(NORX_R);
        }

        /* Final block */
        DECRYPT_LASTBLOCK(A, B, C, D, c, clen, m);
        c += clen;
    }

    /* No trailer in CAESAR API, ignore */

    /* Finalize, and output tag */
    FINALIZE(A, B, C, D);

    /* Verify tag */
    A = _mm256_cmpeq_epi8(A, LOADU(c +  0));
    return (((_mm256_movemask_epi8(A) & 0xFFFFFFFFULL) + 1) >> 32) - 1;
}



