/*
   NORX reference source code package - reference C implementations

   Written in 2014 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdint.h>
#include <string.h>
#include <arm_neon.h>

#include "norx.h"

const char * norx_version = "2.0";

#define NORX_W 64                /* word size */
#define NORX_L 4                 /* round number */
#define NORX_P 1                 /* parallelism degree */
#define NORX_T (NORX_W *  4)     /* tag size */
#define NORX_N (NORX_W *  2)     /* nonce size */
#define NORX_K (NORX_W *  4)     /* key size */
#define NORX_B (NORX_W * 16)     /* permutation width */
#define NORX_C (NORX_W *  4)     /* capacity */
#define NORX_R (NORX_B - NORX_C) /* rate */

#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (NORX_W-1)) / NORX_W)

#define ALIGN(x) __attribute__((aligned(x)))

#define U32TOU64(X) vreinterpretq_u64_u32(X)
#define U64TOU32(X) vreinterpretq_u32_u64(X)
#define U8TOU32(X)  vreinterpretq_u32_u8(X)
#define U32TOU8(X)  vreinterpretq_u8_u32(X)
#define U8TOU64(X)  vreinterpretq_u64_u8(X)
#define U64TOU8(X)  vreinterpretq_u8_u64(X)

#define LOAD(in) U8TOU64( vld1q_u8((uint8_t *)(in)) )
#define STORE(out, x) vst1q_u8((uint8_t*)(out), U64TOU8(x))
#define LOADU(in) LOAD(in)
#define STOREU(out, x) STORE(out, x)

#define XOR(A, B) veorq_u64((A), (B))
#define AND(A, B) vandq_u64((A), (B))
#define ADD(A, B) vaddq_u64((A), (B))

#if 0
#define SHL(A) vshlq_n_u64((A), 1)
#else
#define SHL(A) ADD((A), (A))
#endif

#if 0
#define ROT_63(X) vsriq_n_u64(SHL(X), (X), 63)
#else
#define ROT_63(X) veorq_u64(SHL(X), vshrq_n_u64(X, 63))
#endif

#if 1
#define ROT_N(X, C) vsriq_n_u64(vshlq_n_u64((X), 64-(C)), (X), (C))
#else
#define ROT_N(X, C) veorq_u64(vshrq_n_u64((X), (C)), vshlq_n_u64(X, 64-(C)))
#endif

#define ROT(X, C)               \
(                               \
        (C) == 63 ? ROT_63(X)   \
    :   /* else */  ROT_N(X, C) \
)

#define U0 0xE4D324772B91DF79ULL
#define U1 0x3AEC9ABAAEB02CCBULL
#define U2 0x9DFBA13DB4289311ULL
#define U3 0xEF9EB4BF5A97F2C8ULL
#define U4 0x3F466E92C1532034ULL
#define U5 0xE6E986626CC405C1ULL
#define U6 0xACE40F3B549184E1ULL
#define U7 0xD9CFD35762614477ULL
#define U8 0xB15E641748DE5E6BULL
#define U9 0xAA95E955E10F8410ULL

#define R0  8
#define R1 19
#define R2 40
#define R3 63

/* Implementation */
#define G(S)                                            \
do                                                      \
{                                                       \
    uint64x2_t L[2], R[2];                              \
                                                        \
    L[0] = XOR(S[0], S[2]);    R[0] = XOR(S[1], S[3]);  \
    L[1] = AND(S[0], S[2]);    R[1] = AND(S[1], S[3]);  \
    L[1] = SHL(      L[1]);    R[1] = SHL(      R[1]);  \
    S[0] = XOR(L[0], L[1]);    S[1] = XOR(R[0], R[1]);  \
    S[6] = XOR(S[6], S[0]);    S[7] = XOR(S[7], S[1]);  \
    S[6] = ROT(S[6],   R0);    S[7] = ROT(S[7],   R0);  \
                                                        \
    L[0] = XOR(S[4], S[6]);    R[0] = XOR(S[5], S[7]);  \
    L[1] = AND(S[4], S[6]);    R[1] = AND(S[5], S[7]);  \
    L[1] = SHL(      L[1]);    R[1] = SHL(      R[1]);  \
    S[4] = XOR(L[0], L[1]);    S[5] = XOR(R[0], R[1]);  \
    S[2] = XOR(S[2], S[4]);    S[3] = XOR(S[3], S[5]);  \
    S[2] = ROT(S[2],   R1);    S[3] = ROT(S[3],   R1);  \
                                                        \
    L[0] = XOR(S[0], S[2]);    R[0] = XOR(S[1], S[3]);  \
    L[1] = AND(S[0], S[2]);    R[1] = AND(S[1], S[3]);  \
    L[1] = SHL(      L[1]);    R[1] = SHL(      R[1]);  \
    S[0] = XOR(L[0], L[1]);    S[1] = XOR(R[0], R[1]);  \
    S[6] = XOR(S[6], S[0]);    S[7] = XOR(S[7], S[1]);  \
    S[6] = ROT(S[6],   R2);    S[7] = ROT(S[7],   R2);  \
                                                        \
    L[0] = XOR(S[4], S[6]);    R[0] = XOR(S[5], S[7]);  \
    L[1] = AND(S[4], S[6]);    R[1] = AND(S[5], S[7]);  \
    L[1] = SHL(      L[1]);    R[1] = SHL(      R[1]);  \
    S[4] = XOR(L[0], L[1]);    S[5] = XOR(R[0], R[1]);  \
    S[2] = XOR(S[2], S[4]);    S[3] = XOR(S[3], S[5]);  \
    S[2] = ROT(S[2],   R3);    S[3] = ROT(S[3],   R3);  \
} while(0)

#define DIAGONALIZE(S)                                              \
do                                                                  \
{                                                                   \
    uint64x2_t T[2];                                                \
                                                                    \
    T[0] = vcombine_u64( vget_high_u64(S[2]), vget_low_u64(S[3]) ); \
    T[1] = vcombine_u64( vget_high_u64(S[3]), vget_low_u64(S[2]) ); \
    S[2] = T[0];                                                    \
    S[3] = T[1];                                                    \
                                                                    \
    T[0] = S[4];                                                    \
    S[4] = S[5];                                                    \
    S[5] = T[0];                                                    \
                                                                    \
    T[0] = vcombine_u64( vget_high_u64(S[6]), vget_low_u64(S[7]) ); \
    T[1] = vcombine_u64( vget_high_u64(S[7]), vget_low_u64(S[6]) ); \
    S[6] = T[1];                                                    \
    S[7] = T[0];                                                    \
} while(0)

#define UNDIAGONALIZE(S)                                            \
do                                                                  \
{                                                                   \
    uint64x2_t T[2];                                                \
                                                                    \
    T[0] = vcombine_u64( vget_high_u64(S[3]), vget_low_u64(S[2]) ); \
    T[1] = vcombine_u64( vget_high_u64(S[2]), vget_low_u64(S[3]) ); \
    S[2] = T[0];                                                    \
    S[3] = T[1];                                                    \
                                                                    \
    T[0] = S[4];                                                    \
    S[4] = S[5];                                                    \
    S[5] = T[0];                                                    \
                                                                    \
    T[0] = vcombine_u64( vget_high_u64(S[7]), vget_low_u64(S[6]) ); \
    T[1] = vcombine_u64( vget_high_u64(S[6]), vget_low_u64(S[7]) ); \
    S[6] = T[1];                                                    \
    S[7] = T[0];                                                    \
} while(0)

#define F(S)          \
do                    \
{                     \
    G(S);             \
    DIAGONALIZE(S);   \
    G(S);             \
    UNDIAGONALIZE(S); \
} while(0)

#define PERMUTE(S)              \
do                              \
{                               \
    int i;                      \
    for(i = 0; i < NORX_L; ++i) \
    {                           \
        F(S);                   \
    }                           \
} while(0)

#define INJECT_DOMAIN_CONSTANT(S, TAG)                                \
do                                                                    \
{                                                                     \
    S[7] = XOR(S[7], vcombine_u64(vcreate_u64(0), vcreate_u64(TAG))); \
} while(0)

#define ABSORB_BLOCK(S, IN, TAG)                             \
do                                                           \
{                                                            \
    size_t j;                                                \
    INJECT_DOMAIN_CONSTANT(S, TAG);                          \
    PERMUTE(S);                                              \
    for (j = 0; j < WORDS(NORX_R)/2; ++j)                    \
    {                                                        \
        S[j] = XOR(S[j], LOADU(IN + j * 2 * BYTES(NORX_W))); \
    }                                                        \
} while(0)

#define ABSORB_LASTBLOCK(S, IN, INLEN, TAG)           \
do                                                    \
{                                                     \
    ALIGN(32) unsigned char lastblock[BYTES(NORX_R)]; \
    PAD(lastblock, sizeof lastblock, IN, INLEN);      \
    ABSORB_BLOCK(S, lastblock, TAG);                  \
} while(0)

#define ENCRYPT_BLOCK(S, OUT, IN)                            \
do                                                           \
{                                                            \
    size_t j;                                                \
    INJECT_DOMAIN_CONSTANT(S, PAYLOAD_TAG);                  \
    PERMUTE(S);                                              \
    for (j = 0; j < WORDS(NORX_R)/2; ++j)                    \
    {                                                        \
        S[j] = XOR(S[j], LOADU(IN + j * 2 * BYTES(NORX_W))); \
        STOREU(OUT + j * 2 * BYTES(NORX_W), S[j]);           \
    }                                                        \
} while(0)

#define ENCRYPT_LASTBLOCK(S, OUT, IN, INLEN)          \
do                                                    \
{                                                     \
    ALIGN(32) unsigned char lastblock[BYTES(NORX_R)]; \
    PAD(lastblock, sizeof lastblock, IN, INLEN);      \
    ENCRYPT_BLOCK(S, lastblock, lastblock);           \
    memcpy(OUT, lastblock, INLEN);                    \
} while(0)

#define DECRYPT_BLOCK(S, OUT, IN)                          \
do                                                         \
{                                                          \
    size_t j;                                              \
    INJECT_DOMAIN_CONSTANT(S, PAYLOAD_TAG);                \
    PERMUTE(S);                                            \
    for (j = 0; j < WORDS(NORX_R)/2; ++j)                  \
    {                                                      \
        uint64x2_t T = LOADU(IN + j * 2 * BYTES(NORX_W));  \
        STOREU(OUT + j * 2 * BYTES(NORX_W), XOR(S[j], T)); \
        S[j] = T;                                          \
    }                                                      \
} while(0)

#define DECRYPT_LASTBLOCK(S, OUT, IN, INLEN)                     \
do                                                               \
{                                                                \
    size_t j;                                                    \
    ALIGN(32) unsigned char lastblock[BYTES(NORX_R)];            \
    INJECT_DOMAIN_CONSTANT(S, PAYLOAD_TAG);                      \
    PERMUTE(S);                                                  \
    for (j = 0; j < WORDS(NORX_R)/2; ++j)                        \
    {                                                            \
        STOREU(lastblock + j * 2 * BYTES(NORX_W), S[j]);         \
    }                                                            \
    memcpy(lastblock, IN, INLEN);                                \
    lastblock[INLEN] ^= 0x01;                                    \
    lastblock[BYTES(NORX_R) - 1] ^= 0x80;                        \
    for (j = 0; j < WORDS(NORX_R)/2; ++j)                        \
    {                                                            \
        uint64x2_t T = LOADU(lastblock + j * 2 * BYTES(NORX_W)); \
        STOREU(lastblock + j * 2 * BYTES(NORX_W), XOR(S[j], T)); \
        S[j] = T;                                                \
    }                                                            \
    memcpy(OUT, lastblock, INLEN);                               \
} while(0)

#define INITIALISE(S, NONCE, KEY)                                               \
do                                                                              \
{                                                                               \
    S[0] = LOADU(NONCE);                                                        \
    S[1] = vcombine_u64( vcreate_u64(U0), vcreate_u64(U1) );                    \
    S[2] = LOADU(KEY + 0 * 2 * BYTES(NORX_W));                                  \
    S[3] = LOADU(KEY + 1 * 2 * BYTES(NORX_W));                                  \
    S[4] = vcombine_u64( vcreate_u64(U2), vcreate_u64(U3) );                    \
    S[5] = vcombine_u64( vcreate_u64(U4), vcreate_u64(U5) );                    \
    S[6] = vcombine_u64( vcreate_u64(U6), vcreate_u64(U7) );                    \
    S[7] = vcombine_u64( vcreate_u64(U8), vcreate_u64(U9) );                    \
    S[6] = XOR(S[6], vcombine_u64( vcreate_u64(NORX_W), vcreate_u64(NORX_L) )); \
    S[7] = XOR(S[7], vcombine_u64( vcreate_u64(NORX_P), vcreate_u64(NORX_T) )); \
    PERMUTE(S);                                                                 \
} while(0)

#define ABSORB_DATA(S, IN, INLEN, TAG)       \
do                                           \
{                                            \
    if (INLEN > 0)                           \
    {                                        \
        size_t i = 0;                        \
        size_t l = INLEN;                    \
        while (l >= BYTES(NORX_R))           \
        {                                    \
            ABSORB_BLOCK(S, IN + i, TAG);    \
            i += BYTES(NORX_R);              \
            l -= BYTES(NORX_R);              \
        }                                    \
        ABSORB_LASTBLOCK(S, IN + i, l, TAG); \
    }                                        \
} while(0)

#define ENCRYPT_DATA(S, OUT, IN, INLEN)           \
do                                                \
{                                                 \
    if (INLEN > 0)                                \
    {                                             \
        size_t i = 0;                             \
        size_t l = INLEN;                         \
        while (l >= BYTES(NORX_R))                \
        {                                         \
            ENCRYPT_BLOCK(S, OUT + i, IN + i);    \
            i += BYTES(NORX_R);                   \
            l -= BYTES(NORX_R);                   \
        }                                         \
        ENCRYPT_LASTBLOCK(S, OUT + i, IN + i, l); \
    }                                             \
} while(0)

#define DECRYPT_DATA(S, OUT, IN, INLEN)           \
do                                                \
{                                                 \
    if (INLEN > 0)                                \
    {                                             \
        size_t i = 0;                             \
        size_t l = INLEN;                         \
        while (l >= BYTES(NORX_R))                \
        {                                         \
            DECRYPT_BLOCK(S, OUT + i, IN + i);    \
            i += BYTES(NORX_R);                   \
            l -= BYTES(NORX_R);                   \
        }                                         \
        DECRYPT_LASTBLOCK(S, OUT + i, IN + i, l); \
    }                                             \
} while(0)

#define FINALISE(S)                       \
do                                        \
{                                         \
    INJECT_DOMAIN_CONSTANT(S, FINAL_TAG); \
    PERMUTE(S);                           \
    PERMUTE(S);                           \
} while(0)

#define PAD(OUT, OUTLEN, IN, INLEN) \
do                                  \
{                                   \
    memset(OUT, 0, OUTLEN);         \
    memcpy(OUT, IN, INLEN);         \
    OUT[INLEN] = 0x01;              \
    OUT[OUTLEN - 1] |= 0x80;        \
} while(0)

typedef enum tag__
{
    HEADER_TAG  = 0x01,
    PAYLOAD_TAG = 0x02,
    TRAILER_TAG = 0x04,
    FINAL_TAG   = 0x08,
    BRANCH_TAG  = 0x10,
    MERGE_TAG   = 0x20
} tag_t;


void norx_aead_encrypt(
  unsigned char *c, size_t *clen,
  const unsigned char *a, size_t alen,
  const unsigned char *m, size_t mlen,
  const unsigned char *z, size_t zlen,
  const unsigned char *nonce,
  const unsigned char *key
)
{

    uint64x2_t S[8];

    *clen = mlen + BYTES(NORX_T);
    INITIALISE(S, nonce, key);
    ABSORB_DATA(S, a, alen, HEADER_TAG);
    ENCRYPT_DATA(S, c, m, mlen);
    ABSORB_DATA(S, z, zlen, TRAILER_TAG);
    FINALISE(S);
    STOREU(c + mlen,                   S[0]);
    STOREU(c + mlen + BYTES(NORX_T)/2, S[1]);
}


int norx_aead_decrypt(
  unsigned char *m, size_t *mlen,
  const unsigned char *a, size_t alen,
  const unsigned char *c, size_t clen,
  const unsigned char *z, size_t zlen,
  const unsigned char *nonce,
  const unsigned char *key
)
{
    uint64x2_t S[8];
    uint32x4_t T[2];

    if (clen < BYTES(NORX_T)) { return -1; }

    *mlen = clen - BYTES(NORX_T);

    INITIALISE(S, nonce, key);
    ABSORB_DATA(S, a, alen, HEADER_TAG);
    DECRYPT_DATA(S, m, c, clen - BYTES(NORX_T));
    ABSORB_DATA(S, z, zlen, TRAILER_TAG);
    FINALISE(S);

    /* Verify tag */
    T[0] = vceqq_u32(U64TOU32(S[0]), U8TOU32( vld1q_u8((uint8_t *)(c + clen - BYTES(NORX_T)  )) ));
    T[1] = vceqq_u32(U64TOU32(S[1]), U8TOU32( vld1q_u8((uint8_t *)(c + clen - BYTES(NORX_T)/2)) ));
    T[0] = vandq_u32(T[0], T[1]);
    return 0xFFFFFFFFFFFFFFFFULL == (vgetq_lane_u64(U32TOU64(T[0]), 0) & vgetq_lane_u64(U32TOU64(T[0]), 1)) ? 0 : -1;
}

