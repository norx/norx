/*
   NORX reference source code package - reference C implementations

   Written in 2014 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdio.h>
#include <string.h>
#include "norx.h"

#if defined(_MSC_VER)
    #include <intrin.h>
#else
    #include <x86intrin.h>
#endif

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

#if defined(_MSC_VER)
    #define ALIGN(x) __declspec(align(x))
#else
    #define ALIGN(x) __attribute__((aligned(x)))
#endif

#define LOAD(in) _mm_load_si128((__m128i*)(in))
#define STORE(out, x) _mm_store_si128((__m128i*)(out), (x))
#define LOADU(in) _mm_loadu_si128((__m128i*)(in))
#define STOREU(out, x) _mm_storeu_si128((__m128i*)(out), (x))

#  if defined(__XOP__)
#define ROT(X, C) _mm_roti_epi64((X), -(C))
#elif defined(__SSSE3__)
#define ROT(X, C)                                                                               \
(                                                                                               \
        (C) ==  8 ? _mm_shuffle_epi8((X), _mm_set_epi8(8,15,14,13,12,11,10,9, 0,7,6,5,4,3,2,1)) \
    :   (C) == 40 ? _mm_shuffle_epi8((X), _mm_set_epi8(12,11,10,9,8,15,14,13, 4,3,2,1,0,7,6,5)) \
    :   (C) == 63 ? _mm_or_si128(_mm_add_epi64((X), (X)), _mm_srli_epi64((X), 63))              \
    :   /* else */  _mm_or_si128(_mm_srli_epi64((X), (C)), _mm_slli_epi64((X), 64 - (C)))       \
)
#else
#define ROT(X, C)                                                                               \
(                                                                                               \
        (C) == 63 ? _mm_or_si128(_mm_add_epi64((X), (X)), _mm_srli_epi64((X), 63))              \
    :   /* else */  _mm_or_si128(_mm_srli_epi64((X), (C)), _mm_slli_epi64((X), 64 - (C)))       \
)
#endif

#define XOR(A, B) _mm_xor_si128((A), (B))
#define AND(A, B) _mm_and_si128((A), (B))
#define ADD(A, B) _mm_add_epi64((A), (B))

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
#if defined(TWEAK_LOW_LATENCY)
	#define G(S)                                           \
	do                                                     \
	{                                                      \
	    __m128i L[2], R[2];                                \
	                                                       \
	    L[0] = XOR(S[0], S[2]);    R[0] = XOR(S[1], S[3]); \
	    L[1] = AND(S[0], S[2]);    R[1] = AND(S[1], S[3]); \
	    L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
	    S[0] = XOR(L[0], L[1]);    S[1] = XOR(R[0], R[1]); \
	    S[6] = XOR(S[6], L[0]);    S[7] = XOR(S[7], R[0]); \
	    S[6] = XOR(S[6], L[1]);    S[7] = XOR(S[7], R[1]); \
	    S[6] = ROT(S[6], R0);      S[7] = ROT(S[7], R0);   \
	                                                       \
	    L[0] = XOR(S[4], S[6]);    R[0] = XOR(S[5], S[7]); \
	    L[1] = AND(S[4], S[6]);    R[1] = AND(S[5], S[7]); \
	    L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
	    S[4] = XOR(L[0], L[1]);    S[5] = XOR(R[0], R[1]); \
	    S[2] = XOR(S[2], L[0]);    S[3] = XOR(S[3], R[0]); \
	    S[2] = XOR(S[2], L[1]);    S[3] = XOR(S[3], R[1]); \
	    S[2] = ROT(S[2], R1);      S[3] = ROT(S[3], R1);   \
	                                                       \
	    L[0] = XOR(S[0], S[2]);    R[0] = XOR(S[1], S[3]); \
	    L[1] = AND(S[0], S[2]);    R[1] = AND(S[1], S[3]); \
	    L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
	    S[0] = XOR(L[0], L[1]);    S[1] = XOR(R[0], R[1]); \
	    S[6] = XOR(S[6], L[0]);    S[7] = XOR(S[7], R[0]); \
	    S[6] = XOR(S[6], L[1]);    S[7] = XOR(S[7], R[1]); \
	    S[6] = ROT(S[6], R2);      S[7] = ROT(S[7], R2);   \
	                                                       \
	    L[0] = XOR(S[4], S[6]);    R[0] = XOR(S[5], S[7]); \
	    L[1] = AND(S[4], S[6]);    R[1] = AND(S[5], S[7]); \
	    L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
	    S[4] = XOR(L[0], L[1]);    S[5] = XOR(R[0], R[1]); \
	    S[2] = XOR(S[2], L[0]);    S[3] = XOR(S[3], R[0]); \
	    S[2] = XOR(S[2], L[1]);    S[3] = XOR(S[3], R[1]); \
	    S[2] = ROT(S[2], R3);      S[3] = ROT(S[3], R3);   \
	} while(0)
#else
    #define G(S)                                           \
    do                                                     \
    {                                                      \
        __m128i L[2], R[2];                                \
                                                           \
        L[0] = XOR(S[0], S[2]);    R[0] = XOR(S[1], S[3]); \
        L[1] = AND(S[0], S[2]);    R[1] = AND(S[1], S[3]); \
        L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
        S[0] = XOR(L[0], L[1]);    S[1] = XOR(R[0], R[1]); \
        S[6] = XOR(S[6], S[0]);    S[7] = XOR(S[7], S[1]); \
        S[6] = ROT(S[6], R0);      S[7] = ROT(S[7], R0);   \
                                                           \
        L[0] = XOR(S[4], S[6]);    R[0] = XOR(S[5], S[7]); \
        L[1] = AND(S[4], S[6]);    R[1] = AND(S[5], S[7]); \
        L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
        S[4] = XOR(L[0], L[1]);    S[5] = XOR(R[0], R[1]); \
        S[2] = XOR(S[2], S[4]);    S[3] = XOR(S[3], S[5]); \
        S[2] = ROT(S[2], R1);      S[3] = ROT(S[3], R1);   \
                                                           \
        L[0] = XOR(S[0], S[2]);    R[0] = XOR(S[1], S[3]); \
        L[1] = AND(S[0], S[2]);    R[1] = AND(S[1], S[3]); \
        L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
        S[0] = XOR(L[0], L[1]);    S[1] = XOR(R[0], R[1]); \
        S[6] = XOR(S[6], S[0]);    S[7] = XOR(S[7], S[1]); \
        S[6] = ROT(S[6], R2);      S[7] = ROT(S[7], R2);   \
                                                           \
        L[0] = XOR(S[4], S[6]);    R[0] = XOR(S[5], S[7]); \
        L[1] = AND(S[4], S[6]);    R[1] = AND(S[5], S[7]); \
        L[1] = ADD(L[1], L[1]);    R[1] = ADD(R[1], R[1]); \
        S[4] = XOR(L[0], L[1]);    S[5] = XOR(R[0], R[1]); \
        S[2] = XOR(S[2], S[4]);    S[3] = XOR(S[3], S[5]); \
        S[2] = ROT(S[2], R3);      S[3] = ROT(S[3], R3);   \
    } while(0)
#endif

#if defined(__SSSE3__)
#define DIAGONALIZE(S)                     \
do                                         \
{                                          \
    __m128i T[2];                          \
                                           \
    T[0] = _mm_alignr_epi8(S[3], S[2], 8); \
    T[1] = _mm_alignr_epi8(S[2], S[3], 8); \
    S[2] = T[0];                           \
    S[3] = T[1];                           \
                                           \
    T[0] = S[4];                           \
    S[4] = S[5];                           \
    S[5] = T[0];                           \
                                           \
    T[0] = _mm_alignr_epi8(S[7], S[6], 8); \
    T[1] = _mm_alignr_epi8(S[6], S[7], 8); \
    S[6] = T[1];                           \
    S[7] = T[0];                           \
} while(0)

#define UNDIAGONALIZE(S)                   \
do                                         \
{                                          \
    __m128i T[2];                          \
                                           \
    T[0] = _mm_alignr_epi8(S[2], S[3], 8); \
    T[1] = _mm_alignr_epi8(S[3], S[2], 8); \
    S[2] = T[0];                           \
    S[3] = T[1];                           \
                                           \
    T[0] = S[4];                           \
    S[4] = S[5];                           \
    S[5] = T[0];                           \
                                           \
    T[0] = _mm_alignr_epi8(S[6], S[7], 8); \
    T[1] = _mm_alignr_epi8(S[7], S[6], 8); \
    S[6] = T[1];                           \
    S[7] = T[0];                           \
} while(0)

#else

#define DIAGONALIZE(S)                                               \
do                                                                   \
{                                                                    \
    __m128i T[2];                                                    \
                                                                     \
    T[0] = S[6]; T[1] = S[2];                                        \
    S[6] = S[4]; S[4] = S[5]; S[5] = S[6];                           \
    S[6] = _mm_unpackhi_epi64(S[7], _mm_unpacklo_epi64(T[0], T[0])); \
    S[7] = _mm_unpackhi_epi64(T[0], _mm_unpacklo_epi64(S[7], S[7])); \
    S[2] = _mm_unpackhi_epi64(S[2], _mm_unpacklo_epi64(S[3], S[3])); \
    S[3] = _mm_unpackhi_epi64(S[3], _mm_unpacklo_epi64(T[1], T[1])); \
} while(0)

#define UNDIAGONALIZE(S)                                             \
do                                                                   \
{                                                                    \
    __m128i T[2];                                                    \
                                                                     \
    T[0] = S[4]; S[4] = S[5]; S[5] = T[0];                           \
    T[0] = S[2]; T[1] = S[6];                                        \
    S[2] = _mm_unpackhi_epi64(S[3], _mm_unpacklo_epi64(S[2], S[2])); \
    S[3] = _mm_unpackhi_epi64(T[0], _mm_unpacklo_epi64(S[3], S[3])); \
    S[6] = _mm_unpackhi_epi64(S[6], _mm_unpacklo_epi64(S[7], S[7])); \
    S[7] = _mm_unpackhi_epi64(S[7], _mm_unpacklo_epi64(T[1], T[1])); \
} while(0)

#endif

#define F(S)         \
do                   \
{                    \
    G(S);            \
    DIAGONALIZE(S);  \
    G(S);            \
    UNDIAGONALIZE(S);\
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

#define INJECT_DOMAIN_CONSTANT(S, TAG)        \
do                                            \
{                                             \
    S[7] = XOR(S[7], _mm_set_epi64x(TAG, 0)); \
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
    ALIGN(64) unsigned char lastblock[BYTES(NORX_R)]; \
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
    ALIGN(64) unsigned char lastblock[BYTES(NORX_R)]; \
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
        __m128i T = LOADU(IN + j * 2 * BYTES(NORX_W));     \
        STOREU(OUT + j * 2 * BYTES(NORX_W), XOR(S[j], T)); \
        S[j] = T;                                          \
    }                                                      \
} while(0)

#define DECRYPT_LASTBLOCK(S, OUT, IN, INLEN)                     \
do                                                               \
{                                                                \
    size_t j;                                                    \
    ALIGN(64) unsigned char lastblock[BYTES(NORX_R)];            \
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
        __m128i T = LOADU(lastblock + j * 2 * BYTES(NORX_W));    \
        STOREU(lastblock + j * 2 * BYTES(NORX_W), XOR(S[j], T)); \
        S[j] = T;                                                \
    }                                                            \
    memcpy(OUT, lastblock, INLEN);                               \
} while(0)

#define INITIALISE(S, NONCE, KEY)                     \
do                                                    \
{                                                     \
    S[0] = LOADU(NONCE);                              \
    S[1] = _mm_set_epi64x(U1, U0);                    \
    S[2] = LOADU(KEY + 0 * 2 * BYTES(NORX_W));        \
    S[3] = LOADU(KEY + 1 * 2 * BYTES(NORX_W));        \
    S[4] = _mm_set_epi64x(U3, U2);                    \
    S[5] = _mm_set_epi64x(U5, U4);                    \
    S[6] = _mm_set_epi64x(U7, U6);                    \
    S[7] = _mm_set_epi64x(U9, U8);                    \
    S[6] = XOR(S[6], _mm_set_epi64x(NORX_L, NORX_W)); \
    S[7] = XOR(S[7], _mm_set_epi64x(NORX_T, NORX_P)); \
    PERMUTE(S);                                       \
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
    __m128i S[8];

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
    __m128i S[8];

    if (clen < BYTES(NORX_T)) { return -1; }

    *mlen = clen - BYTES(NORX_T);

    INITIALISE(S, nonce, key);
    ABSORB_DATA(S, a, alen, HEADER_TAG);
    DECRYPT_DATA(S, m, c, clen - BYTES(NORX_T));
    ABSORB_DATA(S, z, zlen, TRAILER_TAG);
    FINALISE(S);

    /* Verify tag */
    S[0] = _mm_cmpeq_epi8(S[0], LOADU(c + clen - BYTES(NORX_T)  ));
    S[1] = _mm_cmpeq_epi8(S[1], LOADU(c + clen - BYTES(NORX_T)/2));
    return _mm_movemask_epi8(AND(S[0], S[1])) == 0xFFFF ? 0 : -1;
}

