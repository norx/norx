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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <arm_neon.h>

typedef enum tag__
{
    HEADER_TAG  = 1 << 0,
    PAYLOAD_TAG = 1 << 1,
    TRAILER_TAG = 1 << 2,
    FINAL_TAG   = 1 << 3,
    BRANCH_TAG  = 1 << 4,
    MERGE_TAG   = 1 << 5
} tag_t;

#define ALIGN(x) __attribute__((aligned(x)))

#define LOAD(in) vreinterpretq_u32_u8( vld1q_u8((uint8_t *)(in)) )
#define LOADU(in) LOAD((in))

#define STORE(out, x) vst1q_u8((uint8_t*)(out), vreinterpretq_u8_u32(x))
#define STOREU(out, x) STORE((out), (x))

#define LOADL(in) vcombine_u32( vreinterpret_u32_u8( vld1_u8((uint8_t *)(in)) ), vcreate_u32(0))
#define STOREL(out, x) vst1_u8((uint8_t *)(out), vget_low_u8(vreinterpretq_u8_u32(x)))


#define ROT(X, C)  \
( \
            (C) == 16 ? vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(X))) \
    :       (C) == 31 ? /* vsriq_n_u32(SHL(X), (X), (C))*/ veorq_u32(vshrq_n_u32(X, C), SHL(X) ) \
    :   /* else */  /*vsriq_n_u32(vshlq_n_u32((X), 32-(C)), (X), (C)) */ veorq_u32(vshrq_n_u32(X, C), vshlq_n_u32(X, 32-(C))) \
)

#define XOR(A, B) veorq_u32((A), (B))
#define AND(A, B) vandq_u32((A), (B))
#define ADD(A, B) vaddq_u32((A), (B))
#if 0
#define SHL(A)    vshlq_n_u32((A), 1)
#else
#define SHL(A) vaddq_u32(A, A)
#endif

#define BLEND(A, B) vcombine_u32(vget_low_u32(B), vget_high_u32(A))
#define SETV(A0, A1, A2, A3) {A0, A1, A2, A3}

#define BYTES(X) (((X) + 7) / 8)

#define NORX_B (NORX_W * 16)
#define NORX_C (NORX_W *  4)
#define NORX_R (NORX_B - NORX_C)

#define  U0 0x0454EDABU
#define  U1 0xAC6851CCU
#define  U2 0xB707322FU
#define  U3 0xA0C7C90DU
#define  U4 0x99AB09ACU
#define  U5 0xA643466DU
#define  U6 0x21C22362U
#define  U7 0x1230C950U
#define  U8 0xA3D8D930U
#define  U9 0x3FA8B72CU
#define U10 0xED84EB49U
#define U11 0xEDCA4787U
#define U12 0x335463EBU
#define U13 0xF994220BU
#define U14 0xBE0BF5C9U
#define U15 0xD7C49104U

#define R0  8
#define R1 11
#define R2 16
#define R3 31

/* Implementation */
#if defined(TWEAK_LOW_LATENCY)
	#define G(A, B, C, D)  \
	do                     \
	{                      \
	    uint32x4_t t0, t1; \
	                       \
	    t0 = XOR( A,  B);  \
	    t1 = AND( A,  B);  \
	    t1 = SHL(t1);      \
	    A  = XOR(t0, t1);  \
	    D  = XOR( D, t0);  \
	    D  = XOR( D, t1);  \
	    D  = ROT( D, R0);  \
	                       \
	    t0 = XOR( C,  D);  \
	    t1 = AND( C,  D);  \
	    t1 = SHL(t1);      \
	    C  = XOR(t0, t1);  \
	    B  = XOR( B, t0);  \
	    B  = XOR( B, t1);  \
	    B  = ROT( B, R1);  \
	                       \
	    t0 = XOR( A,  B);  \
	    t1 = AND( A,  B);  \
	    t1 = SHL(t1);      \
	    A  = XOR(t0, t1);  \
	    D  = XOR( D, t0);  \
	    D  = XOR( D, t1);  \
	    D  = ROT( D, R2);  \
	                       \
	    t0 = XOR( C,  D);  \
	    t1 = AND( C,  D);  \
	    t1 = SHL(t1);      \
	    C  = XOR(t0, t1);  \
	    B  = XOR( B, t0);  \
	    B  = XOR( B, t1);  \
	    B  = ROT( B, R3);  \
	} while(0)
#else
	#define G(A, B, C, D)  \
	do                     \
	{                      \
	    uint32x4_t t0, t1; \
	                       \
	    t0 = XOR( A,  B);  \
	    t1 = AND( A,  B);  \
	    t1 = SHL(t1);      \
	    A  = XOR(t0, t1);  \
	    D  = XOR( D,  A);  \
	    D  = ROT( D, R0);  \
	                       \
	    t0 = XOR( C,  D);  \
	    t1 = AND( C,  D);  \
	    t1 = SHL(t1);      \
	    C  = XOR(t0, t1);  \
	    B  = XOR( B,  C);  \
	    B  = ROT( B, R1);  \
	                       \
	    t0 = XOR( A,  B);  \
	    t1 = AND( A,  B);  \
	    t1 = SHL(t1);      \
	    A  = XOR(t0, t1);  \
	    D  = XOR( D,  A);  \
	    D  = ROT( D, R2);  \
	                       \
	    t0 = XOR( C,  D);  \
	    t1 = AND( C,  D);  \
	    t1 = SHL(t1);      \
	    C  = XOR(t0, t1);  \
	    B  = XOR( B,  C);  \
	    B  = ROT( B, R3);  \
	} while(0)
#endif


#define DIAGONALIZE(A, B, C, D)  \
do                               \
{                                \
    D = vextq_u32(D, D, 3);      \
    /* C = vextq_u32(C, C, 2); */      \
    C = vcombine_u32(vget_high_u32(C), vget_low_u32(C)); \
    B = vextq_u32(B, B, 1);      \
} while(0)

#define UNDIAGONALIZE(A, B, C, D) \
do                                \
{                                 \
    D = vextq_u32(D, D, 1);       \
    /* C = vextq_u32(C, C, 2); */       \
    C = vcombine_u32(vget_high_u32(C), vget_low_u32(C)); \
    B = vextq_u32(B, B, 3);       \
} while(0)

#define F(A, B, C, D)          \
do                             \
{                              \
    G(A, B, C, D);             \
    DIAGONALIZE(A, B, C, D);   \
    G(A, B, C, D);             \
    UNDIAGONALIZE(A, B, C, D); \
} while(0)

#define PERMUTE(A, B, C, D) \
do                          \
{                           \
    int i;                  \
    for(i = 0; i < NORX_L; ++i)  \
    {                       \
        F(A, B, C, D);      \
    }                       \
} while(0)

#define INJECT_DOMAIN_CONSTANT(A, B, C, D, TAG)  \
do                                               \
{                                                \
    const uint32x4_t tag = SETV(0,0,0,TAG);      \
    D = XOR(D, tag);                             \
} while(0)


#define ABSORB_BLOCK(A, B, C, D, BLOCK)             \
do                                                  \
{                                                   \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, HEADER_TAG); \
    PERMUTE(A, B, C, D);                            \
    A = XOR(A, LOADU(BLOCK +  0));                  \
    B = XOR(B, LOADU(BLOCK + 16));                  \
    C = XOR(C, LOADU(BLOCK + 32));                  \
} while(0)

#define ENCRYPT_BLOCK(A, B, C, D, IN, OUT)           \
do                                                   \
{                                                    \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, PAYLOAD_TAG); \
    PERMUTE(A, B, C, D);                             \
    A = XOR(A, LOADU(IN +  0)); STOREU(OUT +  0, A); \
    B = XOR(B, LOADU(IN + 16)); STOREU(OUT + 16, B); \
    C = XOR(C, LOADU(IN + 32)); STOREU(OUT + 32, C); \
} while(0)

#define DECRYPT_BLOCK(A, B, C, D, IN, OUT)                      \
do                                                              \
{                                                               \
    uint32x4_t W0, W1, W2;                                      \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, PAYLOAD_TAG);            \
    PERMUTE(A, B, C, D);                                        \
    W0 = LOADU(IN +  0); STOREU(OUT +  0, XOR(A, W0)); A = W0;  \
    W1 = LOADU(IN + 16); STOREU(OUT + 16, XOR(B, W1)); B = W1;  \
    W2 = LOADU(IN + 32); STOREU(OUT + 32, XOR(C, W2)); C = W2;  \
} while(0)

#define DECRYPT_LASTBLOCK(A, B, C, D, IN, INLEN, OUT)      \
do                                                         \
{                                                          \
    uint32x4_t W0, W1, W2;                                 \
    INJECT_DOMAIN_CONSTANT(A, B, C, D, PAYLOAD_TAG);       \
    PERMUTE(A, B, C, D);                                   \
    STOREU(lastblock +   0, A);                            \
    STOREU(lastblock +  16, B);                            \
    STOREU(lastblock +  32, C);                            \
    memcpy(lastblock, IN, INLEN);                          \
    lastblock[INLEN] ^= 0x01;                              \
    lastblock[BYTES(NORX_R)-1]  ^= 0x80;                              \
    W0 = LOADU(lastblock +  0); STOREU(lastblock +  0, XOR(A, W0)); A = W0;  \
    W1 = LOADU(lastblock + 16); STOREU(lastblock + 16, XOR(B, W1)); B = W1;  \
    W2 = LOADU(lastblock + 32); STOREU(lastblock + 32, XOR(C, W2)); C = W2;  \
    memcpy(OUT, lastblock, INLEN);                         \
} while(0)

#define INITIALIZE(A, B, C, D, N, K)                  \
do                                                    \
{                                                     \
    const uint32x4_t A_ = SETV(N&0xFFFFFFFF, N >> 32, U2, U3);       \
    const uint32x4_t C_ = SETV( U8,  U9, U10, U11);           \
    const uint32x4_t D_ = SETV(U12, U13, U14, U15);           \
    const uint32x4_t P_ = SETV(NORX_W, NORX_L, NORX_P, NORX_T);  \
    A = A_;                                           \
    B = K;                                            \
    C = C_;                                           \
    D = D_;                                           \
    D = XOR(D, P_);                                   \
    PERMUTE(A, B, C, D);                              \
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
    memcpy(BLOCK, IN, INLEN);           \
    BLOCK[INLEN] = 0x01;                \
    BLOCK[BLOCKLEN - 1] |= 0x80;        \
} while(0)


int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen_,
    const unsigned char *ad, unsigned long long adlen_,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
    )
{
    ALIGN(32) unsigned char lastblock[BYTES(NORX_R)];
    uint32x4_t A, B, C, D;
    uint64_t   N; //  = *(const uint64_t *)npub;
    const uint32x4_t K   = LOADU(k +  0);
    size_t mlen = mlen_;
    size_t adlen = adlen_;

    memcpy(&N, npub, sizeof N);
    *clen = mlen + BYTES(NORX_T);

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
    if( mlen > 0 )
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
        memcpy(c, lastblock, mlen);
        c += mlen;
    }

    /* No trailer in CAESAR API, ignore */

    /* Finalize, and output tag */
    FINALIZE(A, B, C, D);
    STOREU(c +  0, A);
    return 0;
}


int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen_,
    const unsigned char *ad, unsigned long long adlen_,
    const unsigned char *npub,
    const unsigned char *k
    )
{
    ALIGN(32) unsigned char lastblock[BYTES(NORX_R)];
    uint32x4_t A, B, C, D;
    uint64_t N; //  = *(const uint64_t *)npub;
    const uint32x4_t  K  = LOADU(k +  0);
    size_t clen = clen_;
    size_t adlen = adlen_;

    if(clen < BYTES(NORX_T))
        return -1;

    memcpy(&N, npub, sizeof N);

    clen -= BYTES(NORX_T);
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
    if( clen > 0 )
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
    A = vceqq_u32(A, LOADU(c +  0));
    return 0xFFFFFFFF == (vgetq_lane_u32(A, 0) & vgetq_lane_u32(A, 1) & vgetq_lane_u32(A, 2) & vgetq_lane_u32(A, 3)) ? 0 : -1;
}




