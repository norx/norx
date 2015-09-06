/*
   NORX reference source code package - reference C implementations

   Written 2014-2015 by:

        - Samuel Neves <sneves@dei.uc.pt>
        - Philipp Jovanovic <jovanovic@fim.uni-passau.de>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#ifndef NORX_NORX_H
#define NORX_NORX_H

#include <stddef.h>
#include <stdint.h>
#include "norx_config.h"

#if   NORX_W == 64
	typedef uint64_t norx_word_t;
#elif NORX_W == 32
	typedef uint32_t norx_word_t;
#else
	#error "Invalid word size!"
#endif

typedef struct norx_state__
{
    norx_word_t S[16];
} norx_state_t[1];

typedef enum tag__
{
    HEADER_TAG  = 0x01,
    PAYLOAD_TAG = 0x02,
    TRAILER_TAG = 0x04,
    FINAL_TAG   = 0x08,
    BRANCH_TAG  = 0x10,
    MERGE_TAG   = 0x20
} tag_t;

/* Low-level operations */
void norx_init(norx_state_t state, const unsigned char *k, const unsigned char *n);
void norx_absorb_data(norx_state_t state, const unsigned char * in, size_t inlen, tag_t tag);
void norx_encrypt_data(norx_state_t state, unsigned char *out, const unsigned char * in, size_t inlen);
void norx_decrypt_data(norx_state_t state, unsigned char *out, const unsigned char * in, size_t inlen);
void norx_process_trailer(norx_state_t state, const unsigned char * in, size_t inlen);
void norx_output_tag(norx_state_t state, unsigned char * tag);
int  norx_verify_tag(const unsigned char * tag1, const unsigned char * tag2);

/* High-level operations */
void norx_aead_encrypt(
        unsigned char *c, size_t *clen,
        const unsigned char *a, size_t alen,
        const unsigned char *m, size_t mlen,
        const unsigned char *z, size_t zlen,
        const unsigned char *nonce, const unsigned char *key);

int norx_aead_decrypt(
        unsigned char *m, size_t *mlen,
        const unsigned char *a, size_t alen,
        const unsigned char *c, size_t clen,
        const unsigned char *z, size_t zlen,
        const unsigned char *nonce, const unsigned char *key);
#endif
