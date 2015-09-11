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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void norx_aead_encrypt(
        unsigned char *c, size_t *clen,
        const unsigned char *a, size_t alen,
        const unsigned char *m, size_t mlen,
        const unsigned char *z, size_t zlen,
        const unsigned char *nonce,
        const unsigned char *key);

int norx_aead_decrypt(
        unsigned char *p, size_t *plen,
        const unsigned char *a, size_t alen,
        const unsigned char *c, size_t clen,
        const unsigned char *z, size_t zlen,
        const unsigned char *nonce,
        const unsigned char *key);

static void print_bytes(const unsigned char *in, size_t inlen)
{
    size_t i;
    for (i = 0; i < inlen; ++i) {
        printf("%02X%c", in[i], i%16 == 15 ? '\n' : ' ');
    }
    if (inlen%16 != 0) {
        printf("\n");
    }
    printf("\n");
}

#define MAX_A 1024
#define MAX_M 1024
#define MAX_Z 1024

int main() {
    unsigned char k[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
    unsigned char n[16] = {0xF0,0xE0,0xD0,0xC0,0xB0,0xA0,0x90,0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10,0x00};
    unsigned char a[MAX_A] = {0};
    unsigned char m[MAX_M] = {0};
    unsigned char c[MAX_M + 32] = {0};
    unsigned char z[MAX_Z] = {0};

    size_t alen = 128;
    size_t mlen = 128;
    size_t clen = 0;
    size_t zlen = 128;
    size_t i = 0;
    int result = -1;

    for (i = 0; i < alen; ++i) { a[i] = i & 255; }
    for (i = 0; i < mlen; ++i) { m[i] = i & 255; }
    for (i = 0; i < zlen; ++i) { z[i] = i & 255; }

    printf("========== SETUP ==========\n");
    printf("Key:\n"); /* NOTE: some NORX variants do not use all of the bytes in the buffer */
    print_bytes(k, sizeof k);
    printf("Nonce:\n"); /* NOTE: some NORX variants do not use all of the bytes in the buffer */
    print_bytes(n, sizeof n);
    printf("Header:\n");
    print_bytes(a, alen);
    printf("Message:\n");
    print_bytes(m, mlen);
    printf("Trailer:\n");
    print_bytes(z, zlen);

    printf("========== ENCRYPTION ==========\n");
    norx_aead_encrypt(c, &clen, a, alen, m, mlen, z, zlen, n, k);
    printf("Ciphertext + tag:\n");
    print_bytes(c, clen);

    printf("========== DECRYPTION ==========\n");
    result = norx_aead_decrypt(m, &mlen, a, alen, c, clen, z, zlen, n, k);
    printf("Decrypted message:\n");
    print_bytes(m, mlen);

    printf("verify: %d\n", result);

    return 0;
}
