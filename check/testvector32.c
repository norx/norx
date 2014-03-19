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

#include "defs.h" /* load32, store32 */

int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
    );

int main(void)
{
    unsigned char k[16];
    unsigned char n[ 8];
    unsigned char h[ 8];
    unsigned char m[16];
    unsigned char c[16 + 16];
    unsigned long long clen = 0;

    store32(k +  0, 0x00112233);
    store32(k +  4, 0x44556677);
    store32(k +  8, 0x8899AABB);
    store32(k + 12, 0xCCDDEEFF);

    store32(n +  0, 0xFFFFFFFF);
    store32(n +  4, 0xFFFFFFFF);

    store32(h +  0, 0x10000002);
    store32(h +  4, 0x30000004);

    store32(m +  0, 0x80000007);
    store32(m +  4, 0x60000005);
    store32(m +  8, 0x40000003);
    store32(m + 12, 0x20000001);

    crypto_aead_encrypt(c, &clen, m, sizeof m, h, sizeof h, NULL, n, k);

    printf("C: %08X %08X %08X %08X\n", load32(c +  0), load32(c +  4), load32(c +  8), load32(c + 12));
    printf("A: %08X %08X %08X %08X\n", load32(c + 16), load32(c + 20), load32(c + 24), load32(c + 28));

    return 0;
}

