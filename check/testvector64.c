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

#include "norx_util.h" /* load64, store64 */

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
    unsigned char k[32];
    unsigned char n[16];
    unsigned char h[16];
    unsigned char m[32];
    unsigned char c[32 + 32];
    unsigned long long clen = 0;

    store64(k +  0, 0x0011223344556677ULL);
    store64(k +  8, 0x8899AABBCCDDEEFFULL);
    store64(k + 16, 0xFFEEDDCCBBAA9988ULL);
    store64(k + 24, 0x7766554433221100ULL);

    store64(n +  0, 0xFFFFFFFFFFFFFFFFULL);
    store64(n +  8, 0xFFFFFFFFFFFFFFFFULL);

    store64(h +  0, 0x1000000000000002ULL);
    store64(h +  8, 0x3000000000000004ULL);

    store64(m +  0, 0x8000000000000007ULL);
    store64(m +  8, 0x6000000000000005ULL);
    store64(m + 16, 0x4000000000000003ULL);
    store64(m + 24, 0x2000000000000001ULL);

    crypto_aead_encrypt(c, &clen, m, sizeof m, h, sizeof h, NULL, n, k);

    printf("C: %016llX %016llX %016llX %016llX\n", load64(c +  0), load64(c +  8), load64(c + 16), load64(c + 24));
    printf("A: %016llX %016llX %016llX %016llX\n", load64(c + 32), load64(c + 40), load64(c + 48), load64(c + 56));

    return 0;
}

