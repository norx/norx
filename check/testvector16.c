#include <stdio.h>

#include "norx_util.h" /* load16, store16 */

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
    unsigned char k[12];
    unsigned char n[ 4];
    unsigned char h[ 4];
    unsigned char m[ 8];
    unsigned char c[8 + 12];
    unsigned long long clen = 0;

    store16(k +  0, 0x0011);
    store16(k +  2, 0x2233);
    store16(k +  4, 0x4455);
    store16(k +  6, 0x6677);
    store16(k +  8, 0x8899);
    store16(k + 10, 0xAABB);

    store16(n +  0, 0xFFFF);
    store16(n +  2, 0xFFFF);

    store16(h +  0, 0x1002);
    store16(h +  2, 0x3004);

    store16(m +  0, 0x8007);
    store16(m +  2, 0x6005);
    store16(m +  4, 0x4003);
    store16(m +  6, 0x2001);


    crypto_aead_encrypt(c, &clen, m, sizeof m, h, sizeof h, NULL, n, k);

    printf("C: %04X %04X %04X %04X\n", load16(c +  0), load16(c +  2), load16(c +  4), load16(c + 6));
    printf("A: %04X %04X %04X %04X %04X %04X\n", load16(c +  8), load16(c + 10), load16(c + 12), load16(c + 14), load16(c + 16), load16(c + 18));

    return 0;
}

