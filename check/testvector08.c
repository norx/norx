#include <stdio.h>

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
    unsigned char k[10] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    unsigned char n[ 4] = {0xFF, 0xFF, 0xFF, 0xFF};
    unsigned char h[ 4] = {0x10, 0x02, 0x30, 0x04};
    unsigned char m[ 8] = {0x80, 0x07, 0x60, 0x05, 0x40, 0x03, 0x20, 0x01};
    unsigned char c[8 + 10];
    unsigned long long clen = 0;

    crypto_aead_encrypt(c, &clen, m, sizeof m, h, sizeof h, NULL, n, k);

    printf("C: %02X %02X %02X %02X %02X %02X %02X %02X\n", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
    printf("A: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17]);

    return 0;
}

