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
#include <stdlib.h>
#include <string.h>

#include "kat.h"

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k);


int check(const unsigned char *kat)
{
    unsigned char w[256];
    unsigned char h[256];
    unsigned char k[32];
    unsigned char n[16];

    unsigned i;
    int place = 0;

    for(i = 0; i < sizeof w; ++i)
        w[i] = 255 & (i*197 + 123);

    for(i = 0; i < sizeof h; ++i)
        h[i] = 255 & (i*193 + 123);

    for(i = 0; i < sizeof k; ++i)
        k[i] = 255 & (i*191 + 123);

    for(i = 0; i < sizeof n; ++i)
        n[i] = 255 & (i*181 + 123);

    for(i = 0; i < sizeof w; ++i)
    {
        unsigned char m[256];
        unsigned char c[256 + 32];
        unsigned long long mlen;
        unsigned long long clen;
        unsigned long long hlen;

        memset(m, 0, sizeof m);
        memcpy(m, w, i);

        clen = 0;
        mlen = hlen = i;

        crypto_aead_encrypt(c, &clen, m, mlen, h, hlen, NULL, n, k);
        if( 0 != memcmp(kat, c, clen) ) {place = 1; goto fail;}

        memset(m, 0, sizeof m);
        mlen = 0;

        if( 0 != crypto_aead_decrypt(m, &mlen, NULL, c, clen, h, hlen, n, k) )
            {place = 2; goto fail;}

        if( 0 != memcmp(m, w, mlen) ) {place = 3; goto fail;}

        kat += clen;
    }
    printf("ok\n");
    return 0;
fail:
    printf("fail at %u:%d\n", i, place);
    return -1;
}

int main()
{
    check(kat);
    return 0;
}

