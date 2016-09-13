/*
 * NORX reference source code package - reference C implementations
 *
 * Written 2014-2016 by: 
 *
 *      - Samuel Neves <sneves@dei.uc.pt>
 *      - Philipp Jovanovic <philipp@jovanovic.io>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#include <string.h>
#include <stdio.h>

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k);

static void genkat(void)
{
	unsigned char w[256];
	unsigned char h[256];
	unsigned char k[32];
	unsigned char n[32];

	unsigned int i, j;

	for(i = 0; i < sizeof w; ++i)
		w[i] = 255 & (i*197 + 123);

	for(i = 0; i < sizeof h; ++i)
		h[i] = 255 & (i*193 + 123);

	for(i = 0; i < sizeof k; ++i)
		k[i] = 255 & (i*191 + 123);

	for(i = 0; i < sizeof n; ++i)
		n[i] = 255 & (i*181 + 123);

	printf("#ifndef NORX_KAT_H\n");
	printf("#define NORX_KAT_H\n");
	printf("static const unsigned char kat[] = \n{\n");
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

		for(j = 0; j < clen; ++j)
			printf("0x%02X%s", c[j], (j + 1 == clen) ? "" : (7 == j%8) ? ",\n" : ", ");

		printf("%s", (i + 1 == sizeof w) ? "\n" : ",\n\n");
	}
	printf("};\n\n");
	printf("#endif\n\n");
}

int main()
{
	genkat();
	return 0;
}

