/*
 hash.c - a random function as described in section 2.4 of the paper
          "EPOC: Efficient Probabilistic Public-Key Encryption" written
          by Tatsuaki Okamoto, Shigenori Uchiyama and Eiichiro Fujisaki.
          This paper has been submitted to IEEE P1363a.

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000
*/

#include <stdio.h>
#include <gmp.h>
#include "ec_arith.h"
#include "psec3.h"
#include "utils.h"
#include "sha1.h"

void encodeBigEndian(BYTE *i_be, WORD i);


/*
 H(x) := SHA^80(<0> || x) || SHA^80(<1> || x) || ... || SHA^L(<n> || x),

 where SHA(x) denotes the 160-bit result of SHA-1 applied to x and
 SHA^l(x) denotes the first l-bits of SHA(x); <i> denotes a binary
 32-bit word of the number i encoded in big-endian; and x is also
 encoded in decreasing significance order (i.e., in big-endian).
 n is equal to the floor of |x|/80 and L = |x| - 80n.

 len  is the length of message in bytes
 hLen is the length of the hashing value in bytes
*/
void indexedSHA(BYTE *out_buffer, WORD outLen, BYTE *in, WORD inLen)
{
SHA1_CTX context;
WORD i, l, indexedLen;
BYTE *in_buffer, *tmp_p;
BYTE index[4];
unsigned char digest[20];

	if(inLen == 0) inLen = 1;

	l = outLen / 10;         /* the floor of hLen/80 in bits (now in bytes) */
	indexedLen = inLen + 4;  /* length of < index > || in */
	in_buffer = (BYTE *) malloc(indexedLen);
	tmp_p = out_buffer;

	SHA1Init(&context);
	for (i=0; i<=l; i++) {
		encodeBigEndian(index, i);
		assignBYTE(in_buffer, index, 4);
		assignBYTE(in_buffer+4, in, inLen);
		SHA1Init(&context);
		SHA1Update(&context, in_buffer, indexedLen);
		SHA1Final(digest, &context);
		if(i<l)
			assignBYTE(tmp_p, digest, 10);
		else
			assignBYTE(tmp_p, digest, outLen-10*l);
		tmp_p += 10;
	}

	memset(in_buffer, 0, indexedLen);
	free(in_buffer);
}


/*
 Encode i to 4 BYTEs in big endian
*/
void encodeBigEndian(BYTE *i_be, WORD i)
{
	i_be[0] = i >> 24;
	i_be[1] = (i >> 16) & 0xff;
	i_be[2] = (i >> 8) & 0xff;
	i_be[3] = i & 0xff;
}
