/*
 keygen.c - PSEC-3 key generation

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000
*/

#include <stdio.h>
#include <gmp.h>
#include "ec_arith.h"
#include "psec3.h"
#include "random.h"

/*
 PSEC-3 Key Generation

 Return: TRUE if succeed; otherwise FALSE
*/
BYTE PSEC3_KeyGeneration (
	EC_PARAM         *E,
	mpz_t            sk,
	EC_POINT         *pk
)
{
RANDOM_STRUCT randomStruct;
unsigned int bytesNeeded;
static unsigned char seedByte = 0;
BYTE *sk_raw;
long i;

	sk_raw = (BYTE *) malloc (E->qLen/8);

	/* initialize random number generator */
	RandomInit(&randomStruct);

	/* initialize with all zero seed bytes for testing purpose only */
	while (1) {
		GetRandomBytesNeeded (&bytesNeeded, &randomStruct);
		if (bytesNeeded == 0) break;
		RandomUpdate (&randomStruct, &seedByte, 1);
	}

	/* generate sk */
	do {
		GenerateBytes(sk_raw, E->pLen/8, &randomStruct);
		printf("PSEC3_KeyGeneration: sk_raw =\n\t");
		for(i=0; i< E->pLen/8; i++)
			printf("%02x ", sk_raw[i]);
		printf("\n\n");

		BYTE2WORD(sk, sk_raw, E->pLen/8);
		mpz_mod(sk, sk, E->p);
	} while (mpz_cmp_ui(sk, 0) == 0);

	printf("PSEC3_KeyGeneration: sk =\n");
	printf("%s\n\n", mpz_get_str(NULL, 16, sk));

	/* compute pk */
	EC_Mult(pk, sk, &(E->P), E);
	printf("PSEC3_KeyGeneration: pk(x, y) =\n");
	printf("%s\n", mpz_get_str(NULL, 16, pk->x));
	printf("%s\n", mpz_get_str(NULL, 16, pk->y));
	printf("%d\n\n", pk->inf_id);

	/* clean up */
	memset(sk_raw, 0, E->qLen/8);
	free(sk_raw);

	return TRUE;
}
