/*
 keygen.c - PSEC-KEM key generation

 Copyright NTT MCL, 2000 & 2001.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.

 10/25/2000 - Enabled to input random seed from file by T. Kobayashi. -- H.O.

 9/19/2001 - Updated to allow Camellia as symmetric encryption algorithm. -- S.O.
*/

#include <stdio.h>
#include <gmp.h>
#include "nessie.h"
#include "ec_arith.h"
#include "psec_kem.h"
#include "random.h"

#if SYMMETRIC_ENCR == ENCRYPT_ALG_CAM
#include "camellia.h"
#endif

/*
 PSEC-KEM Key Generation

 Return: TRUE if succeed; otherwise FALSE
*/
u8 PSEC_KEM_KeyGeneration (
	u32	seedLen,
	EC_PARAM         *E,
	PSEC_KEM_PRIV_KEY        *privateKey,
	PSEC_KEM_PUB_KEY         *publicKey
)
{
mpz_t p_minus_one;

	mpz_init(p_minus_one);

	/* Choose private key from {0, ..., E->p-1} */
	mpz_set (privateKey->sk, E->p);
	mpz_sub_ui(p_minus_one, E->p, 1);
	while (mpz_cmp(privateKey->sk, p_minus_one) > 0)  {
		GenerateNumber(E->pLen, privateKey->sk, global_prng);
	}
	printf("PSEC_KEM_KeyGeneration: sk =\n");
	printf("%s\n\n", mpz_get_str(NULL, 16, privateKey->sk));

	publicKey->Hid = H_MGF1;
#if SYMMETRIC_ENCR == ENCRYPT_ALG_CAM
	publicKey->SEid = ENCRYPT_ALG_CAM;
#else
	publicKey->SEid = ENCRYPT_ALG_XOR;
#endif
	publicKey->hLen = seedLen;
	publicKey->outputKeyLen = OUTPUT_KEY_LEN;

	/* compute pk */
	EC_Mult(&(publicKey->pk), privateKey->sk, &(E->P), E);
	printf("PSEC_KEM_KeyGeneration: pk(x, y) =\n");
	printf("%s\n", mpz_get_str(NULL, 16, (publicKey->pk).x));
	printf("%s\n", mpz_get_str(NULL, 16, (publicKey->pk).y));
	printf("%d\n\n", (publicKey->pk).inf_id);

	printf("PSEC_KEM_KeyGeneration: sk =\n");
	printf("%s\n", mpz_get_str(NULL, 16, (privateKey->sk)));

	mpz_clear(p_minus_one);
	return TRUE;
}
