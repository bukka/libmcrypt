/*
 encrypt.c - PSEC-3 encryption function

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - invoke function ec2os for converting elliptic curve points to
           octet strings
 8/29/00 - use P1363 E.2.3.2 complaint octet string representation for
           an EC point during hashing
*/

#include <stdio.h>
#include <gmp.h>
#include "ec_arith.h"
#include "psec3.h"
#include "hash.h"
#include "utils.h"
#include "random.h"

void BulkEncrypt(BYTE *message, CIPHER_INFO *cipherInfo, BYTE *K, WORD KLen,
	              PSEC3_CIPHERTEXT *ciphertext);

/*
 PSEC-3 encryption

 Return: TRUE if succeed; otherwise FALSE
*/
BYTE PSEC3_Encryption (
   BYTE             *message,        /* plaintext */
   CIPHER_INFO      *cipherInfo,
   PSEC3_PUB_KEY    *publicKey,      /* PSEC3 public key */
   PSEC3_CIPHERTEXT *ciphertext,     /* returned ciphertext */
   EC_PARAM         *E
)
{
mpz_t m, R, r;
EC_POINT T;
BYTE *m_raw, *R_raw, *r_raw, *K_raw, *H_in, *tmp_pr;
WORD H_in_len;
RANDOM_STRUCT randomStruct;
unsigned int bytesNeeded;
static unsigned char seedByte = 0;
long i;

	mpz_init(m);
	mpz_init(R);
	mpz_init(r);
	m_raw = (BYTE *) malloc (publicKey->mLen/8);
	R_raw = (BYTE *) malloc (E->qLen/8);
	r_raw = (BYTE *) malloc (E->pLen/8);
	K_raw = (BYTE *) malloc (cipherInfo->KLen/8);

	memset(m_raw, 0, publicKey->mLen/8);

	/* convert (BYTE *) message to raw format */
	mpz_set_str(m, message, 0);
	WORD2BYTE(m_raw+(publicKey->mLen/8-ABS(m->_mp_size)*4), m->_mp_d,
	          ABS(m->_mp_size));
	/*
	printf("PSEC3_encryption: m_raw =\n");
	for(i=0; i< publicKey->mLen/8; i++)
		printf("%02x ", m_raw[i]);
	printf("\n\n");
	*/

	/* initialize random number generator */
	RandomInit(&randomStruct);

	/* initialize with all zero seed bytes for testing purpose only */
	while (1) {
		GetRandomBytesNeeded (&bytesNeeded, &randomStruct);
		if (bytesNeeded == 0) break;
		RandomUpdate (&randomStruct, &seedByte, 1);
	}

	/* generate R */
	GenerateBytes(R_raw, E->qLen/8, &randomStruct);

	/*
	printf("PSEC3_Encryption: R_raw =\n");
	for(i=0; i< E->qLen/8; i++)
		printf("%02x ", R_raw[i]);
	printf("\n\n");
	*/

	BYTE2WORD(R, R_raw, E->qLen/8);
	printf("R = 0x%s\n", mpz_get_str(NULL, 16, R));

	/* choose r \in_{R} Z_p^* */
	do {
		GenerateBytes(r_raw, E->pLen/8, &randomStruct);
		BYTE2WORD(r, r_raw, E->qLen/8);
		mpz_mod(r, r, E->p);
	} while (mpz_cmp_ui(r, 0) == 0);
	printf("r = 0x%s\n", mpz_get_str(NULL, 16, r));

	/* compute T = r * publicKey->pk */
	EC_initPoint (&T);
	EC_Mult(&T, r, &(publicKey->pk), E);

	/*
	printf("PSEC3_Encryption: T =\n");
	printf("%s\n%s\n%d\n\n", mpz_get_str(NULL, 16, T.x),
	       mpz_get_str(NULL, 16, T.y), T.inf_id);
	*/

	/* compute C1 = r * E->P */
	EC_initPoint (&(ciphertext->C1));
	EC_Mult(&(ciphertext->C1), r, &(E->P), E);

	/*
	printf("PSEC3_Encryption: ciphertext->C1 =\n");
	printf("%s\n%s\n%d\n\n", mpz_get_str(NULL, 16, (ciphertext->C1).x),
	       mpz_get_str(NULL, 16, (ciphertext->C1).y), (ciphertext->C1).inf_id);
	*/

   /* convert C1's EC point to an octet string according to P1363 E.2.3.2 */
   ec2os((ciphertext->C1).po, &(ciphertext->C1), E);
   
	/*
   printf("PSEC3_Encryption: C1 =\n");
   for(i=0; i<(1 + 2*E->qLen/8); i++)
      printf("%02x ", (ciphertext->C1).po[i]);
   printf("\n\n");
	*/
	
	/* compute c1 = x_T \xor R */
	mpz_init(ciphertext->c1);
	mpz_xor(ciphertext->c1, T.x, R);

	/*
	printf("PSEC3_Encryption: ciphertext->c1 =\n");
	printf("%s\n\n", mpz_get_str(NULL, 16, ciphertext->c1));
	*/

	/* compute K_raw := G(R_raw) */
	indexedSHA( K_raw, cipherInfo->KLen/8, R_raw, E->qLen/8);

	/*
	printf("PSEC3_Encryption: K_raw =\n");
	for(i=0; i< cipherInfo->KLen/8; i++)
		printf("%02x ", K_raw[i]);
	printf("\n\n");
	*/

	/* compute c2 */
	BulkEncrypt(m_raw, cipherInfo, K_raw, cipherInfo->KLen, ciphertext);

	/*
	printf("PSEC3_Encryption: ciphertext->c2 =\n");
	for(i=0; i< ciphertext->cipherLen; i++)
		printf("%02x ", ciphertext->c2[i]);
	printf("\n\n");
	*/

	/* compute c3 */
	H_in_len =(E->qLen*4 + ciphertext->cipherLen*8 + publicKey->mLen)/8 + 1;
	H_in   = (BYTE *) malloc (H_in_len);
	assignBYTE(H_in, (ciphertext->C1).po, 1+2*E->qLen/8);
	tmp_pr = H_in + 1 + 2*E->qLen/8;

	/*
	WORD2BYTE(H_in, (ciphertext->C1).x->_mp_d, ABS((ciphertext->C1).x->_mp_size));
	tmp_pr = H_in + ABS((ciphertext->C1).x->_mp_size)*4;
	WORD2BYTE(tmp_pr, (ciphertext->C1).y->_mp_d, ABS((ciphertext->C1).y->_mp_size));
	tmp_pr += ABS((ciphertext->C1).y->_mp_size)*4;
	tmp_pr++[0] = (ciphertext->C1).inf_id;
	*/

	WORD2BYTE(tmp_pr, (ciphertext->c1)->_mp_d, ABS((ciphertext->c1)->_mp_size));
	tmp_pr += ABS((ciphertext->c1)->_mp_size)*4;
	assignBYTE(tmp_pr, ciphertext->c2, ciphertext->cipherLen);
	tmp_pr += ciphertext->cipherLen;
	assignBYTE(tmp_pr, R_raw, E->qLen/8);
	tmp_pr += E->qLen/8;
	assignBYTE(tmp_pr, m_raw, publicKey->mLen/8);
	
	/*
	printf("PSEC3_Encryption: H_in =\n");
	for(i=0; i<H_in_len; i++)
		printf("%02x ", H_in[i]);
	printf("\n\n");
	*/

	indexedSHA( ciphertext->c3, publicKey->hLen/8, H_in, H_in_len);

	/*
	printf("PSEC3_Encryption: ciphertext->c3 =\n");
	for(i=0; i<publicKey->hLen/8; i++)
		printf("%02x ", ciphertext->c3[i]);
	printf("\n\n");
	*/

	/* clean up */
	mpz_clear(m);
	mpz_clear(R);
	mpz_clear(r);

	memset(m_raw, 0, publicKey->mLen/8);
	memset(R_raw, 0, E->qLen/8);
	memset(r_raw, 0, E->pLen/8);
	memset(K_raw, 0, cipherInfo->KLen/8);
	memset(H_in, 0, H_in_len);
	free(m_raw);
	free(R_raw);
	free(r_raw);
	free(K_raw);
	free(H_in);

	H_in_len = 0;

	return TRUE;
}


void BulkEncrypt(BYTE *message, CIPHER_INFO *cipherInfo, BYTE *K, WORD KLen,
	              PSEC3_CIPHERTEXT *ciphertext)
{
   if(cipherInfo->algorithmID == ENCRYPT_ALG_XOR) {
      ciphertext->cipherLen = Vernam(K, KLen, message,
		                               ciphertext->c2);
   }
}
