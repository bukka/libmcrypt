/*
 decrypt.c - PSEC-3 decryption function

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - invoke function os2ec for converting octet string representation
           of an elliptic curve point to x-y coordinate
 8/29/00 - use P1363 E.2.3.2 complaint octet string representation for
           an EC point during hashing
 10/6/2000 - Fixed a little bug in the check of RLen (and changed from 
           bytes to bits) -- S.O.
*/

#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "ec_arith.h"
#include "psec3.h"
#include "hash.h"
#include "utils.h"

void BulkDecrypt(BYTE *message, CIPHER_INFO *cipherInfo, BYTE *K, WORD KLen,
	              PSEC3_CIPHERTEXT *ciphertext);

/*
 PSEC-3 decryption

 Return: TRUE if succeed; otherwise FALSE
*/
BYTE PSEC3_Decryption (
   PSEC3_CIPHERTEXT *ciphertext,
   CIPHER_INFO      *cipherInfo,
   PSEC3_PUB_KEY    *publicKey,
   PSEC3_PRIV_KEY   *privateKey,
   BYTE             *message,
   EC_PARAM         *E
)
{
mpz_t R;
EC_POINT T;
BYTE *R_raw, *K_raw, *m_raw, *H_in, *tmp_ptr, *H_out;
WORD H_in_len, RLen; /* RLen in bits */
BYTE compare_result;
long i;

   /* convert octet string format to EC point format (P1363 E.2.3.2) */
   os2ec(&(ciphertext->C1), (ciphertext->C1).po, E);

	/*
	printf("PSEC3_Decryption: C1 =\n");
	printf("%s\n%s\n%d\n\n", mpz_get_str(NULL, 16, (ciphertext->C1).x),
	       mpz_get_str(NULL, 16, (ciphertext->C1).y),
	       (ciphertext->C1).inf_id);
	printf("PSEC3_Decryption: c1 =\n%s\n\n",
	       mpz_get_str(NULL, 16, ciphertext->c1));
	printf("PSEC3_Decryption: c2 =\n");
	for(i=0; i<ciphertext->cipherLen; i++)
		printf("%02x ", ciphertext->c2[i]);
	printf("\n\n");
	printf("PSEC3_Decryption: c3 =\n");
	for(i=0; i<publicKey->hLen/8; i++)
		printf("%02x ", ciphertext->c3[i]);
	printf("\n\n");
	*/

	mpz_init(R);
	m_raw = (BYTE *) malloc (publicKey->mLen/8);
	R_raw = (BYTE *) malloc (E->qLen/8);
	K_raw = (BYTE *) malloc (cipherInfo->KLen/8);
	H_out = (BYTE *) malloc (publicKey->hLen/8);

	memset(m_raw, 0, publicKey->mLen/8);

	/* compute T = sk * C1 */
	EC_initPoint(&T);
	EC_Mult(&T, privateKey->sk, &(ciphertext->C1), E);

	/* compute R = c1 \xor x_T */
	mpz_xor(R, ciphertext->c1, T.x);
	RLen = mpz_sizeinbase(R, 2);
	/* printf("PSEC3_Decryption: R =\n%s\n\n", mpz_get_str(NULL, 16, R)); */

	/* compute K_raw := G(R_raw) */
	WORD2BYTE(R_raw, R->_mp_d, ABS(R->_mp_size));
	indexedSHA( K_raw, cipherInfo->KLen/8, R_raw, E->qLen/8);

	/*
	printf("PSEC3_Decryption: K_raw =\n\t");
	for(i=0; i< cipherInfo->KLen/8; i++)
		printf("%02x ", K_raw[i]);
	printf("\n\n");
	*/

	/* compute (BYTE *) m_raw */
	BulkDecrypt(m_raw, cipherInfo, K_raw, cipherInfo->KLen, ciphertext);

	/*
	printf("PSEC3_Decryption: m_raw =\n");
	for(i=0; i< publicKey->mLen/8; i++)
		printf("%02x ", m_raw[i]);
	printf("\n\n");
	*/

	/* check c3 */
	H_in_len =(E->qLen*4 + ciphertext->cipherLen*8 + publicKey->mLen)/8 + 1;
	H_in   = (BYTE *) malloc (H_in_len);
   assignBYTE(H_in, (ciphertext->C1).po, 1+2*E->qLen/8);
   tmp_ptr = H_in + 1 + 2*E->qLen/8;

	/*
	WORD2BYTE(H_in, (ciphertext->C1).x->_mp_d, ABS((ciphertext->C1).x->_mp_size));
	tmp_ptr = H_in + ABS((ciphertext->C1).x->_mp_size)*4;
	WORD2BYTE(tmp_ptr, (ciphertext->C1).y->_mp_d, ABS((ciphertext->C1).y->_mp_size));
	tmp_ptr += ABS((ciphertext->C1).y->_mp_size)*4;
	tmp_ptr++[0] = (ciphertext->C1).inf_id;
	*/

	WORD2BYTE(tmp_ptr, (ciphertext->c1)->_mp_d, ABS((ciphertext->c1)->_mp_size));
	tmp_ptr += ABS((ciphertext->c1)->_mp_size)*4;
	assignBYTE(tmp_ptr, ciphertext->c2, ciphertext->cipherLen);
	tmp_ptr += ciphertext->cipherLen;
	assignBYTE(tmp_ptr, R_raw, E->qLen/8);
	tmp_ptr += E->qLen/8;
	assignBYTE(tmp_ptr, m_raw, publicKey->mLen/8);
	
	indexedSHA( H_out, publicKey->hLen/8, H_in, H_in_len);

	/*
	printf("PSEC3_Decryption: H_out =\n");
	for(i=0; i<publicKey->hLen/8; i++)
		printf("%02x ", H_out[i]);
	printf("\n\n");
	*/

	/* compare H_out with ciphertext->c3 */
   compare_result = TRUE;
   for(i=0; i<publicKey->hLen/8; i++)
      if(H_out[i] != ciphertext->c3[i]) compare_result = FALSE;
  
   if(compare_result == FALSE || RLen > E->qLen) {
      printf("PSEC3_Decryption:\n\tH_out and ciphertext->c3 are inconsistent");
      printf("\n\tor the length of session key (%lu)", RLen);
      printf(" is not equal to %lu bits\n",
             E->qLen);
		sprintf(message,"");
   } else {
		sprintf(message,"0x");
      tmp_ptr = message+2;
      i = 0;
      while(m_raw[i] == 0 && i != (publicKey->mLen/8-1)) i++;
      while (i<publicKey->mLen/8) {           
         sprintf(tmp_ptr,"%02x",m_raw[i]);
         tmp_ptr += 2; 
         i++;
      }  
	}

	/* clean up */
	mpz_clear(R);

	memset(m_raw, 0, publicKey->mLen/8);
	memset(R_raw, 0, E->qLen/8);
	memset(K_raw, 0, cipherInfo->KLen/8);
	memset(H_out, 0, publicKey->hLen/8);
	memset(H_in, 0, H_in_len);
	free(m_raw);
	free(R_raw);
	free(K_raw);
	free(H_out);
	free(H_in);

	H_in_len = 0;
	RLen = 0;
	i = 0;

	return TRUE;
}


void BulkDecrypt(BYTE *message, CIPHER_INFO *cipherInfo, BYTE *K, WORD KLen,
	              PSEC3_CIPHERTEXT *ciphertext)
{
   if(cipherInfo->algorithmID == ENCRYPT_ALG_XOR) {
      ciphertext->cipherLen=Vernam(K, KLen, ciphertext->c2, message);
   }
}
