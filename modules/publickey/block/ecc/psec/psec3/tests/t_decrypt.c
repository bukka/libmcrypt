/*
 t_decrypt.c - PSEC-3 decryption test

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - read elliptic curve points in octet strings from a file stream
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <gmp.h>
#include "ec_arith.h"
#include "psec3.h"
#include "utils.h"
#include "test_spec.h"

void usage(char *program_name);

main(int argc, char **argv)
{
PSEC3_PUB_KEY    publicKey;
PSEC3_PRIV_KEY   privateKey;
CIPHER_INFO      cipherInfo;
PSEC3_CIPHERTEXT ciphertext;
EC_PARAM         E;
FILE *pubKey_fp;
FILE *privKey_fp;
FILE *ciphertext_fp;
FILE *psec_param_fp;
BYTE *message;
char *ciphertext_file, *pubKey_file, *privKey_file, *psec_param_file;
long i;

	printf("PSEC-3 Decryption Test (7/00)\n");
	if(argc == 5) {
		ciphertext_file = argv[1];
		pubKey_file     = argv[2];
		privKey_file    = argv[3];
		psec_param_file = argv[4];
	} else {
		usage(argv[0]);
		exit(0);
	}

	ciphertext_fp = open_input(ciphertext_file);
	pubKey_fp     = open_input(pubKey_file);
	privKey_fp    = open_input(privKey_file);
	psec_param_fp = open_input(psec_param_file);
	if(ciphertext_fp == NULL || pubKey_fp == NULL || privKey_fp == NULL ||
	   psec_param_fp == NULL) {
		usage(argv[0]);
		exit(0);
	}

	EC_initPoint(&(publicKey.pk));
	mpz_init(privateKey.sk);
	mpz_init(E.a);
	mpz_init(E.b);
	mpz_init(E.q);
	mpz_init(E.p);
	EC_initPoint(&(E.P));
	EC_initPoint(&(ciphertext.C1));
	mpz_init(ciphertext.c1);

	get_psec_param(&E, psec_param_fp);
	get_pubKey(&publicKey, pubKey_fp);
	get_privKey(&privateKey, privKey_fp);

   /* construct symmetric-key cipher information */
   cipherInfo.algorithmID = T_CIPHER_INFO.algorithmID;
   cipherInfo.mode = T_CIPHER_INFO.mode;
   cipherInfo.direction = DIR_ENCRYPT;
   for(i=0; i<MAX_IV_SIZE; i++) cipherInfo.IV[i] = T_CIPHER_INFO.IV[i];
   for(i=0; i<MAX_ROUNDS; i++) cipherInfo.S[i] = T_CIPHER_INFO.S[i];
   cipherInfo.KLen = 128;

	/*
   printf("t_encrypt: cipherInfo {\n\t");
   printf("algorithmID =%d\n\t",cipherInfo.algorithmID);
   printf("mode = %d\n\t",cipherInfo.mode);
   printf("direction = %d\n\t",cipherInfo.direction);
   printf("KLen = %d\n\t",cipherInfo.KLen);
   printf("IV = ");
   for(i=0; i<MAX_IV_SIZE; i++) {
      if(!(i%8)) printf("\n");
      printf("0x%X ",cipherInfo.IV[i]);
   }
   printf("\n\t");
   printf("S = ");
   for(i=0; i<MAX_ROUNDS; i++) {
      if(!(i%8)) printf("\n");
      printf("0x%lX ",cipherInfo.S[i]);
   }
   printf("\n\n");
	*/

   message = (BYTE *) malloc (2+publicKey.mLen*2/8+1);
   ciphertext.C1.po = (BYTE *) malloc (1 + 2*E.qLen/8);
   ciphertext.c2 = (BYTE *) malloc (publicKey.mLen/8);
   ciphertext.c3 = (BYTE *) malloc (publicKey.hLen/8);

	/* get ciphertext */
	get_ciphertext(&ciphertext, &publicKey, &E, ciphertext_fp);
	ciphertext.cipherLen = publicKey.mLen/8;

	PSEC3_Decryption(&ciphertext, &cipherInfo, &publicKey, &privateKey, message, &E);

	printf("t_decrypt: message = \n%s\n\n", message);

	/* clean up */
	free(ciphertext.c2);
	free(ciphertext.c3);
	free(message);
	fclose(ciphertext_fp);
	fclose(pubKey_fp);
	fclose(privKey_fp);
	fclose(psec_param_fp);

	EC_clearPoint(&(publicKey.pk));
	mpz_clear(privateKey.sk);
	mpz_clear(E.a);
	mpz_clear(E.b);
	mpz_clear(E.q);
	mpz_clear(E.p);
	EC_clearPoint(&(E.P));
	EC_clearPoint(&(ciphertext.C1));
   free(ciphertext.C1.po);
	mpz_clear(ciphertext.c1);

	exit(0);
}


/*
 Display the usage
*/
void usage(char *program_name)
{
	printf("\nUsage : %s ciphertext-file pubkey-file privkey-file psec-param-file\n",
	        program_name);
}
