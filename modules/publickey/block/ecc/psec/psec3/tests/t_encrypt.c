/*
 t_encrypt.c - PSEC-3 encryption test

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - write elliptic curve points in octet strings to a file stream
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
EC_PARAM         E;
CIPHER_INFO      cipherInfo;
PSEC3_CIPHERTEXT ciphertext;
FILE *message_fp;
FILE *pubKey_fp;
FILE *psec_param_fp;
FILE *out_fp;
char *message_file, *pubKey_file, *psec_param_file, *out_file;
BYTE *message;
long i;

	printf("PSEC-3 Encryption Test (7/00)\n");
	if(argc == 5) {
		message_file    = argv[1];
		pubKey_file     = argv[2];
		psec_param_file = argv[3];
		out_file        = argv[4];
	} else {
		usage(argv[0]);
		exit(0);
	}

	message_fp    = open_input(message_file);
	pubKey_fp     = open_input(pubKey_file);
	psec_param_fp = open_input(psec_param_file);
	out_fp        = open_output(out_file);
	if(message_fp == NULL || pubKey_fp == NULL || out_fp == NULL ||
	   psec_param_fp == NULL) {
		usage(argv[0]);
		exit(0);
	}

	EC_initPoint(&(publicKey.pk));
	mpz_init(E.a);
	mpz_init(E.b);
	mpz_init(E.q);
	mpz_init(E.p);
	EC_initPoint(&(E.P));
	EC_initPoint(&(ciphertext.C1));
	mpz_init(ciphertext.c1);

	/* obtain PSEC3 parameters from (FILE *) psec_param_fp */
	get_psec_param(&E, psec_param_fp);

	/* obtain public key information from (FILE *) pubKey_fp */
	get_pubKey(&publicKey, pubKey_fp);

	/*
	printf("t_encrypt: publicKey {\n\t");
	printf("Gid = %hd, Hid = %hd, hLen = %lu, mLen = %lu\n}\n",
	        publicKey.Gid, publicKey.Hid, publicKey.hLen, publicKey.mLen);
	*/

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
	printf("KLen = %lu\n\t",cipherInfo.KLen);
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

	message =  (BYTE *) malloc (2+publicKey.mLen*2/8+1);

   (ciphertext.C1).po = (unsigned char *) malloc (1 + 2*E.qLen/8);

	ciphertext.c2 = (BYTE *) malloc (publicKey.mLen/8);
	ciphertext.c3 = (BYTE *) malloc (publicKey.hLen/8);

	fread (message, 2+publicKey.mLen*2/8, 1, message_fp);
	message[2+publicKey.mLen*2/8] = '\0';
	/* printf("t_encrypt: message = %s\n\n", message); */

	PSEC3_Encryption(message, &cipherInfo, &publicKey, &ciphertext, &E);

	/*
	fprintf(out_fp,"xC1 = 0x%s\n", mpz_get_str(NULL, 16, ciphertext.C1.x));
	fprintf(out_fp,"yC1 = 0x%s\n", mpz_get_str(NULL, 16, ciphertext.C1.y));
	fprintf(out_fp,"inf_idC1 = %d\n", ciphertext.C1.inf_id);
	*/
   /* writing P1363 E.2.3.2 complaint format */
   for(i=0; i<1+2*E.qLen/8; i++)
      fputc(ciphertext.C1.po[i], out_fp);

	fprintf(out_fp,"c1 = 0x%s\n", mpz_get_str(NULL, 16, ciphertext.c1));
	for(i=0; i<ciphertext.cipherLen; i++)
		fputc(ciphertext.c2[i], out_fp);
	for(i=0; i<publicKey.hLen/8; i++)
		fputc(ciphertext.c3[i], out_fp);

	/* clean up */
	free(ciphertext.c2);
	free(ciphertext.c3);
	free(message);
	fclose(message_fp);
	fclose(pubKey_fp);
	fclose(psec_param_fp);
	fclose(out_fp);

	EC_clearPoint(&(publicKey.pk));
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
	printf("\nUsage : %s message-file pubkey-file psec-param-file out-file\n",
	        program_name);
}
