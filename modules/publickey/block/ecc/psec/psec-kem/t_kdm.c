/*
 t_kdm.c - PSEC-KEM key decapsulation test

 Copyright NTT MCL, 2000 & 2001.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - write elliptic curve points in octet strings to a file stream

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.

 10/24/2000 - Modified code to include mLen as part of cipherInfo rather than
              publicKey.
            - Added MLEN (128).  -- S.O.

 10/27/2000 - Added SEid to PSEC2_PUB_KEY,
              Removed algorithmID from CIPHER_INFO -- H.O.

 This code is a modification of the PSEC2 t_decrypt.c decryption test.
 Modifications made by S.O. in September 2001.

 9/25/2001 - Added lines to display success or failure of decapsulation -- S.O.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <gmp.h>
#include <math.h>
#include "nessie.h"
#include "ec_arith.h"
#include "psec_kem.h"
#include "utils.h"

#define FORMAT COMPRESSED

void usage(char *program_name);

main(int argc, char **argv)
{
PSEC_KEM_PUB_KEY    publicKey;
PSEC_KEM_PRIV_KEY   privateKey;
PSEC_KEM_KEY_ENCAPSULATION keyEncapsulation;
PSEC_KEM_KEY_MATERIAL keyMaterial;
EC_PARAM         E;
FILE *pubKey_fp;
FILE *privKey_fp;
FILE *keyEncapsulation_fp;
FILE *psec_param_fp;
s8 *keyEncapsulation_file, *pubKey_file, *privKey_file, *psec_param_file, *rand_file;
s32 i;
u32 coLen, oLen;

	printf("PSEC-KEM Key decapsulation Test (7/6/00)\n");
	if(argc == 6) {
		keyEncapsulation_file = argv[1];
		pubKey_file     = argv[2];
		privKey_file    = argv[3];
		psec_param_file = argv[4];
		rand_file 	= argv[5];
	} else {
		usage(argv[0]);
		exit(0);
	}

	keyEncapsulation_fp = open_input(keyEncapsulation_file);
	pubKey_fp     = open_input(pubKey_file);
	privKey_fp    = open_input(privKey_file);
	psec_param_fp = open_input(psec_param_file);
	if(keyEncapsulation_fp == NULL || pubKey_fp == NULL || privKey_fp == NULL ||
	   psec_param_fp == NULL) {
		usage(argv[0]);
		exit(0);
	}

	/* Initialize PRNG */
	global_prng = InitGlobalPRNG(rand_file);

	EC_initPoint(&(publicKey.pk));
	mpz_init(privateKey.sk);
	mpz_init(E.a);
	mpz_init(E.b);
	mpz_init(E.q);
	mpz_init(E.p);
	EC_initPoint(&(E.P));

	/* Read in EC parameters and public and private keys */
	get_psec_param(&E, psec_param_fp);
	get_pubKey(&publicKey, pubKey_fp);
	get_privKey(&privateKey, privKey_fp);

	/* (quite inefficient way to get message length. Optimize) */
	fseek (keyEncapsulation_fp, 0, SEEK_END);
	coLen = (u32) ftell(keyEncapsulation_fp); 
	rewind (keyEncapsulation_fp);

	/* length of each part of the keyEncapsulation & of the message */
	oLen = (u32)ceil(E.qLen/8.0);
	if (FORMAT == COMPRESSED)
		keyEncapsulation.C0oLen = 1 + oLen + (u32)ceil(publicKey.hLen/8.0);
	else
		keyEncapsulation.C0oLen = 1 + 2*oLen + (u32)ceil(publicKey.hLen/8.0);

	/* prepare storage for keyEncapsulation */
	if ( ((keyEncapsulation.C0 = (u8 *) malloc (keyEncapsulation.C0oLen)) == NULL))
	{
	  fprintf(stderr, "error: out of memory.\n");
          exit (1);
	}

	/* get keyEncapsulation C0 */
	if ((fread (keyEncapsulation.C0, keyEncapsulation.C0oLen, 1, keyEncapsulation_fp) != 1))
	{
	fprintf(stderr, "error: unable to read %d bytes from file '%s'.\n",
	        keyEncapsulation.C0oLen, keyEncapsulation_file);
          exit (1);
	}

	printf("\nKey encapsulation read from file '%s'.\n", keyEncapsulation_file);

	/* prepare storage for keyMaterial */
	keyMaterial.KoLen = (u32)ceil(publicKey.outputKeyLen / 8.0);
	keyMaterial.K_raw = (u8 *) malloc(keyMaterial.KoLen);

	/* decapsulate key */
	if (PSEC_KEM_KDM(&keyEncapsulation, &privateKey, &publicKey, &keyMaterial, &E, FORMAT) == FALSE)
		printf("decapsulation failed\n");
	else
		printf("decapsulation succeeded\n");

	/* clean up */
	fclose(keyEncapsulation_fp);
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

	memset(keyEncapsulation.C0, 0, keyEncapsulation.C0oLen);
	memset(keyMaterial.K_raw, 0, keyMaterial.KoLen);

	free(keyEncapsulation.C0);
	free(keyMaterial.K_raw);

	/* Terminate PRNG */
	FinishGlobalPRNG(global_prng);

	exit(0);
}


/*
 Display the usage
*/
void usage(char *program_name)
{
	printf("\nUsage : %s keyEncapsulation-file pubkey-file privkey-file psec-param-file rand_file\n",
	        program_name);
}
