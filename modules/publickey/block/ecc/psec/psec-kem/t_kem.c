/*
 t_kem.c - PSEC-KEM key encapsulation test

 Copyright NTT MCL, 2000 & 2001.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 This file is a modification of the t_encrypt.c from PSEC-2 encryption test.
 Modifications made in September 2001 by S.O.

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
EC_PARAM         E;
PSEC_KEM_KEY_ENCAPSULATION keyEncapsulation;
PSEC_KEM_KEY_MATERIAL keyMaterial;
FILE *pubKey_fp, *psec_param_fp, *out_fp;
s8 *pubKey_file, *psec_param_file, *out_file, *rand_file;
u32 oLen;

	printf("PSEC-KEM Key Encapsulation Test (7/6/00)\n");
	if(argc == 5) {
		pubKey_file     = argv[1];
		psec_param_file = argv[2];
		out_file        = argv[3];
		rand_file        = argv[4];
	} else {
		usage(argv[0]);
		exit(0);
	}

	pubKey_fp     = open_input(pubKey_file);
	psec_param_fp = open_input(psec_param_file);
	out_fp        = open_output(out_file);
	if(pubKey_fp == NULL || out_fp == NULL ||
	   psec_param_fp == NULL ) {
		usage(argv[0]);
		exit(0);
	}

	/* Initialize PRNG */
	global_prng = InitGlobalPRNG (rand_file);

	/* initialize publicKey */
	EC_initPoint(&(publicKey.pk));

	/* initialize E */
	mpz_init(E.a);
	mpz_init(E.b);
	mpz_init(E.q);
	mpz_init(E.p);
	EC_initPoint(&(E.P));

	/* obtain PSEC_KEM parameters from (FILE *) psec_param_fp */
	get_psec_param(&E, psec_param_fp);

	/* obtain public key information from (FILE *) pubKey_fp */
	get_pubKey(&publicKey, pubKey_fp);

	/* prepare keyEncapsulation storage */
	oLen = (u32)ceil(E.qLen/8.0);
	if (FORMAT == COMPRESSED)
		keyEncapsulation.C0oLen = 1 + oLen + (u32)ceil(publicKey.hLen/8.0);
	else
		keyEncapsulation.C0oLen = 1 + 2*oLen + (u32)ceil(publicKey.hLen/8.0);
	keyEncapsulation.C0 = (u8 *) malloc (keyEncapsulation.C0oLen);
	keyMaterial.KoLen = (u32)ceil(publicKey.outputKeyLen/8.0);
	keyMaterial.K_raw = (u8 *) malloc (keyMaterial.KoLen);

	/* perform key encapsulation */
	PSEC_KEM_KEM(&publicKey, &keyEncapsulation, &keyMaterial, &E, FORMAT);

	/* writing keyEncapsulation */
	fwrite(keyEncapsulation.C0, keyEncapsulation.C0oLen, 1, out_fp);

	/* clean up */
	memset(keyMaterial.K_raw, 0, keyMaterial.KoLen);
	memset(keyEncapsulation.C0, 0, keyEncapsulation.C0oLen);

	free(keyMaterial.K_raw);
	free(keyEncapsulation.C0);

	fclose(pubKey_fp);
	fclose(psec_param_fp);
	fclose(out_fp);

	EC_clearPoint(&(publicKey.pk));
	mpz_clear(E.a);
	mpz_clear(E.b);
	mpz_clear(E.q);
	mpz_clear(E.p);
	EC_clearPoint(&(E.P));

	/* Terminate PRNG */
	FinishGlobalPRNG(global_prng);

	exit(0);
}


/*
 Display the usage
*/
void usage(char *program_name)
{
	printf("\nUsage : %s pubkey-file psec-param-file out-file rand_file \n",
	        program_name);
}
