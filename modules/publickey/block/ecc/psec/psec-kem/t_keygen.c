/*
 t_keygen.c - PSEC-KEM key generation test

 Copyright NTT MCL, 2000 & 2001.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.

 10/24/2000 - Removed mLen from publicKey.  -- S.O.

 10/25/2000 - Enabled to input random seed from file by T.Kobayashi -- H.O.

 9/19/2001 - publicKey has hLen and outputKeyLen fields -- S.O.
 9/19/2001 - PRNG added -- S.O.

 9/25/2001 - writing inf_id for publicKey -- S.O.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <gmp.h>
#include "nessie.h"
#include "ec_arith.h"
#include "psec_kem.h"
#include "utils.h"

#define SEEDLEN 160

void usage(char *program_name);

int main(int argc, char **argv)
{
PSEC_KEM_PUB_KEY publicKey;
PSEC_KEM_PRIV_KEY privateKey;
EC_PARAM E;
FILE *psec_param_fp, *pubKey_fp, *privKey_fp;
s8 *psec_param_file, *pubKey_file, *privKey_file, *random_file;
u32 seedLen = SEEDLEN;

	printf("PSEC-KEM Key Generation Test (10/27/2000)\n");
	if(argc == 5) {
		psec_param_file = argv[1];
		pubKey_file     = argv[2];
		privKey_file    = argv[3];
		random_file    = argv[4];
	} else {
		usage(argv[0]);
		exit(0);
	}

	psec_param_fp = open_input(psec_param_file);
	pubKey_fp  = open_output(pubKey_file);
	privKey_fp = open_output(privKey_file);
	if(psec_param_fp == NULL || pubKey_fp == NULL || privKey_fp == NULL) {
		usage(argv[0]);
		exit(0);
	}

	/* initialize PRNG */
	global_prng = InitGlobalPRNG(random_file);

	/* initialize keys */
	EC_initPoint(&(publicKey.pk));
	mpz_init(privateKey.sk);

	/* initialize E */
	mpz_init(E.a);
	mpz_init(E.b);
	mpz_init(E.q);
	mpz_init(E.p);
	EC_initPoint(&(E.P));

	/* obtain PSEC parameters from (FILE *) psec_param_fp */
	get_psec_param(&E, psec_param_fp);

	/* generate a key-pair */
	PSEC_KEM_KeyGeneration(seedLen, &E, &privateKey, &publicKey);

	/* write to pubKey_fp and privKey_fp */
	fprintf(pubKey_fp, "xpk = 0x%s\n", mpz_get_str(NULL, 16, publicKey.pk.x));
	fprintf(pubKey_fp, "ypk = 0x%s\n", mpz_get_str(NULL, 16, publicKey.pk.y));
	fprintf(pubKey_fp, "infid = %u\n", (publicKey.pk).inf_id);
	fprintf(pubKey_fp, "Hid = %u\n", publicKey.Hid);
	fprintf(pubKey_fp, "SEid = %u\n", publicKey.SEid);
	fprintf(pubKey_fp, "hLen = %u\n", publicKey.hLen);
	fprintf(pubKey_fp, "outputKeyLen = %u\n", publicKey.outputKeyLen);

	fprintf(privKey_fp,"sk = 0x%s\n", mpz_get_str(NULL, 16, privateKey.sk));

	/* clean up */
	fclose(psec_param_fp);
	fclose(pubKey_fp);
	fclose(privKey_fp);

	EC_clearPoint(&(publicKey.pk));
	mpz_clear(privateKey.sk);
	mpz_clear(E.a);
	mpz_clear(E.b);
	mpz_clear(E.q);
	mpz_clear(E.p);
	EC_clearPoint(&(E.P));

	/* Terminate PRNG */
	FinishGlobalPRNG (global_prng);

        exit(0);
}


/*
Display the usage
*/
void usage(char *program_name)
{
	printf("\nUsage : %s psec-param-file pubkey-file privkey-file random_file\n",
	        program_name);
}
