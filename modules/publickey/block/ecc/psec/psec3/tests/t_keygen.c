#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <gmp.h>
#include "ec_arith.h"
#include "psec3.h"
#include "utils.h"

#define GID    2
#define HID    2
#define HLEN   160
#define MLEN   128


void usage(char *program_name);

main(int argc, char **argv)
{
PSEC3_PUB_KEY    publicKey;
PSEC3_PRIV_KEY   privateKey;
EC_PARAM         E;
FILE *psec_param_fp;
FILE *pubKey_fp;
FILE *privKey_fp;
char *psec_param_file, *pubKey_file, *privKey_file;
long i;

	printf("PSEC-3 Key Generation Test (7/3/00)\n");
	if(argc == 4) {
		psec_param_file = argv[1];
		pubKey_file     = argv[2];
		privKey_file    = argv[3];
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

	EC_initPoint(&(publicKey.pk));
	mpz_init(privateKey.sk);
	mpz_init(E.a);
	mpz_init(E.b);
	mpz_init(E.q);
	mpz_init(E.p);
	EC_initPoint(&(E.P));

	/* obtain PSEC parameters from (FILE *) psec_param_fp */
	get_psec_param(&E, psec_param_fp);

	/* generate a key-pair */
	PSEC3_KeyGeneration(&E, privateKey.sk, &(publicKey.pk));

	publicKey.Gid = GID;
	publicKey.Hid = HID;
	publicKey.hLen = HLEN;
	publicKey.mLen = MLEN;

	/* write to pubKey_fp and privKey_fp */
	fprintf(pubKey_fp,"xpk = 0x%s\n", mpz_get_str(NULL, 16, publicKey.pk.x));
	fprintf(pubKey_fp,"ypk = 0x%s\n", mpz_get_str(NULL, 16, publicKey.pk.y));
	fprintf(pubKey_fp,"Gid = %lu\n", publicKey.Gid);
	fprintf(pubKey_fp,"Hid = %lu\n", publicKey.Hid);
	fprintf(pubKey_fp,"hLen = %lu\n", publicKey.hLen);
	fprintf(pubKey_fp,"mLen = %lu", publicKey.mLen);

	fprintf(privKey_fp,"sk = 0x%s", mpz_get_str(NULL, 16, privateKey.sk));

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

	exit(0);
}


/*
Display the usage
*/
void usage(char *program_name)
{
	printf("\nUsage : %s psec-param-file pubkey-file privkey-file\n",
	        program_name);
}
