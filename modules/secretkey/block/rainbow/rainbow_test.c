
#include "rainbow.h"

#define ITERATIONS 1024

void blockPrint(char *buf, int length);
static void cipher_correct_test(void);
static void cipher_speed_test(void);


static const BYTE plainSrc[1024] = {0, };



void main (void)
{
	cipher_correct_test();
	cipher_speed_test();


}

void cipher_correct_test(void)
{
	keyInstance keys;
	cipherInstance ciph;
	BYTE ptext[1024], ctext[1024], keySrc[MAX_KEY_SIZE], inV[MAX_IV_SIZE];
	int i, textLen=1024*8, keySrcLen=16*8, status;


	for (i=0; i<1024; i++) {
		ptext[i] = 0;
		ctext[i] = 0;
	}
	for (i=0; i<MAX_KEY_SIZE; i++) keySrc[i] = 0;
	for (i=0; i<MAX_IV_SIZE; i++) inV[i] = 1; 

	status = makeKey(&keys, DIR_ENCRYPT, keySrcLen, (char *)keySrc);
	if (status != TRUE) {
		printf("Error Occured!__er_code=%d\n",status);
		exit(1);
	}
	/* ECB TEST start-- */
	status = cipherInit(&ciph, MODE_ECB, (char *)inV); 
	if (status != TRUE) {
		printf("Error Occured!__er_code=%d\n",status);
		exit(1);
	}
	status =blockEncrypt(&ciph, &keys, (BYTE *)ptext, textLen,(BYTE *)ctext);
	status =blockDecrypt(&ciph, &keys, (BYTE *)ctext, textLen,(BYTE *)ptext);
	if (strncmp(plainSrc,ptext,1024)==0) printf("----ECB : OK!----\n");
	else printf("----ECB : FAIL!-----\n");

	/* CBC TEST start--- */
	status = cipherInit(&ciph, MODE_CBC, (char *)inV); 
	if (status != TRUE) {
		printf("Error Occured!__er_code=%d\n",status);
		exit(1);
	}
	status =blockEncrypt(&ciph, &keys, (BYTE *)ptext, textLen,(BYTE *)ctext);
	status =blockDecrypt(&ciph, &keys, (BYTE *)ctext, textLen,(BYTE *)ptext);
	if (strncmp(plainSrc,ptext,1024)==0) printf("----CBC : OK!----\n");
	else printf("----CBC : FAIL!-----\n");

	/* CFB1 TEST start--- */
	status = cipherInit(&ciph, MODE_CFB1, (char *)inV); 
	if (status != TRUE) {
		printf("Error Occured!__er_code=%d\n",status);
		exit(1);
	}
	status =blockEncrypt(&ciph, &keys, (BYTE *)ptext, textLen,(BYTE *)ctext); 
	status =blockDecrypt(&ciph, &keys, (BYTE *)ctext, textLen,(BYTE *)ptext); 
	if (strncmp(plainSrc,ptext,1024)==0) printf("----CFB1 : OK!----\n");
	else printf("----CFB1 : FAIL!-----\n");
}

void blockPrint(char *buf, int length)
{
	int i;

	for (i=0; i<length; i++) {
		printf("%02x",buf[i]&0xff);
	}
	printf("\n");
}

static void cipher_speed_test(void)
{
	keyInstance keys;
	cipherInstance ciph;
	BYTE ptext[1024], ctext[1024], keySrc[MAX_KEY_SIZE], inV[MAX_IV_SIZE];
	int i, textLen=1024*8, keySrcLen=16*8, status;
	clock_t elapsed;
	double sec;

	for (i=0; i<1024; i++) {
		ptext[i] = 0;
		ctext[i] = 0;
	}
	for (i=0; i<MAX_KEY_SIZE; i++) keySrc[i] = 0;
	for (i=0; i<MAX_IV_SIZE; i++) inV[i] = 1; 

	status = makeKey(&keys, DIR_ENCRYPT, keySrcLen, (char *)keySrc);
	if (status != TRUE) {
		printf("Error Occured!__er_code=%d\n",status);
		exit(1);
	}

	status = cipherInit(&ciph, MODE_ECB, (char *)inV); 
	if (status != TRUE) {
		printf("Error Occured!__er_code=%d\n",status);
		exit(1);
	}
	elapsed = -clock();
	for (i=0; i<ITERATIONS; i++) {
		status =blockEncrypt(&ciph, &keys, (BYTE *)ptext, textLen,(BYTE *)ctext);
		strncpy (ctext, ptext, 1024);
	}
	elapsed += clock ();
	sec = elapsed ? (double) elapsed / CLOCKS_PER_SEC : 1.0;
	printf("****ECB_speed.... ");
	printf (" %.4f sec(1Mbytes), %.4f Mbytes/sec.\n",
		sec, 1./sec);

	status = cipherInit(&ciph, MODE_CBC, (char *)inV); 
	if (status != TRUE) {
		printf("Error Occured!__er_code=%d\n",status);
		exit(1);
	}
	elapsed = -clock();
	for (i=0; i<ITERATIONS; i++) {
		status =blockEncrypt(&ciph, &keys, (BYTE *)ptext, textLen,(BYTE *)ctext);
		strncpy (ctext, ptext, 1024);
	}
	elapsed += clock ();
	sec = elapsed ? (double) elapsed / CLOCKS_PER_SEC : 1.0;
	printf("****CBC_speed.... ");
	printf (" %.4f sec(1Mbytes), %.4f Mbytes/sec.\n",
		sec, 1./sec);
}

