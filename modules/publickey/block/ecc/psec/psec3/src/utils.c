/*
 utils.c

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <gmp.h>
#include "ec_arith.h"
#include "psec3.h"
#include "utils.h"

/*
 Read PSEC parameters from a file

 Return 1 if succeed, otherwise 0
*/
int get_psec_param(EC_PARAM *E, FILE *fp)
{
char one_line[2*MAX_FIELD_LEN/8+15];
char field_id[10];
char field_body[2*MAX_FIELD_LEN/8+2];
char **endptr = NULL;
unsigned char sign;

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read q: %s\n", strerror(errno));
		return 0;
	}

	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str(E->q, field_body, 0);

	/*
	printf("get_psec_param: E->q =\n\n");
	printf("%s\n", mpz_get_str(NULL, 16, E->q));
	*/

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read a: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str(E->a, field_body, 0);

	/*
	printf("get_psec_param: E->a =\n\n");
	printf("%s\n", mpz_get_str(NULL, 16, E->a));
	*/

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read b: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str(E->b, field_body, 0);

	/*
	printf("get_psec_param: E->b =\n\n");
	printf("%s\n", mpz_get_str(NULL, 16, E->b));
	*/

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read p: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str(E->p, field_body, 0);

	/*
	printf("get_psec_param: E->p =\n\n");
	printf("%s\n", mpz_get_str(NULL, 16, E->p));
	*/

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read x_P: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str((E->P).x, field_body, 0);

	/*
	printf("get_psec_param: (E->P).x =\n\n");
	printf("%s\n", mpz_get_str(NULL, 16, (E->P).x));
	*/

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read y_P: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str((E->P).y, field_body, 0);

	/*
	printf("get_psec_param: (E->P).y =\n\n");
	printf("%s\n", mpz_get_str(NULL, 16, (E->P).y));
	*/

	E->P.inf_id = 0;

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read qLen: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	E->qLen = strtoul(field_body, endptr, 10);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read pLen: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	E->pLen = strtoul(field_body, endptr, 10);

	return 1;
}


/*
 Read public key info from a file

 Return 1 if succeed, otherwise 0
*/
int get_pubKey(PSEC3_PUB_KEY *publicKey, FILE *fp)
{
char one_line[2*MAX_FIELD_LEN/8+15];
char field_id[10];
char field_body[2*MAX_FIELD_LEN/8+2];
char **endptr = NULL;
unsigned char sign;

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read x_pk: %s\n", strerror(errno));
		return 0;
	}

	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str((publicKey->pk).x, field_body, 0);

	/*
	printf("get_pubKey: (publicKey->pk).x =\n\t");
	printf("%s\n", mpz_get_str(NULL, 16, (publicKey->pk).x));
	*/

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read y_pk: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str((publicKey->pk).y, field_body, 0);

	/*
	printf("get_pubKey: (publicKey->pk).y =\n\t");
	printf("%s\n", mpz_get_str(NULL, 16, (publicKey->pk).y));
	*/

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read Gid: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->Gid = atoi(field_body);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read Hid: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->Hid = atoi(field_body);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read hLen: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->hLen = strtoul(field_body, endptr, 10);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read mLen: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->mLen = strtoul(field_body, endptr, 10);

	return 1;
}


/*
 Read private key info from a file

 Return 1 if succeed, otherwise 0
*/
int get_privKey(PSEC3_PRIV_KEY *privateKey, FILE *fp)
{
char one_line[2*MAX_FIELD_LEN/8+15];
char field_id[10];
char field_body[2*MAX_FIELD_LEN/8+2];
char **endptr = NULL;
unsigned char sign;

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_privkey cannot read sk: %s\n", strerror(errno));
		return 0;
	}

	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str(privateKey->sk, field_body, 0);

	/*
	printf("get_privKey: privateKey->sk =\n");
	printf("%s\n", mpz_get_str(NULL, 16, privateKey->sk));
	*/

	return 1;
}


/*
 Read ciphertext from a file

 Return 1 if succeed, otherwise 0
*/
int get_ciphertext(PSEC3_CIPHERTEXT *ciphertext, PSEC3_PUB_KEY *publicKey, EC_PARAM *E, FILE *fp)
{
char one_line[2*MAX_FIELD_LEN/8+15];
char field_id[10];
char field_body[2*MAX_FIELD_LEN/8+2];
char **endptr = NULL;
unsigned char sign;
long i;

/*
	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_ciphertext cannot read x_C1: %s\n", strerror(errno));
		return 0;
	}

	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str((ciphertext->C1).x, field_body, 0);

	printf("get_ciphertext: (ciphertext->C1).x =\n");
	printf("%s\n", mpz_get_str(NULL, 16, (ciphertext->C1).x));

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_ciphertext cannot read y_C1: %s\n", strerror(errno));
		return 0;
	}

	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str((ciphertext->C1).y, field_body, 0);

	printf("get_ciphertext: (ciphertext->C1).y =\n");
	printf("%s\n", mpz_get_str(NULL, 16, (ciphertext->C1).y));

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read inf_idC1: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	(ciphertext->C1).inf_id = atoi(field_body);

	printf("get_ciphertext: (ciphertext->C1).inf_id = %d\n\n",
	       (ciphertext->C1).inf_id);
*/
   /* read C1 in Octect String format (P1363 E.2.3.2) */
   fread((ciphertext->C1).po, 1+2*E->qLen/8, 1, fp);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_ciphertext cannot read c1: %s\n", strerror(errno));
		return 0;
	}

	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	mpz_set_str(ciphertext->c1, field_body, 0);

	/*
	printf("get_ciphertext: ciphertext->c1 =\n");
	printf("%s\n\n", mpz_get_str(NULL, 16, ciphertext->c1));
	*/

	fread(ciphertext->c2, publicKey->mLen/8, 1, fp);
	/*
	printf("get_ciphertext: ciphertext->c2 =\n");
	for(i=0; i<publicKey->mLen/8; i++)
		printf("%02x ", ciphertext->c2[i]);
	printf("\n\n");
	*/

	fread(ciphertext->c3, publicKey->hLen/8, 1, fp);
	/*
	printf("get_ciphertext: ciphertext->c3 =\n");
	for(i=0; i<publicKey->hLen/8; i++)
		printf("%02x ", ciphertext->c3[i]);
	printf("\n\n");
	*/

	return 1;
}

/*
 Open filename for read, return NULL if problem
*/
FILE *open_input(const char *filename)
{
FILE *fp;
errno = 0;

	if(filename == NULL) filename = "\0";
	fp = fopen(filename,"r");
	if (fp == NULL)
		fprintf(stderr, "open_input(\"%s\") failed: %s\n",
		        filename, strerror(errno));

	return fp;
}


/*
 Open filenmae for write, return NULL if problem
*/
FILE *open_output(const char *filename)
{
FILE *fp;
errno = 0;

	if(filename == NULL) filename = "\0";
   fp = fopen(filename,"w+");
   if (fp == NULL)
      fprintf(stderr, "open_output(\"%s\") failed: %s\n",
              filename, strerror(errno));

   return fp;
}

/*
 Parse a line in the format "field_id = field_body"
*/
int parse_field(char *one_line, char *field_id, char *field_body)
{
const char SEPCHARS[] = " \n";
char *tmp1, *tmp2, *tmp3;

	tmp1 = strtok(one_line, SEPCHARS);
	tmp2 = strtok(NULL, " ");
	tmp3 = strtok(NULL, SEPCHARS);
	if(tmp1 == NULL || tmp2 == NULL || tmp3 == NULL) {
		fprintf(stderr, "parse_field finds unrecognized line structure: %s\n",
		        strerror(errno));
		return 0;
	}
	strcpy(field_id, tmp1);
	strcpy(field_body, tmp3);
	/*
	printf("parse_field: field_id = %s\n",field_id);
	printf("parse_field: field_body = %s\n",field_body);
	*/

	return 1;
}


/*
 Copy len BYTEs from from to to
*/
void assignBYTE(BYTE *to, BYTE *from, WORD len)
{
WORD i;

   for(i=0; i<len; i++)
      to[i] = from[i];
}


/*
 Convert (mp_srcptr) xp to a sequence of bytes in big-endian, (BYTE *) xp_raw
*/
void WORD2BYTE(BYTE *xp_raw, mp_srcptr xp, mp_size_t xsize)
{
long i;
BYTE *tmp_p;

	tmp_p = xp_raw;
	for(i=xsize-1; i>=0; i--) {
		tmp_p[0] = xp[i] >> 24;
		tmp_p[1] = (xp[i] >> 16) & 0xff;
		tmp_p[2] = (xp[i] >> 8) & 0xff;
		tmp_p[3] = xp[i] & 0xff;
		tmp_p += 4;
	}
}


/*
 Convert (BYTE *) raw to (mpz_ptr) x
*/
mp_size_t BYTE2WORD(mpz_ptr x, BYTE *raw, mp_size_t size)
{
long i;
BYTE *raw_ascii, *tmp_p;

	raw_ascii = (BYTE *) malloc (size*2+1);
	tmp_p = raw_ascii;

	for(i=0; i<size; i++) {
		sprintf(tmp_p,"%02x", raw[i]);
		tmp_p+=2;
	}
	/* printf("BYTE2WORD: raw_ascii =\n\t%s\n\n", raw_ascii); */

	mpz_set_str(x, raw_ascii, 16);

	memset(raw_ascii, 0, size*2+1);
	free(raw_ascii);

	return mpz_size(x);
}


/*
 One-time pad
*/
WORD Vernam(BYTE *K, WORD kLen, BYTE *in, BYTE *out)
{
unsigned char c;
WORD i;
  
   i = 0;
   while(kLen>0) {
		out[i] = in[i] ^ K[i];
      kLen -= 8;  
		i++;
   }

   return i;
}


/*
 Convert an EC point to an Octet String according to P1363 E.2.3.2
  
 Return 1 if succeed; otherwise 0
*/
int ec2os(unsigned char *po, EC_POINT *P, EC_PARAM *E)
{
unsigned char *buffer, *tmp_ptr;
long i, j;

   if(P->inf_id == EC_O) {
		*po = 0;     /* a single 0 octet represents the point at infinity */
      return 0;
   }
      
   buffer = (unsigned char *) malloc (E->qLen/8);
      
   /* uncompressed format */
   *po = 0x04;
   tmp_ptr = po + 1;

   /* append xP to po */
   j = E->qLen/8 - ABS(P->x->_mp_size)*4;
   /* printf("ec2os: %d\t%d\t%d\n", E->qLen/8, ABS(P->x->_mp_size)*4, j); */
   
   WORD2BYTE(buffer + j, P->x->_mp_d, ABS(P->x->_mp_size));

   for(i=0; i<j; i++) buffer[i] = 0;

   assignBYTE(tmp_ptr, buffer, E->qLen/8);
   tmp_ptr += E->qLen/8;

   /* append yP to po */
   j = E->qLen/8 - ABS(P->y->_mp_size)*4;
   /* printf("ec2os: %d\t%d\t%d\n", E->qLen/8, ABS(P->y->_mp_size)*4, j); */

   WORD2BYTE(buffer + j, P->y->_mp_d, ABS(P->y->_mp_size));

   for(i=0; i<j; i++) buffer[i] = 0;

   assignBYTE(tmp_ptr, buffer, E->qLen/8);

   free(buffer);

   return 1;
}


/*
 Convert an P1363 E.2.3.2 complaint Octet String to an EC point

 Return 1 if succeed; otherwise 0
*/
int os2ec(EC_POINT *P, unsigned char *po, EC_PARAM *E)
{
unsigned char *buffer, *tmp_ptr;
long i, j;

	if(*po == 0) {
		P->inf_id = EC_O;
		return 0;
	}

   tmp_ptr = po;
   /* support uncompressed format only for this reference implementation */
   if(*tmp_ptr == 0x4) {
      tmp_ptr++;
      BYTE2WORD(P->x, tmp_ptr, E->qLen/8);
      tmp_ptr += E->qLen/8;
      BYTE2WORD(P->y, tmp_ptr, E->qLen/8);
      P->inf_id = 0;
   } else
      return 0;

   return 1;
}
