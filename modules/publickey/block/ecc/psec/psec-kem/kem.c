/*
 kem.c - PSEC-KEM key encapsulation mechanism function

 Copyright NTT MCL, 2000 & 2001.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 This code is a modification of encrypt.c code for PSEC-2.
 Modifications made by S.O. in September 2001.

 9/25/2001 - Made changes to deal with point at infinity -- S.O.
*/

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <math.h>
#include "nessie.h"
#include "ec_arith.h"
#include "psec_kem.h"
#include "utils.h"
#include "random.h"

/*
 PSEC-KEM key encapsulation mechanism

 Return: TRUE if succeed; otherwise FALSE
*/
u8 PSEC_KEM_KEM(
   PSEC_KEM_PUB_KEY    *publicKey,     /* PSEC_KEM public key */
   PSEC_KEM_KEY_ENCAPSULATION *keyEncapsulation,    /* returned keyEncapsulation */
   PSEC_KEM_KEY_MATERIAL *keyMaterial,    /* returned key material */
   EC_PARAM         *E,
   PSEC_KEM_EC_ENCODING_FORMAT format
)
{
mpz_t s, u, res, v;
u8 *s_raw, *u_raw, *t_raw, *mgf_arg_1, *mgf_arg_2, *res_raw, *v_raw, *PEH_raw; 
u8 *EG_raw;
s32 i;
u32 hoLen, uoLen, EGoLen, PEHoLen, qoLen;
EC_POINT h_tilde, g_tilde;

	mpz_init(s);
	mpz_init(u);
	mpz_init(res);
	mpz_init(v);

	hoLen = (publicKey->hLen) >> 3;
	uoLen = (u32)ceil(E->pLen/8.0) + 16;
	keyMaterial->KoLen = (publicKey->outputKeyLen) >> 3;
	qoLen = (u32)ceil(E->qLen/8.0);
	if (format == COMPRESSED)  {
		EGoLen = 1 + qoLen;
		PEHoLen = 1 + qoLen;
	}  else  {
		EGoLen = 1 + 2*qoLen;
		PEHoLen = 1 + 2*qoLen;
	}
	if ((publicKey->pk).inf_id == EC_O) 
		PEHoLen = 1;
	if ((E->P).inf_id == EC_O)
		EGoLen = 1;
#ifdef DEBUG
printf("hoLen = %u\n", hoLen);
printf("uoLen = %u\n", uoLen);
printf("keyMaterial->KoLen = %u\n", keyMaterial->KoLen);
printf("EGoLen = %u\n", EGoLen);
printf("PEHoLen = %u\n", PEHoLen);
#endif
	EC_initPoint ( &h_tilde );
	EC_initPoint ( &g_tilde);

	s_raw = (BYTE *) malloc (hoLen);
	u_raw = (BYTE *) malloc (uoLen);
	t_raw = (BYTE *) malloc (uoLen + keyMaterial->KoLen);
	mgf_arg_1 = (u8 *) malloc (4 + hoLen);
	mgf_arg_2 = (u8 *) malloc (4 + EGoLen + PEHoLen);
	res_raw = (u8 *) malloc (hoLen);
	v_raw = (u8 *) malloc (hoLen);
	PEH_raw = (u8 *) malloc (PEHoLen);
	EG_raw = (u8 *) malloc (EGoLen);

	/* generate s */
	GenerateBytes(s_raw, hoLen, global_prng);
	BYTE2WORD (s, s_raw, hoLen);
#ifdef DEBUG
printf("s = 0x%s\n", mpz_get_str(NULL, 16, s));
printf("\n"); fflush(stdout);
#endif

	/* compute t = MGF1(0 || s) */
	U32TO8_BIG(mgf_arg_1, 0L);
	memcpy(mgf_arg_1+4, s_raw, hoLen);
	MGF1( t_raw, 8 * (uoLen + keyMaterial->KoLen), mgf_arg_1, 4 + hoLen);
#ifdef DEBUG
printf("t = ");
printAsHex(t_raw, uoLen+keyMaterial->KoLen);
printf("\n"); fflush(stdout);
#endif

	/* parse t as t = u || K */
	memcpy( u_raw, t_raw, uoLen );
	BYTE2WORD( u, u_raw, uoLen );
	memcpy( keyMaterial->K_raw, t_raw+uoLen, keyMaterial->KoLen );
#ifdef DEBUG
printf("u = 0x%s\n", mpz_get_str(NULL, 16, u));
printf("keyMaterial = ");
printAsHex(keyMaterial->K_raw, keyMaterial->KoLen);
printf("\n"); fflush(stdout);
#endif

	/* compute h_tilde = u * publicKey->pk */
	EC_Mult( &h_tilde, u, &(publicKey->pk), E );
	ec2os (PEH_raw, &h_tilde, E, format);
#ifdef DEBUG
printf("h_tilde.x = 0x%s\n", mpz_get_str(NULL, 16, h_tilde.x));
printf("h_tilde.y = 0x%s\n", mpz_get_str(NULL, 16, h_tilde.y));
printf("PEH = ");
printAsHex(PEH_raw, PEHoLen);
printf("\n"); fflush(stdout);
#endif

	/* compute g_tilde = u * E->P */
	EC_Mult( &g_tilde, u, &(E->P), E );
#ifdef DEBUG
printf("g_tilde.x = 0x%s\n", mpz_get_str(NULL, 16, g_tilde.x));
printf("g_tilde.y = 0x%s\n", mpz_get_str(NULL, 16, g_tilde.y));
printf("g_tilde.inf_id = %u\n", g_tilde.inf_id);
#endif

    /* convert g_tilde's EC point to an octet string according to P1363 E.2.3.2 */
	ec2os( EG_raw, &g_tilde, E, format);
#ifdef DEBUG
printf("EG = ");
printAsHex(EG_raw, EGoLen);
printf("\n"); fflush(stdout);
#endif

	/* compute res = MGF1( 1 || EG || PEH ) */
	U32TO8_BIG ( mgf_arg_2, 1L );
	memcpy( mgf_arg_2 + 4, EG_raw, EGoLen );
	memcpy( mgf_arg_2 + 4 + EGoLen, PEH_raw, PEHoLen );
	MGF1( res_raw, publicKey->hLen, mgf_arg_2, 4 + EGoLen + PEHoLen);
	BYTE2WORD( res, res_raw, hoLen);
#ifdef DEBUG
printf("res = 0x%s\n", mpz_get_str(NULL, 16, res));
printf("\n"); fflush(stdout);
#endif

	/* compute v = s \xor res */
	mpz_xor(v, s, res);
	WORD2BYTE(v_raw, v, hoLen);
#ifdef DEBUG
printf("v = 0x%s\n", mpz_get_str(NULL, 16, v));
printf("\n"); fflush(stdout);
#endif

	/* output C0 = EG || v */
	memcpy( keyEncapsulation->C0, EG_raw, EGoLen);
	memcpy( keyEncapsulation->C0 + EGoLen, v_raw, hoLen);
#ifdef DEBUG
printf("C0 = ");
printAsHex(keyEncapsulation->C0, keyEncapsulation->C0oLen);
printf("\n"); fflush(stdout);
#endif
	
	/* clean up */
	mpz_clear(s);
	mpz_clear(u);
	mpz_clear(res);
	mpz_clear(v);

	memset(s_raw, 0, hoLen);
	memset(u_raw, 0, uoLen);
	memset(t_raw, 0, uoLen + keyMaterial->KoLen);
	memset(mgf_arg_1, 0, 4+hoLen);
	memset(mgf_arg_2, 0, 4 + EGoLen + PEHoLen);
	memset(res_raw, 0, hoLen);
	memset(v_raw, 0, hoLen);
	memset(PEH_raw, 0, PEHoLen);
	memset(EG_raw, 0, EGoLen);

	free(s_raw);
	free(u_raw);
	free(t_raw);
	free(mgf_arg_1);
	free(mgf_arg_2);
	free(res_raw);
	free(v_raw);
	free(PEH_raw);
	free(EG_raw);

	EC_clearPoint ( &h_tilde );
	EC_clearPoint ( &g_tilde );

	return TRUE;
}
