/*
 kdm.c - PSEC-KEM key decapsulation mechanism function

 Copyright NTT MCL, 2000 & 2001.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 This code is a modification of the decrypt.c file from PSEC-2.  
 Modifications made by S.O. in September 2001.

 - 9/25/2001 Made changes to deal with the point at infinity. -- S.O.
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
 PSEC-KEM key decapsulation mechanism

 Return: TRUE if succeed; otherwise FALSE
*/
u8 PSEC_KEM_KDM(
   PSEC_KEM_KEY_ENCAPSULATION *keyEncapsulation,    /* keyEncapsulation */
   PSEC_KEM_PRIV_KEY    *privKey,     /* PSEC_KEM private key */
   PSEC_KEM_PUB_KEY    *publicKey,     /* PSEC_KEM public key */
   PSEC_KEM_KEY_MATERIAL	*keyMaterial,	/* returned key material */
   EC_PARAM         *E,
   PSEC_KEM_EC_ENCODING_FORMAT format
)
{
mpz_t s, u, v, res;
EC_POINT g_tilde, g_bar, h_tilde;
u8 *s_raw, *u_raw, *t_raw, *PEH_raw, *EG_raw, *v_raw, *res_raw;
u8 *mgf_arg_1, *mgf_arg_2;
u32 hoLen, uoLen, EGoLen, PEHoLen, qoLen;
u8 compare_result, return_code;

	mpz_init(s);
	mpz_init(u);
	mpz_init(v);
	mpz_init(res);

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
	if ((E->P).inf_id == EC_O)
		EGoLen = 1;
	if ((publicKey->pk).inf_id == EC_O)
		PEHoLen = 1;
#ifdef DEBUG
printf("hoLen = %u\n", hoLen);
printf("uoLen = %u\n", uoLen);
printf("keyMaterial->KoLen = %u\n", keyMaterial->KoLen);
printf("EGoLen = %u\n", EGoLen);
printf("PEHoLen = %u\n", PEHoLen);
#endif
	EC_initPoint(&g_tilde);
	EC_initPoint ( &h_tilde );
	EC_initPoint ( &g_bar );

	s_raw = (u8 *) malloc (hoLen);
	u_raw = (u8 *) malloc (uoLen);
	t_raw = (u8 *) malloc (uoLen + keyMaterial->KoLen);
	PEH_raw = (u8 *) malloc (PEHoLen);
	EG_raw = (u8 *) malloc (EGoLen);
	v_raw = (u8 *) malloc (hoLen);
	res_raw = (u8 *) malloc (hoLen);
	mgf_arg_1 = (u8 *) malloc (4 + EGoLen + PEHoLen);
	mgf_arg_2 = (u8 *) malloc (4 + hoLen);

	/* parse C0 as EG || v */
	memcpy ( EG_raw, keyEncapsulation->C0, EGoLen );
	memcpy ( v_raw, keyEncapsulation->C0 + EGoLen, hoLen);
	BYTE2WORD ( v, v_raw, hoLen );

	/* convert octet string format to EC point format (P1363 E.2.3.2) */
	return_code = os2ec(&g_tilde, EG_raw, E);
#ifdef DEBUG
printf("os2ec return code for EG = %u\n", return_code);
printf("EG = ");
printAsHex(EG_raw, EGoLen);
printf("\n"); fflush(stdout);
printf("g_tilde.x = 0x%s\n", mpz_get_str(NULL, 16, g_tilde.x));
printf("g_tilde.y = 0x%s\n", mpz_get_str(NULL, 16, g_tilde.y));
#endif

	/* Compute h_tilde = x * g_tilde */
	EC_Mult( &h_tilde, privKey->sk, &g_tilde, E );
#ifdef DEBUG
printf("h_tilde.x = 0x%s\n", mpz_get_str(NULL, 16, h_tilde.x));
printf("h_tilde.y = 0x%s\n", mpz_get_str(NULL, 16, h_tilde.y));
#endif
	return_code = ec2os(PEH_raw, &h_tilde, E, format);
#ifdef DEBUG
printf("PEH = ");
printAsHex(PEH_raw, PEHoLen);
printf("\n"); fflush(stdout);
#endif

	/* compute res = MGF1( 1 || EG || PEH) */
	U32TO8_BIG ( mgf_arg_1, 1L );
	memcpy( mgf_arg_1 + 4, EG_raw, EGoLen );
	memcpy( mgf_arg_1 + 4 + EGoLen, PEH_raw, PEHoLen );
	MGF1( res_raw, publicKey->hLen, mgf_arg_1, 4 + EGoLen + PEHoLen);
	BYTE2WORD( res, res_raw, hoLen);
#ifdef DEBUG
printf("res = 0x%s\n", mpz_get_str(NULL, 16, res));
#endif

	/* Compute s = v \xor MGF (1 || EG || PEH) */
	mpz_xor(s, v, res);
	WORD2BYTE( s_raw, s, hoLen);
#ifdef DEBUG
printf("v = 0x%s\n", mpz_get_str(NULL, 16, v));
printf("s = 0x%s\n", mpz_get_str(NULL, 16, s));
#endif
	
	/* compute t = MGF1(0 || s) */
	U32TO8_BIG(mgf_arg_2, 0L);
	memcpy(mgf_arg_2 + 4, s_raw, hoLen);
	MGF1( t_raw, 8 * (uoLen + keyMaterial->KoLen), mgf_arg_2, 4 + hoLen);
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
printf("u = ");
printAsHex(u_raw, uoLen);
printf("\n"); fflush(stdout);
printf("keyMaterial = ");
printAsHex(keyMaterial->K_raw, keyMaterial->KoLen);
printf("\n"); fflush(stdout);
#endif

	/* compute g_bar = u * E->P */
	EC_Mult( &g_bar, u, &(E->P), E );

	/* compare g_bar and g_tilde */
	compare_result = 0;
	compare_result += ABS(mpz_cmp(g_bar.x, g_tilde.x));
	compare_result += ABS(mpz_cmp(g_bar.y, g_tilde.y));
	if (g_bar.inf_id != g_tilde.inf_id)
		compare_result++;
	if (compare_result) /* g_bar != g_tilde */
		return_code = FALSE;
	else
		return_code = TRUE; /* g_bar == g_tilde */

	/* clean up */
	mpz_clear(s);
	mpz_clear(u);
	mpz_clear(v);
	mpz_clear(res);

	memset(s_raw, 0, hoLen);
	memset(u_raw, 0, uoLen);
	memset(t_raw, 0, uoLen + keyMaterial->KoLen);
	memset(PEH_raw, 0, PEHoLen);
	memset(EG_raw, 0, EGoLen);
	memset(v_raw, 0, hoLen);
	memset(res_raw, 0, hoLen);
	memset(mgf_arg_1, 0, 4 + EGoLen + PEHoLen);
	memset(mgf_arg_2, 0, 4 + hoLen);

	free(s_raw);
	free(u_raw);
	free(t_raw);
	free(PEH_raw);
	free(EG_raw);
	free(v_raw);
	free(res_raw);
	free(mgf_arg_1);
	free(mgf_arg_2);

	EC_clearPoint(&h_tilde);
	EC_clearPoint(&g_tilde);
	EC_clearPoint(&g_bar);

	return return_code;
}
