/*
 utils-psec.c

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.

 10/24/2000 - Modified get_ciphertext to include cipherInfo as a parameter.
	- Modified get_pubKey so that it no longer tries to read in mLen.
	- Modified WORD2BYTE as suggested by T. Kobayashi.
	- Modified calls to WORD2BYTE as suggested by H. Oguro.  -- S.O.

 10/25/2000 - Added get_randomseed by T. Kobayashi. -- H.O.

 10/27/2000 - Modified get_pubKey to read SEid -- H.O.

 9/19/2001 - Modified calls to WORD2BYTE to match changes in utils.c -- S.O.

 9/22/2001 - Added compressed and hybrid formats in ec2os and os2ec. -- S.O.
	   - Added mpz_sqrootm and generateLucasSequence to support changes in ec2os 
	     and os2ec. -- S.O
 9/25/2001 - Made changes to get_pubKey to read in inf_id -- S.O.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <gmp.h>
#include <math.h>
#include "nessie.h"
#include "ec_arith.h"
#include "psec_kem.h"
#include "utils.h"
#include "utils-psec.h"

/*
 Read PSEC parameters from a file

 Return 1 if succeed, otherwise 0
*/
s32 get_psec_param(EC_PARAM *E, FILE *fp)
{
s8 one_line[2*MAX_FIELD_LEN/8+15];
s8 field_id[10];
s8 field_body[2*MAX_FIELD_LEN/8+2];
s8 **endptr = NULL;
u8 sign;

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
	E->qLen = strtoul(field_body, (char **)endptr, 10);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_psec_param cannot read pLen: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	E->pLen = strtoul(field_body, (char **)endptr, 10);

	return 1;
}


/*
 Read public key info from a file

 Return 1 if succeed, otherwise 0
*/
s32 get_pubKey(PSEC_KEM_PUB_KEY *publicKey, FILE *fp)
{
s8 one_line[2*MAX_FIELD_LEN/8+15];
s8 field_id[10];
s8 field_body[2*MAX_FIELD_LEN/8+2];
s8 **endptr = NULL;
u8 sign;

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
		fprintf(stderr, "get_pubKey cannot read pk_inf_id: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	(publicKey->pk).inf_id = atoi(field_body);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read Hid: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->Hid = atoi(field_body);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read SEid: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->SEid = atoi(field_body);

	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read hLen: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->hLen = strtoul(field_body, (char **)endptr, 10);


	if ( fgets(one_line, 2*MAX_FIELD_LEN/8+14, fp) == NULL ) {
		fprintf(stderr, "get_pubKey cannot read outputKeyLen: %s\n", strerror(errno));
		return 0;
	}
	if ( !parse_field(one_line, field_id, field_body) ) return 0;
	publicKey->outputKeyLen = strtoul(field_body, (char **)endptr, 10);

	return 1;
}


/*
 Read private key info from a file

 Return 1 if succeed, otherwise 0
*/
s32 get_privKey(PSEC_KEM_PRIV_KEY *privateKey, FILE *fp)
{
s8 one_line[2*MAX_FIELD_LEN/8+15];
s8 field_id[10];
s8 field_body[2*MAX_FIELD_LEN/8+2];
s8 **endptr = NULL;
u8 sign;

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
 Convert an EC point to an Octet String according to P1363 E.2.3.2

 format == COMPRESSED or UNCOMPRESSED or HYBRID
   
 Return 1 if succeed; otherwise 0
*/ 
u8 ec2os(u8 *po, EC_POINT *P, EC_PARAM *E, u8 format)
{  
u8 *buffer, *tmp_ptr;
s32 i, j;
mpz_t yp_tilde;
u32 yp_tilde_ui;
u32 oLen = (u32)ceil(E->qLen/8.0);

   if(P->inf_id == EC_O) {
      *po = 0;     /* a single 0 octet represents the point at infinity */
      return 0;
   }

   buffer = (u8 *) malloc (oLen);
   mpz_init(yp_tilde);

   /* set first byte */
   yp_tilde_ui = mpz_mod_ui(yp_tilde, P->y, 2);

   switch (format)  {
      case COMPRESSED:
	 if (yp_tilde_ui == 0)
	    *po = 0x02;
	 else
	    *po = 0x03;
         break;

      case UNCOMPRESSED:
         *po = 0x04;
         break;

      case HYBRID:
	 if (yp_tilde_ui == 0)
	    *po = 0x06;
	 else
	    *po = 0x07;
         break;
   }

   tmp_ptr = po + 1;

   /* append xP to po */
   WORD2BYTE(buffer, P->x, oLen); /* 9/14/2001 Satomi */
   assignBYTE(tmp_ptr, buffer, oLen);

   switch (format)  {

      case COMPRESSED:
	 break;

      case UNCOMPRESSED:
      case HYBRID:         
         /* append yP to po */
         tmp_ptr += oLen;
         WORD2BYTE(buffer, P->y, oLen); /* 9/14/2001 Satomi */
         assignBYTE(tmp_ptr, buffer, oLen);
      
 	 break;
   }

   /* clean up */
   free(buffer);

   mpz_clear(yp_tilde);

   return 1;
}


/*
 Convert an P1363 E.2.3.2 compliant Octet String to an EC point

 Return 1 if succeed; otherwise 0
*/
u8 os2ec(EC_POINT *P, u8 *po, EC_PARAM *E)
{
u8 *buffer, *tmp_ptr;
u32 oLen = (u32)ceil(E->qLen/8.0);
PSEC_KEM_EC_ENCODING_FORMAT format; /* format == COMPRESSED or UNCOMPRESSED or HYBRID */
u8 yp_tilde_ui;
mpz_t g, temp, z;
u8 return_code = 1;
   

   if(*po == 0) {
      P->inf_id = EC_O;
      return 0;
   }

   /* read in format */
   tmp_ptr = po;
   yp_tilde_ui = (*tmp_ptr)%2;
   if ((*tmp_ptr == 0x02) || (*tmp_ptr == 0x03))
      format = COMPRESSED;
   else if(*tmp_ptr == 0x04)
      format = UNCOMPRESSED;
   else if ((*tmp_ptr == 0x06) || (*tmp_ptr == 0x07))
      format = HYBRID;

   /* Read in P->x */
   tmp_ptr++;
   BYTE2WORD(P->x, tmp_ptr, oLen);

   switch (format)  {

      case COMPRESSED:
         mpz_init(g);
         mpz_init(temp);
         mpz_init(z);

         /* compute g = x^3 + ax + b mod q */
         mpz_pow_ui(g, P->x, 3);
         mpz_mul(temp, E->a, P->x);
         mpz_add(g, g, temp);
         mpz_add(g, g, E->b);
         mpz_mod(g, g, E->q);

         /* Find square root z of g modulo q */
         if (mpz_sqrootm(z, g, E->q) == 0)  {  /* no square root of g modulo q exists */
            return_code = 0;

         }  else  {  /* square root of g modulo q exists */
            /* temp is the rightmost bit of z */
            if (yp_tilde_ui == (u8)mpz_mod_ui(temp, z, 2))  {
               mpz_set(P->y, z);
            }  else  {
               mpz_sub(P->y, E->q, z); 
            }
         }

         /* local clean up */
         mpz_clear(g);
         mpz_clear(temp);
         mpz_clear(z);
         break;

      case UNCOMPRESSED:
      case HYBRID:
         tmp_ptr += oLen;
         BYTE2WORD(P->y, tmp_ptr, oLen);
         break;
   }

   P->inf_id = 0;

   return return_code;
}

/* Computes the square root modulo p of g, if one exists.
 * p is an odd prime
 * g is an integer such that 0 < g < p
 *
 * Follows the specifications in Annex A (A.2.5) of IEEE P1363 D13 (12 November 1999)
 *
 */
u8 mpz_sqrootm(mpz_t z, mpz_t g, mpz_t p)
{
u32 bitlen, p_mod_8_ui;
mpz_t p_mod_4, p_mod_8, k, gamma, i, Q, P, temp, temp2, V, Q_0;
u8 return_code;

	mpz_init(p_mod_4);
	mpz_init(p_mod_8);
	mpz_init(k);

	if (mpz_mod_ui(p_mod_4, p, 4) == 3)  {
		/* compute k */
		mpz_sub_ui(k, p, 3);
		mpz_tdiv_q_ui(k, k, 4);

		/* compute z = g^{k+1} mod p */
		mpz_add_ui(k, k, 1);
		mpz_powm(z, g, k, p);
		return_code =  1;
	} else  {
		p_mod_8_ui = mpz_mod_ui(p_mod_8, p, 8);
		if (p_mod_8_ui == 5)  {
	
			mpz_init(gamma);
			mpz_init(i);

			/* compute k */
			mpz_sub_ui(k, p, 5);
			mpz_tdiv_q_ui(k, k, 8);

			/* compute gamma = (2g)^k mod p */
			mpz_mul_ui(gamma, g, 2);
			mpz_powm(gamma, gamma, k, p);

			/* compute i = 2*g*gamma^2 mod p */
			mpz_pow_ui(i, gamma, 2);
			mpz_mul_ui(i, i, 2);
			mpz_mul(i, i, g);
			mpz_mod(i, i, p);

			/* compute z = g*gamma*(i-1) mod p */
			mpz_sub_ui(z, i, 1);
			mpz_mul(z, z, gamma);
			mpz_mul(z, z, g);
			mpz_mod(z, z, p);

			/* local clean up */
			mpz_clear(gamma);
			mpz_clear(i);

			return_code = 1;

		} else if (p_mod_8_ui == 1)  {
			mpz_init_set(Q, g);
			mpz_init(P);
			mpz_init(temp);
			mpz_init(temp2);
			mpz_init(V);
			mpz_init(Q_0);
			
			/* Set P to be a random number 0 < P < p */
			bitlen = mpz_sizeinbase(p, 2);
			GenerateNumber(bitlen, P, global_prng);
			while ((mpz_cmp(P, p) >= 0) || (mpz_cmp_ui(P, 0) <= 0))
				GenerateNumber(bitlen, P, global_prng);

			while (1)  {  /* P must be 0 < P < p */
				/* compute V = V_{(p+1)/2} mod p */
				mpz_add_ui(k, p, 1);
				mpz_tdiv_q_ui(k, k, 2);
				generateLucasSequence(V, temp, p, P, Q, k);
		
				/* compute Q_0 = Q^{(p-1)/4} mod p */
				mpz_sub_ui(k, p, 1);
				mpz_tdiv_q_ui(k, k, 2);
				generateLucasSequence(temp, Q_0, p, P, Q, k);

				/* z = V/2 mod p  (Note 1 in A.2.5. of P1363 D13) */
				if (mpz_mod_ui(temp, V, 2) == 0)
					mpz_tdiv_q_ui(z, V, 2);
				else {
					mpz_add(temp, V, p);
					if (mpz_mod_ui(temp2, temp, 2) == 0)  {
						mpz_tdiv_q_ui(z, temp, 2);
					}
				}
				mpz_mod(z, z, p);

				/* compare z^2 mod p and g */
				mpz_pow_ui(temp, z, 2);
				mpz_mod(temp, temp, p);
				if (mpz_cmp(temp, g) == 0)  {
					return_code = 1;
					break;
				}

				/* if 1 < Q_0 < p-1 then no square roots exist */
				mpz_sub_ui(temp, p, 1);
				if ((mpz_cmp_ui(Q_0, 1) > 0) && (mpz_cmp(Q_0, temp) < 0))  {
					return_code = 0;
					break;
				}

				/* pick a new P such that 0 < P < p and repeat */
				GenerateNumber(bitlen, P, global_prng);
				while ((mpz_cmp(P, p) >= 0) || (mpz_cmp_ui(P, 0) <= 0))
					GenerateNumber(bitlen, P, global_prng);
			}

			/* local clean up */
			mpz_clear(Q);
			mpz_clear(P);
			mpz_clear(temp);
			mpz_clear(temp2);
			mpz_clear(V);
			mpz_clear(Q_0);

		} else  {
			return_code = 0;
		}
	}

	/* clean up */
	mpz_clear(p_mod_4);
	mpz_clear(p_mod_8);
	mpz_clear(k);

	return return_code;
}

/* Generates an element of the Lucas Sequence.
 * n an odd integer such that n > 2
 * P and Q integers
 * k a positive integer
 *
 * Follows the specifications in Annex A (A.2.4) of IEEE P1363 D13 (12 November 1999)
 *
 */
void generateLucasSequence(mpz_t V_k_mod_n, mpz_t Q_k_over_2_mod_n, mpz_t n, mpz_t P, mpz_t Q, mpz_t k)
{
mpz_t v_0, v_1, q_0, q_1, temp;
s32 i;
s32 r;

	mpz_init_set_ui(v_0, 2);
	mpz_init_set(v_1, P);
	mpz_init_set_ui(q_0, 1);
	mpz_init_set_ui(q_1, 1);
	mpz_init(temp);

	r = mpz_sizeinbase(k, 2) - 1;

	for (i = r; i >= 0; i--)  {
		/* q_0 = q_0 * q_1 mod n */
		mpz_mul(q_0, q_0, q_1);
		mpz_mod(q_0, q_0, n);

		if (mpz_tstbit(k, i) == 1)  {
			/* q_1 = q_0 * Q mod n */
			mpz_mul(q_1, q_0, Q);
			mpz_mod(q_1, q_1, n);

			/* v_0 = v_0 * v_1 - P * q_0 mod n */
			mpz_mul(v_0, v_0, v_1);
			mpz_mul(temp, P, q_0);
			mpz_sub(v_0, v_0, temp);
			mpz_mod(v_0, v_0, n);

			/* v_1 = v_1^2 - 2 * q_1 mod n */
			mpz_pow_ui(v_1, v_1, 2);
			mpz_mul_ui(temp, q_1, 2);
			mpz_sub(v_1, v_1, temp);
			mpz_mod(v_1, v_1, n);
			
		}  else  {
			mpz_set(q_1, q_0);

			/* v_1 = v_0 * v_1 - P * q_0 mod n */
			mpz_mul(v_1, v_0, v_1);
			mpz_mul(temp, P, q_0);
			mpz_sub(v_1, v_1, temp);
			mpz_mod(v_1, v_1, n);

			/* v_0 = v_0^2 - 2 * q_0 mod n */
			mpz_pow_ui(v_0, v_0, 2);
			mpz_mul_ui(temp, q_0, 2);
			mpz_sub(v_0, v_0, temp);
			mpz_mod(v_0, v_0, n);
		}
	}
			
	/* output v_0 and q_0 */
	mpz_set(V_k_mod_n, v_0);
	mpz_set(Q_k_over_2_mod_n, q_0);

	/* clean up */
	mpz_clear(v_0);
	mpz_clear(v_1);
	mpz_clear(q_0);
	mpz_clear(q_1);
	mpz_clear(temp);

	return;
}
