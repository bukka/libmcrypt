/*
 ec_arith.c - some operations on elliptic curve

 8/29/00 - a minor bug fix so the case of addition a point to the point at
           at infinity would get the point as the result

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000
*/

#include <stdio.h>
#include <gmp.h>
#include "ec_arith.h"

/*
 Obtain inverse of the point P
*/
void EC_invertP(EC_POINT *inverP, EC_POINT *P, EC_PARAM *E)
{
EC_POINT tmp;

	EC_initPoint(&tmp);

	mpz_set(tmp.x, P->x);
	mpz_set(tmp.y, P->y);
	mpz_neg(tmp.y, tmp.y);
	mpz_mod(tmp.y, tmp.y, E->q);

	/* output inverP */
	mpz_set(inverP->x, tmp.x);
	mpz_set(inverP->y, tmp.y);
	inverP->inf_id = P->inf_id;

	EC_clearPoint(&tmp);
}


/*
 Full Addition

 P2 := P0 + P1
*/
void EC_Add(EC_POINT *P2, EC_POINT *P0, EC_POINT *P1, EC_PARAM *E)
{
mpz_t lambda, tmp;
EC_POINT P2_tmp;

	EC_initPoint(&P2_tmp);
	mpz_init(lambda);
	mpz_init(tmp);

	/* printf("EC_Add: E->q =\n%s\n\n", mpz_get_str(NULL, 16, E->q)); */

	if (P0->inf_id == EC_O) {
		mpz_set(P2_tmp.x, P1->x);
		mpz_set(P2_tmp.y, P1->y);
	} else if (P1->inf_id == EC_O) {
		mpz_set(P2_tmp.x, P0->x);
		mpz_set(P2_tmp.y, P0->y);
	} else {
		if (mpz_cmp(P0->x, P1->x) != 0) {
			mpz_sub(lambda, P0->x, P1->x);
			mpz_mod(lambda, lambda, E->q);
			mpz_invert(lambda, lambda, E->q);
			mpz_sub(tmp, P0->y, P1->y);
			mpz_mod(tmp, tmp, E->q);
			mpz_mul(lambda, tmp, lambda);
			mpz_mod(lambda, lambda, E->q);
		} else { /* x0 == x1 */
			if((mpz_cmp(P0->y, P1->y) != 0) || (mpz_cmp_ui(P1->y, 0) == 0)) {
				P2_tmp.inf_id = EC_O;
			} else {
				mpz_mul_ui(lambda, P1->y, 2);
				mpz_mod(lambda, lambda, E->q);
				mpz_invert(lambda, lambda, E->q);
				mpz_mul(tmp, P1->x, P1->x);
				mpz_mul_ui(tmp, tmp, 3);
				mpz_add(tmp, tmp, E->a);
				mpz_mod(tmp, tmp, E->q);
				mpz_mul(lambda, lambda, tmp);
				mpz_mod(lambda, lambda, E->q);
			}
		}

		mpz_mul(P2_tmp.x, lambda, lambda);
		mpz_sub(P2_tmp.x, P2_tmp.x, P0->x);
		mpz_sub(P2_tmp.x, P2_tmp.x, P1->x);
		mpz_mod(P2_tmp.x, P2_tmp.x, E->q);

		mpz_sub(tmp, P1->x, P2_tmp.x);
		mpz_mul(P2_tmp.y, tmp, lambda);
		mpz_sub(P2_tmp.y, P2_tmp.y, P1->y);
		mpz_mod(P2_tmp.y, P2_tmp.y, E->q);
	}

	/* printf("EC_Add: lambda =\n%s\n\n", mpz_get_str(NULL, 16, lambda)); */

	/* output P2 */
	EC_initPoint(P2);
	mpz_set(P2->x, P2_tmp.x);
	mpz_set(P2->y, P2_tmp.y);
	P2->inf_id = P2_tmp.inf_id;

	mpz_clear(lambda);
	mpz_clear(tmp);
	EC_clearPoint(&P2_tmp);
}


/*
 Double Point

 S := 2P
*/
void EC_Double(EC_POINT *S, EC_POINT *P, EC_PARAM *E)
{
mpz_t lambda, tmp;
EC_POINT S_tmp;

	EC_initPoint(&S_tmp);
	mpz_init(lambda);
	mpz_init(tmp);

	if((P->inf_id == EC_O) || (mpz_cmp_ui(P->y, 0) == 0)) {
		S_tmp.inf_id = EC_O;
	} else {
		mpz_mul_ui(lambda, P->y, 2);
		mpz_mod(lambda, lambda, E->q);
		mpz_invert(lambda, lambda, E->q);
		mpz_mul(tmp, P->x, P->x);
		mpz_mul_ui(tmp, tmp, 3);
		mpz_add(tmp, tmp, E->a);
		mpz_mod(tmp, tmp, E->q);
		mpz_mul(lambda, lambda, tmp);
		mpz_mod(lambda, lambda, E->q);

		mpz_mul(S_tmp.x, lambda, lambda);
		mpz_mul_ui(tmp, P->x, 2);
		mpz_sub(S_tmp.x, S_tmp.x, tmp);
		mpz_mod(S_tmp.x, S_tmp.x, E->q);

		mpz_sub(tmp, P->x, S_tmp.x);
		mpz_mul(S_tmp.y, tmp, lambda);
		mpz_sub(S_tmp.y, S_tmp.y, P->y);
		mpz_mod(S_tmp.y, S_tmp.y, E->q);
	}

	/* output S */
	mpz_set(S->x, S_tmp.x);
	mpz_set(S->y, S_tmp.y);
	S->inf_id = S_tmp.inf_id;

	mpz_clear(lambda);
	mpz_clear(tmp);
	EC_clearPoint(&S_tmp);
}

/*
 Full Subtraction

 P2 := P0 - P1
*/
void EC_Sub(EC_POINT *P2, EC_POINT *P0, EC_POINT *P1, EC_PARAM *E)
{
EC_POINT inverP1;

	EC_initPoint(&inverP1);
	EC_invertP(&inverP1, P1, E);
	EC_Add(P2, P0, &inverP1, E);
	EC_clearPoint(&inverP1);
}

/*
 Elliptic Scalar Multiplication

 S := nP
*/
void EC_Mult(EC_POINT *S, mpz_t n, EC_POINT *P, EC_PARAM *E)
{
EC_POINT Q, S_tmp;
mpz_t k, h;
long i;
unsigned long l;

	EC_initPoint(&Q);
	EC_initPoint(&S_tmp);
	mpz_init(k);
	mpz_init(h);

	if(mpz_cmp(n, E->p) > 0)
		mpz_mod(n, n, E->p);

	mpz_set(k, n);
	i = mpz_cmp_ui(n, 0);
	if(i == 0) {
		S_tmp.inf_id = EC_O;
	} else if (i<0) {
		EC_invertP(&Q, P, E);
		mpz_neg(k,k);
	} else {
		mpz_set(Q.x, P->x);
		mpz_set(Q.y, P->y);
		Q.inf_id = P->inf_id;
	}

	mpz_mul_ui(h, k, 3);
	l = mpz_sizeinbase(h, 2)-1;
	/* printf("EC_Mult: l = %lu\n", l); */

	/* set S_tmp <- Q */
	mpz_set(S_tmp.x, Q.x);
	mpz_set(S_tmp.y, Q.y);
	/*
	printf("EC_Mult: S_tmp.x = %s\n\n", mpz_get_str(NULL, 16, S_tmp.x));
	printf("EC_Mult: S_tmp.y = %s\n\n", mpz_get_str(NULL, 16, S_tmp.y));
	*/

	for(i=l-1; i>0; i--) {
		EC_Double(&S_tmp, &S_tmp, E);
		if ( (mpz_tstbit(h, i) == 1) &&
		     (mpz_tstbit(k, i) == 0)) {
			EC_Add(&S_tmp, &S_tmp, &Q, E);
		}
		if ( (mpz_tstbit(h, i) == 0) &&
		     (mpz_tstbit(k, i) == 1)) {
			EC_Sub(&S_tmp, &S_tmp, &Q, E);
		}
	}

	/* output S */
	mpz_set(S->x, S_tmp.x);
	mpz_set(S->y, S_tmp.y);
	S->inf_id = S_tmp.inf_id;

	EC_clearPoint(&Q);
	EC_clearPoint(&S_tmp);
	mpz_clear(k);
	mpz_clear(h);
}


/*
 Initialize a point
*/
void EC_initPoint (EC_POINT *P)
{
	mpz_init(P->x);
	mpz_init(P->y);
	P->inf_id = 0;
}

/*
 Clear a point
*/
void EC_clearPoint (EC_POINT *P)
{     
   mpz_clear(P->x);
   mpz_clear(P->y);
}
