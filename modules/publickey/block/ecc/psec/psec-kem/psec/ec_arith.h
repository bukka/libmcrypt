/*
 ec_arith.h - elliptic curve related data structures and prototypes

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - add (unsgined char *po) to EC_POINT for representing an elliptic
           curve point in octet string format (P1363 E.2.3.2)
 9/14/2000 - changed type declarations to use those in nessie.h --S.O.
*/


typedef struct {
	mpz_t x;
	mpz_t y;
	u8 inf_id;
	u8 *po;       /* octet string format (P1363 E.2.3.2) */
} EC_POINT;

typedef struct {
	mpz_t a;
	mpz_t b;
	mpz_t q;
	u32 qLen;
	mpz_t p;
	u32 pLen;
	EC_POINT P;
} EC_PARAM;

#define EC_O      1        /* the point at infinity */

/* obtain -P */
void EC_invertP(EC_POINT *inverP, EC_POINT *P, EC_PARAM *E);

/* P2 := P0 + P1 */
void EC_Add(EC_POINT *P2, EC_POINT *P0, EC_POINT *P1, EC_PARAM *E);

/* S := 2P */
void EC_Double(EC_POINT *S, EC_POINT *P, EC_PARAM *E);

/* P2 := P0 - P1 */
void EC_Sub(EC_POINT *P2, EC_POINT *P0, EC_POINT *P1, EC_PARAM *E);

/* S := nP */
void EC_Mult(EC_POINT *S, mpz_t n, EC_POINT *P, EC_PARAM *E);

/* initialize a point */
void EC_initPoint (EC_POINT *P);

/* clear a point */
void EC_clearPoint (EC_POINT *P);
