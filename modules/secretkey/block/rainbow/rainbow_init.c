
#include "rainbow.h"

typedef BYTE base[8]; 

BYTE RDC[15]; /* polynomial,p(x), reduction table */
BYTE MTX[8]; /* basis changing matrix */

static BYTE field_mul (BYTE a, BYTE b);
static void make_MTX (base b1, base b2);
static BYTE coef_cnv (BYTE coef, base MATRIX);


int cipherInit(cipherInstance *cipher, BYTE mode, char *IV)
{
	BYTE *vector,irrpoly=0xa9, g, t1,t2,t3,t;
	base pb, nb;  /* pb: standard basis;  nb: normal basis */
	int i, j;


	if (cipher == NULL) return BAD_CIPHER_STATE;
	if (!((1<=mode)&&(mode<=3))) return BAD_CIPHER_MODE;

	vector = IV;

	cipher->mode = mode;
	cipher->blockSize = 16;  /* fixed here */
	strncpy(cipher->IV,vector,BLOCKSIZE);
//	for (i=0; i<BLOCKSIZE; i++) cipher->IV[i] = vector[i];

	/*---> start: make RDC */
	for (i=0;i<8;i++) RDC[i] = 1<<i;
	RDC[8] = irrpoly;  /* = 00011011 <- x^8 + x^4 + x^3 + x + 1 */

	for (i=9;i<15;i++) {
		if (RDC[i-1]&0x80) {
			RDC[i] = (BYTE)(RDC[i-1]<<1)^irrpoly;
		}
		else {
			RDC[i] = RDC[i-1]<<1;
		}
	} /* complete: make RDC */

	/* ----> start : make basis conversion matrix, MTX */
	for (i=0; i<8; i++) pb[i] = (1<<i);
	nb[0] = 2;
	for (j=1; j<8; j++) nb[j] = field_mul(nb[j-1], nb[j-1]);
	make_MTX(pb, nb);
	/* complete: make basis conversion matrix, MTX */

	/* final step for generating the S-box Table RED */
	cipher->RED[0]= cipher->RED[256]= 0;
	for (g=255; g>0; g--) {
		t1 = field_mul(g,g); 
		t2 = field_mul(t1,t1);
		t3 = field_mul(t2,g);
		t1 = field_mul(t2,t2);
		t2 = field_mul(t1,t1);
		t1 = field_mul(t2,t2);
		t  = coef_cnv(field_mul(t1,t3),MTX); /* coefficient changing to 
											  over normal basis */
		t1 = coef_cnv(g,MTX); /* convert g in normal basis coordinates */
		cipher->RED[t1] = t;  /* store g^(37) into RED[g] in normal basis 
		                    coordinates */
		cipher->RED[256+t] = t1; /* store its inverse = g^(193) in normal 
		                    basis coord.*/
	} /* The S-box, RED, has been generated */

	return TRUE;
}

/* this is the field multiplication function over GF(2^8) with 
   the field defining polynomial x^8 + x^4 + x^3 + x + 1 */
static BYTE field_mul (BYTE a, BYTE b)
{
	int cf_a, cf_b;
    BYTE w=0, cf;  

	for (cf_a=0; cf_a < 8; cf_a++) {
		for (cf_b=0; cf_b < 8; cf_b++) {
			cf = ((a>>cf_a)&(b>>cf_b))&1;
			if (cf) w ^= RDC[cf_a+cf_b];
		}
	}
	return w; 
}

/* generate the base conversion matrix of basis b1 to b2 */
static void make_MTX (base b1, base b2)
{
	unsigned short cf, i, j;
	BYTE tmp[8], d;

	for (i=0; i<8; i++) {
		for (cf=0; cf<256; cf++) {
			d = 0;
			for (j=0; j<8; j++) d ^= (((cf>>j)&1)*b2[j]);
			if (d == b1[i]) {
				tmp[i] = (BYTE)cf;
				cf = 257;
			}
		}
	}

	for (i=0; i<8; i++) {
		MTX[i] = 0;
		for (j=0; j<8; j++) MTX[i] ^= (((tmp[j]>>i)&1)<<j);
	}
	return;
}

#define PROD(C, A, B, k) /* inner product routine */ \
{ \
	C = A&B;     \
	C ^= (C>>4); \
	C ^= (C>>2); \
	C ^= (C>>1); \
	C &= 1;      \
}
/* coefficient conversion of coef via basis changing mtx, MTX */
static BYTE coef_cnv (BYTE coef, base MATRIX)
{
	BYTE t=0, w=0;
	int i;

	for (i=0; i<8; i++) {
		PROD(t, MATRIX[i], coef, i);
		w |= (t<<i);
	}
	return w;
}

