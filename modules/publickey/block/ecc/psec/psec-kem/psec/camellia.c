/*************************************************
 *						 *
 *	Camellia Block Encryption Algorithm	 *
 *	  in ANSI-C Language : Camellia.c	 *
 *						 *
 *	    Version M1.01  April 7 2000		 *
 *    Copyright Mitsubishi Electric Corp 2000    *
 *						 *
 *************************************************/

#include <stdio.h>
#include "camellia.h"

/* 
 * CBC-IV0 Mode: Decryption
 *
 * Return the length of the plaintext in bytes.
 * If decryption is incorrect the contents of the plaintext are undefined.
 */
s32 Camellia_CBC_IV0_Decrypt ( 
  const s32 keysize, 
  const u8 *ctext, 
  const u32 ctextLen,
  const u8 *ekey, 
  u8 *ptext )
{
  u8 buffer[16];
  u8 *ptext_ptr, *ctext_ptr;
  u32 padlen, i; 
  u32 acc_out = 0;

  ctext_ptr = (u8 *)ctext;
  ptext_ptr = (u8 *)ptext;

  /* First block decryption */
  Camellia_Decrypt ( keysize, ctext_ptr, ekey, buffer );
  acc_out = 16;

  if (ctextLen > 16) /* there is more than one block */
  {
    memcpy (ptext_ptr, buffer, 16);

    /* 2nd -> (last-1) block decryption (if any) */
    for ( ; acc_out + 16 < ctextLen; acc_out += 16) 
    {
        ptext_ptr += 16;
        ctext_ptr += 16;
        Camellia_Decrypt ( keysize, ctext_ptr, ekey, buffer );
        XorBlock (buffer, ctext_ptr-16, ptext_ptr);
    }
    /* Last (if any) block decryption */
    ptext_ptr += 16;
    Camellia_Decrypt ( keysize, ctext_ptr+16, ekey, buffer );
    XorBlock (buffer, ctext_ptr, buffer);
  }

  /* last block check */
  padlen = (u32)buffer[15];
  if (padlen>16 || padlen<1) 
    return CAM_DECRYPTION_ERROR;
  for (i=16-padlen; i<16; i++)
    if (buffer[i] != buffer[15]) 
      return CAM_DECRYPTION_ERROR;
  memcpy (ptext_ptr, buffer, 16-padlen);

  return (ctextLen-padlen); /* plaintext length */
}

/* 
 * CBC-IV0 Mode: Encryption
 *
 * Return the length of the ciphertext in bytes
 */
u32 Camellia_CBC_IV0_Encrypt ( 
  const s32 keysize, 
  const u8 *ptext, 
  const u32 ptextLen,
  const u8 *ekey, 
  u8 *ctext )
{
  u8 buffer[16];
  u8 *ptext_ptr, *ctext_ptr;
  u32 padlen, tail; 
  u32 acc_out;

  tail = (ptextLen % 16);
  padlen = 16 - tail;

  ptext_ptr = (u8 *)ptext;
  ctext_ptr = (u8 *)ctext;

  if (ptextLen >= 16) 
  {
    /* first block */
    Camellia_Encrypt ( keysize, ptext_ptr, ekey, ctext_ptr );

    /* 2nd -> (last-1) block */
    for ( acc_out = 16; acc_out + 16 <= ptextLen; acc_out += 16) 
    {
      ptext_ptr += 16;
      XorBlock (ptext_ptr, ctext_ptr, buffer);
      ctext_ptr += 16;
      Camellia_Encrypt ( keysize, buffer, ekey, ctext_ptr );
    }
    /* prepare last block */
    memcpy (buffer, ptext_ptr+16, tail);
    memset (buffer + tail, (0xFF & padlen), padlen);
    XorBlock (buffer, ctext_ptr, buffer);
    ctext_ptr += 16;
  } 
  else 
  {
    /* only one block */
    memcpy (buffer, ptext_ptr, tail);
    memset (buffer + tail, (0xFF & padlen), padlen);
  }
  /* encrypt last block */
  Camellia_Encrypt ( keysize, buffer, ekey, ctext_ptr );

  return (ptextLen+padlen); /* ciphertext length */
}
/*********************************************************/


const u8 SIGMA[48] = {
0xa0,0x9e,0x66,0x7f,0x3b,0xcc,0x90,0x8b,
0xb6,0x7a,0xe8,0x58,0x4c,0xaa,0x73,0xb2,
0xc6,0xef,0x37,0x2f,0xe9,0x4f,0x82,0xbe,
0x54,0xff,0x53,0xa5,0xf1,0xd3,0x6f,0x1c,
0x10,0xe5,0x27,0xfa,0xde,0x68,0x2d,0x1d,
0xb0,0x56,0x88,0xc2,0xb3,0xe6,0xc1,0xfd};

const s32 KSFT1[26] = {
0,64,0,64,15,79,15,79,30,94,45,109,45,124,60,124,77,13,
94,30,94,30,111,47,111,47 };
const s32 KIDX1[26] = {
0,0,4,4,0,0,4,4,4,4,0,0,4,0,4,4,0,0,0,0,4,4,0,0,4,4 };
const s32 KSFT2[34] = {
0,64,0,64,15,79,15,79,30,94,30,94,45,109,45,109,60,124,
60,124,60,124,77,13,77,13,94,30,94,30,111,47,111,47 };
const s32 KIDX2[34] = {
0,0,12,12,8,8,4,4,8,8,12,12,0,0,4,4,0,0,8,8,12,12,
0,0,4,4,8,8,4,4,0,0,12,12 };

const u8 SBOX[256] = {
112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
 35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
 20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
 16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
 82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
 64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158};

#define SBOX1(n) SBOX[(n)]
#define SBOX2(n) (u8)((SBOX[(n)]>>7^SBOX[(n)]<<1)&0xff)
#define SBOX3(n) (u8)((SBOX[(n)]>>1^SBOX[(n)]<<7)&0xff)
#define SBOX4(n) SBOX[((n)<<1^(n)>>7)&0xff]

void Camellia_Ekeygen( const s32 n, const u8 *k, u8 *e )
{
	u8 t[64];
	u32 u[20];
	s32  i;

	if( n == 128 ){
		for( i=0 ; i<16; i++ ) t[i] = k[i];
		for( i=16; i<32; i++ ) t[i] = 0;
	}
	else if( n == 192 ){
		for( i=0 ; i<24; i++ ) t[i] = k[i];
		for( i=24; i<32; i++ ) t[i] = k[i-8]^0xff;
	}
	else if( n == 256 ){
		for( i=0 ; i<32; i++ ) t[i] = k[i];
	}

	XorBlock( t+0, t+16, t+32 );

	Camellia_Feistel( t+32, SIGMA+0, t+40 );
	Camellia_Feistel( t+40, SIGMA+8, t+32 );

	XorBlock( t+32, t+0, t+32 );

	Camellia_Feistel( t+32, SIGMA+16, t+40 );
	Camellia_Feistel( t+40, SIGMA+24, t+32 );

	ByteWord( t+0,  u+0 );
	ByteWord( t+32, u+4 );

	if( n == 128 ){
		for( i=0; i<26; i+=2 ){
			RotBlock( u+KIDX1[i+0], KSFT1[i+0], u+16 );
			RotBlock( u+KIDX1[i+1], KSFT1[i+1], u+18 );
			WordByte( u+16, e+i*8 );
		}
	}
	else{
		XorBlock( t+32, t+16, t+48 );

		Camellia_Feistel( t+48, SIGMA+32, t+56 );
		Camellia_Feistel( t+56, SIGMA+40, t+48 );

		ByteWord( t+16, u+8  );
		ByteWord( t+48, u+12 );

		for( i=0; i<34; i+=2 ){
			RotBlock( u+KIDX2[i+0], KSFT2[i+0], u+16 );
			RotBlock( u+KIDX2[i+1], KSFT2[i+1], u+18 );
			WordByte( u+16, e+(i<<3) );
		}
	}
}

void Camellia_Encrypt( const s32 n, const u8 *p, const u8 *e, u8 *c )
{
	s32 i;

	XorBlock( p, e+0, c );

	for( i=0; i<3; i++ ){
		Camellia_Feistel( c+0, e+16+(i<<4), c+8 );
		Camellia_Feistel( c+8, e+24+(i<<4), c+0 );
	}

	Camellia_FLlayer( c, e+64, e+72 );

	for( i=0; i<3; i++ ){
		Camellia_Feistel( c+0, e+80+(i<<4), c+8 );
		Camellia_Feistel( c+8, e+88+(i<<4), c+0 );
	}

	Camellia_FLlayer( c, e+128, e+136 );

	for( i=0; i<3; i++ ){
		Camellia_Feistel( c+0, e+144+(i<<4), c+8 );
		Camellia_Feistel( c+8, e+152+(i<<4), c+0 );
	}

	if( n == 128 ){
		SwapHalf( c );
		XorBlock( c, e+192, c );
	}
	else{
		Camellia_FLlayer( c, e+192, e+200 );

		for( i=0; i<3; i++ ){
			Camellia_Feistel( c+0, e+208+(i<<4), c+8 );
			Camellia_Feistel( c+8, e+216+(i<<4), c+0 );
		}

		SwapHalf( c );
		XorBlock( c, e+256, c );
	}
}

void Camellia_Decrypt( const s32 n, const u8 *c, const u8 *e, u8 *p )
{
	s32 i;

	if( n == 128 ){
		XorBlock( c, e+192, p );
	}
	else{
		XorBlock( c, e+256, p );

		for( i=2; i>=0; i-- ){
			Camellia_Feistel( p+0, e+216+(i<<4), p+8 );
			Camellia_Feistel( p+8, e+208+(i<<4), p+0 );
		}

		Camellia_FLlayer( p, e+200, e+192 );
	}

	for( i=2; i>=0; i-- ){
		Camellia_Feistel( p+0, e+152+(i<<4), p+8 );
		Camellia_Feistel( p+8, e+144+(i<<4), p+0 );
	}

	Camellia_FLlayer( p, e+136, e+128 );

	for( i=2; i>=0; i-- ){
		Camellia_Feistel( p+0, e+88+(i<<4), p+8 );
		Camellia_Feistel( p+8, e+80+(i<<4), p+0 );
	}

	Camellia_FLlayer( p, e+72, e+64 );

	for( i=2; i>=0; i-- ){
		Camellia_Feistel( p+0, e+24+(i<<4), p+8 );
		Camellia_Feistel( p+8, e+16+(i<<4), p+0 );
	}

	SwapHalf( p );
	XorBlock( p, e+0, p );
}

void Camellia_Feistel( const u8 *x, const u8 *k, u8 *y )
{
	u8 t[8];

	t[0] = SBOX1(x[0]^k[0]);
	t[1] = SBOX2(x[1]^k[1]);
	t[2] = SBOX3(x[2]^k[2]);
	t[3] = SBOX4(x[3]^k[3]);
	t[4] = SBOX2(x[4]^k[4]);
	t[5] = SBOX3(x[5]^k[5]);
	t[6] = SBOX4(x[6]^k[6]);
	t[7] = SBOX1(x[7]^k[7]);

	y[0] ^= t[0]^t[2]^t[3]^t[5]^t[6]^t[7];
	y[1] ^= t[0]^t[1]^t[3]^t[4]^t[6]^t[7];
	y[2] ^= t[0]^t[1]^t[2]^t[4]^t[5]^t[7];
	y[3] ^= t[1]^t[2]^t[3]^t[4]^t[5]^t[6];
	y[4] ^= t[0]^t[1]^t[5]^t[6]^t[7];
	y[5] ^= t[1]^t[2]^t[4]^t[6]^t[7];
	y[6] ^= t[2]^t[3]^t[4]^t[5]^t[7];
	y[7] ^= t[0]^t[3]^t[4]^t[5]^t[6];
}

void Camellia_FLlayer( u8 *x, const u8 *kl, const u8 *kr )
{
	u32 t[4],u[4],v[4];

	ByteWord( x, t );
	ByteWord( kl, u );
	ByteWord( kr, v );

	t[1] ^= (t[0]&u[0])<<1^(t[0]&u[0])>>31;
	t[0] ^= t[1]|u[1];
	t[2] ^= t[3]|v[1];
	t[3] ^= (t[2]&v[0])<<1^(t[2]&v[0])>>31;

	WordByte( t, x );
}

void ByteWord( const u8 *x, u32 *y )
{
	s32 i;
	for( i=0; i<4; i++ ){
		y[i] = ((u32)x[(i<<2)+0]<<24) + ((u32)x[(i<<2)+1]<<16)
		     + ((u32)x[(i<<2)+2]<<8 ) + ((u32)x[(i<<2)+3]<<0 );
	}
}

void WordByte( const u32 *x, u8 *y )
{
	s32 i;
	for( i=0; i<4; i++ ){
		y[(i<<2)+0] = (u8)(x[i]>>24&0xff);
		y[(i<<2)+1] = (u8)(x[i]>>16&0xff);
		y[(i<<2)+2] = (u8)(x[i]>> 8&0xff);
		y[(i<<2)+3] = (u8)(x[i]>> 0&0xff);
	}
}

void RotBlock( const u32 *x, const s32 n, u32 *y )
{
	s32 r;
	if( r = (n & 31) ){
		y[0] = x[((n>>5)+0)&3]<<r^x[((n>>5)+1)&3]>>(32-r);
		y[1] = x[((n>>5)+1)&3]<<r^x[((n>>5)+2)&3]>>(32-r);
	}
	else{
		y[0] = x[((n>>5)+0)&3];
		y[1] = x[((n>>5)+1)&3];
	}
}

void SwapHalf( u8 *x )
{
	u8 t;
	s32  i;
	for( i=0; i<8; i++ ){
		t = x[i];
		x[i] = x[8+i];
		x[8+i] = t;
	}
}

void XorBlock( const u8 *x, const u8 *y, u8 *z )
{
	s32 i;
	for( i=0; i<16; i++ ) z[i] = x[i] ^ y[i];
}

/****************************************************************
 * Some tests 
 ****************************************************************/
#ifdef RUN_TEST

#define TRUE	1
#define FALSE	0

#define MAXPLEN		(16*30+13)
void main( void )
{
  const s32 keysize = 128; /* must be 128, 192 or 256 */

  const u8 ptext[16] = {
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
		0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
  const u8 key[32] = {
		0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
		0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
		0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };

  u32 plen, clen, c, error = FALSE;
  u8 ctext[16],rtext[16],ekey[CAM_EKEY_BLEN];
  u8 *ptextcbc, *ctextcbc, *rtextcbc;
  s32  i;

  /* Basic test */
  printf( "Plaintext  " );
  for( i=0; i<16; i++ ) printf( "%02x ", ptext[i] );
  printf( "\n%dbit Key ", keysize );
  for( i=0; i<keysize/8; i++ ) printf( "%02x ", key[i] );
  printf( "\n" );

  Camellia_Ekeygen( keysize, key, ekey );

  Camellia_Encrypt( keysize, ptext, ekey, ctext );

  printf( "Ciphertext " );
  for( i=0; i<16; i++ ) printf( "%02x ", ctext[i] );
  printf( "\n" );

  Camellia_Decrypt( keysize, ctext, ekey, rtext );

  printf( "Plaintext  " );
  for( i=0; i<16; i++ ) printf( "%02x ", rtext[i] );
  printf( "\n" );

  /* 
   * Test CBC-IV0 Mode 
   */
  printf( "\nTesting CBC-IV0 Mode: " );
  ptextcbc = (u8 *)malloc(MAXPLEN);
  srand(0);

  for (plen=0; plen<MAXPLEN; plen++) 
  {
	/* Some random-looking messages */
	for (i=0; i<plen; i++) {
	    ptextcbc[i]= 0xFF & rand();
	}

	clen = (plen/16+1)*16;
  	ctextcbc = (u8 *)malloc(clen);
  	rtextcbc = (u8 *)malloc(clen);
	memset (ctextcbc, 0, clen);
	memset (rtextcbc, 0, clen);

	Camellia_CBC_IV0_Encrypt( keysize, ptextcbc, plen, ekey, ctextcbc );
	c = Camellia_CBC_IV0_Decrypt( keysize, ctextcbc, clen, ekey, rtextcbc );

#if 0
        printf( "\nPlaintext length: %d\n", plen);
        printf( "Plaintext  " );
        for( i=0; i<plen; i++ ) printf( "%02x", ptextcbc[i] ); printf( "\n");
        printf( "Ciphertext " );
        for( i=0; i<clen; i++ ) printf( "%02x", ctextcbc[i] ); printf( "\n");
        printf( "Plaintext  " );
        for( i=0; i<plen; i++ ) printf( "%02x", rtextcbc[i] ); printf( "\n");
#endif

        if (c != 0 || (memcmp(ptextcbc, rtextcbc, plen) != 0) )
	{
	  error = TRUE;
  	  free(ctextcbc);
  	  free(rtextcbc);
	  break;
	}
  	free(ctextcbc);
  	free(rtextcbc);
  }

  if (error)
  {
    printf ("\nDecryption incorrect\n");
    printf( "Plaintext length: %d\n\n", plen);
    printf( "Plaintext  " );
    for( i=0; i<plen; i++ ) printf( "%02x", ptextcbc[i] ); printf( "\n" );
    printf( "Ciphertext " );
    for( i=0; i<clen; i++ ) printf( "%02x", ctextcbc[i] ); printf( "\n" );
    printf( "Plaintext  " );
    for( i=0; i<plen; i++ ) printf( "%02x", rtextcbc[i] ); printf( "\n" );
  }
  else
     printf ("All decryptions correct\n");

  free(ptextcbc);
}
#endif

