/*
 utils.c

 Copyright NTT MCL, 2000.

 Duncan S Wong   
 Security Group, NTT MCL
 July 2000

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.
 10/24/2000 - Modified code for WORD2BYTE as suggested by T. Koayashi.  -- S.O.
 10/27/2000 - Modified get_pubKey to read SEid -- H.O.
 08/16/2001 - WORD2BYTE: conversion is done WORD by WORD -- A.H.
 08/16/2001 - WORD2BYTE: size of BYTE buffer is in bytes  -- A.H.
 08/27/2001 - Modified code for WORD2BYTE: conversion is done 
              WORD by WORD -- A.H.
 08/27/2001 - Implemented MGF1 & KDF2 -- A.H.
 08/30/2001 - Functions digitSum and writeNum added -- A.H.
 08/31/2001 - Functions parse_field_using_sep added -- A.H.
 09/01/2001 - Put EPOC-specific functions in 'utils-epoc2.c' -- A.H.
 09/05/2001 - Several functions added: mpz_double_exp, GenerateP2QModulus,
	      parseLine, parse_field_using_sep. -- A.H.
 09/25/2001 - Fixed a minor bug in mpz_double_exp to take care of the case where
	      there is an exponent that is zero. -- S.O.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <gmp.h>
#include <math.h>
#include "nessie.h"
#include "utils.h"
#include "random.h"
#include "sha1.h"

#include "debug.h"


/*
 Open filename for read

 Return NULL if the is any problem
*/
FILE *open_input(const s8 *filename)
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
 Open filenmae for write

 Return NULL if problem
*/
FILE *open_output(const s8 *filename)
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
 Parse a line in the format "field_id <sep> field_body" (added by A.H.)

 Error code returned was changed. (A.H.)
*/
s32 parse_field_using_sep (s8 *one_line, s8 *field_id, s8 *field_body, s8 sep)
{
  s8 *tmp1, *tmp2;
  s8 sepstr[2];

u8 line[255];
strncpy (line, one_line, 255);

  sepstr[0] = sep; sepstr[1]='\0';

  tmp1 = strtok(one_line, sepstr);
  tmp2 = strtok(NULL, " \n");
  if (tmp1 == NULL)
  {
    fprintf(stderr, 
      "error: line structure does not follow '<id>%c <value>' structure\n", 
            sep);
    return 1;
  }
  if (tmp2 == NULL) 
  {
    fprintf(stderr, 
      "error: line structure does not follow '<id>%c <value>' structure\n", 
            sep);
    return 2;
  }
  strcpy(field_id, tmp1);
  strcpy(field_body, tmp2);

  return 0;
}

void parseLine (
  FILE *in_fp, 
  u8   *infile, 
  u8   *expected_field_id, 
  u8   *expected_field_body_format,
  s32 	expected_line_len,
  void *value_ptr,
  u32  *base_ptr
)
{
  u8 *line;
  u8 *field_body;
  u8 field_id[40];
  u8 format[3];
  u8 errmsg[100];
  u32 d, error_code;

  if ( (line=(u8 *)malloc(expected_line_len)) == NULL ) {
    fprintf (stderr, "error in parseLine: out of memory.\n");
    exit(1);
  }
  if ( (field_body=(u8 *)malloc(expected_line_len)) == NULL ) {
    fprintf (stderr, "error in parseLine: out of memory.\n");
    exit(1);
  }

  fgets (line, expected_line_len, in_fp);  
  error_code = parse_field_using_sep(line, field_id, field_body, ':');
  if ( error_code > 0 ) {
    fprintf(stderr, "     : cannot parse <%s>.\n", 
            (error_code == 1)? "id": "value");
    exit(1);
  }
  if ( strcmp(field_id, expected_field_id) != 0 )
  {
    fprintf(stderr, 
      "error: found \"%s\" while expecting \"%s\" in file '%s'.\n", 
       field_id, expected_field_id, infile);
    exit(1);
  }
  if ( value_ptr != NULL && 
       (d=sscanf(field_body, expected_field_body_format, value_ptr)) != 1 ) 
  {
    fprintf(stderr, "error: unrecognizable value for '%s' in file '%s'.\n", 
             field_id, infile);
    exit(1);
  }

  if (base_ptr != NULL) {
    *base_ptr = (strstr (field_body, "0x") != NULL)? 16: 10;
  }

  free (line);
  free (field_body);
}

/*
 Parse a line in the format "field_id = field_body"
*/
s32 parse_field(s8 *one_line, s8 *field_id, s8 *field_body)
{
const s8 SEPCHARS[] = " \n";
s8 *tmp1, *tmp2, *tmp3;

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
/* WORD i; for(i=0; i<len; i++) to[i] = from[i]; */

   memcpy (to, from, len);
}

/*
 * Convert (mpz_t) m to a sequence of bytes in big-endian, (BYTE *) xp_raw
 * 
 * xp_raw_len contains the size of xp_raw in BYTES. (A.H.)
 * Conversion done in chunks of 32-bits instead of 8-bits. (A.H.)
*/
void WORD2BYTE (u8 *xp_raw, mpz_t m, u32 xp_raw_len)
{
/*   memset (xp_raw, 0, xp_raw_len); */
u32 i, w, l;
BYTE buff[sizeof(WORD)];
mpz_t x;
BYTE *xp = xp_raw;

  /* we assume xp_raw is word-aligned */
  if (xp_raw_len < (mpz_sizeinbase(m,16) >> 1))
    perror ("internal error: WORD2BYTE: buffer size too short for conversion");

  /* extract the least significant WORD of mpz number m (=x),
   * copy WORD to BYTE buffer, and then divide x by 2^{sizeof(WORD)} */
  mpz_init_set(x, m);
  xp += xp_raw_len;

  /* buffer size may not be multiple of sizeof(WORD) bytes */ 
  if ( (l = (xp_raw_len % sizeof(WORD))) > 0 )
  {  
    /* need to try trailing bytes as a special case */
    w = mpz_get_ui(x); 
    U32TO8_BIG( buff, w );
    xp -= l;
    xp_raw_len -= l;
    memcpy ( xp, buff+sizeof(WORD)-l, l );
    mpz_tdiv_q_2exp(x, x, l << 3);  /* x := x/2^(8*l) */
  }

  /* copy each word from mpz number to xp_raw buffer */
  for (i = 0; i < xp_raw_len; i += sizeof(WORD))  {
    xp -= sizeof(WORD);
    w = mpz_get_ui(x); 
    U32TO8_BIG( xp, w);
    mpz_tdiv_q_2exp(x, x, sizeof(WORD) << 3);  /* x := x/(2^32) */
  }
  mpz_clear(x);

  /* zeroize sensitive info */
  memset (buff, 0, sizeof(WORD));
}

/* Convert (big-endian) byte-string (BYTE *) raw to mpz number x.
 
 * raw_size is the size of raw buffer in bytes (A.H.)
 * Conversion done in chunks of 32-bits instead of 8-bits. (A.H.)
 */
u32 BYTE2WORD(mpz_t x, BYTE *raw, u32 raw_size)
{
  s32 l, i, rs;
  BYTE *raw_ptr = raw;
  BYTE bword[sizeof(WORD)];
  u32 word;

  /* Assume raw is WORD-aligned */
  mpz_set_ui (x,0L);

  rs = raw_size-sizeof(WORD);
  for (i=0; i<= rs; i+=sizeof(WORD), raw_ptr += sizeof(WORD)) {
    mpz_mul_2exp (x, x, (u32)(sizeof(WORD) << 3)); 
    mpz_add_ui (x, x, U8TO32_BIG(raw_ptr)); 
  }

  if (l=(raw_size % sizeof(WORD))) {
    bword[0]= bword[1]= bword[2]= bword[3]= 0;
    memcpy(bword+sizeof(WORD)-l, raw_ptr, l);
    word = U8TO32_BIG(bword);
    mpz_mul_2exp (x, x, (u32)(l << 3)); 
    mpz_add_ui (x, x, word);

    /* zeroize sensitive info */
    bword[1]= bword[2]= bword[3]= 0;
  } 
  return mpz_sizeinbase(x,16) >> 1; /* size in bytes of x */
}

/*
 One-time pad

 kLen is the length of 'K' in bits. -- A.H.
*/
u32 Vernam(u8 *K, u32 kLen, u8 *in, u8 *out)
{
u32 i=0; 
u32 kl= kLen;

   while(kLen>0) {
     out[i] = in[i] ^ K[i];
     kLen -= 8;  
     i++;
   }
   return kl/8;
}


/* 
 * Compute the sum of digits in string 'outstr' (both in hex & dec)
 */
u32 digitSum (
  const u8 *	outstr,  /* string in base 10 or 16 */
  u32 		digits   /* byte length of outstr */
)
{
  const u8 symbols[] = "0123456789abcdef";
  u8 digitStr[] ="\0\0";
  u32 i, sum = 0;

  for (i=0; i<digits; i++) 
  {
    digitStr[0] = outstr[i];
    sum += strcspn (symbols, digitStr);
  }
  return sum;
}

/* 
 * Write number with format to file
 */
void writeNum (
  mpz_t 	num, 
  const u32 	bitsizemod, 
  const u32 	base, 
  const u8 *	label,
  FILE *	out_fp
)
{
  u8 *outstr;
  u32 digits;
  u32 outstrlen;

  u8 dgformat[255];
  u8 basestr[5] = "%d"; /* default base is decimal */


  digits = mpz_sizeinbase(num, base);
  outstrlen = digits + 2; /* optional leading sign/space + trailing '\0' */

  if ((outstr=(u8 *)malloc(outstrlen)) == NULL) {
    fprintf (stderr, "error in writeNum: out of memory,\n");
    exit(1);
  }

  memset (outstr, 0, outstrlen);
  mpz_get_str (outstr, base, num);
  fprintf (out_fp, "%s: \t\t%sP2Q-%d\n", NAME_FIELD, label, bitsizemod);
  fprintf (out_fp, "%s: \t%d\n", DIGITS_FIELD, digits);
  sprintf (dgformat, "%s: \t%s\n", DIGITSUM_FIELD, (base == 16)? "0x%x": "%d");
  fprintf (out_fp, dgformat, digitSum(outstr, digits));
  fprintf (out_fp, "%s%s\n", ((base == 10)? "": "0x") , outstr);

  free(outstr);
}

/*
 * Computes r = g^x*h^y mod n efficiently
 * Uses alg. 14.88 of HAC (page 618).
 */
u32 mpz_double_exp (
  mpz_t r,		/* result */
  mpz_t g, 		/* first base */
  mpz_t h, 		/* second base */
  mpz_t x, 		/* first exponent */
  mpz_t y, 		/* first exponent */
  mpz_t n 		/* modulus */
)
{
  mpz_t gh;
  u32 ix, iy, t, tx, ty;
  u8 *I; 
  s32 i;

  /* Built array I[] of non-both-zero exponent bits */
  tx = mpz_sizeinbase (x, 2);
  ty = mpz_sizeinbase (y, 2);
  t = MAX(tx,ty);

  if ((I=(u8 *)malloc(t)) == NULL) {
    fprintf (stderr, "mpz_double_exp: out of memory.\n");
    exit(1);
  }
  memset (I, 0x00, t);

  for ( ix = iy = 0; ix < tx && iy < ty; ix++, iy++ )
  {
    ix = mpz_scan1(x, ix);
    iy = mpz_scan1(y, iy);
    I[ix] |= 0x01;
    I[iy] |= 0x02;
  }
  if (ix < tx) 
  {
    for (; ix < tx; ix++ )
    {
      ix = mpz_scan1(x, ix);
      I[ix] |= 0x01;
    } 
  } else  /* ( iy < ty ) */
  {
    for (; iy < ty; iy++ )
    {
      iy = mpz_scan1(y, iy);
      I[iy] |= 0x02;
    } 
  }

  /* This takes care of the case where the exponent is 0 */
  if (mpz_cmp_ui(x, 0) == 0)
      I[0] ^= 0x01;
  if (mpz_cmp_ui(y, 0) == 0)
      I[0] ^= 0x02;

  /* Computation core */ 
#define G(i)	((i==0x01) ? g: (i==0x02)? h : gh)

  mpz_init (gh);
  mpz_mul (gh, g, h);

  mpz_set (r, G(I[t-1]));
  for ( i = t-2; i >= 0; i--)
  {
    mpz_mul (r, r, r);
    mpz_mod (r, r, n);
    if (I[i] != 0x00) {
      mpz_mul (r, r, G(I[i]));
      mpz_mod (r, r, n);
    }
  }
  mpz_clear (gh);

  return 0;
}

/* Generate a OU modulus n=p^2*q of k bits. Return n, p, q. */
u32 GenerateP2QModulus (
  u32   k3,		/* desired modulus bit size */
  mpz_t n,		/* modulus */
  mpz_t p, 		/* first factor */
  mpz_t q, 		/* second factor */
  RANDOM_STRUCT *prng	/* PRNG */
)
{
  mpz_t r;
  u32 modulus_size, 	/* bit size modulus */
      k = k3/3;		/* bit size prime factors */
  u32 swapped = FALSE;
#ifdef VISUAL_PROGRESS_INDICATOR
  u32 ctr=0;
  u8 wsymbol[] = {'|', '/', '-', '\\'};
#endif

  mpz_init(r);

  /* draw r from {0,1}^k pseudorandomly */
  GenerateNumber (k, r, prng);
  mpz_sub_ui(r, r, 1L);
  mpz_nextprime(p,r);

#ifdef VISUAL_PROGRESS_INDICATOR
  printf("%c", wsymbol[ctr]);fflush(stdout);
#endif
  while (1) {
    /* draw r from {0,1}^k pseudorandomly */
    GenerateNumber (k, r, prng);

    /* compute prime >= r */
    mpz_sub_ui (r, r, 1L);
    mpz_nextprime (q, r);

    /* set p>q */
    if (mpz_cmp(p, q) < 0)
    {
      swapped = TRUE;
      mpz_swap (p, q);
    }

    mpz_mul(n, p, p);
    mpz_mul(n, n, q);

    modulus_size = mpz_sizeinbase (n, 2);
    if (modulus_size == k3) break; /* Found it */

    /* recycle one prime for next iteration */
    if (!swapped)
      mpz_set (p, q); 
    else {
      mpz_set (q, p); 
      swapped = FALSE;
    }
#ifdef VISUAL_PROGRESS_INDICATOR
    printf("\b%c", wsymbol[(++ctr) % 4]);fflush(stdout);
#endif
  } 
#ifdef VISUAL_PROGRESS_INDICATOR
  printf("\b");
#endif

  /* Zeroize sensitive information */
  mpz_xor (r, r, r);
  mpz_clear(r);

  return 0;
}

/* Print contents of byte string in hexadecimal format */
void printAsHex (
  u8 *buf, 		/* byte string buffer */
  u32 len		/* length of buffer in bytes */
)            
{ 
  u32 i; 
  for (i=0; i<len; i++) {           
    printf("%02x", buf[i] & 0xFF);   
  }                                     
}


/*
 Mask Generation Function 1 (MGF1)
 Conforms IEEE Std P1363-a D9, 2000

 H(x,l) := SHA(x || <0>) || SHA(x || <1>) || ... || SHA^t(x || <n>),

 where SHA(x) denotes the 160-bit result of SHA-1 applied to x and
 SHA^t(x) denotes the first t-bits of SHA(x); <i> denotes a binary
 32-bit word of the number i encoded in big-endian. t is equal to l % 160.
 where l is intended the length of the output in bits (ie. l = |H(x,l)|_2 ).

 The output l can be non-multiple of 8.
*/
void MGF1(
  u8 *out, 	/* output buffer */
  u32 outbLen, 	/* output length in BITS */
  u8 *in, 	/* input (x above) */
  u32 inLen	/* input length in bytes */
)
{
  SHA1_CTX context;
  u8 *out_ptr, index[4];
  u8 digest[20];
  u32 e, i, acc_out;
  u32 outLen = ceil(outbLen/8.0);

  out_ptr = out;
  acc_out = 0;

  U32TO8_BIG(index, 0L);
  SHA1Init(&context);
  SHA1Update(&context, in, inLen);
  SHA1Update(&context, index, 4L);

  for (i=1L; acc_out + SHA1_DIGESTSIZE < outLen; i++) {
    SHA1Final(out_ptr, &context);

    out_ptr += SHA1_DIGESTSIZE;
    acc_out += SHA1_DIGESTSIZE;

    U32TO8_BIG(index, i);
    SHA1Init(&context);
    SHA1Update(&context, in, inLen);
    SHA1Update(&context, index, 4L);
  }
  SHA1Final(digest, &context);
  memcpy (out_ptr, digest, outLen - acc_out); 

  /* If outbLen % 8 != 0, clear the 8-(outbLen % 8) rightmost bits
   * 0n the output */
  if ( (e=(outbLen % 8)) > 0 )
    out_ptr[SHA1_DIGESTSIZE] &= 0xFF << e;
}

/*
 Key Derivation Function 2 (KDF2)
 Conforms IEEE Std P1363-a D9, 2000

 H(x,l) := SHA(x || <1>) || SHA(x || <2>) || ... || SHA^t(x || <n>),

 where SHA(x) denotes the 160-bit result of SHA-1 applied to x and
 SHA^t(x) denotes the first t-bits of SHA(x); <i> denotes a binary
 32-bit word of the number i encoded in big-endian. t is equal to l % 160.
 where l is intended the length of the output in bits (ie. l = |H(x,l)|_2 ).

 Note: the algorithm is the same as MGF1 except that the counter i starts
       at 1 rather than 0.
       The output l must be multiple of 8.
*/
void KDF2(
  u8 *out, 	/* output buffer */
  u32 outLen, 	/* output length in bytes */
  u8 *in, 	/* input (x above) */
  u32 inLen	/* input length in bytes */
)
{
  SHA1_CTX context;
  u8 *out_ptr, index[4];
  u8 digest[20];
  u32 i, acc_out;

  out_ptr = out;
  acc_out = 0;

  U32TO8_BIG(index, 1L);
  SHA1Init(&context);
  SHA1Update(&context, in, inLen);
  SHA1Update(&context, index, 4L);

  for (i=2L; acc_out + SHA1_DIGESTSIZE < outLen; i++) {
    SHA1Final(out_ptr, &context);

    out_ptr += SHA1_DIGESTSIZE;
    acc_out += SHA1_DIGESTSIZE;

    U32TO8_BIG(index, i);
    SHA1Init(&context);
    SHA1Update(&context, in, inLen);
    SHA1Update(&context, index, 4L);
  }
  SHA1Final(digest, &context);
  memcpy (out_ptr, digest, outLen - acc_out); 
}

/* encode i to 4 BYTEs in big endian */
/* (required in indexedSHA) */
void encodeBigEndian(u8 *i_be, u32 i)
{
	i_be[0] = i >> 24;
	i_be[1] = (i >> 16) & 0xff;
	i_be[2] = (i >> 8) & 0xff;
	i_be[3] = i & 0xff;
}

/*
 Old Mask Generation Function

 H(x) := SHA^80(<0> || x) || SHA^80(<1> || x) || ... || SHA^L(<n> || x),

 where SHA(x) denotes the 160-bit result of SHA-1 applied to x and
 SHA^l(x) denotes the first l-bits of SHA(x); <i> denotes a binary
 32-bit word of the number i encoded in big-endian; and x is also
 encoded in decreasing significance order (i.e., in big-endian).
 n is equal to the floor of |x|/80 and L = |x| - 80n.

 len  is the length of message in bytes
 hLen is the length of the hashing value in bytes

 (A random function as described in section 2.4 of the paper "EPOC: Efficient 
 Probabilistic Public-Key Encryption" written by Tatsuaki Okamoto, Shigenori 
 Uchiyama and Eiichiro Fujisaki. Original submission to IEEE P1363a)
*/
void indexedSHA(u8 *out_buffer, u32 outLen, u8 *in, u32 inLen)
{
SHA1_CTX context;
u32 i, l, indexedLen;
u8 *in_buffer, *tmp_p;
u8 index[4];
u8 digest[20];

	if(inLen == 0) inLen = 1;

	l = outLen / 10;         /* the floor of hLen/80 in bits (now in bytes) */
	indexedLen = inLen + 4;  /* length of < index > || in */
	in_buffer = (u8 *) malloc(indexedLen);
	tmp_p = out_buffer;

	SHA1Init(&context);
	for (i=0; i<=l; i++) {
		encodeBigEndian(index, i);
		assignBYTE(in_buffer, index, 4);
		assignBYTE(in_buffer+4, in, inLen);
		SHA1Init(&context);
		SHA1Update(&context, in_buffer, indexedLen);
		SHA1Final(digest, &context);
		if(i<l)
			assignBYTE(tmp_p, digest, 10);
		else
			assignBYTE(tmp_p, digest, outLen-10*l);
		tmp_p += 10;
	}

	memset(in_buffer, 0, indexedLen);
	free(in_buffer);
}

/*******************************************************************/
/*******************************************************************/

#ifdef RUN_TEST

#include "speed.h"
#include "epoc2.h"
#include "random.h"

#define NTRIALS 		(10000)
#define VERYFY_CORRECTNESS 	1

/* Testing & speed measuring of WORD2BYTE and BYTE2WORD functions,
 * Also compares algorithm times for double modular exponentiation */
main(int argc, char **argv)
{
  u8 *buff, *buff2;
  mpz_t a,b, m;
  u32 sizeInBytes, i, j, sizeinbits;
  double time, totaltime=0;

  mpz_init_set_str (m, "1234567BCDEF123456ABCDEF123489ABCDEF456789ABCDEF12345678CDEF123456789ABF123456789ABF123456789ABCDEF126789ABCDEF12345678CDEF1234567BCDEF123456789AEF123456789ABCDEF456789ABCDEF123456789AEF123456789ABCDEF", 16);
  mpz_nextprime (m, m);

  mpz_init_set_str (a, "123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ACDEF", 16);
  mpz_init_set_ui (b, 0L);

  sizeInBytes = (mpz_sizeinbase(m,16)+1)/2;
  sizeinbits = mpz_sizeinbase(m,2);
  printf("Testing I2OSP & OS2IP conversion primitives\n\n");
  printf("number bit size : %d\n", sizeinbits);

  buff = (u8 *)malloc(sizeInBytes+1);
  buff2 = (u8 *)malloc(sizeInBytes+1);
  memset (buff, 0, sizeInBytes);
  memset (buff2, 0, sizeInBytes);

  /* I2OSP -> OS2IP -> I2OSP test */

  for (i = NTRIALS; i > 0; i--) {
    speed_starttime();
    WORD2BYTE (buff, a, sizeInBytes);
    BYTE2WORD (b, buff, sizeInBytes);
    time = speed_endtime();
    totaltime += time;

#ifdef VERYFY_CORRECTNESS 
    /* Verify correctness */
    if (mpz_cmp(a,b)) 
    {
      printf ("(trial %d) different\n a = ",i);
      mpz_out_str (stdout, 16, a);
      printf ("\n b = ");
      mpz_out_str (stdout, 16, b);
      printf ("\n");
      exit(1);
    }

    mpz_powm_ui (a, b, 3L, m); /* a = b^3 mod m */
#endif
  }
  printf ("I2OSP->OS2IP->I2OSP: average time: %10.9f secs\n", 
           totaltime/NTRIALS);

  /* OS2IP -> I2OSP -> OS2IP test */
  mpz_set_ui (a, 0L);
  memset (buff, 0, sizeInBytes);

  srand(0x01);
  for (j=0; j<sizeInBytes; j++)
    buff[j] ^= (u8)(rand() & 0xFF);

  time = 0L;
  for (i = NTRIALS; i > 0; i--) {
    speed_starttime();
    BYTE2WORD (a, buff, sizeInBytes);
    WORD2BYTE (buff2, a, sizeInBytes);
    time = speed_endtime();
    totaltime += time;

#ifdef VERYFY_CORRECTNESS 
    if (memcmp( buff,buff,sizeInBytes) ) 
      perror ("different!!\n");
    
    /* update buff */ 
    for (j=0; j<sizeInBytes; j++)
      buff[j] ^= (u8)(rand() & 0xFF);
#endif
  }
  printf ("OS2IP->I2OSP->OS2IP: Average time: %10.9f secs\n", 
           totaltime/NTRIALS);

  free (buff);
  free (buff2);
  mpz_clear(a);
  mpz_clear(b);
  mpz_clear(m);

 {
  /* 
   * Compare Times for double modular exponentiation 
   */
#define MBITSIZE 	(1152)	/* Bit size of modulus */
#undef NTRIALS
#define NTRIALS 	(100)
  EPOC2_PUB_KEY publicKey;
  EPOC2_PRIV_KEY privateKey;
  mpz_t x, y, n, gx, hy, r1, r2;
  u32 i, k3 = MBITSIZE; 
  double totaltime;

  printf ("\nDouble exponentiation Timing test (compute r= g^x*h^y mod n)\n\n");

  mpz_init(x); 
  mpz_init(y);

  /* Initialize PRNG */ 
  global_prng = InitGlobalPRNG(argv[0]);

  /* Use "real-life" bases, modulus */
  mpz_init(publicKey.n);
  mpz_init(publicKey.g);
  mpz_init(publicKey.h);
  mpz_init(privateKey.p);
  mpz_init(privateKey.q);
  mpz_init(privateKey.L_g_p_inv);
  EPOC2_KeyGeneration (k3, &(publicKey), &(privateKey));

  /* Use random exponents */
  GenerateNumber (k3, x, global_prng);
  GenerateNumber (k3, y, global_prng);

  printf ("Modulus (n) bit size: %d\n", k3);
  printf ("g: %s\n", mpz_get_str (NULL, 16, publicKey.g));
  printf ("h: %s\n", mpz_get_str (NULL, 16, publicKey.h));
  printf ("x: %s\n", mpz_get_str (NULL, 16, x));
  printf ("y: %s\n", mpz_get_str (NULL, 16, y));
  printf ("n: %s\n", mpz_get_str (NULL, 16, publicKey.n));
  
  /* Compute double exp using the naive method */
  mpz_init(r1);
  mpz_init(gx); 
  mpz_init(hy);

  totaltime = 0;
  for (i=0; i<NTRIALS; i++)
  {
    speed_starttime();
      mpz_powm(gx, publicKey.g, x, publicKey.n);
      mpz_powm(hy, publicKey.h, y, publicKey.n);
      mpz_mul(r1, gx, hy);
      mpz_mod(r1, r1, publicKey.n);
    totaltime += speed_endtime();
  }

  printf ("\nNaive Algorithm:\n");
  printf ("r= g^x*h^y (mod n) = %s\n", mpz_get_str (NULL, 16, r1));
  printf ("Average time: %10.9f secs\n", totaltime/NTRIALS);

  /* Compute double exp using the optimized method */
  mpz_init(r2);

  totaltime = 0;
  for (i=0; i<NTRIALS; i++)
  {
    speed_starttime();
      mpz_double_exp (r2, publicKey.g, publicKey.h, x, y, publicKey.n);
    totaltime += speed_endtime();
  }

  printf ("\nOptimized Algorithm:\n");
  printf ("r= g^x*h^y (mod n) = %s\n", mpz_get_str (NULL, 16, r2));
  printf ("Average time: %10.9f secs\n", totaltime/NTRIALS);
  
  if (mpz_cmp(r1,r2) != 0)
    printf ("\nError: results differ.\n");
  else
    printf ("\nResults match.\n");

  /* Finish PRNG */ 
  FinishGlobalPRNG(global_prng);

  mpz_clear(r2);
  mpz_clear(r1);
  mpz_clear(privateKey.L_g_p_inv);
  mpz_clear(privateKey.q);
  mpz_clear(privateKey.p);
  mpz_clear(publicKey.h);
  mpz_clear(publicKey.g);
  mpz_clear(publicKey.n);
  mpz_clear(hy);
  mpz_clear(gx); 
  mpz_clear(y);
  mpz_clear(x); 
 }
}
#endif

