/*
 utils.h

 Copyright NTT MCL, 2000.

 Duncan S Wong   
 Security Group, NTT MCL
 July 2000

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.
 10/24/2000 - Modified WORD2BYTE function prototype.  -- S.O.
 10/25/2000 - Added get_randomseed by T. Kobayashi. -- H.O.
 08/16/2001 - WORD2BYTE: conversion is done WORD by WORD -- A.H.
 08/16/2001 - WORD2BYTE: size of BYTE buffer is in bytes  -- A.H.
 09/05/2001 - Several functions added: mpz_double_exp, GenerateP2QModulus,
	      parseLine, parse_field_using_sep, writeNum, digitSum. -- A.H.
*/

#ifndef _UTILS_H_
#define _UTILS_H_

#include <gmp.h>
#include <stdio.h>
#include "nessie.h"
#include "random.h"

/* Constants used when writing/reading numbers from file (added by A.H.)
 */
#define NAME_FIELD 		"Name"
#define DIGITS_FIELD 		"Digits"
#define DIGITSUM_FIELD 		"Digits Sum"

typedef u8  BYTE;
typedef u32  WORD;

#ifndef TRUE
#define TRUE                     1
#define FALSE                    0
#endif

#define LOG10BASE2 	(3.32192809488736)

#define ABS(x) ( (x >= 0) ? x : -x)
#define MIN(x,y) ( (x < y) ? x : y)
#define MAX(x,y) ( (x > y) ? x : y)

/* Compute the sum of digits in string */
u32 digitSum (
  const u8 *	outstr,  /* string in base 10 or 16 */
  u32 		digits   /* byte length of outstr */
);

/* Write number with format (header) to file */
void writeNum (
  mpz_t 	num, 
  const u32 	bitsizemod, 
  const u32 	base, 
  const u8 *	label,
  FILE *	out_fp
);

/* Parse a line in the format "field_id <sep> field_body" (added by A.H.) */
s32 parse_field_using_sep (s8 *one_line, s8 *field_id, s8 *field_body, s8 sep);

/* Parse one line from file into <id>: <body> and 'extract' a value
 * from <body> according to a given format; handle error detection. */
void parseLine (
  FILE *in_fp, u8 *infile,   	    /* File handler & name */
  u8   *expected_field_id,   	    /* <id> */
  u8   *expected_field_body_format, /* sscanf-type format of <body> */
  s32 	expected_line_len,     	    /* max byte size of line to read */
  void *value_ptr,		    /* ptr to return value from <body> */
  u32  *base_ptr		    /* is value decimal or hex ? */
);

/* I2OSP */
void WORD2BYTE(u8 *x_raw, mpz_t x, u32 x_raw_blen);

/* OS2IP */
u32 BYTE2WORD(mpz_t x, u8 *x_raw, u32 x_raw_blen);

/* Input/Output functions */

/* Open file for read */
FILE *open_input(const s8 *filename);

/* Open file for write */
FILE *open_output(const s8 *filename);

/* Parse one line in <field-id> = <field_body> */
s32 parse_field(s8 *one_line, s8 *field_id, s8 *field_body);

/* byte-to-byte copy (from from to to) */
void assignBYTE(u8 *to, u8 *from, u32 len);

/* One-time Pad */
u32 Vernam(u8 *K, u32 kLen, u8 *in, u8 *out);

/* Computes r = g^x*h^y mod n efficiently */
u32 mpz_double_exp (
  mpz_t r,		/* result */
  mpz_t g, 		/* first base */
  mpz_t h, 		/* second base */
  mpz_t x, 		/* first exponent */
  mpz_t y, 		/* first exponent */
  mpz_t n 		/* modulus */
);

/* Generate a OU modulus n=p^2*q of k bits. Return n, p, q. */
u32 GenerateP2QModulus (
  u32   k3,		/* desired modulus bit size */
  mpz_t n,		/* modulus */
  mpz_t p, 		/* first factor */
  mpz_t q, 		/* second factor */
  RANDOM_STRUCT *prng	/* PRNG */
);

/* Print contents of byte string in hexadecimal format */
void printAsHex (
  u8 *buf, 		/* byte string buffer */
  u32 len		/* length of buffer in bytes */
);

/* Mask Generation Function MGF1 */
void MGF1(
  u8 *out, 	/* output buffer */
  u32 outbLen, 	/* output length in bits */
  u8 *in, 	/* input string */
  u32 inLen	/* input length in bytes */
);

/* Key Derivation Function KDF2 */
void KDF2(
  u8 *out, 	/* output buffer */
  u32 outLen, 	/* output length in bytes */
  u8 *in, 	/* input */
  u32 inLen	/* input length in bytes */
);

/* Old Hash function */
void indexedSHA(BYTE *out_buffer, WORD outLen, BYTE *in, WORD inLen);

#endif /* _UTILS_H_ */
