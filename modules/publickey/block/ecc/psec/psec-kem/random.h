/*
 random.h

 Copyright NTT MCL, 2000.

 Duncan S Wong   
 Security Group, NTT MCL
 July 2000

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.
 7/23/2001 - Redesigned to implement DSS PRNG (FIPS 186) -- A.H.
 08/28/2001 - Function GetRandomBytesNeeded modified -- A.H.
 08/28/2001 - New function 'SeedPRNGfromFile' created -- A.H.
*/

#ifndef _RANDOM_H_
#define _RANDOM_H_

#include "nessie.h"
#include "random.h"
#include "sha1.h"
#include <gmp.h>

/* Constant PRNG_MOD_BLEN is parameter 'b' in DSS PRNG algorithm. 
 *  - 160 <= b <= 512 (arbitrary) if SHA-1-based G.
 *  - b = 160 if DES-based G.
 *
 * Here, SHA-1-based G is used, so we choose b=160 = 20*8
 * Notice is a multiple of 8 bits. */

#define PRNG_MOD_BLEN 		SHA1_DIGESTSIZE 

/* prng is ready to go after collecting a seed (512 bits) */
#define RANDOM_BYTES_NEEDED 	64

/* maximum number of output blocks before reseeding is needed */
#define MAX_OUT_BLOCKS		UINT_MAX

/* error codes */
#define PRNG_NO_ERROR		0	/* ok */
#define PRNG_NOT_SEEDED		1	/* need to call RandomUpdate */
#define PRNG_NO_DATA_TO_RESEED	2	/* reseeding attempted but no entropy */
#define PRNG_NOT_INIT		3	/* need to call RandomInit or 
					   InitGlobalPRNG */

/* random structure */
typedef struct {
  u32 	bytesNeeded;	   /* randomness needed to properly seed the PRNG */
  u8 	seedbuf[RANDOM_BYTES_NEEDED];  /* seed buffer (before generating output) */

  mpz_t zstate;		   /* PRNG state (PRNG_MOD_BLEN bytes) */
  u32 	outputAvailable;   /* no. of output bytes already available */
  u8 	output[SHA1_DIGESTSIZE]; /* already computed PRNG output */
  u32	maxNoOutputBlocks; /* maximum number of output blocks allowed */

  u8 	pool[PRNG_MOD_BLEN]; /* entropy-gathering pool */
  u32	bytesPool; 	   /* length of input fed to the pool */

  SHA1_CTX hashCtx;    /* just for speed; doesn't keep info across calls */
} RANDOM_STRUCT;

/* 
 * PRNG functions
 */

/* Initialize the PRNG given by randomStruct */
u32 RandomInit (
  RANDOM_STRUCT *randomStruct	/* PRNG */
);

/* Returns how many bytes of seed are required to (re)initialize PRNG */
u32 GetRandomBytesNeeded (
  u32 		*bytesNeeded,	/* same as returned value */
  RANDOM_STRUCT *randomStruct	/* PRNG */
);

/* Add new randomness (entropy) to the PRNG */
u32 RandomUpdate (
  RANDOM_STRUCT *randomStruct,	/* PRNG */
  u8 		*block,		/* new entropy */
  u32 		blockLen	/* new entropy byte size */
);

/* Initialize (seed) a PRNG using bytes from file.
 * Calls to GetRandomBytesNeeded & RandomUpdate */
u32 SeedPRNGfromFile (
  const u8	*rfile, 	/* contains enough random bytes to seed */
  RANDOM_STRUCT *randomStruct	/* PRNG */
);

/* Generate pseudorandom bytes */
u32 GenerateBytes (
  u8 		*block,		/* buffer to receive the pr bytes */
  u32 		blockLen,	/* requested number of pr bytes */
  RANDOM_STRUCT *randomStruct	/* PRNG */
);

/* Pseudorandomly generate a k-bit number */
u32 GenerateNumber (
  u32 k, 			/* desired bit length of number  */
  mpz_t n, 			/* number to generate pseudorandomly */
  RANDOM_STRUCT *randomStruct 	/* PRNG */
);

/* Reseed the PRNG given by randomStruct.
 * It requires previous calls to RandomUpdate. If there is no (enough)
 * entropy stored returns PRNG_NO_DATA_TO_RESEED. Use GetRandomBytesNeeded
 * to find out how much (random) input is still needed.  */
u32 RandomReseed (
  RANDOM_STRUCT *randomStruct	/* PRNG */
);

/* Finish PRNG given by randomStruct */
u32 RandomFinal (
  RANDOM_STRUCT *randomStruct
);

/* 
 * Global PRNG (provided for simplicity)
 *
 * It can be access by using the pre-declared pointer 'global_prng'.
 * The functions InitGlobalPRNG and FinishGlobalPRNG must be called before
 * first & after last use respectively (there is NO need to call RandomInit
 * nor RandomFinal).
 * To obtain pseudorandom bytes, just call GenerateBytes ( , , global_ptr).
 * To obtain add inputs to the PRNG, just call RandomUpdate ( , , global_ptr).
 */
#ifndef _RANDOM_C_
/* global PRNG pointer */
extern RANDOM_STRUCT *global_prng;
#endif /* _RANDOM_C_ */

/* Initialize Global PRNG from file */
RANDOM_STRUCT * InitGlobalPRNG (
  u8 *seedfile
);

/* Finish Global PRNG */
u32 FinishGlobalPRNG (
  RANDOM_STRUCT * global_prng
);

/*
 * Low-level functions
 */

/* "one-way" function as proposed by NIST (FIPS 186 apx 3.3) */
void sha1G (
  RANDOM_STRUCT *randomStruct, 
  u8 *block
);

/* Needed for EPOC-1/2/3 test programs TO_BE_REMOVED */
s32 get_randomseed(const u32 k, mpz_t rand_a, mpz_t rand_b, mpz_t rand_c,
		   const u8 *randomfile, RANDOM_STRUCT *r);
#endif /* _RANDOM_H_ */
