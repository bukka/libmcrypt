/*
 random.c

 Alejandro Hevia
 Copyright NTT MCL, 2001.

 Security Group, NTT MCL
 July 2001

 01/07/2000 - First version created. -- Duncan S Wong
 09/14/2000 - Changed type declarations to match those in nessie.h -- S.O.

 07/23/2001 - Rewritten to implement DSS PRNG (FIPS 186) -- A.H.
 08/28/2001 - Function GetRandomBytesNeeded modified -- A.H.
 08/28/2001 - New function 'SeedPRNGfromFile' created -- A.H.
 08/29/2001 - 'get_randomseed' moved here -- A.H.
 09/03/2001 - 'get_randomseed' returns 0 instead of 1 -- A.H.
 
 Notes: 
 - This implementation follows FIPS 186 appendix 3.3 (using SHA-1)
   except:
    1. To avoid Blaichenbacher's attack, there is NO reduction modulo q
       on the PRNG output.
    2. The PRNG user inputs are handled differently.
      (a) The implementation does not feed the user inputs directly into 
          the (FIPS 186 PRNG) output generation algorithm. Instead, it hashes 
          them down and accumulates them in a 'pool'. This pool is used to 
	  reseed the PRNG after a certain number (MAX_OUT_BLOCKS < 2^64) of 
	  output block generations. 
      (b) The output generation algorithm (function GenerateBytes()) sets 
          its optional user input (XSEEDj in FIPS 186, apdx 3.3) to zero before 
          generating each output block. This is actually allowed in the PRNG
	  specification in FIPS 186 appendix 3.3.
      (b) The reseeding process is computed in a "standard" way:
          new_state = H(previous_state || pool).
*/

#define _RANDOM_C_

#include <math.h>
#include <stdio.h>
#include <errno.h>
#include "random.h"
#include "debug.h"

/* 
 * Global PRNG (see random.h)
 */
RANDOM_STRUCT *global_prng;

/* global constants (for efficiency) */
static mpz_t one; /* mpz constant one */
static mpz_t two2pow; /* mpz constant modulus */

/* 
 * Initialize PRNG 
 */
u32 RandomInit (RANDOM_STRUCT *randStruct)
{
  /* prng is still NOT seeded */
  randStruct->bytesNeeded = RANDOM_BYTES_NEEDED;

  /* clear state, pool seed buffer & set limits */
  mpz_init_set_ui (randStruct->zstate, 0L);
  randStruct->outputAvailable = 0;
  memset ((u8 *)randStruct->pool, 0, sizeof(randStruct->pool));
  randStruct->bytesPool = 0;
  memset ((u8 *)randStruct->seedbuf, 0, sizeof(randStruct->seedbuf));
  randStruct->maxNoOutputBlocks = MAX_OUT_BLOCKS;

  /* init global constants */
  mpz_init_set_ui (one, 1L);
  mpz_init (two2pow);
  mpz_ui_pow_ui (two2pow, 2L, (u32)(PRNG_MOD_BLEN << 3));
  
  return PRNG_NO_ERROR;
}

/* 
 * Update PRNG state with new input 
 */
u32 RandomUpdate (
  RANDOM_STRUCT *randStruct,     /* prng context */
  u8 		*block,	         /* input */
  u32 		blockLen         /* input length */
)
{
  u8	auxbuff[SHA1_DIGESTSIZE];
  u8 	*blockptr;
  u32 	blen;

  if (randStruct == NULL) return PRNG_NOT_INIT;

  blockptr = block;
  blen = blockLen;

  if (blen == 0) return PRNG_NO_ERROR; /* nothing happens */
  if (randStruct->bytesNeeded > 0)
  {
    /* Initial seeding is not complete */
    if (blen < randStruct->bytesNeeded) 
    {
      /* not enough seed, save it for later */
      memcpy (
       (u8 *)(randStruct->seedbuf+RANDOM_BYTES_NEEDED-randStruct->bytesNeeded),
        blockptr, blen);
      randStruct->bytesNeeded -= blen;
      return PRNG_NO_ERROR;
    } 
    /* complete the seed buffer */
    memcpy (
      (u8 *)(randStruct->seedbuf+RANDOM_BYTES_NEEDED-randStruct->bytesNeeded), 
       blockptr, randStruct->bytesNeeded);
    blockptr += randStruct->bytesNeeded;
    blen     -= randStruct->bytesNeeded;

    /* compute initial state as state = H( seedbuf ) */
    SHA1Init (&(randStruct->hashCtx)); 	
    SHA1Update (&(randStruct->hashCtx), 
		randStruct->seedbuf, RANDOM_BYTES_NEEDED);	
    SHA1Final (auxbuff, &(randStruct->hashCtx));	

    /* transform seed buffer into mpz number (the PRNG state) */
    BYTE2WORD (randStruct->zstate, auxbuff, PRNG_MOD_BLEN);
    randStruct->bytesNeeded = 0;

    /* if there is more input use it for state update; otw return */
    if (blen == 0) return PRNG_NO_ERROR;
  }

  /* Bulk input processing 
   *
   * Design note: The update operation is no more than hashing down 
   *     the current pool (state) concatenated with the new input.
   *     Namely:  new_pool = H(previous_pool || input)
   */
  SHA1Init (&(randStruct->hashCtx)); 	
  SHA1Update (&(randStruct->hashCtx), randStruct->pool, PRNG_MOD_BLEN);	
  SHA1Update (&(randStruct->hashCtx), blockptr, blen);	
  SHA1Final (randStruct->pool, &(randStruct->hashCtx));	
  randStruct->bytesPool += blen;

  /* Zeroize sensitive information */
  memset (auxbuff, 0, SHA1_DIGESTSIZE);
  blen = 0;

  return PRNG_NO_ERROR;
}

/* Number of bytes are needed to complete seeding of PRNG
 * Function returns this value (A.H.)
 */
u32 GetRandomBytesNeeded(u32 *bytesNeeded, RANDOM_STRUCT *randStruct)
{
  /* If PRNG is not initialized we cannot return PRNG_NOT_INIT (>0) !!!
   * Instead we fool the caller so next PRNG call triggers the error */
  if (randStruct == NULL) return 0; 

  *bytesNeeded = randStruct->bytesNeeded;
  return (randStruct->bytesNeeded);
}

/* Generate pseudorandom bytes */

u32 GenerateBytes (
u8 *block,
u32 blockLen,
RANDOM_STRUCT *randStruct
)
{
u32 available;
u8 auxbuff[PRNG_MOD_BLEN];
mpz_t zaux;
u32 return_code = PRNG_NO_ERROR; 

  if (randStruct == NULL) return PRNG_NOT_INIT;

  /* Is the prng seeded? */
  if (randStruct->bytesNeeded) return PRNG_NOT_SEEDED; 

  /* Initializations */
  mpz_init_set_ui (zaux, 0L);
  
  if (!randStruct->maxNoOutputBlocks)
  {
    /* max no. of output blocks exceeded; we need to reseed */
    return_code = RandomReseed (randStruct);
    /* If return_code is PRNG_NO_DATA_TO_RESEED, return output anyway 
     * but forward return code */
  } else
    randStruct->maxNoOutputBlocks--;

  /* There may be output available from previous output generation */
  available = randStruct->outputAvailable;
  
  /* Generate and copy prng output */
  while (blockLen > available) {
    /* copy prng output (if any) to user buffer */
    memcpy ((u8 *)block,
            (u8 *)&randStruct->output[SHA1_DIGESTSIZE-available], available);
    block += available;
    blockLen -= available;

    /* 
     * generate new output 
     */

    /* In FIPS 186 apdx 3.1, prng output is G(state + optional_user_input)
     * Here, optional_user_input = 0. 
     * To avoid Blaichenbacher's attack, there is NO reduction modulo q
     * on the output. */

    /* transform prng state (zstate) into byte array */	
    WORD2BYTE (auxbuff, randStruct->zstate, PRNG_MOD_BLEN);

    /* Compute randStruct->output = G(state); */
    sha1G (randStruct, auxbuff);
    /* randStruct->output now contains the PRNG output */
    available = SHA1_DIGESTSIZE;

    /* 
     * update prng state 
     */

    /* transform output into mpz_t number */		
    BYTE2WORD (zaux, randStruct->output, SHA1_DIGESTSIZE);	
    /* update state: new state S_{i+1} = H(Si+ti) + S_i + 1 */	
    mpz_add (zaux, zaux, randStruct->zstate);			
    mpz_add (randStruct->zstate, zaux, one);			
    mpz_mod (randStruct->zstate, randStruct->zstate, two2pow);
  }

  /* copy last chunk of prng output to user buffer */
  memcpy ((u8 *)block, 
          (u8 *)&randStruct->output[SHA1_DIGESTSIZE-available], blockLen);
  randStruct->outputAvailable = available - blockLen;

  /* Zeroize sensitive information */
  memset (auxbuff, 0, PRNG_MOD_BLEN);
  mpz_clear (zaux);
  available = 0;

  return (return_code);
}

/* Reseed the PRNG given by randomStruct.
 * It requires previous calls to RandomUpdate. If there is no (enough)
 * entropy stored returns PRNG_NO_DATA_TO_RESEED. Use GetRandomBytesNeeded
 * to find out how much (random) input is still needed.  
 */
u32 RandomReseed (RANDOM_STRUCT *randStruct)
{ 
  u8 auxbuff[PRNG_MOD_BLEN];

  if (randStruct == NULL) return PRNG_NOT_INIT;
  if (randStruct->bytesPool) {
    /* reseed from pool; new_state = H(previous_state || pool) */

    /* transform zstate to byte string */
    WORD2BYTE (auxbuff, randStruct->zstate, PRNG_MOD_BLEN);
    /* compute hash */
    SHA1Init (&(randStruct->hashCtx)); 	
    SHA1Update (&(randStruct->hashCtx), auxbuff, PRNG_MOD_BLEN);	
    SHA1Update (&(randStruct->hashCtx), 
		  randStruct->pool, PRNG_MOD_BLEN);	
    SHA1Final (randStruct->pool, &(randStruct->hashCtx));	
      
    /* transform new pool to mpz number (zstate, the new prng state)  */
    BYTE2WORD (randStruct->zstate, randStruct->pool, PRNG_MOD_BLEN);
    return PRNG_NO_ERROR;
  } 
  else 
    /* no input has been fed since last reseed! */
    return  PRNG_NO_DATA_TO_RESEED;
}

/* Finish PRNG given by randomStruct 
 */
u32 RandomFinal (RANDOM_STRUCT *randStruct)
{
  if (randStruct == NULL) return PRNG_NOT_INIT;
  mpz_clear (randStruct->zstate);

  memset ((u8 *)randStruct->seedbuf, 0, RANDOM_BYTES_NEEDED);
  memset ((u8 *)randStruct->output, 0, SHA1_DIGESTSIZE);
  memset ((u8 *)randStruct->pool, 0, PRNG_MOD_BLEN);
  memset ((u8 *)&(randStruct->hashCtx), 0, sizeof(SHA1_CTX)); 
}

/*
 * Seed PRNG using randomness from file
 * Assume file contains at least RANDOM_BYTES_NEEDED 'random' bytes
 */
u32 SeedPRNGfromFile (const u8 *rfile, RANDOM_STRUCT *r)
{
  FILE *fp;
  u32 n=RANDOM_BYTES_NEEDED;
  u32 bytes;
  u8 *buffer;

  if (r == NULL) return PRNG_NOT_INIT;
  if ( (fp = (FILE *)open_input(rfile)) == NULL) {
    exit(1);
  }
  
  if ( (buffer = (u8 *)malloc(RANDOM_BYTES_NEEDED)) == NULL) {
        fprintf(stderr, "error in SeedPRNGfromFile: out of memory.\n");
        exit (1); 
  }

  while (GetRandomBytesNeeded (&n, r) > 0) {
    if ( (bytes = fread (buffer, 1, n, fp)) < n ) {
      if ( ferror(fp) ) {
        fprintf(stderr, "error while reading randomness file '%s' : %s\n", 
                rfile, strerror(errno));
        exit (1); 
      } 
      if ( feof(fp) ) {
        fprintf(stderr, 
	   "error: not enough bytes in file '%s' to seed PRNG.\n", rfile);
        fprintf(stderr, "(bytes expected: %d, bytes read: %d).\n",
	   RANDOM_BYTES_NEEDED, bytes);
        exit (1); 
      } 
      fprintf(stderr, "error in SeedPRNGfromFile: unkown error\n");
      exit (1); 
    }
    RandomUpdate (r, buffer, bytes);
  }

  /* zeroize sensitive information */
  memset (buffer, 0, RANDOM_BYTES_NEEDED);

  free (buffer);
  fclose(fp);
}

/* 
 * Pseudorandomly generate a mpz number of exactly k bits 
 */
u32 GenerateNumber (
  u32 k, 		/* desired bit length of number  */
  mpz_t n, 		/* number to generate pseudorandomly */
  RANDOM_STRUCT *r 	/* PRNG */
)	
{
  u8 *buffer;
  u32 bufferlen;
  u32 e, c;

  if (r == NULL) return PRNG_NOT_INIT;

  /* Assert (n is initialized by caller) */

  /* buffer to store pseudorandom bytes */
  bufferlen = ceil (k/8.0);
  if ((buffer = (u8 *)malloc(bufferlen)) == NULL)
  {
     fprintf (stderr, "error in GenerateNumber: out of memory,\n");
     exit(1);
  }

  /* 
   * Generate number
   */
  c = GenerateBytes (buffer, bufferlen, r);
  if (c != PRNG_NO_ERROR) return c;

  /* if k is not a multiple of 8, clear the unwanted most significant bits 
   * Set most significant bit to 1 so it is exactly k bit long.  */
  if ( (e=(k % 8)) > 0 ) {
    buffer[0] &= 0xFF >> (8-e);
    buffer[0] |= 0x01 << (e-1);
  } else
    buffer[0] |= 0x80;

  /* Convert byte string into mpz number */
  BYTE2WORD (n, buffer, bufferlen);

  return PRNG_NO_ERROR;
}

/*
 * Global PRNG functions 
 */

/* Initialize Global PRNG */
RANDOM_STRUCT * InitGlobalPRNG (
  u8 *seedfile
)
{
  global_prng = (RANDOM_STRUCT *)malloc(sizeof(RANDOM_STRUCT));
  RandomInit (global_prng);
  SeedPRNGfromFile (seedfile, global_prng);
  return global_prng;
}

/* Finish Global PRNG */
u32 FinishGlobalPRNG (
  RANDOM_STRUCT * global_prng
)
{
  if (global_prng == NULL) 
    return PRNG_NOT_INIT;
  else {
    RandomFinal (global_prng); 
    free(global_prng);  
  } 
  return PRNG_NO_ERROR;
}

/* 
 * low-level functions
 */

/* G function based on SHA-1 as defined in FIPS 186 apdx 3.3 
 */
void sha1G (RANDOM_STRUCT *randStruct, u8 *cblock)
{
u32 i, j, k;
u8 *output = randStruct->output;
u8 buff[64];

    /* For SHA1-based G, initialization vector T is equal to SHA-1 
     * constants H1..H5 so we call SHAInit() anyway */
    SHA1Init (&(randStruct->hashCtx)); 	

    /* cblock is zero padded upto 512 bits ( =64 bytes) */
    memcpy (buff, cblock, PRNG_MOD_BLEN);
    memset ((u8 *)(buff+PRNG_MOD_BLEN), 0, 64-PRNG_MOD_BLEN);

    /* Performs main step in sha-based G */
    SHA1Transform ((randStruct->hashCtx).state, buff);		

    /* Store state in output */
    for (i = 0, j = 0; j < 20; i++, j += 4)  {
        output[j  ] = (u8)(((randStruct->hashCtx).state[i] >> 24) & 0xff);
        output[j+1] = (u8)(((randStruct->hashCtx).state[i] >> 16) & 0xff);
        output[j+2] = (u8)(((randStruct->hashCtx).state[i] >> 8) & 0xff);
        output[j+3] = (u8)(((randStruct->hashCtx).state[i]) & 0xff);
    }
}

/*
 Read random seed info from a file  add by kotetsu 10/24

 Return 1 if succeed, otherwise 0
*/
s32 get_randomseed (
  const u32 k,          /* bit length of rand_a, rand_b and rand_c */
  mpz_t rand_a, 
  mpz_t rand_b, 
  mpz_t rand_c,
  const u8 *randomfile, 
  RANDOM_STRUCT *r)
{
  mpz_t n;
  u8 *buffer;
  u32 bufferlen;
  u32 e, i;

  mpz_init (n);

  bufferlen = ceil (k/8.0);
  if ((buffer = (u8 *)malloc(bufferlen)) == NULL)
  {
     fprintf (stderr, "error in get_randomseed: out of memory,\n");
     exit(1);
  }

  /* Seed the PRNG */
  SeedPRNGfromFile (randomfile, r);

  /* 
   * Generate rand_a, rand_b, rand_c
   */
  for (i=0; i<3; i++)
  {
    GenerateBytes (buffer, bufferlen, r);
    /* if k is not a multiple of 8, clear the unwanted most significant bits 
     * Set most significant bit to 1 so it is exactly k bit long.  */
    if ( (e=(k % 8)) > 0 ) {
      buffer[0] &= 0xFF >> (8-e);
      buffer[0] |= 0x01 << (e-1);
    } else
      buffer[0] |= 0x80;

    /* Convert byte string into mpz number */
    BYTE2WORD (n, buffer, bufferlen);
    mpz_set ((i==0)? rand_a: ((i==1)? rand_b: rand_c), n);
  }

  mpz_clear (n);
  
  return PRNG_NO_ERROR;
}

#ifdef RUN_TEST

#include "speed.h"
#include "camellia.h"

#define T	(10000)
#define MPZOPS_PER_BLOCK	(30)

/* Prototype for G_from_ANSI which implements ANSI PRNG
 * See ansi/generators3.c
 */
void G_from_ANSI(u8 *t, u8 *c, u8 *G);

main(int argc, char **argv)
{
 u32 i, k, n, c;
 mpz_t zero, zob, z, two;
 RANDOM_STRUCT r;
 u8 digest[SHA1_DIGESTSIZE], key[128], ekey[272];
 u8 *output, byte;
 double time;
 
 output = (u8 *)malloc((T+4)*SHA1_DIGESTSIZE);
 if (output == NULL) { 
   fprintf (stderr, "main: out of memory!\n");
   exit(1);
 }
 memset ((u8 *)output, 0, (T+4)*SHA1_DIGESTSIZE);

 mpz_init_set_ui (zero, 0L);
 mpz_init_set_ui (zob, 0L);
 mpz_init_set_ui (z, 0L);
 mpz_init_set_ui (two, 2L);

 /* DSS PRNG */
 RandomInit (&r);
 /* Use (no-so-random) input to initialize the PRNG */
 /* use srand(time(NULL)) if does not need reproducibility */
 srand(0); 
 while(1) {
   GetRandomBytesNeeded(&n, &r);
   if (n == 0) break;
   byte = 0xFF & rand();
   RandomUpdate (&r, &byte, 1);
 };

 speed_starttime();
 c = GenerateBytes (output, T*SHA1_DIGESTSIZE, &r);
 time = speed_endtime();

 printf ("DSS PRNG> time: %10.9f secs\n", time);
 printf ("DSS PRNG> rate: %10.9f Mbits/sec\n", T*SHA1_DIGESTSIZE*8/(1048576*time));

 /* Reseed forced */
 for (i=0; i< (u32)rand() % 1000; i++) {
   byte = 0xFF & rand();
   RandomUpdate (&r, &byte, 1);
 };
 RandomReseed (&r);

 speed_starttime();
 c = GenerateBytes (output, T*SHA1_DIGESTSIZE, &r);
 time = speed_endtime();

 printf ("DSS PRNG (reseeded)> time: %10.9f secs\n", time);
 printf ("DSS PRNG (reseeded)> rate: %10.9f Mbits/sec\n", T*SHA1_DIGESTSIZE*8/(1048576*time));

 /* Try Global PRNG */
 global_prng = InitGlobalPRNG (argv[0]);  /* initialization from the binary... 
 				 	     why not ? */
 speed_starttime();
 c = GenerateBytes (output, T*SHA1_DIGESTSIZE, global_prng);
 time = speed_endtime();

 printf ("DSS PRNG (global)> time: %10.9f secs\n", time);
 printf ("DSS PRNG (global)> rate: %10.9f Mbits/sec\n", T*SHA1_DIGESTSIZE*8/(1048576*time));
 FinishGlobalPRNG(global_prng); 

 /* Compare with one full SHA1 operation per block */
 speed_starttime();
 for (k=0; k<T; k++) {
    SHA1Init(&(r.hashCtx));
    SHA1Update(&(r.hashCtx), (u8 *)(output+k*20), 20);
    SHA1Final(digest, &(r.hashCtx));
 }
 time = speed_endtime();

 printf ("SHA1> time: %10.9f secs\n", time);
 printf ("SHA1> rate: %10.9f Mbits/sec\n", T*SHA1_DIGESTSIZE*8/(1048576*time));

 /* Compare with two Camellia encryption per block */

 memset (key, 0x17, 20); /* will need 20 bytes later (for ANSI) */
 memset (ekey, 0, 272); /* extended key */
 Camellia_Ekeygen( 128, key, ekey );

 speed_starttime();
 for (k=0; k<T; k++) {
    Camellia_Encrypt( 128, (u8 *)(output+k*20), ekey, digest);
    Camellia_Encrypt( 128, (u8 *)(output+(k+1)*20), ekey, digest);
 }
 time = speed_endtime();

 printf ("CAM> time: %10.9f secs\n", time);
 printf ("CAM> rate: %10.9f Mbits/sec\n", T*128/(1048576*time));

 /* Compare with one SHA1Transform per block */
 speed_starttime();
 for (k=0; k<T; k++) {
    SHA1Init(&(r.hashCtx));
    SHA1Transform(r.hashCtx.state, (u8 *)(output+k*20));
 }
 time = speed_endtime();

 printf ("SHAT> time: %10.9f secs\n", time);
 printf ("SHAT> rate: %10.9f Mbits/sec\n", T*SHA1_DIGESTSIZE*8/(1048576*time));

 /* Compare with one SHA1Transform + MPZOPS_PER_BLOCK mpz-number operations 
  * per block */
 speed_starttime();
 for (k=0; k<T; k++) {
    SHA1Init(&(r.hashCtx));
    SHA1Transform(r.hashCtx.state, (u8 *)(output+k*20));
    for (i=0; i<MPZOPS_PER_BLOCK; i++)
      mpz_add (z, z, one);
 }
 time = speed_endtime();

 printf ("SHAT+%d-MPZ> time: %10.9f secs\n", MPZOPS_PER_BLOCK, time);
 printf ("SHAT+%d-MPZ> rate: %10.9f Mbits/sec\n", MPZOPS_PER_BLOCK, 
 	T*SHA1_DIGESTSIZE*8/(1048576*time));

 /* Compare with DSS PRNG implementation by ANSI */
 speed_starttime();
 for (k=0; k<T; k++) {
   G_from_ANSI (key, output+(k+1)*20, output+k*20);
 }
 time = speed_endtime();

 printf ("ANSI PRNG> time: %10.9f secs\n", time);
 printf ("ANSI PRNG> rate: %10.9f Mbits/sec\n", T*SHA1_DIGESTSIZE*8/(1048576*time));
 RandomFinal (&r); 

 free(output); 
}
#endif
