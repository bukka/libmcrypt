#ifndef __SQHASH_H
#define __SQHASH_H

/**
 *	Hashing support.
 *
 *	IMPORTANT REMARK: input buffers to the hashing functions
 *	must be word-aligned on machines requiring it.
 */

#include "square.h"

/* Matyas-Meyer-Oseas single block length hashing scheme: */
typedef struct {
	squareBlock digest;
	squareBlock block; /* context data block */
	unsigned occupied; /* number of occupied bytes in the data block */
	word32 byteCount[2]; /* 64-bit message byte count (byteCount[0]: low word, byteCount[1]: high word) */
	squareKeySchedule roundKeys;
} squareHashContext;

/**
 * Initialize a Square hashing context.
 */
void squareHashInit(squareHashContext *ctxHash);

/**
 * Updates a Square hashing context with a data buffer dataBuffer of length dataLength.
 */
void squareHashUpdate(squareHashContext *ctxHash, const byte *dataBuffer, unsigned dataLength);

/**
 * Finished evaluation of a 128-bit Square digest, clearing the context.
 */
void squareHashFinal(squareHashContext *ctxHash, squareBlock digest);

/**
 * Hash a single message dataBuffer of length dataLength into a 128-bit Square digest.
 */
void squareHash(const byte *dataBuffer, unsigned dataLength, squareBlock digest);

#if 0
/**
 * Hash a single message dataBuffer of length dataLength into a 128-bit Square digest
 * using the Knudsen-Preneel double block length hashing scheme.
 */
void squareHashKP(const byte *dataBuffer, unsigned dataLength, byte digest[2*SQUARE_BLOCKSIZE]);
#endif

#endif /* __SQHASH_H */
