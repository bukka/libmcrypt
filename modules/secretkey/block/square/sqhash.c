/**
 *	The following hashing scheme is described in
 *	Matyas, S.M., Meyer, C.H. and Oseas, J.,
 *	"Generating Strong One-Way Functions with Cryptographic Algorithm",
 *	IBM Technical Disclosure Bulletin 27, 10A(1985), p. 5658-5659,
 *	and also in Schneier, B., "Applied Cryptography" (2nd ed), 1996.
 *
 *	Let the symbol || represent string concatenation, and length(s)
 *	to be the length of string s.  Given a string m, let M = m || P,
 *	where P consists of a single "1" bit, followed by enough "0" bits
 *	to make	length(m || "1") mod 128 = 64, followed by the 64-bit
 *	representation of length(m) in big-endian order, so that
 *	length(M) mod 128 = 0, i.e. length(M) = 128*n for some n.
 *	Let M_1, M_2, ... M_n be the n 128-bit blocks of M.  Define hash(m)
 *  recursively by:
 *		H_0 = <128-bit constant>
 *		H_i = encrypt(M_i, H_{i-1}) xor M_i
 *		hash(m) = H_n
 *	where encrypt(p, k) represents the Square ciphertext corresponding
 *	to the plaintext p under key k.  In this implementation we choose
 *	the <128-bit constant> to consist of 128 zero bits.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "square.h"
#include "sqhash.h"


/* platform endianness: */
#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#	if defined(_M_IX86) || defined(_M_I86) || defined(__alpha)
#		define LITTLE_ENDIAN
#	else
#		error "Either LITTLE_ENDIAN or BIG_ENDIAN must be defined"
#	endif
#elif defined(LITTLE_ENDIAN) && defined(BIG_ENDIAN)
#	error "LITTLE_ENDIAN and BIG_ENDIAN must not be simultaneously defined"
#endif /* !LITTLE_ENDIAN && !BIG_ENDIAN */


#define D(p)((word32 *)(p))

#define byteReverse(w) \
{ \
	rev = (w); \
	rev = (rev << 16) | (rev >> 16); \
	(w) = ((rev & 0xff00ff00UL) >> 8) ^ ((rev & 0x00ff00ffUL) << 8); \
} /* byteReverse */

#define squareHashStep(roundKeys, msgDigest, msgStream) \
{ \
	squareExpandKey(msgDigest, roundKeys); \
	D(msgDigest)[0]  = D(msgStream)[0]; \
	D(msgDigest)[1]  = D(msgStream)[1]; \
	D(msgDigest)[2]  = D(msgStream)[2]; \
	D(msgDigest)[3]  = D(msgStream)[3]; \
	squareEncrypt(D(msgDigest), roundKeys); \
	D(msgDigest)[0] ^= D(msgStream)[0]; \
	D(msgDigest)[1] ^= D(msgStream)[1]; \
	D(msgDigest)[2] ^= D(msgStream)[2]; \
	D(msgDigest)[3] ^= D(msgStream)[3]; \
} /* squareHashStep */


/**
 * Initialize a Square hashing context.
 */
void squareHashInit(squareHashContext *ctxHash) {
	assert(ctxHash != NULL);
	memset(ctxHash, 0, sizeof(squareHashContext));
} /* squareHashInit */


/**
 * Update a Square hashing context with a data buffer dataBuffer of length dataLength.
 */
void squareHashUpdate(squareHashContext *ctxHash, const byte *dataBuffer, unsigned dataLength) {
	assert(ctxHash != NULL);
	assert(dataBuffer != NULL);
	assert(ctxHash->occupied < SQUARE_BLOCKSIZE); /* invariant */

	/* update byte count: */
	if ((word32)dataLength > 0xFFFFFFFFUL - ctxHash->byteCount[0]) {
		ctxHash->byteCount[1]++;
	}
	ctxHash->byteCount[0] += (word32)dataLength;
	
	/* if the data buffer is not enough to complete the context data block, just append it: */
	if (ctxHash->occupied + (word32)dataLength < SQUARE_BLOCKSIZE) { /* N.B. typecast avoids 16-bit overflow */
		memcpy(&ctxHash->block[ctxHash->occupied], dataBuffer, dataLength);
		ctxHash->occupied += dataLength;
		assert(ctxHash->occupied < SQUARE_BLOCKSIZE);
		return; /* delay processing */
	}

	/* complete the context data block: */
	memcpy(&ctxHash->block[ctxHash->occupied], dataBuffer, SQUARE_BLOCKSIZE - ctxHash->occupied);
	dataBuffer += SQUARE_BLOCKSIZE - ctxHash->occupied;
	dataLength -= SQUARE_BLOCKSIZE - ctxHash->occupied;

	/* process the completed context data block: */
	squareHashStep(ctxHash->roundKeys, ctxHash->digest, ctxHash->block);
	/* process data in chunks of SQUARE_BLOCKSIZE bytes: */
	while (dataLength >= SQUARE_BLOCKSIZE) {
		squareHashStep(ctxHash->roundKeys, ctxHash->digest, dataBuffer);
		dataBuffer += SQUARE_BLOCKSIZE;
		dataLength -= SQUARE_BLOCKSIZE;
	}

	/* delay processing of remaining data: */
	memcpy(ctxHash->block, dataBuffer, dataLength);
	ctxHash->occupied = dataLength; /* < SQUARE_BLOCKSIZE */
	
	assert(ctxHash->occupied < SQUARE_BLOCKSIZE);
} /* squarehashUpdate */


/**
 * Finish evaluation of a Square digest, clearing the context.
 */
void squareHashFinal(squareHashContext *ctxHash, squareBlock digest) {
#ifdef LITTLE_ENDIAN
	word32 rev; // needed by byteReverse()
#endif /* ?LITTLE_ENDIAN */
	assert(ctxHash != NULL);
	assert(ctxHash->occupied < SQUARE_BLOCKSIZE);
	assert(digest != NULL);
	/* append toggle to the message (there's always at least one byte left): */
	ctxHash->block[ctxHash->occupied++] = 0x80; /* big-endian convention */
	/* pad with null bytes to make the message 64 (mod 128) bits long: */
	if (ctxHash->occupied > SQUARE_BLOCKSIZE - 8) {
		/* no room for length field on the current block */
		memset(&ctxHash->block[ctxHash->occupied], 0, SQUARE_BLOCKSIZE - ctxHash->occupied);
		/* process the completed message chunk: */
		squareHashStep(ctxHash->roundKeys, ctxHash->digest, ctxHash->block);
		memset(ctxHash->block, 0, SQUARE_BLOCKSIZE - 8);
	} else {
		memset(&ctxHash->block[ctxHash->occupied], 0, SQUARE_BLOCKSIZE - 8 - ctxHash->occupied);
	}
	/* append length field in big-endian order (N.B. in bits, not bytes): */
	D(ctxHash->block)[2] = (ctxHash->byteCount[1] << 3) + (ctxHash->byteCount[0] >> 29);
	D(ctxHash->block)[3] = (ctxHash->byteCount[0] << 3);
#ifdef LITTLE_ENDIAN
	byteReverse(D(ctxHash->block)[2]);
	byteReverse(D(ctxHash->block)[3]);
#endif /* ?LITTLE_ENDIAN */
	/* process the last padded message chunk: */
	squareHashStep(ctxHash->roundKeys, ctxHash->digest, ctxHash->block);
	memcpy(digest, ctxHash->digest, SQUARE_BLOCKSIZE);
	/* destroy potentially sensitive information: */
#ifdef DESTROY_TEMPORARIES
	memset(ctxHash, 0, sizeof(squareHashContext));
#	ifdef LITTLE_ENDIAN
	rev = 0L;
#	endif /* ?LITTLE_ENDIAN */
#endif /* ?DESTROY_TEMPORARIES */
} /* squareHashFinal */


/**
 * Hash a single message msgStream of length msgLength into the 128-bit msgDigest
 */
void squareHash(const byte *msgStream, unsigned msgLength, squareBlock msgDigest) {
	unsigned bytes = msgLength;
	word32 roundKeys[R+1][4];
	squareBlock msgToggle;
#ifdef LITTLE_ENDIAN
	word32 rev; // needed by byteReverse()
#endif /* ?LITTLE_ENDIAN */

	memset(msgDigest, 0, SQUARE_BLOCKSIZE);
	while (msgLength >= SQUARE_BLOCKSIZE) {
		squareHashStep(roundKeys, msgDigest, msgStream);
		msgStream += SQUARE_BLOCKSIZE;
		msgLength -= SQUARE_BLOCKSIZE;
	}
	/* handle the last 0 <= msgLength < SQUARE_BLOCKSIZE bytes: */
	memcpy(msgToggle, msgStream, msgLength);
	/* append toggle to the message(there's always at least one byte left): */
	msgToggle[msgLength++] = 0x80; /* big-endian convention */
	/* pad with null bytes to make the message 64 (mod 128) bits long: */
	if (msgLength > SQUARE_BLOCKSIZE - 8) {
		/* no room for length field on the current block */
		memset(&msgToggle[msgLength], 0, SQUARE_BLOCKSIZE - msgLength);
		/* process the completed message chunk: */
		squareHashStep(roundKeys, msgDigest, msgToggle);
		memset(msgToggle, 0, SQUARE_BLOCKSIZE - 8);
	} else {
		memset(&msgToggle[msgLength], 0, SQUARE_BLOCKSIZE - 8 - msgLength);
	}
	/* append length field in big-endian order (N.B. in bits, not bytes): */
	D(msgToggle)[2] = (word32)bytes >> 29;
	D(msgToggle)[3] = (word32)bytes <<  3;
#ifdef LITTLE_ENDIAN
	byteReverse(D(msgToggle)[2]);
	byteReverse(D(msgToggle)[3]);
#endif /* ?LITTLE_ENDIAN */
	/* process the last padded message chunk: */
	squareHashStep(roundKeys, msgDigest, msgToggle);
#ifdef DESTROY_TEMPORARIES
	/* destroy potentially sensitive information: */
	bytes = 0;
	memset(roundKeys, 0, sizeof(roundKeys));
	memset(msgToggle, 0, sizeof(msgToggle));
#	ifdef LITTLE_ENDIAN
	rev = 0L;
#	endif /* ?LITTLE_ENDIAN */
#endif /* ?DESTROY_TEMPORARIES */
} /* squareHash */
