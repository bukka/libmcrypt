/* 
** sha1.c
**
** Contains all of the SHA1 functions: SHA1Transform, SHA1Init, SHA1Update, and SHA1Final.
**
** Copyright NTT MCL, 2000.
**
** Satomi Okazaki
** Security Group, NTT MCL
**
**************************
** 13 December 1999.  In SHA1Transform, changed "buffer" to be const.
** In SHA1Update, changed "data to be const.  -- S.O.
**
** 14 September 2000.  Removed the endian-ness check.  -- S.O.
**
** 17 October 2000.  Fixed an endian bug that was introduced by the removal
** of the endian-ness check.  -- S.O.
**
** 27 August 2001. Fixed error in comment in main processing loop of
** "SHA1Update": "64-bit" -> "64-byte". -- A.H.
**
*/
#include "sha1.h"
#include "nessie.h"

/* Rotation of "value" by "bits" to the left */
#define rotLeft(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* Basic SHA1 functions */
#define f(u,v,w) (((u) & (v)) | ((~u) & (w)))
#define g(u,v,w) (((u) & (v)) | ((u) & (w)) | ((v) & (w)))
#define h(u,v,w) ((u) ^ (v) ^ (w))

/* Used in expanding from a 16 word block into an 80 word block  */
#define X(i) (words[(i)%16] = rotLeft (words[((i)-3)%16] ^ words[((i)-8)%16] \
                              ^ words[((i)-14)%16] ^ words[((i)-16)%16], 1))


/* (R0+R1), R2, R3, R4 are the different round operations used in SHA1 */
#define R0(a, b, c, d, e, i) { \
    (e) += f((b), (c), (d)) + (words[i]) + 0x5A827999 + rotLeft((a),5); \
    (b) = rotLeft((b), 30); \
}
#define R1(a, b, c, d, e, i)  { \
    (e) += f((b), (c), (d)) + (X(i)) + 0x5A827999 + rotLeft((a),5); \
    (b) = rotLeft((b), 30); \
}
#define R2(a, b, c, d, e, i) { \
    (e) += h((b), (c), (d)) + (X(i)) + 0x6ED9EBA1 + rotLeft((a),5); \
    (b) = rotLeft((b), 30); \
}
#define R3(a, b, c, d, e, i)  { \
    (e) += g((b), (c), (d)) + (X(i)) + 0x8F1BBCDC + rotLeft((a),5); \
    (b) = rotLeft((b), 30); \
}
#define R4(a, b, c, d, e, i)  { \
    (e) += h((b), (c), (d)) + (X(i)) + 0xCA62C1D6 + rotLeft((a),5); \
    (b) = rotLeft((b), 30); \
}

/* Hashes a single 512-bit block. This is the compression function - the core of the algorithm.
**/
void SHA1Transform(
                   u32       state[5], 
                   const u8 buffer[SHA1_BLOCKSIZE]
                   )
{
    u32 a, b, c, d, e;
    u32 words[16];
    int i;

    /* Convert the big-endian buffer of chars to a collection of words */
    for (i = 0; i < 16; ++i) {
        words[i] = U8TO32_BIG(buffer+4*i);
    }

    /* Initialize working variables */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. */
    /* Round 1 */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e, 10); R0(e,a,b,c,d, 11);
    R0(d,e,a,b,c, 12); R0(c,d,e,a,b, 13); R0(b,c,d,e,a, 14); R0(a,b,c,d,e, 15);
    R1(e,a,b,c,d, 16); R1(d,e,a,b,c, 17); R1(c,d,e,a,b, 18); R1(b,c,d,e,a, 19);

    /* Round 2 */
    R2(a,b,c,d,e, 20); R2(e,a,b,c,d, 21); R2(d,e,a,b,c, 22); R2(c,d,e,a,b, 23);
    R2(b,c,d,e,a, 24); R2(a,b,c,d,e, 25); R2(e,a,b,c,d, 26); R2(d,e,a,b,c, 27);
    R2(c,d,e,a,b, 28); R2(b,c,d,e,a, 29); R2(a,b,c,d,e, 30); R2(e,a,b,c,d, 31);
    R2(d,e,a,b,c, 32); R2(c,d,e,a,b, 33); R2(b,c,d,e,a, 34); R2(a,b,c,d,e, 35);
    R2(e,a,b,c,d, 36); R2(d,e,a,b,c, 37); R2(c,d,e,a,b, 38); R2(b,c,d,e,a, 39);

    /* Round 3 */
    R3(a,b,c,d,e, 40); R3(e,a,b,c,d, 41); R3(d,e,a,b,c, 42); R3(c,d,e,a,b, 43);
    R3(b,c,d,e,a, 44); R3(a,b,c,d,e, 45); R3(e,a,b,c,d, 46); R3(d,e,a,b,c, 47);
    R3(c,d,e,a,b, 48); R3(b,c,d,e,a, 49); R3(a,b,c,d,e, 50); R3(e,a,b,c,d, 51);
    R3(d,e,a,b,c, 52); R3(c,d,e,a,b, 53); R3(b,c,d,e,a, 54); R3(a,b,c,d,e, 55);
    R3(e,a,b,c,d, 56); R3(d,e,a,b,c, 57); R3(c,d,e,a,b, 58); R3(b,c,d,e,a, 59);

    /* Round 4 */
    R4(a,b,c,d,e, 60); R4(e,a,b,c,d, 61); R4(d,e,a,b,c, 62); R4(c,d,e,a,b, 63);
    R4(b,c,d,e,a, 64); R4(a,b,c,d,e, 65); R4(e,a,b,c,d, 66); R4(d,e,a,b,c, 67);
    R4(c,d,e,a,b, 68); R4(b,c,d,e,a, 69); R4(a,b,c,d,e, 70); R4(e,a,b,c,d, 71);
    R4(d,e,a,b,c, 72); R4(c,d,e,a,b, 73); R4(b,c,d,e,a, 74); R4(a,b,c,d,e, 75);
    R4(e,a,b,c,d, 76); R4(d,e,a,b,c, 77); R4(c,d,e,a,b, 78); R4(b,c,d,e,a, 79);    

    /* Update the chaining values */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}

/* SHA1Init - Initialize new context.
**/
void SHA1Init(
              SHA1_CTX* context
              )
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

/* Run your data through this.  This will call the compression function SHA1Transform for each
** 64-byte block of data.
**/
void SHA1Update(
                SHA1_CTX*            context, 
                const u8* data, 
                u32        dataLen
                )
{
    u32 numByteDataProcessed; /* Number of bytes processed so far */
    u32 numByteInBuffMod64;   /* Number of bytes in the buffer mod 64 */
    
    numByteInBuffMod64 = (context->count[0] >> 3) % 64;

    /* Adding in the number of bits of data */
    if ((context->count[0] += dataLen << 3) < (dataLen << 3))   {
        context->count[1]++;	/* add in the carry bit */
    }
    context->count[1] += (dataLen >> 29);

    /* If there is at least one block to be processed... */
    if ((numByteInBuffMod64 + dataLen) > 63) {

        /* Copy over 64-numByteInBuffMod64 bytes of data to the end of buffer */
        memcpy(&context->buffer[numByteInBuffMod64], data, 
            (numByteDataProcessed = 64 - numByteInBuffMod64));
		
        /* Perform the transform on the buffer */
        SHA1Transform(context->state, context->buffer);

        /* As long as there are 64-byte blocks of data remaining, transform each one. */
        for ( ; numByteDataProcessed + 63 < dataLen; numByteDataProcessed += 64) {
            SHA1Transform(context->state, &data[numByteDataProcessed]);
        }
        
        numByteInBuffMod64 = 0;
    }
    /* Else there is not enough to process one block. */
    else 
        numByteDataProcessed = 0;

    /* Copy over the remaining data into the buffer */
    memcpy(&context->buffer[numByteInBuffMod64], &data[numByteDataProcessed], 
        dataLen - numByteDataProcessed);
}

/* Add padding and return the message digest.
**/
void SHA1Final(
               u8 digest[SHA1_DIGESTSIZE], 
               SHA1_CTX*     context
               )
{
    u32 i, j;
    u8 numBits[8];
    
    /* Record the number of bits */
    for (i = 1, j = 0; j < 8; i--, j += 4) {
        numBits[j] = (u8)((context->count[i] >> 24) & 0xff);
        numBits[j+1] = (u8)((context->count[i] >> 16) & 0xff);
        numBits[j+2] = (u8)((context->count[i] >> 8) & 0xff);
        numBits[j+3] = (u8)(context->count[i] & 0xff);
    }

    /* Add padding */
    SHA1Update(context, (u8 *)"\200", 1);
    while ((context->count[0] & 504) != 448)
        SHA1Update(context, (u8 *)"\0", 1);
    
    /* Append length */
    SHA1Update(context, numBits, 8);  /* Should cause a SHA1Transform() */

    /* Store state in digest */
    for (i = 0, j = 0; j < 20; i++, j += 4)  {
        digest[j] = (u8)((context->state[i] >> 24) & 0xff);
        digest[j+1] = (u8)((context->state[i] >> 16) & 0xff);
        digest[j+2] = (u8)((context->state[i] >> 8) & 0xff);
        digest[j+3] = (u8)((context->state[i]) & 0xff);
    }

    /* Wipe variables */
    i = 0;
    j = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(&numBits, 0, 8);
}
