/* 
** sha1.h
**
** Copyright NTT MCL, 2000.
**
** Satomi Okazaki
** Security Group, NTT MCL
** November 1999
**
**************************
** 13 December 1999.  In SHA1Transform, changed "buffer" to be const.
** In SHA1Update, changed "data to be const.  -- S.O.
**
** 14 September 2000.  Changed type declarations to use the ones in 
** nessie.h.  -- S.O.
*/
#ifndef __SHA1_H__
#define __SHA1_H__

#include <stdio.h>
#include <string.h>
#include "nessie.h"

#ifndef SHA1_DIGESTSIZE
#define SHA1_DIGESTSIZE  20
#endif

#ifndef SHA1_BLOCKSIZE
#define SHA1_BLOCKSIZE   64
#endif

typedef struct {
    u32 state[5];
    u32 count[2];	/* stores the number of bits */
    u8 buffer[SHA1_BLOCKSIZE];
} SHA1_CTX; 

void SHA1Transform(u32 state[5], const u8 buffer[SHA1_BLOCKSIZE]);
void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const u8 *data, u32 len);
void SHA1Final(u8 digest[SHA1_DIGESTSIZE], SHA1_CTX *context);

#endif /* __SHA1_H__ */
