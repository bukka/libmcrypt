/*
 random.c

 Copyright NTT MCL, 2000.

 Duncan S Wong   
 Security Group, NTT MCL
 July 2000
*/

#include "random.h"
#include "sha1.h"

#define RANDOM_BYTES_NEEDED 256

int RandomInit (RANDOM_STRUCT *randStruct)
{
  randStruct->bytesNeeded = RANDOM_BYTES_NEEDED;
  memset ((unsigned char *)randStruct->state, 0, sizeof(randStruct->state));
  randStruct->outputAvailable = 0;
  
  return (0);
}


int RandomUpdate (
RANDOM_STRUCT *randStruct,
unsigned char *block,
unsigned int blockLen
)
{
SHA1_CTX context;
unsigned char digest[20];
unsigned int i, x;
  
  SHA1Init (&context);
  SHA1Update (&context, block, blockLen);
  SHA1Final (digest, &context);

  /* add digest to state */
  x = 0;
  for (i = 0; i < 20; i++) {
    x += randStruct->state[19-i] + digest[19-i];
    randStruct->state[19-i] = (unsigned char)x;
    x >>= 8;
  }
  
  if (randStruct->bytesNeeded < blockLen)
    randStruct->bytesNeeded = 0;
  else
    randStruct->bytesNeeded -= blockLen;
  
  /* Zeroize sensitive information. */
  memset ((unsigned char *)digest, 0, sizeof (digest));
  x = 0;
  
  return (0);
}


int GetRandomBytesNeeded(unsigned int *bytesNeeded, RANDOM_STRUCT *randStruct)
{
  *bytesNeeded = randStruct->bytesNeeded;
  
  return (0);
}


int GenerateBytes (
unsigned char *block,
unsigned int blockLen,
RANDOM_STRUCT *randStruct
)
{
SHA1_CTX context;
unsigned int available, i;
  
  if (randStruct->bytesNeeded)
    return (0x0408);
  
  available = randStruct->outputAvailable;
  
	while (blockLen > available) {
		memcpy ((unsigned char *)block,
		        (unsigned char *)&randStruct->output[20-available], available);
		block += available;
		blockLen -= available;

		/* generate new output */
		SHA1Init (&context);
		SHA1Update (&context, randStruct->state, 20);
		SHA1Final (randStruct->output, &context);
		available = 16;

		/* increment state */
		for (i = 0; i < 20; i++)
		if (randStruct->state[19-i]++)
			break;
	}

	memcpy ((unsigned char *)block,
	        (unsigned char *)&randStruct->output[16-available], blockLen);
	randStruct->outputAvailable = available - blockLen;

	return (0);
}


void RandomFinal (RANDOM_STRUCT *randStruct)
{
	memset ((unsigned char *)randStruct, 0, sizeof (*randStruct));
}

