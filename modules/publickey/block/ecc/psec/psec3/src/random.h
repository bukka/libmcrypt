/*
 random.h

 Copyright NTT MCL, 2000.

 Duncan S Wong   
 Security Group, NTT MCL
 July 2000
*/


/* random structure */
typedef struct {
  unsigned int bytesNeeded;
  unsigned char state[20];
  unsigned int outputAvailable;
  unsigned char output[20];
} RANDOM_STRUCT;


int RandomInit (RANDOM_STRUCT *randomStruct);


int RandomUpdate (
RANDOM_STRUCT *randomStruct,
unsigned char *block,
unsigned int blockLen
);


int GetRandomBytesNeeded (
unsigned int *bytesNeeded,
RANDOM_STRUCT *randomStruct
);


int GenerateBytes (
unsigned char *block,
unsigned int blockLen,
RANDOM_STRUCT *randomStruct
);


void RandomFinal (RANDOM_STRUCT *randomStruct);
