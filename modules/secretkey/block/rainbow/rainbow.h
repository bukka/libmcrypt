/***************************************************** 
 * Rainbow Cipher header file for ANSI C             *
 *   Chang-Hyi Lee  and  Jeong-Soo Kim                *
 *   Digital Communication Lab.,                     *
 *   SAIT, Samsung Advanced Institute of Technology  *
 *****************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>
#include <assert.h>
#include <string.h>
//#include "rainbow_tbl.h"

/*  Defines:  */
#define     BITSPERBLOCK    128  /*  Number of bits in a cipher block  */
#define     BLOCKSIZE       (BITSPERBLOCK/8)  /* # bytes in a cipher block  */
#define     BLOCK_WSIZE     (BITSPERBLOCK/32) /* # WORD32's in a cipher block  */
#define     DIR_ENCRYPT     0    /*  Are we encrpyting?  */
#define     DIR_DECRYPT     1    /*  Are we decrpyting?  */
#define     MODE_ECB        1    /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC        2    /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode? */
#define     TRUE            1
#define     FALSE           0


/*  Error Codes :  */
#define     BAD_KEY_DIR        -1  /*  Key direction is invalid, e.g.,
					unknown value */
#define     BAD_KEY_MAT        -2  /*  Key material not of correct 
					length */
#define     BAD_KEY_INSTANCE   -3  /*  Key passed is not valid  */
#define     BAD_KEY_LENGTH     -4  /*  Key size in bits is wrong */
#define     BAD_CIPHER_MODE    -5  /*  Params struct passed to 
					cipherInit invalid */
#define     BAD_CIPHER_STATE   -6  /*  Cipher in wrong state (e.g., not 
					initialized) */
#define     BAD_CIPHER_INPUT   -7  /*  Wrong cipher input length */

#define     MAX_KEY_SIZE	   32  /* # of ASCII char's needed to
					represent a key */
#define     MAX_IV_SIZE		   16  /* # bytes needed to
					represent an IV  */
#define     SCHEDULE_KEY_SIZE  16*2*(R+1) /* total size of scheduled key */

#define     R           7   /* proposed encryption round */


/*  Typedefs:  */
    typedef unsigned char	BYTE;	 /*  8 bit */
    typedef unsigned short	WORD16;	 /* 16 bit */
#ifdef __alpha
	typedef unsigned int	WORD32;	 /* 32 bit */
#else  /* !__alpha */
	typedef unsigned long	WORD32;	 /* 32 bit */
#endif /* :__alpha */


/*  The structure for key information */
typedef struct {
      BYTE  direction;	/*  In our case this is negligible, since this
	      structure involve both enc/dec Keys */
      int   keyLen;	    /*  Length of the key  */
      char  keyMaterial[MAX_KEY_SIZE+1];  /*  Raw key data in ASCII */
      BYTE	KS_Enc[SCHEDULE_KEY_SIZE];     /*  encryption key */
	  BYTE	KS_Dec[SCHEDULE_KEY_SIZE];     /*  decryption key */
      } keyInstance;

/*  The structure for cipher information */
typedef struct {
      BYTE  mode;            /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
      BYTE  IV[MAX_IV_SIZE]; /* A possible Initialization Vector for 
      					ciphering */
	  BYTE  RED[512];        /* The S-box table RED=[f]|[f^(-1)] */
      int   blockSize;    	 /* Here It is fixed : 128  */
      } cipherInstance;

/*  Function protoypes  */
int makeKey(keyInstance *key, BYTE direction, int keyLen,
			char *keyMaterial);

int cipherInit(cipherInstance *cipher, BYTE mode, char *IV);

int blockEncrypt(cipherInstance *cipher, keyInstance *key, BYTE *input, 
			int inputLen, BYTE *outBuffer);

int blockDecrypt(cipherInstance *cipher, keyInstance *key, BYTE *input,
			int inputLen, BYTE *outBuffer);

