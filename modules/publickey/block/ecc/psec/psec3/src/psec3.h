/*
 psec3.h - PSEC-3 software specification

 Version 0.1

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - modified the representation of elliptic curve point so to
           conform to P1363 E.2.3.2
 8/29/00 - use P1363 E.2.3.2 complaint octet string representation for
           an EC point during hashing
*/


typedef unsigned char  BYTE;
typedef unsigned long  WORD;

#define MAX_FIELD_LEN            256

#define TRUE                     1
#define FALSE                    0

#define MAX_IV_SIZE              16          /* # bytes */
#define ENCRYPT_BLOCK_LEN        128
#define MAX_ROUNDS               24

#define MODE_UNSPECIFIED         0
#define MODE_ECB                 1
#define MODE_CBC                 2
#define MODE_CFB                 3

#define ENCRYPT_ALG_XOR          1          /* one-time pad */
#define DIR_ENCRYPT              0
#define DIR_DECRYPT              1

#define MD_MD5                   1
#define MD_SHA                   2


/* PSEC-3 public and private key */
typedef struct {
	EC_POINT pk;
	WORD Gid;
	WORD Hid;
	WORD hLen;
	WORD mLen;
} PSEC3_PUB_KEY;

typedef struct {
	mpz_t sk;
} PSEC3_PRIV_KEY;


/* Symmetric-key cipher information */
typedef struct {
	BYTE algorithmID;
	BYTE mode;
	BYTE direction;           /* encrypting or decrypting */
	WORD KLen;                /* length of the symmetric key */
	BYTE IV[MAX_IV_SIZE];     /* initialization vector */
	WORD S[MAX_ROUNDS];       /* key schedule */
} CIPHER_INFO;


/* PSEC-3 ciphertext */
typedef struct {
	EC_POINT C1;
	mpz_t c1;
	BYTE *c2;
	WORD cipherLen;
	BYTE *c3;
} PSEC3_CIPHERTEXT;
	

/* key-pair generation */
BYTE PSEC3_KeyGeneration (
	EC_PARAM     *E,
	mpz_t        sk,
	EC_POINT     *pk
);


/* encryption */
BYTE PSEC3_Encryption (
	BYTE             *message,    /* plaintext */
	CIPHER_INFO      *cipherInfo,
	PSEC3_PUB_KEY    *publicKey,  /* PSEC3 public key */
	PSEC3_CIPHERTEXT *ciphertext,  /* returned ciphertext */
	EC_PARAM         *E
);


/* decryption */
BYTE PSEC3_Decryption (
	PSEC3_CIPHERTEXT *ciphertext,
	CIPHER_INFO      *cipherInfo,
	PSEC3_PUB_KEY    *publicKey,
	PSEC3_PRIV_KEY   *privateKey,
	BYTE             *message,
	EC_PARAM         *E
);


#define ABS(x) (x >= 0 ? x : -x)
