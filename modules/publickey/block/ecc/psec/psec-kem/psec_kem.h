/*
 psec_pem.h - PSEC-KEM software specification

 Copyright NTT MCL, 2000 & 2001.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 Based on psec2.h.  Modifications made by S.O. in September 2001.
*/


#define MAX_FIELD_LEN            256

#define TRUE                     1
#define FALSE                    0

/* Symmetric Encryption schemes supported */
#define ENCRYPT_ALG_XOR         1       /* one-time pad */
#define ENCRYPT_ALG_CAM		2	/* Camellia */

/* Hash functions allowed */
#define H_INDEXED_SHA	1	/* as recomended in old spec */
#define H_MGF1		2	/* P1363a 2000 */
#define H_KDF2		3	/* P1363a 2000 */

#define OUTPUT_KEY_LEN	256

/** Selectable Parameters **/
#define SYMMETRIC_ENCR ENCRYPT_ALG_CAM


typedef enum  {
	COMPRESSED,
	UNCOMPRESSED,
	HYBRID
} PSEC_KEM_EC_ENCODING_FORMAT;

/* PSEC-KEM public and private key */
typedef struct {
	EC_POINT pk;
	u8 Hid;
	u8 SEid;
	u32 hLen;
	u32 outputKeyLen;
} PSEC_KEM_PUB_KEY;

typedef struct {
	mpz_t sk;
} PSEC_KEM_PRIV_KEY;


/* PSEC-KEM key material */
typedef struct {
	u8 *K_raw;
	u32 KoLen;
} PSEC_KEM_KEY_MATERIAL;
	
/* PSEC-KEM key encapsulation */
typedef struct {
	u8 *C0; /* PSEC-KEM key encapsulation */
	u32 C0oLen;
} PSEC_KEM_KEY_ENCAPSULATION;

/* key-pair generation */
u8 PSEC_KEM_KeyGeneration (
	u32	seedLen,
	EC_PARAM     *E,
	PSEC_KEM_PRIV_KEY        *privateKey,
	PSEC_KEM_PUB_KEY     *publicKey
);

/* key encapsulation */
u8 PSEC_KEM_KEM(
	PSEC_KEM_PUB_KEY    *publicKey,     /* PSEC_KEM public key */
	PSEC_KEM_KEY_ENCAPSULATION	*keyEncapsulation,/* returned key encapsulation */
	PSEC_KEM_KEY_MATERIAL	*key,/* returned key material */
	EC_PARAM         *E,
	PSEC_KEM_EC_ENCODING_FORMAT format
);

/* key decapsulation */
u8 PSEC_KEM_KDM (
	PSEC_KEM_KEY_ENCAPSULATION  *keyEncapsulation,
	PSEC_KEM_PRIV_KEY   *privateKey,
	PSEC_KEM_PUB_KEY    *publicKey,
	PSEC_KEM_KEY_MATERIAL	*key,/* returned key material */
	EC_PARAM         *E,
	PSEC_KEM_EC_ENCODING_FORMAT format
);

/** Unused Parameters **/

/* Block cipher constants */
#define DIR_ENCRYPT              0
#define DIR_DECRYPT              1

#define MAX_IV_SIZE              16          /* # bytes */
#define ENCRYPT_BLOCK_LEN        128
#define MAX_ROUNDS               24

#define MODE_UNSPECIFIED         0
#define MODE_ECB                 1
#define MODE_CBC                 2
#define MODE_CFB                 3

/* Symmetric-key cipher information */
typedef struct {
	u8 mode;
	u8 direction;           /* encrypting or decrypting */
	u32 mLen;		  /* message length in bits */
	u8 IV[MAX_IV_SIZE];     /* initialization vector */
	u32 S[MAX_ROUNDS];       /* key schedule */
} CIPHER_INFO;
