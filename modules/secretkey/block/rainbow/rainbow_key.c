
#include "rainbow.h"

#define     WD(a)    ((WORD32 *)(a)) /* for utility */

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


/* Microsoft C / Intel x86 optimizations: */
#if defined(_MSC_VER) && defined(_M_IX86) 
#	define HARDWARE_ROTATIONS
#	define ASSEMBLER_CORE
#endif  /* :(_MSC_VER && _M_IX86) */


#ifdef HARDWARE_ROTATIONS
#	define ROTL(x, s) (_lrotl ((x), (s)))
#	define ROTR(x, s) (_lrotr ((x), (s)))
#else  /* !HARDWARE_ROTATIONS */
#	define ROTL(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
#	define ROTR(x, s) (((x) >> (s)) | ((x) << (32 - (s))))
#endif /* :HARDWARE_ROTATIONS */

#ifdef LITTLE_ENDIAN
#	ifdef MASKED_BYTE_EXTRACTION
#		define GETB0(x) (((x)      ) & 0xffU)
#		define GETB1(x) (((x) >>  8) & 0xffU)
#		define GETB2(x) (((x) >> 16) & 0xffU)
#		define GETB3(x) (((x) >> 24) & 0xffU)
#	else  /* !MASKED_BYTE_EXTRACTION */
#		define GETB0(x) ((BYTE)  ((x)      ))
#		define GETB1(x) ((BYTE)  ((x) >>  8))
#		define GETB2(x) ((BYTE)  ((x) >> 16))
#		define GETB3(x) ((BYTE)  ((x) >> 24))
#	endif /* :MASKED_BYTE_EXTRACTION */
#	define PUTB0(x) ((WORD32) (x)      )
#	define PUTB1(x) ((WORD32) (x) <<  8)
#	define PUTB2(x) ((WORD32) (x) << 16)
#	define PUTB3(x) ((WORD32) (x) << 24)
#else  /* !LITTLE_ENDIAN */
#	ifdef MASKED_BYTE_EXTRACTION
#		define GETB0(x) (((x) >> 24) & 0xffU)
#		define GETB1(x) (((x) >> 16) & 0xffU)
#		define GETB2(x) (((x) >>  8) & 0xffU)
#		define GETB3(x) (((x)      ) & 0xffU)
#	else  /* !MASKED_BYTE_EXTRACTION */
#		define GETB0(x) ((BYTE)  ((x) >> 24))
#		define GETB1(x) ((BYTE)  ((x) >> 16))
#		define GETB2(x) ((BYTE)  ((x) >>  8))
#		define GETB3(x) ((BYTE)  ((x)      ))
#	endif /* :MASKED_BYTE_EXTRACTION */
#	define PUTB0(x) ((WORD32) (x) << 24)
#	define PUTB1(x) ((WORD32) (x) << 16)
#	define PUTB2(x) ((WORD32) (x) <<  8)
#	define PUTB3(x) ((WORD32) (x)      )
#endif /* :LITTLE_ENDIAN */

#define COPY_BLOCK(trg, src) \
{ \
	(trg)[0] = (src)[0]; \
	(trg)[1] = (src)[1]; \
	(trg)[2] = (src)[2]; \
	(trg)[3] = (src)[3]; \
} /* COPY_BLOCK */ 


/******** from here, represented key generation ********/

static void rainbowMixing (WORD32 *roundKey)
{ /* key mixing procedure via rorarions and XOR operations */
	roundKey[0] = ROTR(roundKey[0],3)^
		ROTR(roundKey[1],5)^
		ROTR(roundKey[2],7)^
		ROTR(roundKey[3],11)^0xb7e15163;
	roundKey[1] = ROTR(roundKey[0],5)^
		ROTR(roundKey[1],7)^
		ROTR(roundKey[2],11)^
		ROTR(roundKey[3],3)^0xb7e15163;
	roundKey[2] = ROTR(roundKey[0],7)^
		ROTR(roundKey[1],11)^
		ROTR(roundKey[2],3)^
		ROTR(roundKey[3],5)^0xb7e15163;
	roundKey[3] = ROTR(roundKey[0],11)^
		ROTR(roundKey[1],3)^
		ROTR(roundKey[2],5)^
		ROTR(roundKey[3],7)^0xb7e15163;
} /* rainbowMixing */

/* make decryption key to satisfy the cipher's self reciprocality(self-invertable) */
#define SUB_KEY_SCROL(K_, K, M, i) \
{ \
	(K_)[i] = ((K)[0]&(M)[i])^((K)[1]&(M)[(i+1)%4])^   \
		((K)[2]&(M)[(i+2)%4])^((K)[3]&(M)[(i+3)%4]); \
}

int makeKey(keyInstance *key, BYTE direction, int keyLen,
			char *keyMaterial)
{
	WORD32 *get, *encKey, *decKey;	
	int i, j;


	if (key == NULL) return BAD_KEY_INSTANCE;
	i = keyLen%32;
	if (i != 0) return BAD_KEY_LENGTH;
	i = keyLen/8;
	if (!((16<=i)&&(i<=32))) return BAD_KEY_MAT;
		
	key->direction = direction;
	key->keyLen = keyLen;
	strncpy (key->keyMaterial, keyMaterial, keyLen);

	get = WD(keyMaterial);
	encKey = WD(key->KS_Enc);
	COPY_BLOCK(encKey, get); /* put the key material to the first key-block */

	i = (keyLen-128)/32;		
	encKey += 4;
    COPY_BLOCK(encKey, (encKey-4)); 
	
	get += 4;
	for (j=0; j<i; j++) encKey[j] ^= get[j]; 
	           /* to make it applicable to |key material|=128,160,192,...,256 in bits */
	rainbowMixing(encKey);

	for (i=2; i < 2*(R+1); i++) {
		/* apply the rainbowMixing function: */
		encKey += 4;
		COPY_BLOCK(encKey, encKey-4);
		rainbowMixing(encKey);
	}

	
	encKey = (WD(key->KS_Enc))+4;
	for (j = 0; j < R+1; j++) {
		encKey[0] = encKey[1]^encKey[2]^encKey[3]^0xffffffffL;
		encKey += 8;
	}  /* to make the key-masking be self-invertable */

	decKey = (WD(key->KS_Dec))+4;
	for (j = 0; j < R+1; j++) {
		encKey -= 8;
		COPY_BLOCK(decKey, encKey);
		decKey += 8;
	}

	encKey = (WD(key->KS_Enc)) + 8*R;
	decKey = WD(key->KS_Dec);

	/* to make the whole encryption process be self-reciprocal! */
	for (j = 0; j < R+1; j++) {
		SUB_KEY_SCROL(decKey,encKey,(encKey+4),0);
		SUB_KEY_SCROL(decKey,encKey,(encKey+4),1);
		SUB_KEY_SCROL(decKey,encKey,(encKey+4),2);
		SUB_KEY_SCROL(decKey,encKey,(encKey+4),3);
		decKey += 8;
		encKey -= 8;
	}


	return TRUE;
} /* rainbow-RoundKeys are generated*/
