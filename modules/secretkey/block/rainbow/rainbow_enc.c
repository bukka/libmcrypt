
#include "rainbow.h"

#define     WD(a)    ((WORD32 *)(a)) /* for utility */


static void RB_Enc_ecb (BYTE *table, BYTE *cipherKey, BYTE *input, int inputLen, 
						BYTE *outBuffer);
static void RB_Enc_cbc (BYTE *table, BYTE *cipherKey, BYTE *iv, BYTE *input, 
						int inputLen, BYTE *outBuffer);
static void RB_Enc_cfb1 (BYTE *table, BYTE *cipherKey, BYTE *iv, BYTE *input, 
						 int inputLen, BYTE *outBuffer);


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


/******** from here, represented the encryption routine ********/

#define G_function(RN) \
{ /* G-layer */ \
	data[0] ^= key[(RN)][0]; \
	data[1] ^= key[(RN)][1]; \
	data[2] ^= key[(RN)][2]; \
	data[3] ^= key[(RN)][3]; \
}

#define B_function(RN) \
{ /* B-layer */ \
	tmp[0] = (data[0] & key[(RN)][0])^\
		 (data[1] & key[(RN)][1])^    \
		 (data[2] & key[(RN)][2])^    \
		 (data[3] & key[(RN)][3]);    \
	tmp[1] = (data[0] & key[(RN)][1])^\
		  (data[1] & key[(RN)][2])^   \
		  (data[2] & key[(RN)][3])^   \
		  (data[3] & key[(RN)][0]);   \
	tmp[2] = (data[0] & key[(RN)][2])^\
		  (data[1] & key[(RN)][3])^   \
		  (data[2] & key[(RN)][0])^   \
		  (data[3] & key[(RN)][1]);   \
	tmp[3] = (data[0] & key[(RN)][3])^\
		  (data[1] & key[(RN)][0])^   \
		  (data[2] & key[(RN)][1])^   \
		  (data[3] & key[(RN)][2]);   \
}

#define R_function(TABLE) \
{ /* R-layer */ \
	data[0] = PUTB1((TABLE)[GETB0(tmp[0])])|  \
		PUTB0((TABLE)[256+GETB1(tmp[0])])|    \
		PUTB3((TABLE)[GETB2(tmp[0])])|        \
		PUTB2((TABLE)[256+GETB3(tmp[0])]);    \
	data[1] = PUTB2((TABLE)[GETB0(tmp[1])])|  \
		PUTB0((TABLE)[256+GETB2(tmp[1])])|    \
		PUTB3((TABLE)[GETB1(tmp[1])])|        \
		PUTB1((TABLE)[256+GETB3(tmp[1])]);    \
	data[2] = PUTB3((TABLE)[GETB0(tmp[2])])|  \
		PUTB0((TABLE)[256+GETB3(tmp[2])])|    \
		PUTB2((TABLE)[GETB1(tmp[2])])|        \
		PUTB1((TABLE)[256+GETB2(tmp[2])]);    \
	data[3] = PUTB2((TABLE)[GETB0(tmp[3])])|  \
		PUTB0((TABLE)[256+GETB2(tmp[3])])|    \
		PUTB3((TABLE)[GETB1(tmp[3])])|        \
		PUTB1((TABLE)[256+GETB3(tmp[3])]);    \
}

#define ROUND_function(key_num) \
{ /* one round process 'F_function' in the document */ \
	G_function(key_num);   \
	B_function(key_num+1); \
	R_function(SBox);      \
}

#define ONEBLOCK_CIPH /* here : only for the blockLen=16bytes */ \
{ /* one block encryption */ \
	ROUND_function(0);  \
	ROUND_function(2);  \
	ROUND_function(4);  \
	ROUND_function(6);  \
	ROUND_function(8);  \
	ROUND_function(10); \
	ROUND_function(12); \
	G_function(14);     \
	B_function(15);     \
	COPY_BLOCK(data,tmp);\
}

int blockEncrypt (cipherInstance *cipher, keyInstance *keys, BYTE *input,
				 int inputLen, BYTE *outBuffer)
{
	if (cipher == NULL) return BAD_CIPHER_STATE;
	if (keys == NULL) return BAD_KEY_INSTANCE;
	if (inputLen%128) return BAD_CIPHER_INPUT;

	if (cipher->mode == MODE_ECB) {
		RB_Enc_ecb (cipher->RED, keys->KS_Enc, input, inputLen, outBuffer);
		return TRUE;
	}
	if (cipher->mode == MODE_CBC) {
		RB_Enc_cbc (cipher->RED, keys->KS_Enc,cipher->IV, input, inputLen, outBuffer);
		return TRUE;
	}
	if (cipher->mode == MODE_CFB1) {
		RB_Enc_cfb1 (cipher->RED, keys->KS_Enc,cipher->IV, input, inputLen, outBuffer);
		return TRUE;
	}
	return BAD_CIPHER_MODE;
}

/* ECB-mode encryption */
static void RB_Enc_ecb (BYTE *table, BYTE *cipherKey, BYTE *input, int inputLen, 
						BYTE *outBuffer)
{
	WORD32 tmp[4], data[4], key[2*(R+1)][4];
	WORD32 *scan, *tar;
	BYTE *SBox;
	int i, ib;

	SBox = table;
	scan = WD(cipherKey);
	for (i=0; i<2*(R+1); i++) {
		COPY_BLOCK(key[i], scan);
		scan += 4;
	}

	ib = inputLen/BITSPERBLOCK;  /* check # of cyphering blocks */
	scan = WD(input);
	tar = WD(outBuffer);

	for (i=0; i<ib; i++) {
		COPY_BLOCK(data, scan);
		ONEBLOCK_CIPH; /* encrypt */
		COPY_BLOCK(tar, data);
		scan += BLOCK_WSIZE;
		tar += BLOCK_WSIZE;
	}
}

#define BLOCK_XOR(B, A) \
{ \
	B[0] ^= A[0];\
	B[1] ^= A[1];\
	B[2] ^= A[2];\
	B[3] ^= A[3];\
}
/* CBC-mode encryption */
static void RB_Enc_cbc (BYTE *table, BYTE *cipherKey, BYTE *iv, BYTE *input, int inputLen, 
					BYTE *outBuffer)
{
	WORD32 tmp[4], data[4], key[2*(R+1)][4];
	WORD32 *scan, *tar;
	BYTE *SBox;
	int i, ib;

	SBox = table;
	scan = WD(cipherKey);
	for (i=0; i<2*(R+1); i++) {
		COPY_BLOCK(key[i], scan);
		scan += 4;
	}

	ib = inputLen/BITSPERBLOCK;  /* check # of cyphering blocks */
	scan = WD(input);
	tar = WD(outBuffer);

	COPY_BLOCK(data, scan);
	BLOCK_XOR(data, WD(iv));  /* added initial vector */
	ONEBLOCK_CIPH; /* encrypt */
	COPY_BLOCK(tar, data);

	for (i=1; i<ib; i++) {
		scan += BLOCK_WSIZE;
		tar += BLOCK_WSIZE;
		BLOCK_XOR(data, scan);  /* cipher block chaining */
		ONEBLOCK_CIPH; /* encrypt */
		COPY_BLOCK(tar, data);
	}
}

#define LSHIFT_PAST(D, b) \
{ /* shift by 1bit of and paste 1bit to cipher input data */ \
	dt = D[0]>>31;       \
	D[0] = (D[0]<<1)|b;  \
	df = (D[1]<<1)|dt;   \
	dt = D[1]>>31;       \
	D[1] = df;           \
	df = (D[2]<<1)|dt;   \
	dt = D[2]>>31;       \
	D[2] = df;           \
	D[3] = (D[3]<<1)|dt; \
}

/* CFB1-mode encryption */
static void RB_Enc_cfb1 (BYTE *table, BYTE *cipherKey, BYTE *iv, BYTE *input, int inputLen, 
					BYTE *outBuffer)
{
	WORD32 tmp[4], data[4], feed[4], key[2*(R+1)][4], df,dt, *cnv;
	BYTE *scan, *tar, *SBox;
	register BYTE grab, bit, fback;
	int i, j;

	SBox = table;
	cnv = WD(cipherKey);
	for (i=0; i<2*(R+1); i++) {
		COPY_BLOCK (key[i], cnv);
		cnv += 4;
	}
	scan = input;
	tar = outBuffer;

	COPY_BLOCK(feed, WD(iv));
	COPY_BLOCK(data, feed);
	ONEBLOCK_CIPH ; /* encrypt */
	bit = (BYTE)(data[3]>>31);

	for (i=0; i<inputLen/8; i++) {
		grab = 0;  /* when the BYTE 'grab' being filled, 
		          hand over to outBuffer */
		for (j=0; j<8; j++) {
			fback = ((*scan>>j)&1)^bit;  /* preparing feedback bit */
			grab |= (fback<<j);
			LSHIFT_PAST(feed, fback);  /* preparing cipher input block */
			COPY_BLOCK(data, feed);
			ONEBLOCK_CIPH ; /* decrypt */
			bit = (BYTE)(data[3]>>31);
		}
		*tar = grab;
		scan++;
		tar++;
	}
}

