/*************************************************
 *						 *
 *	Camellia Block Encryption Algorithm	 *
 *	  in ANSI-C Language : Camellia.c	 *
 *						 *
 *	    Version M1.01  April 7 2000		 *
 *    Copyright Mitsubishi Electric Corp 2000    *
 *						 *
 *************************************************/

/* 
 * 8/27/2001 - Create camellia.h -- A.H.
 * 8/27/2001 - Changed type declarations to match those in nessie.h -- A.H.
 * 9/08/2001 - Added constants for key sizes and error codes. -- A.H.
 */

#ifndef _CAMELLIA_H_
#define _CAMELLIA_H_

#include "nessie.h"

/* 
 * Constants 
 */

/* Permitted key lengths (do not change this values) */
#define CAM_KEY_LEN1		(128)
#define CAM_KEY_LEN2		(192)
#define CAM_KEY_LEN3		(256)
#define CAM_EKEY_BLEN		(272)

/* Actual key length: must choose between CAM_KEY_LEN{1,2,3} */
#define CAM_KEY_LEN		CAM_KEY_LEN1

/* Other constants (do not modify) */
#define CAM_KEY_BLEN		(CAM_KEY_LEN/8)
#define CAM_DECRYPTION_ERROR	(-1)

/* 
 * Basic Primitives
 */

void Camellia_Ekeygen( const s32 keysize, const u8 *key, u8 *ekey );
void Camellia_Encrypt( const s32 keysize, const u8 *ptext, const u8 *ekey, 
                       u8 *ctext );
void Camellia_Decrypt( const s32 keysize, const u8 *ctext, const u8 *ekey, 
                       u8 *ptext );

/* 
 * Modes of Operation 
 */

/* CBC-IV0 Mode: Encryption */
u32 Camellia_CBC_IV0_Encrypt ( 
  const s32 keysize, 
  const u8 *ptext, 
  const u32 ptextLen,
  const u8 *ekey, 
  u8 *ctext 
);

/* CBC-IV0 Mode: Decryption */
s32 Camellia_CBC_IV0_Decrypt ( 
  const s32 keysize, 
  const u8 *ctext, 
  const u32 ctextLen,
  const u8 *ekey, 
  u8 *ptext 
);

/* Low Level functions */
void Camellia_Feistel( const u8 *, const u8 *, u8 * );
void Camellia_FLlayer( u8 *, const u8 *, const u8 * );

void ByteWord( const u8 *, u32 * );
void WordByte( const u32 *, u8 * );
void XorBlock( const u8 *, const u8 *, u8 * );
void SwapHalf( u8 * );
void RotBlock( const u32 *, const s32, u32 * );

#endif /* _CAMELLIA_H_ */
