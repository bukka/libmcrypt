/*** field2n.h ***/

#define WORDBYTES	sizeof(int)
#define WORD4BITS       (WORDBYTES*2)
#define WORDSIZE	(WORDBYTES*8)
#define NUMBITS		233
#define TYPE2
/*#undef TYPE2 */

#ifdef TYPE2
#define field_prime	((NUMBITS<<1)+1)
#else
#define field_prime (NUMBITS+1)
#endif

#define	NUMWORD		(NUMBITS/WORDSIZE)
#define UPRSHIFT	(NUMBITS%WORDSIZE)
#define MAXLONG		(NUMWORD+1)
#define	NUMBYTES	((NUMBITS+7)/8)
#define	NUM4BITS	((NUMBITS+3)/4)

#define MAXBITS		(MAXLONG*WORDSIZE)
#define MAXSHIFT	(WORDSIZE-1)
#define MSB			(1L<<MAXSHIFT)

#define UPRBIT		(1L<<(UPRSHIFT-1))
#define UPRMASK		(~(-1L<<UPRSHIFT))
#define SUMLOOP(i)	for(i=0; i<MAXLONG; i++)
#define SUMLOOPD(i)	for(i=NUMWORD; i>=0; i--)

#define LONGWORD	(field_prime/WORDSIZE)
#define LONGSHIFT	((field_prime-1)%WORDSIZE)
#define LONGBIT		(1L<<(LONGSHIFT-1))
#define LONGMASK         (~(-1L<<LONGSHIFT))

typedef	short int INDEX;

typedef unsigned long ELEMENT;

typedef struct {
	ELEMENT 	e[MAXLONG];
}  FIELD2N;

typedef struct {
	ELEMENT e[LONGWORD+1];
} CUSTFIELD;

