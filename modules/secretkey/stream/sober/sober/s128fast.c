/* s128: SOBER-128 stream cipher and MAC -- fast implementation */
/* Copyright C 2003 QUALCOMM Incorporated */

/*
This software is free for commercial and non-commercial use subject to
the following conditions:

1.  Copyright remains vested in QUALCOMM Incorporated, and Copyright
notices in the code are not to be removed.  If this package is used in a
product, QUALCOMM should be given attribution as the author of the SOBER
family of encryption algorithms. This can be in the form of a textual
message at program startup or in documentation (online or textual)
provided with the package.

2.  Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

a. Redistributions of source code must retain the copyright notice,
   this list of conditions and the following disclaimer.

b. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

c. All advertising materials mentioning features or use of this
   software must display the following acknowledgement:  This product
   includes software developed by QUALCOMM Incorporated.

3.  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE AND AGAINST
INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

4.  The license and distribution terms for any publically available version
or derivative of this code cannot be changed, that is, this code cannot
simply be copied and put under another distribution license including
the GNU Public License.

5.  The SOBER family of encryption algorithms are covered by patents in
the United States of America and other countries. A free and
irrevocable license is hereby granted for the use of such patents to
the extent required to utilize the SOBER family of encryption
algorithms for any purpose, subject to the condition that any
commercial product utilising any of the SOBER family of encryption
algorithms should show the words "Encryption by QUALCOMM" either on the
product or in the associated documentation.
*/

/* interface, multiplication table and SBox */
#include <stdlib.h>
#include "s128.h"
#include "s128sbox.h"
#include "s128multab.h"

/*
 * FOLD is how many register cycles need to be performed after combining the
 * last byte of key and non-linear feedback, before every byte depends on every
 * byte of the key. This depends on the feedback and nonlinear functions, and
 * on where they are combined into the register.
 */
#define FOLD N		/* how many iterations of folding to do */
#define INITKONST 0x6996c53a /* value of KONST to use during key loading */
#define KEYP 15		/* where to insert key words */
#define FOLDP 4		/* where to insert non-linear feedback */
#define MACP 4		/* where to adjust register for MAC accumulation */

/* Useful macros -- little endian words on a little endian machine */
#define B(x,i) ((UCHAR)(((x) >> (8*i)) & 0xFF))
#define BYTE2WORD(b) (*(WORD *)b)
#define WORD2BYTE(w, b) ((*(WORD *)(b)) = w)
#define XORWORD(w, b) ((*(WORD *)(b)) ^= w)

/* give correct offset for the current position of the register,
 * where logically R[0] is at position "zero".
 */
#define OFF(zero, i) (((zero)+(i)) % N)

/* step the LFSR */
/* After stepping, "zero" moves right one place */
#define STEP(R,z) \
    R[OFF(z,0)] = R[OFF(z,15)] ^ R[OFF(z,4)] ^ \
	(R[OFF(z,0)] << 8) ^ Multab[(R[OFF(z,0)] >> 24) & 0xFF]

static void
cycle(WORD R[])
{
    WORD	t;
    int		i;

    STEP(R,0);
    t = R[0];
    for (i = 1; i < N; ++i)
	R[i-1] = R[i];
    R[N-1] = t;
}

/* Return a non-linear function of some parts of the register.
 */
#define NLFUNC(c,z) \
{ \
    t = c->R[OFF(z,0)] + c->R[OFF(z,16)]; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    t = ROTR(t, 8); \
    t = ((t + c->R[OFF(z,1)]) ^ c->konst) + c->R[OFF(z,6)]; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    t = t + c->R[OFF(z,13)]; \
}

static WORD
nltap(s128_ctx *c)
{
    WORD	t;

    /* t = */ NLFUNC(c, 0);
    return t;
}

/* accumulate a nonlinear function of a register word and an input word for MAC
 */
#define MACFUNC(c,i,z) \
{ \
    t = c->R[OFF(z,MACP)] + i; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    t = ROTR(t, 8); \
    t += c->konst; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    c->R[OFF(z,MACP)] = t; \
}
    
static void
macfunc(s128_ctx *c, WORD i)
{
    WORD	t;

    MACFUNC(c, i, 0);
}

/* initialise to known state
 */
static void
s128_initstate(s128_ctx *c)
{
    int		i;

    /* Register initialised to Fibonacci numbers */
    c->R[0] = 1;
    c->R[1] = 1;
    for (i = 2; i < N; ++i)
	c->R[i] = c->R[i-1] + c->R[i-2];
    c->konst = INITKONST;
}

/* Save the current register state
 */
static void
s128_savestate(s128_ctx *c)
{
    int		i;

    for (i = 0; i < N; ++i)
	c->initR[i] = c->R[i];
}

/* initialise to previously saved register state
 */
static void
s128_reloadstate(s128_ctx *c)
{
    int		i;

    for (i = 0; i < N; ++i)
	c->R[i] = c->initR[i];
}

/* Initialise "konst"
 */
static void
s128_genkonst(s128_ctx *c)
{
    WORD	newkonst;

    do {
	cycle(c->R);
	newkonst = nltap(c);
    } while ((newkonst & 0xFF000000) == 0);
    c->konst = newkonst;
}

/* Load key material into the register
 */
#define ADDKEY(k) \
	c->R[KEYP] += (k);

#define XORNL(nl) \
	c->R[FOLDP] ^= (nl);

/* nonlinear diffusion of register for key and MAC */
#define DROUND(z) STEP(c->R,z); NLFUNC(c,(z+1)); c->R[OFF((z+1),FOLDP)] ^= t; 
static void
s128_diffuse(s128_ctx *c)
{
    WORD	t;

    /* relies on FOLD == N! */
    DROUND(0);
    DROUND(1);
    DROUND(2);
    DROUND(3);
    DROUND(4);
    DROUND(5);
    DROUND(6);
    DROUND(7);
    DROUND(8);
    DROUND(9);
    DROUND(10);
    DROUND(11);
    DROUND(12);
    DROUND(13);
    DROUND(14);
    DROUND(15);
    DROUND(16);
}

static void
s128_loadkey(s128_ctx *c, UCHAR key[], int keylen)
{
    int		i;
    WORD	k;

    /* start folding in key, reject odd sized keys */
    if ((keylen & 3) != 0)
	abort();
    for (i = 0; i < keylen; i += 4)
    {
	k = BYTE2WORD(&key[i]);
	ADDKEY(k);
        cycle(c->R);
	XORNL(nltap(c));
    }

    /* also fold in the length of the key */
    ADDKEY(keylen);

    /* now diffuse */
    s128_diffuse(c);
}

/* Published "key" interface
 */
void
s128_key(s128_ctx *c, UCHAR key[], int keylen)
{
    s128_initstate(c);
    s128_loadkey(c, key, keylen);
    s128_genkonst(c);
    s128_savestate(c);
}

/* Published "IV" interface
 */
void
s128_IV(s128_ctx *c, UCHAR iv[], int ivlen)
{
    s128_reloadstate(c);
    s128_loadkey(c, iv, ivlen);
}

/* XOR pseudo-random bytes into buffer */
#define SROUND(z) STEP(c->R,z); NLFUNC(c,(z+1)); XORWORD(t, buf+(z*4));
void
s128_stream(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    /* do small or odd size buffers the slow way, at least at first */
    while ((nbytes % (N*4)) != 0) {
	cycle(c->R);
	t = nltap(c);
	XORWORD(t, buf);
	buf += 4;
	nbytes -= 4;
    }
    /* now do lots at a time, if there's any left */
    while (buf < endbuf)
    {
	SROUND(0);
	SROUND(1);
	SROUND(2);
	SROUND(3);
	SROUND(4);
	SROUND(5);
	SROUND(6);
	SROUND(7);
	SROUND(8);
	SROUND(9);
	SROUND(10);
	SROUND(11);
	SROUND(12);
	SROUND(13);
	SROUND(14);
	SROUND(15);
	SROUND(16);
	buf += 4*17;
    }
}

/* accumulate words into MAC without encryption */
#define MROUND(z) STEP(c->R,z); MACFUNC(c,BYTE2WORD(buf+(z*4)),(z+1));
void
s128_maconly(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    /* do small or odd size buffers the slow way, at least at first */
    while ((nbytes % (N*4)) != 0) {
	cycle(c->R);
	macfunc(c, BYTE2WORD(buf));
	buf += 4;
	nbytes -= 4;
    }
    /* now do lots at a time, if there's any left */
    while (buf < endbuf)
    {
	MROUND(0);
	MROUND(1);
	MROUND(2);
	MROUND(3);
	MROUND(4);
	MROUND(5);
	MROUND(6);
	MROUND(7);
	MROUND(8);
	MROUND(9);
	MROUND(10);
	MROUND(11);
	MROUND(12);
	MROUND(13);
	MROUND(14);
	MROUND(15);
	MROUND(16);
	buf += 4*17;
    }
}

/* simultaneously encrypt and accumulate MAC */
#define EROUND(z) \
    STEP(c->R,z); \
    t2 = BYTE2WORD(buf+(z*4)); \
    MACFUNC(c,t2,(z+1)); \
    NLFUNC(c,(z+1)); \
    t ^= t2; \
    WORD2BYTE(t, buf+(z*4));
void
s128_encrypt(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0, t2 = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    /* do small or odd size buffers the slow way, at least at first */
    while ((nbytes % (N*4)) != 0) {
	cycle(c->R);
	t = BYTE2WORD(buf);
	macfunc(c, t);
	t ^= nltap(c);
	WORD2BYTE(t, buf);
	nbytes -= 4;
	buf += 4;
    }
    /* now do lots at a time, if there's any left */
    while (buf < endbuf)
    {
	EROUND(0);
	EROUND(1);
	EROUND(2);
	EROUND(3);
	EROUND(4);
	EROUND(5);
	EROUND(6);
	EROUND(7);
	EROUND(8);
	EROUND(9);
	EROUND(10);
	EROUND(11);
	EROUND(12);
	EROUND(13);
	EROUND(14);
	EROUND(15);
	EROUND(16);
	buf += 4*17;
    }
}

/* simultaneously decrypt and accumulate MAC */
#undef DROUND
#define DROUND(z) \
    STEP(c->R,z); \
    NLFUNC(c,(z+1)); \
    XORWORD(t, buf+(z*4)); \
    MACFUNC(c,BYTE2WORD(buf+(z*4)),(z+1));
void
s128_decrypt(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    /* do small or odd size buffers the slow way, at least at first */
    while ((nbytes % (N*4)) != 0) {
	cycle(c->R);
	t = nltap(c);
	t ^= BYTE2WORD(buf);
	macfunc(c, t);
	WORD2BYTE(t, buf);
	nbytes -= 4;
	buf += 4;
    }
    /* now do lots at a time, if there's any left */
    while (buf < endbuf)
    {
	DROUND(0);
	DROUND(1);
	DROUND(2);
	DROUND(3);
	DROUND(4);
	DROUND(5);
	DROUND(6);
	DROUND(7);
	DROUND(8);
	DROUND(9);
	DROUND(10);
	DROUND(11);
	DROUND(12);
	DROUND(13);
	DROUND(14);
	DROUND(15);
	DROUND(16);
	buf += 4*17;
    }
}

/* Having accumulated a MAC, finish processing and return it */
void
s128_finish(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    /* perturb the state to mark end of input -- sort of like adding more key */
    ADDKEY(INITKONST);
    cycle(c->R);
    XORNL(nltap(c));
    s128_diffuse(c);
    /* don't bother optimising this loop, because it's a state
     * of delusion to generate more than N words of MAC.
     */
    endbuf = &buf[nbytes];
    while (buf < endbuf)
    {
	cycle(c->R);
	t = nltap(c);
	WORD2BYTE(t, buf);
	buf += 4;
    }
}
