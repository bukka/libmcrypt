/* s128: SOBER-128 stream cipher and MAC -- reference implementation */
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

/* some useful macros -- machine independent little-endian */
#define B(x,i) ((UCHAR)(((x) >> (8*i)) & 0xFF))
#define BYTE2WORD(b) ( \
	(((WORD)(b)[3] & 0xFF)<<24) | \
	(((WORD)(b)[2] & 0xFF)<<16) | \
	(((WORD)(b)[1] & 0xFF)<<8) | \
	(((WORD)(b)[0] & 0xFF)) \
)
#define WORD2BYTE(w, b) { \
	(b)[3] = B(w,3); \
	(b)[2] = B(w,2); \
	(b)[1] = B(w,1); \
	(b)[0] = B(w,0); \
}
#define XORWORD(w, b) { \
	(b)[3] ^= B(w,3); \
	(b)[2] ^= B(w,2); \
	(b)[1] ^= B(w,1); \
	(b)[0] ^= B(w,0); \
}

/* cycle the contents of the shift register
 */
static void
cycle(WORD *R)
{
    WORD	t;
    int		i;

    t = (R[0] << 8) ^ Multab[(R[0] >> 24) & 0xFF] ^ R[4] ^ R[15];
    for (i = 1; i < N; ++i)
	R[i-1] = R[i];
    R[N-1] = t;
}

/* Return a non-linear function of some parts of the register.
 */
static WORD
nltap(s128_ctx *c)
{
    WORD	t;

    t = c->R[0] + c->R[16];
    t ^= Sbox[(t >> 24) & 0xFF];
    t = ROTR(t, 8);
    t = ((t + c->R[1]) ^ c->konst) + c->R[6];
    t ^= Sbox[(t >> 24) & 0xFF];
    return (t + c->R[13]);
}

/* accumulate a nonlinear function of a register word and an input word for MAC
 */
static void
macfunc(s128_ctx *c, WORD i)
{
    WORD	t;

    t = c->R[MACP] + i;
    t ^= Sbox[(t >> 24) & 0xFF];
    t = ROTR(t, 8);
    t += c->konst;
    t ^= Sbox[(t >> 24) & 0xFF];
    c->R[MACP] = t;
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
static void
s128_diffuse(s128_ctx *c)
{
    int		i;

    for (i = 0; i < FOLD; ++i)
    {
	cycle(c->R);
	XORNL(nltap(c));
    }
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
void
s128_stream(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    while (buf < endbuf)
    {
	cycle(c->R);
	t = nltap(c);
	XORWORD(t, buf);
	buf += 4;
    }
}

/* accumulate words into MAC without encryption */
void
s128_maconly(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    while (buf < endbuf)
    {
	cycle(c->R);
	macfunc(c, BYTE2WORD(buf));
	buf += 4;
    }
}

/* combined MAC and encryption */
void
s128_encrypt(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    while (buf < endbuf)
    {
	cycle(c->R);
	macfunc(c, BYTE2WORD(buf));
	t = nltap(c);
	XORWORD(t, buf);
	buf += 4;
    }
}

/* combined MAC and decryption */
void
s128_decrypt(s128_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if ((nbytes & 3) != 0)
	abort();
    endbuf = &buf[nbytes];
    while (buf < endbuf)
    {
	cycle(c->R);
	t = nltap(c);
	XORWORD(t, buf);
	macfunc(c, BYTE2WORD(buf));
	buf += 4;
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
    /* generate stream output as MAC */
    endbuf = &buf[nbytes];
    while (buf < endbuf)
    {
	cycle(c->R);
	t = nltap(c);
	WORD2BYTE(t, buf);
	buf += 4;
    }
}
