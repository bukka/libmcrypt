/* @(#)t32.c	1.3 (QUALCOMM) 03/21/01 */

/* Header for t32:  32 bit SOBER stream cipher. */
/*
This software is free for commercial and non-commercial use in
non-embedded applications subject to the following conditions.

Copyright remains vested in QUALCOMM Incorporated, and Copyright
notices in the code are not to be removed.  If this package is used in
a product, QUALCOMM should be given attribution as the author of the
SOBER encryption algorithm. This can be in the form of a textual
message at program startup or in documentation (online or textual)
provided with the package.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

3. All advertising materials mentioning features or use of this
   software must display the following acknowledgement:  This product
   includes software developed by QUALCOMM Incorporated.

4. The software is not embedded in a device intended for a specific
   application, for example but not limited to communication devices
   (including mobile telephones), smart cards, cash registers, teller
   machines, network routers.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

The license and distribution terms for any publically available version
or derivative of this code cannot be changed, that is, this code cannot
simply be copied and put under another distribution license including
the GNU Public License.
*/

#define N 17
#define CONST_C 0x6996c53a
#define WORDSIZE 32
#define WORD unsigned long

/* multiplication tables */
#include "multab.h"
#include "sbox.h"

WORD	Initial[N];   /* Initial contents of shift register -- key schedule */
WORD	R[2*N];       /* Working storage for the shift register */
unsigned char stcnt;  /* stutter count -- when == 0 next output stored */
WORD	stctrl;       /* used 2 bits at a time */
WORD	konst;        /* key dependent non-linear function */
int	r;            /* current offset in sliding window buffer */

/* external interface declarations */
void t32_key(unsigned char key[], int keylen);
void t32_genbytes(unsigned long frame, unsigned char buf[], int nbytes);

/*
 * FOLD is how many register cycles need to be performed after combining the
 * last byte of key and non-linear feedback.
 */
#define FOLD N        /* how many iterations of folding to do */
#define KEYP 15       /* where to insert key words */
#define FOLDP 4       /* where to insert non-linear feedback */

/* end of SOBER header */

/* cycle the contents of the shift register */

static int cycle(WORD *R, int r)
{
    R[r-N] = R[r] = R[r-N+15] ^ R[r-N+4] ^ MUL0xC2DB2AA3(R[r-N]);
    if (++r == 2*N)
        r = N;
    return r;
}

/* Return a non-linear function of some parts of the register.
 * The positions of the state bytes form a maximal span full positive
 * difference set, and are 0, 1, 6, 13, 16.
 */

static WORD
nltap(WORD *R, int r)
{
    WORD   t;

    t = R[r-N+0] + R[r-N+16];
    t = SBox[t >> 24] ^ (t & 0xFFFFFF);
    t = (t + R[r-N+1] + R[r-N+6]) ^ konst;
    return (WORD) (t + R[r-N+13]);
}

/* load some key material into the register */

static void
loadkey(unsigned char key[], int keylen)
{
    int		i, keyp;
    WORD	k;

    /* start folding in key, odd byte first if there is one */
    if ((keylen & 3) != 0)
    {
	keyp = k = 0;
	switch (keylen & 3) {
	case 3:	k = (k << 8) + key[keyp++];
	case 2:	k = (k << 8) + key[keyp++];
	case 1:	k = (k << 8) + key[keyp++];
	}
	if (r-2*N+KEYP < 0)
	    R[r-N+KEYP] += k;
	else
	    R[r-2*N+KEYP] = R[r-N+KEYP] = R[r-N+KEYP] + k;
        r = cycle(R, r);
	if (r-2*N+FOLDP < 0)
	    R[r-N+FOLDP] ^= nltap(R, r);
	else
	    R[r-2*N+FOLDP] = R[r-N+FOLDP] = R[r-N+FOLDP] ^ nltap(R, r);
    }
    for (i = keylen & 3; i < keylen; i += 4)
    {
	k = (key[i] << 24) + (key[i+1] << 16) + (key[i+2] << 8) + key[i+3];
	if (r-2*N+KEYP < 0)
	    R[r-N+KEYP] += k;
	else
	    R[r-2*N+KEYP] = R[r-N+KEYP] = R[r-N+KEYP] + k;
        r = cycle(R, r);
	if (r-2*N+FOLDP < 0)
	    R[r-N+FOLDP] ^= nltap(R, r);
	else
	    R[r-2*N+FOLDP] = R[r-N+FOLDP] = R[r-N+FOLDP] ^ nltap(R, r);
    }

    /* also fold in the length of the key */
    if (r-2*N+KEYP < 0)
	R[r-N+KEYP] += keylen;
    else
	R[r-2*N+KEYP] = R[r-N+KEYP] = R[r-N+KEYP] + keylen;

    /* now diffuse */
    for (i = 0; i < FOLD; ++i)
    {
	r = cycle(R, r);
	if (r-2*N+FOLDP < 0)
	    R[r-N+FOLDP] ^= nltap(R, r);
	else
	    R[r-2*N+FOLDP] = R[r-N+FOLDP] = R[r-N+FOLDP] ^ nltap(R, r);
    }
}

/* calculate initial contents of the shift register */

void
t32_key(unsigned char key[], int keylen)
{
    int i;

    /* fill the register with fibonacci numbers */
    R[0] = R[1] = 1;
    for (i = 2; i < N; i++)
        R[i] = R[i-1] + R[i-2];

    /* initialise the pointers and start folding in key */
    r = N;
    konst = 0;
    loadkey(key, keylen);

    /* save state and key word for nonlinear function */
    r = cycle(R, r);
    konst = nltap(R, r);
    for (i = 0; i < N; i++)
        Initial[i] = R[r-N+i];
    stcnt = 0;
}

/* Fold in the per-frame key */

void
t32_seckey(unsigned char seckey[], int seckeylength)
{
    register int    i;

    /* copy initial contents */
    for (i = 0; i < N; i++)
        R[i] = Initial[i];
    r = N;

    loadkey(seckey, seckeylength);

    stcnt = 0;
}

/* XOR pseudo-random bytes into buffer */

#define XORWORD(p,v) (p[0] ^= ((v) >> 24), p[1] ^= ((v) >> 16), \
			p[2] ^= ((v) >> 8), p[3] ^= (v), p += 4)
void
t32_gen(unsigned char *buf, int nbytes)
{
    unsigned char   *endbuf;
    WORD	t = 0;

    /* assert((nbytes & 3) == 0) */
    endbuf = &buf[nbytes];
    while (buf < endbuf)
    {
        stctrl >>= 2;

        /* reprime stuttering if necessary */

        if (stcnt == 0)
        {
            stcnt = WORDSIZE/2;
            r = cycle(R, r);
            stctrl = nltap(R, r);
        }
        stcnt--;

        r = cycle(R, r);
        switch (stctrl & 0x3) {

        case 0: /* just waste a cycle and loop */
            continue;

        case 1: /* use the first output from two cycles */
            t = nltap(R, r) ^ CONST_C;
            r = cycle(R, r);
            break;

        case 2: /* use the second output from two cycles */
            r = cycle(R, r);
            t = nltap(R, r);
            break;

        case 3: /* return from one cycle */
            t = nltap(R, r) ^ ~CONST_C;
            break;

        }
	XORWORD(buf, t);
    }
}

/* encrypt/decrypt a frame of data */

void
t32_genbytes(unsigned long frame, unsigned char *buf, int nbytes)
{
    unsigned char   framebuf[4];

    framebuf[0] = (frame >> 24) & 0xFF;
    framebuf[1] = (frame >> 16) & 0xFF;
    framebuf[2] = (frame >>  8) & 0xFF;
    framebuf[3] = (frame) & 0xFF;
    t32_seckey(framebuf, 4);
    t32_gen(buf, nbytes);
}

#ifdef TEST
#include <stdio.h>
#include <string.h>
#include "hexlib.h"

/* test vectors */
typedef unsigned char   uchar;
typedef unsigned long   word32;
uchar   *testkey = (uchar *)"test key 128bits";
word32  testframe = 1L;
uchar   testbuf[40];
WORD	testkonst = 0xf6b8511b;
char    *testout = "05 5a eb be 9f 5b 39 d2 99 df bd 79 e8 58 da 2e fa e0 96 f4"
		"fb fc 5a 04 0b aa 4e 39 ec 7a 3f 7f 38 71 ba 9b 5a b1 55 02"
		;
char    *zeros = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		;
#define ITERATIONS 999999
char    *iterout =
		"79 97 5d d0 cb 2f 83 04 f2 85 85 6b 18 db cf a7 c8 a0 e4 c6"
		"21 f9 88 68 1a df 17 ea 7d 8d cf 32 2a 7d f5 fd fe 3e ee c7"
		;
uchar   bigbuf[1024*1024];

void
test_t32(void)
{
    long	i;

    /* test encryption */
    t32_key(testkey, strlen((char *)testkey));
    printf("%14s: %08lx\n", "konst", konst);
    if (konst != testkonst) 
	printf("Expected %08lx, got %08lx.\n", testkonst, konst);
    t32_genbytes(testframe, testbuf, sizeof testbuf);
    hexprint("testbuf", testbuf, sizeof testbuf);
    hexcheck(testbuf, testout, sizeof testbuf);
    /* test decryption */
    t32_key(testkey, strlen((char *)testkey));
    t32_genbytes(testframe, testbuf, sizeof testbuf);
    hexprint("decryption", testbuf, sizeof testbuf);
    hexcheck(testbuf, zeros, sizeof testbuf);
    /* test iterations */
    t32_key(testkey, strlen((char *)testkey));
    t32_genbytes(testframe, testbuf, sizeof testbuf);
    for (i = 0; i < ITERATIONS; ++i) {
	t32_key(testbuf, 16);
	t32_gen(testbuf, sizeof testbuf);
    }
    hexprint("iterated", testbuf, sizeof testbuf);
    hexcheck(testbuf, iterout, sizeof testbuf);
}

void
time_t32(void)
{
    word32      i;

    t32_key(testkey, strlen((char *)testkey));
    for (i = 0; i < 10; ++i)
        t32_genbytes(i, bigbuf, sizeof bigbuf);
}

void
lsb_t32(void)
{
    register int	i;

    t32_key(testkey, 8);
    for (i = 0; i < 1024; ++i)
	r = cycle(R, r);
    for (i = 0; i < 4096; ++i) {
	r = cycle(R, r);
	printf("%lx", (unsigned long)(R[r] & 0x1));
    }
    printf("\n");
}

#ifndef KEYLOAD
int
main(int ac, char **av)
{
    int         n;
    uchar       key[16];
    int         keysz;
    word32      hook;

    if (ac == 2 && strcmp(av[1], "-test") == 0) {
        test_t32();
        return nerrors;
    }
    if (ac == 2 && strcmp(av[1], "-time") == 0) {
        time_t32();
        return 0;
    }
    if (ac == 2 && strcmp(av[1], "-lsb") == 0) {
        lsb_t32();
        return 0;
    }

    if (ac >= 2)
        hexread(key, av[1], keysz = strlen(av[1]) / 2);
    else
        hexread(key, "0000000000000000", keysz = 8);
    sscanf(ac >= 3 ? av[2] : "00000000", "%lx", &hook);
    sscanf(ac >= 4 ? av[3] : "10000", "%d", &n);

    t32_key(key, keysz);
    if (n > sizeof bigbuf) n = sizeof bigbuf;
    t32_genbytes(hook, bigbuf, n);
    hexbulk(bigbuf, n);
    return 0;
}
#else
#include "stdlib.h"
main(int ac, char **av) {
    int		i, j;
    int		n;
    char	c;
    WORD	state1, state2;
    uchar       key[16];

    sscanf(ac > 1 ? av[1] : "0^", "%x%c", &n, &c);
    for (i = 0; i < 2500; ++i) {
	/* random key */
	for (j = 0; j < sizeof key; ++j)
	    key[j] = random() & 0xFF;
	t32_key(key, sizeof key);
	t32_seckey("\0\0\0\0", 4);
	state1 = R[(r+n)%N];
	t32_seckey("\0\0\0\1", 4);
	state2 = R[(r+n)%N];
	printf("0x%04x\n",
	    c == '^' ?
		state1 ^ state2
		:
		(state1 - state2) & 0xFFFF);
    }
}
#endif
#endif
