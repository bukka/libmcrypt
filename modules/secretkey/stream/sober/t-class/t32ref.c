/* @(#)t32ref.c	1.1 (QUALCOMM) 03/21/01 */

/* Header for T32:  32 bit SOBER T-class stream cipher. */
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
#define OPW (WORDSIZE/8) /* Octets per WORD */
#define WORD unsigned long

/* multiplication table and SBox */
#include "multab.h"
#include "sbox.h"

#define UCHAR unsigned char

typedef struct {
    WORD	R[2*N];	/* Working storage for the shift register */
    int 	stcnt;	/* stutter count -- when == 0 next output stored */
    WORD	stctrl;	/* used 1 bits at a time */
    int		r;	/* current offset in sliding window buffer */
    UCHAR	part[OPW]; /* partial generated word */
    int		leftover; /* how many octets of part are valid */
    WORD	initR[N]; /* saved register contents */ 
    WORD	konst;	/* key dependent constant */
} t32_ctx;

void t32_genbytes(t32_ctx *c, UCHAR buf[], int nbytes);

/*
 * FOLD is how many register cycles need to be performed after combining the
 * last byte of key and non-linear feedback, before every byte depends on every
 * byte of the key. This depends on the feedback and nonlinear functions, and
 * on where they are combined into the register.
 */
#define FOLD N        /* how many iterations of folding to do */
#define KEYP 15       /* where to insert key words */
#define FOLDP 4       /* where to insert non-linear feedback */

/* end of header */

/* cycle the contents of the shift register */

static int cycle(WORD *R, int r)
{
    R[r-N] = R[r] = MUL0xC2DB2AA3(R[r-N]) ^ R[r-N+4] ^ R[r-N+15];
    if (++r == 2*N)
        r = N;
    return r;
}

/* Return a non-linear function of some parts of the register.
 */

static WORD
nltap(WORD *R, int r, WORD konst)
{
    WORD   t;

    t = R[r-N+0] + R[r-N+16];
    t = SBox[t >> 24] ^ (t & 0xFFFFFF);
    t = (t + R[r-N+1] + R[r-N+6]) ^ konst;
    return (WORD) (t + R[r-N+13]);
}

/* initialise to known state
 */

void
t32_initstate(t32_ctx *c)
{
    int		i;

    /* Register initialised to Fibonacci numbers */
    c->R[0] = 1;
    c->R[1] = 1;
    for (i = 2; i < N; ++i)
	c->R[i] = c->R[i-1] + c->R[i-2];
    c->r = N;
    c->konst = 0;
    c->stcnt = c->leftover = 0;
}

/* Save the current register state
 */

void
t32_savestate(t32_ctx *c)
{
    int		i;

    for (i = 0; i < N; ++i)
	c->initR[i] = c->R[c->r - N + i];
}

/* initialise to previously saved register state
 */

void
t32_reloadstate(t32_ctx *c)
{
    int		i;

    for (i = 0; i < N; ++i)
	c->R[i] = c->initR[i];
    c->r = N;
    c->stcnt = c->leftover = 0;
}

/* Initialise "konst"
 */
void
t32_genkonst(t32_ctx *c)
{
    c->r = cycle(c->R, c->r);
    c->konst = nltap(c->R, c->r, c->konst);
}

/* Load key material into the register
 */
#define ADDKEY(k) \
    if (c->r-2*N+KEYP < 0) \
	c->R[c->r-N+KEYP] += (k); \
    else \
	c->R[c->r-2*N+KEYP] = c->R[c->r-N+KEYP] = c->R[c->r-N+KEYP] + (k);

#define XORNL(nl) \
    if (c->r-2*N+FOLDP < 0) \
	c->R[c->r-N+FOLDP] ^= (nl); \
    else \
	c->R[c->r-2*N+FOLDP] = c->R[c->r-N+FOLDP] = c->R[c->r-N+FOLDP] ^ (nl);

void
t32_loadkey(t32_ctx *c, UCHAR key[], int keylen)
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
	ADDKEY(k);
        c->r = cycle(c->R, c->r);
	XORNL(nltap(c->R, c->r, c->konst));
    }
    for (i = keylen & 3; i < keylen; i += 4)
    {
	k = (key[i] << 24) + (key[i+1] << 16) + (key[i+2] << 8) + key[i+3];
	ADDKEY(k);
        c->r = cycle(c->R, c->r);
	XORNL(nltap(c->R, c->r, c->konst));
    }

    /* also fold in the length of the key */
    ADDKEY(keylen);

    /* now diffuse */
    for (i = 0; i < FOLD; ++i)
    {
	c->r = cycle(c->R, c->r);
	XORNL(nltap(c->R, c->r, c->konst));
    }
    c->stcnt = c->leftover = 0;
}

/* Handle partial word stores
 * First use up any left over octets.
 * Then if the buffer isn't long enough, generate OPW octets and keep leftovers.
 * Updates buf and nbytes, call with addresses.
 */

void
t32_partial(t32_ctx *c, UCHAR **buf, int *nbytes)
{
    for (;;) {
	while (c->leftover != 0 && *nbytes != 0) {
	    *(*buf)++ ^= c->part[OPW - c->leftover];
	    -- c->leftover;
	    -- *nbytes;
	}
	if (*nbytes >= OPW || *nbytes == 0)
	    return;
	*(WORD *)c->part = 0;
	t32_genbytes(c, c->part, OPW);
	c->leftover = OPW;
    }
}

/* XOR pseudo-random bytes into buffer */

#define XORWORD(p,v) (p[0] ^= ((v) >> 24), p[1] ^= ((v) >> 16), \
		      p[2] ^= ((v) >> 8), p[3] ^= (v), p += OPW)
void
t32_genbytes(t32_ctx *c, UCHAR *buf, int nbytes)
{
    UCHAR       *endbuf;
    WORD	t = 0;

    if (c->leftover != 0)
	t32_partial(c, &buf, &nbytes);
    endbuf = &buf[nbytes & ~(OPW - 1)];
    while (buf < endbuf)
    {
        c->stctrl >>= 2;
	/* reprime stuttering if necessary */
	if (c->stcnt == 0) {
	    c->stcnt = WORDSIZE/2;
	    c->r = cycle(c->R, c->r);
            c->stctrl = nltap(c->R, c->r, c->konst);
        }
        c->stcnt--;

	c->r = cycle(c->R, c->r);
        switch (c->stctrl & 0x3) {

        case 0: /* just waste a cycle and loop */
            continue;

        case 1: /* use the first output from two cycles */
            t = nltap(c->R, c->r, c->konst) ^ CONST_C;
            c->r = cycle(c->R, c->r);
            break;

        case 2: /* use the second output from two cycles */
            c->r = cycle(c->R, c->r);
            t = nltap(c->R, c->r, c->konst);
            break;

        case 3: /* return from one cycle */
            t = nltap(c->R, c->r, c->konst) ^ ~CONST_C;
            break;

        }
	XORWORD(buf, t);
    }
    nbytes &= (OPW - 1);
    if (nbytes != 0)
	t32_partial(c, &buf, &nbytes);
}

#ifdef TEST
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "hexlib.h"

/* test vectors */
typedef unsigned char   uchar;
typedef unsigned long   word32;
uchar   *testkey = (uchar *)"test key 128bits";
uchar   *testframe = (uchar *)"\0\0\0\1";
uchar   testbuf[256];
WORD    testkonst = 0xf6b8511b;
char    *testout1 = /* fixed SBox */
		"05 5a eb be 9f 5b 39 d2 99 df bd 79 e8 58 da 2e"
                "fa e0 96 f4 fb fc 5a 04 0b aa 4e 39 ec 7a 3f 7f 38 71 ba 9b"
                "5a b1 55 02 e0 86 43 a9 9d 16 36 3d 92 da c2 cc 31 ae 48 54"
                "66 b5 b1 3f 3d a8 c4 b0 0a 17 e8 c4 84 f2 b2 93 1f a2 9f 9b"
                "e8 e3 0f 6e be f6 9e 51 72 bf 30 2d e8 35 28 fc 75 78 47 82"
                "1c 70 5d 0d 1b 87 45 c5 8d 19 f6 fd 37 b4 76 9c 32 0f 72 53"
                "32 a4 d4 f3 64 03 d4 74 12 29 c8 dd 84 09 9a dd 88 2b 5e 3a"
                "f7 5e e3 e5 84 9b 5b 81 68 bf da de c7 c8 85 53 81 4a 17 d2"
                "d6 9e 92 5c 21 13 d4 70 5a 76 53 2e 83 6e 6e 48 5d dd 8d 7d"
                "6a 4e bc 40 07 39 e7 a0 97 8f 51 69 b8 c1 e5 ff 06 04 62 2c"
                "d4 a4 3f c1 f9 82 d1 67 9d 46 65 30 82 18 37 f8 7a 16 5d 53"
                "3a 5f 04 6d c0 e2 18 14 93 a9 24 bd fa ab 8d 27 65 d0 a6 90"
                "be 6f 0a dc c3 af ae 4b 51 1c 49 83 4b 76 f8 d2 b7 3a 35 40"
    ;
#define ITERATIONS 999999
char    *iterout =
		"79 97 5d d0 cb 2f 83 04 f2 85 85 6b 18 db cf a7 c8 a0 e4 c6"
		"21 f9 88 68 1a df 17 ea 7d 8d cf 32 2a 7d f5 fd fe 3e ee c7"
		;
uchar   bigbuf[1024*1024];
t32_ctx	ctx, *c = &ctx;

void
test_t32(void)
{
    int		i;

    /* basic test */
    bzero(testbuf, sizeof testbuf);
    t32_initstate(c);
    t32_loadkey(c, testkey, strlen((char *)testkey));
    t32_genkonst(c);
    printf("%14s: %08lx\n", "konst", c->konst);
    if (c->konst != testkonst)
	printf("Expected %08lx, got %08lx.\n", testkonst, c->konst);
    t32_loadkey(c, testframe, 4);
    t32_genbytes(c, testbuf, sizeof testbuf);
    hexprint("one chunk", testbuf, sizeof testbuf);
    hexcheck(testbuf, testout1, sizeof testbuf);

    /* test again, generating little chunks */
    bzero(testbuf, sizeof testbuf);
    t32_initstate(c);
    t32_loadkey(c, testkey, strlen((char *)testkey));
    t32_genkonst(c);
    printf("%14s: %08lx\n", "konst", c->konst);
    if (c->konst != testkonst)
	printf("Expected %08lx, got %08lx.\n", testkonst, c->konst);
    t32_loadkey(c, testframe, 4);
    for (i = 0; i < sizeof testbuf / (OPW+1); ++i)
	t32_genbytes(c, &testbuf[i * (OPW+1)], (OPW+1));
    t32_genbytes(c, &testbuf[i * (OPW+1)], sizeof testbuf - (OPW+1)*i);
    hexprint("many chunks", testbuf, sizeof testbuf);
    hexcheck(testbuf, testout1, sizeof testbuf);

    /* test many times iterated */
    bzero(testbuf, sizeof testbuf);
    t32_initstate(c);
    t32_loadkey(c, testkey, strlen((char *)testkey));
    t32_genkonst(c);
    t32_loadkey(c, testframe, 4);
    t32_genbytes(c, testbuf, 32);
    for (i = 0; i < ITERATIONS; ++i) {
	t32_initstate(c);
	t32_loadkey(c, testbuf, 16);
	t32_genkonst(c);
	t32_genbytes(c, testbuf, 32);
    }
    hexprint("iterated", testbuf, 32);
    hexcheck(testbuf, iterout, 32);
}

void
time_t32(void)
{
    word32      i;

    t32_initstate(c);
    t32_loadkey(c, testkey, strlen((char *)testkey));
    for (i = 0; i < 10; ++i)
	t32_genbytes(c, bigbuf, sizeof bigbuf);
}

void
lsb_t32(void)
{
    register int	i;

    t32_initstate(c);
    t32_loadkey(c, testkey, strlen((char *)testkey));
    for (i = 0; i < 1024; ++i)
	c->r = cycle(c->R, c->r);
    for (i = 0; i < 1024*100; ++i) {
	c->r = cycle(c->R, c->r);
	printf("%lx", (unsigned long)nltap(c->R, c->r, c->konst) & 0x01);
    }
    printf("\n");
}

int
main(int ac, char **av)
{
    int         n;
    uchar       key[32];
    int         keysz;

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
    sscanf(ac >= 3 ? av[2] : "10000", "%d", &n);

    t32_initstate(c);
    t32_loadkey(c, key, keysz);
    t32_genkonst(c);
    t32_loadkey(c, key, keysz);
    t32_genbytes(c, bigbuf, sizeof bigbuf);
    hexbulk(bigbuf, n);
    return 0;
}
#endif
