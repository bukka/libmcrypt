/* @(#)s128Test.c	1.9 (QUALCOMM SOBER-128) 03/02/24 */
/*
 * Test harness for SOBER-128
 *
 * Copyright C 2002, Qualcomm Inc. Written by Greg Rose
 */

/*
This software is free for commercial and non-commercial use subject to
the following conditions:

1.  Copyright remains vested in QUALCOMM Incorporated, and Copyright
notices in the code are not to be removed.  If this package is used in
a product, QUALCOMM should be given attribution as the author of the
SOBER encryption algorithm. This can be in the form of a textual
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

#include "s128.h"		/* interface definitions */

s128_ctx ctx;

/* testing and timing harness */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "hexlib.h"

/* mostly for debugging, print the LFSR contents. */
int	v = 2; /* disables debug stuff */
void
printLFSR(const char *s, WORD R[])
{
    register int	i;

    if (v < 2) return;
    printf("%s\n", s);
    for (i = 0; i < N; ++i) {
	printf("%*s%08lx\n", i*4, "", R[i]);
    }
}

void
bzero(unsigned char *b, int n)
{
    while (--n >= 0)
	*b++ = 0;
}

/* test vectors */
UCHAR	*testkey = (UCHAR *)"test key 128bits";
UCHAR	*testframe = (UCHAR *)"\0\0\0\0";

#define TESTSIZE 20
#define STREAMTEST 10000
#define ITERATIONS 999999
char    *testout1 =
	"43 50 0c cf 89 91 9f 1d aa 37 74 95 f4 b4 58 c2 40 37 8b bb";
char	*streamout =
	"f3 65 18 3f db 56 7e 50 bc d1 84 1b 76 c9 25 01 56 ca 34 bb";
char	*macout =
	"1c 06 c4 1e cd dc 39 c2 d8 ca f1 eb 19 b6 96 d6 cc 66 60 7f";
char	*encmacout =
	"43 50 0c cf 1a 92 20 c6 9a 0e 44 67 d8 7e 27 17 bd 08 93 4d";
char	*macmacout =
	"1c 06 c4 1e cd dc 39 c2 d8 ca f1 eb 19 b6 96 d6 cc 66 60 7f";
char	*zeros = 
	"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
char    *iterout =
	"2c 80 4d 44 cb eb b7 5e 46 dc 59 8b 80 da f5 47 09 60 03 09";
char	*ivout = 
	"92 28 c7 79 91 75 49 8c 6d 5f fb cd 8a fb 85 07 48 21 4a 8f";

UCHAR	testbuf[STREAMTEST + TESTSIZE];
UCHAR	macbuf[TESTSIZE];
UCHAR	mac[TESTSIZE];
UCHAR	bigbuf[1024*1024];

void
test_s128(int quick)
{
    int		i;
    extern int	keylen;

    /* basic test */
    bzero(testbuf, sizeof testbuf);
    s128_key(&ctx, testkey, strlen((char *)testkey));
    printLFSR("Saved LFSR", ctx.initR);
    s128_IV(&ctx, testframe, 4);
    s128_stream(&ctx, testbuf, TESTSIZE);
    hexprint("one chunk", testbuf, TESTSIZE);
    hexcheck(testbuf, testout1, TESTSIZE);

    /* generate and test more of the same stream */
    s128_stream(&ctx, testbuf + TESTSIZE, STREAMTEST);
    hexprint("STREAMTEST", testbuf + STREAMTEST, TESTSIZE);
    hexcheck(testbuf + STREAMTEST, streamout, TESTSIZE);

    /* generate and check a MAC of an empty buffer */
    bzero(macbuf, sizeof macbuf);
    s128_IV(&ctx, testframe, 4);
    s128_maconly(&ctx, macbuf, sizeof macbuf);
    s128_finish(&ctx, macbuf, sizeof macbuf);
    hexprint("MAC test", macbuf, sizeof macbuf);
    hexcheck(macbuf, macout, sizeof macbuf);

    /* encrypt and MAC an empty buffer */
    bzero(macbuf, sizeof macbuf);
    s128_IV(&ctx, testframe, 4);
    s128_encrypt(&ctx, macbuf, sizeof macbuf);
    hexprint("MAC+enc test", macbuf, sizeof macbuf);
    hexcheck(macbuf, encmacout, sizeof macbuf);
    s128_finish(&ctx, mac, sizeof mac);
    hexprint("final MAC", mac, sizeof mac);
    hexcheck(mac, macmacout, sizeof mac);

    /* now decrypt it and verify the MAC */
    s128_IV(&ctx, testframe, 4);
    s128_decrypt(&ctx, macbuf, sizeof macbuf);
    hexprint("MAC+dec test", macbuf, sizeof macbuf);
    hexcheck(macbuf, zeros, sizeof macbuf);
    s128_finish(&ctx, mac, sizeof mac);
    hexprint("final MAC", mac, sizeof mac);
    hexcheck(mac, macmacout, sizeof mac);

    if (quick)
	return;

    /* test many times iterated */
    for (i = 0; i < ITERATIONS; ++i) {
	if (i % 500 == 0)
	    printf("%6d\r", i), fflush(stdout);
	s128_key(&ctx, testbuf, TESTSIZE);
	s128_stream(&ctx, testbuf, TESTSIZE);
    }
    printf("1000000\n");
    hexprint("iterated", testbuf, TESTSIZE);
    hexcheck(testbuf, iterout, TESTSIZE);

    /* test many times iterated through the IV */
    s128_key(&ctx, testkey, strlen((char *)testkey));
    s128_IV(&ctx, NULL, 0);
    bzero(testbuf, sizeof testbuf);
    s128_stream(&ctx, testbuf, TESTSIZE);
    for (i = 0; i < ITERATIONS; ++i) {
	if (i % 500 == 0)
	    printf("%6d\r", i), fflush(stdout);
	s128_IV(&ctx, testbuf, 4);
	s128_stream(&ctx, testbuf, 4);
    }
    printf("1000000\n");
    hexprint("IV test", testbuf, TESTSIZE);
    hexcheck(testbuf, ivout, TESTSIZE);
}

#define BLOCKSIZE	1600	/* for MAC-style tests */
#define MACSIZE		8
/* Perform various timing tests
 */
void
time_s128(void)
{
    long	i;
    clock_t	t;
    WORD	k[4] = { 0, 0, 0, 0 };

    test_s128(1);
    s128_key(&ctx, testkey, strlen((char *)testkey));
    s128_IV(&ctx, (unsigned char *)"", 0);

    /* test stream generation speed */
    t = clock();
    for (i = 0; i < 200000000; ) {
	i += sizeof bigbuf;
	s128_stream(&ctx, bigbuf, sizeof bigbuf);
    }
    t = clock() - t;
    printf("%f Mbyte per second single stream encryption\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0);

    /* test packet encryption speed */
    t = clock();
    for (i = 0; i < 200000000; ) {
	s128_IV(&ctx, testframe, 4);
	s128_stream(&ctx, bigbuf, BLOCKSIZE);
	i += BLOCKSIZE;
    }
    t = clock() - t;
    printf("%f Mbyte per second encrypt %d-byte blocks\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0,
	BLOCKSIZE, MACSIZE*8);

    /* test MAC generation speed */
    t = clock();
    for (i = 0; i < 200000000; ) {
	s128_IV(&ctx, testframe, 4);
	s128_maconly(&ctx, bigbuf, BLOCKSIZE);
	s128_finish(&ctx, macbuf, MACSIZE);
	i += BLOCKSIZE;
    }
    t = clock() - t;
    printf("%f Mbyte per second MAC %d-byte blocks %d-bit MAC\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0,
	BLOCKSIZE, MACSIZE*8);

    /* test combined encryption speed */
    t = clock();
    for (i = 0; i < 200000000; ) {
	s128_IV(&ctx, testframe, 4);
	s128_encrypt(&ctx, bigbuf, BLOCKSIZE);
	s128_finish(&ctx, macbuf, MACSIZE);
	i += BLOCKSIZE;
    }
    t = clock() - t;
    printf("%f Mbyte per second MAC and encrypt %d-byte blocks %d-bit MAC\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0,
	BLOCKSIZE, MACSIZE*8);

    /* test combined decryption speed */
    t = clock();
    for (i = 0; i < 200000000; ) {
	s128_IV(&ctx, testframe, 4);
	s128_decrypt(&ctx, bigbuf, BLOCKSIZE);
	s128_finish(&ctx, macbuf, MACSIZE);
	i += BLOCKSIZE;
    }
    t = clock() - t;
    printf("%f Mbyte per second decrypt and MAC %d-byte blocks %d-bit MAC\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0,
	BLOCKSIZE, MACSIZE*8);

    /* test key setup time */
    t = clock();
    for (i = 0; i < 10000000; ++i) {
	k[3] = i;
	s128_key(&ctx, (UCHAR *)k, 16);
    }
    t = clock() - t;
    printf("%f million 128-bit keys per second\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0);

    /* test IV setup time */
    t = clock();
    for (i = 0; i < 10000000; ++i) {
	k[3] = i;
	s128_IV(&ctx, (UCHAR *)k, 16);
    }
    t = clock() - t;
    printf("%f million 128-bit IVs per second\n",
	(((double)i/((double)t / (double)CLOCKS_PER_SEC))) / 1000000.0);
}

int
main(int ac, char **av)
{
    int         n, i;
    int		vflag = 0;
    UCHAR	key[32], IV[32];
    int         keysz, IVsz;
    extern int	keylen;
    extern WORD	K[];

    if (ac == 2 && strcmp(av[1], "-test") == 0) {
        test_s128(0);
        return nerrors;
    }
    if (ac == 2 && strcmp(av[1], "-time") == 0) {
        time_s128();
        return 0;
    }

    if (ac >= 2 && strcmp(av[1], "-verbose") == 0) {
	vflag = 1;
	++av, --ac;
    }
    if (ac >= 2)
        hexread(key, av[1], keysz = strlen(av[1]) / 2);
    else
        hexread(key, "0000000000000000", keysz = 8);
    if (ac >= 3)
        hexread(IV, av[2], IVsz = strlen(av[2]) / 2);
    else
        IVsz = 0;
    sscanf(ac >= 4 ? av[3] : "1000000", "%d", &n);

    if ((keysz | IVsz) & 0x3) {
	fprintf(stderr, "Key and IV must be multiple of 4 bytes\n");
	return 1;
    }
    s128_key(&ctx, key, keysz);
    s128_IV(&ctx, IV, IVsz);
    if (vflag) {
	printLFSR("Initial LFSR", ctx.initR);
    }
    while (n > 0) {
	i = sizeof bigbuf;
	i = n > i ? i : n;
	s128_stream(&ctx, bigbuf, i);
	hexbulk(bigbuf, i);
	n -= i;
    }
    return 0;
}
