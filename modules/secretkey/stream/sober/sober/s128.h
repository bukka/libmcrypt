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

#ifndef _S128_DEFINED
#define _S128_DEFINED 1

#define N 17
#define WORDSIZE 32
#define WORD unsigned long
#define UCHAR unsigned char

#define ROTL(w,x) (((w) << (x))|((w) >> (32 - (x))))
#define ROTR(w,x) (((w) >> (x))|((w) << (32 - (x))))

typedef struct {
    WORD	R[N];		/* Working storage for the shift register */
    WORD	initR[N];	/* saved register contents */ 
    WORD	konst;		/* key dependent constant */
} s128_ctx;

/* interface definitions */
void s128_key(s128_ctx *c, UCHAR key[], int keylen); 	/* set key */
void s128_IV(s128_ctx *c, UCHAR iv[], int ivlen);	/* set Init Vector */
void s128_stream(s128_ctx *c, UCHAR *buf, int nbytes);	/* stream cipher */
void s128_maconly(s128_ctx *c, UCHAR *buf, int nbytes);	/* accumulate MAC */
void s128_encrypt(s128_ctx *c, UCHAR *buf, int nbytes); /* encrypt + MAC */
void s128_decrypt(s128_ctx *c, UCHAR *buf, int nbytes); /* encrypt + MAC */
void s128_finish(s128_ctx *c, UCHAR *buf, int nbytes);	/* finalise MAC */

#endif /* _S128_DEFINED */
