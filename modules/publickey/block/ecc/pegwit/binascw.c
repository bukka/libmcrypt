/* binasc.c
**
**  BAS64 armour by Mr. Tines <tines@windsong.demon.co.uk>
From tines@ravnaandtines.com Thu Dec  7 20:05:04 2000
Date: Thu, 7 Dec 2000 20:50:15 +0000
From: Mr. Tines <tines@ravnaandtines.com>
Reply-To: pegwit@egroups.com
To: pegwit@egroups.com
Subject: Re: [pegwit] ECC status

In message <3A2F62D8.C81BFACF@iname.com>, disastry@iname.com writes
>well.. it's not easy to follow Mr. Tines binasc code,
>must say I also don't understand it fully, but if you send me the code
>I can tray to look what's wrong...

I've not had time&energy recently to look at the current code base.
Looking at the code I have from v8 days, a commentary on the armouring:-

We output 64+\n\0 = 66 character maximum lines, taking up to 48 raw
bytes.

bintoasc takes a 6-bit value and returns a character; the inverse is
asctibin, which takes the (unsigned) character back to the 6-bit value
or 0200 for out of band.

Data are composed into asciiBuffer, with writeHead being the next
character position to write. space is the free space in the buffer,
minus allowance for line end and closing null. bin is the current (up
to) trio of bytes to turn into 4 characters; inBin being the valid
number.

wipeBinascStatic - zeroes all the above

flushBuffer - if there is anything in the buffer, add \n\0 and write it
out, resetting the buffer to empty

encode - takes count bytes from p[] and produces 4 output characters,
with '=' used as padding if only 1 or 2 bytes are input (1 byte in gives
6 bits to the first character, 2 to the 2nd and then "==" is appended; 2
bytes give 6 from the first|2 + 4|4| padding "="

push3bytes - if there is not space for an output quartet, flush; then
append the encoding of what is in bin to the line.

flushArmour - if there is an incomplete triple, encode it anyway - inBin
should be set to <3 so we get padding; then flush 

fwritePlus - acts like fwrite, but does an encoding pass if we're not
going to stdout.  If we are, then we have to model the semantics of
writing n contiguous blocks of size bytes - for each byte, if <3 bytes
in "bin" append across, and step everything along.  When there are 3,
push the buffer out, continuing until all bytes have been flushed.
Every size bytes, increment a counter until we have reached n.  

Note that flushArmour() is needed to clear any trailing bytes.

fputcPlus is a similar wrapper for fputc - append the byte, and encode
it out if we have a trio.

Note that both these, using static buffers as they do, assume that
writes are not happening interleaved to different streams, which would
corrupt things - the old Pegwit architecture meant that assuming that
the output stream was a singleton was a valid one.

In a more modern language, all these file-static data members would be
private data members of an object, and all these functions methods of
that object, private then if static now.



-- PGPfingerprint: BC01 5527 B493 7C9B  3C54 D1B7 248C 08BC --
 _______ {pegwit v8 public key =581cbf05be9899262ab4bb6a08470}
/_  __(_)__  ___ ___     {69c10bcfbca894a5bf8d208d001b829d4d0}
 / / / / _ \/ -_|_-<            http://www.ravnaandtines.com/ 
/_/ /_/_//_/\__/___/@ravnaandtines.com         PGP key on page 

-------------------------- eGroups Sponsor -------------------------~-~>
eLerts
It's Easy. It's Fun. Best of All, it's Free!
http://click.egroups.com/1/9699/0/_/_/_/976222368/
---------------------------------------------------------------------_->

To unsubscribe from this group, send an email to:
pegwit-unsubscribe@egroups.com



*/

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#include "pegwitw.h"
#include "binascw.h"


#define LINE_LEN   48L /* binary bytes per armour line */
#define MAX_LINE_SIZE 66 /* expands to this plus \n\0 over*/

/* Index this array by a 6 bit value to get the character corresponding
 * to that value.  */
 static unsigned char bintoasc[] 
   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Index this array by a 7 bit value to get the 6-bit binary field
 * corresponding to that value.  Any illegal characters return high bit set.
 */
static
unsigned char asctobin[] = {
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0076,0200,0200,0200,0077,
   0064,0065,0066,0067,0070,0071,0072,0073,
   0074,0075,0200,0200,0200,0200,0200,0200,
   0200,0000,0001,0002,0003,0004,0005,0006,
   0007,0010,0011,0012,0013,0014,0015,0016,
   0017,0020,0021,0022,0023,0024,0025,0026,
   0027,0030,0031,0200,0200,0200,0200,0200,
   0200,0032,0033,0034,0035,0036,0037,0040,
   0041,0042,0043,0044,0045,0046,0047,0050,
   0051,0052,0053,0054,0055,0056,0057,0060,
   0061,0062,0063,0200,0200,0200,0200,0200
};


#define PAD      '='
/* the armoured value corresponding to no bits set */
#define ZERO   'A'

static char asciiBuffer[MAX_LINE_SIZE];
static char *writeHead=asciiBuffer;
static int space = MAX_LINE_SIZE-2;
static unsigned char bin[3];
static int inBin = 0;

int getLine(char *buffer, int buflen, char ** t, int addLF)
{
    char *pos;
    int n, crh = 0;

    if (!**t)
      return *buffer = 0;
    pos = strchr(*t, '\n');
    if (pos)
      n = pos - *t + 1;
    else // last line not EOL terminated
      n = strlen(*t);
    if (buflen && n > buflen - 1) {
      n = buflen - 1;
      addLF = 0;
      crh = 1;
    }
    memcpy(buffer, *t, n);
    *t += n;
    if (n > 1 && buffer[n-1] == '\n' && buffer[n-2] == '\r') /* EOL -> \n */
        buffer[--n - 1] = '\n';
    if (addLF && buffer[n-1] != '\n') /* EOL -> \n */
      buffer[n++] = '\n';
    if (crh && buffer[n-1] == '\r' && **t == '\n')
      buffer[n-1] = *((*t)++);
    buffer[n] = 0;
    return n;
}

int putLine(char **buffer, char * t, int addCRLF)
{
    char *pos;
    int n, n1;

    if (!*t)
      return **buffer = 0;
    pos = strchr(t, '\n');
    if (pos)
      n = pos - t + 1;
    else // last line not EOL terminated
      n = strlen(t);
    memcpy(*buffer, t, n);
    n1 = n;
    t += n;
    if (n && (*buffer)[n-1] == '\n' && (*buffer)[n-2] != '\r') { /* EOL -> \r\n */
        (*buffer)[n - 1] = '\r';
        (*buffer)[n++] = '\n';
    }
    if (addCRLF && (*buffer)[n-1] != '\n') { /* EOL -> \r\n */
      (*buffer)[n++] = '\r';
      (*buffer)[n++] = '\n';
    }
    (*buffer)[n] = 0;
    *buffer += n;
    return n1;
}

int putLines(char **buffer, char * t, int addCRLF)
{
    int n, n1 = 0;
    while (*t) {
        n = putLine(buffer, t, addCRLF);
        t += n;
        n1 += n;
    }
    return n1;
}

void burnBinasc(void)
{
  memset( asciiBuffer, 0, sizeof(asciiBuffer) );
  memset( bin, 0, sizeof(bin) );
}

static int flushBuffer(FILE * stream, char **t_out, int nocrlf)
{
   int retv;

   if(asciiBuffer == writeHead )return 1;

   if (!nocrlf) {
       if (!stream)
         *writeHead++ = '\r';
       *writeHead++ = '\n';
   }
   *writeHead++ = '\0';

   writeHead=asciiBuffer;
   space = MAX_LINE_SIZE - 2;
 
// fprintf(stderr,"%s\n",asciiBuffer);
 
   if (stream)
     retv = fputs(asciiBuffer, stream) >= 0;
   if (t_out && *t_out) {
     strcpy(*t_out, asciiBuffer);
     retv = strlen(*t_out);
     *t_out += retv;
   }
   return retv;
}


/* output one group of up to 3 bytes, pointed at by p, on file f. */
static void encode(unsigned char p[3], char buffer[4], int count)
{
   if(count < 3)
   {
      p[count] = 0; /* some bits from this byte may be used */
      buffer[2] = buffer[3] = PAD;
   }
   buffer[0] =     bintoasc[p[0] >> 2];
   buffer[1] =     bintoasc[((p[0] << 4) & 0x30) | ((p[1] >> 4) & 0x0F)];
   if(count > 1)
   {
      buffer[2] = bintoasc[((p[1] << 2) & 0x3C) | ((p[2] >> 6) & 0x03)];
      if(count > 2) buffer[3] = bintoasc[p[2] & 0x3F];
   }
}

static int push3bytes(FILE *stream, char **t_out, int nocrlf)
{
   /* is there space left on the buffer ?*/
   if(space < 4)
   {
      int push = flushBuffer(stream, t_out, nocrlf);
      if(!push) return 0;
   }
   encode(bin, writeHead, inBin);
   inBin = 0;
   writeHead+=4;
   space -= 4;
   return 1;
}


/* flush any left-overs */
int flushArmour(FILE * stream, char **t_out, int nocrlf)
{
   int result = 1;
   if(inBin) result = push3bytes(stream, t_out, nocrlf);
   if(result) result = flushBuffer(stream, t_out, nocrlf);
   return result;
}

size_t fwritePlus(const void *ptr, size_t size, size_t n, FILE *stream, int binmode, char ** t_out)
{
   size_t result = 0;
   unsigned bytesOver = 0;
   unsigned char *out = (unsigned char *)ptr;
/*
fprintf(stderr, "fwrite Plus writing %d bytes\n", n*size);
{
   int i;
   for(i=0; i<4; ++i)
   {
      fprintf(stderr,"%x %x %x %x\n",
      out[0], out[1], out[2], out[3]);
      out+=4;
   }
   out = (unsigned char*)ptr;
}
*/
   if(binmode) {
      if (stream)
         return fwrite(ptr, size, n, stream);
      else
         return 0;
   }

   while(result < n)
   {
      bin[inBin] = *out;
      ++inBin;
      ++out;
      ++bytesOver;
      if(3 == inBin)
      {
         if(!push3bytes(stream, t_out, 0)) return result;
         inBin=0;
      }
      if(bytesOver==size)
      {
         ++result;
         bytesOver = 0;
      }
   }
   return n;
}

int fputcPlus(int c, FILE *stream, int binmode, char **t_out)
{
   if(binmode) {
      if (stream)
         return fputc(c, stream);
      else
         return 0;
   }

   bin[inBin] = (unsigned char)(c & 0xFF);
   ++inBin;
   if(3 == inBin)
   {
      if(!push3bytes(stream, t_out, 0)) return EOF;
      inBin=0;
   }
   return c;
}


/*-------------- Input ASCII Armoured Cyphertext ------------------------*/

static int decodeBuffer(char *inbuf, unsigned char *outbuf, int *outlength)
{
   unsigned char *bp;
   int   length;
   unsigned int c1,c2,c3,c4;
   int hit_padding = 0;

   length = 0;
   bp = (unsigned char *)inbuf;

/*fprintf(stderr, "decodeBuffer >%s<\n", inbuf);*/

   /* FOUR input characters go into each THREE output charcters */

   while(*bp != '\0' && !hit_padding)
   {
      /* check for padding */
      if(bp[3] == PAD)
      {
         hit_padding = 1; /* allow for quoted printable = -> =3D */
         if(bp[2] == PAD || !strcmp((char*)bp + 2, "=3D=3D"))
         {
            length += 1;
            bp[2] = ZERO;
         }
         else
            length += 2;
         bp[3] = ZERO;
      }
      else
         length += 3; /* unpadded */

      if(bp[0] & 0x80 || (c1 = asctobin[bp[0]]) & 0x80 ||
         bp[1] & 0x80 || (c2 = asctobin[bp[1]]) & 0x80 ||
         bp[2] & 0x80 || (c3 = asctobin[bp[2]]) & 0x80 ||
         bp[3] & 0x80 || (c4 = asctobin[bp[3]]) & 0x80)
      {
         return ERR_BADARMOR;
      }
      bp += 4;
      *outbuf++ = (unsigned char)((c1 << 2) | (c2 >> 4));
      *outbuf++ = (unsigned char)((c2 << 4) | (c3 >> 2));
      *outbuf++ = (unsigned char)((c3 << 6) | c4);
   }

   *outlength = length;
   return 1-hit_padding; //!hit_padding;
}

static unsigned char binaryBuffer[LINE_LEN];
static unsigned char *readHead = binaryBuffer;
static int bytesLeft = 0;
static int more = 1;

/* Acts like fread if the stream is a file; from stdin, however
** it expects that the data have been Base64 encoded, so we */

size_t freadPlus(void *ptr, size_t size, size_t n, FILE *stream, int binmode, char **t_inp)
{
   size_t result = 0;
   unsigned bytesOver = 0;
   unsigned char *out = ptr;

   if(binmode) {
      if (stream)
         return fread(ptr, size, n, stream);
      else
         return 0;
   }

   while(result < n)
   {
       /* start by satisying bytes from the buffer */
      if(bytesLeft >= size-bytesOver)
      {
         memcpy(out, readHead, size-bytesOver);
         bytesLeft -= (size-bytesOver);
         readHead += (size-bytesOver);
         out += (size-bytesOver);

         ++result;  /* a chunk satsified, so increment count */
         bytesOver = 0; /* and none left over */
      }
      else
      {
         memcpy(out, readHead, bytesLeft);
         bytesOver += bytesLeft;
         out += bytesLeft;
         bytesLeft = 0;
      }

      /* on buffer exhaustion */
      if(0==bytesLeft)
      {
         int l;
         char inBuf[MAX_LINE_SIZE];

         memset(binaryBuffer, 0, (size_t) LINE_LEN);

         if(!more) break; /* hit the termination */
         if (stream) {
            if(feof(stream)) break; /* end stop */
         } else
            if(!**t_inp) break; /* end stop */

         inBuf[0] = 0; /* Added by George Barwood, 22/4/97 */
         if (stream)
            fgets(inBuf, MAX_LINE_SIZE, stream);  /* 64+\n\0 */
         else
            getLine(inBuf, MAX_LINE_SIZE, t_inp, 0);
         if('#' == inBuf[0]) break;

         l = strlen(inBuf);
         while(inBuf[l-1] < ' ' && l>0){--l; inBuf[l] = '\0';}

         more = decodeBuffer(inBuf, binaryBuffer, &bytesLeft);
         if (more < 0)
            return more;
         memset(inBuf, 0, MAX_LINE_SIZE);
         readHead = binaryBuffer;
      }
   }
/*
fprintf(stderr, "freadPlus returning %d bytes\n", result*size);
{
   int i;
   out = ptr;
   for(i=0; i<4; ++i)
   {
      fprintf(stderr,"%x %x %x %x\n",
      out[0], out[1], out[2], out[3]);
      out+=4;
   }
}
*/
   return result;
}


void init_binasc(void)
{
    writeHead = asciiBuffer;
    space = MAX_LINE_SIZE-2;
    inBin = 0;

    readHead = binaryBuffer;
    bytesLeft = 0;
    more = 1;
}
