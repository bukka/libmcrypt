/*
  pegwit (originally) by George Barwood <george.barwood@dial.pipex.com>
  100% Public Domain
  clearsigning code by Mr. Tines <tines@windsong.demon.co.uk>
  also the filter mode support.
  lots of new code by Disastry <Disastry@iname.com>.
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include "sha256.h"

#ifndef USUAL_TYPES
#define USUAL_TYPES
	typedef unsigned char	byte;	/*  8 bit */
	typedef unsigned short	word16;	/* 16 bit */
#ifdef __alpha
	typedef unsigned int	word32;	/* 32 bit */
#else  /* !__alpha */
	typedef unsigned long	word32;	/* 32 bit */
#endif /* ?__alpha */
#endif /* ?USUAL_TYPES */

//#include "blowfish.h"
//#define BF160CBC (0x80)
//#define BF224CBC (0x81)
#include "rijndael-alg-fst.h"
#define RJND256CBC (0x88)
#define RJND224CBC (0x89)

#include "pegwitw.h"
#include "keyring.h"
#include "binascw.h"

#include "field2n.h"
#include "eliptic.h"
#include "protocols.h"

#include "pgwecc.h"

#if defined(WIN32)
//void __stdcall OutputDebugStringA(char * lpOutputString);
//char aaa[1000];
#endif

/*
#if defined(WIN32) && !defined(_CONSOLE)
void MesgBox(const char *m1, const char *m2);
#endif
*/

#if defined(__BORLANDC__) && defined(__MSDOS__)
#include <dos.h>
unsigned _stklen = 32768u;
#endif


static const char pubkey_magic [] = PUBKEY_MAGIC;

static const char begin_clearsign [] = "###\n";
static const char begin_clearsign_lf [] = "###\r\n";
static const char begin_clearsign_0 [] = "###";
static const char end_clearsign [] = "### end pegwit v9 signed text\n";
static const char end_clearsign_lf [] = "### end pegwit v9 signed text\r\n";
static const char end_ckarmour [] = "### end pegwit v9 -fE encrypted text\n";
static const char end_ckarmour_lf [] = "### end pegwit v9 -fE encrypted text\r\n";
static const char end_pkarmour [] = "### end pegwit v9 -fe encrypted text\n";
static const char end_pkarmour_lf [] = "### end pegwit v9 -fe encrypted text\r\n";
static const char escape [] = "## ";
/*
const char warn_long_line [] = 
  "Very long line - > 8k bytes.  Binary file?\n"
  "Clearsignature dubious\a\a\a\n";
const char warn_control_chars [] = 
  "Large number of control characters.  Binary file?\n"
  "Clearsignature dubious\a\a\a\n";
*/

//----------------------------


//limit == 0  -> process whole file
//limit == -1 -> process first line
//limit == n  -> process n bytes
void hash_process_file( hash_context * c, FILE * f_inp, int limit )
{
  unsigned n;
  unsigned char buffer[0x4001];
  while (1)
  {
    n = 0x4000;
    if (limit>=0x4000)
        limit-=0x4000;
    else if (limit>0)
        n = limit;
    n = fread( buffer, 1, n, f_inp ); /* note: no error check */
    if (n==0) break;
    if (limit = -1) {
        buffer[4000] = 0;
        n = strcspn(buffer, "\r\n");
        if (n==0) break;
        buffer[n] = 0;
    }
    hash_process( c, buffer, n );
    if (limit = -1) break;
    if (n < 0x4000) break;
  }
  memset( buffer, 0, sizeof(buffer) );
  fseek( f_inp, 0, SEEK_SET );
}

//limit == 0  -> process whole buffer
//limit == -1 -> process first line
//limit == n  -> process n bytes
void hash_process_buf( hash_context * c, char * t_inp, int limit )
{
  unsigned n;
  unsigned char buffer[0x4000];
  while (*t_inp)
  {
    n = getLine(buffer, sizeof(buffer), &t_inp, 0);

    if (n==0) break;
    if (limit = -1) {
        buffer[4000] = 0;
        n = strcspn(buffer, "\r\n");
        if (n==0) break;
        buffer[n] = 0;
    }
    hash_process( c, buffer, n );
    if (limit = -1) break;
  }
}

int downcase(char c)
{
      if(isascii(c)) if(isupper(c)) return tolower(c);
      return c;
}

int case_blind_compare(const char *a, const char *b)
{
    while(*a && *b)
    {
        if(downcase(*a) < downcase(*b)) return -1;
        if(downcase(*a) > downcase(*b)) return 1;
        a += 1;
        b += 1;
    }
    if(*a) return 1;
    if(*b) return -1;
    return 0;
}

int hash_process_ascii( hash_context * c, FILE * f_inp,
  FILE * f_out, int write)
{
  unsigned n, ll;
  unsigned char buffer[0x4000], *begin;
  unsigned long bytes=0, control=0;

  ll = 0;
  while (1)
  {
      unsigned i;
      
      fgets((char*)buffer, 0x4000, f_inp);  /* EOL -> \n */
      if(feof(f_inp)) break;

      n = strlen((char*)buffer);
      begin = buffer;

      if(n > 0x2000)
      {
        ll++;
      }

      bytes += n;
      for(i=0; i<n; ++i)
      {
        if(buffer[i] >= 0x7F) ++control;
        if(buffer[i] < ' ' && buffer[i] != '\n' && buffer[i] != '\r'
          && buffer[i] != '\t') ++control;
      }

      if(write)
      {
        if (!strncmp( (char*)buffer, escape, 2 ) ||
            !case_blind_compare((char*)buffer, "from") )
        {
          fputs( escape, f_out );
        }
        fputs( (char*)buffer, f_out);
      }
      else
      {
        if(!strncmp((char*)buffer, escape, 3)) {n-=3, begin+=3;}
        else if(!strncmp((char*)buffer, end_clearsign, 3)) break; /* must be end of packet */
        fputs((char*)begin, f_out);
      }

      hash_process( c, begin, n );
  }
  //if(ll) {
  //  //fputs( warn_long_line, stderr );
  //  MessageOut(warn_long_line, 0);
  //}
  //if(control*6 > bytes)
  //{
  //  //fputs( warn_control_chars, stderr );
  //  MessageOut(warn_control_chars, 0);
  //}

  memset( buffer, 0, sizeof(buffer) );
  return ERR_NOERROR;
}

int hash_process_ascii_buf( hash_context * c, char ** t_inp,
  char ** t_out, int write)
{
  unsigned n, ll;
  unsigned char buffer[0x4000], *begin;
  unsigned long bytes=0, control=0;

  ll = 0;
  while (**t_inp)
  {
      unsigned i;
      
      n = getLine(buffer, sizeof(buffer), t_inp, 1);

      begin = buffer;

      if(n > 0x2000)
      {
        ll++;
      }

      bytes += n;
      for(i=0; i<n; ++i)
      {
        if(buffer[i] >= 0x7F) ++control;
        if(buffer[i] < ' ' && buffer[i] != '\n' && buffer[i] != '\r'
          && buffer[i] != '\t') ++control;
      }

      if(write)
      {
        if (!strncmp( (char*)buffer, escape, 2 ) ||
            !case_blind_compare((char*)buffer, "from") )
        {
          putLine(t_out, (char *)escape, 0);
        }
        putLine(t_out, buffer, 1);
      }
      else
      {
        if(!strncmp((char*)buffer, escape, 3)) {n-=3, begin+=3;}
        else if(!strncmp((char*)buffer, end_clearsign, 3)) break; /* must be end of packet */
        putLine(t_out, begin, 1);
      }

      hash_process( c, begin, n );
  }
  //if(ll) {
  //  //fputs( warn_long_line, stderr );
  //  MessageOut(warn_long_line, 0);
  //}
  //if(control*6 > bytes)
  //{
  //  //fputs( warn_control_chars, stderr );
  //  MessageOut(warn_control_chars, 0);
  //}

  memset( buffer, 0, sizeof(buffer) );
  return ERR_NOERROR;
}


typedef struct /* Whole structure will be hashed */
{
  unsigned count;        /* Count of words */
  word32 seed[2+HW*2];   /* Used to crank prng */
} prng;

prng g_prnd = {0,{0}};

void prng_init( void * prnd )
{
  if (!prnd) prnd = &g_prnd;
  memset( prnd, 0, sizeof(prng) );
}

/*  I think this just hashes the input ascii pass phrase to
create the actuall secret.  Let's do it more simple.  */

void prng_set_count( prng * prnd, unsigned count )
{
    if (prnd->count < count)
        prnd->count = count;
}

void prng_set_secret( prng * prnd, FILE * f_key, int limit )
{
  hash_context c[1];
  hash_initial( c );
  hash_process_file( c, f_key, limit );
  hash_final( c, prnd->seed+1 );
  prng_set_count(prnd, 1+HW);
}

void prng_set_secret_buf( prng * prnd, char * t_key, int limit )
{
  hash_context c[1];
  hash_initial( c );
  hash_process_buf( c, t_key, limit );
  hash_final( c, prnd->seed+1 );
  prng_set_count(prnd, 1+HW);
}

void prng_init_mac(hash_context c[1])
{
  hash_initial( c );
}

void prng_set_mac( prng * prnd, FILE * f_inp )
{
  hash_context c[1];
  hash_initial( c );
  hash_process_file( c, f_inp, 0 );
  hash_final( c, prnd->seed+1+HW );
  prng_set_count(prnd, 1 + 2*HW);
}

void prng_set_mac_buf( prng * prnd, char * t_inp )
{
  hash_context c[1];
  hash_initial( c );
  hash_process_buf( c, t_inp, 0 );
  hash_final( c, prnd->seed+1+HW );
  prng_set_count(prnd, 1 + 2*HW);
}

void prng_set_rnd( void * vprnd, FILE * f_inp, char * t_inp, int s_inp )
{
  hash_context c[1];
  prng * prnd = vprnd;

  if (!prnd) prnd = &g_prnd;
  hash_initial( c );
  if (prnd->count)
    hash_process( c, (char *)prnd->seed, prnd->count*4 );
  if (f_inp)
    hash_process_file( c, f_inp, s_inp );
  if (t_inp) {
    if (s_inp) hash_process( c, t_inp, s_inp );
    else hash_process_buf( c, t_inp, 0 );
  }
  hash_final( c, prnd->seed+1+ (prnd->seed[0]&1)*HW );
  prng_set_count(prnd, 1+((prnd->seed[0]&1)+1)*HW);
  prnd->seed[0] ++;
}

void clearsign( prng * prnd, FILE * f_inp, FILE * f_out )
{
  hash_context c[1];

  prng_init_mac(c);
  fputs(begin_clearsign,f_out);
  hash_process_ascii( c, f_inp, f_out, 1 );
  fputs(end_clearsign,f_out);
  hash_final( c, prnd->seed+1+HW );
  prng_set_count(prnd, 1 + 2*HW);
}

void clearsign_buf( prng * prnd, char * t_inp, char * t_out )
{
  hash_context c[2];

  prng_init_mac(c);
  strcpy(t_out, begin_clearsign_lf);
  t_out += strlen(t_out);
  hash_process_ascii_buf( c, &t_inp, &t_out, 1 );
  strcpy(t_out, end_clearsign_lf);
  hash_final( c, prnd->seed+1+HW );
  prng_set_count(prnd, 1 + 2*HW);
}

int position(FILE  * f_inp) /* scan ascii file for ### introducer */
{
  while(!feof(f_inp))
  {
      char buffer[1024];
      fgets(buffer, 1024, f_inp);
      if(!strncmp(buffer, begin_clearsign, 3)) break;
  }
  if(feof(f_inp))
    return ERR_NOHEADER;
  return ERR_NOERROR;
}

int position_buf(char ** t_inp) /* scan ascii file for ### introducer */
{
  char *pos;
  int n;

  pos = strstr(*t_inp, begin_clearsign_0);
  if (pos)
    if (pos != *t_inp)
      if (*(pos-1) != '\n')
        pos = NULL;
  if (pos) {
    pos += strlen(begin_clearsign_0);
    if (*pos == '\r')
      pos++;
    if (*pos != '\n')
      pos = NULL;
  }
  if (!pos)
    return ERR_NOHEADER;
  n = pos - *t_inp + 1;
  *t_inp += n;
  //return n;
  return ERR_NOERROR;
}

int readsign( prng * prnd, FILE * f_inp, FILE * f_out )
{
  int pos;
  hash_context c[2];
  prng_init_mac(c);

  pos = position(f_inp);
  if(pos<0) return pos;
  hash_process_ascii( c, f_inp, f_out, 0 );
  hash_final( c, prnd->seed+1+HW );
  prng_set_count(prnd, 1 + 2*HW);
  return ERR_NOERROR;
}

int readsign_buf( prng * prnd, char ** t_inp, char * t_out )
{
  int pos;

  hash_context c[2];
  prng_init_mac(c);

  pos = position_buf(t_inp);
  if(pos<0) return pos;
  *t_out = 0;
  hash_process_ascii_buf( c, t_inp, &t_out, 0 );
  hash_final( c, prnd->seed+1+HW );
  prng_set_count(prnd, 1 + 2*HW);
  return ERR_NOERROR;
}

void prng_set_time( prng * prnd )
{
  prnd->seed[1+2*HW] = (word32) time(0);
  prng_set_count(prnd, 2 + 2*HW);
}

word32 prng_next( prng * prnd )
{
  word32 tmp[HW];
  byte buffer[ (2*HW + 2) * 4 ];
  unsigned i,j;
  hash_context c;

  prnd->seed[0] += 1;
  for ( i = 0; i < prnd->count; i++ )
  {
    for ( j = 0; j < 4; j++ )
    {
      buffer[ i*4 + j ] = (byte) ( prnd->seed[i] >> (j*8) );
    }
  }
  
  hash_initial( &c );
  hash_process( &c, buffer, prnd->count*4 );
  hash_final( &c, tmp );
  memset( buffer, 0, sizeof(buffer) );
  return tmp[0];
}

void prng_to_vlong( prng * prnd, FIELD2N * V )
{
  int i;
  SUMLOOP(i)
   V->e[i] = (ELEMENT) prng_next( prnd );
  V->e[0] &= UPRMASK;
}

void hash_to_vlong( word32 * mac, FIELD2N * V )
{
  int i;
  SUMLOOP(i) {
    if (i<HW)
      V->e[NUMWORD-i] = mac[i];
    else
      V->e[NUMWORD-i] = 0;
  }
  V->e[0] &= UPRMASK;
}

/*
void get_vlong( FILE *f,  FIELD2N * v )
{
  int k;
  char u;
  null (v);
  k = NUMBITS & (~3);
  while (1)
  {
    u = fgetc( f );
    if ( u >= '0' && u <= '9' )
      u -= '0';
    else if ( u >= 'a' && u <= 'z' )
      u -= 'a' - 10;
    else if ( u >= 'A' && u <= 'Z' )
      u -= 'A' - 10;
    else if ( u <= ' ' )
      continue;
    else
      break;
    if (k>=0) {
        v->e[NUMWORD-k/WORDSIZE] |= u << (k%WORDSIZE);
        k-=4;
    }
  }
}

void get_vlong_buf( char *t, FIELD2N * v )
{
  int k;
  char u;
  null (v);
  k = NUMBITS & (~3);
  while (1)
  {
    u = *t++;
    if (!u)
      break;
    if ( u >= '0' && u <= '9' )
      u -= '0';
    else if ( u >= 'a' && u <= 'z' )
      u -= 'a' - 10;
    else if ( u >= 'A' && u <= 'Z' )
      u -= 'A' - 10;
    else if ( u <= ' ' )
      continue;
    else
      break;
    if (k>=0) {
        v->e[NUMWORD-k/WORDSIZE] |= u << (k%WORDSIZE);
        k-=4;
    }
  }
}
*/
/*
void get_vlong_a( FILE *f, FIELD2N * v )
{
  int i=0, k;
  char buffer[256], u;

  null (v);
  k = NUMBITS & (~3);
  buffer[0]=0;
  fgets(buffer, 256, f);

  while ((u = buffer[i++]) != 0)
  {
    if ( u >= '0' && u <= '9' )
      u -= '0';
    else if ( u >= 'a' && u <= 'z' )
      u -= 'a' - 10;
    else if ( u >= 'A' && u <= 'Z' )
      u -= 'A' - 10;
    else if ( u <= ' ' )
      continue;
    else
      break;
    if (k>=0) {
        v->e[NUMWORD-k/WORDSIZE] |= u << (k%WORDSIZE);
        k-=4;
    }
  }
}

void get_vlong_a_buf( char **t, FIELD2N * v )
{
  int i=0, k;
  char buffer[256], u;

  null (v);
  k = NUMBITS & (~3);
  buffer[0]=0;

  getLine(buffer, sizeof(buffer), t, 0);

  while ((u = buffer[i++]) != 0)
  {
    if ( u >= '0' && u <= '9' )
      u -= '0';
    else if ( u >= 'a' && u <= 'z' )
      u -= 'a' - 10;
    else if ( u >= 'A' && u <= 'Z' )
      u -= 'A' - 10;
    else if ( u <= ' ' )
      continue;
    else
      break;
    if (k>=0) {
        v->e[NUMWORD-k/WORDSIZE] |= u << (k%WORDSIZE);
        k-=4;
    }
  }
}
*/
/*
const char hex[16] = "0123456789abcdef";
//  convert a field2n to a hex ascii string, see print_field

void put_vlong( FIELD2N * v, FILE *f )
{
  int i,j;
  unsigned x;
   
  SUMLOOP(i)
  {
    x = v->e[i];
    for (j=WORDSIZE-4;j>=0;j-=4) {
      if (i || j < UPRSHIFT)
        fputc( hex[ (x >> j) & 0xF ], f );
    }
  }
}

void put_vlong_buf( FIELD2N * v, char **t )
{
  int i,j;
  *t += strlen(*t);
  SUMLOOP(i)
  {
    unsigned x = v->e[i];
    for (j=WORDSIZE-4;j>=0;j-=4) {
      if (i || j < UPRSHIFT)
        *(*t)++ = hex[ (x >> j) & 0xF ];
    }
  }
  **t = 0;
}
*/

void put_binary_vlong (FILE *f, FIELD2N * v, int binmode, char **t)
{
  int i,j;
  SUMLOOPD(i)
  {
    unsigned x = v->e[i];
    for (j=0;j<WORDSIZE;j+=8) {
      if (i || j < UPRSHIFT)
        fputcPlus ((x >> j) & 0xFF, f, binmode, t);
    }
  }
}

int get_binary_vlong(FILE *f, FIELD2N * v, int binmode, char **t)
{
  int i;
  byte u[NUMBYTES];
  unsigned n = NUMBYTES;
  null (v);

  i = freadPlus(u, 1, NUMBYTES, f, binmode, t);
  if (i == -1)
    return ERR_INPUT;
  if (i != NUMBYTES)
    return ERR_INPUT;
  while (n--)
  {
    v->e[NUMWORD-n/WORDBYTES] |= u[n] << ((n%WORDBYTES)*8);
  }
  return ERR_NOERROR;
}

int get_binary_byte(FILE *f, byte *b, int binmode, char **t)
{
  byte u[2];
  int i;

  i = freadPlus(u, 1, 1, f, binmode, t);
  if (i == -1)
    return ERR_INPUT;
  *b=u[0];
  return ERR_NOERROR;
}

#define BIG_BLOCK_SIZE 0x1000
//#define BIG_BLOCK_SIZE 0x20 // for testing
typedef word32 big_buf[BIG_BLOCK_SIZE/4 + 5]; /* Use word32 to force alignment */
/* 3 extra words to cope with expansion */
//#define BS 8
#define BS 16
#define RK 14

int sym_encrypt( FIELD2N * secret, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** t_out, int cph )
{
  //BLOWFISH_CTX ctx;
  u32 rk[4*(RK + 1)];
  word32 Cprev[4] = {0, 0, 0, 0}, *C[4];
  big_buf buffer;
  char *cbuf = (char *)buffer;
  int err = ERR_NOERROR, n = 0, n1, n0, bi, t = BS+1, written, lastb, iii;
  FIELD2N secretk;

  if (t_out && !*t_out) t_out = 0;
  if ((!f_inp && !t_inp) || ( f_inp &&  t_inp) || 
      (binmode && (t_inp || t_out)))
    err = ERR_BADPARAM;

  //if (cph == BF224CBC)
  //  Blowfish_Init (&ctx, (unsigned char*)&(secret->e[1]), (NUMWORD)*WORDBYTES);
  //else if (cph == BF160CBC)
  //  Blowfish_Init (&ctx, (unsigned char*)&(secret->e[3]), (NUMWORD-2)*WORDBYTES);
  //else err = ERR_BADPARAM;

  copy(secret, &secretk);
  if (cph == RJND224CBC)
    secretk.e[0] = secretk.e[NUMWORD]; // only 224 bytes used
  else if (cph != RJND256CBC)
    err = ERR_BADPARAM;

  if (!err)
    rijndaelKeySetupEnc(rk, (unsigned char*)&secretk, 256);

  while (!err) {
    n1 = 0;
    if (f_inp)
      n1 = fread( cbuf+(BS+1-t), 1, BIG_BLOCK_SIZE+t, f_inp );
    else
      for (n1 = 0; n1<BIG_BLOCK_SIZE; n1 += n0) {
        n0 = getLine(cbuf+(BS+1-t)+n1, BIG_BLOCK_SIZE+t-n1+1, &t_inp, 1);
        if (!n0)
          break;
      }
    n1 += n;
    if (!n1) {
      written = fwritePlus( &lastb,1,1,f_out, binmode, t_out );
      if ( written != 1 ) err = ERR_OUTPUT;
      break;
    }
    if (n1>BIG_BLOCK_SIZE+BS)
        n = BIG_BLOCK_SIZE;
    else if (n1<=BIG_BLOCK_SIZE)
        n=n1;
    else // n1>BIG_BLOCK_SIZE && n1<=BIG_BLOCK_SIZE+BS-1
        n=n1;
    if (n1<BS && t) {
      time((long *)(cbuf+n1));
      n = BS;
    }
    for (bi=0; bi+BS<=n; bi+=BS) {
        if (bi+BS*2>n && (n&(BS-1))) {
            //for (iii=0;iii<BS/4;iii++)
            //  *(unsigned long *)(cbuf+n-BS+iii*4) ^= Cprev[iii];
            //Blowfish_Encrypt(&ctx, (unsigned long *)(cbuf+n-8), (unsigned long *)(cbuf+n-4));
            rijndaelEncrypt(rk, RK, (cbuf+n-BS), (cbuf+n-BS));
        }
        for (iii=0;iii<BS/4;iii++) {
          C[iii] = (unsigned long *)(cbuf+bi+iii*4);
          *C[iii] ^= Cprev[iii];
        }
        //Blowfish_Encrypt(&ctx, C0, C1);
        rijndaelEncrypt(rk, RK, (cbuf+bi), (cbuf+bi));
        for (iii=0;iii<BS/4;iii++)
          Cprev[iii] = *C[iii];
    }
    if (n1<BS && t) {
      lastb = n1;
      n = BS;
    } else
      lastb = 0;
    written = fwritePlus( cbuf,1,n,f_out, binmode, t_out );
    if ( written != n ) {err = ERR_OUTPUT; break;}
    n = 0;
    if (n1>BIG_BLOCK_SIZE+BS) {
        n = n1-BIG_BLOCK_SIZE;
        memmove(cbuf, cbuf+BIG_BLOCK_SIZE, n);
    }
    t = 0;
  } // while

  //memset( &ctx, 0, sizeof(ctx) );
  memset( &rk, 0, sizeof(rk) );
  return err;
} // sym_encrypt

int sym_decrypt( FIELD2N * secret, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char * t_out, int cph )
{
  //BLOWFISH_CTX ctx;
  u32 rk[4*(RK + 1)];
  word32 Cprev[4] = {0, 0, 0, 0}, *C[4], Ctmp[4];
  big_buf buffer;
  char *cbuf = (char *)buffer, tmp;
  int err = ERR_NOERROR, n = 0, n1, bi, t = BS+1, written, iii;
  FIELD2N secretk;

  if ((!f_inp && !t_inp) || ( f_inp &&  t_inp) || 
      (binmode && (t_inp || t_out)))
    err = ERR_BADPARAM;

  //if (cph == BF224CBC)
  //  Blowfish_Init (&ctx, (unsigned char*)&(secret->e[1]), (NUMWORD)*WORDBYTES);
  //else if (cph == BF160CBC)
  //  Blowfish_Init (&ctx, (unsigned char*)&(secret->e[3]), (NUMWORD-2)*WORDBYTES);
  //else err = ERR_BADPARAM;

  copy(secret, &secretk);
  if (cph == RJND224CBC)
    secretk.e[0] = secretk.e[NUMWORD]; // only 224 bytes used
  else if (cph != RJND256CBC)
    err = ERR_BADPARAM;

  if (!err)
    rijndaelKeySetupDec(rk, (unsigned char*)&secretk, 256);

  while (!err) {
    n1 = freadPlus( cbuf+(BS+1-t), 1, BIG_BLOCK_SIZE+t, f_inp, binmode, &t_inp );
    if (n1 == -1) {err = ERR_INPUT; break;}
    n1+=n;
    if (!n1)
      break;
    if (n1>BIG_BLOCK_SIZE+BS)
        n = BIG_BLOCK_SIZE;
    else if (n1<=BIG_BLOCK_SIZE)
        n=n1-1;
    else // n1>BIG_BLOCK_SIZE && n1<=BIG_BLOCK_SIZE+BS-1
        n=n1-1;
    for (bi=0; bi<n; bi+=BS) {
        if (bi+BS>n) {
              bi = n-(BS-bi%BS);
              for (iii=0;iii<BS/4;iii++)
                Cprev[iii] = 0;
        }
        for (iii=0;iii<BS/4;iii++) {
          C[iii] = (unsigned long *)(cbuf+bi+iii*4);
          Ctmp[iii] = *C[iii];
        }
        //Blowfish_Decrypt(&ctx, C0, C1);
        rijndaelDecrypt(rk, RK, (cbuf+bi), (cbuf+bi));
        for (iii=0;iii<BS/4;iii++) {
          *C[iii] ^= Cprev[iii];
          Cprev[iii] = Ctmp[iii];
        }
    }
    if (n1<=BS+1 && t) {
        n = cbuf[BS];
        if (n>BS-1) {err = ERR_SYMDECRYPT; break;}
        if (n==0)
          n = BS;
    } else
    if (n1<=BIG_BLOCK_SIZE)
        if (cbuf[n] !=0) {err = ERR_SYMDECRYPT; break;}

    if (f_out)
      written = fwrite( cbuf, 1, n, f_out );
    if (t_out) {
      tmp = cbuf[n];
      cbuf[n] = 0;
      putLines(&t_out, cbuf, 0);
      cbuf[n] = tmp;
      written = n;
    }
    if ( written != n ) {err = ERR_OUTPUT; break;}
    n = 0;
    if (n1>BIG_BLOCK_SIZE+BS) {
        n = n1-BIG_BLOCK_SIZE;
        memmove(cbuf, cbuf+BIG_BLOCK_SIZE, n);
    }
    t = 0;
  } // while

  //memset( &ctx, 0, sizeof(ctx) );
  memset( &rk, 0, sizeof(rk) );
  return err;
} // sym_decrypt

int do_make_key( FILE * f_key, char * t_key, FILE * f_out, char ** pt_out)
{ // i
  prng prnd;
  FIELD2N pub,secret;
  int err = ERR_NOERROR;
  char * t_out;

  do {
    if ((!f_key && !t_key) || (!f_out && !pt_out) ||
        ( f_key &&  t_key))
      {err = ERR_BADPARAM; break;}

    init_binasc();

    /* Initialise the prng and calculate keys */

    prng_init( &prnd );

    if (t_key) prng_set_secret_buf( &prnd, t_key, -1 );
    if (f_key) prng_set_secret( &prnd, f_key, -1 );
    prng_to_vlong( &prnd, &secret );
    prng_init( &prnd );

  /* Do operation */

//#ifdef _DEBUG
//print_field("secret key", &secret);
//#endif
    MakePublicKey( &pub, &secret );
//#ifdef _DEBUG
//print_field("public key", &pub);
//#endif
    if (f_out) {
        fputs( pubkey_magic, f_out);
        //put_vlong( &pub, f_out );
        put_binary_vlong( f_out, &pub, 0, 0 );
        if(!flushArmour(f_out, 0, 0))
          err = ERR_OUTPUT;
//          fprintf(stderr,"err=%d\n",err);
    }
    t_out = 0;
    if (pt_out) {
        *pt_out = p_malloc(KEYSIZE+1);
        if (!*pt_out) {err = ERR_NOMEMORY; break;}
        t_out = *pt_out;
        //put_vlong_buf( &pub, &t_out );
        put_binary_vlong( 0, &pub, 0, &t_out );
        if(!flushArmour(0, &t_out, 1))
            {err = ERR_OUTPUT; break;}
    }
  } while (0);

  //if (t_key) free(t_key);
  if (err && pt_out && *pt_out) {free(*pt_out); *pt_out = NULL;}
  if (f_out) fflush(f_out);
  /* burn sensistive information */
  null( &secret );
  return err;
} // do_make_key

int do_encrypt_pk( FILE ** pf_key, char ** pt_key, FILE * f_inp, FILE * f_out, FILE * f_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec, unsigned numkey)
{ // e
  prng prnd;
  FIELD2N session,rval,msg1,msg2;
  FIELD2N *ppub;
  int err = ERR_NOERROR;
  unsigned kn;
  char * t_out, * t_tmp;
  FILE * f_tmp;

  do {
    if ((!pf_key && !pt_key) || (!f_inp && !t_inp) || (!f_out && !pt_out) || (!f_sec && !t_sec) ||
                                ( f_inp &&  t_inp) ||                        ( f_sec &&  t_sec) ||
        (pt_out && !t_inp) ||
        (binmode && (t_inp || pt_out)) ||
         numkey>127 || numkey<1)
      {err = ERR_BADPARAM; break;}

    ppub = malloc(numkey * sizeof(FIELD2N));
    if (!ppub) {err = ERR_NOMEMORY; break;}

    init_binasc();

    /* Initialise the prng and calculate keys */

    prng_init( &prnd );

    /* public key operations */
    for (kn = 0; kn < numkey && !err; kn++) {
      //if (pt_key) get_vlong_buf( pt_key[kn], &ppub[kn] ); /* should be a validity check here */
      //if (pf_key) get_vlong( pf_key[kn], &ppub[kn] ); /* should be a validity check here */
      t_tmp = pt_key ? pt_key[kn] : 0;
      f_tmp = pf_key ? pf_key[kn] : 0;
      if ((!f_tmp && !t_tmp) || ( f_tmp &&  t_tmp))
        err = ERR_BADPARAM;
      else
        err = get_binary_vlong( f_tmp, &ppub[kn], 0, &t_tmp );
    }
    if (err) break;

    //if (f_sec) prng_set_secret( &prnd, f_sec, 512 ); // 512 - in case it is /dev/random (or other stream)
    //if (t_sec) prng_set_secret_buf( &prnd, t_sec, 0 );
    //if (f_inp) prng_set_mac( &prnd, f_inp );
    //if (t_inp) prng_set_mac_buf( &prnd, t_inp );
    if (f_sec) prng_set_rnd( &prnd, f_sec, 0, 512 );
    if (t_sec) prng_set_rnd( &prnd, 0, t_sec, 0 );
    prng_set_rnd( &prnd, f_inp, t_inp, 0 );

    if (g_prnd.count) prng_set_rnd( &prnd, 0, (char *)g_prnd.seed, g_prnd.count*4 ); // add global entropy if collected

    /* Do operation */

    t_out = 0;
    if (t_inp && pt_out) {
      *pt_out = p_malloc((size_t)((double)strlen(t_inp) * 1.4)+80+80*numkey); // not good
      if (!*pt_out) {err = ERR_NOMEMORY; break;}
      t_out = *pt_out;
      *t_out = 0;
    }

    if(!binmode) {
      if (f_out) fputs(begin_clearsign,f_out);
      if (t_out) { strcpy(t_out, begin_clearsign_lf); t_out += strlen(t_out); }
    }

    fputcPlus (numkey, f_out, binmode, &t_out); // number of recipients
    prng_set_time( &prnd );
    prng_to_vlong( &prnd, &session );
//#ifdef _DEBUG
//print_field("session", &session);
//#endif
    for (kn=0; kn<numkey; kn++) {
        prng_set_time( &prnd );
        prng_to_vlong( &prnd, &rval );
//#ifdef _DEBUG
//print_field("public key", &ppub[kn]);
//#endif
//sprintf(aaa, "pubkey: %08x %08x\n", ppub[kn].e[0], ppub[kn].e[1]);
//OutputDebugStringA(aaa);
//sprintf(aaa, "session: %08x %08x\n", session.e[0], session.e[1]);
//OutputDebugStringA(aaa);
        EncodeSecret( &ppub[kn], &session, &rval, &msg1, &msg2);
        put_binary_vlong( f_out, &msg1, binmode, &t_out );
        put_binary_vlong( f_out, &msg2, binmode, &t_out );
//#ifdef _DEBUG
//print_field("msg1", &msg1);
//print_field("msg2", &msg2);
//#endif
    }
    //fputcPlus (BF224CBC, f_out, binmode, &t_out); // cipher
    //err = sym_encrypt( &session, f_inp, f_out, binmode, t_inp, &t_out, BF224CBC);
    fputcPlus (RJND224CBC, f_out, binmode, &t_out); // cipher
    err = sym_encrypt( &session, f_inp, f_out, binmode, t_inp, &t_out, RJND224CBC);
    if (err) break;

    if(!binmode) {
        if(!flushArmour(f_out, &t_out, 0))
          {err = ERR_OUTPUT; break;}
        if (f_out) fputs(end_pkarmour, f_out);
        if (t_out) strcpy(t_out, end_pkarmour_lf);
    }
  } while (0);

  //if (pt_key) for (kn = 0; kn < numkey; kn++) if (pt_key[kn]) free(pt_key[kn]);
  //if (t_sec) free(t_sec);
  //if (t_inp) free(t_inp);
  if (err && pt_out && *pt_out) {free(*pt_out); *pt_out = NULL;}
  if (f_out) fflush(f_out);
  /* burn sensistive information */
  prng_init( &prnd );
  null ( &session );
  null ( &rval );
  return err;
} // do_encrypt_pk

int do_decrypt_pk( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out, unsigned * keyn)
{ // d
  prng prnd;
  FIELD2N secret,session,msg1,msg2;
  int err = ERR_NOERROR, rdkc = 1;
  unsigned kn;
  char * t_out, * t_tmp;
  unsigned int b = 0;
  //char mstr[50];

  do {
    if ((!f_key && !t_key) || (!f_inp && !t_inp) || (!f_out && !pt_out) ||
        ( f_key &&  t_key) || ( f_inp &&  t_inp) ||
        (pt_out && !t_inp) ||
        (binmode && (t_inp || pt_out)) || !keyn)
      {err = ERR_BADPARAM; *keyn = 0; break;}
    else if (*keyn>127 || *keyn<1)
      {err = ERR_BADPARAM; *keyn = 0; break;}

    init_binasc();

    /* Initialise the prng and calculate keys */

    prng_init( &prnd );

    if (t_key) prng_set_secret_buf( &prnd, t_key, -1 );
    if (f_key) prng_set_secret( &prnd, f_key, -1 );
    prng_to_vlong( &prnd, &secret );
    prng_init( &prnd );

    /* Do operation */

    t_tmp = t_out = 0;
    if (t_inp && pt_out) {
      *pt_out = p_malloc((size_t)((double)strlen(t_inp) * 1.2)+10); // not good
      if (!*pt_out) {err = ERR_NOMEMORY; *keyn = 0; break;}
      t_out = *pt_out;
      *t_out = 0;
      t_tmp = t_inp;
    }
    if(!binmode) {
        if (f_inp) err = position(f_inp);
        if (t_out) err = position_buf(&t_tmp);
    }
    err = get_binary_byte( f_inp, (unsigned char *)&b, binmode, &t_tmp); // number of recipients
    if (err) {*keyn = 0; break;}
    if (!b || (b&0x80)) {err = ERR_NOECC; *keyn = 0; break;}
    if (*keyn > b) {
        err = ERR_BADKEYNUM; *keyn = b; break;
      //  rdkc = *keyn = 0;
      //  sprintf(mstr, "Encrypted only to %u keys, trying key #%u\n\n", b, *keyn);
      //  MessageOut(mstr, 0);
    }
      //if (b>1 && rdkc) {
      //  sprintf(mstr, "Encrypted to %u keys, trying key #%u\n\n", b, *keyn);
      //  MessageOut(mstr, 0);
      //}
    for (kn=0; kn<b && !err; kn++) {
      if (!err) err = get_binary_vlong( f_inp, (*keyn-1 == kn)?&msg1:&session, binmode, &t_tmp );
      if (!err) err = get_binary_vlong( f_inp, (*keyn-1 == kn)?&msg2:&session, binmode, &t_tmp );
    }
    *keyn = b;
    if (err) break;
    err = get_binary_byte( f_inp, (unsigned char *)&b, binmode, &t_tmp); // cipher
    if (err) break;
    //if (b!=BF224CBC) {err = ERR_BADSYMCIPHER; break;}
    if (b!=RJND224CBC) {err = ERR_BADSYMCIPHER; break;}
//#ifdef _DEBUG
//print_field("secret key", &secret);
//print_field("msg1", &msg1);
//print_field("msg2", &msg2);
//#endif
    DecodeSecret( &secret, &session, &msg1, &msg2 );
//#ifdef _DEBUG
//print_field("session", &session);
//#endif
//sprintf(aaa, "session: %08x %08x\n", session.e[0], session.e[1]);
//OutputDebugStringA(aaa);
    //err = sym_decrypt( &session, f_inp, f_out, binmode, t_tmp, t_out, BF224CBC );
    err = sym_decrypt( &session, f_inp, f_out, binmode, t_tmp, t_out, RJND224CBC );
  } while (0);

  //if (t_key) free(t_key);
  //if (t_inp) free(t_inp);
  if (err && pt_out && *pt_out) {free(*pt_out); *pt_out = NULL;}
  if (f_out) fflush(f_out);
  /* burn sensistive information */
  null( &secret );
  null( &session );
  return err;
} // do_decrypt_pk


int do_encrypt_c( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out)
{ // E
  prng prnd;
  //FIELD2N secret;
  int err = ERR_NOERROR;
  char * t_out;
  word32 secret[HW];

  do {
    if ((!f_key && !t_key) || (!f_inp && !t_inp) || (!f_out && !pt_out) ||
        ( f_key &&  t_key) || ( f_inp &&  t_inp) ||
        (pt_out && !t_inp) ||
        (binmode && (t_inp || pt_out)))
      {err = ERR_BADPARAM; break;}

    init_binasc();

    /* Initialise the prng and calculate keys */

    prng_init( &prnd );

    if (t_key) prng_set_secret_buf( &prnd, t_key, -1 );
    if (f_key) prng_set_secret( &prnd, f_key, -1 );
    //hash_to_vlong( prnd.seed+1, &secret );
    memcpy(secret, (prnd.seed+1), sizeof(secret));
    prng_init( &prnd );

    /* Do operation */

    t_out = 0;
    if (t_inp) {
      *pt_out = p_malloc((size_t)((double)strlen(t_inp) * 1.4)+70); // not good
      if (!*pt_out) {err = ERR_NOMEMORY; break;}
      t_out = *pt_out;
      *t_out = 0;
    }
    if(!binmode) {
      if (f_out) fputs(begin_clearsign,f_out);
      if (t_out) { strcpy(t_out, begin_clearsign_lf); t_out += strlen(t_out); }
    }
    //fputcPlus (BF160CBC, f_out, binmode, &t_out); // cipher
    //err = sym_encrypt( &secret, f_inp, f_out, binmode, t_inp, &t_out, BF160CBC );
    fputcPlus (RJND256CBC, f_out, binmode, &t_out); // cipher
    err = sym_encrypt( &secret, f_inp, f_out, binmode, t_inp, &t_out, RJND256CBC );
    if (err) break;
    if(!binmode) {
      if(!flushArmour(f_out, &t_out, 0))
          {err = ERR_OUTPUT; break;}
      if (f_out) fputs(end_ckarmour, f_out);
      if (t_out)  strcpy(t_out, end_ckarmour_lf);
    }
  } while (0);

  //if (t_key) free(t_key);
  //if (t_inp) free(t_inp);
  if (err && pt_out && *pt_out) {free(*pt_out); *pt_out = NULL;}
  if (f_out) fflush(f_out);
  /* burn sensistive information */
  //null( &secret );
  memset(secret, 0, sizeof(secret));
  return err;
} // do_encrypt_c

int do_decrypt_c( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out)
{ // D
  prng prnd;
  //FIELD2N secret;
  int err = ERR_NOERROR;
  char * t_out, * t_tmp;
  unsigned char b = 0;
  word32 secret[HW];

  do {
    if ((!f_key && !t_key) || (!f_inp && !t_inp) || (!f_out && !pt_out) ||
        ( f_key &&  t_key) || ( f_inp &&  t_inp) ||
        (pt_out && !t_inp) ||
        (binmode && (t_inp || pt_out)))
      {err = ERR_BADPARAM; break;}

    init_binasc();

    /* Initialise the prng and calculate keys */

    prng_init( &prnd );

    if (t_key) prng_set_secret_buf( &prnd, t_key, -1 );
    if (f_key) prng_set_secret( &prnd, f_key, -1 );
    //hash_to_vlong( prnd.seed+1, &secret );
    memcpy(secret, (prnd.seed+1), sizeof(secret));
    prng_init( &prnd );

    /* Do operation */

    t_tmp = t_out = 0;
    if (t_inp) {
      *pt_out = p_malloc((size_t)((double)strlen(t_inp) * 1.2)+10); // not good
      if (!*pt_out) {err = ERR_NOMEMORY; break;}
      t_out = *pt_out;
      *t_out = 0;
      t_tmp = t_inp;
    }

    if(!binmode) {
        if (f_inp) err = position(f_inp);
        if (t_inp) err = position_buf(&t_tmp);
    }
    if (err) break;
    err = get_binary_byte( f_inp, &b, binmode, &t_tmp); // cipher
    if (err) break;
    //if (b!=BF160CBC) {err = ERR_BADSYMCIPHER; break;}
    //err = sym_decrypt( &secret, f_inp, f_out, binmode, t_tmp, t_out, BF160CBC );
    if (b!=RJND256CBC) {err = ERR_BADSYMCIPHER; break;}
    err = sym_decrypt( &secret, f_inp, f_out, binmode, t_tmp, t_out, RJND256CBC );
  } while (0);
 
  //if (t_key) free(t_key);
  //if (t_inp) free(t_inp);
  if (err && pt_out && *pt_out) {free(*pt_out); *pt_out = NULL;}
  if (f_out) fflush(f_out);
  /* burn sensistive information */
  //null( &secret );
  memset(secret, 0, sizeof(secret));
  return err;
} // do_decrypt_c

int do_sign( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out)
{ // s(binmode), S
  prng prnd;
  FIELD2N secret,session,mac;
  SIGNATURE sig;
  int err = ERR_NOERROR;
  char * t_out;

  //if (f_key) f_key = fopen( f_key, "r" );
  //if (f_inp) f_inp = fopen( f_inp, binmode ? "rb" : "r" );
  //if (f_out) f_out = fopen( f_inp, binmode ? "wb" : "w" );

  do {
    if ((!f_key && !t_key) || (!f_inp && !t_inp) || (!f_out && !pt_out) ||
        ( f_key &&  t_key) || ( f_inp &&  t_inp) ||
        (pt_out && !t_inp) ||
        (binmode && (t_inp || pt_out)))
      {err = ERR_BADPARAM; break;}

    init_binasc();

    /* Initialise the prng and calculate keys */

    prng_init( &prnd );

    if (t_key) prng_set_secret_buf( &prnd, t_key, -1 );
    if (f_key) prng_set_secret( &prnd, f_key, -1 );
    prng_to_vlong( &prnd, &secret );

    t_out = 0;
    if (binmode) { // s
      if (f_inp) prng_set_mac( &prnd, f_inp );
      if (t_inp) prng_set_mac_buf( &prnd, t_inp );
      if (pt_out) {
        *pt_out = p_malloc(KEYSIZE*2+5);
        if (!*pt_out) {err = ERR_NOMEMORY; break;}
        t_out = *pt_out;
      }
    } else { // S
      if (f_inp)
        clearsign( &prnd, f_inp, f_out );
      if (t_inp) {
        *pt_out = p_malloc((size_t)((double)strlen(t_inp) * 1.2)+170); // not good
        if (!*pt_out) {err = ERR_NOMEMORY; break;}
        t_out = *pt_out;
        clearsign_buf( &prnd, t_inp, t_out );
        t_out += strlen(t_out);
      }
    }
    hash_to_vlong( prnd.seed+1+HW, &mac );

    if (g_prnd.count) prng_set_rnd( &prnd, 0, (char *)g_prnd.seed, g_prnd.count*4 ); // add global entropy if collected
    prng_set_rnd( &prnd, f_key, t_key, 0 );

    /* Do operation */

//#ifdef _DEBUG
//print_field("secret key", &secret);
//print_field("hash", &mac);
//#endif
    //do
    //{
        prng_set_time( &prnd );
        prng_to_vlong( &prnd, &session );
        Sign( &secret, &session, &mac, &sig );
    //} while ( sig.c[0] == 0 );
//#ifdef _DEBUG
//print_field("sinature.c", &sig.c);
//print_field("sinature.d", &sig.d);
//#endif
//#ifdef _DEBUG
//{ // verify right now
//FIELD2N pub;
//MakePublicKey( &pub, &secret );
//print_field("public key", &pub);
//if (!Verify( &pub, &mac, &sig )) fputs( err_signature, stderr );
//}
//#endif

    if (f_out) {
        //put_vlong( &sig.d, f_out );
        put_binary_vlong( f_out, &sig.d, 0, &t_out );
        if(!flushArmour(f_out, &t_out, 1))
          {err = ERR_OUTPUT; break;}
        //if(!binmode) // S
          fputs("\n", f_out); /* avoid word wrap */
        //else // s
        //  fputs( ":", f_out );
        //put_vlong( &sig.c, f_out );
        put_binary_vlong( f_out, &sig.c, 0, &t_out );
        if(!flushArmour(f_out, &t_out, 1))
          {err = ERR_OUTPUT; break;}
        //if(!binmode) // S
          fputs("\n", f_out); /* avoid word wrap */
    } else {
        //put_vlong_buf( &sig.d, &t_out );
        put_binary_vlong( f_out, &sig.d, 0, &t_out );
        if(!flushArmour(f_out, &t_out, 1))
          {err = ERR_OUTPUT; break;}
        //if(!binmode) // S
          strcat(t_out, "\r\n"); /* avoid word wrap */
        //else // s
        //  strcat(t_out, ":");
        t_out += strlen(t_out);
        //put_vlong_buf( &sig.c, &t_out );
        put_binary_vlong( f_out, &sig.c, 0, &t_out );
        if(!flushArmour(f_out, &t_out, 1))
          {err = ERR_OUTPUT; break;}
        //if(!binmode) // S
          strcat(t_out, "\r\n"); /* avoid word wrap */
    }
  } while (0);

  //if (t_key) free(t_key);
  //if (t_inp) free(t_inp);
  if (err && pt_out && *pt_out) {free(*pt_out); *pt_out = NULL;}
  if (f_out) fflush(f_out);
  /* burn sensistive information */
  prng_init( &prnd );
  null( &secret );
  null( &session );
  return err;
} // do_sign

int do_verify( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, FILE * f_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec)
{ // v(binmode), V
  prng prnd;
  FIELD2N pub,mac;
  SIGNATURE sig;
  int err = ERR_NOERROR;
  char * t_tmp;

  do {
    if ((!f_key && !t_key) || (!f_inp && !t_inp) || (!f_out && !pt_out && !binmode) || (!f_sec && !t_sec && binmode) ||
                              ( f_inp &&  t_inp) || ( f_out &&  pt_out)             || ( f_sec &&  t_sec) ||
        (pt_out && !t_inp) ||
        (binmode && (t_inp || pt_out)))
      {err = ERR_BADPARAM; break;}

    init_binasc();

    /* Initialise the prng and calculate keys */

    prng_init( &prnd );

    /* public key operations */
    //if (t_key) get_vlong_buf( t_key, &pub ); /* should be a validity check here */
    //if (f_key) get_vlong( f_key, &pub ); /* should be a validity check here */
    t_tmp = t_key;
    err = get_binary_vlong( f_key, &pub, 0, &t_tmp );
    if (err) break;

    if (binmode) {
        if (f_inp) prng_set_mac( &prnd, f_inp );
        if (t_inp) prng_set_mac_buf( &prnd, t_inp );
    } else {
        if (f_inp)
          err = readsign( &prnd, f_inp, f_out );
        if (t_inp) {
          *pt_out = p_malloc((size_t)((double)strlen(t_inp) * 1.2)); // not good
          if (!*pt_out) {err = ERR_NOMEMORY; break;}
          t_tmp = t_inp;
          err = readsign_buf( &prnd, &t_tmp, *pt_out );
        }
    }
    if (err) break;

    hash_to_vlong( prnd.seed+1+HW, &mac );

    /* Do operation */

    if(binmode) // v
    {
        //if (f_sec) {
        //  get_vlong( f_sec, &sig.d );
        //  get_vlong( f_sec, &sig.c );
        //} else {
        //  get_vlong_buf( t_sec, &sig.d );
        //  get_vlong_buf( t_sec, &sig.c );
        //}
        t_tmp = t_sec;
        err = get_binary_vlong( f_sec, &sig.d, 0, &t_tmp );
        if (err) break;
        err = get_binary_vlong( f_sec, &sig.c, 0, &t_tmp );
    }
    else // V /* if( 'V' == operation) */
    {
        //if (f_inp) {
        //  get_vlong_a( f_inp, &sig.d );
        //  get_vlong_a( f_inp, &sig.c );
        //} else {
        //  get_vlong_a_buf( &t_tmp, &sig.d );
        //  get_vlong_a_buf( &t_tmp, &sig.c );
        //}
        err = get_binary_vlong( f_inp, &sig.d, binmode, &t_tmp );
        if (err) break;
        err = get_binary_vlong( f_inp, &sig.c, binmode, &t_tmp );
	}
//#ifdef _DEBUG
//print_field("public key", &pub);
//print_field("hash", &mac);
//print_field("sinature.c", &sig.c);
//print_field("sinature.d", &sig.d);
//#endif
    if (err) break;
    if (!Verify( &pub, &mac, &sig ))
        err = ERR_BADSIGN;
  } while (0);

  //if (t_key) free(t_key);
  //if (t_sec) free(t_sec);
  //if (t_inp) free(t_inp);
  if (err && pt_out && *pt_out) {free(*pt_out); *pt_out = NULL;}
  if (f_out) fflush(f_out);
  /* burn sensistive information */
  prng_init( &prnd );
  return err;
} // do_verify


void burn_stack(void)
{  
  /* just in case any local burn code has been forgotten */
  /* size is just a fairly conservative guess */
  unsigned char x [ 20000 ];
  memset( x, 0, sizeof(x) );
}

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
  #if defined(_M_IX86) || defined(_M_I86) || defined(__alpha)
    #define LITTLE_ENDIAN
  #else
    #error "LITTLE_ENDIAN or BIG_ENDIAN must be defined"
	#endif
#endif

char *errbigendian = "Porting error : need to define BIG_ENDIAN instead of LITTLE_ENDIAN\n";
char *errlittleendian = "Porting error : need to define LITTLE_ENDIAN instead of BIG_ENDIAN\n";

char * checkEndian(void)
{
  static byte x[4] = {1,2,3,4};
	#ifdef LITTLE_ENDIAN
    if ( *(word32*)x != 0x04030201 )
			return errbigendian;
	#else
	  if ( *(word32*)x != 0x01020304 )
			return errlittleendian;
  #endif
	return NULL;
}



//------------------------------------
int dll_make_key( char * fn_key, char * t_key, char * fn_out, char ** pt_out)
{
    FILE * f_key = NULL, * f_out = NULL;
    int res;
    if (fn_key) f_key = fopen( fn_key, "r" );
    if (fn_out) f_out = fopen( fn_out, "w" );
    if ((fn_key && !f_key) || (fn_out && !f_out))
        res = ERR_INPUT;
    else
        res = do_make_key( f_key, t_key, f_out, pt_out);
    if (f_key) fclose(f_key);
    if (f_out) fclose(f_out);
    return res;
} // dll_make_key

int dll_encrypt_pk( char ** pfn_key, char ** pt_key, char * fn_inp, char * fn_out, char * fn_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec, unsigned numkey)
{
    FILE ** pf_key = NULL, * f_inp = NULL, * f_out = NULL, * f_sec = NULL;
    int res;
    unsigned ii;
    res = 0;
    if (pfn_key) {
        pf_key = malloc((numkey)*sizeof(FILE *));
        if (pf_key) {
            memset(pf_key, 0, (numkey)*sizeof(FILE *));
            for (ii=0; ii <= numkey; ii++) {
                if (pfn_key[ii]) {
                    pf_key[ii] = fopen( pfn_key[ii], "r" );
                    if (!pf_key[ii]) {
                        res = ERR_INPUT;
                        break;
                    }
                }
            } // for
        }
    }
    if (fn_inp) f_inp = fopen( fn_inp, binmode ? "rb" : "r" );
    if (fn_out) f_out = fopen( fn_out, binmode ? "wb" : "w" );
    if (fn_sec) f_sec = fopen( fn_sec, binmode ? "wb" : "w" );
    if (res || (fn_inp && !f_inp) || (fn_out && !f_out) || (fn_sec && !f_sec))
        res = ERR_INPUT;
    else
        res = do_encrypt_pk( pf_key, pt_key, f_inp, f_out, f_sec, binmode, t_inp, pt_out, t_sec, numkey);
    if (pf_key) {
        for (ii=0; ii <= numkey; ii++)
            if (pf_key[ii]) fclose(pf_key[ii]);
        free(pf_key);
    }
    if (f_inp) fclose(f_inp);
    if (f_out) fclose(f_out);
    if (f_sec) fclose(f_sec);
    return res;
} // dll_encrypt_pk

int dll_decrypt_pk( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode, char * t_inp, char ** pt_out, unsigned * keyn)
{
    FILE * f_key = NULL, * f_inp = NULL, * f_out = NULL;
    int res;
    if (fn_key) f_key = fopen( fn_key, "r" );
    if (fn_inp) f_inp = fopen( fn_inp, binmode ? "rb" : "r" );
    if (fn_out) f_out = fopen( fn_out, binmode ? "wb" : "w" );
    if ((fn_key && !f_key) || (fn_inp && !f_inp) || (fn_out && !f_out))
        res = ERR_INPUT;
    else
        res = do_decrypt_pk( f_key, t_key, f_inp, f_out, binmode, t_inp, pt_out, keyn);
    if (f_key) fclose(f_key);
    if (f_inp) fclose(f_inp);
    if (f_out) fclose(f_out);
    return res;
} // dll_decrypt_pk

int dll_encrypt_c( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode,  char * t_inp, char ** pt_out)
{
    FILE * f_key = NULL, * f_inp = NULL, * f_out = NULL;
    int res;
    if (fn_key) f_key = fopen( fn_key, "r" );
    if (fn_inp) f_inp = fopen( fn_inp, binmode ? "rb" : "r" );
    if (fn_out) f_out = fopen( fn_out, binmode ? "wb" : "w" );
    if ((fn_key && !f_key) || (fn_inp && !f_inp) || (fn_out && !f_out))
        res = ERR_INPUT;
    else
        res = do_encrypt_c( f_key, t_key, f_inp, f_out, binmode, t_inp, pt_out);
    if (f_key) fclose(f_key);
    if (f_inp) fclose(f_inp);
    if (f_out) fclose(f_out);
    return res;
} // dll_encrypt_c

int dll_decrypt_c( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode, char * t_inp, char ** pt_out)
{
    FILE * f_key = NULL, * f_inp = NULL, * f_out = NULL;
    int res;
    if (fn_key) f_key = fopen( fn_key, "r" );
    if (fn_inp) f_inp = fopen( fn_inp, binmode ? "rb" : "r" );
    if (fn_out) f_out = fopen( fn_out, binmode ? "wb" : "w" );
    if ((fn_key && !f_key) || (fn_inp && !f_inp) || (fn_out && !f_out))
        res = ERR_INPUT;
    else
        res = do_decrypt_c( f_key, t_key, f_inp, f_out, binmode, t_inp, pt_out);
    if (f_key) fclose(f_key);
    if (f_inp) fclose(f_inp);
    if (f_out) fclose(f_out);
    return res;
} // dll_decrypt_c

int dll_sign( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode, char * t_inp, char ** pt_out)
{
    FILE * f_key = NULL, * f_inp = NULL, * f_out = NULL;
    int res;
    if (fn_key) f_key = fopen( fn_key, "r" );
    if (fn_inp) f_inp = fopen( fn_inp, binmode ? "rb" : "r" );
    if (fn_out) f_out = fopen( fn_out, binmode ? "wb" : "w" );
    if ((fn_key && !f_key) || (fn_inp && !f_inp) || (fn_out && !f_out))
        res = ERR_INPUT;
    else
        res = do_sign( f_key, t_key, f_inp, f_out, binmode, t_inp, pt_out);
    if (f_key) fclose(f_key);
    if (f_inp) fclose(f_inp);
    if (f_out) fclose(f_out);
    return res;
} // dll_sign

int dll_verify( char * fn_key, char * t_key, char * fn_inp, char * fn_out, char * fn_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec)
{
    FILE * f_key = NULL, * f_inp = NULL, * f_out = NULL, * f_sec = NULL;
    int res;
    if (fn_key) f_key = fopen( fn_key, "r" );
    if (fn_inp) f_inp = fopen( fn_inp, binmode ? "rb" : "r" );
    if (fn_out) f_out = fopen( fn_out, binmode ? "wb" : "w" );
    if (fn_sec) f_sec = fopen( fn_sec, binmode ? "r" : "r" );
    if ((fn_key && !f_key) || (fn_inp && !f_inp) || (fn_out && !f_out) || (fn_sec && !f_sec))
        res = ERR_INPUT;
    else
        res = do_verify( f_key, t_key, f_inp, f_out, f_sec, binmode, t_inp, pt_out, t_sec);
    if (f_key) fclose(f_key);
    if (f_inp) fclose(f_inp);
    if (f_out) fclose(f_out);
    if (f_sec) fclose(f_sec);
    return res;
} // dll_verify

