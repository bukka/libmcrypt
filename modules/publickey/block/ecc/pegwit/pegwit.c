/*
  pegwit by George Barwood <george.barwood@dial.pipex.com>
  100% Public Domain
  clearsigning code by Mr. Tines <tines@windsong.demon.co.uk>
  also the filter mode support.
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

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

#include "pegwitw.h"
#include "keyring.h"
#include "binascw.h"


#if defined(__BORLANDC__) && defined(__MSDOS__)
#include <dos.h>
unsigned _stklen = 32768u;
#endif

const char manual /*:)*/ [] = 
  "Pegwit v9 alfa.04\n\n"
  "Usage (init/encrypt/decrypt/sign/verify) :\n"
  "  generate key\n"
  "    -i <secret-key >public-key\n"
  "    -I \"key name\" <secret-key\n"
  "  list keys\n"
  "    -l\n"
  "  encrypt/decrypt\n"
  "    -e[n] public-key [public-key ...] plain cipher <random-junk\n"
  "    -d[n] cipher plain <secret-key\n"
  "  encrypt/decrypt (conventionaly)\n"
  "    -E plain cipher <key\n"
  "    -D cipher plain <key\n"
  "  sign/verify\n"
  "    -s plain <secret-key >signature\n"
  "    -v public-key plain <signature\n"
  "  clearsign/verify\n"
  "    -S text <secret-key >clearsigned-text\n"
  "    -V public-key clearsigned-text >text\n"
  "  other\n"
  "    -f[operation] [type pegwit -f for details]\n"
  "  for -e, -v and -V operations public-key is:\n"
  "    filename (key is read from separate file)\n"
  "    =substring (uses key from pegwit.pkr that contains substring)\n"
  "    #index (uses key from pegwit.pkr)\n";
const char filterManual [] =
  "Pegwit v9 alfa.04 [filter sub-mode]\n\n"
  "Usage (encrypt/decrypt/sign/verify) :\n"
  "  encrypt/decrypt (ascii armored output)\n"
  "    -fe[n] public-key [public-key ...] random-junk <plain >ascii-cipher\n"
  "    -fd[n] secret-key <ascii-cipher >plain\n"
  "  encrypt/decrypt (conventionaly, ascii armored output)\n"
  "    -fE key <plain >ascii-cipher\n"
  "    -fD key <ascii-cipher >plain\n"
  "  clearsign/verify\n"
  "    -fS secret-key <text >clearsigned-text\n"
  "    -fV public-key <clearsigned-text >text\n"
  "  for -fe, -fv and -fV operations public-key is:\n"
  "    filename (key is read from separate file)\n"
  "    =substring (uses key from pegwit.pkr that contains substring)\n"
  "    #index (uses key from pegwit.pkr)\n";

const char pubkey_magic [] = PUBKEY_MAGIC;

const char err_output [] = "Pegwit, error writing output, disk full?";
const char err_open_failed [] = "Pegwit, error : failed to open ";
const char err_bad_public_key [] = "Pegwit, error : public key must start with \"";
const char err_signature [] = "signature did not verify\a\a\a\n";
const char err_decrypt [] = "decryption failed\a\a\a\n";
const char err_clearsig_header_not_found [] = 
  "Clearsignature header \"###\" not found\a\a\a\n";
const char err_decode_failed[] =
"Pegwit; Out of range characters encountered in ASCII armouring.\n";


/*
const char warn_long_line [] = 
  "Very long line - > 8k bytes.  Binary file?\n"
  "Clearsignature dubious\a\a\a\n";
const char warn_control_chars [] = 
  "Large number of control characters.  Binary file?\n"
  "Clearsignature dubious\a\a\a\n";
*/

//----------------------------


FILE * chkopen( char * s, char * mode )
{
  FILE * result = fopen(s,mode);
  if (!result)
  {
    fputs( err_open_failed, stderr );
    fputs( s, stderr );
  }
  return result;
}


/*
void burn_stack(void)
{  
  // just in case any local burn code has been forgotten
  // size is just a fairly conservative guess
  unsigned char x [ 20000 ];
  memset( x, 0, sizeof(x) );
}
*/


int showError(int filter)
{
    if (filter)
        fputs(filterManual, stderr);
    else {
        fputs(manual, stderr);
        /* gfSelfTest(100);
        ecSelfTest(100);*/
    }
    return 1;    
}


int main( unsigned argc, char * argv[] )
{
  int err = ERR_NOERROR, operation, filter=0, binmode = 0, numkeys = 0, ii, kidx;
  unsigned expect, arg_ix;
  FILE * f_key = NULL, * f_inp = NULL, * f_out = NULL, *f_sec = NULL, ** pf_key = NULL;
  char **pt_key = NULL, *t_key = NULL, * t_out = NULL, * cerr;
  char *keyname;
  char openForRead [3] = "rb";
  char openForWrite [3] = "wb";
  char openKey[3] = "rb";
  #ifdef TIMETEST
    time_t tt = time(NULL);
  #endif

  cerr = checkEndian();
  if (cerr)
  {
  	fprintf(stderr, cerr);
   	 return 1;
  }

  if (InitECC())
  {
  	fprintf(stderr, "InitECC() failed\n");
    	return 1;
  }
  
  LoadKeyring();

  if ( argc<2 || argv[1][0] != '-')
    return showError(filter);
  operation = argv[1][1];

  if('f' == operation)
  {
      filter=1;
      operation = argv[1][2];
      if(0 == argv[1][2])
         return showError(1);
      if('e' == operation || 'd' == operation)
        numkeys = atoi(&argv[1][3]);
      else
        if (0 != argv[1][3]) return showError(filter);
  }
  else
  {
    if('e' == operation || 'd' == operation)
      numkeys = atoi(&argv[1][2]);
    else
      if (argv[1][2] != 0 ) return showError(filter);
  }

  /* Check the number of arguments */
  expect = 0;

  if(!filter)
  {
         if ( operation == 'i' || operation == 'l' )  expect = 2;
    else if ( operation == 'I' )                      expect = 3;
    else if ( operation == 's' )                     {expect = 3; binmode=1;}
    else if ( operation == 'S' )                      expect = 3;
    else if ( operation == 'd' || operation == 'v' ||
              operation == 'D' || operation == 'E' ) {expect = 4; binmode=1;}
    else if ( operation == 'V' )                      expect = 4;
    else if ( operation == 'e' )                     {expect = 5 + numkeys; binmode=1;}
  }
  else
  {
    if('V' == operation || 'S' == operation || 'E' == operation ||
      'D' == operation || 'd' == operation ) expect = 3;
   else if ('e' == operation) expect = 4 + numkeys;
  }
  numkeys++;

  if ( argc != expect ) return showError(filter);

  arg_ix = 2;
  if ( operation == 'I' ) arg_ix = 3;

  f_key = stdin;
  if ( operation == 'e' || operation == 'v' || 'V' == operation || filter )
  {
    unsigned ij, isPub = 1;
    if(filter && 'e' != operation && 'V' != operation) isPub = 0; /* d || D || E || S */

    if('S' == operation || 'd' == operation) openKey[1] = 0;

    pf_key = malloc((numkeys)*sizeof(FILE *));
    pt_key = malloc((numkeys)*sizeof(char *));
    memset(pf_key, 0, (numkeys)*sizeof(FILE *));
    memset(pt_key, 0, (numkeys)*sizeof(char *));
    for (ii=0; ii < numkeys; ii++) {
      keyname = argv[arg_ix++];
      if ( operation == 'e' || operation == 'v' || 'V' == operation ) {
        if (keyname[0] == '=' || keyname[0] == '#') {
            if (keyname[0] == '=') {
              kidx = FindKeySubstr(&keyname[1]);
              if (kidx<0) {
                fprintf(stderr, "Pegwit, error : can not find public key \"%s\"", &keyname[1] );
                return 1;
              }
            } else { // == '#'
              if (sscanf(&keyname[1], "%d", &kidx) != 1) {
                fprintf(stderr, "Pegwit, error : bad public key number \"%s\"", &keyname[1] );
                return 1;
              }
              if (kidx < 0 || kidx >= GetNumKeys()) {
                fprintf(stderr, "Pegwit, error : bad public key number \"%s\"", &keyname[1] );
                return 1;
              }
              if (!GetKeyPtr(kidx)) {
                fprintf(stderr, "Pegwit, error : can not find public key number \"%s\"", &keyname[1] );
                return 1;
              }
            }
            pt_key[ii] = malloc(KEYSIZE+1);
            strncpy(pt_key[ii], GetKeyPtr(kidx), KEYSIZE);
            pt_key[ii][KEYSIZE] = 0;
        } else {
          pf_key[ii] = chkopen( keyname, openKey );
          if (!pf_key[ii]) {
            fprintf(stderr, "Pegwit, error : can not find public key file \"%s\"", keyname );
            return 1;
          }
        }
      } else {
        pf_key[ii] = chkopen( keyname, openKey );
        if (!pf_key[ii]) {
            fprintf(stderr, "Pegwit, error : can not find key file \"%s\"", keyname );
            return 1;
        }
      }

      if (isPub && pf_key[ii])
          for (ij=0; pubkey_magic[ij]; ij+=1) {
            if ( fgetc( pf_key[ii] ) != pubkey_magic[ij] )
            {
              fputs( err_bad_public_key, stderr );
              fputs( pubkey_magic, stderr );
              fputc( '"', stderr );
              return 1;
            }
          }

      if (!pf_key[ii] && !pt_key[ii]) {
        fprintf(stderr, "Pegwit, error : can not find public key \"%s\"", keyname );
        return 1;
      }

      if ( operation == 'd' )
        break;
    }
    f_key = pf_key[0];
    t_key = pt_key[0];
  }

  f_inp = stdin;
  f_out = stdout;

  if(!filter)
  {
    if('V' == operation || 'S' == operation)
      openForRead[1] = openForWrite[1] = 0;

    f_sec = 0;
    if('e' == operation || 'v' == operation) f_sec = stdin;
    if ( argc > arg_ix )
    {
      f_inp = chkopen( argv[arg_ix++], openForRead );
      if (!f_inp) return 1;
    }
    if ( argc > arg_ix )
    {
      f_out = chkopen( argv[arg_ix++], openForWrite );
      //printf("fout = %s\n", argv[arg_ix-1]);
      if (!f_out) return 1;
    }
  }
  else
  {
      f_sec = 0;
      if('e' == operation)
      {
        //printf("open file %s\n", argv[arg_ix]);
        f_sec = chkopen( argv[arg_ix++], openForRead );
        if (!f_sec) return 1;
      }
  }

  switch (operation) {
  case 'l':
      if (GetNumKeys()) {
        char fmt[20];

        sprintf(fmt, "%%s\n    %%.%ds\n\n", KEYSIZE);
        for (ii=0; ii<GetNumKeys(); ii++)
          if (GetKeyPtr(ii))
            printf(fmt,GetKeyPtr(ii)+KEYSIZE+1, GetKeyPtr(ii));
      }
      break;
  case 'i':
      //printf("calling do_make_key\n");
      err = do_make_key( f_key, 0, f_out, 0);
      break;
  case 'I':
      //printf("calling do_make_key\n");
      err = do_make_key( f_key, 0, 0, &t_out);
      if (!err) {
          AddKey(argv[arg_ix-1], t_out);
          SaveKeyring();
      }
      if (t_out) p_free(t_out);
      break;
  case 'e':
      //printf("encrypt: numkeys=%x binmode=%d \n", numkeys, binmode);
      err = do_encrypt_pk( pf_key, pt_key, f_inp, f_out, f_sec, binmode, 0, 0, 0, numkeys);
      break;
  case 'd':
      //printf("decrypt: numkeys=%x binmode=%d \n", numkeys, binmode);
      err = do_decrypt_pk( f_key, 0, f_inp, f_out, binmode, 0, 0, &numkeys);
      if (err == ERR_BADKEYNUM) {
        fprintf(stderr, "Encrypted only to %u keys !\n", numkeys);
        err = -200;
      }
      if (!err && numkeys!=1)
        fprintf(stderr, "\n\nEncrypted to %u keys !\n\n", numkeys);
      //printf("end case d\n");
      break;
  case 'E':
      err = do_encrypt_c( f_key, 0, f_inp, f_out, binmode, 0, 0);
      break;
  case 'D':
      err = do_decrypt_c( f_key, 0, f_inp, f_out, binmode, 0, 0);
      break;
  case 's':
  case 'S':
      err = do_sign( f_key, 0, f_inp, f_out, binmode, 0, 0);
      break;
  case 'v':
  case 'V':
      err = do_verify( f_key, t_key, f_inp, f_out, f_sec, binmode, 0, 0, 0);
      if (!err) 
        fputs( "Signature good\n", stderr );
      break;
  }
  if (t_key) free(t_key);
  if (pt_key) free(pt_key);
  if (pf_key) free(pf_key);

  if (err) switch (err) {
  case -200:
  case ERR_NOERROR:
    break;
  case ERR_NOHEADER:
    fputs( err_clearsig_header_not_found, stderr );
    break;
  case ERR_OUTPUT:
    fputs( err_output, stderr );
    break;
  case ERR_SYMDECRYPT:
    fputs( err_decrypt, stderr );
    break;
  case ERR_NOMEMORY:
    fputs( "Out of memory\a\a\a\n", stderr );
    break;
  case ERR_BADSIGN:
    fputs( err_signature, stderr );
    break;
  case ERR_INPUT:
    fputs( "Input error\a\a\a\n", stderr );
    break;
  case ERR_BADSYMCIPHER:
    fputs( "Unknow cipher\a\a\a\n", stderr );
    break;
  case ERR_NOECC:
    fputs( "Bad file\a\a\a\n", stderr );
    break;
  case ERR_BADARMOR:
    fprintf(stderr, err_decode_failed);
    break;
  case ERR_UNKNOWN:
  default:
    fputs( "Unknown error\a\a\a\n", stderr );
    break;
  }

  burn_stack();
  burnBinasc();

  #ifdef TIMETEST
    fprintf(stderr, "time %u\n", time(NULL) - tt);
  #endif
  return -err;
}
