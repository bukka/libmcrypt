
#define PUBKEY_MAGIC "pegwit v9 public key ="


void burn_stack(void);
char * checkEndian(void);
int InitECC(void);


void prng_init( void * prnd );
void prng_set_rnd( void * prnd, FILE * f_inp, char * t_inp, int st_inp );



int do_make_key( FILE * f_key, char * t_key, FILE * f_out, char ** pt_out);
// f_key - input - private key, file hanle, caller fopen(), caller should fclose()
// t_key - input - private key, zero terminated string
//      only one of f_key or t_key can be used, another should be set to 0
//
// f_out - input - public key, file hanle, caller fopen(), caller should fclose()
// pt_out - output - public key, zero terminated string, function allocated with p_malloc(), caller must free with p_free()

int do_encrypt_pk( FILE ** pf_key, char ** pt_key, FILE * f_inp, FILE * f_out, FILE * f_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec, unsigned numkey);
// pf_key - input - array of public keys, file hanles, caller fopen(), caller should fclose()
// pt_key - input - array of public keys, zero terminated strings
//      only one of pf_key[i] or pt_key[i] can be used, another should be set to 0
//
// numkey - input - number of public keys (in pf_key or pt_key arrays) to encrypt with, 1 to 127
//
// f_inp - input - input data, file hanle, caller fopen(), caller should fclose()
// t_inp - input - input data, zero terminated string
//      only one of f_inp or t_inp should be used, another should be set to 0
//
// f_out - input - output data, file hanle, caller fopen(), caller should fclose()
// pt_out - output - output data, zero terminated string, function allocated with p_malloc(), caller must free with p_free()
//      if pt_out is used input should be in t_inp
//
// f_sec - input - random data, file hanle, caller fopen(), caller should fclose()
// t_sec - input - random data, zero terminated string
//      only one of f_sec or t_sec should be used, another should be set to 0
//
// binmode - input - if 0 file is encrypted in ASCII mode, must be 0 if t_inp or pt_out used.

int do_decrypt_pk( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out, unsigned * keyn);
// f_key - input - private key, file hanle, caller fopen(), caller should fclose()
// t_key - input - private key, zero terminated string
//      only one of f_key or t_key can be used, another should be set to 0
//
// keyn - input - pointer number of key to decrypt with, 1 to 127
// keyn - output - pointer number of keys
//
// f_inp - input - input data, file hanle, caller fopen(), caller should fclose()
// t_inp - input - input data, zero terminated string
//      only one of f_inp or t_inp should be used, another should be set to 0
//
// f_out - input - output data, file hanle, caller fopen(), caller should fclose()
// pt_out - output - output data, zero terminated string, function allocated with p_malloc(), caller must free with p_free()
//      if pt_out is used input should be in t_inp
//
// binmode - input - if 0 file is encrypted in ASCII mode, must be 0 if t_inp or pt_out used.

int do_encrypt_c( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out);
// f_key - input - key file hanle, caller fopen(), caller should fclose()
// t_key - input - key, zero terminated string
// f_inp
// t_inp
// f_out
// pt_out
// binmode

int do_decrypt_c( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out);
// f_key - input - key file hanle, caller fopen(), caller should fclose()
// t_key - input - key, zero terminated string
// f_inp
// t_inp
// f_out
// pt_out
// binmode

int do_sign( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, int binmode, char * t_inp, char ** pt_out);
// f_key - input - private key, file hanle, caller fopen(), caller should fclose()
// t_key - input - private key, zero terminated string
//
// f_inp - input - input data, file hanle, caller fopen(), caller should fclose()
// t_inp - input - input data, zero terminated string
//      only one of f_inp or t_inp should be used, another should be set to 0
//
// f_out - input - output data, file hanle, caller fopen(), caller should fclose()
// pt_out - output - output data, zero terminated string, function allocated with p_malloc(), caller must free with p_free()
// if pt_out is used input should be in t_inp
//
// binmode - input - if 0 file is clearsigned in ASCII mode, must be 0 if t_inp or pt_out used.
//                   if 1 detached signature is made (in f_out of pt_out)

int do_verify( FILE * f_key, char * t_key, FILE * f_inp, FILE * f_out, FILE * f_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec);
// f_key - input - public key, file hanle, caller fopen(), caller should fclose()
// t_key - input - public key, zero terminated string
//      only one of f_key or t_key can be used, another should be set to 0
//
// f_inp - input - input data, file hanle, caller fopen(), caller should fclose()
// t_inp - input - input data, zero terminated string
//      only one of f_inp or t_inp should be used, another should be set to 0
//
// f_out - input - output data, file hanle, caller fopen(), caller should fclose()
// pt_out - output - output data, zero terminated string, function allocated with p_malloc(), caller must free with p_free()
//      used only if checking clearsignature (if binmode == 0)
//      if pt_out is used input should be in t_inp
//
// f_sec - input - detached signature, file hanle, caller fopen(), caller should fclose()
// t_inp - input - detached signature, zero terminated string
//      used only if checking detached signature (if binmode == 1)
//
// binmode - input - if 0 file is clearsigned in ASCII mode, must be 0 if t_inp or pt_out used.
//                   if 1 detached signature is checked (from t_sec or f_sec)


// DLL functions
// parameters are the same, the only difference is that these
// functions expects file names instead of handles
int dll_make_key( char * fn_key, char * t_key, char * fn_out, char ** pt_out);
int dll_encrypt_pk( char ** pfn_key, char ** pt_key, char * fn_inp, char * fn_out, char * fn_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec, unsigned numkey);
int dll_decrypt_pk( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode, char * t_inp, char ** pt_out, unsigned * keyn);
int dll_encrypt_c( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode,  char * t_inp, char ** pt_out);
int dll_decrypt_c( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode, char * t_inp, char ** pt_out);
int dll_sign( char * fn_key, char * t_key, char * fn_inp, char * fn_out, int binmode, char * t_inp, char ** pt_out);
int dll_verify( char * fn_key, char * t_key, char * fn_inp, char * fn_out, char * fn_sec, int binmode, char * t_inp, char ** pt_out, char * t_sec);


#if  defined(WIN32) && !defined(WINAPI)
 /* define GlobalXxx if windows.h not included */
void * __stdcall GlobalAlloc(unsigned,unsigned);
void * __stdcall GlobalLock(void *);
void * __stdcall GlobalHandle(void *);
void * __stdcall GlobalFree(void *);
int __stdcall GlobalUnlock(void *);
#endif

#if defined(WIN32)
#define p_malloc(x) GlobalLock(GlobalAlloc(0x42, (x)))
#define p_free(lp) (GlobalUnlock(GlobalHandle(lp)), GlobalFree(GlobalHandle(lp)))
#else
#define p_malloc malloc
#define p_free free
#endif


// error codes
#define ERR_NOERROR (0)
#define ERR_UNKNOWN (-1)
#define ERR_OUTPUT (-2) /* "Pegwit, error writing output, disk full?"; */
#define ERR_INPUT (-3)
#define ERR_BADARMOR (-4)
#define ERR_NOHEADER (-5) /* "Clearsignature header \"###\" not found\a\a\a\n"; */
#define ERR_SYMDECRYPT (-6) /* "decryption failed\a\a\a\n"; */
#define ERR_BADSYMCIPHER (-7)
#define ERR_NOECC (-8)
#define ERR_BADSIGN (-9) /* "signature did not verify\a\a\a\n"; */
#define ERR_BADKEYNUM (-10)
#define ERR_BADPARAM (-11)
#define ERR_NOMEMORY (-12)
