/*
 utils-psec.h

 Copyright NTT MCL, 2000.

 Duncan S Wong
 Security Group, NTT MCL
 July 2000

 7/18/00 - modified get_ciphertext to read elliptic curve points which are
           in octet string format
         - add function ec2os to convert elliptic curve points to octet
           strings
         - add function os2ec to convert octet strings to elliptic curve
           points

 9/14/2000 - Changed type declarations to match those in nessie.h -- S.O.

 10/24/2000 - Modified get_ciphertext to include cipherInfo as a 
	      parameter. 
	    - Modified WORD2BYTE function prototype -- S.O.

 10/25/2000 - Added get_randomseed by T. Kobayashi. -- H.O.

 9/22/2001 - Added compressed and hybrid formats to ec2os.  -- S.O.
*/

s32 get_psec_param(EC_PARAM *E, FILE *fp);

s32 get_pubKey(PSEC_KEM_PUB_KEY *publicKey, FILE *fp);

s32 get_privKey(PSEC_KEM_PRIV_KEY *privateKey, FILE *fp);

u8 ec2os(u8 *po, EC_POINT *P, EC_PARAM *E, u8 format);

u8 os2ec(EC_POINT *P, u8 *po, EC_PARAM *E);

u8 mpz_sqrootm(mpz_t z, mpz_t g, mpz_t p);

void generateLucasSequence(mpz_t V_k_mod_n, mpz_t Q_k_over_2_mod_n, mpz_t n, mpz_t P, mpz_t Q, mpz_t k);
