/*
 utils.h

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
*/

int get_psec_param(EC_PARAM *E, FILE *fp);

int get_pubKey(PSEC3_PUB_KEY *publicKey, FILE *fp);

int get_privKey(PSEC3_PRIV_KEY *privateKey, FILE *fp);

int get_ciphertext(PSEC3_CIPHERTEXT *ciphertext, PSEC3_PUB_KEY *publicKey, EC_PARAM *E, FILE *fp);

FILE *open_input(const char *filename);

FILE *open_output(const char *filename);

int parse_field(char *one_line, char *field_id, char *field_body);

void assignBYTE(BYTE *to, BYTE *from, WORD len);

void WORD2BYTE(BYTE *xp_raw, mp_srcptr xp, mp_size_t xsize);

mp_size_t BYTE2WORD(mpz_ptr x, BYTE *raw, mp_size_t size);

WORD Vernam(BYTE *K, WORD kLen, BYTE *in, BYTE *out);

int ec2os(unsigned char *po, EC_POINT *P, EC_PARAM *E);

int os2ec(EC_POINT *P, unsigned char *po, EC_PARAM *E);
