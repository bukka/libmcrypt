/************************************************************
*														    	*
*  Implement combinations of math packages to create 	    				*
*  advanced protocols.  Massy-Omura is first example.	    				*
*  Nyberg_Rueppel second.				    						*
*							    								*
*		Author = Mike Rosing			    						*
*		 Date  = Jan 4, 1998	 		    							*
*							    								*
*		NR Jan. 9, 1998				    						*
*							    								*
*  Modified Oct. 17, 2000 to work with freelip for integer  				*
*  part as subsection to pegwit.                            						*
************************************************************/

#include <stdio.h>
#include "field2n.h"
#include "lip.h"
#include "eliptic.h"
#include "protocols.h"

#include "sha256.h"

/*  A 233 bit number is 70.14 decimal digits, so I'll leave room for 80  */

#define MAXSTRING 	            80

extern unsigned long random_seed;
extern void sha_memory();

/*  print out an integer.  input is label string and pointer
	to integer, sends to terminal.
*/

void print_int( string, number)
char	*string;
verylong number;
{
	char	teststring[MAXSTRING], outchar[2*MAXSTRING];
	
	zswrite( teststring, number);
	sprintf(outchar, "%s\n%s\n", string, teststring);
	printf("%s\n", outchar);
}
	
/*  function to compare BIGINT value to 1.
	Returns 1 if it is, 0 otherwise.
*/

INDEX int_onecmp( number)
verylong number;
{

	if (! zscompare( number, 1L)) return(1);
	return (0);
}

/*  convert verylong integer to and from FIELD2N.
	Brings over as many bits as will fit, least
	significant first.
	Note, these routines will fail for NUMBITS 
	greater than 450 bits (on 32 bit machines,
	225 on 16, 900 on 64).
*/

void zint_to_field( zint, field)
verylong	zint;
FIELD2N		*field;
{
	INDEX	i;
	ELEMENT	temp;
	
	i = 1;
	while (i<(short)zint[0] && i<=MAXLONG)
	{
		temp = zint[i] >> (2*(i-1));
		field->e[MAXLONG - i] = temp | zint[i+1] << (WORDSIZE - 2*i);
		i++;
	}
	field->e[MAXLONG - i] = zint[i] >> 2*(i-1);
}

void field_to_zint( field, zint)
FIELD2N		*field;
verylong	*zint;
{
	INDEX	i;
	ELEMENT	temp;
	
//	*zint = 0;
	zzero(zint);
	(*zint)[1] = field->e[NUMWORD] & 0x3fffffff;
	for ( i=1; i<MAXLONG; i++)
	{
		temp = (field->e[NUMWORD - i] << (2*i)) & 0x3fffffff;
		(*zint)[i+1] = temp | field->e[MAXLONG - i] >> (WORDSIZE - 2*i);
		(*zint)[0]++;
	}
}

/*  Generate a key pair, a random value plus a point.
	This was called ECKGP for Elliptic Curve Key Generation
	Primitive in an early draft of IEEE P1363.

	Input:  EC parameters including public curve, point,
			point order and cofactor
	
	Output: EC key pair including
			secret key k and random point R = k* base point
*/

void ECKGP( Base, Key, rand_key)
EC_PARAMETER	*Base;
EC_KEYPAIR		*Key;
FIELD2N		*rand_key;
{
	verylong		key_num, point_order, quotient, remainder;
	//FIELD2N		rand_key;

	key_num = 0;
	point_order = 0;
	quotient = 0;
	remainder = 0;
		
/*  ensure random value is less than point order  */
	
	//random_field( &rand_key);

	field_to_zint( rand_key, &key_num);
	field_to_zint( &Base->pnt_order, &point_order);
	zdiv( key_num, point_order, &quotient, &remainder);
	zint_to_field( remainder, &Key->prvt_key);

	elptic_mul( &Key->prvt_key, &Base->pnt, &Key->pblc_key, &Base->crv);
	
	zfree( &key_num);
	zfree( &point_order);
	zfree( &quotient);
	zfree( &remainder);
}

/*  As required in Massey-Omura protocol, create a number
	and its inverse over known curve order.  Input is
	public EC parameters, output is random e and d
	modulo curve order where ed = 1 mod N
*/
/*
void gen_MO_pair ( Public, e, d)
EC_PARAMETER	*Public;
FIELD2N			*e, *d;
{
	FIELD2N	garbage;
	BIGINT	gcd_check, crv_order, pnt_order, cfactor;
	BIGINT	search, en, de;

/*  since 2 is always a factor, stay odd while hunting  */
/*
	int_null( &search);
	search.hw[INTMAX] = 2;

/*  compute curve order  */
/*
	field_to_int( &Public->pnt_order, &pnt_order);
	field_to_int( &Public->cofactor, &cfactor);
	int_mul( &cfactor, &pnt_order, &crv_order);

/*  find random value prime to curve order.  EC curves over
	GF(2^n) are always even  */
/*	
	random_field( &garbage);
	garbage.e[NUMWORD] |= 1L;
	field_to_int( &garbage, &en);
	int_gcd( &en, &crv_order, &gcd_check);

/*  hunt for value that is relatively prime to curve order  */
/*
	while ( !int_onecmp( &gcd_check))
	{
		int_add( &search, &en, &en);
		int_gcd( &en, &crv_order, &gcd_check);
	}

/*  compute an inverse to complete the pair  */
/*
	mod_inv( &en, &crv_order, &de);
	int_to_field( &en, e);
	int_to_field( &de, d);
}

/*  Massey-Omura secret sharing protocol, sender side.
	Computes an encryption, decryption pair (e, d) and
	embeds data on public curve (Pub_crv).  
	Output is e*Pm and d.
*/
/*
void onb_Massey_Omura_send( Pub_crv, message, send_point, decrypt)
EC_PARAMETER	*Pub_crv;
FIELD2N			*message, *decrypt;
POINT			*send_point;
{
	POINT	msg;
	FIELD2N	e;
	
/*  embed data on given curve.  Change increment or field size to
	ensure trouble free operations.
*/
/*	opt_embed( message, &Pub_crv->crv, 0, 0, &msg);

/*  create random encryption and decryption pair  */

/*	gen_MO_pair( Pub_crv, &e, decrypt);

/*  compute point to transmit  */

/*	elptic_mul( &e, &msg, send_point, &Pub_crv->crv);
}

/*  Massey-Omura secret sharing protocol, receiver side.
	input: senders point (rcv_point), public curve (Pub_crv).
	generates encrypt, decrypt pair,
	output: e*rcv_point (step2), decrypt
*/
/*
void onb_Massey_Omura_rcv( Pub_crv, rcv_point, step2, decrypt)
EC_PARAMETER	*Pub_crv;
POINT			*rcv_point, *step2;
FIELD2N			*decrypt;
{
	FIELD2N	e;
	
/* create encrypt, decrypt pair  */

/*	gen_MO_pair (Pub_crv, &e, decrypt);

/*  compute point to transmit back  */

/*	elptic_mul ( &e, rcv_point, step2, &Pub_crv->crv);
}

/*  Subroutine to compute hash of a message and return the result 
	as an integer.  Used in all signature schemes.
	
	Enter with pointer to message, message length
*/

void hash_to_int( Message, length, hash_value)
char 			*Message;
unsigned long 	length;
verylong		*hash_value;		/*  then to an integer  */
{
	unsigned long	message_digest[HW];	/*  from SHA-1 hash function  */
	FIELD2N		mdtemp;			/*  convert to NUMBITS size (if needed)  */
	INDEX		i, count;
		
	if (!length) {
/*  message already IS hash_value!! */
        field_to_zint( Message, hash_value);
        return;
    }

/*  compute hash of input message  */

	sha_memory(	Message, length, message_digest);

/*  convert message digest into an integer */

	null ( &mdtemp);
	count = 0;
	SUMLOOP (i)
	{
		mdtemp.e[ NUMWORD - i] = message_digest[i];
        count++;
		if (count >= HW) break;
	}
	mdtemp.e[0] &= UPRMASK;
	field_to_zint( &mdtemp, hash_value);
}
	
/*  Implement Nyberg-Rueppel signature scheme described in IEEE P1363 draft
	standard of August 1997.  This uses SHA-1 as the hash algorithm on the
	message.  Inputs are a pointer to Message, public elliptic curve parameters
	including the order of the curve, and the signers secret key for signing, 
	or public key for verification.
*/

/*  Nyberg-Rueppel elliptic curve signature scheme.

	Inputs: pointer to Message to be signed and its length,
			pointer to elliptic curve parameters,
			pointer to signer's secret key,
			pointer to signature storage area.
			
	Output: fills signature storage area with 2 numbers
			first number = SHA(Message) + random value
			second number = random value - signer's secret key times first number
					both are done modulo base point order
			
			The output is converted back to FIELD2N variables to save space
			and to make verification easier.
*/
/*
void NR_Signature( Message, length, public_curve, secret_key, signature)
char *Message;
unsigned long length;
EC_PARAMETER *public_curve;
FIELD2N *secret_key;
SIGNATURE *signature;
{
	BIGINT			hash_value;
	FIELD2N			random_value;
	POINT			random_point;
	BIGINT			x_value, k_value, sig_value;
	BIGINT			temp, quotient;
	BIGINT			key_value, point_order;
	INDEX			i, count;

/*  compute hash of input message  */

/*	hash_to_int( Message, length,  &temp);
	field_to_int( &public_curve->pnt_order, &point_order);
	int_div( &temp, &point_order, &quotient, &hash_value);
	
/*  create random value and generate random point on public curve  */

/*	random_field( &random_value);
	elptic_mul( &random_value, &public_curve->pnt, 
					&random_point, &public_curve->crv);
	
/*  convert x component of random point to an integer and add to message
	digest modulo the order of the base point.
*/

/*	field_to_int( &random_point.x, &x_value);
	int_add( &x_value, &hash_value, &temp);

	int_div( &temp, &point_order, &quotient, &sig_value);
	int_to_field( &sig_value, &signature->c);

/*  final step is to combine signer's secret key with random value  
		second number = random value - secret key * first number
		modulo order of base point
*/

/*	field_to_int( &random_value, &k_value);
	field_to_int( secret_key, &key_value);
	int_mul( &key_value, &sig_value, &temp);
	int_div( &temp, &point_order, &quotient, &sig_value);
	
	int_sub( &k_value, &sig_value, &sig_value);
	while( sig_value.hw[0] & 0x8000) 
		int_add( &point_order, &sig_value, &sig_value);
	int_div( &sig_value, &point_order, &quotient, &temp);
	int_to_field( &sig_value, &signature->d);
}

/*  verify a signature of a message using Nyberg-Rueppel scheme.

	Inputs:	Message to be verified of given length,
			elliptic curve parameters public_curve 
			signer's public key (as a point),
			signature block.
	
	Output: value 1 if signature verifies,
			value 0 if failure to verify.
*/

/*int NR_Verify( Message, length, public_curve, signer_point, signature)
char			*Message;
unsigned long 	length;
EC_PARAMETER	*public_curve;
POINT			*signer_point;
SIGNATURE		*signature;
{
	BIGINT			hash_value;
	POINT			Temp1, Temp2, Verify;
	BIGINT			x_value, c_value;
	BIGINT			temp, quotient;
	BIGINT			check_value, point_order;
	INDEX			i, count;
	
/*  find hidden point from public data  */

/*	elptic_mul( &signature->d, &public_curve->pnt, &Temp1, &public_curve->crv);
	elptic_mul( &signature->c, signer_point, &Temp2, &public_curve->crv);
	esum( &Temp1, &Temp2, &Verify, &public_curve->crv);
	
/*  convert x value of verify point to an integer and first signature value too  */

/*	field_to_int( &Verify.x, &x_value);
	field_to_int( &signature->c, &c_value);

/*  compute resultant message digest from original signature  */

/*	field_to_int( &public_curve->pnt_order, &point_order);
	int_sub( &c_value, &x_value, &temp);
	while( temp.hw[0] & 0x8000) 			/* ensure positive result */
/*		int_add( &point_order, &temp, &temp);
	int_div( &temp, &point_order, &quotient, &check_value);

/*  generate hash of message and compare to original signature  */
/*
	hash_to_int( Message, length, &temp);
	int_div( &temp, &point_order, &quotient, &hash_value);
	
	int_null(&temp);
	int_sub( &hash_value, &check_value, &temp);
	while( temp.hw[0] & 0x8000) 		/*  ensure positive zero */
/*		int_add( &point_order, &temp, &temp);

/*  return error if result of subtraction is not zero  */

/*	INTLOOP(i) if (temp.hw[i]) return(0);  
	return(1);
}

/*  Elliptic Curve Secret Value Derivation Primative, Menezes-Qu-Vanstone version.
	Enter with "this sides" secret and public key, as well as ephemeral secret and
	ephemeral public key, the other sides publick and ephemeral keys, and the 
	elliptic curve parameters they are all based on including curve, point and 
	order of the point.
	
	Returns a shared secret value.  This version uses an integer package as well
	as elliptic curve mathematics.
*/

void onb_mqv( Base, my_first, my_second, 
				their_first, their_second,
				shared_secret)
EC_PARAMETER *Base;
EC_KEYPAIR	 *my_first, *my_second;
POINT        *their_first, *their_second;
FIELD2N      *shared_secret;
{
	verylong	my_x_value=0;
	verylong	my_secret=0, my_ephemeral=0;
	FIELD2N	my_half_x, their_half_x;
	verylong	temp1=0, quotient=0, temp2=0;
	verylong	cfactor=0, point_order=0;
	FIELD2N	e_value;
	POINT	Temp, Common;
	INDEX	i, limit, half_msb;
	ELEMENT	mask;
	
/*  convert x component of my ephemeral key to an integer modulo
	2^h where h is half the size of the order of the base point.
	Since we are using curves with order almost equal to the 
	field size, the value of h is about half NUMBITS.  
	Change limit to meet the specs for your application.
*/

	limit = NUMBITS / 2;
	half_msb = limit % WORDSIZE;
	mask = ~(~0 << half_msb);
	limit = limit/WORDSIZE + ( half_msb ? 1 : 0);
	copy( &my_second->pblc_key.x, &my_half_x);
	for( i=0; i<limit; i++) my_half_x.e[i] = 0;
	my_half_x.e[i] &= mask;
	my_half_x.e[i] |= 1L << half_msb;
	field_to_zint( &my_half_x, &my_x_value);

/*  get half the other sides ephemeral key  */

	copy( &their_second->x, &their_half_x);
	for( i=0; i<limit; i++) their_half_x.e[i] = 0;
	their_half_x.e[i] &= mask;
	their_half_x.e[i] |= 1L << half_msb;
	
/*  compute multiplier from my secrets and x component  */

	field_to_zint( &my_first->prvt_key, &my_secret);
	field_to_zint( &my_second->prvt_key, &my_ephemeral);
	field_to_zint( &Base->pnt_order, &point_order);
	zmul( my_x_value, my_secret, &temp1);
	zadd( temp1, my_ephemeral, &temp1);
	zdiv( temp1, point_order, &quotient, &temp2);
	
/*  convert integer to equivelent compressed value for 
	elliptic multiply. */
	
	zint_to_field( &temp2, &e_value);

/*  use other sides public points to create their 
	portion of the secret.  */
	
	elptic_mul( &their_half_x, their_first, &Common, &Base->crv);
	esum( their_second, &Common, &Temp, &Base->crv);
	elptic_mul( &e_value, &Temp, &Common, &Base->crv);

/*  take output from common point  */

	copy( &Common.x, shared_secret);
	
	zfree( &my_x_value);
	zfree( &my_secret);
	zfree( &my_ephemeral);;
	zfree( &temp1);
	zfree(  &quotient);
	zfree( &temp2);
	zfree( &cfactor);
	zfree( &point_order);

}

/*  DSA version of Elliptic curve signature primitive of IEEE P1363.

	Enter with EC parameters, signers private key, pointer to message and
	it's length.
	
	Output is 2 values in SIGNITURE structure.
	value "c" = x component of random point modulo point order of
				public point  (random point = random key * public point)
	value "d" = (random key)^-1 * (message hash + signer's key * c)
*/

//void onb_DSA_Signature( Message, length, public_curve, secret_key, signature)
void onb_DSA_Signature( Message, length, public_curve, secret_key, signature, random)
char *Message;
unsigned long length;
EC_PARAMETER *public_curve;
FIELD2N *secret_key;
SIGNATURE *signature;
FIELD2N *random;
{
	verylong			hash_value=0;		/*  then to an integer  */
	EC_KEYPAIR		random_key;
	verylong			x_value=0, k_value=0, sig_value=0, c_value=0;
	verylong			temp=0, quotient=0;
	verylong			key_value=0, point_order=0, u_value=0;
	INDEX			i, count;

/*  compute hash of input message  */

	hash_to_int( Message, length, &hash_value);
	
/*  create random value and generate random point on public curve  */

	ECKGP( public_curve, &random_key, random);
		
/*  convert x component of random point to an integer modulo
	the order of the base point.  This is first part of 
	signature.
*/

	field_to_zint( &public_curve->pnt_order, &point_order);
	field_to_zint( &random_key.pblc_key.x, &x_value);
	zdiv( x_value, point_order, &quotient, &c_value);
	zint_to_field( c_value, &signature->c);
	
/*	multiply that  by signers private key and add to message
	digest modulo the order of the base point. 
	hash value + private key * c value
*/

	field_to_zint( secret_key, &key_value);
	zmul( key_value, c_value, &temp);
	zadd( temp, hash_value, &temp);
	zdiv( temp, point_order, &quotient, &k_value);
	
/*  final step is to multiply by inverse of random key value
		modulo order of base point.
*/

	field_to_zint( &random_key.prvt_key, &temp);
	zinvmod( temp, point_order, &u_value);
	zmul( u_value, k_value, &temp);
	zdiv( temp, point_order, &quotient, &sig_value);
	zint_to_field( sig_value, &signature->d);
	
	zfree( &hash_value);
	zfree( &x_value);
	zfree( &k_value);
	zfree(  &sig_value);
	zfree( &c_value);
	zfree( &temp);
	zfree( &quotient);
	zfree( &key_value);
	zfree( &point_order);
	zfree(  &u_value);

}

/*  verify a signature of a message using DSA scheme.

	Inputs:	Message to be verified of given length,
			elliptic curve parameters public_curve 
			signer's public key (as a point),
			signature block.
	
	Output: value 1 if signature verifies,
			value 0 if failure to verify.
*/

int onb_DSA_Verify( Message, length, public_curve, signer_point, signature)
char			*Message;
unsigned long 	length;
EC_PARAMETER	*public_curve;
POINT			*signer_point;
SIGNATURE		*signature;
{
	verylong			hash_value=0;
	POINT			Temp1, Temp2, Verify;
	verylong			c_value=0, d_value=0;
	verylong			temp=0, quotient=0, h1=0, h2=0;
	verylong			check_value=0, point_order=0;
	INDEX			i, count;
	FIELD2N			h1_field, h2_field;

/*  compute inverse of second signature value  */

	field_to_zint( &public_curve->pnt_order, &point_order);
	field_to_zint( &signature->d, &temp);
	zinvmod( temp, point_order, &d_value);
	
/*  generate hash of message  */

	hash_to_int( Message, length, &hash_value);

/*  compute elliptic curve multipliers:
	h1 = hash value * d_value, h2 = c * d_value
*/

	zmul( hash_value, d_value, &temp);
	zdiv( temp, point_order, &quotient, &h1);
	zint_to_field( h1, &h1_field);
	field_to_zint( &signature->c, &c_value);
	zmul( d_value, c_value, &temp);
	zdiv( temp, point_order, &quotient, &h2);
	zint_to_field( h2, &h2_field);

/*  find hidden point from public data  */

	elptic_mul( &h1_field, &public_curve->pnt, &Temp1, &public_curve->crv);
	elptic_mul( &h2_field, signer_point, &Temp2, &public_curve->crv);
	esum( &Temp1, &Temp2, &Verify, &public_curve->crv);
	
/*  convert x value of verify point to an integer modulo point order */

	field_to_zint( &Verify.x, &temp);
	zdiv( temp, point_order, &quotient, &check_value);
	
/*  compare resultant message digest from original signature  */

	zzero(&temp);
	zsub( c_value, check_value, &temp);
	
	i = ziszero( temp);

	zfree( &hash_value);
	zfree( &c_value);
	zfree( &d_value);
	zfree( &temp);
	zfree( &quotient);
	zfree( &h1);
	zfree(  &h2);
	zfree( &check_value);
	zfree( &point_order);
	
/*  return error if result of subtraction is not zero  */

	return (i);
}
/*
main()
{
	EC_PARAMETER	Base;
	EC_KEYPAIR		Signer;
	SIGNATURE		signature;
	BIGINT			prime_order;
	POINT			temp;
	INDEX 			i, error;
	char			Message[1024];
	
	char string1[MAXSTRING] = "5192296858534827627896703833467507"; /*N 113  */
/*	char string1[MAXSTRING] = "680564733841876926932320129493409985129";*/ /*N~ 131 */
/*	char string1[MAXSTRING] = "5444517870735015415344659586094410599059";*/ /*N 134 (g^2 = g+1)	*/
/*	char string1[MAXSTRING] = "19822884620916109459140767798279811163792081";*/ /*N~ 148 GF(16) */
/*	char string1[MAXSTRING] = "91343852333181432387730573045979447452365303319";*/  /* N 158 */
	
/*	init_opt_math();
	
	random_seed = 0xFEEDFACE;

/*  compute curve order from Koblitz data  */

/*	ascii_to_bigint(&string1, &prime_order);
	int_to_field( &prime_order, &Base.pnt_order);
	null( &Base.cofactor);
	Base.cofactor.e[NUMWORD] = 2;

/*  create Koblitz curve  */

/*	Base.crv.form = 1;
	one(&Base.crv.a2);
	one(&Base.crv.a6);
	print_curve("Koblitz 113", &Base.crv);

/*  create base point of known order with no cofactor  */

/*	rand_point( &temp, &Base.crv);
	print_point("random point", &temp);
	edbl( &temp, &Base.pnt, &Base.crv);
	print_point(" Base point ",&Base.pnt);
	
/*  create a secret key for testing. Note that secret key must be less than order.
	The standard implies that the field size which can be used is one bit less than
	the length of the public base point order.
*/

/*	ECKGP( &Base, &Signer);
	print_field("Signer's secret key", &Signer.prvt_key);
	print_point("Signers public key", &Signer.pblc_key);
	
/*  create a message to be signed  */

/*	for (i=0; i<1024; i++) Message[i] = i;

/*  call Nyberg_Ruepple signature scheme  */

/*	NR_Signature( Message, 1024, &Base, &Signer.prvt_key, &signature);
	print_field("first component of signiture", &signature.c);
	print_field("second component of signiture", &signature.d);

/*  verify message has not been tampered.  Need public curve parameters, signers
	public key, message, length of message, and order of public curve parameters
	as well as the signature. If there is a null response, message is not same as
	the orignal signed version.
*/
/*	error = NR_Verify( Message, 1024, &Base, &Signer.pblc_key, &signature);
	if (error) printf("Message Verifies");
	else printf("Message fails!");
}
*/