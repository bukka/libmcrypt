#include "lip.h"
#include "field2n.h"
#include "eliptic.h"
#include "protocols.h"

#include "pgwecc.h"

// NIST curve       form,     a2,               a6
//CURVE Public_Curve = {0, {0,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,1}};
CURVE Public_Curve = {0, {0,0,0,0,0,0,0,0}, {0x000001ff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff}};
//POINT Base_Point = {{0x00000172,0x32ba853a,0x7e731af1,0x29f22ff4,0x149563a4,0x19c26bf5,0x0a4c9d6e,0xefad6126},
//                    {0x000001db,0x537dece8,0x19b7f70f,0x555a67c4,0x27a8cd9b,0xf18aeb9b,0x56e0c110,0x56fae6a3}};
POINT Base_Point = {{0x000000fd,0xe76d9dcd,0x26e643ac,0x26f1aa90,0x1aa12978,0x4b71fc07,0x22b2d056,0x14d650b3},
//                    {0x00000064,0x3e317633,0x155c9e04,0x47ba8020,0xa3c43177,0x450ee036,0xd6335014,0x34cac978}};
                    {0x0000011c,0x7f469f4b,0x1f778bd9,0x4fbe2627,0xfe4084b3,0xf9b5fb31,0xce60f571,0xc64c8b6e}};
FIELD2N pnt_order = {0x00000080,0x00000000,0x00000000,0x00000000,0x00069d5b,0xb915bcd4,0x6efb1ad5,0xf173abdf};
                    //3450873173395281893717377931138512760570940988862252126328087024741343

EC_PARAMETER Base = {
//                     {0, {0,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,1}},
                     {0, {0,0,0,0,0,0,0,0}, {0x000001ff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff}},
//                      {{0x00000172,0x32ba853a,0x7e731af1,0x29f22ff4,0x149563a4,0x19c26bf5,0x0a4c9d6e,0xefad6126},
//                       {0x000001db,0x537dece8,0x19b7f70f,0x555a67c4,0x27a8cd9b,0xf18aeb9b,0x56e0c110,0x56fae6a3}},
                      {{0x000000fd,0xe76d9dcd,0x26e643ac,0x26f1aa90,0x1aa12978,0x4b71fc07,0x22b2d056,0x14d650b3},
//                       {0x00000064,0x3e317633,0x155c9e04,0x47ba8020,0xa3c43177,0x450ee036,0xd6335014,0x34cac978}},
                       {0x0000011c,0x7f469f4b,0x1f778bd9,0x4fbe2627,0xfe4084b3,0xf9b5fb31,0xce60f571,0xc64c8b6e}},
                      {0x00000080,0x00000000,0x00000000,0x00000000,0x00069d5b,0xb915bcd4,0x6efb1ad5,0xf173abdf},
                     {0,0,0,0,0,0,0,4}
                    };

void print_field();

int InitECC(void)
{
	init_opt_math();
#ifdef _DEBUG
{
POINT temp; int b, *v;
//print_field("bp.x ", &Base_Point.x);
//print_field("bp.y ", &Base_Point.y);
opt_embed(&Base_Point.x, &Public_Curve, 0, 0, &temp);
//print_field("bp.y0", &temp.y);
b = isdiff(&Base_Point.y, &temp.y);
opt_embed(&Base_Point.x, &Public_Curve, 0, 1, &temp);
//print_field("bp.y1", &temp.y);
b = b && isdiff(&Base_Point.y, &temp.y);
if (b) {v=NULL; *v=0;}; /* assert - point is not on curve */
}
#endif
	return 0;
}

void NormSecret(FIELD2N * secret, FIELD2N * secretm)
{
	verylong key_num=0, point_order=0, quotient=0, remainder=0;

	field_to_zint( secret, &key_num);
//	print_field("input secret", secret);
	field_to_zint( &pnt_order, &point_order);
//	print_field("point order is", &pnt_order);
	zdiv( key_num, point_order, &quotient, &remainder);
	zint_to_field( remainder, secretm);
//	print_field("output secret", secretm);
	zfree( &key_num);
	zfree( &point_order);
	zfree( &quotient);
	zfree( &remainder);
}

int MakePublicKey(FIELD2N * pub, FIELD2N * secret)
{
	FIELD2N secretm;
   	POINT publ;

    	NormSecret(secret, &secretm);
//    	print_field("new secret", &secretm);
    	elptic_mul(&secretm, &Base_Point, &publ, &Public_Curve);
    	Pack(&publ, pub);
    	return 1;
}

int EncodeSecret(FIELD2N * pub, FIELD2N * d, FIELD2N * r, FIELD2N * Xpck, FIELD2N * Rpck)
{
	POINT Ppub, X, R;
	POINT H, D;

    Unpack(pub, &Ppub);
	//send_elgamal(&Base_Point, &Public_Curve, &Ppub, d, &X, &R);
	    //random_field (&r);
	    elptic_mul (r, &Base_Point, &R, &Public_Curve);
	    opt_embed( d, &Public_Curve, 0, 0, &D);
	    elptic_mul( r, &Ppub, &H, &Public_Curve);
	    esum( &H, &D, &X, &Public_Curve);
    Pack(&X, Xpck);
    Pack(&R, Rpck);
    return 1;
}

int DecodeSecret(FIELD2N * secret, FIELD2N * d, FIELD2N * Xpck, FIELD2N * Rpck)
{
	FIELD2N secretm;
	POINT X, R;
	POINT H, D;

    NormSecret(secret, &secretm);
    Unpack(Xpck, &X);
    Unpack(Rpck, &R);
	//receive_elgamal(&Base_Point, &Public_Curve, &secretm, &X, &R, d);
	    elptic_mul( &secretm, &R, &H, &Public_Curve);
	    esub( &X, &H, &D, &Public_Curve);
	    copy(&D.x, d);
    return 1;
}

int Sign(FIELD2N * secret, FIELD2N * session, FIELD2N * mac, SIGNATURE * sig)
{
	FIELD2N secretm;

    NormSecret(secret, &secretm);

    onb_DSA_Signature(mac, 0, &Base, &secretm, sig, session);
    return 1;
}

int Verify(FIELD2N * pub, FIELD2N * mac, SIGNATURE * sig)
{
	POINT Ppub;

    Unpack(pub, &Ppub);
    return
        onb_DSA_Verify(mac, 0, &Base, &Ppub, sig);
}


void Pack(POINT * unp, FIELD2N * pck)
{
  ELEMENT sy;
  POINT temp;

//print_field("  PACK in ", &unp->x);
//print_field("  PACK in ", &unp->y);
  copy(&unp->x, pck);
  opt_embed(pck, &Public_Curve, 0, 0, &temp);
//  opt_embed(pck, &Public_Curve, 0, 1, &temp);
  sy = isdiff(&unp->y, &temp.y);
  pck->e[0] |= (sy<<(UPRSHIFT)); // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//print_field("  PACK out", pck);
}

void Unpack(FIELD2N * pck, POINT * unp)
{  
  int sy;

//print_field("UNPACK in ", pck);
  sy = (pck->e[0] >> UPRSHIFT) & 1; // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  pck->e[0] &= UPRMASK;
  opt_embed(pck, &Public_Curve, 0, sy, unp);
//print_field("UNPACK out", &unp->x);
//print_field("UNPACK out", &unp->y);
}

int isdiff(FIELD2N * a, FIELD2N * b)
{
  int i, v = 0;

  SUMLOOP(i)
    if (a->e[i] != b->e[i])
        return 1;
  return 0;
}
