/*  These structures described in IEEE P1363 Nov. 1997  */

typedef struct
{
	CURVE	crv;
	POINT	pnt;
	FIELD2N	pnt_order;
	FIELD2N	cofactor;
} EC_PARAMETER;

typedef struct
{
	FIELD2N	prvt_key;
	POINT	pblc_key;
} EC_KEYPAIR;

typedef struct 
{
	FIELD2N		c;
	FIELD2N		d;
} SIGNATURE;

/* prototypes */

void print_int();
INDEX int_onecmp();
void gen_MO_pair();
void onb_Massey_Omura_rcv();
void onb_Massey_Omura_send();
void NR_Signature();
int NR_Verify();
void onb_mqv();
void onb_DSA_Signature();
int onb_DSA_Verify();
void hash_to_int();