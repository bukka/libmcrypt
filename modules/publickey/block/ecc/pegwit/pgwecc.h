CURVE Public_Curve;
POINT Base_Point;
FIELD2N pnt_order;

//int InitECC(void);

int MakePublicKey( FIELD2N * pub, FIELD2N * secret );
int EncodeSecret(FIELD2N * pub, FIELD2N * d, FIELD2N * r, FIELD2N * Xpck, FIELD2N * Rpck);
int DecodeSecret(FIELD2N * secret, FIELD2N * d, FIELD2N * Xpck, FIELD2N * Rpck);
int Sign( FIELD2N * secret, FIELD2N * session, FIELD2N * mac, SIGNATURE * sig );
int Verify( FIELD2N * pub, FIELD2N * mac, SIGNATURE * sig );

void NormSecret(FIELD2N * secret, FIELD2N * secretm);
void Pack(POINT * unp, FIELD2N * pck);
void Unpack(FIELD2N * pck, POINT * unp);
int isdiff(FIELD2N * a, FIELD2N * b);
