
#define KR_SIZE 10

#define KEYSIZE 40

int LoadKeyring(void);
int SaveKeyring(void);
int FreeKeyring(void);
int DelKey(int num);
int SetDefKey(int defkey);
int FindKey(char *keyname, char *keydata);
int FindKeySubstr(char *keydatasubstr);
int AddKey(char *keyname, char *keydata);
int GetNumKeys(void);
char * GetKeyPtr(int num);
