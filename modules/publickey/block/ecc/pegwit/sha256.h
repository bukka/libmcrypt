#define HW 8

typedef struct {
	unsigned long state[8], length, curlen;
	unsigned char buf[64];
} sha_state;


void sha_init(sha_state *md);
void sha_process(sha_state *md, unsigned char *buf, int len);
void sha_done(sha_state *md, unsigned char *hash);
void sha_memory(unsigned char *buf, int len, unsigned char *hash);
int  sha_file(unsigned char *filename, unsigned char *hash);


/* old stuff */
#define hash_context sha_state
#define hash_initial sha_init
#define hash_process sha_process
#define hash_final(s,h) sha_done(s,(unsigned char *)(h))
