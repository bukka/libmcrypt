#include <stdlib.h>
#include <malloc.h>

#include <mcrypt_secret_common_inc.h>

#if !defined(word32)
#define word32 int
#endif

#undef WIN32DLL_DEFINE
#define WIN32DLL_DEFINE /* */

#undef IS_BLOCK_ALGORITHM
#define IS_BLOCK_ALGORITHM TRUE

#undef HAS_IV
#define HAS_IV FALSE

