#if !defined(MCRYPT_COMMON_INITIALIZE)
#define MCRYPT_COMMON_INITIALIZE

/*
 * Not all functions apply to all modules. The convention is to give a
 * return code of -1 for an error condition, so that is what we use to
 * represent inapplicable functions.
 */

#if !defined(FALSE)
#define FALSE 0
#endif

#if !defined(TRUE)
#define TRUE 1
#endif

#if !defined(NOT_APPLICABLE)
#define NOT_APPLICABLE -1
#endif

#define IS_BLOCK_MODE NOT_APPLICABLE
#define IS_BLOCK_ALGORITHM_MODE NOT_APPLICABLE
#define HAS_IV NOT_APPLICABLE
#define IS_BLOCK_ALGORITHM NOT_APPLICABLE
#define IS_PUBLIC_KEY_ALGORITHM NOT_APPLICABLE
#define IS_AUTHENTICATION_MECHANISM NOT_APPLICABLE

#endif

