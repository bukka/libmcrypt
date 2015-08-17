#ifndef MCRYPT_MODULES_H
#define MCRYPT_MODULES_H

/* always inlining */
#if defined(__GNUC__) && __GNUC__ >= 3
#define mcrypt_always_inline inline __attribute__((always_inline))
#else
#define mcrypt_always_inline inline
#endif

#define mcrypt_rotl32(x,n) \
	(((x) << ((word32)(n))) | ((x) >> (32 - (word32)(n))))
#define mcrypt_rotr32(x,n) \
	(((x) >> ((word32)(n))) | ((x) << (32 - (word32)(n))))
#define mcrypt_rotl16(x,n) \
	(((x) << ((word16)(n))) | ((x) >> (16 - (word16)(n))))
#define mcrypt_rotr16(x,n) \
	(((x) >> ((word16)(n))) | ((x) << (16 - (word16)(n))))

/* Use hardware rotations.. when available */
#ifdef swap32
# define mcrypt_byteswap32(x) swap32(x)
#else
# ifdef swap_32
#  define mcrypt_byteswap32(x) swap_32(x)
# else
#  ifdef bswap_32
#   define mcrypt_byteswap32(x) bswap_32(x)
#  else
#   define mcrypt_byteswap32(x) \
	((mcrypt_rotl32(x, 8) & 0x00ff00ff) | \
	 (mcrypt_rotr32(x, 8) & 0xff00ff00))
#  endif
# endif
#endif

#ifdef swap16
# define mcrypt_byteswap16(x) swap16(x)
#else
# ifdef swap_16
#  define mcrypt_byteswap16(x) swap_16(x)
# else
#  ifdef bswap_16
#   define mcrypt_byteswap16(x) bswap_16(x)
#  else
#   define mcrypt_byteswap16(x)	\
	((mcrypt_rotl16(x, 8) & 0x00ff) | (mcrypt_rotr16(x, 8) & 0xff00))
#  endif
# endif
#endif

#define mcrypt_bzero(x, y) memset(x, 0, y)

mcrypt_always_inline static void memxor(
	unsigned char *o1, unsigned char *o2, int length)
{
	int i;

	for (i = 0; i < length; i++) {
		o1[i] ^= o2[i];
	}
}

/* MODULE STRUCTURES DEFINITIONS */

/* Pre-definitions */
typedef struct _mcrypt_module mcrypt_module;
typedef struct _mcrypt_module_sk_mode mcrypt_module_sk_mode;

/**
 * @brief Module type
 */
typedef enum _mcrypt_module_type {
	MCRYPT_MODULE_SK_MODE = 1
} mcrypt_module_type;

/* Module Secret Key Mode */

/**
 * Initialize secret key mode hook
 * @param module module handle
 * @param key block key
 * @param key_len key length
 * @param iv initial vector
 * @param iv_len initial vector length
 */
typedef size_t (*mcrypt_module_sk_mode_init_t) (
	mcrypt_module *module,
	void *key, size_t key_len,
	void *iv, size_t iv_len);

/**
 * @brief Secret key mode structure
 */
struct _mcrypt_module_sk_mode {
	/** action hooks */
	struct {
		/** initializing */
		mcrypt_module_sk_mode_init_t init;
	} hooks;
};

/**
 * @brief Main module structure
 */
struct _mcrypt_module {
	/** module type */
	mcrypt_module_type type;
	/** mcrypt internal module */
	void *mim;
	/** type specific data */
	union {
		/** secret key mode data */
		mcrypt_module_sk_mode mode;
	} module;
};

#endif /* MCRYPT_MODULES_H */
