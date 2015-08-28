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
	MCRYPT_MODULE_SK_BLOCK = 1,
	MCRYPT_MODULE_SK_MODE,
} mcrypt_module_type;


/* Block */

/**
 * Init block context
 * @param module module handle
 * @param key block key
 * @param key_len key length
 * @return 0 on success, otherwise negative value
 */
typedef int (*mcrypt_module_sk_block_init_t) (
	mcrypt_module *module,
	void *key, size_t key_len);

/**
 * Destroy block context
 * @param module module handle
 * @return 0 on success, otherwise negative value
 */
typedef int (*mcrypt_module_sk_block_destroy_t) (
	mcrypt_module *module);

/**
 * Set block key
 * @param module module handle
 * @param key block key
 * @param key_len key length
 * @return 0 on success, otherwise negative value
 */
typedef int (*mcrypt_module_sk_block_set_key_t) (
	mcrypt_module *module,
	void *key, size_t key_len);

/**
 * Set block key
 * @param module module handle
 * @param len number of keys in the returned array
 * @return array of sizes
 */
typedef size_t *(*mcrypt_module_sk_block_get_supported_key_sizes_t) (
	mcrypt_module *module, size_t *len);

/**
 * Encrypt block
 * @param module module handle
 * @param key key (has to be excactly key size long)
 * @param pt plain text (has to be excactly block size long)
 */
typedef size_t (*mcrypt_module_sk_block_encrypt_t) (
	mcrypt_module *module,
	void *key, void *pt);

/**
 * Decrypt block
 * @param module module handle
 * @param key key (has to be excactly key size long)
 * @param ct cipher text (has to be excactly block size long)
 */
typedef size_t (*mcrypt_module_sk_block_encrypt_t) (
	mcrypt_module *module,
	void *key, void *ct);

/**
 * @brief secret key block structure
 */
struct _mcrypt_module_sk_block {
	/** block size */
	short int block_size;
	/** key size */
	short int key_size;
	/** action hooks */
	struct {
		/** initializing */
		mcrypt_module_sk_block_init_t init;
		/** destroying */
		mcrypt_module_sk_block_destroy_t destroy;
		/** set key */
		mcrypt_module_sk_block_set_key_t set_key;
		/** get supported key sizes */
		mcrypt_module_sk_block_get_supported_key_sizes_t
		get_supported_key_sizes;
		/** encrypt */
		mcrypt_module_sk_block_encrypt_t encrypt;
		/** decrypt */
		mcrypt_module_sk_block_decrypt_t decrypt;
	} hooks;
};


/* Mode */

#define MCRYPT_MODULE_F_IV        1
#define MCRYPT_MODULE_F_BLOCK     2
#define MCRYPT_MODULE_F_BLOCK_ALG 4

/* Module Secret Key Mode */

/**
 * Initialize secret key mode hook
 * @param module module handle
 * @param key block key
 * @param key_len key length
 * @param iv initial vector
 * @param iv_len initial vector length
 */
typedef int (*mcrypt_module_sk_mode_init_t) (
	mcrypt_module *module,
	void *key, size_t key_len,
	void *iv, size_t iv_len);

/**
 * Destroy secret key mode hook
 * @param module module handle
 */
typedef void (*mcrypt_module_sk_mode_destroy_t) (mcrypt_module *module);

/**
 * Set mode state (IV)
 * @param module module handle
 * @param iv initial vector
 * @param iv_len initial vector length
 */
typedef size_t (*mcrypt_module_sk_mode_set_state_t) (
	mcrypt_module *module,
	void *iv, size_t iv_len);

/**
 * Get mode state (IV)
 * @param module module handle
 * @param iv initial vector (output parameter)
 * @param iv_len initial vector length (output parameter)
 */
typedef size_t (*mcrypt_module_sk_mode_get_state_t) (
	mcrypt_module *module,
	void *iv, size_t *iv_len);

/**
 * Encrypt
 * @param module module handle
 * @param key encryption key
 * @param key_len length of the key
 * @param pt plain text
 * @param pt_len plain text length
 * @param func callback for block cipher
 */
typedef size_t (*mcrypt_module_sk_mode_encrypt_t) (
	mcrypt_module *module,
	void *key, size_t key_len,
	void *pt, size_t pt_len,
	mcrypt_module_sk_block_encrypt_t func
);

/**
 * Decrypt
 * @param module module handle
 * @param key encryption key
 * @param key_len length of the key
 * @param ct cipher text
 * @param ct_len cipher text length
 * @param func callback for block cipher
 */
typedef size_t (*mcrypt_module_sk_mode_decrypt_t) (
	mcrypt_module *module,
	void *key, size_t key_len,
	void *ct, size_t ct_len,
	mcrypt_module_sk_block_decrypt_t func
);

/**
 * @brief Secret key mode structure
 */
struct _mcrypt_module_sk_mode {
	/** action hooks */
	struct {
		/** initializing */
		mcrypt_module_sk_mode_init_t init;
		/** destroying */
		mcrypt_module_sk_mode_destroy_t destroy;
		/** set state */
		mcrypt_module_sk_mode_set_state_t set_state;
		/** get state */
		mcrypt_module_sk_mode_set_state_t get_state;
		/** encrypt */
		mcrypt_module_sk_mode_encrypt_t encrypt;
		/** decrypt */
		mcrypt_module_sk_mode_decrypt_t decrypt;
	} hooks;
};

/**
 * @brief Main module structure
 */
struct _mcrypt_module {
	/** module type */
	mcrypt_module_type type;
	/** module flags */
	unsigned flags;
	/** module name */
	const char *name;
	/** module version */
	unsigned version;
	/** mcrypt internal module context */
	void *context;
	/** type specific data */
	union {
		/** secret key block data */
		mcrypt_module_sk_block block;
		/** secret key mode data */
		mcrypt_module_sk_mode mode;
	} module;
};

#endif /* MCRYPT_MODULES_H */
