/* All modules will contain these operations, and there's nothing specific
 * to a given module in any implementation.
 *
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

WIN32DLL_DEFINE _is_block_mode()
{
	return IS_BLOCK_MODE;
}

WIN32DLL_DEFINE _is_block_algorithm_mode()
{
	return IS_BLOCK_ALGORITHM_MODE;
}

WIN32DLL_DEFINE _has_iv()
{
	return HAS_IV;
}

WIN32DLL_DEFINE _is_block_algorithm()
{
	return IS_BLOCK_ALGORITHM;
}

WIN32DLL_DEFINE _is_block_algorithm_mode()
{
	return IS_BLOCK_ALGORITHM_MODE;
}

WIN32DLL_DEFINE _is_public_key_algorithm()
{
	return IS_PUBLIC_KEY_ALGORITHM;
}

WIN32DLL_DEFINE _is_authentication_mechanism()
{
	return IS_AUTHENTICATION_MECHANISM;
}

WIN32DLL_DEFINE _is_encumbered()
{
	return ENCUMBRANCE;
}

WIN32DLL_DEFINE _is_accelerated()
{
	return IS_ACCELERATED;
}

