/* All modules will contain these operations, and there's nothing specific
 * to a given module in any implementation.
 *
 * Not all functions apply to all modules. The convention is to give a
 * return code of -1 for an error condition, so that is what we use to
 * represent inapplicable functions.
 */

#include <stdint.h>

#if !defined(FALSE)
#define FALSE 0
#endif

#if !defined(TRUE)
#define TRUE 1
#endif

#if !defined(NOT_APPLICABLE)
#define NOT_APPLICABLE -1
#endif

#if !defined(MAXINT)
#define MAXINT -1
#endif

#define UNDEFINED MAXINT
#define NEXT_UNDEFINED MAXINT

/* At present, 32-bit integers are used to handle the code attributes. This
 * can be extended as far as necessary. Note that some listed atttributes
 * do not correspond with any existing code in libmcrypt. These are
 * extremely provisional and may well change. This part of the API is not
 * yet frozen and should be used with extreme caution.
 */

#define PUBLIC_KEY 00000001 
#define BLOCK_MODE 00000002
#define BLOCK_ALGO 00000004
#define AUTH_LAYER 00000008
#define ACCEL_ALGO 00000016

#define FIPS_COMPL 00000032
#define RSRVD_STD1 00000064
#define RSRVD_STD2 00000128
#define RSRVD_STD3 00000256
#define RSRVD_STD4 00000512

#define ANY_STNDRD 00000992

#define VLN_THEORY 00001024
#define VLN_THREAT 00002048
#define VLN_WIDOPN 00004096

#define KNOWN_BUGS 00007168

#define IP_PATENTS 00008192
#define IP_CPYRITE 00016384
#define IP_SUMOTHR 00032768 

#define IP_PROBLEM 00057344

/* Bits 0 - 15 defined above. Bits 16-32 are reserved for future use */

#if !defined(uint32)
#define uint32 unsigned int
#endif

typedef struct __mcryptlib_linklist
{
	uint32 id;
	uint32 desc;
	struct __mcryptlib_linklist *next;
	struct __mcryptlib_linklist *prev;
} _mcryptlib_linklist_node, *_mcryptlib_linklist_ptr;

static _mcryptlib_linklist_ptr _mcl_ptr;

static uint32 _mcryptlib_next_unused;

WIN32DLL_DEFINE _mcryptlib_linklist_ptr _new_node()
{
	_mcryptlib_linklist_ptr ptr;

	ptr = (_mcryptlib_linklist_ptr) malloc(sizeof(_mcryptlib_linklist_node));
	ptr->id = 0;
	ptr->desc = 0;
	ptr->next = NULL;
	ptr->prev = NULL;
	return(ptr);
}

WIN32DLL_DEFINE _new_list()
{
	_mcl_ptr = _new_node();
	_mcryptlib_next_unused = 0;
}

WIN32DLL_DEFINE _register_description(uint32 *id, uint32 desc)
{
	_mcryptlib_linklist_ptr temp = _mcl_ptr;
	_mcryptlib_linklist_ptr prev;

	if (*id == NEXT_UNDEFINED)
	{
		*id = _mcryptlib_next_unused;
	}

	while ((temp != NULL) && (temp->id != *id))
	{
		prev = temp;
		temp = temp->next;
	}

	if (temp == NULL)
	{
		temp = _new_node();
		temp->prev = prev;
		prev->next = temp;
	}
	temp->id = *id;
	temp->desc = desc;
}

WIN32DLL_DEFINE uint32 _generic_query(uint32 query) 
{
	_mcryptlib_linklist_ptr temp = _mcl_ptr;

	while ((temp != NULL) && (temp->id != query))
	{
		temp = temp->next;

	}
	if (temp == NULL)
	{
		return(UNDEFINED);
	}
	else
	{
		return(temp->desc);
	}
}

#if !defined(IS_PUBLIC_KEY_ALGORITHM)
#define IS_PUBLIC_KEY_ALGORITHM 0
#endif

#if !defined(IS_BLOCK_ALGORITHM_MODE)
#define IS_BLOCK_ALGORITHM_MODE 0
#endif

#if !defined(IS_AUTHENTICATION_MECHANISM)
#define IS_AUTHENTICATION_MECHANISM 0
#endif

#if !defined(ENCUMBRANCE)
#define ENCUMBRANCE 0
#endif

#if !defined(IS_ACCELERATED)
#define IS_ACCELERATED 0
#endif

#if !defined(IS_BLOCK_MODE)
#define IS_BLOCK_MODE 0
#endif

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

