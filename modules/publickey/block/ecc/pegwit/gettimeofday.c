#ifdef WIN32
#include <windows.h>

// temporary workaround :-/

DWORD gettimeofday(void)
{
    return GetTickCount();
}


#endif
