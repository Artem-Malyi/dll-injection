//
// rsFileProtect.cpp
//

#include <Windows.h>

#ifdef _WIN64
    #define LOG_PREFIX "rsFileProtect64"
#else
    #define LOG_PREFIX "rsFileProtect32"
#endif
#define DEBUG_LOGGER_ENABLED
#define FILE_LOGGER_ENABLED
#include "logger.h"

BOOL WINAPI EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    LOG("hInstance: 0x%0*x, dwReason: 0x%0*x, lpReserved: 0x%0*x", PTR_WIDTH, hinstDLL, PTR_WIDTH, fdwReason, PTR_WIDTH, lpReserved);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        LOG("Process attach");
        __try {
            //
            // Place your code here.
            //
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG("SEH exception occurred");
        }
        break;
    }
    case DLL_THREAD_ATTACH: {
        LOG("Thread attach");
        break;
    }
    case DLL_THREAD_DETACH: {
        LOG("Thread detach");
        break;
    }
    case DLL_PROCESS_DETACH:
        LOG("Process detach");
        break;
    }
    return TRUE;
}