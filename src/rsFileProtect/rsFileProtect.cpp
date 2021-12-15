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

DWORD WINAPI ThreadProc(_In_ LPVOID lpParameter);

BOOL WINAPI EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    LOG("hInstance: 0x%0*x, dwReason: 0x%0*x, lpReserved: 0x%0*x", PTR_WIDTH, hinstDLL, PTR_WIDTH, fdwReason, PTR_WIDTH, lpReserved);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        LOG("Process attach");
        __try {
            //
            // The correct way to start a separate service thread from this dll would be to export the
            // dedicated function, and to call this function from the injecting process. This would allow
            // for a proper unloading of the dll when needed, without deadlocking the process of interest.
            // But for now, assuming that this dll will be loaded forever inside the process, the thread
            // is started from DllMain.
            //

            CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
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

DWORD WINAPI ThreadProc(_In_ LPVOID lpParameter) {
    while (TRUE) {
        LOG("Running service thread...");

        Sleep(5000);
    }

    return 0;
}