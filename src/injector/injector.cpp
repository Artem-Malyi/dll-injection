//
// injector.cpp
//

#include <Windows.h>

#ifdef _WIN64
    #define LOG_PREFIX "injector64"
#else
    #define LOG_PREFIX "injector32"
#endif
#define DEBUG_LOGGER_ENABLED
#define FILE_LOGGER_ENABLED
#include "logger.h"

void testDll();

BOOL WINAPI EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    LOG("hInstance: 0x%0*x, dwReason: 0x%0*x, lpReserved: 0x%0*x", PTR_WIDTH, hinstDLL, PTR_WIDTH, fdwReason, PTR_WIDTH, lpReserved);

    //
    // Place your code here.
    //
    testDll();

    UINT uiStatus = ERROR_SUCCESS;
    LOG("Calling ExitProcess(%d)...", uiStatus);
    ExitProcess(uiStatus);

    return ERROR_SUCCESS;
}

void testDll() {
    #ifdef _WIN64
        #ifdef _DEBUG
            #define DLL_NAME L"rsFileProtect64d.dll"
        #else
            #define DLL_NAME L"rsFileProtect64.dll"
        #endif
    #else
        #ifdef _DEBUG
            #define DLL_NAME L"rsFileProtect32d.dll"
        #else
            #define DLL_NAME L"rsFileProtect32.dll"
        #endif
    #endif

    LoadLibrary(DLL_NAME);
    Sleep(2000);
}