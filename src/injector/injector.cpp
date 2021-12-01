//
// injector.cpp
//

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <cassert>

#ifdef _WIN64
    #define LOG_PREFIX "injector64"
#else
    #define LOG_PREFIX "injector32"
#endif
#define DEBUG_LOGGER_ENABLED
#define FILE_LOGGER_ENABLED
#include <logger.h>

#include <peutils.h>

typedef unsigned __int64 QWORD;

// forward declarations
#if _WIN64
    extern "C" void __fastcall shLoadLibraryA(void);
#else
    extern "C" void __stdcall shLoadLibraryA(void);
#endif

void testShellcodeInLocalProcess();

BOOL WINAPI EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    LOG("hInstance: 0x%p, dwReason: 0x%p, lpReserved: 0x%p", hinstDLL, fdwReason, lpReserved);

    __try {
        peutils::listTEBLoadedDlls();

        testShellcodeInLocalProcess();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("SEH exception occurred");
    }

    UINT uiStatus = ERROR_SUCCESS;
    LOG("Calling ExitProcess(%d)...", uiStatus);
    ExitProcess(uiStatus);

    return ERROR_SUCCESS;
}

PSTR getFullDllName() {
    #ifdef _WIN64
        #ifdef _DEBUG
            #define DLL_NAME "rsFileProtect64d.dll"
        #else
            #define DLL_NAME "rsFileProtect64.dll"
        #endif
    #else
        #ifdef _DEBUG
            #define DLL_NAME "rsFileProtect32d.dll"
        #else
            #define DLL_NAME "rsFileProtect32.dll"
        #endif
    #endif

    CHAR filePath[MAX_PATH] = { 0 };
    DWORD dwRes = GetModuleFileNameA(NULL, filePath, sizeof(filePath));
    if (!dwRes)
        return NULL;

    BOOL bRes = PathRemoveFileSpecA(filePath);
    if (!bRes)
        return NULL;

    static CHAR fullDllName[MAX_PATH] = { 0 };
    int res = wnsprintfA(fullDllName, sizeof(fullDllName), "%s\\%s", filePath, DLL_NAME);
    if (res < 0)
        return NULL;

    return fullDllName;
}

void testShellcodeInLocalProcess() {
    PSTR pShellcodeStr = reinterpret_cast<char*>(shLoadLibraryA);
    size_t shellcodeLen = strlen(pShellcodeStr);
    LOG("Shellcode string length is: %d", shellcodeLen);

    PSTR pDllnameStr = getFullDllName();
    size_t dllnameLen = strlen(pDllnameStr);
    LOG("Full path to dll is: %s", pDllnameStr);

    HMODULE pImageBaseBefore = GetModuleHandleA(pDllnameStr);

    size_t memLen = shellcodeLen + dllnameLen + 1;
    PSTR pMem = new char[memLen];
    memset(pMem, 0, memLen);
    if (!pMem)
        return;

    // for the following to work the shellcode must be null-free!
    strncpy(pMem, pShellcodeStr, shellcodeLen);
    strncpy(pMem + shellcodeLen, pDllnameStr, dllnameLen);
    size_t fullLen = strlen(pMem);
    LOG("Payload full length is: %d", fullLen);

    DWORD dwOldPermissions = 0;
    BOOL bRes = VirtualProtect(pMem, memLen, PAGE_EXECUTE_READWRITE, &dwOldPermissions);
    LOG("VirtualProtect(PAGE_EXECUTE_READWRITE) returned: %d", bRes);

    typedef void(__stdcall* shellcode_t)();
    shellcode_t pShellcode = reinterpret_cast<shellcode_t>(pMem);

    LOG("Calling LoadLibrary(%s) shellcode", pDllnameStr);
    pShellcode();

    Sleep(2000);
    LOG("Returned from LoadLibrary() call");

    HMODULE pImageBaseAfter = GetModuleHandleA(pDllnameStr);

    assert(!pImageBaseBefore && pImageBaseAfter);

    bRes = FreeLibrary(pImageBaseAfter);
    LOG("FreeLibrary(0x%p) returned %d", pImageBaseAfter, bRes);

    delete[] pMem;
}
