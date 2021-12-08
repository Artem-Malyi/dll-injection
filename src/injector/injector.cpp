//
// injector.cpp
//

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <Psapi.h>
#include <Tlhelp32.h>
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
void testShellcodeInOtherProcess(PWSTR processName);

BOOL WINAPI EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    LOG("hInstance: 0x%p, dwReason: 0x%p, lpReserved: 0x%p", hinstDLL, fdwReason, lpReserved);

    __try {
        peutils::listTEBLoadedDlls();

        testShellcodeInLocalProcess();

        testShellcodeInOtherProcess(L"notepad.exe");
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

DWORD getPidByModuleName(PWSTR processName) {
    if (!processName && !processName[0])
        return -1;
    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    BOOL bProcess = Process32First(hTool32, &pe32);
    if (bProcess == TRUE) {
        while ((Process32Next(hTool32, &pe32)) == TRUE) {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                return pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hTool32);
    return -1;
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
    LOG("GetModuleHandleA(%s) returned 0x%p", pDllnameStr, pImageBaseAfter);

    assert(!pImageBaseBefore && pImageBaseAfter);

    if (pImageBaseAfter) {
        bRes = FreeLibrary(pImageBaseAfter);
        LOG("FreeLibrary(0x%p) returned %d", pImageBaseAfter, bRes);

        delete[] pMem;
    }
}

void testShellcodeInOtherProcess(PWSTR processName) {
    SetLastError(0);
    ULONG ulLastError = GetLastError();

    DWORD pid = getPidByModuleName(processName);
    LOG("getPidByModuleName(%S) returned %d", processName, pid);
    if (pid == -1)
        return;

    // Get process handle
    SetLastError(0);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LOG("OpenProcess(%d) returned 0x%08x", pid, hProcess);
    if (hProcess == INVALID_HANDLE_VALUE)
        return;

    // Allocate memory inside the process
    PSTR pDllnameStr = getFullDllName();
    size_t dllnameLen = strlen(pDllnameStr);
    LOG("Full path to dll is: %s", pDllnameStr);
    SetLastError(0);
    LPVOID pDllName = (LPVOID)VirtualAllocEx(hProcess, NULL, dllnameLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ulLastError = GetLastError();
    LOG("VirtualAllocEx(phandle: 0x%08x, size: %d) returned 0x%08x, GetLastError(): %d", hProcess, dllnameLen, pDllName, ulLastError);
    if (!pDllName)
        return;

    // Finding LoadLibraryAddr
    SetLastError(0);
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    LOG("GetProcAddress(LoadLibraryA) returned 0x%08x, GetLastError(): %d", pLoadLibrary, ulLastError);
    if (!pLoadLibrary)
        return;

    // Write to memory
    SetLastError(0);
    BOOL bRes = WriteProcessMemory(hProcess, pDllName, pDllnameStr, dllnameLen, NULL);
    ulLastError = GetLastError();
    LOG("WriteProcessMemory(phandle: 0x%08x) returned %d, GetLastError(): %d", hProcess, bRes, ulLastError);
    if (!bRes)
        return;

    // Create a thread inside virtual address space of the process
    SetLastError(0);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllName, NULL, NULL);
    ulLastError = GetLastError();
    LOG("CreateRemoteThread(phandle: 0x%08x) returned 0x%08x, GetLastError(): %d", hProcess, hThread, ulLastError);

    CloseHandle(hProcess);
}