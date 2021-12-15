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

// forward declarations
#if _WIN64
    extern "C" void __fastcall shLoadLibraryA(void);
#else
    extern "C" void __stdcall shLoadLibraryA(void);
#endif

PCSTR getDllPath();
void testShellcodeInLocalProcess(PCSTR dllPath);
void injectDllIntoProcess(PCSTR dllPath, PCSTR processName);
void injectDllIntoProcessBeatAslr(PCSTR dllPath, PCSTR processName);

BOOL WINAPI EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    LOG("hInstance: 0x%p, dwReason: 0x%p, lpReserved: 0x%p", hinstDLL, fdwReason, lpReserved);

    __try {
        //peutils::listTEBLoadedDlls();

        //testShellcodeInLocalProcess(getDllPath());

        //injectDllIntoProcess(getDllPath(), "notepad.exe");

        injectDllIntoProcessBeatAslr(getDllPath(), "notepad.exe");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("SEH exception occurred");
    }

    UINT uiStatus = ERROR_SUCCESS;
    LOG("Calling ExitProcess(%d)...", uiStatus);
    ExitProcess(uiStatus);

    return ERROR_SUCCESS;
}

PCSTR getDllPath() {
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
    int res = wnsprintfA(fullDllName, _countof(fullDllName), "%s\\%s", filePath, DLL_NAME);
    if (res < 0)
        return NULL;

    return fullDllName;
}

DWORD getPidByModuleName(PCSTR processName) {
    if (!processName && !processName[0])
        return -1;
    WCHAR procName[MAX_PATH] = { 0 };
    wnsprintfW(procName, _countof(procName), L"%S", processName);
    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    BOOL bProcess = Process32First(hTool32, &pe32);
    if (bProcess == TRUE) {
        while ((Process32Next(hTool32, &pe32)) == TRUE) {
            if (wcscmp(pe32.szExeFile, procName) == 0) {
                return pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hTool32);
    return -1;
}

//
// testShellcodeInLocalProcess
//     Appends the given dllPath to the end of the LoadLibraryA shellcode,
//     places it on the memory heap, and executes it from there.
//     Asserts that this dll is in the list of loaded libraries, and unloads
//     it, if it's loaded.
//     Assumes that the shellcode is null-free.
//
// Parameters:
//     dllPath - the full path to the DLL image on the file system.
//
void testShellcodeInLocalProcess(PCSTR dllPath) {
    PSTR pShellcodeStr = reinterpret_cast<char*>(shLoadLibraryA);
    size_t shellcodeLen = strlen(pShellcodeStr);
    LOG("Shellcode string length is: %d", shellcodeLen);

    size_t dllPathLen = strlen(dllPath);
    LOG("Full path to dll is: %s", dllPath);

    HMODULE pImageBaseBefore = GetModuleHandleA(dllPath);

    size_t memLen = shellcodeLen + dllPathLen + 1;
    PSTR pMem = new char[memLen];
    memset(pMem, 0, memLen);
    if (!pMem)
        return;

    // For the following to work the shellcode must be null-free!
    strncpy(pMem, pShellcodeStr, shellcodeLen);
    strncpy(pMem + shellcodeLen, dllPath, dllPathLen);
    size_t fullLen = strlen(pMem);
    LOG("Payload full length is: %d", fullLen);

    DWORD dwOldPermissions = 0;
    BOOL bRes = VirtualProtectEx(GetCurrentProcess(), pMem, memLen, PAGE_EXECUTE_READWRITE, &dwOldPermissions);
    LOG("VirtualProtectEx(PAGE_EXECUTE_READWRITE) returned: %d", bRes);

    typedef void(__stdcall* shellcode_t)();
    shellcode_t pShellcode = reinterpret_cast<shellcode_t>(pMem);

    LOG("Calling LoadLibrary(%s) shellcode", dllPath);
    pShellcode();

    Sleep(2000);
    LOG("Returned from LoadLibrary() call");

    HMODULE pImageBaseAfter = GetModuleHandleA(dllPath);
    LOG("GetModuleHandleA(%s) returned 0x%p", dllPath, pImageBaseAfter);

    assert(!pImageBaseBefore && pImageBaseAfter);

    if (pImageBaseAfter) {
        bRes = FreeLibrary(pImageBaseAfter);
        LOG("FreeLibrary(0x%p) returned %d", pImageBaseAfter, bRes);

        delete[] pMem;
    }
}

//
// injectDllIntoProcess
//     Performs the OpenProcess/VirtualAllocEx/GetProcAddress(LoadLibrary)/WriteProcessMemory/CreateRemoteThread
//     injection approach.
//     Relies on the fact that all the processes of the same address pointer size, will actually have kernel32.dll
//     being loaded to the same location in memory, as all other processes from the same user login session.
//     In this case, the address of LoadLibraryA function in current process will be exactly the same as in,
//     for instance, notepad.exe .
//
// Parameters:
//     dllPath - the full path to the DLL image on the file system.
//     processName - the name of the process to inject DLL into.
//
void injectDllIntoProcess(PCSTR dllPath, PCSTR processName) {
    SetLastError(0);
    ULONG ulLastError = GetLastError();

    DWORD pid = getPidByModuleName(processName);
    LOG("getPidByModuleName(%s) returned %d", processName, pid);
    if (pid == -1)
        return;

    // Get process handle
    SetLastError(0);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LOG("OpenProcess(%d) returned 0x%08x", pid, hProcess);
    if (hProcess == INVALID_HANDLE_VALUE)
        return;

    // Allocate memory inside the process
    size_t dllPathLen = strlen(dllPath);
    LOG("Full path to dll is: %s", dllPath);
    SetLastError(0);
    LPVOID pDllName = (LPVOID)VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ulLastError = GetLastError();
    LOG("VirtualAllocEx(phandle: 0x%08x, size: %d) returned 0x%08x, GetLastError(): %d", hProcess, dllPathLen, pDllName, ulLastError);
    if (!pDllName)
        return;

    // Finding LoadLibraryA address
    SetLastError(0);
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    LOG("GetProcAddress(LoadLibraryA) returned 0x%08x, GetLastError(): %d", pLoadLibrary, ulLastError);
    if (!pLoadLibrary)
        return;

    // Write to memory
    SetLastError(0);
    BOOL bRes = WriteProcessMemory(hProcess, pDllName, dllPath, dllPathLen, NULL);
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

//
// injectDllIntoProcessBeatAslr
//     Performs the OpenProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread injection approach.
//     Appends the given dllPath to the end of the LoadLibraryA shellcode, writes it to the virtual memory
//     of the given process, and creates a remote execution thread there, starting from the base address
//     of this memory region.
//     Assumes that the shellcode is null-free.
//
// Parameters:
//     dllPath - the full path to the DLL image on the file system.
//     processName - the name of the process to inject DLL into.
//
void injectDllIntoProcessBeatAslr(PCSTR dllPath, PCSTR processName) {
    SetLastError(0);
    ULONG ulLastError = GetLastError();

    // Prepare shellcode by appending the dllPath to it
    PSTR pShellcodeStr = reinterpret_cast<char*>(shLoadLibraryA);
    size_t shellcodeLen = strlen(pShellcodeStr);
    LOG("Shellcode string length is: %d", shellcodeLen);

    size_t dllPathLen = strlen(dllPath);
    LOG("Full path to dll is: %s", dllPath);

    HMODULE pImageBaseBefore = GetModuleHandleA(dllPath);

    size_t memLen = shellcodeLen + dllPathLen + 1;
    PSTR pMem = new char[memLen];
    memset(pMem, 0, memLen);
    if (!pMem)
        return;

    // For the following to work the shellcode must be null-free!
    strncpy(pMem, pShellcodeStr, shellcodeLen);
    strncpy(pMem + shellcodeLen, dllPath, dllPathLen);
    LOG("Shellcode full length is: %d", strlen(pMem));

    // Get the process id by the given process name
    DWORD pid = getPidByModuleName(processName);
    LOG("getPidByModuleName(%s) returned %d", processName, pid);
    if (pid == -1) {
        delete[] pMem;
        return;
    }

    // Get process handle
    SetLastError(0);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LOG("OpenProcess(%d) returned 0x%08x", pid, hProcess);
    if (hProcess == INVALID_HANDLE_VALUE) {
        delete[] pMem;
        return;
    }

    SetLastError(0);
    LPVOID pBuffer = (LPVOID)VirtualAllocEx(hProcess, NULL, memLen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ulLastError = GetLastError();
    LOG("VirtualAllocEx(phandle: 0x%08x, size: %d) returned 0x%08x, GetLastError(): %d", hProcess, memLen, pBuffer, ulLastError);
    if (!pBuffer) {
        delete[] pMem;
        return;
    }

    // Write to memory
    SetLastError(0);
    BOOL bRes = WriteProcessMemory(hProcess, pBuffer, pMem, memLen, NULL);
    ulLastError = GetLastError();
    LOG("WriteProcessMemory(phandle: 0x%08x) returned %d, GetLastError(): %d", hProcess, bRes, ulLastError);
    if (!bRes) {
        delete[] pMem;
        return;
    }

    // Create a thread inside virtual address space of the process
    SetLastError(0);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pBuffer, NULL, NULL, NULL);
    ulLastError = GetLastError();
    LOG("CreateRemoteThread(phandle: 0x%08x) returned 0x%08x, GetLastError(): %d", hProcess, hThread, ulLastError);

    CloseHandle(hProcess);

    delete[] pMem;
}
