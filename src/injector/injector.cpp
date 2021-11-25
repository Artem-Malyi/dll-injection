//
// injector.cpp
//

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

#ifdef _WIN64
    #define LOG_PREFIX "injector64"
#else
    #define LOG_PREFIX "injector32"
#endif
#define DEBUG_LOGGER_ENABLED
#define FILE_LOGGER_ENABLED
#include "logger.h"

typedef unsigned __int64 QWORD;

// forward declarations
#if _WIN64
    extern "C" void __fastcall shLoadLibraryA(void);
    extern "C" QWORD __fastcall stringToRor13Hash(PSTR);
    extern "C" PVOID __fastcall getProcAddressAsm(PVOID peImage, QWORD shl13NameHash);
    PVOID getProcAddress(PVOID peImage, QWORD shl13NameHash);
#else
    extern "C" void __stdcall shLoadLibraryA(void);
    extern "C" DWORD __stdcall stringToRor13Hash(PSTR);
#endif

void testShellcodeInLocalProcess();
void accessPebLdr();


BOOL WINAPI EntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    LOG("hInstance: 0x%p, dwReason: 0x%p, lpReserved: 0x%p", hinstDLL, fdwReason, lpReserved);

    __try {
        accessPebLdr();

        //testShellcodeInLocalProcess();
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
    shellcode_t pShellcode = (shellcode_t)pMem;

    LOG("Calling LoadLibrary(%s) shellcode", pDllnameStr);
    pShellcode();

    Sleep(2000);

    LOG("Returned from LoadLibrary() call");

    //delete[] pMem;
}

void accessPebLdr() {
    // Thread Environment Block (TEB)
#if defined(_M_X64) // x64
    PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
    PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

    // This structure was obtained by pdbdump.exe util from the leaked Windows Vista ntdll.pdb with private debugging symbols:
    // c:\symcache\ntdll.pdb\B958B2F91A5A46B889DAFAB4D140CF252\ntdll.pdb

    typedef struct __LDR_DATA_TABLE_ENTRY_VISTA {
        /*<thisrel this+0x00>*/ /*|0x8|*/ struct _LIST_ENTRY InLoadOrderLinks;
        /*<thisrel this+0x08>*/ /*|0x8|*/ struct _LIST_ENTRY InMemoryOrderLinks;
        /*<thisrel this+0x10>*/ /*|0x4|*/ void* DllBase;
        /*<thisrel this+0x14>*/ /*|0x4|*/ void* EntryPoint;
        /*<thisrel this+0x18>*/ /*|0x4|*/ unsigned long SizeOfImage;
        /*<thisrel this+0x1c>*/ /*|0x8|*/ struct _LIST_ENTRY InInitializationOrderLinks;
        /*<thisrel this+0x24>*/ /*|0x8|*/ struct _UNICODE_STRING FullDllName;
        /*<thisrel this+0x2c>*/ /*|0x8|*/ struct _UNICODE_STRING BaseDllName;
        /*<thisrel this+0x34>*/ /*|0x4|*/ unsigned long Flags;
        /*<thisrel this+0x38>*/ /*|0x2|*/ unsigned short LoadCount;
        /*<thisrel this+0x3a>*/ /*|0x2|*/ unsigned short TlsIndex;
        /*<thisrel this+0x3c>*/ /*|0x8|*/ struct _LIST_ENTRY HashLinks;
        /*<thisrel this+0x3c>*/ /*|0x4|*/ void* SectionPointer;
        /*<thisrel this+0x40>*/ /*|0x4|*/ unsigned long CheckSum;
        /*<thisrel this+0x44>*/ /*|0x4|*/ unsigned long TimeDateStamp;
        /*<thisrel this+0x44>*/ /*|0x4|*/ void* LoadedImports;
        /*<thisrel this+0x48>*/ /*|0x4|*/ void* EntryPointActivationContext;
        /*<thisrel this+0x4c>*/ /*|0x4|*/ void* PatchInformation;
    } _LDR_DATA_TABLE_ENTRY_VISTA, * P_LDR_DATA_TABLE_ENTRY_VISTA;
    // <size 0x50>

    // Process Environment Block (PEB)
    PPEB pebPtr = (PPEB)tebPtr->ProcessEnvironmentBlock;
    PLIST_ENTRY it = pebPtr->Ldr->InMemoryOrderModuleList.Flink;
    while (it) {
        P_LDR_DATA_TABLE_ENTRY_VISTA pModuleEntry = (P_LDR_DATA_TABLE_ENTRY_VISTA)it;
        PVOID base = pModuleEntry->DllBase;
        if (!pModuleEntry->FullDllName.Length)
            break;
        LOG("Loaded module: %S, image base: 0x%p", pModuleEntry->FullDllName.Buffer, pModuleEntry->DllBase);
        it = it->Flink;
    }

#ifdef _WIN64
    PVOID pKernel32Base = ((P_LDR_DATA_TABLE_ENTRY_VISTA)pebPtr->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink)->DllBase;
    PVOID pLoadLibrary = getProcAddress(pKernel32Base, 0x07203081c80f2041); // 0x07203081c80f2041 for LoadLibraryA
    LOG("LoadLibrary: 0x%p, expected: 0x%p", pLoadLibrary, GetProcAddress((HMODULE)pKernel32Base, "LoadLibraryA"));
#endif
}

#ifdef _WIN64
#pragma optimize ("gs", on)
PVOID getProcAddress(PVOID peImage, QWORD ror13NameHash) {
    PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)peImage;
    PIMAGE_NT_HEADERS64 inh = (PIMAGE_NT_HEADERS64)((PBYTE)idh + idh->e_lfanew);
    PIMAGE_DATA_DIRECTORY idd = &inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)peImage + idd->VirtualAddress);
    PDWORD namesTable = (PDWORD)((PBYTE)peImage + ied->AddressOfNames);
    PDWORD funcsTable = (PDWORD)((PBYTE)peImage + ied->AddressOfFunctions);
    for (DWORD i = 0; i < ied->NumberOfNames; i++) {
        PSTR name = (PSTR)((PBYTE)peImage + namesTable[i]);
        PVOID func = (PVOID)((PBYTE)peImage + funcsTable[i]);
        QWORD hash = 0;
        PSTR it = name;
        while (it && *it) {
            hash <<= 13;
            hash += *it;
            ++it;
        }
        if (hash == ror13NameHash) {
            //LOG("%s: 0x%p, hash: 0x%p", name, func, hash);
            return func;
        }
    }
    return NULL;
}
#endif