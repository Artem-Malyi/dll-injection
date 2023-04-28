//
// peutils.cpp
//
// Utility functions that work with Portable Executable images and Windows Loader.
//

#include <Windows.h>
#include <winternl.h> // for PEB/TEB structures

#ifdef _WIN64
#define LOG_PREFIX "peutils64"
#else
#define LOG_PREFIX "peutils32"
#endif
#define DEBUG_LOGGER_ENABLED
#define FILE_LOGGER_ENABLED
#include <logger.h>

namespace peutils {

    void listTEBLoadedDlls() {
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
            P_LDR_DATA_TABLE_ENTRY_VISTA pModuleEntry = reinterpret_cast<P_LDR_DATA_TABLE_ENTRY_VISTA>(it);
            PVOID base = pModuleEntry->DllBase;
            if (!pModuleEntry->FullDllName.Length)
                break;
            LOG("Loaded module: %S, image base: 0x%p", pModuleEntry->FullDllName.Buffer, pModuleEntry->DllBase);
            it = it->Flink;
        }
    }

}