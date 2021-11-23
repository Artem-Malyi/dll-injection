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
        ;pushad
        ;mov     eax, esp                ;// 1. get the pointer to accessible memory, it will be referenced in step 3 below
        ;call    $+4                     ;// 2. e8 ff ff ff ff  [after this call eip will point to the last ff byte in this instruction]
        ;db      030h                    ;// 3. ff 30 -> push dword ptr [eax]
        ;pop     eax                     ;// 4. retore stack pointer after previos instruction
        ;pop     eax                     ;// 5. pop the value that was pushed by call
        ;sub     eax, 8                  ;// 6. eax is now holds a pointer the the beginning of code loadLibraryA

        ;mov     ebx, eax
        ;mov     ecx, 0 - (getKernel32Base - shLoadLibraryA)
        ;neg     ecx
        ;add     eax, ecx
        ;call    eax                     ;// call getKernel32Base, after the call eax = pKernel32Base

        ;mov     edx, ebx
        ;mov     ecx, 0 - (getProcAddress - shLoadLibraryA)
        ;neg     ecx
        ;add     edx, ecx
        ;mov     esi, 0EC0E4E8Eh         ;// "LoadLibraryA", obtained by ROR13 hashing approach
        ;call    edx                     ;// getProcAddress(eax - pKernel32Base, esi - hash of "LoadLibraryA" string)

        ;mov     edx, ebx
        ;mov     ecx, 0 - (dllName - shLoadLibraryA)
        ;neg     ecx
        ;add     edx, ecx
        ;push    edx                     ;// pDllName
        ;call    eax                     ;// call LoadLibraryA(dllName)

        ;popad
        ret
    shLoadLibraryA endp

    dllName	    db 0                    ;//"ws2_32.dll",0

end