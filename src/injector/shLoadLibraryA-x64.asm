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
        sub     rsp, 40                 ;// 40 bytes of shadow space: 32 for RCX, RDX, R8 and R9 registers, and 8 bytes
                                        ;// to align the stack from previous usage - the return RIP address pushed on the stack
        and     rsp, 0fffffffffffffff0h ;// Align the stack to a multiple of 16 bytes

        mov     rax, rsp                ;// 1. get the pointer to accessible memory in the stack, it will be referenced in step 3 below
        call    $+4                     ;// 2. e8 ff ff ff ff  [after this call RIP will point to the last ff byte in this instruction]
        db      030h                    ;// 3. ff 30 -> push qword ptr [rax]
        pop     rax                     ;// 4. retore stack pointer after previos instruction
        pop     rax                     ;// 5. pop the value that was pushed by call
        sub     rax, 16                 ;// 6. rax is now holding the pointer to the beginning of the shLoadLibraryA code

        mov     r15, rax
        mov     rcx, 0 - (getKernel32Base - shLoadLibraryA)
        neg     rcx
        add     rax, rcx
        call    rax                     ;// call getKernel32Base, after the call rax = pKernel32Base

        mov     r10, r15
        mov     rcx, 0 - (getProcAddressAsm - shLoadLibraryA)
        neg     rcx
        add     r10, rcx
        mov     rcx, rax                ;// rcx = pKernel32Base
        mov     rdx, 07203081c80f2041h  ;// rdx = hash of "LoadLibraryA" string, obtained by shl13 hashing approach
        call    r10                     ;// call getProcAddress, after the call rax = pLoadLibraryA

        mov     rcx, r15
        ;mov     rdx, 0 - (dllName - shLoadLibraryA)
        ;neg     rdx
        ;add     rcx, rdx                ;// pDllName
        lea     rcx, [dllName] 
        call    rax                     ;// call LoadLibraryA(dllName)

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


;    getProcAddress proc
;        int 3
;        mov     r10, rax                ;// Store the base address of the module that is being loaded from in ebp.
;        add     rax, [rax+03ch]         ;// Skip over the MSDOS header to the start of the PE header.
;        xor     r8, r8
;        mov     r8b, 088h
;        add     rax, r8
;        mov     edx, [rax]              ;// The export table is 0x78 bytes from the start of the PE header. Extract it and store the relative address in edx.
;        add     edx, ebp                ;// Make the export table address absolute by adding the base address to it.
;        mov     ecx, [edx+018h]         ;// Extract the number of exported items and store it in ecx which will be used as the counter.
;        mov     ebx, [edx+020h]         ;// Extract the names table relative offset and store it in ebx.
;        add     ebx, ebp                ;// Make the names table address absolute by adding the base address to it.
;      FindFunctionLoop:
;        jecxz   lFindFunctionFinished   ;// If rcx is zero then the last symbol has been checked and as such jump to
;                                        ;// the end of the function. If this condition is ever true then the requested symbol was not resolved properly.
;        dec     rcx
;        mov     esi, [ebx+ecx*4]        ;// Extract the relative offset of the name associated with the current symbol and store it in esi.
;        add     rsi, r10                ;// Make the address of the symbol name absolute by adding the base address to it.
;        ;// Compute hash
;        xor     edi, edi                ;// Zero edi as it will hold the hash value for the current symbols function name.
;        xor     eax, eax                ;// Zero eax in order to ensure that the high order bytes are zero as this will
;                                        ;// hold the value of each character as it walks through the symbol name.
;        cld                             ;// Clear the direction flag to ensure that it increments instead of decrements
;                                        ;// when using the lods* instructions. This instruction can be optimized out
;                                        ;// assuming that the environment being exploited is known to have the DF flag unset.
;      ComputeHashAgain:
;        lodsb                           ;// Load the byte at esi, the current symbol name, into al and increment esi.
;        test    al, al                  ;// Bitwise test al with itself to see if the end of the string has been reached.
;        jz      ComputeHashFinished     ;// If ZF is set the end of the string has been reached. Jump to the end of the hash calculation.
;        ror     edi, 0dh                ;// Rotate the current value of the hash 13 bits to the right.
;        add     edi, eax                ;// Add the current character of the symbol name to the hash accumulator.
;        jmp     ComputeHashAgain        ;// Continue looping through the symbol name.
;
;      ComputeHashFinished:
;        cmp     edi, [esp+4]            ;// Check to see if the computed hash matches the requested hash.
;        jnz     FindFunctionLoop        ;// If the hashes do not match, continue enumerating the exported symbol list.
;                                        ;// Otherwise, drop down and extract the VMA of the symbol.
;        mov     ebx, [edx+024h]         ;// Extract the ordinals table relative offset and store it in ebx.
;        add     rbx, r10                ;// Make the ordinals table address absolute by adding the base address to it.
;        mov     cx,  [ebx+2*ecx]        ;// Extract the current symbols ordinal number from the ordinal table. Ordinals are two bytes in size.
;        mov     ebx, [edx+01ch]         ;// Extract the address table relative offset and store it in ebx.
;        add     rbx, r10                ;// Make the address table address absolute by adding the base address to it.
;        mov     eax, [ebx+4*ecx]        ;// Extract the relative function offset from its ordinal and store it in eax.
;        add     rax, r10                ;// Make the function's address absolute by adding the base address to it.
;
;      lFindFunctionFinished:
;        ret
;    getProcAddress endp


    ; rcx - image base
    ; rdx - shl13 hash
    getProcAddressAsm proc
;PVOID getProcAddress(PVOID peImage, QWORD ror13NameHash) {
;        mov     qword ptr [rsp+8],rbx
;        mov     qword ptr [rsp+10h],rsi  
;        mov     qword ptr [rsp+18h],rdi  
;    PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)peImage;
;    PIMAGE_NT_HEADERS64 inh = (PIMAGE_NT_HEADERS64)((PBYTE)idh + idh->e_lfanew);
        movsxd  rax,dword ptr [rcx+3Ch] ; 00007FF7ABBD135F 48 63 41 3C 
;    PIMAGE_DATA_DIRECTORY idd = &inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
;    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)peImage + idd->VirtualAddress);
;    PDWORD namesTable = (PDWORD)((PBYTE)peImage + ied->AddressOfNames);
;    PDWORD funcsTable = (PDWORD)((PBYTE)peImage + ied->AddressOfFunctions);
;    for (DWORD i = 0; i < ied->NumberOfNames; i++) {
        xor     r11d,r11d               ; 00007FF7ABBD1363 45 33 DB  
        mov     rsi,rdx                 ; 00007FF7ABBD1366 48 8B F2 
        mov     r10,rcx                 ; 00007FF7ABBD1369 4C 8B D1 
        mov     r8d,dword ptr [rax+rcx+88h] ; 00007FF7ABBD136C 44 8B 84 08 88 00 00 00  
        mov     eax,dword ptr [r8+rcx+20h]  ; 00007FF7ABBD1374 41 8B 44 08 20   
        mov     edi,dword ptr [r8+rcx+18h]  ; 00007FF7ABBD1379 41 8B 7C 08 18   
        mov     ebx,dword ptr [r8+rcx+1Ch]  ; 00007FF7ABBD137E 41 8B 5C 08 1C   
        lea     r9,[rax+rcx]            ; 00007FF7ABBD1383 4C 8D 0C 08    
        test    edi,edi                 ; 00007FF7ABBD1387 85 FF         
        je      lHashNotFound           ;00007FF7ABBD1389 74 3B       
        sub     rbx,rax                 ; 00007FF7ABBD138B 48 2B D8 
;        PSTR name = (PSTR)((PBYTE)peImage + namesTable[i]);
;        PVOID func = (PVOID)((PBYTE)peImage + funcsTable[i]);
      lNextFunction:
        mov     r8d,dword ptr [r9+rbx]  ;00007FF7ABBD138E 45 8B 04 19   
;        QWORD hash = 0;
        xor     ecx,ecx                 ;00007FF7ABBD1392 33 C9      
        mov     edx,dword ptr [r9]      ;00007FF7ABBD1394 41 8B 11    
        add     r8,r10                  ;00007FF7ABBD1397 4D 03 C2     
        add     rdx,r10                 ;00007FF7ABBD139A 49 03 D2     
;        PSTR it = name;
;        while (it && *it) {
        je      lCompareHash            ;00007FF7ABBD139D 74 16     
      lNextChar:
        cmp     byte ptr [rdx],0        ;00007FF7ABBD139F 80 3A 00     
        je      lCompareHash            ;00007FF7ABBD13A2 74 11      
;            hash <<= 13;
;            hash += *it;
        movsx   rax,byte ptr [rdx]      ;00007FF7ABBD13A4 48 0F BE 02    
        shl     rcx,0Dh                 ;00007FF7ABBD13A8 48 C1 E1 0D    
        add     rcx,rax                 ;00007FF7ABBD13AC 48 03 C8     
;            ++it;
        add     rdx,1                   ;00007FF7ABBD13AF 48 83 C2 01   
        jne     lNextChar               ;00007FF7ABBD13B3 75 EA      
;        }
;        if (hash == ror13NameHash) {
      lCompareHash:
        cmp     rcx,rsi                 ; 00007FF7ABBD13B5 48 3B CE      
        je      lHashFound              ; 00007FF7ABBD13B8 74 1E         
;    PIMAGE_DATA_DIRECTORY idd = &inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
;    PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)peImage + idd->VirtualAddress);
;    PDWORD namesTable = (PDWORD)((PBYTE)peImage + ied->AddressOfNames);
;    PDWORD funcsTable = (PDWORD)((PBYTE)peImage + ied->AddressOfFunctions);
;    for (DWORD i = 0; i < ied->NumberOfNames; i++) {
        inc     r11d                    ; 00007FF7ABBD13BA 41 FF C3       
        add     r9,4                    ; 00007FF7ABBD13BD 49 83 C1 04    
        cmp     r11d,edi                ; 00007FF7ABBD13C1 44 3B DF     
        jb      lNextFunction           ; 00007FF7ABBD13C4 72 C8        
;        }
;    }
;    return NULL;
      lHashNotFound:
        xor     eax,eax                 ; 00007FF7ABBD13C6 33 C0        
;}
      lReturn:
;        mov     rbx,qword ptr [rsp+8]   ; 00007FF7ABBD13C8 48 8B 5C 24 08    
;        mov     rsi,qword ptr [rsp+10h] ; 00007FF7ABBD13CD 48 8B 74 24 10  
;        mov     rdi,qword ptr [rsp+18h] ; 00007FF7ABBD13D2 48 8B 7C 24 18   
        ret  ; 00007FF7ABBD13D7 C3    
;            //LOG("%s: 0x%p, hash: 0x%p", name, func, hash);
;            return func;
      lHashFound:
        mov     rax,r8                  ; 00007FF7ABBD13D8 49 8B C0     
        jmp     lReturn                 ; 00007FF7ABBD13DB EB EB        
;--- No source file -------------------------------------------------------------
    getProcAddressAsm endp


    dllName	    db 0                    ; "ws2_32.dll",0


    stringToRor13Hash proc              ; rcx - the pointer to the ascii string
        mov     rsi, rcx                ; ror13: 0xC6042601260A288D, rol13: 0x07203081c80f2041
        xor     rdi, rdi                ; Zero rdi as it will hold the hash value for the current symbols function name.
        xor     rax, rax                ; Zero rax in order to ensure that the high order bytes are zero as this will hold the resulting hash.
        cld
      lComputeHash:
        lodsb                           ; Load the byte at rsi, the current symbol name, into al and increment rsi.
        test    al, al                  ; Bitwise test al with itself to see if the end of the string has been reached.
        jz      lHashFinished           ; If ZF is set the end of the string has been reached. Jump to the end of the hash calculation.
        ror     rdi, 0dh                ; Rotate the current value of the hash 13 bits to the right.
        add     rdi, rax                ; Add the current character of the symbol name to the hash accumulator.
        jmp     lComputeHash            ; Continue looping through the symbol name.
      lHashFinished:
        mov		rax, rdi
        ret
    stringToRor13Hash endp


end