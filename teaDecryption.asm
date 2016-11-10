        push    ebp
        mov     ebp, esp
        sub     esp, 16
        mov     eax, DWORD   [ebp+8]
        movzx   eax, BYTE   [eax]
        mov     BYTE   [ebp-1], al
        mov     eax, DWORD   [ebp+8]
        movzx   eax, BYTE   [eax+1]
        mov     BYTE   [ebp-2], al
        mov     BYTE   [ebp-3], 32
        mov     BYTE   [ebp-5], -71
        mov     eax, DWORD   [ebp+12]
        movzx   eax, BYTE   [eax]
        mov     BYTE   [ebp-6], al
        mov     eax, DWORD   [ebp+12]
        movzx   eax, BYTE   [eax+1]
        mov     BYTE   [ebp-7], al
        mov     eax, DWORD   [ebp+12]
        movzx   eax, BYTE   [eax+2]
        mov     BYTE   [ebp-8], al
        mov     eax, DWORD   [ebp+12]
        movzx   eax, BYTE   [eax+3]
        mov     BYTE   [ebp-9], al
        mov     BYTE   [ebp-4], 0
        jmp     L5
L6:
        movzx   eax, BYTE   [ebp-1]
        sal     eax, 4
        mov     edx, eax
        movzx   eax, BYTE   [ebp-8]
        add     eax, edx
        mov     ecx, eax
        movzx   edx, BYTE   [ebp-1]
        movzx   eax, BYTE   [ebp-3]
        add     eax, edx
        xor     ecx, eax
        movzx   eax, BYTE   [ebp-1]
        shr     al, 5
        mov     edx, eax
        movzx   eax, BYTE   [ebp-9]
        add     eax, edx
        xor     eax, ecx
        sub     BYTE   [ebp-2], al
        movzx   eax, BYTE   [ebp-2]
        sal     eax, 4
        mov     edx, eax
        movzx   eax, BYTE   [ebp-6]
        add     eax, edx
        mov     ecx, eax
        movzx   edx, BYTE   [ebp-2]
        movzx   eax, BYTE   [ebp-3]
        add     eax, edx
        xor     ecx, eax
        movzx   eax, BYTE   [ebp-2]
        shr     al, 5
        mov     edx, eax
        movzx   eax, BYTE   [ebp-7]
        add     eax, edx
        xor     eax, ecx
        sub     BYTE   [ebp-1], al
        movzx   eax, BYTE   [ebp-5]
        sub     BYTE   [ebp-3], al
        movzx   eax, BYTE   [ebp-4]
        add     eax, 1
        mov     BYTE   [ebp-4], al
L5:
        cmp     BYTE   [ebp-4], 31
        jbe     L6
        mov     eax, DWORD   [ebp+8]
        movzx   edx, BYTE   [ebp-1]
        mov     BYTE   [eax], dl
        mov     eax, DWORD   [ebp+8]
        lea     edx, [eax+1]
        movzx   eax, BYTE   [ebp-2]
        mov     BYTE   [edx], al
        leave
        ret 