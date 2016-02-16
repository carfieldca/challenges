global _start

_start:
        xor eax,eax
        push eax
        push dword 0x20727625
        push dword 0x78247227
        push dword 0x73757473
        push dword 0x23782770
        push dword 0x71762475
        push dword 0x79207974
        push dword 0x27747079
        push dword 0x23257179
        push dword 0x79257272
        push dword 0x76247171
        push dword 0x70237577
        push dword 0x79702474
        push dword 0x74207327
        push dword 0x70737872
        push dword 0x24702720
        push dword 0x73237274
        push dword 0x20277277
        push dword 0x78722720
        push dword 0x77247324
        push dword 0x77222725
        push dword 0x24722479
        push dword 0x76277875
        push dword 0x75257271
        push dword 0x70207725
        push dword 0x24722779
        push dword 0x27727620
        push dword 0x24707377
        push dword 0x72252075
        push dword 0x75252077
        push dword 0x72722775
        push dword 0x23792720
        push dword 0x77702024
        push esp
        pop esi
        mov edi,esi
        mov edx,edi
        cld
        mov ecx,0x80
        mov ebx,0x41
        xor eax,eax
        push eax
jmplabel:
        lodsb
        xor eax,ebx
        stosb
        loop jmplabel
        push esp
        pop esi
        int3
