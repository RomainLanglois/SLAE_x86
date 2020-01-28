#include <stdio.h>
#include <string.h>

// decoder.nasm shellcode is stored here
unsigned char shellcode[] = \
INSERT_SHELLCODE;

int main()
{
	// print the length of the shellcode
	printf("Shellcode Length:  %d\n", strlen(shellcode));
	// convert shellcode to a function
	int (*ret)() = (int(*)())shellcode;
	// execute the shellcode has a function
	ret();
}


