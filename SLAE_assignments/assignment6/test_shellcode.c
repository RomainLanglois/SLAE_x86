#include <stdio.h>
#include <string.h>

// the shellcode is stored here
unsigned char code[] = \
"Shellcode goes here";

int main()
{
	// print the length of the shellcode
	printf("Shellcode Length:  %d\n", strlen(code));

	// convert the shellcode variable to a function
	int (*ret)() = (int(*)())code;

	// execute the shellcode
	ret();

}