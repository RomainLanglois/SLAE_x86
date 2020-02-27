#include <stdio.h>
#include <string.h>

// egg_hunter.nasm shellcode is stored here
unsigned char egg_hunter[] = \
"INSERT EGG HUNTER HERE";

unsigned char shellcode[] = \
"FIRST EGG"
"SECOND EGG"
"INSERT PAYLOAD TO EXECUTE HERE";

int main()
{
	// print the length of the shellcodes
	printf("Egg hunter shellcode length:  %d\n", strlen(egg_hunter));
	printf("Shellcode length:  %d\n", strlen(shellcode));

	// convert shellcode to a function
	int (*ret)() = (int(*)())egg_hunter;

	// execute the shellcode
	ret();

}
