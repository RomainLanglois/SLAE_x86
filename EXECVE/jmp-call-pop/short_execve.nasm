;execve('/bin/bash', NULL, NULL)

global _start

_start:
	jmp stage_1


stage_2:
	pop ebx
	xor eax, eax
	mov al, 11
	
	int 0x80


stage_1:
	call stage_2
	shell: db "/bin/bash"
	;Could have been -> shell: db "/bin/sh" 
