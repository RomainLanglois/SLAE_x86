;A simple execve using the JUMP-CALL-POP technique
global _start

_start:
	;First part: JUMP
	jmp stage_1				;Jump to stage_1


stage_2:
	;Third part: POP
	pop esi				;Pop the "/bin/bash" string inside esi
	xor eax, eax				;Initialize eax to NULL
	mov BYTE [esi + 9], al		;Push a NULL byte on the stack
	mov DWORD [esi + 10], esi		;Push "/bin/bash on the stack"
	mov DWORD [esi + 14], eax		;Push a NULL byte on the stack

	lea ebx, [esi]			;Initiliaze ebx to "/bin/bash"
	lea ecx, [esi + 10]			;Initialize ecx to ["/bin/bash", NULL]
	lea edx, [esi + 14]			;Initialize edx to NULL
	mov al, 11				;Move execve systemcall number inside eax

	;Systemcall details:
    	; --> execve("/bin/bash%00", ["/bin/bash%00", NULL], NULL)
	int 0x80				;Execute systemcall


stage_1:
	;Second part: CALL
	call stage_2				;Use the CALL instruction to jump to stage_2
	shell: db "/bin/bash"		;The instruction to execute using execve
