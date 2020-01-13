#!/usr/bin/python3
# Python XOR Encoder 

shellcode = b"shellcode goes here"
encoded = ""

print('Shellcode len: {}'.format(len(shellcode)))
print('Encoded shellcode ...')

for x in bytearray(shellcode):
	# XOR Encoding 	
	y = x^0xAA # <--- 0xAA: Byte used to encode the shellcode using XOR (Can be replaced by any logical operand)
	encoded += '0x'
	encoded += '%02x,' % y

print(encoded) # <--- Print an encoded shellcode format usable by NASM


