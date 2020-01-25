#!/usr/bin/python3
# Python XOR Encoder 

shellcode = b"shellcode goes here"
encoded_shellcode = ""

print('Shellcode len: {}'.format(len(shellcode)))
print('Encoded shellcode ...')

for x in bytearray(shellcode):
	# XOR Encoding using 0xAA byte
	y = x ^ 0xAA
	encoded_shellcode += '{},'.format(hex(y))

# Print the encoded shellcode
print(encoded_shellcode)


