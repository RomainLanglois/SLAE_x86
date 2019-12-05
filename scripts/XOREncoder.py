# Python XOR Encoder 

# TO DO: make it compatible with python3

shellcode = ("Shellcode goes here !")
encoded = ""

print 'Shellcode len: %d' % len(bytearray(shellcode))
print 'Encoded shellcode ...'

for x in bytearray(shellcode) :
	# XOR Encoding 	
	y = x^0xAA # <--- 0xAA: Byte used to encode the shellcode using XOR 
	encoded += '0x'
	encoded += '%02x,' % y

print encoded # <--- Print an encoded shellcode format usable by NASM


