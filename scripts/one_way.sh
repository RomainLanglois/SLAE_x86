#!/bin/bash

# Check for a nasm file parameter
if [ $# -eq 0 ]
  then
    echo "Please supply a nasm file"
    echo "Usage:"
    echo "./one_way.sh <file>"
    exit
fi

# Compile the nasm file
echo "[!] Compiling NASM file..."
nasm -f elf32 -o $1.o $1.nasm
ld -m elf_i386 -z execstack -o $1 $1.o
echo "[+] Done !"

echo ""
 
# Generating shellcode from the nasm file
echo "[!] Getting shellcode..."
objdump -d ./$1 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' > /tmp/result.txt
shellcode=`cat /tmp/result.txt`
rm /tmp/result.txt
echo "[+] Done !"

echo ""

# Modifying C code
echo '[!] Adding shellcode to test_shellcode.c'
sed "s/INSERT_SHELLCODE/$shellcode/" test_shellcode.c > shellcode.c
echo "[+] Done !"

echo ""

# Compiling shellcode.c file
echo '[!] Compiling shellcode.c file'
gcc shellcode.c -o shellcode -m32 -fno-stack-protector -z execstack
echo "[+] Done !"

