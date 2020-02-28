# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-1523

## Assignment#5: What to do ?
For this assignment we have to:
* Take up to three shellcodes examples created by Msfvenom
* Use a disassembler like GDB/Ndisasm/Libemu to reverse them
* Present the analysis 

Now, let's get to work.
=

## 1) First shellcode: a simple exec shellcode
### Reverse the the code using IDA
The first shellcode, I decided to analyse, is a simple exec shellcode. This shellcode can be generated using msfvenom:
```console
kali@kali:/tmp$ msfvenom -p linux/x86/shell_reverse_tcp -f elf -o reverse_shell 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of elf file: 152 bytes
Saved as: reverse_shell 
``` 
We will use IDA to understand how the assembly of this shellcode works:

![ida_exec](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_exec.png)

Based on the above code, this shellcode only use one systemcall. This shellcode main goal is to execute a system command using the "execve" syscall. So I'm going to describe with more details how the parameters are passed to this syscall.

1) First, the shellcode initialize eax to 0xB which is the syscall number for execve.
2) Second, it will push on the stack the string "-c%00" and move it inside edi.
3) Third, the string "/bin/sh%00" will also be pushed on the stack and ebx will be initialized to the stack pointer esp.
4) Fourth, the shellcode will use the call instruction to jump to next the instruction, but most important, will push the pointer which point to "id%00" into the stack. This is the parameter passed to execve in order to be executed.
5) Fifth, the code will then push edi ("-c%00"), ebx ("/bin/sh%00") into the stack and initialize the ecx register to the stack pointer esp.
6) Finally, we can deducted the following "execve" systemcall:
     * execve("/bin/sh%00", ["/bin/sh%00", "-c%00", "id%00"], NULL)

## 2) Second shellcode: a tcp reverse shell
### Reverse the the code using IDA 
The second shellcode, I decided to analyse, is a tcp reverse shell. This shellcode can be generated using msfvenom:
```console
kali@kali:/tmp$ msfvenom -p linux/x86/shell_reverse_tcp -f elf -o reverse_shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of elf file: 152 bytes
Saved as: reverse_shell
``` 

We will use IDA to understand how the assembly of this shellcode works:

![ida_reverse_shell](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_reverse_shell/IDA_reverse_shell.png)

Based on the above code, we can divide this code in four parts: 
1) The first part will explain the first call to "socketcall".
2) The second part will give more details on the "dup2" syscall. 
3) The third part will explain the second call to "socketcall" 
4) Finally, the last part will detailled how the "execve" syscall is used. 

### The first systemcall:
Based on the IDA results, the first systemcall is a "socketcall". 

![ida_reverse_shell_S1](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_reverse_shell/IDA_reverse_shell_S1.png)

The parameters of this syscall can be found below:
* socketcall(1, 0xffffd6b4)

As we can see this syscall is passed "1" as a first argument and a pointer to different values as the second parameter. Which means, based on the manual page of "socketcall", that this function is calling the "socket" function. Why ?
* "1" is the number which represents the "socket" function.
* "0xffffd6b4" is the pointer which point to the variables used by "socket".

Here is the real function call behind "socketcall" and all of its parameters:
* socket(2,1,0)
     * "2" means AF_INET: IPv4.
     * "1" means SOCK_STREAM: TCP.
     * "0" means NULL.

### The second systemcall:
Based on the IDA results, the second systemcall is a "dup2". "dup2" is called three times thanks to a loop. Those syscalls redirect the STDIN, STDOUT and STDERR into the socket. 

![ida_reverse_shell_S2](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_reverse_shell/IDA_reverse_shell_S2.png)

The parameters of this syscall can be found below:
* dup2(3,2)
* dup2(3,1)
* dup2(3,0)
     * "3" is the socket file descriptor.
     * "0", "1", "2" represents respectively STDIN, STDOUT and STDERR. 

### The third systemcall:
Based on the IDA results, the third systemcall is a "socketcall". 

![ida_reverse_shell_S3](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_reverse_shell/IDA_reverse_shell_S3.png)

The parameters of this syscall can be found below:
* socketcall(3, 0xffffd6a4)

As we can see this syscall is passed "3" as a first argument and a pointer to different values as the second parameter. Which means, based on the manual page of "socketcall", that this function is calling the "connect" function. Why ?
* "3" is the value which represents the "connect" function.
* "0xffffd6b4" is the pointer which hold all the variables used by "connect".

Here is the real function call behind "socketcall" and all of its parameters:
* connect(3, 0xffffd6b0, 0x66)
     * "3" is the socket file descriptor.
     * "0xffffd6b0" is pointer to a structure which holds:
          * The ip address: 127.0.0.1.
          * The port number: 4444.
          * The transport protocol used: TCP.
     * "0x66" is the structure size.

### The fourth systemcall:
Based on the IDA results, the fourth systemcall is a "execve". This syscall is reponsible from spawning a shell. This function takes two parameters "/bin/sh%00" and two NULL bytes. 

![ida_reverse_shell_S4](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_reverse_shell/IDA_reverse_shell_S4.png)

The parameters of this syscall can be found below:
* execve("/bin/sh%00", ["/bin/sh%00", NULL], NULL)

## 3) Third shellcode: a TCP bind shell
### Reverse the the code using IDA
The last shellcode, I decided to analyse, is a tcp bind shell. This shellcode can be generated using msfvenom:
```console
kali@kali:/tmp$ msfvenom -p linux/x86/shell_bind_tcp -f elf -o bind_shell 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 78 bytes
Final size of elf file: 162 bytes
Saved as: bind_shell
```

We will use IDA to understand how the assembly of this shellcode works:

![ida_bind_shell](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_bind_shell/IDA_bind_shell.png)

Based on the above code, we can divide this code in six parts: 
1) The first part will explain the first call to "socketcall".
2) The second part will explain the second call to "socketcall". 
3) The third part will explain the third call to "socketcall" 
4) The fourth part will explain the fourth call "socketcall"
5) The fifth part will give more details on the "dup2" syscall. 
6) Finally, the last part will detailled how the "execve" syscall is used. 

### The first systemcall:
Based on the IDA results, the first systemcall is a "socketcall".

![ida_bind_shell_S1](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_bind_shell/IDA_bind_shell_S1.png)

The parameters of this syscall can be found below:
* socketcall(1, 0xffffd1c4)

As we can see this syscall is passed "1" as a first argument and a pointer to different values as the second parameter. Which means, based on the manual page of "socketcall", that this function is calling the "socket" function. Why ?
* "1" is the number which represents the "socket" function.
* "0xffffd1c4" is the pointer which point to the variables used by "socket".

Here is the real function call behind "socketcall" and all of its parameters:
* socket(2,1,0)
     * "2" means AF_INET: IPv4.
     * "1" means SOCK_STREAM: TCP.
     * "0" means NULL.

### The second systemcall:
Based on the IDA results, the second systemcall is a "socketcall". 

![ida_bind_shell_S2](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_bind_shell/IDA_bind_shell_S2.png)

The parameters of this syscall can be found below:
* socketcall(2, 0xffffd1b8)

As we can see this syscall is passed "2" as a first argument and a pointer to different values as the second parameter. Which means, based on the manual page of "socketcall", that this function is calling the "bind" function. Why ?
* "2" is the value which represents the "bind" function.
* "0xffffd1b8" is the pointer which hold all the variables used by "bind".

Here is the real function call behind "socketcall" and all of its parameters:
* bind(3, 0xffffd1c4, 0x10)
     * "3" is the socket file descriptor.
     * "0xffffd1c4" is pointer to a structure which holds:
          * The port number: 4444.
          * The transport protocol used: TCP.
     * "0x10" is the structure size.

### The third systemcall:
Based on the IDA results, the third systemcall is a "socketcall". 

![ida_bind_shell_S3](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_bind_shell/IDA_bind_shell_S3.png)

The parameters of this syscall can be found below:
* socketcall(4, 0xffffd1b8)

As we can see this syscall is passed "4" as a first argument and a pointer to different values as the second parameter. Which means, based on the manual page of "socketcall", that this function is calling the "listen" function. Why ?
* "4" is the value which represents the "listen" function.
* "0xffffd1b8" is the pointer which hold all the variables used by "bind".

Here is the real function call behind "socketcall" and all of its parameters:
* listen(3)
     * "3" is the socket file descriptor.

### The fourth systemcall:
Based on the IDA results, the fourth systemcall is a "socketcall". 

![ida_bind_shell_S4](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_bind_shell/IDA_bind_shell_S4.png)

The parameters of this syscall can be found below:
* socketcall(5, 0xffffd1b8)

As we can see this syscall is passed "5" as a first argument and a pointer to different values as the second parameter. Which means, based on the manual page of "socketcall", that this function is calling the "accept" function. Why ?
* "5" is the value which represents the "accept" function.
* "0xffffd1b8" is the pointer which hold all the variables used by "bind".

Here is the real function call behind "socketcall" and all of its parameters:
* accept(3, 0xffffd1c4, 0x10)
     * "3" is the socket file descriptor.
     * "0xffffd1c4" is pointer to a structure which holds:
          * The port number: 4444.
          * The transport protocol used: TCP.
     * "0x10" is the structure size.

### The fifth systemcall:
Based on the IDA results, the second systemcall is a "dup2". "dup2" is called three times thanks to a loop. Those syscalls redirect the STDIN, STDOUT and STDERR into the socket. 

![ida_bind_shell_S5](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_bind_shell/IDA_bind_shell_S5.png)

The parameters of this syscall can be found below:
* dup2(3,2)
* dup2(3,1)
* dup2(3,0)
     * "3" is the socket file descriptor.
     * "0", "1", "2" represents respectively STDIN, STDOUT and STDERR.

### The last systemcall:
Based on the IDA results, the fourth systemcall is a "execve". This syscall is reponsible from spawning a shell. This function takes two parameters "/bin/sh%00" and two NULL bytes. 

![ida_bind_shell_S6](https://github.com/RomainLanglois/SLAE_x86/blob/master/SLAE_assignments/assignment5/IDA_bind_shell/IDA_bind_shell_S6.png)

The parameters of this syscall can be found below:
* execve("/bin/sh%00", ["/bin/sh%00", NULL], NULL)