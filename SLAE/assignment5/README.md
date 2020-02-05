# SLAE course
This course can be found here:
[Link to course](https://www.pentesteracademy.com/course?id=3)

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
#msfvenom -p linux/x86/exec CMD=id -f elf -o exec 
``` 
We will use IDA to understand how the assembly of this shellcode works:

![ida_exec](https://github.com/RomainLanglois/Shellcode/blob/master/SLAE/assignment5/IDA_exec.png)

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
#msfvenom -p linux/x86/shell_reverse_tcp -f elf -o reverse_shell 
``` 

We will use IDA to understand how the assembly of this shellcode works:

![ida_reverse_shell](https://github.com/RomainLanglois/Shellcode/blob/master/SLAE/assignment5/IDA_reverse_shell.png)

Based on the above code, we can divide this code in four parts: 
1) The first part will explain the first call to "socketcall".
2) The second part will give more details on the "dup2" syscall. 
3) The third part will explain the second call to "socketcall" 
4) Finally, the last part will detailled how the "execve" syscall is used. 

### The first systemcall:
Based on the IDA results, the first systemcall is a "socketcall". 

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

The parameters of this syscall can be found below:
* dup2(3,2)
* dup2(3,1)
* dup2(3,0)
     * "3" is the socket file descriptor.
     * "0", "1", "2" represents respectively STDIN, STDOUT and STDERR. 

### The third systemcall:
Based on the IDA results, the third systemcall is a "socketcall". 

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

The parameters of this syscall can be found below:
* execve("/bin/sh%00", ["/bin/sh%00", NULL], NULL)

## 3) Third shellcode: a TCP bind shell
### Reverse the the code using IDA
The last shellcode, I decided to analyse, is a tcp bind shell. This shellcode can be generated using msfvenom:
```console
#msfvenom -p linux/x86/linux/x86/shell_bind_tcp -f elf -o bind_shell 
```

We will use IDA to understand how the assembly of this shellcode works: