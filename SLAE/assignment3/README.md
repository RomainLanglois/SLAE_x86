# SLAE course
The course can be found here:
[Link to course](https://www.pentesteracademy.com/course?id=3)

## Assignment#3: What to do ?
This assignment is divided in 3 steps:
* Define and explain an egg hunter
* Create a working demo of an egg hunter
* Make the egg hunter easily configurable for different payloads

Now, let's get to work.
=

## Step 1: Define and explain an egg hunter
The Egg hunting technique is used when there are not enough available consecutive memory locations to insert the shellcode.  Instead, a unique “tag” is prefixed with shellcode. 

When the “Egg hunter” shellcode is executed, it searches for the unique “tag” that was prefixed with the large payload and starts the execution of the payload. 

In classic stack based buffer overflow, the buffer size is big enough to hold the shellcode. But, what will happen if there is not enough consecutive memory space available for the shellcode to fit in after overwrite happens.

In general the egg hunter code needs to follow three rules:
1) It must be robust
    * This requirement is used to express the fact that the egg hunter must be capable of searching through memory regions that are invalid and would otherwise crash the application if they were to be dereferenced improperly. It must also be capable of searching for the egg anywhere in memory.
2) It must be small
    * The size is a principal requirement for the egg hunters as they must be able to go where no other payload would be able to fit when used in conjunction with an exploit. The smaller the better.
3) It should be fast
    * In order to avoid sitting idly for minutes while the egg hunter does its task, the methods used to search VAS should be as quick as possible, without violating the first requirement or second requirements without proper justification.

An amazing PDF from "hick.org" describes the whole process and how to use it:
[Link to PDF](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

## Step 2: create a working demo of an egg hunter
The egg hunter code is divided in four major parts:
1) The first step initialize the registers to NULL. 

2) The next step is to perform a page alignment operation on the current pointer that is being validated by doing a bitwise OR operation on the low 16-bits of the current pointer (stored in edx) and then incrementing edx by one. This operation is equivalent to adding 0x1000 to the value in edx. The reason these two operations are separated is to avoid nullbytes inside the shellcode.

3) The third step is to use a systemcall 'access' which will take an address as a parameter and check for us if the memory address is valid. If not the systemcall will return '0xf2' telling us the given address is invalid and then loop until the result returns a valid address.

4) The last step is to check two times the presence of the egg. Because, if we don't do this check a second time the egg hunter code will jump on the wrong memory address and then execute an invalid code.

The egg hunter shellcode:
```nasm
insert egg hunter assembly code here
```

The C code used to test our egg hunter shellcode:
```c
```

Let's compile it and execute it:
```console
```

## Step 3: make the egg hunter easily configurable for different payloads
The following C code can be used to configure different payloads and load them in memory using the egg hunter shellcode.
```c
Insert C code here
```

Let's compile the code and execute it:
```console
insert compile commands here
```

## Bonus:
During my work, I found another way to create an egg hunter using far less code.
Here is a different version of the previous code:
```nasm
insert new version egg hunter assembly code
```

Here is the C code used to test the previous assembly code:
```c
insert C code used to test the previous assembly code
```

Let's compile it and execute it:
```console
insert bash commands
```