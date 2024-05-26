/*
 * NEWDES-2 by Alexander Pukall 2006
 * 
 * 15552-bit keys with 1944 * 8-bit subkeys
 * 
 * Based on NEWDES by Robert Scott
 * 
 * 128-bit block cipher (like AES) 64 rounds
 * 
 * Uses MD2II hash function to create the 1944 subkeys
 * 
 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain 
 * 
 * Compile with gcc: gcc newdes2.c -o newdes2
 * 
 */

#include <stdio.h>
#include <string.h>

#define n1 1944 /* 15552-bit NEWDES2 key for 1944 * 8-bit subkeys */

int x1,x2,i;
unsigned char h2[n1];
unsigned char h1[n1*3];


static void init()
{
    
   x1 = 0;
   x2 = 0;
    for (i = 0; i < n1; i++)
        h2[i] = 0;
    for (i = 0; i < n1; i++)
        h1[i] = 0;
}

static void hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13, 199,  11,  67, 237, 193, 164,  77, 115, 184, 141, 222,  73,
        38, 147,  36, 150,  87,  21, 104,  12,  61, 156, 101, 111, 145,
       119,  22, 207,  35, 198,  37, 171, 167,  80,  30, 219,  28, 213,
       121,  86,  29, 214, 242,   6,   4,  89, 162, 110, 175,  19, 157,
         3,  88, 234,  94, 144, 118, 159, 239, 100,  17, 182, 173, 238,
        68,  16,  79, 132,  54, 163,  52,   9,  58,  57,  55, 229, 192,
       170, 226,  56, 231, 187, 158,  70, 224, 233, 245,  26,  47,  32,
        44, 247,   8, 251,  20, 197, 185, 109, 153, 204, 218,  93, 178,
       212, 137,  84, 174,  24, 120, 130, 149,  72, 180, 181, 208, 255,
       189, 152,  18, 143, 176,  60, 249,  27, 227, 128, 139, 243, 253,
        59, 123, 172, 108, 211,  96, 138,  10, 215,  42, 225,  40,  81,
        65,  90,  25,  98, 126, 154,  64, 124, 116, 122,   5,   1, 168,
        83, 190, 131, 191, 244, 240, 235, 177, 155, 228, 125,  66,  43,
       201, 248, 220, 129, 188, 230,  62,  75,  71,  78,  34,  31, 216,
       254, 136,  91, 114, 106,  46, 217, 196,  92, 151, 209, 133,  51,
       236,  33, 252, 127, 179,  69,   7, 183, 105, 146,  97,  39,  15,
       205, 112, 200, 166, 223,  45,  48, 246, 186,  41, 148, 140, 107,
        76,  85,  95, 194, 142,  50,  49, 134,  23, 135, 169, 221, 210,
       203,  63, 165,  82, 161, 202,  53,  14, 206, 232, 103, 102, 195,
       117, 250,  99,   0,  74, 160, 241,   2, 113};
       
    int b1,b2,b3,b4,b5;
   
	b4=0;
    while (b6) {
    
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];

            x1 = h2[x2] ^= s4[b5 ^ x1];
        }

        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
           }
          }
        }

static void end(unsigned char h4[n1])
{
    
    unsigned char h3[n1];
    int i, n4;
    
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}



unsigned char b0,b1,b2,b3,b4,b5,b6,b7;
unsigned char b8,b9,b10,b11,b12,b13,b14,b15;

    static char f[256] = {
32,137,239,188,102,125,221,72,212,68,81,37,86,237,147,149,
70,229,17,124,115,207,33,20,122,143,25,215,51,183,138,142,
146,211,110,173,1,228,189,14,103,78,162,36,253,167,116,255,
158,45,185,50,98,168,250,235,54,141,195,247,240,63,148,2,
224,169,214,180,62,22,117,108,19,172,161,159,160,47,43,171,
194,175,178,56,196,112,23,220,89,21,164,130,157,8,85,251,
216,44,94,179,226,38,90,119,40,202,34,206,35,69,231,246,
29,109,74,71,176,6,60,145,65,13,77,151,12,127,95,199,
57,101,5,232,150,210,129,24,181,10,121,187,48,193,139,252,
219,64,88,233,96,128,80,53,191,144,218,11,106,132,155,104,
91,136,31,42,243,66,126,135,30,26,87,186,182,154,242,123,
82,166,208,39,152,190,113,205,114,105,225,84,73,163,99,111,
204,61,200,217,170,15,198,28,192,254,134,234,222,7,236,248,
201,41,177,156,92,131,67,249,245,184,203,9,241,0,27,46,
133,174,75,18,93,209,100,120,76,213,16,83,4,107,140,52,
58,55,3,244,97,197,238,227,118,49,79,230,223,165,153,59};
    

void encrypt(unsigned char h4[n1])
{
int i;

i=0;

for(int y=0;y<64;y++){
       
      b4 = b4 ^ f[b0 ^ h4[i++]];
      b5 = b5 ^ f[b1 ^ h4[i++]];
      b6 = b6 ^ f[b2 ^ h4[i++]];
      b7 = b7 ^ f[b3 ^ h4[i++]];
      
      b12 = b12 ^ f[b8 ^ h4[i++]];
      b13 = b13 ^ f[b9 ^ h4[i++]];
      b14 = b14 ^ f[b10 ^ h4[i++]];
      b15 = b15 ^ f[b11 ^ h4[i++]];
      
      b4 = b4 ^ f[b12 ^ h4[i++]];
      b5 = b5 ^ f[b13 ^ h4[i++]];
      b6 = b6 ^ f[b14 ^ h4[i++]];
      b7 = b7 ^ f[b15 ^ h4[i++]];
    
      b12 = b12 ^ f[b4 ^ h4[i++]];
      b13 = b13 ^ f[b5 ^ h4[i++]];
      b14 = b14 ^ f[b6 ^ h4[i++]];
      b15 = b15 ^ f[b7 ^ h4[i++]];
      
      b1 = b1 ^ f[b4 ^ h4[i++]];
      b2 = b2 ^ f[b4 ^ b5];
      b3 = b3 ^ f[b6 ^ h4[i++]];
      b0 = b0 ^ f[b7 ^ h4[i++]];
      
      b9  = b9 ^ f[b12 ^ h4[i++]];
      b10 = b10 ^ f[b12 ^ b13];
      b11 = b11 ^ f[b14 ^ h4[i++]];
      b8 =  b8 ^ f[b15 ^ h4[i++]]; 
      
      b1 = b1 ^ f[b9 ^ h4[i++]];
      b2 = b2 ^ f[b10 ^ h4[i++]];
      b3 = b3 ^ f[b11 ^ h4[i++]];
      b0 = b0 ^ f[b8 ^ h4[i++]];
      
      b9  = b9 ^ f[b1 ^ h4[i++]];
      b10 = b10 ^ f[b2 ^ h4[i++]];
      b11 = b11 ^ f[b3 ^ h4[i++]];
      b8 =  b8 ^ f[b0 ^ h4[i++]]; 
   
   }
      b4 = b4 ^ f[b0 ^ h4[i++]];
      b5 = b5 ^ f[b1 ^ h4[i++]];
      b6 = b6 ^ f[b2 ^ h4[i++]];
      b7 = b7 ^ f[b3 ^ h4[i++]];
      
      b12 = b12 ^ f[b8 ^ h4[i++]];
      b13 = b13 ^ f[b9 ^ h4[i++]];
      b14 = b14 ^ f[b10 ^ h4[i++]];
      b15 = b15 ^ f[b11 ^ h4[i++]];
      
      b4 = b4 ^ f[b12 ^ h4[i++]];
      b5 = b5 ^ f[b13 ^ h4[i++]];
      b6 = b6 ^ f[b14 ^ h4[i++]];
      b7 = b7 ^ f[b15 ^ h4[i++]];
      
      b12 = b12 ^ f[b4 ^ h4[i++]];
      b13 = b13 ^ f[b5 ^ h4[i++]];
      b14 = b14 ^ f[b6 ^ h4[i++]];
      b15 = b15 ^ f[b7 ^ h4[i++]];
      
      b1 = b1 ^ f[b9 ^ h4[i++]];
      b2 = b2 ^ f[b10 ^ h4[i++]];
      b3 = b3 ^ f[b11 ^ h4[i++]];
      b0 = b0 ^ f[b8 ^ h4[i++]];
      
      b9  = b9 ^ f[b1 ^ h4[i++]];
      b10 = b10 ^ f[b2 ^ h4[i++]];
      b11 = b11 ^ f[b3 ^ h4[i++]];
      b8 =  b8 ^ f[b0 ^ h4[i++]]; 
      
}

void decrypt(unsigned char h4[n1])
{
int i;

i=1943;

      b8 =  b8 ^ f[b0 ^ h4[i--]]; 
      b11 = b11 ^ f[b3 ^ h4[i--]];
      b10 = b10 ^ f[b2 ^ h4[i--]];
      b9  = b9 ^ f[b1 ^ h4[i--]];
 
      b0 = b0 ^ f[b8 ^ h4[i--]];
      b3 = b3 ^ f[b11 ^ h4[i--]];
      b2 = b2 ^ f[b10 ^ h4[i--]];
      b1 = b1 ^ f[b9 ^ h4[i--]];
 
      b15 = b15 ^ f[b7 ^ h4[i--]];
      b14 = b14 ^ f[b6 ^ h4[i--]];
      b13 = b13 ^ f[b5 ^ h4[i--]];
      b12 = b12 ^ f[b4 ^ h4[i--]];
  
      b7 = b7 ^ f[b15 ^ h4[i--]];
      b6 = b6 ^ f[b14 ^ h4[i--]];
      b5 = b5 ^ f[b13 ^ h4[i--]];
      b4 = b4 ^ f[b12 ^ h4[i--]];
   
      b15 = b15 ^ f[b11 ^ h4[i--]];
      b14 = b14 ^ f[b10 ^ h4[i--]];
      b13 = b13 ^ f[b9 ^ h4[i--]];
      b12 = b12 ^ f[b8 ^ h4[i--]];
    
      b7 = b7 ^ f[b3 ^ h4[i--]];
      b6 = b6 ^ f[b2 ^ h4[i--]];
      b5 = b5 ^ f[b1 ^ h4[i--]];
      b4 = b4 ^ f[b0 ^ h4[i--]];
 

for(int y=0;y<64;y++){
       
      b8 =  b8 ^ f[b0 ^ h4[i--]]; 
      b11 = b11 ^ f[b3 ^ h4[i--]];
      b10 = b10 ^ f[b2 ^ h4[i--]];
      b9  = b9 ^ f[b1 ^ h4[i--]];

      b0 = b0 ^ f[b8 ^ h4[i--]];
      b3 = b3 ^ f[b11 ^ h4[i--]];
      b2 = b2 ^ f[b10 ^ h4[i--]];
      b1 = b1 ^ f[b9 ^ h4[i--]];

      b8 =  b8 ^ f[b15 ^ h4[i--]]; 
      b11 = b11 ^ f[b14 ^ h4[i--]];
      b10 = b10 ^ f[b12 ^ b13];
      b9  = b9 ^ f[b12 ^ h4[i--]];

      b0 = b0 ^ f[b7 ^ h4[i--]];
      b3 = b3 ^ f[b6 ^ h4[i--]];
      b2 = b2 ^ f[b4 ^ b5];
      b1 = b1 ^ f[b4 ^ h4[i--]];

      b15 = b15 ^ f[b7 ^ h4[i--]];
      b14 = b14 ^ f[b6 ^ h4[i--]];
      b13 = b13 ^ f[b5 ^ h4[i--]];
      b12 = b12 ^ f[b4 ^ h4[i--]];

      b7 = b7 ^ f[b15 ^ h4[i--]];
      b6 = b6 ^ f[b14 ^ h4[i--]];
      b5 = b5 ^ f[b13 ^ h4[i--]];
      b4 = b4 ^ f[b12 ^ h4[i--]];

      b15 = b15 ^ f[b11 ^ h4[i--]];
      b14 = b14 ^ f[b10 ^ h4[i--]];
      b13 = b13 ^ f[b9 ^ h4[i--]];
      b12 = b12 ^ f[b8 ^ h4[i--]];

      b7 = b7 ^ f[b3 ^ h4[i--]];
      b6 = b6 ^ f[b2 ^ h4[i--]];
      b5 = b5 ^ f[b1 ^ h4[i--]];
      b4 = b4 ^ f[b0 ^ h4[i--]];
   
   }

}

int main()
{
	
      unsigned char text[33]; /* up to 256 chars for the password */
                              /* password can be hexadecimal */
                              /* strcpy = null terminated string */
      unsigned char h4[n1];

  printf("NEWDES2 by Alexander PUKALL 2006 \n 128-bit block 15552-bit subkeys 64 rounds\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on NEWDES by Robert Scott\n\n");

    /* The key creation procedure is slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many blocks as you want without having to hash the key again. */
    /* init(); hashing(text,length);  end(h4); -> only once */
    
    /* EXAMPLE 1 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abc");

    hashing(text, 32);
    end(h4); /* h4 = 15552-bit key from hash "My secret password!0123456789abc */
    
    /* 0xFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE NEWDES2 block plaintext */
    
    b0=0xFE;b1=0xFE;b2=0xFE;b3=0xFE;b4=0xFE;b5=0xFE;b6=0xFE;b7=0xFE;
    b8=0xFE;b9=0xFE;b10=0xFE;b11=0xFE;b12=0xFE;b13=0xFE;b14=0xFE;b15=0xFE;
  
   
    printf("Key 1:%s\n",text);
    printf("Plaintext   1: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n",b8,b9,b10,b11,b12,b13,b14,b15);

    encrypt(h4);
    
    printf("Encryption  1: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n",b8,b9,b10,b11,b12,b13,b14,b15);
       
    decrypt(h4);
    
    printf("Decryption  1: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n\n",b8,b9,b10,b11,b12,b13,b14,b15);

    /* EXAMPLE 2 */
    
    /* 0x00000000000000000000000000000000 NEWDES2 block plaintext */
    
    b0=0x00;b1=0x00;b2=0x00;b3=0x00;b4=0x00;b5=0x00;b6=0x00;b7=0x00;
    b8=0x00;b9=0x00;b10=0x00;b11=0x00;b12=0x00;b13=0x00;b14=0x00;b15=0x00;
  
   
    printf("Key 1:%s\n",text);
    printf("Plaintext   2: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n",b8,b9,b10,b11,b12,b13,b14,b15);

    encrypt(h4);
    
    printf("Encryption  2: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n",b8,b9,b10,b11,b12,b13,b14,b15);
       
    decrypt(h4);
    
    printf("Decryption  2: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n\n",b8,b9,b10,b11,b12,b13,b14,b15);

    /* EXAMPLE 3 */
    
   
    /* 0x00000000000000000000000000000001 NEWDES2 block plaintext */
    
    b0=0x00;b1=0x00;b2=0x00;b3=0x00;b4=0x00;b5=0x00;b6=0x00;b7=0x00;
    b8=0x00;b9=0x00;b10=0x00;b11=0x00;b12=0x00;b13=0x00;b14=0x00;b15=0x01;
  
   
    printf("Key 1:%s\n",text);
    printf("Plaintext   3: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n",b8,b9,b10,b11,b12,b13,b14,b15);

    encrypt(h4);
    
    printf("Encryption  3: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n",b8,b9,b10,b11,b12,b13,b14,b15);
       
    decrypt(h4);
    
    printf("Decryption  3: %0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",b0,b1,b2,b3,b4,b5,b6,b7);
    printf("%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X\n\n",b8,b9,b10,b11,b12,b13,b14,b15);

	
}

/*

Key 1:My secret password!0123456789abc
Plaintext   1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
Encryption  1: 8872B36042D6EF097DE833DEB79905C7
Decryption  1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

Key 1:My secret password!0123456789abc
Plaintext   2: 00000000000000000000000000000000
Encryption  2: 3A938CCAEE6D79698A0A7C36A79E9267
Decryption  2: 00000000000000000000000000000000

Key 1:My secret password!0123456789abc
Plaintext   3: 00000000000000000000000000000001
Encryption  3: 924D9982C85059F04D8F07379D3EA528
Decryption  3: 00000000000000000000000000000001

*/
