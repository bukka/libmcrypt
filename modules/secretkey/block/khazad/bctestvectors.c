/********************************************************************
 *
 *     IST project 1999-12324 NESSIE
 *
 *     Copyright (c)
 *        Katholieke Universiteit Leuven
 *        Ecole Normale Superieure
 *        Royal Holloway, University of London
 *        Siemens AG
 *        Technion - Israel Institute if Technology
 *        Universite Catholique de Louvain
 *        Universitetet i Bergen
 *     2000, All Rights Reserved
 *
 ********************************************************************
 *
 *      FILE:     bctestvectors.c
 *
 *      DATE:     21/09/00
 *      VERSION:  1.0
 *
 *      CONTENTS: Test vector generation for block ciphers 
 *      TARGET:   Any computer with a portable C compiler
 *
\********************************************************************/

#include <stdio.h>
#include <string.h>
#include "nessie.h"

void print_data(char *str, u8 *val, int len);
int compare_blocks(u8 *m1, u8 *m2, int len_bits); /* 0=equal, 1=not eq. */

int main()
{
  struct NESSIEstruct subkeys;
  u8 key[KEYSIZEB];
  u8 plain[BLOCKSIZEB];
  u8 cipher[BLOCKSIZEB];
  u8 decrypted[BLOCKSIZEB];

  u32 i;
  int v;

  printf("Test vectors -- set 1\n");
  printf("=====================\n\n");

  /* If key size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(KEYSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      key[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 1, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

      for(i=0; i<99; i++)
        NESSIEencrypt(&subkeys, cipher, cipher);
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
      for(i=0; i<900; i++)
        NESSIEencrypt(&subkeys, cipher, cipher);
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);

      printf("\n");
    }

  printf("Test vectors -- set 2\n");
  printf("=====================\n\n");

  /* If block size is not a multiple of 8, this tests too much (intentionally) */
  for(v=0; v<(BLOCKSIZEB*8); v++)
    {
      memset(plain, 0, BLOCKSIZEB);
      memset(key, 0, KEYSIZEB);
      plain[v>>3] = 1<<(7-(v&7));

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 2, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

      for(i=0; i<99; i++)
        NESSIEencrypt(&subkeys, cipher, cipher);
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
      for(i=0; i<900; i++)
        NESSIEencrypt(&subkeys, cipher, cipher);
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);

      printf("\n");
    }

  printf("Test vectors -- set 3\n");
  printf("=====================\n\n");

  for(v=0; v<256; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);
      NESSIEdecrypt(&subkeys, cipher, decrypted);

      printf("Set 3, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);
      print_data("cipher", cipher, BLOCKSIZEB);
      print_data("decrypted", decrypted, BLOCKSIZEB);

      if(compare_blocks(plain, decrypted, BLOCKSIZE) != 0)
        printf("** Decryption error: **\n"
               "   Decrypted ciphertext is different than the plaintext!\n");

      for(i=0; i<99; i++)
        NESSIEencrypt(&subkeys, cipher, cipher);
      print_data("Iterated 100 times", cipher, BLOCKSIZEB);
      for(i=0; i<900; i++)
        NESSIEencrypt(&subkeys, cipher, cipher);
      print_data("Iterated 1000 times", cipher, BLOCKSIZEB);

      printf("\n");
    }

  printf("Test vectors -- set 4\n");
  printf("=====================\n\n");

  for(v=0; v<4; v++)
    {
      memset(plain, v, BLOCKSIZEB);
      memset(key, v, KEYSIZEB);

      NESSIEkeysetup(key, &subkeys);
      NESSIEencrypt(&subkeys, plain, cipher);

      printf("Set 4, vector#%3d:\n", v);
      print_data("key", key, KEYSIZEB);
      print_data("plain", plain, BLOCKSIZEB);

      for(i=0; i<99999999; i++)
        {
          memset(key, cipher[BLOCKSIZEB-1], KEYSIZEB);
          NESSIEkeysetup(key, &subkeys);
          NESSIEencrypt(&subkeys, cipher, cipher);
        }
      print_data("Iterated 10^8 times", cipher, BLOCKSIZEB);

      printf("\n");
    }

  printf("\n\nEnd of test vectors\n");

  return 0;
}

void print_data(char *str, u8 *val, int len)
{
  int i;

  static char *hex="0123456789ABCDEF";

  printf("%25s=", str);
  for(i=0; i<len; i++)
    {
      putchar(hex[(val[i]>>4)&0xF]);
      putchar(hex[(val[i]   )&0xF]);
    }
  putchar('\n');
}

int compare_blocks(u8 *m1, u8 *m2, int len_bits)
{
  int i;
  int lenb=(len_bits+7)>>3;
  int mask0 = (1<<(((len_bits-1)&7)+1))-1;

  if((m1[0]&mask0) != (m2[0]&mask0))
    return 1;

  for(i=1; i<lenb; i++)
    if(m1[i] != m2[i])
        return 1;

  return 0;
}
