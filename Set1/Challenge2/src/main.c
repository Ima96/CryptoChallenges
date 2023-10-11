/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Challenge 2 of CryptoPals crypto challenges			 *
 * 				which consist on performing a fixed XOR operation    *
 * 				between two hex encoded buffers.					 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <stdlib.h>
#include "encodings.h"
#include "crypto.h"

int main(void)
{
   crypto_status status = CRYPTO_ERR;
   uint8_t buff1[] = "1c0111001f010100061a024b53535009181c";
   uint8_t buff2[] = "686974207468652062756c6c277320657965";
   int buff1_sz = sizeof(buff1) - 1;
   int buff2_sz = sizeof(buff2) - 1;

   uint8_t *hex_buff1 = NULL;
   uint8_t *hex_buff2 = NULL;
   uint8_t *XORed_bin = NULL;
   uint8_t *XORed_ascii = NULL;

   DEBUG_CRYPTO("Size of buff1: %d\n", buff1_sz);

   printf("Buffer1: %s\nBuffer2: %s\n", buff1, buff2);

   hex_buff1 = AsciiHex2Bin(buff1, buff1_sz);
   hex_buff2 = AsciiHex2Bin(buff2, buff2_sz);

   XORed_bin = malloc(buff1_sz);
   status = FixedXOR(hex_buff1, hex_buff2, buff1_sz, buff2_sz, XORed_bin);

   free(hex_buff1);
   hex_buff1 = NULL;
   free(hex_buff2);
   hex_buff2 = NULL;

   if (status != CRYPTO_OK)
   {
      printf("Something went wrong in XOR function!\n");
      free(XORed_bin);
      XORed_bin = NULL;
      exit(EXIT_FAILURE);
   }

   XORed_ascii = BinHex2Ascii(XORed_bin, buff1_sz);
   printf("\nXORed result: %s\n", XORed_ascii);

   free(XORed_bin);
   XORed_bin = NULL;
   free(XORed_ascii);
   XORed_ascii = NULL;

   return 0;
}