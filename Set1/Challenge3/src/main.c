/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Challenge 3 of CryptoPals crypto challenges.		 *
 * 				A hex encoded string has been given which has been   *
 * 				XOR'd agains a single character. Devise a method	 *
 *              to score a piece of English plaintext.               *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encodings.h"
#include "crypto.h"

int main(void)
{
   crypto_status status = CRYPTO_ERR;
   uint8_t The_String[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
   uint8_t *hex_string = NULL;
   int string_sz = 0;

   printf("The string: %s\n", (char *)The_String);

   string_sz = sizeof(The_String) - 1; // -1 to get rid of the 0 string terminator
   hex_string = AsciiHex2Bin(The_String, string_sz);

   printf("The hex string: ");
   for(int i = 0; i < string_sz; i++)
      printf("%02x ", hex_string[i]);
   printf("\n");

   float score = 0, best_score = 10000;
   uint8_t best_key_candidate = 0, best_decryption_attempt[string_sz+1];
   for (uint8_t i = 32; i < 127; i++)
   {
      uint8_t current_key_attempt;
      uint8_t decryption_attempt[string_sz];
      int decrypt_size = 0;

      current_key_attempt = i;

      status = FixedXOR_SingleChar(hex_string, current_key_attempt, string_sz, decryption_attempt, &decrypt_size);
      if (status != CRYPTO_OK)
      {
         printf("Decrypting error!!\n");
         free(hex_string);
         hex_string = NULL;
         return -1;
      }

      status = English_Score(decryption_attempt, decrypt_size, &score);

      if (score < best_score)
      {
         best_score = score;
         best_key_candidate = current_key_attempt;
         memcpy(best_decryption_attempt, decryption_attempt, decrypt_size);
         best_decryption_attempt[decrypt_size] = '\0';
      }
   }

   printf("========================================================================\n");
   printf("The best key candidate for the decryption is: %c\n", best_key_candidate);
   printf("The decryption result is:\n\"%s\"\n", best_decryption_attempt);

   free(hex_string);
   hex_string = NULL;

   return 0;
}