/**
 * Challenge 14 seems that was thought to be done using a random
 * prefix that is generated only ONCE at the beginning. But, when
 * reading it I understood that a random prefix with random length
 * each time was intended. I find this second approach more exciting
 * and once the solution to the first original option is done, the
 * second variant will also be developed.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"
#include "encodings.h"


int main(void)
{
   printf("=========== CryptoPals: Challenge 14 ===========\n");

   int ret_val = EXIT_FAILURE;
   crypto_status e_status = CRYPTO_ERR;
   uint8_t au8_b64_encoded_pt[250] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

   // First conditioning the input string.
   uint16_t u16_decoded_pt_len = 0;
   uint8_t * pu8_plaintext = DecodeBase64(au8_b64_encoded_pt, strlen(au8_b64_encoded_pt), &u16_decoded_pt_len);
   uint8_t * pu8_obtained_unknown_msg = NULL;

   e_status = oneByteAtATime_ECB_Decryption_Harder(pu8_plaintext, u16_decoded_pt_len, &pu8_obtained_unknown_msg);

   if (CRYPTO_OK != e_status)
   {
      ret_val = EXIT_FAILURE;
   }
   else
   {
      printf("The obtained unknown string is:\n%s\nAgainst the real string:\n%s\n", pu8_obtained_unknown_msg, pu8_plaintext);

      if (0 == memcmp(pu8_obtained_unknown_msg, pu8_plaintext, strlen(pu8_obtained_unknown_msg)))
      {
         printf("Result ----> SUCESS!\n");
         ret_val = EXIT_SUCCESS;
      }
      else
      {
         printf("Result ----> FAIL: The strings are not equal...\n");
         ret_val = EXIT_FAILURE;
      }
      
   }
   

   if (pu8_plaintext)
      free(pu8_plaintext);
   pu8_plaintext = NULL;

   if (pu8_obtained_unknown_msg)
      free(pu8_obtained_unknown_msg);
   pu8_obtained_unknown_msg = NULL;

   return ret_val;
}