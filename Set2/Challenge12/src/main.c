#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "misc.h"
#include "encodings.h"

int main(void)
{
   int ret_val = EXIT_FAILURE;
   crypto_status EStatus = CRYPTO_ERR;
   uint8_t au8_b64_encoded_pt[250] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

   // First conditioning the input string.
   uint16_t u16_decoded_pt_len = 0;
   uint8_t * pu8_plaintext = DecodeBase64(au8_b64_encoded_pt, strlen(au8_b64_encoded_pt), &u16_decoded_pt_len);
   uint8_t * pu8_obtained_unknown_msg = NULL;

   EStatus = oneByteAtATime_ECB_Decryption(pu8_plaintext, u16_decoded_pt_len, NULL, 0, &pu8_obtained_unknown_msg);

   if (CRYPTO_OK != EStatus)
   {
      ret_val = EXIT_FAILURE;
   }
   else
   {
      printf("The obtained unknown string (length=%ld) is:\n%s\nAgainst the real string (length=%ld):\n%s\n", strlen(pu8_obtained_unknown_msg), pu8_obtained_unknown_msg, strlen(pu8_plaintext), pu8_plaintext);

      if (0 == memcmp(pu8_obtained_unknown_msg, pu8_plaintext, strlen(pu8_obtained_unknown_msg)))
      {
         printf("<INFO> SUCESS!\n");
         ret_val = EXIT_SUCCESS;
      }
      else
      {
         printf("<FAIL> The strings are not equal...\n");
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