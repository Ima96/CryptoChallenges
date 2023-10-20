#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "misc.h"
#include "encodings.h"

int main(void)
{

   crypto_status EStatus = CRYPTO_ERR;
   uint8_t au8_b64_encoded_pt[250] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

   // First conditioning the input string.
   uint16_t u16_decoded_pt_len = 0;
   uint8_t * pu8_plaintext = DecodeBase64(au8_b64_encoded_pt, strlen(au8_b64_encoded_pt), &u16_decoded_pt_len);

   EStatus = oneByteAtATime_ECB_Decryption(pu8_plaintext, u16_decoded_pt_len);

   if (pu8_plaintext)
      free(pu8_plaintext);
   pu8_plaintext = NULL;

   return EXIT_SUCCESS;
}