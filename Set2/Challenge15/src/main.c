
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"

int main(void)
{
   printf("=========== CryptoPals: Challenge 15 ===========\n");

   uint8_t a_u8_valid_pad[] = "ICE ICE BABY\x04\x04\x04\x04";
   uint8_t a_u8_wrong_pad1[] = "ICE ICE BABY\x05\x05\x05\x05";
   uint8_t a_u8_wrong_pad2[] = "ICE ICE BABY\x01\x02\x03\x04";
   uint8_t * pu8_stripped_plain = NULL;
   uint32_t u32_stripped_sz = 0;

   crypto_status e_status = CRYPTO_ERR;


   e_status = PKCS7_pad_strip(a_u8_valid_pad, strlen(a_u8_valid_pad), AES128_KEY_SIZE, &pu8_stripped_plain, &u32_stripped_sz);
   if (e_status != CRYPTO_OK)
   {
      printf("Invalid PKCS#7 padding...\n");
   }
   else
   {
      printf("Valid PKCS#7 pad --> Plaintext(%d): %s\n", u32_stripped_sz, pu8_stripped_plain);
      if (pu8_stripped_plain)
         free(pu8_stripped_plain);
      pu8_stripped_plain = NULL;
   }

   e_status = PKCS7_pad_strip(a_u8_wrong_pad1, strlen(a_u8_wrong_pad1), AES128_KEY_SIZE, &pu8_stripped_plain, &u32_stripped_sz);
   if (e_status != CRYPTO_OK)
   {
      printf("Invalid PKCS#7 padding...\n");
   }
   else
   {
      printf("Valid PKCS#7 pad --> Plaintext(%d): %s\n", u32_stripped_sz, pu8_stripped_plain);
      if (pu8_stripped_plain)
         free(pu8_stripped_plain);
      pu8_stripped_plain = NULL;
   }

   e_status = PKCS7_pad_strip(a_u8_wrong_pad2, strlen(a_u8_wrong_pad2), AES128_KEY_SIZE, &pu8_stripped_plain, &u32_stripped_sz);
   if (e_status != CRYPTO_OK)
   {
      printf("Invalid PKCS#7 padding...\n");
   }
   else
   {
      printf("Valid PKCS#7 pad --> Plaintext(%d): %s\n", u32_stripped_sz, pu8_stripped_plain);
      if (pu8_stripped_plain)
         free(pu8_stripped_plain);
      pu8_stripped_plain = NULL;
   }

   return EXIT_SUCCESS;
}