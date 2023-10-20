

#include <stdlib.h>
#include <unistd.h>

#include "crypto.h"
#include "misc.h"
#include "encodings.h"

int main(void)
{

   crypto_status SStatus;
   uint8_t au8_rnd_aes256_key[AES128_KEY_SIZE] = {0};

   uint8_t au8_message[50] = {'A'};
   crypto_aes_mode_t mode;

   for (int i = 0; i < 15; ++i)
   {
      SStatus = OracleAES128_ECB_CBC(au8_message, 50, &mode);
      if (SStatus != CRYPTO_OK)
      {
         printf("<ERROR> Something went wrong!\n");
         return EXIT_FAILURE;
      }

      if (mode == E_AES128_ECB)
         printf("Detected ECB!\n");
      else if (mode == E_AES128_CBC)
         printf("Detected CBC!!\n");
      else
         printf("Unknown...\n");

      sleep(1);
   }

   return EXIT_SUCCESS;
}