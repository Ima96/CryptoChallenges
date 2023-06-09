

#include <stdlib.h>
#include "crypto.h"

#define BLOCK_SIZE   20U

void main(int argc, char *argv[])
{
   crypto_status o_status = CRYPTO_ERR;

   uint8_t a16_u8_str_to_pad[16] = {'Y', 'E', 'L', 'L', 'O', 'W', ' ',  'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
   uint8_t * pu8_padded_str = NULL;
   uint16_t u16_block_size = BLOCK_SIZE;
   uint32_t u32_padded_size = 0;

   if (argc >= 2)
      u16_block_size = strtol(argv[1], NULL, 10);

   o_status = PKCS7_pad(a16_u8_str_to_pad, 16, u16_block_size, &pu8_padded_str, &u32_padded_size);
   if (o_status != CRYPTO_OK)
   {
      printf("<ERROR> Something went wrong!\n");
      if (pu8_padded_str)
         free(pu8_padded_str);
      return;
   }

   printf("Padded buffer: ");
   for (int i = 0; i < u32_padded_size; ++i)
      printf("%02X ", pu8_padded_str[i]);
   printf("\n");

   if (pu8_padded_str)
      free(pu8_padded_str);
}