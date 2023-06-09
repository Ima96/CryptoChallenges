

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "misc.h"
#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

void main(int argc, char *argv[])
{
   FILE *fip = NULL;
   if ((fip = fopen(argv[1], "r")) == NULL)
   {
      printf("<ERROR> Could not open the file!\n");
      return;
   }

   /* Read file by lines into a matrix */
   uint8_t **cipherlines = NULL;
   uint16_t cipherline_count = 0;

   cipherlines = readFileLines(fip, &cipherline_count);
   if (cipherlines == NULL)
      return;

   /* Detect AES-ECB for each line readed */
   for (int i = 0; i < cipherline_count; ++i)
   {
      #if defined(DEBUG_APP)
      printf("Line %d: %s\n", i, cipherlines[i]);
      #endif
      if (CRYPTO_OK == (Detect_AES_ECB(cipherlines[i], strlen(cipherlines[i]), AES128_KEY_SIZE)))
         printf("AES-ECB Detected in line #%d: %s\n", i, cipherlines[i]);
   }

   /* Clean-up */
   fclose(fip);
   for (int i = 0; i < cipherline_count; ++i)
   {
      if (cipherlines[i])
         free(cipherlines[i]);
   }
   if (cipherlines)
      free(cipherlines);
}