

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <encodings/encodings.h>
#include <crypto/crypto.h>

void main(int argc, char *argv[])
{
   if (argc != 2)
   {
      printf("<ERROR> The executable needs at least 1 input argument!\n");
      return;
   }

   FILE *fip = NULL;
   if ((fip = fopen(argv[1], "r")) == NULL)
   {
      printf("<ERROR> Could not open the input file!\n");
      return;
   }

   /* Read Ciphertext */
   fseek(fip, 0, SEEK_END);
   uint16_t cipherlen = ftell(fip);
   rewind(fip);
   uint8_t *ciphertext = calloc(cipherlen, sizeof(uint8_t));

   char c = 0;
   uint16_t cont = 0;
   while ((c = getc(fip)) != EOF)
   {
      if (c != '\n')
         ciphertext[cont++] = c;
   }

   printf("Ciphertext:\n\"%s\"\n", ciphertext);

   /* Decode from Base64 */
   uint16_t bin_cipherlen = 0;
   uint8_t *bin_ciphertext = DecodeBase64(ciphertext, cont, 
                                          &bin_cipherlen);

   /* OpenSSL */
   int outlen;
   int plaintext_len;
   uint8_t key[16] = {'Y', 'E', 'L', 'L', 'O', 'W', ' ',  'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};

   Init_OpenSSL();
   uint8_t *a_u8_plaintext = NULL;
   if (CRYPTO_OK != DecryptAES_ECB_OpenSSL(bin_ciphertext, bin_cipherlen, key, &a_u8_plaintext, &plaintext_len))
   {
      printf("<ERROR> Something went wrong...\n");
      goto cleanup;
   }

   printf("Decrypted message:\n\"%s\"\n", a_u8_plaintext);

   /* Clean-up */
cleanup:
   if (ciphertext)
      free(ciphertext);

   Cleanup_OpenSSL();
}