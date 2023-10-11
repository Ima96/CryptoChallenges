

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
   uint8_t *ciphertext = calloc(cipherlen+1, sizeof(uint8_t));

   char c = 0;
   uint16_t cont = 0;
   while ((c = getc(fip)) != EOF)
   {
      if (c != '\n')
         ciphertext[cont++] = c;
   }
   ciphertext[cont] = '\n';
   fclose(fip);

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
   if (CRYPTO_OK != DecryptAES128_ECB_OpenSSL(bin_ciphertext, bin_cipherlen, key, &a_u8_plaintext, &plaintext_len))
   {
      printf("<ERROR> Something went wrong...\n");
      goto cleanup;
   }

   printf("Decrypted message:\n\"%s\"\n", a_u8_plaintext);

   uint8_t * pu8_reciphertxt = NULL;
   int32_t i32_recipherlen = 0;
   if (CRYPTO_OK != EncryptAES128_ECB_OpenSSL(a_u8_plaintext, plaintext_len, key, &pu8_reciphertxt, &i32_recipherlen))
   {
      printf("<ERROR> Something went wrong...\n");
      goto cleanup;
   }

   if (bin_cipherlen == i32_recipherlen)
      printf("Same cipher length achieved!!\n");
   else
      printf("NOT the same cipher lengths achieved...\n");

   if (0 == memcmp(bin_ciphertext, pu8_reciphertxt, bin_cipherlen))
      printf("Same cipher text obtained!!\n");
   else
   {
      printf("NOT the same cipher text obtained...\n");
      for (int i = 0; i < i32_recipherlen; ++i)
         printf("%02X vs %02X \n", bin_ciphertext[i], pu8_reciphertxt[i]);
   }

   /* Clean-up */
cleanup:
   if (ciphertext)
      free(ciphertext);
   ciphertext = NULL;

   if (bin_ciphertext)
      free(bin_ciphertext);
   bin_ciphertext = NULL;

   if (a_u8_plaintext)
      free(a_u8_plaintext);
   a_u8_plaintext = NULL;

   if (pu8_reciphertxt)
      free(pu8_reciphertxt);
   pu8_reciphertxt = NULL;

   Cleanup_OpenSSL();
}