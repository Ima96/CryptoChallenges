

#include <stdio.h>
#include <stdlib.h>
#include <misc/misc.h>
#include <crypto/crypto.h>
#include <encodings/encodings.h>

int main(int argc, char * argv[])
{

   FILE *fip = NULL;
   uint8_t * pu8_file_contents = NULL;
   uint16_t u16_file_size = 0;

   if (NULL != (fip = fopen(argv[1], "r")))
   {
      u16_file_size = readFile(fip, &pu8_file_contents, (uint8_t)'\n');
      fclose(fip);
   }
   else
   {
      printf("<ERROR> Could not open the file!\n");
      fclose(fip);
      return EXIT_FAILURE;
   }

   printf("File contents: \n%s\n", pu8_file_contents);

   uint16_t u16_cipherlen = 0;
   uint8_t * pu8_ciphertext = DecodeBase64(pu8_file_contents, u16_file_size, &u16_cipherlen);

   crypto_status e_status;
   uint8_t a16_u8_key[AES128_KEY_SIZE] = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
   uint8_t a16_u8_iv[16] = {'\0'};
   uint8_t * pu8_plaintext = NULL;
   uint8_t * pu8_ciphertext_padded = NULL;
   uint16_t u16_plainlen = 0;

   Init_OpenSSL();

   e_status = DecryptAES128_CBC_OpenSSL(pu8_ciphertext, u16_cipherlen, a16_u8_key, a16_u8_iv, &pu8_plaintext, &u16_plainlen);

   if (e_status != CRYPTO_OK)
   {
      printf("<ERROR> Something went wrong while decrypting...\n");
      if (pu8_file_contents)
         free(pu8_file_contents);
      if (pu8_ciphertext)
         free(pu8_ciphertext);
      return EXIT_FAILURE;
   }

   printf("Deciphered text: \n%.*s\n", u16_plainlen, pu8_plaintext);

   /* Clean-up */
   if (pu8_file_contents)
      free(pu8_file_contents);
   if (pu8_ciphertext)
      free(pu8_ciphertext);
   if (pu8_plaintext)
      free(pu8_plaintext);
   
   Cleanup_OpenSSL();

   return EXIT_SUCCESS;
}