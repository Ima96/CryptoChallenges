
#include <string.h>
#include "encodings.h"
#include "crypto.h"

void HammingTest(void)
{
   crypto_status status = CRYPTO_ERR;
   uint8_t buf1[15] = "this is a test";
   uint8_t buf2[15] = "wokka wokka!!!";
   uint16_t test_hamm_dist = 0;

   status = ComputeBufHammingDist(buf1, strlen(buf1), buf2, strlen(buf2), &test_hamm_dist);

   if (status != CRYPTO_OK)
   {
      printf("[DEBUG] Some crypto-op went wrong computing the hamming distance...\n");
      return;
   }

   if (test_hamm_dist == 37)
      printf("[DEBUG] Hamming test working fine! value = %d\n", test_hamm_dist);
   else
      printf("[DEBUG] Hamming test NOT working fine...\n");
}

void B64Test(void)
{
   uint8_t test_str1[] = "SGVsbG8gV29ybGQh";
   uint8_t test_str2[] = "SGVsbG8gV29ybGQhIQ==";
   uint8_t test_str3[] = "SGVsbG8gV29ybGQhISE=";
   uint8_t expected_res1[] = {
      0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21
   };
   uint8_t expected_res2[] = {
      0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x21
   };
   uint8_t expected_res3[] = {
      0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x21, 0x21
   };

   uint8_t *test_res1 = DecodeBase64(test_str1, 16, NULL);
   uint8_t *test_res2 = DecodeBase64(test_str2, 20, NULL);
   uint8_t *test_res3 = DecodeBase64(test_str3, 20, NULL);

   if (0 != (memcmp(expected_res1, test_res1, 12)) ||
         0 != (memcmp(expected_res2, test_res2, 13)) ||
         0 != (memcmp(expected_res3, test_res3, 14)))
      printf("[DEBUG] Base64 decode not working...\n");
   else
      printf("[DEBUG] Base64 decode working fine!\n");
}

int main(int argc, char * argv[])
{
   #if defined(DEBUG_APP)
   HammingTest();
   B64Test();
   #endif

   if (argc != 2)
   {
      printf("<ERROR> Number of arguments wrong!\n");
      printf("Usage: ./break-rkxor /path/to/cipherfile\n");
      return -1;
   }

   crypto_status status = CRYPTO_ERR;
   FILE *fip = NULL;
   char c = 0;
   uint8_t *ciphertext = NULL;
   uint32_t ciphertext_len = 0;
   uint32_t cont = 0;

   /* Read the encripted file and store ciphertext in memory */
   fip = fopen(argv[1], "r");
   if (fip == NULL)
   {
      printf("<ERROR> Error openning the file!\n");
      return -1;
   }

   fseek(fip, 0, SEEK_END);
   ciphertext_len = ftell(fip);
   rewind(fip);

   ciphertext = calloc(ciphertext_len, sizeof(uint8_t));
   while ((c = getc(fip)) != EOF)
   {
      if (c != '\n')
         ciphertext[cont++] = c;
   }
   fclose(fip);

   #if defined(DEBUG_APP)
   printf("[DEBUG] Readed ciphertext:\n\"%s\"\n", ciphertext);
   #endif

   /* Decode from Base64 */
   uint16_t bin_cipherlen = 0;
   uint8_t *bin_ciphertext = DecodeBase64(ciphertext, cont, 
                                          &bin_cipherlen);

   #if defined(DEBUG_APP)
   printf("[DEBUG] Decoded:\n");
   for (int i = 0; i < bin_cipherlen; i++)
      printf("%02X ", bin_ciphertext[i]);
   printf("\n");
   #endif

   /* Guess most probable KeySize value */
   uint8_t m_prob_keysizes[4] = {0};
   Guess_RKXOR_KeySize(bin_ciphertext, bin_cipherlen, m_prob_keysizes);

   printf("Guessed best keysize attempts: ");
   for (int i = 0; i < 4; i++)
      printf("%d ", m_prob_keysizes[i]);
   printf("\n");

   /* Break Repeating-key XOR */
   uint8_t **possible_keys = NULL;
   possible_keys = (uint8_t **) malloc(4 * sizeof(uint8_t *));
   uint8_t *best_decryption_key = NULL;
   uint16_t best_decryption_key_sz = 0;
   float best_final_score = 100000;

   for (int i = 0; i < 4; ++i)
   {
      float final_plain_score = 0;
      uint8_t curr_keysize = m_prob_keysizes[i];
      uint16_t num_blocks  = bin_cipherlen / curr_keysize;

      uint8_t **cipher_blocks = NULL;

      cipher_blocks = (uint8_t **) malloc(curr_keysize * sizeof(uint8_t *));
      possible_keys[i] = (uint8_t *) malloc(curr_keysize * sizeof(uint8_t));

      for (int j = 0; j < curr_keysize; ++j)
      {
         cipher_blocks[j] = (uint8_t *) malloc(num_blocks * sizeof(uint8_t));
         for (int k = 0; k < num_blocks; ++k)
            cipher_blocks[j][k] = bin_ciphertext[(k*curr_keysize)+j];

         BreakFixedASCIIXOR_Key(cipher_blocks[j], num_blocks, 
                           &possible_keys[i][j]);
      }

      for (int clean = 0; clean < curr_keysize; ++clean)
         free(cipher_blocks[clean]);
      free(cipher_blocks);

      uint8_t *test_text = malloc((bin_cipherlen/2) * sizeof(uint8_t));
      EncryptRepeatingKeyXor(bin_ciphertext, (bin_cipherlen/2), possible_keys[i], curr_keysize, test_text);

      #if defined(DEBUG_APP)
      printf("[DEBUG] Obtained key attempt --> %.*s\n", curr_keysize, possible_keys[i]);
      printf("[DEBUG] Test decrypted text:\n%.*s\n", (bin_cipherlen/2), test_text);
      #endif

      English_Score(test_text, (bin_cipherlen/2), &final_plain_score);

      if (final_plain_score < best_final_score)
      {
         best_final_score = final_plain_score;
         best_decryption_key = realloc(best_decryption_key, (curr_keysize + 1) * sizeof(uint8_t));
         best_decryption_key_sz = curr_keysize;
         memcpy(best_decryption_key, possible_keys[i], best_decryption_key_sz);
         best_decryption_key[best_decryption_key_sz] = '\0';
      }

   }
   printf("Best key: \"%s\"\n", best_decryption_key);
   for (int i = 0; i < 4; ++i)
   {
      if (possible_keys[i])
         free(possible_keys[i]);
   }
   if (possible_keys)
      free(possible_keys);

   uint8_t *plaintext = malloc(bin_cipherlen * sizeof(uint8_t));
   EncryptRepeatingKeyXor(bin_ciphertext, bin_cipherlen, best_decryption_key, best_decryption_key_sz, plaintext);

   printf("Deciphered text:\n%.*s\n", bin_cipherlen, plaintext);

   return 0;
}