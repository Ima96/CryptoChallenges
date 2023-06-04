

#include <string.h>
#include <crypto.h>
#include <encodings.h>

#define MAX_KEY_LEN  64

int main(int argc, char * argv[])
{
   if (argc != 3)
      return -1;
   
   char filename[125] = {0}, c = 0;
   uint8_t *line = NULL;
   uint16_t line_len = 0;
   FILE *fip = NULL;
   uint8_t key[MAX_KEY_LEN] = {0};
   uint16_t key_len = 0;

   key_len = strlen(argv[2]);
   if (key_len > MAX_KEY_LEN)
   {
      printf("Key length is bigger than supported!\n");
      return -1;
   }
   memcpy(key, argv[2], key_len);

   memcpy(filename, argv[1], strlen(argv[1]));
   fip = fopen(filename, "r");
   if (fip == NULL)
   {
      printf("Error openning the file!\n");
      return -1;
   }

   do
   {
      c = getc(fip);
      line = realloc(line, line_len+1);
      line[line_len] = c;
      line_len++;
   } while (c != EOF);
   fclose(fip);
   
   line_len--;
   line[line_len] = '\0';

   printf("Plaintext:\n\"%s\"\n", line);

   uint8_t *ciphertext = calloc(line_len, sizeof(uint8_t));
   EncryptRepeatingKeyXor(line, line_len-1, key, key_len, ciphertext);
   printf("Ciphertext:\n\"%s\"\n", ciphertext);

   uint8_t *hex_ciphertext = Encode2Hex(ciphertext, line_len-1);
   printf("Final HEX encoded:\n\"%s\"\n", hex_ciphertext);

   if (line)
      free(line);
   if (ciphertext)
      free(ciphertext);
   if (hex_ciphertext)
      free(hex_ciphertext);

   return 0;
}