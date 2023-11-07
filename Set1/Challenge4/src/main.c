/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Challenge 4 of CryptoPals crypto challenges.		 *
 * 				A hex encoded string has been given which has been   *
 * 				XOR'd agains a single character and it is located    * 
 *              between some other lines in the file. Devise a       *
 *              method to score a piece of English plaintext.        *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encodings.h"
#include "crypto.h"

#define MAX_LINE_LENGTH 160

int main(void)
{
   FILE *fip = NULL;
   char filename[125] = "./resources/ciphertext4.txt";

   if((fip = fopen(filename, "rb")) == NULL)
   {
      printf("Error opening the file...\n");
      return -1;
   }

   char c = 0;
   uint16_t line_len = 0, decripted_buff_len = 0;
   uint8_t *line = NULL, *hex_line = NULL, *decripted_buff = NULL, *message = NULL;
   crypto_status status = CRYPTO_ERR;
   float line_score = 0, best_line_score = 10000;

   do
   {
      c = getc(fip);
      line = realloc(line, line_len+1);
      line[line_len] = c;
      line_len++;

      if(c == '\n' || c == EOF)
      {
         line[line_len-1] = '\0';
         #if defined(DEBUG_APP)
         printf("%s\n", line);
         #endif
         hex_line = AsciiHex2Bin(line, line_len-1);

         if(decripted_buff)
            free(decripted_buff);
         decripted_buff = calloc(line_len-1, sizeof(uint8_t));
         status = BreakFixedXOR(hex_line, line_len-1, decripted_buff, 
                                    &decripted_buff_len, &line_score);
         
         free(hex_line);
         hex_line = NULL;

         if (status != CRYPTO_OK)
            printf("Error with the cryptoshit!\n");

         if (line_score < best_line_score)
         {
            best_line_score = line_score;
            if (message)
               free(message);
            message = calloc(decripted_buff_len+1, sizeof(uint8_t));
            memcpy(message, decripted_buff, decripted_buff_len);
            message[decripted_buff_len] = '\0';
            #if defined(DEBUG_APP)
            printf("[UPDATE] = %s --> Score: %f\n", message, best_line_score);
            #endif
         }
            
         line_len = 0;
      }

   } while(c != EOF);

   fclose(fip);
   printf("The best decryption result is:\"%s\"\n-->The score was = %f\n", message, best_line_score);

   /* Clean-up */
   if (message)
      free(message);
   if (decripted_buff)
      free(decripted_buff);
   if (line)
      free(line);

   return 0;
}
