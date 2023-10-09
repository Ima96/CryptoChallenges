

#include <stdlib.h>
#include "misc.h"

uint16_t getFileSize(FILE *fip, uint8_t const filter)
{
   uint16_t f_size;

   if (fip == NULL)
      return 0;
   
   if (filter == 0)
   {
      fseek(fip, 0, SEEK_END);
      f_size = ftell(fip);
   }
   else
   {
      char c = 0;
      while ((c = getc(fip)) != EOF)
      {
         if (c != filter)
            f_size++;
      }
   }

   rewind(fip);
   return f_size;
}

uint16_t readFile(FILE *fip, uint8_t **outbuf, uint8_t const filter)
{
   if (fip == NULL)
      return 0;
   
   char c = 0;
   uint8_t * temp = NULL;
   uint16_t count = 0;
   uint16_t f_size = getFileSize(fip, filter);
   
   temp = malloc(f_size * sizeof(uint8_t));

   while ((c = getc(fip)) != EOF)
   {
      if (filter != 0)
      {
         if (c != filter)
         {
            temp[count] = c;
            count++;
         }
      }
      else
      {
         temp[count] = c;
         count++;
      }
   }

   *outbuf = temp;
   return (f_size == count) ? f_size : 0;
}

uint16_t getFileLineCount(FILE *fip)
{
   if (fip == NULL)
      return 0;

   char c = 0;
   uint16_t count = 0;
   while ((c = getc(fip)) != EOF)
      if (c == '\n') count++;
   
   rewind(fip);
   return count;
}

uint8_t **readFileLines(FILE *fip, uint16_t *line_count)
{
   if (fip == NULL)
      return NULL;

   char c = 0;
   uint8_t **temp_buf = NULL;
   uint16_t ln_num = getFileLineCount(fip);

   temp_buf = malloc(ln_num * sizeof(uint8_t *));

   for (int i = 0; i < ln_num; ++i)
   {
      uint16_t count = 0;
      while ((c = getc(fip)) != '\n')
      {
         temp_buf[i] = realloc(temp_buf[i], count + 1);
         temp_buf[i][count] = c;
         count++;
      }
      temp_buf[i] = realloc(temp_buf[i], count+1);
      temp_buf[count+1] = '\0';
   }

   *line_count = ln_num;
   return temp_buf;
}

void PrintHex(uint8_t const * const pu8_buff, int32_t const i32_buff_len)
{
   for (int32_t i32_idx = 0; i32_idx < i32_buff_len; i32_idx++)
   {
      printf("%02X ", pu8_buff[i32_idx]);
   }
   printf("\n");
}