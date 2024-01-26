

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

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
   
   temp = (uint8_t *) malloc((f_size + 1) * sizeof(uint8_t));

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
   temp[count] = '\0';

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

   temp_buf = (uint8_t **) calloc(ln_num, sizeof(uint8_t *));

   for (int i = 0; i < ln_num; ++i)
   {
      uint16_t count = 0;
      temp_buf[i] = NULL;
      while ((c = getc(fip)) != '\n')
      {
         temp_buf[i] = (uint8_t *) realloc(temp_buf[i], (count + 1) * sizeof(uint8_t));
         temp_buf[i][count] = c;
         count++;
      }
      temp_buf[i] = (uint8_t *) realloc(temp_buf[i], (count + 1) * sizeof(uint8_t));
      temp_buf[i][count] = '\0';
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

int isLittleEndian(void)
{
   int16_t i = 1;
   int8_t *p = (int8_t *) &i;

   if (p[0] == 1) 
      return 1;
   else 
      return 0;
}

void ss_free(void * p_buffer, uint64_t u64_length)
{
   if (p_buffer)
   {
      memset(p_buffer, 0, u64_length);
      free(p_buffer);
      p_buffer = NULL;
   }
}