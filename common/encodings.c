/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Source file containing the necessary definitions	 *
 * 				for some common encoding variables and operations.	 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#include <string.h>

#include "encodings.h"

/* Private global variables */
static const char Base64Digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int Base64Invs[] = { 
   62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 
   60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 
};

uint8_t *AsciiHex2Bin(uint8_t *AsciiEncoded, int size)
{
    uint8_t *hex_str = NULL;

   hex_str = malloc(size+1);
   for (int i = 0; i < size; i++)
   {
      if(AsciiEncoded[i] < 58 && AsciiEncoded[i] > 47)
      {
         hex_str[i] = AsciiEncoded[i] - 48; 
      }
      if(AsciiEncoded[i] < 103 && AsciiEncoded[i] > 96)
      {
         hex_str[i] = AsciiEncoded[i] - 87;
      }
   }

   hex_str[size] = '\0';

   return hex_str;
}

uint8_t *BinHex2Ascii(uint8_t *HexEncoded, int size)
{
    uint8_t *ascii_str = NULL;

   ascii_str = malloc(size+1);
   for (int i = 0; i < size; i++)
   {
      if (HexEncoded[i] < 10)
         ascii_str[i] = HexEncoded[i] + 48;

      if (HexEncoded[i] >= 10 && HexEncoded[i] < 16)
         ascii_str[i] = HexEncoded[i] + 87;
   }

   ascii_str[size] = '\0';

   return ascii_str;
}

uint8_t *Hex2Base64(uint8_t *HexEncoded, int size)
{
    uint8_t *base64_str = NULL;
   uint8_t first_char = 0, second_char = 0;
   int base64_str_size = 0;

   DEBUG_ENCODINGS("The size of HexEncoded string is: %d\n", size);

   // Size of base64 string is calculated with ratio of 2/3 from hex.
   base64_str_size = ceil(size * 2 / 3);
   base64_str = malloc(base64_str_size+1);
   DEBUG_ENCODINGS("The size of the resulting base64 string is: %d\n", base64_str_size);

   int cont = 0;
   for (int i = 0; i < size; i += 3)
   {

      first_char = (HexEncoded[i] & 0x0F) << 2;
      first_char = first_char | (HexEncoded[i+1] & 0x0C) >> 2;
      //DEBUG_ENCODINGS("Tries with the first element: %c\n", Base64Digits[first_char]);
      second_char = (HexEncoded[i+1] & 0x03) << 4 | (HexEncoded[i+2] & 0x0F);
      //DEBUG_ENCODINGS("Tries with the second element: %c\n", Base64Digits[second_char]);
      base64_str[cont++] = Base64Digits[first_char];
      base64_str[cont++] = Base64Digits[second_char];
   }

   base64_str[base64_str_size] = '\0';

   return base64_str;
}

uint8_t *Encode2Hex(uint8_t *ciphertext, uint16_t len)
{
   uint8_t *binHex = calloc(len*2, sizeof(uint8_t));

   uint32_t cont = 0;
   for (int i = 0; i < len; i++)
   {
      binHex[cont] = (ciphertext[i] >> 4) & 0x0F;
      binHex[cont+1] = ciphertext[i] & 0x0F;
      cont += 2; 
   }
   uint8_t *asciiHex = BinHex2Ascii(binHex, len*2);
   free(binHex);
   binHex = NULL;

   return asciiHex;
}

uint16_t B64DecodeSize(uint8_t const * const buf, uint16_t len)
{
   uint16_t res_len = (len * 3) / 4;

   for (uint16_t i = (len-1); i > 0; i--)
   {
      if (buf[i] == '=')
         res_len--;
      else
         break;
   }

   return res_len;
}

uint16_t B64EncodeSize(uint8_t const * const pu8_buf, uint16_t u16_len)
{
   uint16_t u16_ret = u16_len;

   if (u16_len % 3 != 0)
      u16_ret += 3 - (u16_len % 3);
   
   u16_ret /= 3;
   u16_ret *= 4;

   return u16_ret;
}

uint8_t *DecodeBase64(uint8_t *buf, uint16_t len, uint16_t *res_size)
{
   uint16_t res_len = B64DecodeSize(buf, len);
   uint8_t *decoded = calloc(res_len+1, sizeof(uint8_t));

   int v;
   for (uint16_t i = 0, j = 0; i < len; i += 4, j += 3) 
   {
      v = Base64Invs[buf[i]-43];
      v = (v << 6) | Base64Invs[buf[i+1]-43];
      v = buf[i+2] == '=' ? v << 6 : (v << 6) | Base64Invs[buf[i+2]-43];
      v = buf[i+3] == '=' ? v << 6 : (v << 6) | Base64Invs[buf[i+3]-43];

      decoded[j] = (v >> 16) & 0xFF;
      if (buf[i+2] != '=')
         decoded[j+1] = (v >> 8) & 0xFF;
      if (buf[i+3] != '=')
         decoded[j+2] = v & 0xFF;
   }
   decoded[res_len] = '\0';

   if (res_size != NULL)
      *res_size = res_len;
   return decoded;
}

uint8_t *EncodeBase64(uint8_t const * const pu8_buf, uint16_t const u16_len, uint16_t *u16_res_size)
{

   if (pu8_buf == NULL || u16_len == 0)
      return NULL;

   uint16_t u16_res_len = B64EncodeSize(pu8_buf, u16_len);
   uint8_t * pu8_encoded = (uint8_t *) calloc(u16_res_len + 1, sizeof(uint8_t));
   pu8_encoded[u16_res_len] = '\0';

   *u16_res_size = u16_res_len;

   int v;
   for (int i = 0, j = 0; i < u16_len; i += 3, j += 4)
   {
      v = pu8_buf[i];
      v = i + 1 < u16_len ? v << 8 | pu8_buf[i+1] : v << 8;
      v = i + 2 < u16_len ? v << 8 | pu8_buf[i+2] : v << 8;

      pu8_encoded[j] = Base64Digits[(v >> 18) & 0x3F];
      pu8_encoded[j+1] = Base64Digits[(v >> 12) & 0x3F];

      if (i+1 < u16_len)
         pu8_encoded[j+2] = Base64Digits[(v >> 6) & 0x3F];
      else
         pu8_encoded[j+2] = '=';

      if (i+2 < u16_len)
         pu8_encoded[j+3] = Base64Digits[v & 0x3F];
      else
         pu8_encoded[j+3] = '=';
   }

   return pu8_encoded;
}

uint8_t *ParseCookieAsJson(uint8_t const * const pu8_ck_buf)
{
   if (0 == strlen(pu8_ck_buf))
      return NULL;

   uint8_t * pu8_temp_buf = (uint8_t *) calloc(strlen(pu8_ck_buf), sizeof(uint8_t));
   memcpy(pu8_temp_buf, pu8_ck_buf, strlen(pu8_ck_buf));
   
   uint16_t u16_parsed_idx = 0;
   uint8_t * pu8_parsed = (uint8_t *) malloc(4 * sizeof(uint8_t));
   memcpy(pu8_parsed, "{\n\t", 3);
   u16_parsed_idx += 3;

   char delimiters[2] = {'=', '&'};
   char * token = strtok(pu8_temp_buf, delimiters);

   uint8_t u8_cont = 0;
   while (token != NULL)
   {
      pu8_parsed = realloc(pu8_parsed, u16_parsed_idx + strlen(token));
      memcpy(pu8_parsed + u16_parsed_idx, token, strlen(token));
      u16_parsed_idx += strlen(token);
      if ((u8_cont % 2) == 0)
      {
         pu8_parsed = realloc(pu8_parsed, u16_parsed_idx + 2);
         memcpy(pu8_parsed+u16_parsed_idx, ": ", 2);
         u16_parsed_idx += 2;
      }
      else
      {
         pu8_parsed = realloc(pu8_parsed, u16_parsed_idx + 3);
         memcpy(pu8_parsed+u16_parsed_idx, ",\n\t", 3);
         u16_parsed_idx += 3;
      }
      token = strtok(NULL, delimiters);
      u8_cont++;
   }

   pu8_parsed[u16_parsed_idx-3] = '\n';
   pu8_parsed[u16_parsed_idx-2] = '}';
   pu8_parsed[u16_parsed_idx-1] = '\0';

   if (pu8_temp_buf)
      free(pu8_temp_buf);
   pu8_temp_buf = NULL;

   return pu8_parsed;
}