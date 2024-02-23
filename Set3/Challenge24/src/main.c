/***********************************************************************************************************************
 * @file    main.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief 
 * 
 * @version 0.1
 * @date    29/01/2024
 * 
 * @copyright Copyright (c) 2024
 * 
 **********************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include "crypto.h"
#include "misc.h"


int main(void)
{
   printf("=========== CryptoPals: Challenge 24 ===========\n");

   int32_t i32_ret = CRYPTO_ERR;
   uint8_t au8_known_plaintext[] = "AAAAAAAAAAAAAA";
   uint32_t u32_known_plainlen = strlen(au8_known_plaintext);

   uint8_t u8_rnd_prepend_len = 0;
   GeneratePseudoRandomBytes(&u8_rnd_prepend_len, 1);
   uint8_t * pu8_rnd_prepend = (uint8_t *) calloc(u8_rnd_prepend_len, sizeof(uint8_t));
   GeneratePseudoRandomBytes(pu8_rnd_prepend, u8_rnd_prepend_len);

   uint32_t u32_plainlen = u8_rnd_prepend_len + u32_known_plainlen;
   uint8_t * pu8_plaintext = (uint8_t *) calloc(u32_plainlen, sizeof(uint8_t));
   memcpy(pu8_plaintext, pu8_rnd_prepend, u8_rnd_prepend_len);
   memcpy(pu8_plaintext+u8_rnd_prepend_len, au8_known_plaintext, u32_known_plainlen);
   ss_free(pu8_rnd_prepend, u8_rnd_prepend_len);

   uint8_t * pu8_ciphertxt = NULL;
   uint16_t u16_seed = (time(0) & 0xFFFF);

   i32_ret = MT19937_32_cipher(pu8_plaintext, u32_plainlen, u16_seed, &pu8_ciphertxt);

   uint16_t u16_found_seed = 0;
   uint8_t * pu8_deciphertxt = NULL;
   i32_ret = MT19937_32_break_16bit_seed(pu8_ciphertxt, u32_plainlen, au8_known_plaintext, 
                                          &u16_found_seed, &pu8_deciphertxt);

   if (i32_ret == CRYPTO_OK)
   {
      printf("SUCCESS!! Found matching seed: %u (%u)\n", u16_found_seed, u16_seed);
   }
   else
   {
      printf("Could not find matching seed: %u (real) vs %u (found)\n", u16_seed, u16_found_seed);
   }

   ss_free(pu8_ciphertxt, u32_plainlen+1);
   ss_free(pu8_deciphertxt, u32_plainlen+1);

   uint8_t * pu8_token = NULL;
   i32_ret = MT19937_32_gen_16byte_token(&pu8_token);
   if (CRYPTO_OK == i32_ret)
   {
      printf("Token generated successfully --> ");
      for (uint8_t u8_idx = 0; u8_idx < 16; u8_idx++)
         printf("%02X ", pu8_token[u8_idx]);
      printf("\n");

      i32_ret = MT19937_32_verify_token(pu8_token);
      if (CRYPTO_OK == i32_ret)
      {
         printf("Token generated using MT19937\n");
      }
      else
      {
         printf("Error, it should return that is has been generated with the MT19937 generator...\n");
      }
   }
   else
   {
      printf("Error when generating token...\n");
   }

   uint8_t au16_invalid_token[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
   i32_ret = MT19937_32_verify_token(au16_invalid_token);
   if (CRYPTO_OK == i32_ret)
   {
      i32_ret = CRYPTO_ERR;
      printf("ERROR! Detected as token has generated using MT19937 when it is not.\n");
   }
   else
   {
      i32_ret = CRYPTO_OK;
      printf("Success, the token was not generated with MT19937!\n");
   }
   
   return i32_ret;
}