/***********************************************************************************************************************
 * @file    main.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Main program to solve Challenge 17 of cryptochallenges.
 * @version 0.1
 * @date    06/11/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "encodings.h"

int32_t random_select_and_CBC_encrypt(uint8_t ** ppu8_ciphertext, 
                                       uint16_t * pu16_chiphelen, 
                                       uint8_t a16_u8_iv[AES128_KEY_SIZE]);

uint8_t * pu8_a10_b64_string_pool[10] = 
{ 
   "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
   "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
   "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
   "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
   "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
   "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
   "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
   "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
   "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
   "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};

int main()
{

   printf("=========== CryptoPals: Challenge 17 ===========\n");

   uint8_t a16_u8_iv[AES128_KEY_SIZE] = {0};
   crypto_status e_status = CRYPTO_ERR;
   uint8_t * pu8_ciphertext = NULL;
   uint16_t u16_cipherlen = 0;
   e_status = random_select_and_CBC_encrypt(&pu8_ciphertext, &u16_cipherlen, a16_u8_iv);

   if (e_status != CRYPTO_OK)
   {
      printf("ERROR...\n");
      return EXIT_FAILURE;
   }

   uint8_t * pu8_obt_plaintxt = NULL;
   uint16_t u16_obt_plainlen = 0;
   e_status = AES128CBC_padding_oracle_attack(pu8_ciphertext, u16_cipherlen, a16_u8_iv, 
                                                &pu8_obt_plaintxt, &u16_obt_plainlen);

   if (e_status == CRYPTO_OK)
   {
      printf("Obtained plaintext after CBC padding oracle attack: \n\"%s\"\n", pu8_obt_plaintxt);
      uint8_t * pu8_original_plaintxt = NULL;
      int32_t i32_original_plainlen = 0;
      decryptBufferAesCbcStaticKey(pu8_ciphertext, u16_cipherlen, a16_u8_iv, &pu8_original_plaintxt, 
                                    &i32_original_plainlen);
      
      uint8_t * pu8_orig_plaintxt_unpad = NULL;
      uint32_t u32_orig_plainlen_unpad = 0;
      PKCS7_pad_strip(pu8_original_plaintxt, i32_original_plainlen, AES128_KEY_SIZE, &pu8_orig_plaintxt_unpad, 
                        &u32_orig_plainlen_unpad);
      
      if (pu8_original_plaintxt)
         free(pu8_original_plaintxt);

      if (0 == memcmp(pu8_orig_plaintxt_unpad, pu8_obt_plaintxt, u32_orig_plainlen_unpad))
      {
         printf("Result --> SUCCES!!\n");
      }
      else
      {
         printf("Result --> FAIL...\n"
                  "The strings do not match...\n"
                  "  Original string: %s\n"
                  "  Obtained string: %s\n",
                  pu8_orig_plaintxt_unpad,
                  pu8_obt_plaintxt);
      }

      if (pu8_orig_plaintxt_unpad)
         free(pu8_orig_plaintxt_unpad);
   }

   if (pu8_ciphertext)
      free(pu8_ciphertext);

   if (pu8_obt_plaintxt)
      free(pu8_obt_plaintxt);
   
   staticAesKeyRemove();

   return 0;
}

crypto_status random_select_and_CBC_encrypt(uint8_t ** ppu8_ciphertext, 
                                             uint16_t * pu16_chipherlen, 
                                             uint8_t a16_u8_iv[AES128_KEY_SIZE])
{
   crypto_status e_retval = CRYPTO_ERR;

   uint16_t u16_pool_rows = sizeof(pu8_a10_b64_string_pool)/sizeof(pu8_a10_b64_string_pool[0]);
   #ifdef DEBUG_MAIN
   printf("The ciphertext pool row size is: %d\n", u16_pool_rows);
   #endif
   
   srandom(time(NULL));
   uint16_t u16_rnd_pool_idx = (uint16_t) (random() % ((u16_pool_rows - 1) + 1));
   uint8_t * pu8_rnd_pool_str = pu8_a10_b64_string_pool[u16_rnd_pool_idx];
   uint16_t u16_rnd_pool_str_len = strlen(pu8_rnd_pool_str);
   printf("The selected random string is (index = %d): %s\n", u16_rnd_pool_idx, pu8_rnd_pool_str);

   uint16_t u16_rnd_pool_str_dcd_len = 0;
   uint8_t * pu8_rnd_pool_str_dcd = DecodeBase64(pu8_rnd_pool_str, u16_rnd_pool_str_len, &u16_rnd_pool_str_dcd_len);
   #ifdef DEBUG_MAIN
   printf("\n\nDecoded value is (len=%d): %s\n", u16_rnd_pool_str_dcd_len, pu8_rnd_pool_str_dcd);
   #endif

   e_retval = GeneratePseudoRandomBytes(a16_u8_iv, AES128_KEY_SIZE);
   if (e_retval == CRYPTO_OK)
   {
      uint8_t * pu8_temp_buf = NULL;
      uint16_t u16_temp_buf_len = 0;
      e_retval = encryptBufferAesCbcStaticKey(pu8_rnd_pool_str_dcd, u16_rnd_pool_str_dcd_len, 
                                                a16_u8_iv, &pu8_temp_buf, &u16_temp_buf_len);
      if (e_retval == CRYPTO_OK)
      {
         *ppu8_ciphertext = pu8_temp_buf;
         *pu16_chipherlen = u16_temp_buf_len;
      }
   }

   if (pu8_rnd_pool_str_dcd)
      free(pu8_rnd_pool_str_dcd);
   
   return e_retval;
}