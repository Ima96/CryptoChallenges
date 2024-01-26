/***********************************************************************************************************************
 * @file    main.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * @brief   
 * 
 * @version 0.1
 * @date    20/11/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"
#include "encodings.h"
#include "misc.h"

int main(void)
{
   printf("=========== CryptoPals: Challenge 18 ===========\n");

   crypto_status e_status = CRYPTO_ERR;
   uint8_t au8_ciphertext_b64[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
   uint16_t u16_ciphertext_b64_len = strlen(au8_ciphertext_b64);

   uint16_t u16_ciphertext_len = 0;
   uint8_t * pu8_ciphertext = DecodeBase64(au8_ciphertext_b64, u16_ciphertext_b64_len, &u16_ciphertext_len);

   struct SAES128CTR_config s_ctr_config;
   memcpy(&(s_ctr_config.m_au8_key), "YELLOW SUBMARINE", AES128_KEY_SIZE);
   s_ctr_config.m_u64_nonce = 0;

   uint8_t * pu8_plaintext = NULL;
   e_status = AES128CTR_function(pu8_ciphertext, u16_ciphertext_len, s_ctr_config, &pu8_plaintext);
   if (e_status == CRYPTO_OK)
   {
      printf("The obtained plaintext is: \"%s\"\n", pu8_plaintext);
   }
   else
   {
      printf("Something went wrong...\n");
   }

   /* Clean up */
   ss_free(pu8_ciphertext, u16_ciphertext_len);
   ss_free(pu8_plaintext, u16_ciphertext_len);
}