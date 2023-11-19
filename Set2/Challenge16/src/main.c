
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto.h"
#include "BitflippingOracleCBC.h"

int main(void)
{  
   /* Our goal is to achieve a string ";admin=true;" after decryption with CBC. For this, we can encrypt
      a known plaintext, and then generate a pad with the known plaintext and the wanted string.
      XORing the previous block of the known plaintext with this pad will result in the XORed block to be
      totally scrambled but the next block (the one we want) to have the string desired.
    */

   printf("=========== CryptoPals: Challenge 16 ===========\n");

   int32_t i32_result = E_BOC_ERR;
   uint8_t * pu8_known_plaintext = NULL;
   uint16_t u16_known_ptxt_len = strlen(BOC_STR_TO_SEARCH) - 1;
   uint8_t * pu8_pad = NULL;
   uint8_t * pu8_iv = NULL;
   struct OBitflippingOracleCBC o_oracle;

   OBitflippingOracleCBC_init(&o_oracle);

   pu8_known_plaintext = (uint8_t *) calloc(u16_known_ptxt_len, sizeof(uint8_t));
   memset(pu8_known_plaintext, 'X', u16_known_ptxt_len);

   pu8_pad = (uint8_t *) calloc(u16_known_ptxt_len, sizeof(uint8_t));
   i32_result = FixedXOR(BOC_STR_TO_SEARCH, pu8_known_plaintext, u16_known_ptxt_len, u16_known_ptxt_len, pu8_pad);

   i32_result = OBitflippingOracleCBC_encrypt(&o_oracle, pu8_known_plaintext, u16_known_ptxt_len, &pu8_iv);
   printf("Stored message: %s\n", o_oracle.m_pu8_concat_str);

   i32_result = FixedXOR((o_oracle.m_pu8_encrypted_str)+16, pu8_pad, u16_known_ptxt_len, u16_known_ptxt_len, (o_oracle.m_pu8_encrypted_str)+16);

   i32_result = OBitflippingOracleCBC_check_admin_true(&o_oracle, pu8_iv);
   if (i32_result == E_BOC_OK)
   {
      printf("Result --> FOUND!!\n");
      uint8_t * pu8_decrypted = NULL;
      uint16_t u16_decrypted_len = 0;
      i32_result = OBitflippingOracleCBC_decrypt(&o_oracle, &pu8_decrypted, &u16_decrypted_len, pu8_iv);
      printf("  Decryption: %*s\n", u16_decrypted_len, pu8_decrypted);
      free(pu8_decrypted);
   }
   else if (i32_result == E_BOC_NOT_FOUND)
   {
      printf("Result --> NOT FOUND...\n");
      uint8_t * pu8_decrypted = NULL;
      uint16_t u16_decrypted_len = 0;
      i32_result = OBitflippingOracleCBC_decrypt(&o_oracle, &pu8_decrypted, &u16_decrypted_len, pu8_iv);
      printf("  Decryption: %*s\n", u16_decrypted_len, pu8_decrypted);
      free(pu8_decrypted);
   }
   else
   {
      printf("ERROR - Something went wrong...\n");
   }


   OBitflippingOracleCBC_destroy(&o_oracle);
   if (pu8_known_plaintext)
      free(pu8_known_plaintext);
   pu8_known_plaintext = NULL;
   
   if (pu8_pad)
      free(pu8_pad);
   pu8_pad = NULL;

   if (pu8_iv)
      free(pu8_iv);
   pu8_iv = NULL;

   return 0;
}