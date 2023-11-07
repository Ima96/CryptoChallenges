/***********************************************************************************************************************
 * @file    tests.cpp
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   File that contains the suit of tests to verify that the challenges are completed, and to make sure that 
 *          changes to routines in common libraries and routines do not alter the result of previous challenges.
 * 
 * @version 0.1
 * @date    06/11/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/
#include <iostream>
#include <stdint.h>

#include "gtest/gtest.h"
#include "crypto.h"
#include "encodings.h"
#include "misc.h"


TEST(Set1, ch1_Hex2Base64)
{
   uint8_t au8_ascii_hex_in[] = 
               "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
   int32_t i32_ascii_hex_len = sizeof(au8_ascii_hex_in) - 1;

   std::cout << "The hex(ascii) string: " << au8_ascii_hex_in << std::endl;

   uint8_t * pu8_hex = AsciiHex2Bin(au8_ascii_hex_in, i32_ascii_hex_len);

   uint8_t * pu8_base64 = Hex2Base64(pu8_hex, i32_ascii_hex_len);

   uint8_t au8_base64_golden[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

   char * pc_str_golden = reinterpret_cast<char *>(au8_base64_golden);
   char * pc_str_candidate = reinterpret_cast<char *>(pu8_base64);
   ASSERT_STREQ(pc_str_golden, pc_str_candidate);

   std::cout << "Obtained Base64 string is: " << pc_str_candidate << std::endl;
   
   free(pu8_hex);
   free(pu8_base64);
}

TEST(Set1, ch2_FixedXOR)
{
   uint8_t au8_buff1[] = "1c0111001f010100061a024b53535009181c";
   uint8_t au8_buff2[] = "686974207468652062756c6c277320657965";
   int32_t i32_buff1_sz = sizeof(au8_buff1) - 1;
   int32_t i32_buff2_sz = sizeof(au8_buff2) - 1;

   uint8_t * pu8_hex_buff1 = AsciiHex2Bin(au8_buff1, i32_buff1_sz);
   uint8_t * pu8_hex_buff2 = AsciiHex2Bin(au8_buff2, i32_buff2_sz);

   uint8_t * pu8_XORed_bin = new uint8_t [i32_buff1_sz];
   ASSERT_EQ(CRYPTO_OK, FixedXOR(pu8_hex_buff1, pu8_hex_buff2, i32_buff1_sz, i32_buff2_sz, pu8_XORed_bin));

   uint8_t * pu8_XORed_ascii = BinHex2Ascii(pu8_XORed_bin, i32_buff1_sz);

   uint8_t au8_golden_res[] = "746865206b696420646f6e277420706c6179";
   char * pc_str_golden = reinterpret_cast<char *>(au8_golden_res);
   char * pc_str_candidate = reinterpret_cast<char *>(pu8_XORed_ascii);
   ASSERT_STREQ(pc_str_golden, pc_str_candidate);

   std::cout << "Obtained XORed string is: " << pc_str_candidate << std::endl;

   free(pu8_hex_buff1);
   free(pu8_hex_buff2);
   delete [] pu8_XORed_bin;
}

TEST(Set1, ch3_SingleByteXORCipher)
{
   uint8_t au8_the_string[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
   uint8_t * pu8_hex_string = NULL;
   int32_t i32_string_sz = 0;

   printf("The encrypted string: %s\n", au8_the_string);

   i32_string_sz = sizeof(au8_the_string) - 1;
   pu8_hex_string = AsciiHex2Bin(au8_the_string, i32_string_sz);

   float f_score = 0, f_best_score = 10000;
   uint8_t u8_best_key_candidate = 0;
   uint8_t * pu8_decryption_attempt = new uint8_t [i32_string_sz];
   uint8_t * pu8_best_decryption_attempt = new uint8_t [i32_string_sz + 1];
   for (uint8_t i = 32; i < 127; i++)
   {
      uint8_t u8_current_key_attempt;
      int32_t i32_decrypt_size = 0;

      u8_current_key_attempt = i;

      ASSERT_EQ(CRYPTO_OK, FixedXOR_SingleChar(pu8_hex_string, u8_current_key_attempt, 
                                                i32_string_sz, pu8_decryption_attempt, 
                                                &i32_decrypt_size));

      English_Score(pu8_decryption_attempt, i32_decrypt_size, &f_score);

      if (f_score < f_best_score)
      {
         f_best_score = f_score;
         u8_best_key_candidate = u8_current_key_attempt;
         memcpy(pu8_best_decryption_attempt, pu8_decryption_attempt, i32_decrypt_size);
         pu8_best_decryption_attempt[i32_decrypt_size] = '\0';
      }
   }

   printf("========================================================================\n");
   printf("The best key candidate for the decryption is: %c\n", u8_best_key_candidate);

   char ac_golden_res[] = "Cooking MC's like a pound of bacon";
   char * pc_candidate_res = reinterpret_cast<char *>(pu8_best_decryption_attempt);
   ASSERT_STREQ(ac_golden_res, pc_candidate_res);

   printf("The decryption result is:\n\"%s\"\n", pu8_best_decryption_attempt);

   free(pu8_hex_string);
   pu8_hex_string = NULL;

   delete [] pu8_decryption_attempt;
   delete [] pu8_best_decryption_attempt;
}

TEST(Set1, ch4_DetectSingleByteXOR)
{
   FILE * ps_fin = NULL;
   uint16_t u16_line_count = 0;
   char ac_filename[125] = "./resources/ciphertext4.txt";

   ps_fin = fopen(ac_filename, "rb");
   ASSERT_NE(nullptr, ps_fin) << "Run the test binary from inside the bin folder, "
                                 "and ensure access to \"./resources/ciphertext4.txt\"\n";

   uint8_t ** ppu8_file_strings = readFileLines(ps_fin, &u16_line_count);
   ASSERT_NE(nullptr, ppu8_file_strings);

   uint8_t * pu8_hex_line = NULL;
   uint8_t * pu8_line = NULL;
   uint8_t * pu8_decrypted_buff = NULL;
   uint8_t * pu8_message = NULL;
   uint16_t u16_line_len = 0;
   uint16_t u16_decrypted_buff_len = 0;
   float f_line_score = 0;
   float f_best_line_score = 10000;
   uint16_t u16_line_detected = 0;

   for(uint16_t u16_idx = 0; u16_idx < u16_line_count; u16_idx++)
   {
      pu8_line = ppu8_file_strings[u16_idx];
      u16_line_len = strlen(reinterpret_cast<char *>(pu8_line));
      pu8_hex_line = AsciiHex2Bin(pu8_line, u16_line_len);

      if(pu8_decrypted_buff)
         free(pu8_decrypted_buff);
      pu8_decrypted_buff = new uint8_t [u16_line_len];//(uint8_t *)calloc(u16_line_len, sizeof(uint8_t));
      ASSERT_EQ(CRYPTO_OK, BreakFixedXOR(pu8_hex_line, u16_line_len, pu8_decrypted_buff, 
                                          &u16_decrypted_buff_len, &f_line_score));
      
      free(pu8_hex_line);
      pu8_hex_line = NULL;

      if (f_line_score < f_best_line_score)
      {
         u16_line_detected = u16_idx;
         f_best_line_score = f_line_score;
         if (pu8_message)
            free(pu8_message);
         pu8_message = new uint8_t [u16_decrypted_buff_len+1]; //(uint8_t *) calloc(u16_decrypted_buff_len+1, sizeof(uint8_t));
         memcpy(pu8_message, pu8_decrypted_buff, u16_decrypted_buff_len);
         pu8_message[u16_decrypted_buff_len] = '\0';
      }
   }

   ASSERT_EQ(170, u16_line_detected);

   char ac_golden_res[] = "Now that the party is jumping\n";
   char * pc_candidate_res = reinterpret_cast<char *>(pu8_message);
   ASSERT_STREQ(pc_candidate_res, ac_golden_res);

   std::cout << "The detected string is in line #" << u16_line_detected 
               << " and is the following\n\"" << pu8_message << "\"" << std::endl;

}

TEST(Set1, ch5_RepeatingKeyXOR)
{
   
}