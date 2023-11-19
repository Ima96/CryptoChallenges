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
// Exec command
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include "gtest/gtest.h"
#include "golden.h"
// #include "crypto.h"
// #include "encodings.h"
// #include "misc.h"

std::string exec(const char* cmd) {
   std::array<char, 128> buffer;
   std::string result;
   std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
   if (!pipe) {
      throw std::runtime_error("popen() failed!");
   }
   while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
      result += buffer.data();
   }
   return result;
}

TEST(Set1, ch1_Hex2Base64)
{
   std::string cmd_result = exec("./ch1_hex2base64");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch1_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch1_golden_result), ch1_golden_result.length()) << std::endl;
}

TEST(Set1, ch2_FixedXOR)
{
   std::string cmd_result = exec("./ch2_XOR");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch2_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch2_golden_result), ch2_golden_result.length()) << std::endl;
}

TEST(Set1, ch3_SingleByteXORCipher)
{
   std::string cmd_result = exec("./ch3_decipher");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch3_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch3_golden_result), ch3_golden_result.length()) << std::endl;
}

TEST(Set1, ch4_DetectSingleByteXOR)
{
   std::string cmd_result = exec("./ch4_detect");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch4_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch4_golden_result), ch4_golden_result.length()) << std::endl;

}

TEST(Set1, ch5_RepeatingKeyXOR)
{
   std::string cmd_result = exec("./ch5_encript-rkxor ./resources/plaintext5.txt ICE");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch5_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch5_golden_result), ch5_golden_result.length()) << std::endl;
}

TEST(Set1, ch6_BreakRepeatingKeyXOR)
{
   std::string cmd_result = exec("./ch6_break-rkxor ./resources/ciphertext6.txt");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch6_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch6_golden_result), ch6_golden_result.length()) << std::endl;
}

TEST(Set1, ch7_AES_ECB)
{
   std::string cmd_result = exec("./ch7_decrypt_aes-ecb ./resources/ciphertext7.txt");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch7_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch7_golden_result), ch7_golden_result.length()) << std::endl;
}

TEST(Set1, ch8_DetectAES_ECB)
{
   std::string cmd_result = exec("./ch8_detect_aes-ecb ./resources/ciphertext8.txt");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch8_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch8_golden_result), ch8_golden_result.length()) << std::endl;
}

TEST(Set2, ch9_PKCS7_Padding)
{
   std::string cmd_result = exec("./ch9_pad-pkcs7");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch9_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch9_golden_result), ch9_golden_result.length()) << std::endl;
}

TEST(Set2, ch10_ImplementCBC)
{
   std::string cmd_result = exec("./ch10_decrypt-cbc ./resources/ciphertext10.txt");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch10_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch10_golden_result), ch10_golden_result.length()) << std::endl;
}

TEST(Set2, ch11_ECB_CBC_Oracle)
{
   std::cout << "Challenge 11 takes a little time, its executing..." << std::endl;
   std::string cmd_result = exec("./ch11_oracle");
   
   std::string current_string;
   std::vector<std::string> lines;
   for (uint16_t u16_idx = 0; u16_idx < cmd_result.length(); u16_idx++)
   {
      char c_current_char = cmd_result[u16_idx];
      if (c_current_char == '\n')
      {
         lines.push_back(current_string);
         current_string.clear();
      }
      else
         current_string.push_back(c_current_char);
   }
   
   // Check correct detection
   for (uint16_t u16_idx = 0; u16_idx < lines.size(); u16_idx += 2)
   {
      if (lines[u16_idx].find("Using CBC") != std::string::npos)
         ASSERT_NE(std::string::npos, lines[u16_idx+1].find("Detected CBC!!"));
      else if (lines[u16_idx].find("Using ECB") != std::string::npos)
         ASSERT_NE(std::string::npos, lines[u16_idx+1].find("Detected ECB!"));
      else
         FAIL();
   }
}

TEST(Set2, ch12_Byte_At_A_Time)
{
   std::string cmd_result = exec("./ch12_baat_ecb_break");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch12_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch12_golden_result), ch12_golden_result.length()) << std::endl;
}

TEST(Set2, ch13_ecb_cut_n_paste)
{
   std::string cmd_result = exec("./ch13_ecb_cut_n_paste");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch13_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch13_golden_result), ch13_golden_result.length()) << std::endl;
}

TEST(Set2, ch14_ecb_baat_harder)
{
   std::string cmd_result = exec("./ch14_ecb_baat_harder");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch14_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch14_golden_result), ch14_golden_result.length()) << std::endl;
}

TEST(Set2, ch15_pkcs7_validation)
{
   std::string cmd_result = exec("./ch15_pkcs7_validation");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch15_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch15_golden_result), ch15_golden_result.length()) << std::endl;
}

TEST(Set2, ch16_bitflipping_cbc)
{
   std::string cmd_result = exec("./ch16_bitflipping_cbc");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch16_golden_result)) << 
      "The otput from the command execution is:" << std::endl << cmd_result << std::endl;

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch16_golden_result), ch16_golden_result.length()) << std::endl;
}

TEST(Set3, ch17_cbc_padding_oracle)
{
   std::string cmd_result = exec("./ch17_cbc_padding_oracle");
   
   ASSERT_NE(std::string::npos, cmd_result.find(ch17_golden_result));

   std::cout << "Found golden string in result --> " <<
      cmd_result.substr(cmd_result.find(ch17_golden_result), ch17_golden_result.length()) << std::endl;
}