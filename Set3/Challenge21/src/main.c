/***********************************************************************************************************************
 * @file    main.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Main program to solve Challenge 21 of cryptochallenges, implementing a MT19937 Mersenne Twister RNG.
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
#include <time.h>
#include <inttypes.h>

#include "crypto.h"
#include "encodings.h"
#include "misc.h"

int main(void)
{
   printf("=========== CryptoPals: Challenge 21 ===========\n");
   printf("The implementation of the MT19937 Mersenne Twister \n"
          "RNG is done inside the cryptopals library. The \n"
          "test of the correct implementation is done in the\n"
          "googleTest binary. This program only prints some\n"
          "PRNG values seeding the generator with current time.\n");

   struct OMT19937 o_mt;
   OMT19937_init(&o_mt);
   OMT19937_seed_mt(&o_mt, time(0));

   for (uint8_t u8_idx = 0; u8_idx < UINT8_MAX; u8_idx++)
   {
      printf("Rand num #%d: %" PRIu32 "\n", u8_idx, OMT19937_get_num(&o_mt));
   }

   printf("===================================================\n");
   printf("The implementation of the MT19937 Mersenne Twister \n"
          "RNG is done inside the cryptopals library. The \n"
          "test of the correct implementation is done in the\n"
          "googleTest binary. This program only prints some\n"
          "PRNG values seeding the generator with current time.\n");


   return EXIT_SUCCESS;
}