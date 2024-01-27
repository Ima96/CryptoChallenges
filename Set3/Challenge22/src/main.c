/***********************************************************************************************************************
 * @file    main.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief 
 * 
 * @version 0.1
 * @date    22/01/2024
 * 
 * @copyright Copyright (c) 2024
 * 
 **********************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>

#include "crypto.h"

uint32_t seedAndGetPseudoRndNum(struct OMT19937 * po_mt);

int main(void)
{
   printf("=========== CryptoPals: Challenge 22 ===========\n");

   struct OMT19937 o_mt;
   OMT19937_init(&o_mt);
   uint32_t u32_rnd_num = seedAndGetPseudoRndNum(&o_mt);
   uint64_t u64_time_now = time(0);

   // Get seed
   uint32_t u32_found_seed = 0;
   for (int64_t i64_seconds = 1; i64_seconds < 25000; i64_seconds++)
   {
      uint32_t u32_possible_seed = u64_time_now - i64_seconds;
      OMT19937_seed_mt(&o_mt, u32_possible_seed);

      if (u32_rnd_num == OMT19937_get_num(&o_mt))
      {
         u32_found_seed = u32_possible_seed;
         break;
      }
   }

   if (u32_found_seed != 0)
   {
      printf("Found seed is %" PRIu32 "!\n", u32_found_seed);
   }
   else
   {
      printf("Either the seed is 0 or it has not been found...\n");
   }

   return EXIT_SUCCESS;
}

uint32_t seedAndGetPseudoRndNum(struct OMT19937 * po_mt)
{
   uint32_t u32_ret_val = 0;

   uint16_t u16_rnd_wait = random() % (1000 - 40 + 1) + 40;
   sleep(u16_rnd_wait);
   uint32_t u32_original_seed = time(0);
   printf("Originally used seed: %" PRIu32 "\n", u32_original_seed);
   OMT19937_seed_mt(po_mt, u32_original_seed);

   u16_rnd_wait = random() % (1000 - 40 + 1) + 40;
   sleep(u16_rnd_wait);
   u32_ret_val = OMT19937_get_num(po_mt);

   return u32_ret_val;
}
