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


int main(void)
{
   printf("=========== CryptoPals: Challenge 23 ===========\n");

   struct OMT19937 o_mt;
   OMT19937_init(&o_mt);

   uint32_t au32_initial_states[OMT19937_N] = {0};
   for (uint16_t u16_idx = 0; u16_idx < OMT19937_N; u16_idx++)
   {
      au32_initial_states[u16_idx] = MT19937_32_untemper_fnct(OMT19937_get_num(&o_mt));
   }

   // Clone generator
   struct OMT19937 o_cloned_mt;
   OMT19937_init(&o_cloned_mt);
   OMT19937_set_gen_state(&o_cloned_mt, au32_initial_states, OMT19937_N);

   for (uint32_t u32_idx = 0; u32_idx < 5000000; u32_idx++)
   {
      if (OMT19937_get_num(&o_mt) != OMT19937_get_num(&o_cloned_mt))
      {
         printf("Idx original: %u  /  Idx clonned: %u\n", o_mt.m_u32_index, o_cloned_mt.m_u32_index);
         printf("Error! Not same number\n");
         break;
      }

      if (u32_idx == (5000000-1))
      {
         printf("Generator cloned successfully!!\n");
      }
   }
   
   return EXIT_SUCCESS;
}