/***********************************************************************************************************************
 * @file    OMT19937.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Implementation of a MT19937-32 bit RNG generator object.
 * 
 * @version 0.1
 * @date 19/01/2024
 * 
 * @copyright Copyright (c) 2024
 * 
 **********************************************************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "OMT19937.h"

#define OMT19937_W   32
#define OMT19937_M   397
#define OMT19937_R   31

#define OMT19937_A   0x9908B0DF

#define OMT19937_U   11
#define OMT19937_D   0xFFFFFFFF

#define OMT19937_S   7
#define OMT19937_B   0x9D2C5680

#define OMT19937_T   15
#define OMT19937_C   0xEFC60000

#define OMT19937_L   18

#define OMT19937_F   1812433253

static void OMT19937_twist(struct OMT19937 * po_this);
static uint32_t OMT19937_extract_number(struct OMT19937 * const po_this);

static const uint64_t vf_u32_lower_mask = ((uint32_t)1 << OMT19937_R) - 1;
static const uint64_t vf_u32_upper_mask = (((uint64_t)1 << OMT19937_W) - 1) - vf_u32_lower_mask;

static void OMT19937_twist(struct OMT19937 * po_this)
{
   uint32_t * p_loc_mt = po_this->m_au32_mt;
   for (uint32_t u32_idx = 0; u32_idx < OMT19937_N; u32_idx++)
   {
      uint32_t u32_x = (p_loc_mt[u32_idx] & vf_u32_upper_mask) | (p_loc_mt[(u32_idx+1) % OMT19937_N] & vf_u32_lower_mask);
      uint32_t u32_xA = u32_x >> 1;
      if ((u32_x % 2) != 0)
      {
         u32_xA = u32_xA ^ OMT19937_A;
      }
      p_loc_mt[u32_idx] = p_loc_mt[(u32_idx+OMT19937_M) % OMT19937_N] ^ u32_xA;
   }
   po_this->m_u32_index = 0;
}

static uint32_t OMT19937_extract_number(struct OMT19937 * const po_this)
{
   if (po_this->m_u32_index >= OMT19937_N)
   {
      if (po_this->m_u32_index > OMT19937_N)
      {
         printf("WARNING! Generator was never seeded... Applying constant seed per reference C code!\n");
         OMT19937_seed_mt(po_this, 5489);
      }
      OMT19937_twist(po_this);
   }

   uint32_t u32_y = po_this->m_au32_mt[po_this->m_u32_index];
   u32_y = u32_y ^ ((u32_y >> OMT19937_U) & OMT19937_D);
   u32_y = u32_y ^ ((u32_y << OMT19937_S) & OMT19937_B);
   u32_y = u32_y ^ ((u32_y << OMT19937_T) & OMT19937_C);
   u32_y = u32_y ^ (u32_y >> OMT19937_L);

   po_this->m_u32_index++;

   return u32_y;
}

void OMT19937_init(struct OMT19937 * po_this)
{
   po_this->m_u32_index = OMT19937_N + 1;
   memset(po_this->m_au32_mt, 0, OMT19937_N * sizeof(uint32_t));
}

void OMT19937_seed_mt(struct OMT19937 * po_this, uint32_t const u32_seed)
{
   po_this->m_u32_index = OMT19937_N;
   uint32_t * p_loc_mt = po_this->m_au32_mt;
   p_loc_mt[0] = u32_seed;

   for (uint32_t u32_idx = 1; u32_idx < OMT19937_N; u32_idx++)
      p_loc_mt[u32_idx] = OMT19937_D & (OMT19937_F * (p_loc_mt[u32_idx-1] ^ (p_loc_mt[u32_idx-1] >> 
         (OMT19937_W-2))) + u32_idx);

}

void OMT19937_set_gen_state(struct OMT19937 * po_this, uint32_t au32_gen_state[OMT19937_N], uint32_t u32_gen_idx)
{
   for (uint16_t u16_idx = 0; u16_idx < OMT19937_N; u16_idx++)
   {
      po_this->m_au32_mt[u16_idx] = au32_gen_state[u16_idx];
   }
   po_this->m_u32_index = u32_gen_idx;
}

uint32_t OMT19937_get_num(struct OMT19937 * const po_this)
{
   return OMT19937_extract_number(po_this);
}