/***********************************************************************************************************************
 * @file    OMT19937.h
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Implementation of a MT19937-32 bit RNG generator object.
 * 
 * @version 0.1
 * @date    22/01/2024
 * 
 * @copyright Copyright (c) 2024
 * 
 **********************************************************************************************************************/

#include <stdint.h>

#define OMT19937_N   624

struct OMT19937
{
   uint32_t m_au32_mt[OMT19937_N];
   uint32_t m_u32_index;
};

/***********************************************************************************************************************
 * @brief   Initializes the index and generator states.
 * 
 * @param po_this[in/out]  Pointer to the object.
 **********************************************************************************************************************/
void OMT19937_init(struct OMT19937 * po_this);

/***********************************************************************************************************************
 * @brief   Function to seed the generator.
 * 
 * @param po_this[in/out]  Pointer to the object.
 * @param u32_seed[in]  Seed value.
 **********************************************************************************************************************/
void OMT19937_seed_mt(struct OMT19937 * po_this, uint32_t const u32_seed);

/***********************************************************************************************************************
 * @brief   Set the generator state to a user defined state and index. It enables to clone a generator.
 * 
 * @param po_this[in/out]     Pointer to the object.
 * @param au32_gen_state[in]  User-defined state.
 * @param u32_gen_idx[in]     User-defined index.
 **********************************************************************************************************************/
void OMT19937_set_gen_state(struct OMT19937 * po_this, uint32_t au32_gen_state[OMT19937_N], uint32_t u32_gen_idx);

/***********************************************************************************************************************
 * @brief   Interface to get new random value from the generator.
 * 
 * @param po_this[in/out]  Pointer to the object.
 * @return uint32_t  Returned random value.
 **********************************************************************************************************************/
uint32_t OMT19937_get_num(struct OMT19937 * po_this);