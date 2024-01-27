/***********************************************************************************************************************
 * @file    OArray.h
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * @brief 
 * 
 * @version 0.1
 * @date    19/01/2024
 * 
 * @copyright Copyright (c) 2024
 * 
 **********************************************************************************************************************/

#include <stdint.h>

struct OArray
{
   uint8_t     *m_pu8_data;   //!< Pointer to the stored array
   uint32_t    m_u32_length;  //!< Length of the array
};



