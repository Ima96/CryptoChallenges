/***********************************************************************************************************************
 * @file    BitflippingOracleCBC.c
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Source file of OBitflipplingOracleCBC object with the corresponding functionality.
 * 
 * @version 0.1
 * @date    30/10/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/

#include <stdlib.h>
#include <string.h>

#include "BitflippingOracleCBC.h"
#include "crypto.h"

static int32_t OBitflippingOracleCBC_check_init_str(struct OBitflippingOracleCBC const * const po_this);

static int32_t OBitflippingOracleCBC_set_strs(struct OBitflippingOracleCBC * const po_this,
                                                uint8_t const * const pu8_prepend_str, uint16_t const u16_prepend_len,
                                                uint8_t const * const pu8_append_str, uint16_t const u16_append_len
                                                );

static int32_t OBitflippingOracleCBC_conform_str(struct OBitflippingOracleCBC * po_this,
                                                   uint8_t const * const pu8_str,
                                                   uint16_t const u16_str_len);

static int32_t OBitflippingOracleCBC_condition_user_input(uint8_t const * const pu8_str,
                                                            uint16_t const u16_str_len,
                                                            uint8_t ** ppu8_conditioned_str);

static int32_t OBitflippingOracleCBC_AES128CBC_encrypt(struct OBitflippingOracleCBC * po_this, 
                                                         uint8_t const a_u8_iv[BOC_AES128_KEYSIZE]);

static int32_t OBitflippingOracleCBC_conform_and_encrypt(struct OBitflippingOracleCBC * po_this,
                                                         uint8_t const * const pu8_str,
                                                         uint16_t const u16_str_len, 
                                                         uint8_t const a_u8_iv[BOC_AES128_KEYSIZE]);

static int32_t OBitflippingOracleCBC_find_substring(uint8_t const * const pu8_base_str, 
                                                      uint16_t const u16_base_str_len);

static int32_t OBitflippingOracleCBC_find_bytes(uint8_t const * const pu8_haystack,
                                                uint16_t const u16_haystack_len, 
                                                uint8_t const * const pu8_needle,
                                                uint16_t const u16_needle_len);

/***********************************************************************************************************************
 * PUBLIC FUNCTIONS
 **********************************************************************************************************************/
void OBitflippingOracleCBC_init(struct OBitflippingOracleCBC * const po_this)
{
   memset(po_this->m_a_u8_prepend_str, 0, sizeof(po_this->m_a_u8_prepend_str));
   memset(po_this->m_a_u8_append_str, 0, sizeof(po_this->m_a_u8_append_str));
   po_this->m_pu8_concat_str = NULL;
   po_this->m_u16_concat_str_len = 0;
   po_this->m_pu8_encrypted_str = NULL;
   po_this->m_u16_encrypted_len = 0;
   // Set default strs
   memcpy(po_this->m_a_u8_prepend_str, BOC_DEFAULT_PREPEND, strlen(BOC_DEFAULT_PREPEND));
   memcpy(po_this->m_a_u8_append_str, BOC_DEFAULT_APPEND, strlen(BOC_DEFAULT_APPEND));

   // Generate random AES128 Key
   GenRndAES128Key(po_this->m_a_u8_aes_128_cbc_key);
}

void OBitflippingOracleCBC_init_with_strs(struct OBitflippingOracleCBC * const po_this,
                                          uint8_t const * const pu8_prepend_str, uint16_t const u16_prepend_len,
                                          uint8_t const * const pu8_append_str, uint16_t const u16_append_len)
{
   memset(po_this->m_a_u8_prepend_str, 0, sizeof(po_this->m_a_u8_prepend_str));
   memset(po_this->m_a_u8_append_str, 0, sizeof(po_this->m_a_u8_append_str));
   po_this->m_pu8_concat_str = NULL;
   po_this->m_u16_concat_str_len = 0;
   po_this->m_pu8_encrypted_str = NULL;
   po_this->m_u16_encrypted_len = 0;

   OBitflippingOracleCBC_set_strs(po_this ,pu8_prepend_str, u16_prepend_len, pu8_append_str, u16_append_len);
}

void OBitflippingOracleCBC_destroy(struct OBitflippingOracleCBC * const po_this)
{
   memset(po_this->m_a_u8_prepend_str, 0, sizeof(po_this->m_a_u8_prepend_str));
   memset(po_this->m_a_u8_append_str, 0, sizeof(po_this->m_a_u8_append_str));

   if (po_this->m_pu8_concat_str)
      free(po_this->m_pu8_concat_str);
   po_this->m_pu8_concat_str = NULL;
   po_this->m_u16_concat_str_len = 0;

   if (po_this->m_pu8_encrypted_str)
      free(po_this->m_pu8_encrypted_str);
   po_this->m_pu8_encrypted_str = NULL;
   po_this->m_u16_encrypted_len = 0;
}

int32_t OBitflippingOracleCBC_set_usr_str(struct OBitflippingOracleCBC * const po_this,
                                          uint8_t const * const pu8_usr_str,
                                          uint16_t const u16_usr_str_len)
{
   int32_t i32_result = E_BOC_OK;

   if (po_this == NULL || pu8_usr_str == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   if (u16_usr_str_len >= BOC_MAX_USR_STR_LEN)
   {
      i32_result = E_BOC_EINLIM;
   }
   else
   {
      uint8_t * pu8_conditioned_str = NULL;
      i32_result = OBitflippingOracleCBC_condition_user_input(pu8_usr_str, u16_usr_str_len, &pu8_conditioned_str);
      if (i32_result == E_BOC_OK)
      {
         i32_result = OBitflippingOracleCBC_conform_str(po_this, pu8_conditioned_str, u16_usr_str_len);
      }

      if (pu8_conditioned_str)
         free(pu8_conditioned_str);
      pu8_conditioned_str = NULL;
   }

   return i32_result;
}

int32_t OBitflippingOracleCBC_encrypt(struct OBitflippingOracleCBC * po_this,
                                       uint8_t const * const pu8_plaintext,
                                       uint16_t const u16_plaintext_len,
                                       uint8_t ** ppu8_iv_ctx)
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL || pu8_plaintext == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else if (E_BOC_OK != OBitflippingOracleCBC_check_init_str(po_this))
   {
      i32_result = E_BOC_ESTR_INIT;
   }
   else
   {
      if (*ppu8_iv_ctx == NULL)
      {
         *ppu8_iv_ctx = (uint8_t *) calloc(BOC_AES128_KEYSIZE+1, sizeof(uint8_t));
         i32_result = GeneratePseudoRandomBytes(*ppu8_iv_ctx, BOC_AES128_KEYSIZE);
         (*ppu8_iv_ctx)[BOC_AES128_KEYSIZE] = '\0';
      }

      i32_result = OBitflippingOracleCBC_conform_and_encrypt(po_this, pu8_plaintext, u16_plaintext_len, *ppu8_iv_ctx);
   }

   return i32_result;
}

int32_t OBitflippingOracleCBC_decrypt(struct OBitflippingOracleCBC * po_this, 
                                       uint8_t ** ppu8_decryption, 
                                       uint16_t * u16_decrypted_len, 
                                       uint8_t const * const pu8_iv)
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL || po_this->m_pu8_encrypted_str == NULL || pu8_iv == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else
   {
      uint8_t * pu8_temp_buf = NULL;
      uint16_t u16_temp_buf_len = 0;
      i32_result = AES128CBC_decrypt_OpenSSL(po_this->m_pu8_encrypted_str, po_this->m_u16_encrypted_len,
                                                po_this->m_a_u8_aes_128_cbc_key, pu8_iv, 
                                                &pu8_temp_buf, &u16_temp_buf_len);
      if (i32_result == E_BOC_OK)
      {
         uint8_t * pu8_plaintext = NULL;
         uint32_t u32_plaintxt_len = 0;
         i32_result = PKCS7_pad_strip(pu8_temp_buf, u16_temp_buf_len, BOC_AES128_KEYSIZE, 
                                       &pu8_plaintext, &u32_plaintxt_len);
         if (i32_result == E_BOC_OK)
         {
            *ppu8_decryption = pu8_plaintext;
            *u16_decrypted_len = u32_plaintxt_len;
         }
         if (pu8_temp_buf)
            free(pu8_temp_buf);
         pu8_temp_buf = NULL;
      }
   }

   return i32_result;
}

int32_t OBitflippingOracleCBC_check_admin_true(struct OBitflippingOracleCBC * po_this, uint8_t const * const pu8_iv)
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL || po_this->m_pu8_encrypted_str == NULL || pu8_iv == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else
   {
      uint8_t * pu8_decrypted_str = NULL;
      uint16_t u16_decrypted_len = 0;
      i32_result = OBitflippingOracleCBC_decrypt(po_this, &pu8_decrypted_str, &u16_decrypted_len, pu8_iv);
      if (i32_result == E_BOC_OK)
      {
         i32_result = OBitflippingOracleCBC_find_substring(pu8_decrypted_str, u16_decrypted_len);
         if (pu8_decrypted_str)
            free(pu8_decrypted_str);
         pu8_decrypted_str = NULL;
      }
   }

   return i32_result;
}

/***********************************************************************************************************************
 * PRIVATE FUNCTIONS
 **********************************************************************************************************************/
static int32_t OBitflippingOracleCBC_set_strs(struct OBitflippingOracleCBC * const po_this,
                                                uint8_t const * const pu8_prepend_str, uint16_t const u16_prepend_len,
                                                uint8_t const * const pu8_append_str, uint16_t const u16_append_len
                                                )
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL || pu8_prepend_str == NULL || pu8_append_str == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else if (u16_prepend_len >= BOC_MAX_PREPEND_LEN || u16_append_len >= BOC_MAX_APPEND_LEN)
   {
      i32_result = E_BOC_EINLIM;
   }
   else
   {
      memcpy(po_this->m_a_u8_prepend_str, pu8_prepend_str, u16_prepend_len);
      memcpy(po_this->m_a_u8_append_str, pu8_append_str, u16_append_len);
      i32_result = E_BOC_OK;
   }

   return i32_result;
}

static int32_t OBitflippingOracleCBC_check_init_str(struct OBitflippingOracleCBC const * const po_this)
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else
   {
      i32_result = E_BOC_ESTR_INIT;
      for (uint8_t u8_idx = 0; u8_idx < BOC_MAX_PREPEND_LEN; u8_idx++)
      {
         if (po_this->m_a_u8_prepend_str[u8_idx])
         {
            i32_result = E_BOC_OK;
            break;
         }
      }

      if (i32_result == E_BOC_OK)
      {
         i32_result = E_BOC_ESTR_INIT;
         for (uint8_t u8_idx = 0; u8_idx < BOC_MAX_APPEND_LEN; u8_idx++)
         {
            if (po_this->m_a_u8_append_str[u8_idx])
            {
               i32_result = E_BOC_OK;
               break;
            }
         }
      }
   }

   return i32_result;
}

static int32_t OBitflippingOracleCBC_conform_str(struct OBitflippingOracleCBC * po_this,
                                                         uint8_t const * const pu8_str,
                                                         uint16_t const u16_str_len)
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL || pu8_str == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else if (E_BOC_OK != OBitflippingOracleCBC_check_init_str(po_this))
   {
      i32_result = E_BOC_ESTR_INIT;
   }
   else
   {
      uint16_t u16_prepend_len = strlen(po_this->m_a_u8_prepend_str);
      uint16_t u16_append_len = strlen(po_this->m_a_u8_append_str);
      uint16_t u16_concat_calc_size = u16_prepend_len + u16_str_len + u16_append_len;
      po_this->m_pu8_concat_str = (uint8_t *) realloc(po_this->m_pu8_concat_str, (u16_concat_calc_size+1) * sizeof(uint8_t));
      memcpy(po_this->m_pu8_concat_str, po_this->m_a_u8_prepend_str, u16_prepend_len);
      memcpy(po_this->m_pu8_concat_str+u16_prepend_len, pu8_str, u16_str_len);
      memcpy(po_this->m_pu8_concat_str+u16_prepend_len+u16_str_len, po_this->m_a_u8_append_str, u16_append_len);
      po_this->m_pu8_concat_str[u16_concat_calc_size] = '\0';
      po_this->m_u16_concat_str_len = u16_concat_calc_size;
      i32_result = E_BOC_OK;
   }

   return i32_result;
}

static int32_t OBitflippingOracleCBC_condition_user_input(uint8_t const * const pu8_str,
                                                            uint16_t const u16_str_len,
                                                            uint8_t ** ppu8_conditioned_str)
{
   int32_t i32_result = E_BOC_ERR;

   if (pu8_str == NULL || ppu8_conditioned_str == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else
   {
      uint8_t * pu8_temp_buf = (uint8_t *) calloc(u16_str_len + 1, sizeof(uint8_t));
      for (uint16_t u16_idx = 0; u16_idx < u16_str_len; u16_idx++)
      {
         if (pu8_str[u16_idx] == '=' || pu8_str[u16_idx] == ';')
         {
            pu8_temp_buf[u16_idx] = '-';
         }
         else
         {
            pu8_temp_buf[u16_idx] = pu8_str[u16_idx];
         }
      }
      pu8_temp_buf[u16_str_len] = '\0';

      *ppu8_conditioned_str = pu8_temp_buf;
      i32_result = E_BOC_OK;
   }

   return i32_result;
}

static int32_t OBitflippingOracleCBC_AES128CBC_encrypt(struct OBitflippingOracleCBC * po_this, 
                                                         uint8_t const a_u8_iv[BOC_AES128_KEYSIZE])
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL || po_this->m_pu8_concat_str == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else
   {
      uint8_t * pu8_temp_buf = NULL;
      uint16_t u16_temp_buf_len = 0;
      if (po_this->m_pu8_encrypted_str)
         free(po_this->m_pu8_encrypted_str);
      po_this->m_pu8_encrypted_str = NULL;
      i32_result = AES128CBC_encrypt_OpenSSL(po_this->m_pu8_concat_str, po_this->m_u16_concat_str_len,
                                                po_this->m_a_u8_aes_128_cbc_key, a_u8_iv,
                                                &pu8_temp_buf, &u16_temp_buf_len);
      if (i32_result == E_BOC_OK)
      {
         po_this->m_pu8_encrypted_str = pu8_temp_buf;
         po_this->m_u16_encrypted_len = u16_temp_buf_len;
      }
   }

   return i32_result;
}

static int32_t OBitflippingOracleCBC_conform_and_encrypt(struct OBitflippingOracleCBC * po_this,
                                                         uint8_t const * const pu8_str,
                                                         uint16_t const u16_str_len, 
                                                         uint8_t const a_u8_iv[BOC_AES128_KEYSIZE])
{
   int32_t i32_result = E_BOC_ERR;

   if (po_this == NULL || pu8_str == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else
   {
      i32_result = OBitflippingOracleCBC_set_usr_str(po_this, pu8_str, u16_str_len);
      if (i32_result == E_BOC_OK)
      {
         i32_result = OBitflippingOracleCBC_AES128CBC_encrypt(po_this, a_u8_iv);
      }
   }

   return i32_result;
}

static int32_t OBitflippingOracleCBC_find_substring(uint8_t const * const pu8_base_str, 
                                                      uint16_t const u16_base_str_len)
{
   int32_t i32_result = E_BOC_ERR;

   if (pu8_base_str == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else if (u16_base_str_len < strlen(BOC_STR_TO_SEARCH))
   {
      i32_result = E_BOC_EINLIM;
   }
   else
   {
      i32_result = OBitflippingOracleCBC_find_bytes(pu8_base_str, u16_base_str_len,
                                                      BOC_STR_TO_SEARCH, strlen(BOC_STR_TO_SEARCH));
   }

   return i32_result;
}

static int32_t OBitflippingOracleCBC_find_bytes(uint8_t const * const pu8_haystack,
                                                uint16_t const u16_haystack_len, 
                                                uint8_t const * const pu8_needle,
                                                uint16_t const u16_needle_len)
{
   int32_t i32_result = E_BOC_NOT_FOUND;

   if (pu8_haystack == NULL || pu8_needle == NULL)
   {
      i32_result = E_BOC_EINVAL;
   }
   else if (u16_haystack_len < u16_needle_len)
   {
      i32_result = E_BOC_EINLIM;
   }
   else
   {
      for (uint16_t u16_idx = 0; u16_idx < (u16_haystack_len-u16_needle_len); u16_idx++)
      {
         if (0 == memcmp(&pu8_haystack[u16_idx], pu8_needle, u16_needle_len))
         {
            i32_result = E_BOC_OK;
            break;
         }
      }
   }

   return i32_result;
}