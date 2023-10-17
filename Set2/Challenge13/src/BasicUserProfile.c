
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "BasicUserProfile.h"
#include <crypto/crypto.h>

static int32_t OBasicUserProfile_check_input_data(uint8_t const * const pu8_in_mail);

static int32_t OBasicUserProfile_get_role_str(enum EBasicUserRoles const e_role,
                                                uint8_t * const pu8_str_buf);

static int32_t OBasicUserProfile_get_role_enum(uint8_t const * const pu8_str_buf,
                                                enum EBasicUserRoles * pe_role);

static int32_t OBasicUserProfile_encode_as_cookie(struct OBasicUserProfile * const po_this,
                                                   uint8_t const * const pu8_email);

static int32_t OBasicUserProfile_encrypt_cookie(struct OBasicUserProfile * const po_this);

static int32_t OBasicUserProfile_parse_cookie(struct OBasicUserProfile * const po_this, 
                                                uint8_t const * const pu8_cookie_str);

static uint16_t vf_u16_uid_counter = 0;

void OBasicUserProfile_create(struct OBasicUserProfile * const po_this)
{
   memset(po_this, 0, sizeof(*po_this));
   po_this->m_e_role = E_NOUSER;
   po_this->m_pu8_encrypted_cookie = NULL;
}

static int32_t OBasicUserProfile_check_input_data(uint8_t const * const pu8_in_mail)
{
   int32_t i32_return = E_BUP_ERR;

   if (pu8_in_mail == NULL)
   {
      i32_return = E_BUP_ERR_INVAL;
   }
   else
   {
      uint8_t * pu8_temp_str = (uint8_t *) calloc(strlen(pu8_in_mail) + 1, sizeof(uint8_t));
      memcpy(pu8_temp_str, pu8_in_mail, strlen(pu8_in_mail) + 1);
      uint8_t a2_u8_delimiters[2] = {'=', '&'};
      uint8_t * pu8_token = strtok(pu8_temp_str, a2_u8_delimiters);
      pu8_token = strtok(NULL, a2_u8_delimiters); // second call

      if (pu8_token == NULL)
      {
         i32_return = E_BUP_OK;
      }
      else
      {
         i32_return = E_BUP_ERR_INVAL;
      }

      if (pu8_temp_str)
         free(pu8_temp_str);
      pu8_temp_str = NULL;
   }

   return i32_return;
}

static int32_t OBasicUserProfile_encrypt_cookie(struct OBasicUserProfile * const po_this)
{
   int32_t i32_return = E_BUP_ERR;

   i32_return = encryptBufferAesEcbStaticKey(po_this->m_au8_encoded_profile, 
                                 strlen(po_this->m_au8_encoded_profile), 
                                 &po_this->m_pu8_encrypted_cookie,
                                 &po_this->m_i32_enc_len
                              );

   return i32_return;
}

int32_t OBasicUserProfile_gen_profile(
   struct OBasicUserProfile * po_this,
   uint8_t const * const pu8_email
)
{
   int32_t i32_return = E_BUP_ERR;

   if (po_this == NULL || pu8_email == NULL || strlen(pu8_email) == 0)
   {
      i32_return = E_BUP_ERR_INVAL;
   }
   else if (strlen(pu8_email) >= BUP_EMAIL_MAX_LEN)
   {
      i32_return = E_BUP_ERR_RANGE;
   }
   else if ((i32_return = OBasicUserProfile_check_input_data(pu8_email)) != E_BUP_OK)
   {
      i32_return = E_BUP_ERR_INVAL;
   }
   else if (po_this->m_pu8_encrypted_cookie != NULL)
   {
      // Already created profile...
      i32_return = E_BUP_OK;
   }
   else
   {
      i32_return = OBasicUserProfile_encode_as_cookie(po_this, pu8_email);

      if (i32_return == E_BUP_OK)
      {
         i32_return = OBasicUserProfile_parse_cookie(po_this, po_this->m_au8_encoded_profile);
      }

      if (i32_return == E_BUP_OK)
      {
         i32_return = OBasicUserProfile_encrypt_cookie(po_this);
      }
   }

   return i32_return;
}

void OBasicUserProfile_print_json(struct OBasicUserProfile const * const po_this)
{
   if (po_this == NULL)
      return;

   uint8_t a11_u8_role_str[11] = {0};
   OBasicUserProfile_get_role_str(po_this->m_e_role, a11_u8_role_str);
   printf(  "{\n"
            "  email: %s\n"
            "  uid: %d\n"
            "  role: %s\n"
            "}\n",
            po_this->m_a100_u8_email,
            po_this->m_u16_uid,
            a11_u8_role_str
         );
}

static int32_t OBasicUserProfile_get_role_str(enum EBasicUserRoles const e_role,
                                                uint8_t * const pu8_str_buf
                                             )
{
   int32_t i32_return = E_BUP_ERR;

   switch (e_role)
   {
      case E_NOUSER:       memcpy(pu8_str_buf, "no-user", 8); i32_return = E_BUP_OK; break;
      case E_USER:         memcpy(pu8_str_buf, "user", 5); i32_return = E_BUP_OK; break;
      case E_ADMIN:        memcpy(pu8_str_buf, "admin", 6); i32_return = E_BUP_OK; break;
      case E_OPERATOR:     memcpy(pu8_str_buf, "operator", 9); i32_return = E_BUP_OK; break;
      case E_MAINTAINER:   memcpy(pu8_str_buf, "maintainer", 11); i32_return = E_BUP_OK; break;
      case E_INTEGRATOR:   memcpy(pu8_str_buf, "integrator", 11); i32_return = E_BUP_OK; break;
      default: 
         i32_return = E_BUP_ERR; 
         break;
   }

   return i32_return;
}

static int32_t OBasicUserProfile_get_role_enum(uint8_t const * const pu8_str_buf,
                                                enum EBasicUserRoles * const pe_role)
{
   int32_t i32_return = E_BUP_ERR;
   enum EBasicUserRoles e_local_role = E_USER;

   if (pu8_str_buf == NULL || strlen(pu8_str_buf) == 0)
   {
      i32_return = E_BUP_ERR_INVAL;
   }
   else
   {
      if (0 == memcmp(pu8_str_buf, "no-user", 7))           {e_local_role = E_NOUSER; i32_return = E_BUP_OK;}
      else if (0 == memcmp(pu8_str_buf, "user", 4))         {e_local_role = E_USER; i32_return = E_BUP_OK;}
      else if (0 == memcmp(pu8_str_buf, "admin", 5))        {e_local_role = E_ADMIN; i32_return = E_BUP_OK;}
      else if (0 == memcmp(pu8_str_buf, "operator", 8))     {e_local_role = E_OPERATOR; i32_return = E_BUP_OK;}
      else if (0 == memcmp(pu8_str_buf, "integrator", 10))  {e_local_role = E_INTEGRATOR; i32_return = E_BUP_OK;}
      else if (0 == memcmp(pu8_str_buf, "maintainer", 10))  {e_local_role = E_MAINTAINER; i32_return = E_BUP_OK;}
      else  {e_local_role = E_USER; i32_return = E_BUP_ERR;}

      if (i32_return == E_BUP_OK)
         *pe_role = e_local_role;
   }

   return i32_return;
}

static int32_t OBasicUserProfile_encode_as_cookie(struct OBasicUserProfile * const po_this,
                                                   uint8_t const * const pu8_email
                                                )
{
   int32_t i32_return = E_BUP_ERR;

   if (po_this == NULL)
   {
      i32_return = E_BUP_ERR_INVAL;
   }
   else
   {
      uint16_t u16_idx = 0;
      memcpy(po_this->m_au8_encoded_profile, "email=", 6);
      u16_idx += 6;

      memcpy(po_this->m_au8_encoded_profile+u16_idx, pu8_email, strlen(pu8_email));
      u16_idx += strlen(pu8_email);

      memcpy(po_this->m_au8_encoded_profile+u16_idx, "&uid=", 5);
      u16_idx += 5;

      uint8_t a6_u8_uid_str[6] = {0};
      sprintf(a6_u8_uid_str, "%" PRIu16, vf_u16_uid_counter);
      vf_u16_uid_counter++;
      memcpy(po_this->m_au8_encoded_profile+u16_idx, a6_u8_uid_str, strlen(a6_u8_uid_str));
      u16_idx += strlen(a6_u8_uid_str);

      memcpy(po_this->m_au8_encoded_profile+u16_idx, "&role=", 6);
      u16_idx += 6;

      uint8_t a11_u8_role_str[11] = {0};
      i32_return = OBasicUserProfile_get_role_str(E_USER, a11_u8_role_str);
      if (i32_return == E_BUP_OK)
      {
         memcpy(po_this->m_au8_encoded_profile+u16_idx, a11_u8_role_str, strlen(a11_u8_role_str));
         u16_idx += strlen(a11_u8_role_str);
         po_this->m_au8_encoded_profile[u16_idx] = '\0';
         i32_return = E_BUP_OK;
      }
   }

   return i32_return;
}

int32_t OBasicUserProfile_decrypt_and_parse(struct OBasicUserProfile * const po_this)
{
   int32_t i32_return = E_BUP_ERR;

   if (po_this == NULL)
   {
      i32_return = E_BUP_ERR_INVAL;
   }
   else
   {
      uint8_t * pu8_decrypted_cookie = NULL;
      int32_t i32_decrypted_cookie_len = 0;

      i32_return = decryptBufferAesEcbStaticKey(po_this->m_pu8_encrypted_cookie, 
                                                po_this->m_i32_enc_len,
                                                &pu8_decrypted_cookie,
                                                &i32_decrypted_cookie_len);
      
      printf("Decrypted cookie: %s\n", pu8_decrypted_cookie);

      if (i32_return == E_BUP_OK)
      {
         i32_return = OBasicUserProfile_parse_cookie(po_this, pu8_decrypted_cookie);
      }

      if (pu8_decrypted_cookie)
         free(pu8_decrypted_cookie);
      pu8_decrypted_cookie = NULL;
   }

   return i32_return;
}

static int32_t OBasicUserProfile_parse_cookie(struct OBasicUserProfile * const po_this, 
                                                uint8_t const * const pu8_cookie_str)
{
   int32_t i32_return = E_BUP_ERR;

   if (pu8_cookie_str == NULL || 0 == strlen(pu8_cookie_str))
   {
      i32_return = E_BUP_ERR_INVAL;
   }
   else
   {
      uint8_t * pu8_temp_buf = (uint8_t *) calloc(strlen(pu8_cookie_str) + 1, sizeof(uint8_t));
      memcpy(pu8_temp_buf, pu8_cookie_str, strlen(pu8_cookie_str) + 1);

      uint8_t delimiters[2] = {'=', '&'};
      uint8_t * pu8_token = strtok(pu8_temp_buf, delimiters);
      while (pu8_token != NULL)
      {
         if (0 == memcmp(pu8_token, "email", 5))
         {
            pu8_token = strtok(NULL, delimiters);
            memcpy(po_this->m_a100_u8_email, pu8_token, strlen(pu8_token));
         }
         else if (0 == memcmp(pu8_token, "uid", 3))
         {
            pu8_token = strtok(NULL, delimiters);
            po_this->m_u16_uid = (uint16_t) atoi(pu8_token);
         }
         else if (0 == memcmp(pu8_token, "role", 4))
         {
            pu8_token = strtok(NULL, delimiters);
            i32_return = OBasicUserProfile_get_role_enum(pu8_token, &po_this->m_e_role);
         }
         pu8_token = strtok(NULL, delimiters);
      }

      if (pu8_temp_buf)
         free(pu8_temp_buf);
      pu8_temp_buf = NULL;
   }

   return i32_return;
}

void OBasicUserProfile_destroy(struct OBasicUserProfile * const po_this)
{
   if (po_this->m_pu8_encrypted_cookie != NULL)
      free(po_this->m_pu8_encrypted_cookie);
   po_this->m_pu8_encrypted_cookie = NULL;
   
   memset(po_this, 0, sizeof(*po_this));
}