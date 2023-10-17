#ifndef _BASIC_USER_PROFILE_H_
#define _BASIC_USER_PROFILE_H_

#include <stdint.h>

/* Defines */
#define BUP_EMAIL_MAX_LEN     100
#define BUP_ENCODED_MAX_LEN   6 + BUP_EMAIL_MAX_LEN + 5 + 5 + 6 + 10 + 1

/* Structures */
enum EBasicUserProfileStatus
{
   E_BUP_OK         = 0,
   E_BUP_ERR        = -1,
   E_BUP_ERR_INVAL  = -2,
   E_BUP_ERR_RANGE  = -3
};

enum EBasicUserRoles
{
   E_NOUSER       = -1,
   E_USER         = 0,
   E_ADMIN        = 1,
   E_OPERATOR     = 2,
   E_MAINTAINER   = 3,
   E_INTEGRATOR   = 4
};

struct OBasicUserProfile
{
   uint8_t                    m_a100_u8_email[BUP_EMAIL_MAX_LEN];
   uint16_t                   m_u16_uid;
   uint8_t                    m_au8_encoded_profile[BUP_ENCODED_MAX_LEN];
   uint8_t                  * m_pu8_encrypted_cookie;
   int32_t                    m_i32_enc_len;
   enum EBasicUserRoles       m_e_role;
};

int32_t OBasicUserProfile_gen_profile(
   struct OBasicUserProfile * po_this,
   uint8_t const * const pu8_email
);

void OBasicUserProfile_create(struct OBasicUserProfile * const po_this);

int32_t OBasicUserProfile_decrypt_and_parse(struct OBasicUserProfile * const po_this);

void OBasicUserProfile_print_json(struct OBasicUserProfile const * const po_this);

void OBasicUserProfile_destroy(struct OBasicUserProfile * const po_this);

#endif //_BASIC_USER_PROFILE_H_