#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "crypto.h"

#include "BasicUserProfile.h"

struct OBasicUserProfile bup_attacker(void);
int numPlaces (int n);

int main(void)
{
   int32_t res = 0;

   struct OBasicUserProfile o_hacked_profile = bup_attacker();

   res = OBasicUserProfile_decrypt_and_parse(&o_hacked_profile);
   if (E_BUP_OK != res)
   {
      printf("Could not decrypt and parse the hacked profile...\n");
      return EXIT_FAILURE;
   }
   printf("Directly role value after attack (if admin = 1): %d\n", o_hacked_profile.m_e_role);

   OBasicUserProfile_destroy(&o_hacked_profile);
   staticAesKeyRemove();

   return EXIT_SUCCESS;
}

int numPlaces (int n) 
{
   if (n < 0) return numPlaces ((n == INT_MIN) ? INT_MAX: -n);
   if (n < 10) return 1;
   return 1 + numPlaces (n / 10);
}

// We know that generating a new profile gives a "user" role. Thus, for a
// blocksize of 16, we need strlen(email + rest_of_cookie) % block_size = 
// 0.
// crafted_mail_len = (email=&uid=x&role=) % block_size;
// We have 2 incognitas here, email length and uid value. Depending on the
// value of uid, email length will vary. The attacker will start assuming
// the value only is 1 digit, if does not work, it will decrease by 1 the
// email length, and so on.
struct OBasicUserProfile bup_attacker(void)
{
   struct OBasicUserProfile o_hacked_admin_user;
   OBasicUserProfile_create(&o_hacked_admin_user);
   int32_t i32_res = E_BUP_ERR;
   int32_t i32_pad_len = 0;
   uint8_t au8_admin_role_str[6] = "admin";
   uint8_t u8_admin_role_len = strlen(au8_admin_role_str);
   uint8_t * pu8_padded_admin_str = NULL;
   uint8_t au8_base_num_chars[] = "email=&uid=&role=";
   uint8_t au8_email_prepend[] = "email=";
   uint8_t u8_email_pre_len = strlen(au8_email_prepend);
   uint8_t au8_email_append[] = "@gmail.com";
   uint8_t u8_email_append_len = strlen(au8_email_append);
   uint8_t u8_assumed_uid_digits = 1;
   uint8_t u8_crafted_mail_len = 0;
   uint8_t u8_crafted_mail_len_inv = 0;
   uint8_t u8_crafted_total_mail_len = 0;
   uint8_t * pu8_crafted_email = NULL;

   i32_res = PKCS7_pad(au8_admin_role_str, 
                        u8_admin_role_len, 
                        AES128_KEY_SIZE, 
                        &pu8_padded_admin_str, 
                        &i32_pad_len);

   u8_crafted_mail_len = (u8_email_pre_len +u8_email_append_len) % AES128_KEY_SIZE;
   pu8_crafted_email = (uint8_t *) calloc(u8_crafted_mail_len+strlen(au8_email_append)+i32_pad_len+1, sizeof(uint8_t));

   memset(pu8_crafted_email, 'A', u8_crafted_mail_len);
   memcpy(pu8_crafted_email+u8_crafted_mail_len, au8_email_append, u8_email_append_len);
   memcpy(pu8_crafted_email+u8_crafted_mail_len+u8_email_append_len, pu8_padded_admin_str, i32_pad_len);
   pu8_crafted_email[u8_crafted_mail_len+u8_email_append_len+i32_pad_len] = '\0';

   if (pu8_padded_admin_str)
      free(pu8_padded_admin_str);
   pu8_padded_admin_str = NULL;

   struct OBasicUserProfile o_admin_ciphertext;
   OBasicUserProfile_create(&o_admin_ciphertext);
   i32_res = OBasicUserProfile_gen_profile(&o_admin_ciphertext, pu8_crafted_email);
   uint8_t a16_u8_copy_cipher[AES128_KEY_SIZE] = {0};
   uint8_t u8_copy_idx = AES128_KEY_SIZE;
   memcpy(a16_u8_copy_cipher, &(o_admin_ciphertext.m_pu8_encrypted_cookie[u8_copy_idx]), AES128_KEY_SIZE);
   OBasicUserProfile_destroy(&o_admin_ciphertext);
   
   while(u8_assumed_uid_digits < 6)
   {
      u8_crafted_mail_len_inv = 
                  (strlen(au8_base_num_chars) + u8_email_append_len + u8_assumed_uid_digits) % AES128_KEY_SIZE;
      u8_crafted_mail_len = AES128_KEY_SIZE - u8_crafted_mail_len_inv;
      u8_crafted_total_mail_len = u8_crafted_mail_len + u8_email_append_len + 1;

      pu8_crafted_email = (uint8_t *) realloc(pu8_crafted_email, u8_crafted_total_mail_len * sizeof(uint8_t));
      memset(pu8_crafted_email, 'A', u8_crafted_mail_len);
      memcpy(pu8_crafted_email+u8_crafted_mail_len, au8_email_append, u8_email_append_len);
      pu8_crafted_email[u8_crafted_total_mail_len-1] = '\0';
      
      i32_res = OBasicUserProfile_gen_profile(&o_hacked_admin_user, pu8_crafted_email);

      if (i32_res == E_BUP_OK && numPlaces(o_hacked_admin_user.m_u16_uid) == u8_assumed_uid_digits)
      {
         printf("<ATTACK> Found! Digit(s) #%d crafted_email: %s\n", u8_assumed_uid_digits, pu8_crafted_email);
         printf("<ATTACK> Created profile: %s\n", o_hacked_admin_user.m_au8_encoded_profile);
         uint8_t u8_paste_idx = o_hacked_admin_user.m_i32_enc_len - AES128_KEY_SIZE;
         memcpy(&o_hacked_admin_user.m_pu8_encrypted_cookie[u8_paste_idx], a16_u8_copy_cipher, AES128_KEY_SIZE);
         break;
      }

      if (pu8_crafted_email)
         free(pu8_crafted_email);
      pu8_crafted_email = NULL;

      OBasicUserProfile_destroy(&o_hacked_admin_user);
      u8_assumed_uid_digits++;
   }

   if (pu8_crafted_email)
      free(pu8_crafted_email);
   pu8_crafted_email = NULL;

   if (pu8_crafted_email)
      free(pu8_crafted_email);
   pu8_crafted_email = NULL;

   return o_hacked_admin_user;
}