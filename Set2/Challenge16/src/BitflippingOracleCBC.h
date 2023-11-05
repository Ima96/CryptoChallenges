/***********************************************************************************************************************
 * @file    BitflippingOracleCBC.h
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Header file of BitflippingOracleCBC to create an object oriented structure with associated functionality
 *          to perform bitflipping attacks to AES-128 CBC.
 * 
 * @version 0.1
 * @date    30/10/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/

#ifndef _BITFLIPPING_ORACLE_CBC_
#define _BITFLIPPING_ORACLE_CBC_

#define BOC_MAX_PREPEND_LEN   150
#define BOC_MAX_APPEND_LEN    150
#define BOC_DEFAULT_PREPEND   "comment1=cooking%20MCs;userdata="
#define BOC_DEFAULT_APPEND    ";comment2=%20like%20a%20pound%20of%20bacon"
#define BOC_MAX_USR_STR_LEN   UINT16_MAX - BOC_MAX_PREPEND_LEN - BOC_MAX_APPEND_LEN

#define BOC_STR_TO_SEARCH     ";admin=true;"

#define E_BOC_OK            0    //!< Success status code.
#define E_BOC_ERR          -1    //!< Generic error status code.
#define E_BOC_EINVAL       -2    //!< Input value error status code.
#define E_BOC_ESTR_INIT    -3    //!< Strings not initialized error status code.
#define E_BOC_EINLIM       -4    //!< Input limit range error status code.
#define E_BOC_NOT_FOUND    -5    //!< Searching substring not found

#define BOC_AES128_KEYSIZE 16    //!< Size of AES128 bit key in bytes.

#include <stdint.h>

/***********************************************************************************************************************
 * @brief Structure representing object OBitflippingOracleCBC.
 **********************************************************************************************************************/
struct OBitflippingOracleCBC
{
   uint8_t  m_a_u8_prepend_str[BOC_MAX_PREPEND_LEN];  //!< Member containing the string to prepend the user input
   uint8_t  m_a_u8_append_str[BOC_MAX_APPEND_LEN];    //!< Member containing the string to append to the user input
   uint8_t  *m_pu8_concat_str;            //!< Member that contains the concatenated string.
   uint16_t m_u16_concat_str_len;         //!< Member specifying the length of the concatenated string.
   uint8_t  m_a_u8_aes_128_cbc_key[BOC_AES128_KEYSIZE];  //!< Memeber that holds the key to encrypt and decrypt the
                                                         //!< strigns.
   uint8_t  m_a_u8_iv[BOC_AES128_KEYSIZE];   //!< Member that contains the initialization vector for encryption and
                                             //!< decryption.
   uint8_t  *m_pu8_encrypted_str;      //!< Member pointing to the whole encrypted string
   uint16_t m_u16_encrypted_len;       //!< member that specifies the length of the encrypted string

};

/***********************************************************************************************************************
 * @brief Constructor of an instance of OBitflippingOracleCBC object.
 * 
 * @param po_this Pointer to itself.
 **********************************************************************************************************************/
void OBitflippingOracleCBC_init(struct OBitflippingOracleCBC * const po_this);

/***********************************************************************************************************************
 * @brief Constructor of an OBitflippingOracleCBC object, that sets the prepend and append strings to a user-defined
 *          value.
 * 
 * @param po_this[in]         Pointer to itself object.
 * @param pu8_prepend_str[in] User-defined prepend string to set in the object.
 * @param u16_prepend_len[in] Length of the user-defined prepend string.
 * @param pu8_append_str[in]  User-defined append string to set in the object.
 * @param u16_append_len[in]  Length of the user-defined append string.
 **********************************************************************************************************************/
void OBitflippingOracleCBC_init_with_strs(struct OBitflippingOracleCBC * const po_this,
                                          uint8_t const * const pu8_prepend_str, uint16_t const u16_prepend_len,
                                          uint8_t const * const pu8_append_str, uint16_t const u16_append_len);

/***********************************************************************************************************************
 * @brief Destroy and de-initialize/free memory of an OBitflipplingOracleCBC object.
 * 
 * @param po_this Pointer to itself.
 **********************************************************************************************************************/
void OBitflippingOracleCBC_destroy(struct OBitflippingOracleCBC * const po_this);

/***********************************************************************************************************************
 * @brief Function that gets the arbitrary string from the user input and stablishes a concatenated string with the 
 *          prepend and append strings.
 * 
 * @param po_this[in]         Pointer to self object.
 * @param pu8_usr_str[in]     Arbitrary string defined by the user.
 * @param u16_usr_str_len[in] Length of the arbitrary string introduced by the user.
 * 
 * @return int32_t   Return status code:
 *                      - E_BOC_OK: everything went fine.
 **********************************************************************************************************************/
int32_t OBitflippingOracleCBC_set_usr_str(struct OBitflippingOracleCBC * const po_this,
                                          uint8_t const * const pu8_usr_str,
                                          uint16_t const u16_usr_str_len);

/***********************************************************************************************************************
 * @brief This function receives a buffer from the user, conforms the string prependig and appending the respective
 *          strings to it, checks the input and quotes the ilegal characters, and finally encrypts it based on the 
 *          random AES key and the IV (passed or generated, in the latter case it is returned back).
 * 
 * @param po_this[in/out]        Pointer to self object.
 * @param pu8_plaintext[in]      String passed to be checked, composed and encrypted.
 * @param u16_plaintext_len[in]  Length of the plaintext string.
 * @param a_u8_iv[in/out]        IV used for encryption. If null, it is randomly generated and passed back as context to
 *                               recover the plaintext when decrypting.
 *  
 * @return int32_t   Return status code:
 *                      - E_BOC_OK: success.
 *                      - E_BOC_EINVAL: invalid input values passed.
 *                      - E_BOC_ESTR_INIT: prepend and append strings are not initialized.
 **********************************************************************************************************************/
int32_t OBitflippingOracleCBC_encrypt(struct OBitflippingOracleCBC * po_this,
                                       uint8_t const * const pu8_plaintext,
                                       uint16_t const u16_plaintext_len,
                                       uint8_t ** ppu8_iv_ctx);

/***********************************************************************************************************************
 * @brief This function simply decrypts the stored encripted string using the IV passed.
 * 
 * @param po_this[in]            Pointer to self object.
 * @param pu8_decryption[out]    Decrypted string.
 * @param u16_decrypted_len[out] Decrypted string length.
 * @param pu8_iv[in]             IV to use while decrypting.
 * 
 * @return int32_t   Return status code:
 *                      - E_BOC_OK: success.
 *                      - E_BOC_EINVAL: invalid input values passed.
 **********************************************************************************************************************/
int32_t OBitflippingOracleCBC_decrypt(struct OBitflippingOracleCBC * po_this, 
                                       uint8_t ** ppu8_decryption, 
                                       uint16_t * u16_decrypted_len, 
                                       uint8_t const * const pu8_iv);

/***********************************************************************************************************************
 * @brief Function that decrypts the concatenated string and checks whether the string ";admin=true;" is in it.
 * 
 * @param po_this[in]   Pointer to self object.
 * @param pu8_iv[in]    IV to use in decryption process.
 * 
 * @return int32_t   Return status code:
 *                      - E_BOC_OK: string is found
 *                      - E_BOC_EINVAL: invalid input values passed.
 *                      - E_BOC_NOT_FOUND: string is not found in the decrypted string.
 **********************************************************************************************************************/
int32_t OBitflippingOracleCBC_check_admin_true(struct OBitflippingOracleCBC * po_this, uint8_t const * const pu8_iv);

#endif // _BITFLIPPING_ORACLE_CBC_