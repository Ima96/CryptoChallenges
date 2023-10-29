/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Header file containing the necessary definitions	 *
 * 				for some common encoding variables and operations.	 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#ifndef _CRYPTO_H_
#define _CRYPTO_H_

/* Includes */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

/* Defines */
#define BYTE_SIZE 2

#define AES128_KEY_SIZE   16

/* Handy MACROs */
#ifdef DEBUG_CRYPT
#define DEBUG_CRYPTO(fmt, ...) {fflush(stdout); fprintf(stdout, "[CRYPTO_DEBUG] %s(%d): " fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__); fflush(stdout); }
#else 
#define DEBUG_CRYPTO(...)
#endif

/* Typedefs */
typedef enum crypto_status
{
   CRYPTO_OK           =  0,
   CRYPTO_ERR          =  1,
   CRYPTO_ERR_SSL      =  2,
   CRYPTO_NO_DETECTED  =  3,
   CRYPTO_INVAL        =  4
} crypto_status;

typedef enum Ecrypto_aes_mode
{
   E_AES128_ECB   = 0,
   E_AES128_CBC   = 1
} crypto_aes_mode_t;

/* Original frequencies from God's know where... */
/* static float english_freq[26] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                     // V-Z
}; */

/* Frequencies from 'Alice in wonderland' */
static float english_freq[27] = {
    0.0651, 0.0109, 0.0178, 0.0365, 0.1005, 0.0148, 0.0187,  // A-G
    0.0546, 0.0557, 0.0011, 0.0086, 0.0349, 0.0156, 0.0520,  // H-N
    0.0603, 0.0113, 0.0015, 0.0403, 0.0481, 0.0792, 0.0257,  // O-U
    0.0063, 0.0198, 0.0011, 0.0168, 0.0006, 0.2022           // V-Z-SPACE
};

/* Public fuction definitions */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes two hex encoded strings in binary and XORs them to get the    *
 * resulting hex encoded in binary.                                                  *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
crypto_status FixedXOR(uint8_t *Buffer1, uint8_t *Buffer2, int Buff1_sz, int Buff2_sz, uint8_t *XORed);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes a buffer and XORs it with a given character. The Buffer is    *
 * assumed that is encoded in hexadecimal.                                           *
 * The size of the buffer has to be provided and the result is given in the "res"    *
 * parameter. The parameter "res_sz" indicates the size of the result.               *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
crypto_status FixedXOR_SingleChar(uint8_t const * const Buffer, uint8_t Single_Ch_Key, int Buff_sz, uint8_t *res, int *res_sz);

crypto_status FixedXOR_SingleCharASCII(uint8_t const * const Buffer, uint8_t Single_Ch_Key, int Buff_sz, uint8_t *res);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes a buffer with a potential english phrase in it and it         *
 * calculates its "englishness" (a score of it likelihood to be an english prhase).  *
 * The algorithm used for it is called chi squared, and its used with the english    *
 * letter frequencies obtained from the wikipedia. The lower the score, more english *
 * the phrase is.                                                                    *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
crypto_status English_Score(uint8_t *phrase, int phrase_sz, float *score);

crypto_status BreakFixedXOR(uint8_t const * const encripted_buff,
										         uint16_t const encripted_buff_len,
										         uint8_t * const decripted_buff,
										         uint16_t * const decripted_buff_len,
										         float * const final_score
                                       );

crypto_status BreakFixedASCIIXOR_Key(	uint8_t const * const encripted_buff,
										   uint16_t const encripted_buff_len,
                                 uint8_t * const key
										   );

crypto_status EncryptRepeatingKeyXor(uint8_t const * const plaintext,
                                       uint16_t const plain_len,
                                       uint8_t const * const key,
                                       uint16_t const key_len,
                                       uint8_t * const ciphertext
                                       );

crypto_status ComputeBufHammingDist(uint8_t const * const buf1, 
                                    uint16_t const buf1_len,
                                    uint8_t const * const buf2,
                                    uint16_t const buf2_len,
                                    uint16_t * res_dist
                                    );

void Guess_RKXOR_KeySize(uint8_t const * const bin_ciphertext,
                           uint16_t const bin_cipherlen,
                           uint8_t keysize_attempts[4]);

void Init_OpenSSL(void);

void Cleanup_OpenSSL(void);

crypto_status DecryptAES128_ECB_OpenSSL(uint8_t const * const ciphertext,
                                       uint16_t const cipherlen,
                                       uint8_t const * const key,
                                       uint8_t **plaintext,
                                       int *plaintext_len
                                       );

crypto_status EncryptAES128_ECB_OpenSSL(uint8_t const * const pu8_plaintext,
                                       uint16_t const u16_plainlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t **ppu8_cipherext,
                                       int32_t * pi32_cipherlen
                                       );

crypto_status Detect_AES_ECB(uint8_t const * const pu8_buff,
                              uint16_t const u16_buff_len,
                              uint16_t const u16_block_size
                              );

crypto_status PKCS7_pad(uint8_t const * const pu8_buf, uint32_t const u32_buf_size, uint16_t const u16_block_size,
                        uint8_t ** pu8_outbuf, uint32_t * pu32_padded_size);

crypto_status DecryptAES128_CBC_OpenSSL(uint8_t const * const pu8_ciphertxt,
                                       uint16_t const u16_cipherlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t const * const pu8_initial_iv,
                                       uint8_t ** const pu8_plaintxt,
                                       uint16_t * const pu16_plainlen
                                       );

crypto_status EncryptAES128_CBC_OpenSSL(uint8_t const * const pu8_plaintxt,
                                       uint16_t const u16_plainlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t const * const pu8_initial_iv,
                                       uint8_t ** const ppu8_ciphertxt,
                                       uint16_t * const pu16_cipherlen
                                       );

crypto_status GeneratePseudoRandomBytes(uint8_t * const rnd_buf, 
                                          uint16_t const n_bytes);

crypto_status GenRndAES128Key(uint8_t * const rnd_buf);

crypto_status OracleAES128_ECB_CBC(uint8_t const * const pu8_message, 
                                    uint16_t const u16_msg_sz,
                                    crypto_aes_mode_t * const e_detected_mode);

crypto_status staticAesEcbKeyCheckAndInit(void);

void staticAesEcbKeyRemove(void);

crypto_status encryptBufferAesEcbStaticKey(uint8_t const * const pu8_buffer,
                                             uint16_t const u16_bufferlen,
                                             uint8_t ** pu8_ciphertext,
                                             int32_t * const i32_cipherlen);

crypto_status decryptBufferAesEcbStaticKey(uint8_t const * const pu8_ciphertext,
                                             uint16_t const u16_cipherlen,
                                             uint8_t ** ppu8_plaintext,
                                             int32_t * const pi32_plainlen);

crypto_status guessOracleBlockSize(uint16_t * u16_guessed_blocksize);

crypto_status oneByteAtATime_ECB_Decryption(uint8_t const * const pu8_unknown_msg, uint16_t const u16_msg_len,
                                             uint8_t const * const pu8_rand_prepend, 
                                             uint8_t u8_rand_prepend_len,
                                             uint8_t ** ppu8_obtained_unknown_msg);

crypto_status oneByteAtATime_ECB_Decryption_Harder(uint8_t const * const pu8_unknown_msg, uint16_t const u16_msg_len,
                                                   uint8_t ** ppu8_obtained_unknown_msg);

#endif