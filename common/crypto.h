/***********************************************************************************************************************
 * @file    crypto.h
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Header file with public functions available in the libcryptopals.so library.
 * 
 * @version 0.1
 * @date    21/11/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/


#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************************************************************
 *                                                    INCLUDES
 **********************************************************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

/***********************************************************************************************************************
 *                                                    DEFINES
 **********************************************************************************************************************/
#define BYTE_SIZE 2           //!< Byte size for hexadecimal Fixed XOR.

#define AES128_KEY_SIZE   16  //!< Length in bytes of the AES 128-bit key.

/***********************************************************************************************************************
 *                                                  HANDY MACROS
 **********************************************************************************************************************/
#ifdef DEBUG_CRYPT
#define DEBUG_CRYPTO(fmt, ...) {fflush(stdout); \
                                 fprintf(stdout, "[CRYPTO_DEBUG] %s(%d): " fmt, \
                                          __FUNCTION__, __LINE__, ## __VA_ARGS__); \
                                 fflush(stdout); \
                              }
#else 
#define DEBUG_CRYPTO(...)
#endif

#define LOG_CRYPTO_ERROR(fmt, ...) {fflush(stdout); \
                                    fprintf(stdout, "[CRYPTO_ERROR] %s(%d): " fmt, \
                                             __FUNCTION__, __LINE__, ## __VA_ARGS__); \
                                    fflush(stdout); \
                                 }

/***********************************************************************************************************************
 *                                                   TYPEDEFS
 **********************************************************************************************************************/
typedef enum crypto_status
{
   CRYPTO_OK           =   0,    //!< Successful result
   CRYPTO_ERR          =  -1,    //!< Generic error
   CRYPTO_ERR_SSL      =  -2,    //!< Error concerning OpenSSL operations
   CRYPTO_NO_DETECTED  =  -3,    //!< Error to indicate an AES mode was not detected
   CRYPTO_INVAL        =  -4,    //!< Error to indicate that the input parameters are not valid
   CRYPTO_PKCS7_ERR    =  -5     //!< Error concerning PKCS#7 padding scheme.
} crypto_status;

/***********************************************************************************************************************
 * @brief Typedef of enumeration of AES cipher modes.
 **********************************************************************************************************************/
typedef enum Ecrypto_aes_mode
{
   E_AES128_ECB   = 0,  //!< AES ECB mode.
   E_AES128_CBC   = 1   //!< AES128 CBC mode.
} crypto_aes_mode_t;

/* Public fuction definitions */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes two hex encoded strings in binary and XORs them to get the    *
 * resulting hex encoded in binary.                                                  *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
crypto_status FixedXOR(uint8_t *Buffer1, uint8_t *Buffer2, int Buff1_sz, int Buff2_sz, uint8_t *XORed);

/***********************************************************************************************************************
 *                                                PUBLIC FUNCTIONS
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * @brief   This routine performs a simple byte-by-byte XOR operation between two buffers of equal length.
 * 
 * @param Buffer1[in]   Constant pointer to the first buffer.
 * @param Buffer2[in]   Constant pointer to the second buffer.
 * @param Buff1_sz[in]  Size of the first buffer.
 * @param Buff2_sz[in]  Size of the second buffer.
 * @param XORed[out]    Output resulting buffer, having the same length of the other two.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 *                            - CRYPTO_ERR:  buffer sizes are not equal.
 **********************************************************************************************************************/
crypto_status FixedXOR(uint8_t const * const Buffer1, uint8_t const * const Buffer2, 
                        int Buff1_sz, int Buff2_sz, uint8_t *XORed);

/***********************************************************************************************************************
 * @brief   This function takes a buffer and XORs it with a given character. The Buffer is assumed that is encoded in 
 *          hexadecimal. The size of the buffer has to be provided and the result is given in the "res" parameter. The 
 *          parameter "res_sz" indicates the size of the result.
 * 
 * @todo    Protect the function against non-allocated result pointer.
 * 
 * @param Buffer[in]          Buffer to XOR against the specific same byte, encoded in hexadeximal.
 * @param Single_Ch_Key[in]   Byte to XOR the whole buffer.
 * @param Buff_sz[in]         Buffer size.
 * @param res[out]            Output resulting buffer.
 * @param res_sz[out]         Size of resulting buffer.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 **********************************************************************************************************************/
crypto_status FixedXOR_SingleChar(uint8_t const * const Buffer, uint8_t Single_Ch_Key, 
                                    int Buff_sz, uint8_t *res, int *res_sz);

/***********************************************************************************************************************
 * @brief   This routine XORs each byte of a buffer with the same specified byte. The resulting buffer is returned in
 *          the "res" variable with the same size of the original buffer.
 * 
 * @todo    Protect the function against non-allocated result pointer.
 * 
 * @param Buffer[in]          Buffer to XOR against the specified single byte.
 * @param Single_Ch_Key[in]   Byte to XOR the whole buffer.
 * @param Buff_sz[in]         Size of the original buffer.
 * @param res[out]            Output buffer containing the result of the operation.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 **********************************************************************************************************************/
crypto_status FixedXOR_SingleCharASCII(uint8_t const * const Buffer, uint8_t Single_Ch_Key, int Buff_sz, uint8_t *res);

/***********************************************************************************************************************
 * @brief   This function takes a buffer with a potential english phrase in it and it calculates its "englishness" 
 *          (a score of its likelihood to be an english prhase). The algorithm used for it is called chi squared, and 
 *          its used with the english letter frequencies obtained from the book "Alice in Wonderland". The lower the 
 *          score, more probable for the phrase to be english.
 * 
 * @param phrase[in]    Input buffer containing the phrase to evaluate.
 * @param phrase_sz[in] Size in bytes of the input phrase.
 * @param score[out]    Output of the resulting english score for the phrase.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 *                            - CRYPTO_ERR:  the phrase contains a non-printable character.
 **********************************************************************************************************************/
crypto_status English_Score(uint8_t *phrase, int phrase_sz, float *score);

/***********************************************************************************************************************
 * @brief   This routine gets a buffer which has been encrypted with a fixed XOR operation against the same byte, and
 *          assuming the plaintext is in English, it obtains the plaintext with best score of being english. The input
 *          encrypted buffer is assumed to be encoded in hexadecimal.
 * 
 * @param encripted_buff[in]        Input encrypted buffer. Assumed to be in hexadecimal encoding.
 * @param encripted_buff_len[in]    Length in bytes of the input encrypted buffer.
 * @param decripted_buff[out]       Pointer to a buffer where the best decrypted plaintext will be stored.
 * @param decripted_buff_len[out]   Length of the best encrypted buffer.
 * @param final_score[out]          Englishness score for the best obtained plaintext.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 *                            - CRYPTO_ERR:  there was an error during the process.
 **********************************************************************************************************************/
crypto_status BreakFixedXOR(uint8_t const * const encripted_buff,
                              uint16_t const encripted_buff_len,
										uint8_t * const decripted_buff,
										uint16_t * const decripted_buff_len,
										float * const final_score);

/***********************************************************************************************************************
 * @brief   This routine gets a buffer which has been encrypted whit a fixed XOR operation against the same key byte,
 *          and assuming the plaintext is in English, it obtains the key-byte candidate that returns the best English
 *          score. The input encrypted buffer is just ciphertext with no encoding, just raw ciphertext bytes.
 * 
 * @param encripted_buff[in]        Pointer to the encrypted buffer.
 * @param encripted_buff_len[in]    Length of the encrypted buffer.
 * @param key[out]                  Pointer to return the best key-byte candidate.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 *                            - CRYPTO_ERR:  there was an error during the process.
 **********************************************************************************************************************/
crypto_status BreakFixedASCIIXOR_Key(uint8_t const * const encripted_buff,
                                       uint16_t const encripted_buff_len,
                                       uint8_t * const key);

/***********************************************************************************************************************
 * @brief   This routine encrypts a diven plaintext XORing each byte with its corresponding key-byte. It is known as
 *          repeating key XOR, because for a given key and keylength, each block of the plaintext of length keylength
 *          is encrypted XORing it against the key.
 * 
 * @todo    Protect and check the ciphertext memory allocation.
 * 
 * @param plaintext[in]    Pointer to the array containing the plaintext to encrypt.
 * @param plain_len[in]    Length of the pointer to encrypt.
 * @param key[in]          Pointer to the key.
 * @param key_len[in]      Length of the key.
 * @param ciphertext[out]  Pointer to the result of the encryption operation.
 *  
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 **********************************************************************************************************************/
crypto_status EncryptRepeatingKeyXor(uint8_t const * const plaintext,
                                       uint16_t const plain_len,
                                       uint8_t const * const key,
                                       uint16_t const key_len,
                                       uint8_t * const ciphertext);

/***********************************************************************************************************************
 * @brief   Given to buffers, this routine calculates the Hamming Distance between the two of them.
 * 
 * @param buf1[in]      Pointer to one of the buffers.
 * @param buf1_len[in]  Length of the first buffer.
 * @param buf2[in]      Pointer to the second buffer.
 * @param buf2_len[in]  Length of the second buffer.
 * @param res_dist[out] Output result of the hamming distance.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful completion of operations.
 *                            - CRYPTO_ERR:  error with buffer lengths (not equal).
 **********************************************************************************************************************/
crypto_status ComputeBufHammingDist(uint8_t const * const buf1, 
                                    uint16_t const buf1_len,
                                    uint8_t const * const buf2,
                                    uint16_t const buf2_len,
                                    uint16_t * res_dist);

/***********************************************************************************************************************
 * @brief   This routine takes a ciphertext (no encoded, raw bytes), and assuming it has been encrypted using a 
 *          repeating key XOR cipher, it obtains the 4 most probable key sizes (between 2 and 40) or in other words, 
 *          block sizes.
 * 
 * @todo    Protect non-allocated output memory.
 * 
 * @param bin_ciphertext[in]     Pointer to input ciphertext buffer.
 * @param bin_cipherlen[in]      Length of the input ciphertext.
 * @param keysize_attempts[out]  Output array of the 4 most probable block sizes.
 **********************************************************************************************************************/
void Guess_RKXOR_KeySize(uint8_t const * const bin_ciphertext,
                           uint16_t const bin_cipherlen,
                           uint8_t keysize_attempts[4]);

/***********************************************************************************************************************
 * @brief   This routine initializes the OpenSSL library adding all ciphers and loading the crypto error strings.
 * 
 **********************************************************************************************************************/
void Init_OpenSSL(void);

/***********************************************************************************************************************
 * @brief   This routine closes OpenSSL once the operations with it are finished, to free memory and clean up all data.
 * 
 **********************************************************************************************************************/
void Cleanup_OpenSSL(void);

/***********************************************************************************************************************
 * @brief   This routine uses OpenSSL's AES128 in ECB mode to decrypt a given ciphertext with a given key. This routine 
 *          does not take into account any padding. The output is given in plaintext, and memory for it is allocated 
 *          inside this routine.
 * 
 * @param ciphertext[in]      Pointer to the input ciphertext to decrypt.
 * @param cipherlen[in]       Length of the ciphertext.
 * @param key[in]             Pointer to a 16-byte length key.
 * @param plaintext[out]      Output pointer to the new allocated decrypted plaintext.
 * @param plaintext_len[out]  Length of the decrypted plaintext.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:      successful completion of operations.
 *                            - CRYPTO_ERR_SSL: error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status DecryptAES128_ECB_OpenSSL(uint8_t const * const ciphertext,
                                       uint16_t const cipherlen,
                                       uint8_t const * const key,
                                       uint8_t **plaintext,
                                       int *plaintext_len);

/***********************************************************************************************************************
 * @brief   This routine uses OpenSSL's AES128 in ECB mode to encrypt a given plaintext with a given key. The routine
 *          expects the plaintext to have valid PKCS#7 padding, and if does not, it adds the necessary padding. The 
 *          output is given in the variable ppu8_ciphertext , and memory is allocated inside the routine.
 * 
 * @param pu8_plaintext[in]   Pointer to the input plaintext to encrypt.
 * @param u16_plainlen[in]    Length of the plaintext.
 * @param pu8_key[in]         Pointer to a 16-byte length key.
 * @param ppu8_cipherext[out] Pointer to a pointer where memmory is going to be allocated to store the encryption.
 * @param pi32_cipherlen[out] Pointer to the memmory storing the output encryption length value.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:         successful completion of operations.
 *                            - CRYPTO_ERR_SSL:    error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status EncryptAES128_ECB_OpenSSL(uint8_t const * const pu8_plaintext,
                                       uint16_t const u16_plainlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t **ppu8_cipherext,
                                       int32_t * pi32_cipherlen);

/***********************************************************************************************************************
 * @brief   This routine takes a ciphertext and detects whether it has been encrypted using AES in ECB mode.
 * 
 * @param pu8_buff[in]        Pointer to the input ciphertext.
 * @param u16_buff_len[in]    Length of the ciphertext.
 * @param u16_block_size[in]  Block size used in the encryption.
 *  
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:            the passed ciphertext has been encrypted using AES in ECB mode.
 *                            - CRYPTO_NO_DETECTED:   the ciphertext has NOT been encrypted using AES in ECB mode.
 **********************************************************************************************************************/
crypto_status Detect_AES_ECB(uint8_t const * const pu8_buff,
                              uint16_t const u16_buff_len,
                              uint16_t const u16_block_size);

/***********************************************************************************************************************
 * @brief   This function takes a buffer and pads it to a multiple of the specified block size, according the PKCS#7
 *          padding scheme. The output is given in an allocated pointer.
 * 
 * @param pu8_buf[in]            Pointer to the buffer to pad.
 * @param u32_buf_size[in]       Length of the buffer to pad.
 * @param u16_block_size[in]     Block size to pad to.
 * @param pu8_outbuf[out]        Pointer to the output buffer, allocated in this function.
 * @param pu32_padded_size[out]  Pointer to the memmory holding the length of the output padded buffer
 *  
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful padding of buffer.
 *                            - CRYPTO_ERR:  error during padding operation.
 **********************************************************************************************************************/
crypto_status PKCS7_pad(uint8_t const * const pu8_buf, uint32_t const u32_buf_size, uint16_t const u16_block_size,
                        uint8_t ** pu8_outbuf, uint32_t * pu32_padded_size);

/***********************************************************************************************************************
 * @brief   This function takes a buffer and checks whether it has a valid PKCS#7 padding for a given block size. 
 *          Additionally, if the pointer pu16_pad_size is not NULL and the padding is valid, the pad size is returned 
 *          in this memmory address.
 * 
 * @param pu8_buf[in]         Pointer to input buffer for pad validation.
 * @param u32_buf_sz[in]      Length of the input buffer.
 * @param u16_block_size[in]  Block size for pad validation.
 * @param pu16_pad_size[out]  Output pad size if the padding is valid.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:         input buffer has valid PKCS#7 padding.
 *                            - CRYPTO_INVAL:      input values are not valid.
 *                            - CRYPTO_PKCS7_ERR:  the input buffer has NOT a valid PKCS#7 padding.
 **********************************************************************************************************************/
crypto_status PCKS7_pad_validation(uint8_t const * const pu8_buf, uint32_t const u32_buf_sz, 
                                    uint16_t const u16_block_size, uint16_t * const pu16_pad_size);

/***********************************************************************************************************************
 * @brief   This function takes in a buffer and if it has a valid PKCS#7 padding, it strips it off and returns the new
 *          unpadded buffer in ppu8_outbuf, assigning it the corresponding memory in this routine.
 * 
 * @param pu8_buf[in]               Pointer to the buffer to potentially strip off the PKCS#7 padding.
 * @param u32_buf_size[in]          Length of the input padded buffer.
 * @param u16_block_size[in]        Block size for padding validation purposes.
 * @param ppu8_outbuf[out]          Pointer to the memory address allocated in the function with the unpadded buffer.
 * @param pu32_stripped_size[out]   Length of the new unpadded buffer.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:         input buffer has valid PKCS#7 padding.
 *                            - CRYPTO_INVAL:      input values are not valid.
 *                            - CRYPTO_PKCS7_ERR:  the input buffer has NOT a valid PKCS#7 padding.
 **********************************************************************************************************************/
crypto_status PKCS7_pad_strip(uint8_t const * const pu8_buf, uint32_t const u32_buf_size, uint16_t const u16_block_size,
                              uint8_t ** ppu8_outbuf, uint32_t * const pu32_stripped_size);

/***********************************************************************************************************************
 * @brief   This routine returns n_bytes number of pseudo-random bytes in rnd_buf pointer.
 * 
 * @param rnd_buf[in/out]  Pointer to the buffer which will hold the pseudo-random bytes.
 * @param n_bytes[in]      Number of pseudo-random bytes to generate.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful generation of pseudo-random bytes.
 *                            - CRYPTO_ERR:  rnd_buff is a null pointer.
 **********************************************************************************************************************/
crypto_status GeneratePseudoRandomBytes(uint8_t * const rnd_buf, 
                                          uint16_t const n_bytes);

/***********************************************************************************************************************
 * @brief   This function generates a 16-byte pseudo-random buffer to be used as an AES128 key, invoking
 *          GeneratePseudoRandomBytes
 * 
 * @param rnd_buf[in]   Pointer to the buffer that will hold the generated pseudo-random 16-byte AES128 key.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful generation of pseudo-random bytes.
 *                            - CRYPTO_ERR:  rnd_buff is a null pointer.
 **********************************************************************************************************************/
crypto_status GenRndAES128Key(uint8_t * const rnd_buf);

/***********************************************************************************************************************
 * @brief   This routine takes a message buffer and it prepends and appends a randomly generated random length bytes 
 *          (between 5 and 10). After this, it generates an AES128 key and encrypts the conformed plaintext either using
 *          ECB or CBC, randomly chosen. Finally, it invokes the routine Detect_AES_ECB and returns whether the 
 *          plaintext has been encrypted using ECB or CBC.
 * 
 * @param pu8_message[in]        Pointer to the message buffer.
 * @param u16_msg_sz[in]         Length of the message.
 * @param e_detected_mode[out]   Output of the type of AES mode detected.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful operations.
 *                            - CRYPTO_ERR:  generic error during routine execution.
 *                            - CRYPTO_ERR_SSL: error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status OracleAES128_ECB_CBC(uint8_t const * const pu8_message, 
                                    uint16_t const u16_msg_sz,
                                    crypto_aes_mode_t * const e_detected_mode);

/***********************************************************************************************************************
 * @brief   This function checks if the local static AES128 key is initialized and if it's not, it initializes it 
 *          allocating memory for it and invoking GenRndAES128Key function.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   key already initialized / successful initialization of the static key.
 *                            - CRYPTO_ERR:  generic error during routine execution.
 **********************************************************************************************************************/
crypto_status staticAesKeyCheckAndInit(void);

/***********************************************************************************************************************
 * @brief   This routine securely erases the static AES128 key and frees its memory allocation.
 **********************************************************************************************************************/
void staticAesKeyRemove(void);

/***********************************************************************************************************************
 * @brief   This function encrypts a given buffer using a static AES128 key and ECB mode. The output is returned in 
 *          pu8_ciphertext and memory is allocated for it inside this routine.
 * 
 * @param pu8_buffer[in]      Pointer to input buffer to encrypt.
 * @param u16_bufferlen[in]   Length of the buffer to encrypt.
 * @param pu8_ciphertext[out] Pointer to memory address that whill hold the encrypted buffer.
 * @param i32_cipherlen[out]  Pointer to the memory address where the length of the encryption will be stored.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful operations.
 *                            - CRYPTO_ERR:  generic error during routine execution.
 *                            - CRYPTO_ERR_SSL: error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status encryptBufferAesEcbStaticKey(uint8_t const * const pu8_buffer,
                                             uint16_t const u16_bufferlen,
                                             uint8_t ** pu8_ciphertext,
                                             int32_t * const i32_cipherlen);

/***********************************************************************************************************************
 * @brief   This function decrypts a given buffer using a static AES128 key and ECB mode. The output is returned in 
 *          ppu8_plaintext and memory for it is allocated inside this function.
 * 
 * @param pu8_ciphertext[in]     Pointer to the input ciphertext to be decrypted.
 * @param u16_cipherlen[in]      Length of the input ciphertext.
 * @param ppu8_plaintext[out]    Pointer to the output buffer where the decryption will be stored.
 * @param pi32_plainlen[out]     Pointer to the memory address where the length of the decryption will be returned.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful operations.
 *                            - CRYPTO_ERR:  generic error during routine execution.
 *                            - CRYPTO_ERR_SSL: error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status decryptBufferAesEcbStaticKey(uint8_t const * const pu8_ciphertext,
                                             uint16_t const u16_cipherlen,
                                             uint8_t ** ppu8_plaintext,
                                             int32_t * const pi32_plainlen);

/***********************************************************************************************************************
 * @brief   This function encrypts a given buffer using a static AES128 key and CBC mode with a given Initialization
 *          Vector (IV). The output is returned in pu8_ciphertext and memory for it is allocated in this function. If
 *          the IV is not set (i.e. is null), a pseudo-random buffer of 16-bytes is used as IV and this is returned in
 *          the in/out pointer pu8_iv.
 * 
 * @param pu8_buffer[in]         Pointer to input buffer to encrypt.
 * @param u16_bufferlen[in]      Length of the input buffer.
 * @param pu8_iv[in/out]         Pointer to the 16-byte IV for encryption.
 * @param pu8_ciphertext[out]    Pointer to the output memory address where the resulting encryption will be placed.
 * @param u16_cipherlen[out]     Pointer to the output memory address where the length of the encryption will be stored.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful operations.
 *                            - CRYPTO_ERR:  generic error during routine execution.
 *                            - CRYPTO_ERR_SSL: error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status encryptBufferAesCbcStaticKey(uint8_t const * const pu8_buffer,
                                             uint16_t const u16_bufferlen,
                                             uint8_t * pu8_iv,
                                             uint8_t ** pu8_ciphertext,
                                             uint16_t * const u16_cipherlen);

/***********************************************************************************************************************
 * @brief   This function decrypts a given ciphertext with a static AES128 key and CBC mode with a given Initialization
 *          Vector (IV). The output is returned in the pointer ppu8_plaintext where memory for it is allocated inside 
 *          this fuction. Unlike for encryption, if the pu8_iv is null, it returns error because it makes no sense to 
 *          decrypt the buffer against a random IV.
 * 
 * @param pu8_ciphertext[in]     Pointer to the input ciphertext to decrypt.
 * @param u16_cipherlen[in]      Length of the ciphertext buffer.
 * @param pu8_iv[in]             Pointer to the IV buffer.
 * @param ppu8_plaintext[out]    Pointer to the memory address where the result plaintext will be returned.
 * @param pi32_plainlen[out]     Pointer to the memory address where the length of the plaintext will be returned.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:   successful operations.
 *                            - CRYPTO_ERR:  generic error during routine execution.
 *                            - CRYPTO_ERR_SSL: error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status decryptBufferAesCbcStaticKey(uint8_t const * const pu8_ciphertext,
                                             uint16_t const u16_cipherlen,
                                             uint8_t const * const pu8_iv,
                                             uint8_t ** ppu8_plaintext,
                                             int32_t * const pi32_plainlen);

/***********************************************************************************************************************
 * @brief   This routine implements a cryptographic attack against AES128 in ECB mode, also known as Byte-At-A-Time
 *          (BAAT) attack. This resides in an Oracle that encrypts a buffer with a user-controlled input concatenated
 *          with an unknown text. The goal is to get that text. This is achived, first deducing the length of the 
 *          plaintext, then confirming that the Oracle uses AES in ECB mode, and finally breaking the encryption by 
 *          adjusting the user-controlled input length to place only one unknown byte at the end of a block, and brute
 *          forcing this byte value. This results in the obtention of the not-user-controlled plaintext.
 * 
 *          In addition, there is another harder variant of this attack, where the Oracle encrypts a buffer that is 
 *          formed the same as before, but now with a random (fixed between 1 and 16) length prefix. The use of this is 
 *          controlled by the variable \p pu8_rand_prepend where if it is NULL it is treated as for the first case, and 
 *          if it is not null, the buffer that it points to is the one used for the prefix.
 * 
 * @param pu8_unknown_msg[in]             Pointer to set the unknown message to discover.
 * @param u16_msg_len[in]                 Length of the unknown message to discover.
 * @param pu8_rand_prepend[in]            Pointer to the randomly generated prefix
 * @param u8_rand_prepend_len[in]         Length of the randomly generated prefix. 
 * @param ppu8_obtained_unknown_msg[out]  Pointer to the memory address to store the result broken plaintext.
 *  
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:            successful operations.
 *                            - CRYPTO_ERR:           generic error during routine execution.
 *                            - CRYPTO_ERR_SSL:       error during OpenSSL crypto operations.
 *                            - CRYPTO_NOT_DETECTED:  the encryption was not detected to be ECB.
 **********************************************************************************************************************/
crypto_status oneByteAtATime_ECB_Decryption(uint8_t const * const pu8_unknown_msg, uint16_t const u16_msg_len,
                                             uint8_t const * const pu8_rand_prepend, 
                                             uint8_t u8_rand_prepend_len,
                                             uint8_t ** ppu8_obtained_unknown_msg);

/***********************************************************************************************************************
 * @brief   This is a routine that extends the \see oneByteAtATime_ECB_Decryption() to make the necessary conditioning
 *          to add a prefix to the unknown message, guess the random prepend length and break the cipher to get the 
 *          unknown plaintext.
 * 
 * @param pu8_unknown_msg[in]             Pointer to set the unknown message to discover.
 * @param u16_msg_len[in]                 Length of the unknown message to discover.
 * @param ppu8_obtained_unknown_msg[out]  Pointer to the memory address to store the result broken plaintext.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:            successful operations.
 *                            - CRYPTO_ERR:           generic error during routine execution.
 *                            - CRYPTO_ERR_SSL:       error during OpenSSL crypto operations.
 *                            - CRYPTO_NOT_DETECTED:  the encryption was not detected to be ECB.
 **********************************************************************************************************************/
crypto_status oneByteAtATime_ECB_Decryption_Harder(uint8_t const * const pu8_unknown_msg, uint16_t const u16_msg_len,
                                                   uint8_t ** ppu8_obtained_unknown_msg);

/***********************************************************************************************************************
 * @brief   This routine implements the AES128 decryption in CBC mode using the custom \see DecryptAES128_ECB_OpenSSL()
 *          for a given key and IV. If the input ciphertext is not a multiple of the AES128 block size (16), an error is
 *          returned.
 * 
 * @param pu8_ciphertxt[in]   Pointer to the input ciphertext to decrypt.
 * @param u16_cipherlen[in]   Length of the input ciphertext to decrypt.
 * @param pu8_key[in]         Pointer to an AES128 key.
 * @param pu8_initial_iv[in]  Pointer to the initialization vector that will be used for decryption.
 * @param pu8_plaintxt[out]   Pointer to the output memory address where the decrytped plaintext will be stored.
 * @param pu16_plainlen[out]  Pointer to the memory address where the length of the decrypted plaintext will be stored.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:      successful completion of operations.
 *                            - CRYPTO_ERR:     generic error during operation.
 *                            - CRYPTO_ERR_SSL: error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status AES128CBC_decrypt_OpenSSL(uint8_t const * const pu8_ciphertxt,
                                       uint16_t const u16_cipherlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t const * const pu8_initial_iv,
                                       uint8_t ** const pu8_plaintxt,
                                       uint16_t * const pu16_plainlen);

/***********************************************************************************************************************
 * @brief   This routine implements the AES128 encryption in CBC mode for a given key and IV. The implementation first 
 *          checks for valid PKCS#7 padding in the plaintext using \see PKCS7_pad_validation() and if its not valid, it 
 *          adds a valid padding invoking \see PCKS7_pad(). After this, the algorithm of CBC encryption is implementing 
 *          using the functions \see FixedXOR() and \see EncryptAES128_ECB_OpenSSL().
 * 
 * @param pu8_plaintxt[in]       Pointer to the input plaintext to encrypt.
 * @param u16_plainlen[in]       Length of the input plaintext to encrypt.
 * @param pu8_key[in]            Pointer to an AES128 (16-byte) key buffer.
 * @param pu8_initial_iv[in]     Pointer to a 16-byte length Initialization Vector.
 * @param ppu8_ciphertxt[out]    Pointer to the memory address where the resulting ciphertext will be placed.
 * @param pu16_cipherlen[out]    Pointer to the memory address where the length of the ciphertext will be stored.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:         successful completion of operations.
 *                            - CRYPTO_ERR:        generic error during operation.
 *                            - CRYPTO_PKCS7_ERR:  there was an error when padding the plaintext.
 *                            - CRYPTO_ERR_SSL:    error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status AES128CBC_encrypt_OpenSSL(uint8_t const * const pu8_plaintxt,
                                       uint16_t const u16_plainlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t const * const pu8_initial_iv,
                                       uint8_t ** const ppu8_ciphertxt,
                                       uint16_t * const pu16_cipherlen);

/***********************************************************************************************************************
 * @brief   Given a routine that decrypts a ciphertext using AES128 in CBC and validates the padding, this routine
 *          implements an attack that breaks the encryption of the ciphertext by obtaining a "zeroing IV" for each 
 *          cipher block, and XOR-ing it with the ciphertext to get the plaintext.
 * 
 * @param pu8_ciphertext[in]     Pointer to the ciphertext to be guessed / broken.
 * @param u16_cipherlen[in]      Length of the input ciphertext.
 * @param a16_u8_iv[in]          Array of 16-bytes of the IV used for encryption.
 * @param ppu8_obt_plaintxt[out] Output pointer to the memory address where the discovered plaintext will be stored.
 * @param pu16_obt_plainlen[out] Output pointer to the memory where the length of the obtained plaintext will be stored.
 * 
 * @return crypto_status   The return code can be:
 *                            - CRYPTO_OK:         successful completion of operations.
 *                            - CRYPTO_INVAL:      input parameters are not valid.
 *                            - CRYPTO_ERR:        generic error during operation.
 *                            - CRYPTO_PKCS7_ERR:  there was an error when stripping the pad from the plaintext.
 *                            - CRYPTO_ERR_SSL:    error during OpenSSL crypto operations.
 **********************************************************************************************************************/
crypto_status AES128CBC_padding_oracle_attack(uint8_t const * const pu8_ciphertext,
                                                uint16_t const u16_cipherlen,
                                                uint8_t a16_u8_iv[AES128_KEY_SIZE],
                                                uint8_t ** ppu8_obt_plaintxt,
                                                uint16_t * pu16_obt_plainlen);

#ifdef __cplusplus
}
#endif

#endif // _CRYPTO_H_