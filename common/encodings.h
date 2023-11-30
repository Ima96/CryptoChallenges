/***********************************************************************************************************************
 * @file    encodings.h
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Header file with the functions to operate with different encodings like Base64 or Hexadecimal.
 * 
 * @version 0.1
 * @date    30/11/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/

#ifndef _ENCODINGS_H_
#define _ENCODINGS_H_

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
 *                                                  HANDY MACROS
 **********************************************************************************************************************/
#ifdef DEBUG_ENC
#define DEBUG_ENCODINGS(fmt, ...) {fflush(stdout); fprintf(stdout, "%s:%d: " fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__); fflush(stdout); }
#else 
#define DEBUG_ENCODINGS(...)
#endif

/***********************************************************************************************************************
 *                                                PUBLIC FUNCTIONS
 **********************************************************************************************************************/
/***********************************************************************************************************************
 * @brief   This function takes an hexadecimal ASCII string and converts it to hexadecimal  binary values, returning a
 *          pointer to the result null-terminated.
 * 
 * @param AsciiEncoded[in]    Pointer to the hexadecimal ascii string.
 * @param size[in]            Length of the input string
 * 
 * @return uint8_t*  Resulting hexadecimal encoded in binary values buffer. 
 **********************************************************************************************************************/
uint8_t *AsciiHex2Bin(uint8_t *AsciiEncoded, int size);

/***********************************************************************************************************************
 * @brief   This function takes a buffer in hexadecimal binary values and converts it to their respective ASCCI values
 *          so that it can be printed. It returns the pointer to the string null-terminated.
 * 
 * @param HexEncoded[in]   Pointer to the hexadecimal buffer in binary values.
 * @param size[in]         Length of the hexadecimal buffer.
 * 
 * @return uint8_t*  Resulting hexadecimal encoded ASCII string.
 **********************************************************************************************************************/
uint8_t *BinHex2Ascii(uint8_t *HexEncoded, int size);

/***********************************************************************************************************************
 * @brief   This function takes an array that is encoded in hexadecimal and converts it to Base 64. It returns a pointer
 *          to the encoded buffer.
 * 
 * @param HexEncoded[in]   Input pointer to the hexadecimal encoded string.
 * @param size[in]         Length of the input hexadecimal encoded string.
 * 
 * @return uint8_t*  Pointer to the resulting Base64 string.
 **********************************************************************************************************************/
uint8_t *Hex2Base64(uint8_t *HexEncoded, int size);

/***********************************************************************************************************************
 * @brief   This function takes a ciphertext and encodes it into hexadecimal ASCII values. It returns the pointer to the
 *          encoded string.
 * 
 * @param ciphertext[in]   Pointer to the input ciphertext to encode.
 * @param len[in]          Length of the input ciphertext.
 * 
 * @return uint8_t*  Pointer to the resulting hexadecimal encoding in ASCII values.
 **********************************************************************************************************************/
uint8_t *Encode2Hex(uint8_t *ciphertext, uint16_t len);

/***********************************************************************************************************************
 * @brief   Function that decodes an input buffer from Base64 encoding. The algorithm used is taken from the internet, 
 *          and is supposed to be one of the fastest algorithms relying in a table with magic number and inverse 
 *          values. The result is given as a pointer to the buffer holding the decoded values.
 * 
 * @param buf[in]       Pointer to the input buffer in Base64 to decode.
 * @param len[in]       Length of the input buffer.
 * @param res_size[out] Output to store the length of the new decoded string.
 * 
 * @return uint8_t*  Pointer to the decoded string.
 **********************************************************************************************************************/
uint8_t *DecodeBase64(uint8_t *buf, uint16_t len, uint16_t *res_size);

/***********************************************************************************************************************
 * @brief   Function that encodes an input buffer to Base64 encoding. The algorithm used is taken from the internet, and
 *          is supposed to be one of the fastest algorithms. The result is given as a pointer to the buffer holding the 
 *          encoded values.
 * 
 * @param pu8_buf[in]         Pointer to the input buffer that is going to be encoded.
 * @param u16_len[in]         Length of the input buffer to encode.
 * @param u16_res_size[out]   Output of the size of the newly encoded string.
 * 
 * @return uint8_t* 
 **********************************************************************************************************************/
uint8_t *EncodeBase64(uint8_t const * const pu8_buf, uint16_t const u16_len, uint16_t *u16_res_size);

/***********************************************************************************************************************
 * @brief   This function takes a string that is encoded as a cookie, format "key1=value1&key2=value2..." and parses it 
 *          to JSON format string. The return is a pointer to the string holding the JSON parsed cookie.
 * 
 * @param pu8_ck_buf[in]   Input cookie type buffer, which must be null-terminated.
 * 
 * @return uint8_t*  Pointer to the address which holds the JSON parsed cookie.
 **********************************************************************************************************************/
uint8_t *ParseCookieAsJson(uint8_t const * const pu8_ck_buf);

#ifdef __cplusplus
}
#endif

#endif // _ENCODINGS_H_