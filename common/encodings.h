/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Header file containing the necessary definitions	 *
 * 				for some common encoding variables and operations.	 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#ifndef _ENCODINGS_H_
#define _ENCODINGS_H_

/* Includes */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

/* Handy MACROs */
#ifdef DEBUG_ENC
#define DEBUG_ENCODINGS(fmt, ...) {fflush(stdout); fprintf(stdout, "%s:%d: " fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__); fflush(stdout); }
#else 
#define DEBUG_ENCODINGS(...)
#endif

/* Private global variables */
static const char Base64Digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int Base64Invs[] = { 
   62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 
   60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 
};

/* Public fuction definitions */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes an ASCII encoded string and converts it to hexadecimal in     *
 *  binary, returning a pointer to the result.                                       *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
uint8_t *AsciiHex2Bin(uint8_t *AsciiEncoded, int size);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes an Hex binary array and converts it to ASCII string,          *
 * returning a pointer to the result.                                                *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
uint8_t *BinHex2Ascii(uint8_t *HexEncoded, int size);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes a hexadecimal encoded binary array and converts it to base64  *
 * returning a pointer to the result.                                                *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
uint8_t *Hex2Base64(uint8_t *HexEncoded, int size);

uint8_t *Encode2Hex(uint8_t *ciphertext, uint16_t len);

uint8_t *DecodeBase64(uint8_t *buf, uint16_t len, uint16_t *res_size);

uint8_t *EncodeBase64(uint8_t const * const pu8_buf, uint16_t const u16_len, uint16_t *u16_res_size);

#endif