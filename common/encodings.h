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
static char Base64Digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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


#endif