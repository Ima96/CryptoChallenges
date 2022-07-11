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

/* Handy MACROs */
#ifdef DEBUG_CRYPT
#define DEBUG_CRYPTO(fmt, ...) {fflush(stdout); fprintf(stdout, "%s:%d: " fmt, __FUNCTION__, __LINE__, ## __VA_ARGS__); fflush(stdout); }
#else 
#define DEBUG_CRYPTO(...)
#endif

/* Typedefs */
typedef enum crypto_status
{
    CRYPTO_OK = 0,
    CRYPTO_ERR
} crypto_status;

static float english_freq[26] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                     // V-Z
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
crypto_status FixedXOR_SingleChar(uint8_t *Buffer, uint8_t Single_Ch_Key, int Buff_sz, uint8_t *res, int *res_sz);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This function takes a buffer with a potential english phrase in it and it         *
 * calculates its "englishness" (a score of it likelihood to be an english prhase).  *
 * The algorithm used for it is called chi squared, and its used with the english    *
 * letter frequencies obtained from the wikipedia. The lower the score, more english *
 * the phrase is.                                                                    *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
crypto_status English_Score(uint8_t *phrase, int phrase_sz, float *score);

#endif