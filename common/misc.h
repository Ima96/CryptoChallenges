/***********************************************************************************************************************
 * @file    misc.h
 * @author  Imanol Etxezarreta (ietxezarretam@gmail.com)
 * 
 * @brief   Header file that contains the miscelaneous helper functions to read/write, print, check, etc. different
 *          operations and files during the challenges.
 * 
 * @version 0.1
 * @date    30/11/2023
 * 
 * @copyright Copyright (c) 2023
 * 
 **********************************************************************************************************************/

#ifndef _MISC_H_
#define _MISC_H_

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************************************************************
 *                                                    INCLUDES
 **********************************************************************************************************************/
#include <stdio.h>
#include <stdint.h>

/***********************************************************************************************************************
 *                                                PUBLIC FUNCTIONS
 **********************************************************************************************************************/
/***********************************************************************************************************************
 * @brief   This function gets a file pointer to an already successfully openned file, reads its contents and returns 
 *          them in a buffer, with the buffer length. There is a possibility to add a filter value, where this value 
 *          will be filtered and thus, ignored and not included in the result.
 * 
 * @param fip[in]       Pointer to the input file descriptor.
 * @param outbuf[out]   Pointer to the red contents of the file. The memory of this variable is assigned here.
 * @param filter[in]    Filter character to ignore from the reading.
 * 
 * @return uint16_t  Length of the output buffer.
 **********************************************************************************************************************/
uint16_t readFile(FILE *fip, uint8_t **outbuf, uint8_t const filter);

/***********************************************************************************************************************
 * @brief   This function reads the contents of a file line by line and returns these contents in a 2D array where the 
 *          number of rows is the number of lines and each row contains the contents of each line.
 * 
 * @param fip[in]          Pointer to a valid file descriptor.
 * @param line_count[out]  Number of lines read from the file.
 * 
 * @return uint8_t**    The return is the pointer to the memory address that holds the 2D array with the file lines.
 **********************************************************************************************************************/
uint8_t **readFileLines(FILE *fip, uint16_t *line_count);

/***********************************************************************************************************************
 * @brief   This functions takes an arbitrary buffer and its length and prints it in hexadecimal format.
 * 
 * @param pu8_buff[in]     Pointer to the input buffer.
 * @param i32_buff_len[in] Length of the buffer to print.
 **********************************************************************************************************************/
void PrintHex(uint8_t const * const pu8_buff, int32_t const i32_buff_len);

/***********************************************************************************************************************
 * @brief   This function checks whether the actual machine uses Little Endian data format or not.
 * 
 * @return int    The return value is equal to 1 if the machine uses Little Endian and 0 in any other case.
 **********************************************************************************************************************/
int isLittleEndian(void);

void ss_free(void * p_buffer, uint64_t u64_length);

#ifdef __cplusplus
}
#endif

#endif // _MISC_H_