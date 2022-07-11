/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Source file containing the necessary definitions	 *
 * 				for some common encoding variables and operations.	 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "encodings.h"

uint8_t *AsciiHex2Bin(uint8_t *AsciiEncoded, int size)
{
    uint8_t *hex_str = NULL;

    hex_str = malloc(size);
    for (int i = 0; i < size; i++)
    {
        if(AsciiEncoded[i] < 58 && AsciiEncoded[i] > 47)
        {
                hex_str[i] = AsciiEncoded[i] - 48; 
        }
        if(AsciiEncoded[i] < 103 && AsciiEncoded[i] > 96)
        {
                hex_str[i] = AsciiEncoded[i] - 87;
        }
    }

    return hex_str;
}

uint8_t *BinHex2Ascii(uint8_t *HexEncoded, int size)
{
    uint8_t *ascii_str = NULL;

    ascii_str = malloc(size);
    for (int i = 0; i < size; i++)
    {
        if (HexEncoded[i] < 10)
            ascii_str[i] = HexEncoded[i] + 48;

        if (HexEncoded[i] >= 10 && HexEncoded[i] < 16)
            ascii_str[i] = HexEncoded[i] + 87;
    }

    return ascii_str;
}

uint8_t *Hex2Base64(uint8_t *HexEncoded, int size)
{
    uint8_t *base64_str = NULL;
    uint8_t first_char = 0, second_char = 0;
    int base64_str_size = 0;

    DEBUG_ENCODINGS("The size of HexEncoded string is: %d\n", size);

    // Size of base64 string is calculated with ratio of 2/3 from hex.
    base64_str_size = ceil(size * 2 / 3);
    base64_str = malloc(base64_str_size);
    DEBUG_ENCODINGS("The size of the resulting base64 string is: %d\n", base64_str_size);

    int cont = 0;
    for (int i = 0; i < size; i += 3)
    {

        first_char = (HexEncoded[i] & 0x0F) << 2;
        first_char = first_char | (HexEncoded[i+1] & 0x0C) >> 2;
        //DEBUG_ENCODINGS("Tries with the first element: %c\n", Base64Digits[first_char]);
        second_char = (HexEncoded[i+1] & 0x03) << 4 | (HexEncoded[i+2] & 0x0F);
        //DEBUG_ENCODINGS("Tries with the second element: %c\n", Base64Digits[second_char]);
        base64_str[cont++] = Base64Digits[first_char];
        base64_str[cont++] = Base64Digits[second_char];
    }

    return base64_str;
}
