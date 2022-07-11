/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Source file containing the necessary definitions	 *
 * 				for some cryptographic operations and variables.	 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "crypto.h"

crypto_status FixedXOR(uint8_t *Buffer1, uint8_t *Buffer2, int Buff1_sz, int Buff2_sz, uint8_t *res)
{
	crypto_status status = CRYPTO_ERR;

	DEBUG_CRYPTO("Buff1_sz: %d\n", Buff1_sz);
	DEBUG_CRYPTO("Buff2_sz: %d\n", Buff2_sz);

	if (Buff1_sz != Buff2_sz)
	{
		DEBUG_CRYPTO("The sizes of the buffers do not match!\n");
		return status;
	}

	for (int i = 0; i < Buff1_sz; i++)
		res[i] = Buffer1[i] ^ Buffer2[i];
	
	status = CRYPTO_OK;

	return status;
}

crypto_status FixedXOR_SingleChar(uint8_t *Buffer, uint8_t Single_Ch_Key, int Buff_sz, uint8_t *res, int *res_sz)
{
	crypto_status status = CRYPTO_ERR;
	uint8_t temp;

	DEBUG_CRYPTO("Buff_sz: %d\n", Buff_sz);
	DEBUG_CRYPTO("Single Character key: %c\n", Single_Ch_Key);

	int cont = 0;
	for (int i = 0; i < Buff_sz; i += BYTE_SIZE)
	{
		temp = ((Buffer[i] << 4) & 0xF0 ) | (Buffer[i+1] & 0x0F);
		res[cont] = temp ^ Single_Ch_Key;
		cont++;
	}

	// Return deciphered buffer size in Buff_sz
	*res_sz = cont;
	
	status = CRYPTO_OK;

	return status;
}

crypto_status English_Score(uint8_t *phrase, int phrase_sz, float *score)
{
	crypto_status status = CRYPTO_ERR;
	int count[26] = {0}, ignored = 0;
	uint8_t character;

	for (int i = 0; i < phrase_sz; i++)
	{
		character = phrase[i];
		if (character >= 65 && character <= 90)
			count[character - 65]++;
		else if (character >= 97 && character <= 122)
			count[character - 97]++;
		else if (character >= 32 && character <= 126)
			ignored++;
		else if (character == 9 || character == 10 || character == 13)
			ignored++;
		else
		{
			*score = 10000;
			return status;
		}
	}

	float chi2 = 0, expected_count = 0, difference = 0;
	int effective_length = phrase_sz - ignored;
	for (int i = 0; i < 26; i++)
	{
		expected_count = effective_length * english_freq[i];
		difference = count[i] - expected_count;
		chi2 += difference*difference/expected_count;
	}

	*score = chi2;
	status = CRYPTO_OK;

	return status;
}