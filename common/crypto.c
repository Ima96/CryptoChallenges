/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Source file containing the necessary definitions	 *
 * 				for some cryptographic operations and variables.	 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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

crypto_status FixedXOR_SingleChar(uint8_t const * const Buffer, uint8_t Single_Ch_Key, int Buff_sz, uint8_t *res, int *res_sz)
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

crypto_status FixedXOR_SingleCharASCII(uint8_t const * const Buffer, 
                                       uint8_t Single_Ch_Key, 
                                       int Buff_sz, 
                                       uint8_t *res
                                       )
{
	crypto_status status = CRYPTO_ERR;
	uint8_t temp;

	DEBUG_CRYPTO("Buff_sz: %d\n", Buff_sz);
	DEBUG_CRYPTO("Single Character key: %c\n", Single_Ch_Key);

	int cont = 0;
	for (int i = 0; i < Buff_sz; i++)
		res[i] = Buffer[i] ^ Single_Ch_Key;
	
	status = CRYPTO_OK;

	return status;
}

crypto_status English_Score(uint8_t *phrase, int phrase_sz, float *score)
{
	crypto_status status = CRYPTO_ERR;
	int count[27] = {0}, ignored = 0;
	uint8_t character;

	for (int i = 0; i < phrase_sz; i++)
	{
		character = phrase[i];
		if (character >= 65 && character <= 90)
			count[character - 65]++;
		else if (character >= 97 && character <= 122)
			count[character - 97]++;
		else if (character == 32)
			++count[26];
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

	float chi2 = 0, expected_count = 0, expected_ignored_count = 0, difference = 0;
	int effective_length = phrase_sz - ignored;
	for (int i = 0; i < 27; i++)
	{
		expected_count = effective_length * english_freq[i];
		difference = count[i] - expected_count;
		chi2 += difference*difference/expected_count;
	}

	*score = chi2+ignored;
	status = CRYPTO_OK;

	return status;
}

crypto_status BreakFixedXOR(	uint8_t const * const encripted_buff,
										uint16_t const encripted_buff_len,
										uint8_t * const decripted_buff,
										uint16_t * const decripted_buff_len,
										float * const final_score
										)
{
	crypto_status status = CRYPTO_ERR;
	float score = 0, best_score = 100000;
	uint8_t best_key_candidate = 0, *decryption_attempt = NULL;

	decryption_attempt = (uint8_t *) malloc(encripted_buff_len * sizeof(uint8_t));
	if (!decryption_attempt)
		return CRYPTO_ERR;
	for (uint8_t i = 32; i < 127; i++)
	{
		uint8_t current_key_attempt;
		//uint8_t decryption_attempt[string_sz];
		int decrypt_size = 0;

		current_key_attempt = i;

		status = FixedXOR_SingleChar(encripted_buff, current_key_attempt, encripted_buff_len, decryption_attempt, &decrypt_size);
		if (status != CRYPTO_OK)
		{
			printf("Decrypting error!!\n");
			return -1;
		}

		status = English_Score(decryption_attempt, decrypt_size, &score);

		if (score < best_score)
		{
			best_score = score;
			*final_score = score;
			best_key_candidate = current_key_attempt;
			*decripted_buff_len = decrypt_size;
			memcpy(decripted_buff, decryption_attempt, decrypt_size);
		}
	}

	return CRYPTO_OK;
}

crypto_status BreakFixedASCIIXOR_Key(	uint8_t const * const encripted_buff,
										   uint16_t const encripted_buff_len,
                                 uint8_t * const key
										   )
{
	crypto_status status = CRYPTO_ERR;
	float score = 0, best_score = 100000;
	uint8_t best_key_candidate = 0, *decryption_attempt = NULL;

	decryption_attempt = (uint8_t *) malloc(encripted_buff_len * sizeof(uint8_t));
	if (!decryption_attempt)
		return CRYPTO_ERR;
	for (uint8_t i = 32; i < 127; i++)
	{
		uint8_t current_key_attempt;
		//uint8_t decryption_attempt[string_sz];
		int decrypt_size = 0;

		current_key_attempt = i;

		status = FixedXOR_SingleCharASCII(encripted_buff, current_key_attempt, encripted_buff_len, decryption_attempt);
      decrypt_size = encripted_buff_len;
      
		if (status != CRYPTO_OK)
		{
			printf("Decrypting error!!\n");
			return -1;
		}

		status = English_Score(decryption_attempt, decrypt_size, &score);

		if (score < best_score)
		{
			best_score = score;
			best_key_candidate = current_key_attempt;
         *key = best_key_candidate;
		}
	}

	return CRYPTO_OK;
}

crypto_status EncryptRepeatingKeyXor(uint8_t const * const plaintext,
                                       uint16_t const plain_len,
                                       uint8_t const * const key,
                                       uint16_t const key_len,
                                       uint8_t * const ciphertext
                                       )
{
   for (int i = 0; i < plain_len; i++)
      ciphertext[i] = plaintext[i] ^ key[i % key_len];

   return CRYPTO_OK;
}

uint16_t ComputeHammingDist(uint8_t const byte1, 
                              uint8_t const byte2
                              )
{
   uint16_t dist = 0;

   for (uint8_t val = (byte1 ^ byte2); val > 0; ++dist)
      val = val & (val - 1);

   return dist;
}

crypto_status ComputeBufHammingDist(uint8_t const * const buf1, 
                                    uint16_t const buf1_len,
                                    uint8_t const * const buf2,
                                    uint16_t const buf2_len,
                                    uint16_t * res_dist
                                    )
{
   if (buf1_len != buf2_len)
      return CRYPTO_ERR;

   uint16_t dist = 0;
   for (int i = 0; i < buf1_len; i++)
      dist += ComputeHammingDist(buf1[i], buf2[i]);

   *res_dist = dist;
   return CRYPTO_OK;
}

void Guess_RKXOR_KeySize(uint8_t const * const bin_ciphertext,
                           uint16_t const bin_cipherlen,
                           uint8_t keysize_attempts[4])
{
   uint8_t *buf1 = NULL;
   uint8_t *buf2 = NULL;
   uint16_t hamm_dist = 0;
   float norm_hamm = 0;
   float best_norms[4] = {1000};

   for (uint8_t KEYSIZE = 2; KEYSIZE <= 40; ++KEYSIZE)
   {
      double sum = 0.0;
      uint16_t blocks = 0;
      buf1 = realloc(buf1, KEYSIZE * sizeof(uint8_t));
      buf2 = realloc(buf2, KEYSIZE * sizeof(uint8_t));

      for (int i = 0; i < bin_cipherlen; i += 2*KEYSIZE)
      {
         memcpy(buf1, &bin_ciphertext[i], KEYSIZE);
         memcpy(buf2, &bin_ciphertext[i+KEYSIZE], KEYSIZE);

         ComputeBufHammingDist(buf1, KEYSIZE, buf2, KEYSIZE, &hamm_dist);
         sum += hamm_dist;
      }
      blocks = bin_cipherlen / (KEYSIZE * 2);
      norm_hamm = sum / (KEYSIZE * blocks);
      
      #if defined(DEBUG_APP)
      printf("[DEBUG] Averaged & normalized distance for KEYSIZE = %d: %f\n", KEYSIZE, norm_hamm);
      #endif

      if (norm_hamm < best_norms[0])
      {
         best_norms[3] = best_norms[2];
         keysize_attempts[3] = keysize_attempts[2];
         best_norms[2] = best_norms[1];
         keysize_attempts[2] = keysize_attempts[1];
         best_norms[1] = best_norms[0];
         keysize_attempts[1] = keysize_attempts[0];
         best_norms[0] = norm_hamm;
         keysize_attempts[0] = KEYSIZE;
      }
      else if (norm_hamm < best_norms[1])
      {
         best_norms[3] = best_norms[2];
         keysize_attempts[3] = keysize_attempts[2];
         best_norms[2] = best_norms[1];
         keysize_attempts[2] = keysize_attempts[1];
         best_norms[1] = norm_hamm;
         keysize_attempts[1] = KEYSIZE;
      }
      else if (norm_hamm < best_norms[2])
      {
         best_norms[3] = best_norms[2];
         keysize_attempts[3] = keysize_attempts[2];
         best_norms[2] = norm_hamm;
         keysize_attempts[2] = KEYSIZE;
      }
      else if (norm_hamm < best_norms[3])
      {
         best_norms[3] = norm_hamm;
         keysize_attempts[3] = KEYSIZE;
      }

      norm_hamm = 0;
   }
   if (buf1)
      free(buf1);
   if (buf2)
      free(buf2);
   
   return;
}

void Init_OpenSSL(void)
{
   ERR_load_crypto_strings();
   OpenSSL_add_all_ciphers();
   OPENSSL_config(NULL);
}

void Cleanup_OpenSSL(void)
{
   EVP_cleanup();
   CRYPTO_cleanup_all_ex_data();
   ERR_free_strings();
}

crypto_status DecryptAES_ECB_OpenSSL(uint8_t const * const ciphertext,
                                       uint16_t const cipherlen,
                                       uint8_t const * const key,
                                       uint8_t **plaintext,
                                       int *plaintext_len
                                       )
{
   

   EVP_CIPHER_CTX *ctx;
   uint8_t *plaintext_temp = NULL;
   int outlen;

   if (!(ctx = EVP_CIPHER_CTX_new()))
   {
      printf("<ERROR> Could not create new cipher ctx!\n");
      return CRYPTO_ERR_SSL;
   }

   if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
   {
      printf("<ERROR> Could not initialize cipher!!\n");
      return CRYPTO_ERR_SSL;
   }

   plaintext_temp = malloc(cipherlen * sizeof(uint8_t));
   if (1 != EVP_DecryptUpdate(ctx, plaintext_temp, &outlen, ciphertext, (int)cipherlen))
   {
      printf("<ERROR> Could not update Decrypt Routine!!\n");
      return CRYPTO_ERR_SSL;
   }
   *plaintext_len = outlen;

   if (1 != EVP_DecryptFinal_ex(ctx, plaintext_temp + outlen, &outlen))
   {
      printf("<ERROR> Could not Finish Decrypt Routine!!\n");
      return CRYPTO_ERR_SSL;
   }
   *plaintext_len += outlen;

   plaintext_temp[*plaintext_len] = '\0';

   EVP_CIPHER_CTX_free(ctx);

   *plaintext = plaintext_temp;
   return CRYPTO_OK;
}

crypto_status Detect_AES_ECB(uint8_t const * const pu8_buff,
                              uint16_t const u16_buff_len,
                              uint16_t const u16_block_size
                              )
{
   uint16_t u16_num_blocks = u16_buff_len / u16_block_size;
   uint8_t *pu8_curr_block = NULL;
   pu8_curr_block = malloc(u16_block_size * sizeof(uint8_t));

   for (int j = 0; j < u16_num_blocks; ++j)
   {
      memcpy(pu8_curr_block, &pu8_buff[j*u16_block_size], u16_block_size);
      for (int k = j + 1; k < u16_num_blocks; ++k)
      {
         if (0 == (memcmp(pu8_curr_block, &pu8_buff[k*u16_block_size], u16_block_size)))
         {
            if (pu8_curr_block)
               free(pu8_curr_block);
            return CRYPTO_OK;
         }
      }
   }

   return CRYPTO_NO_DETECTED;
}