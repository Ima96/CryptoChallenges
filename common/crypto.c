/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Source file containing the necessary definitions	 *
 * 				for some cryptographic operations and variables.	 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#define _GNU_SOURCE     //!< GNU specific for memmem()
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto.h"

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

static uint32_t MT19937_32_untemper_right_shift(uint32_t const u32_num, 
                                                uint32_t const u32_shift, 
                                                uint32_t const u32_mask);
                                             
static uint32_t MT19937_32_untemper_left_shift(uint32_t const u32_num, 
                                                uint32_t const u32_shift, 
                                                uint32_t const u32_mask);

crypto_status FixedXOR(uint8_t const * const Buffer1, uint8_t const * const Buffer2, 
                        int Buff1_sz, int Buff2_sz, uint8_t *res)
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

	DEBUG_CRYPTO("Buff_sz: %d\n", Buff_sz);
	DEBUG_CRYPTO("Single Character key: %c\n", Single_Ch_Key);

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

	float chi2 = 0, expected_count = 0, difference = 0;
	int effective_length = phrase_sz - ignored;
	for (int i = 0; i < 27; i++)
	{
		expected_count = effective_length * english_freq[i];
		difference = count[i] - expected_count;
		chi2 += difference*difference/expected_count;
	}

	*score = chi2+(ignored*20); // Punish harder the ignored characters
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
	//uint8_t best_key_candidate = 0;
   uint8_t *decryption_attempt = NULL;

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
         if (decryption_attempt)
            free(decryption_attempt);
         decryption_attempt = NULL;
			return -1;
		}

		status = English_Score(decryption_attempt, decrypt_size, &score);

		if (score < best_score)
		{
			best_score = score;
			*final_score = score;
			//best_key_candidate = current_key_attempt;
			*decripted_buff_len = decrypt_size;
			memcpy(decripted_buff, decryption_attempt, decrypt_size);
		}
	}

   if (decryption_attempt)
      free(decryption_attempt);
   decryption_attempt = NULL;

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
	for (uint16_t i = 0; i < 256; i++)
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

   if (decryption_attempt)
      free(decryption_attempt);
   decryption_attempt = NULL;

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
   float best_norms[4] = {1000, 1000, 1000, 1000};

   for (uint8_t KEYSIZE = 2; KEYSIZE <= 40; ++KEYSIZE)
   {
      double sum = 0.0;
      uint16_t blocks = 0;
      buf1 = realloc(buf1, KEYSIZE * sizeof(uint8_t));
      buf2 = realloc(buf2, KEYSIZE * sizeof(uint8_t));

      for (int i = 0; i < (bin_cipherlen - 2*KEYSIZE); i += 2*KEYSIZE)
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
   // Deprecated...
   //OPENSSL_config(NULL);
}

void Cleanup_OpenSSL(void)
{
   EVP_cleanup();
   CRYPTO_cleanup_all_ex_data();
   ERR_free_strings();
}

crypto_status DecryptAES128_ECB_OpenSSL(uint8_t const * const ciphertext,
                                       uint16_t const cipherlen,
                                       uint8_t const * const key,
                                       uint8_t **plaintext,
                                       int *plaintext_len
                                       )
{
   

   EVP_CIPHER_CTX *ctx = NULL;
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

   EVP_CIPHER_CTX_set_padding(ctx, 0);

   plaintext_temp = malloc((cipherlen + 1) * sizeof(uint8_t));
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

crypto_status EncryptAES128_ECB_OpenSSL(uint8_t const * const pu8_plaintext,
                                       uint16_t const u16_plainlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t ** ppu8_cipherext,
                                       int32_t * pi32_cipherlen
                                       )
{
   

   EVP_CIPHER_CTX *ctx = NULL;
   uint8_t *pu8_ciphertext_temp = NULL;
   uint8_t *pu8_plaintext_padded = NULL;
   int32_t i32_plainlen_padded = 0;
   int outlen;

   if (CRYPTO_OK != PCKS7_pad_validation(pu8_plaintext, u16_plainlen, AES128_KEY_SIZE, NULL))
   {
      if (CRYPTO_OK != PKCS7_pad(pu8_plaintext, u16_plainlen, AES128_KEY_SIZE, &pu8_plaintext_padded, 
         &i32_plainlen_padded))
      {
         printf("<ERROR> Could not pad plaintext properly...\n");
         return CRYPTO_ERR_SSL;
      }
   }
   else
   {
      i32_plainlen_padded = u16_plainlen;
      pu8_plaintext_padded = (uint8_t *) calloc(u16_plainlen, sizeof(uint8_t));
      memcpy(pu8_plaintext_padded, pu8_plaintext, u16_plainlen);
   }

   if (!(ctx = EVP_CIPHER_CTX_new()))
   {
      printf("<ERROR> Could not create new cipher ctx!\n");
      return CRYPTO_ERR_SSL;
   }

   if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, pu8_key, NULL))
   {
      printf("<ERROR> Could not initialize cipher!!\n");
      return CRYPTO_ERR_SSL;
   }
   EVP_CIPHER_CTX_set_padding(ctx, 0);

   pu8_ciphertext_temp = malloc(i32_plainlen_padded+1 * sizeof(uint8_t));
   if (1 != EVP_EncryptUpdate(ctx, pu8_ciphertext_temp, &outlen, pu8_plaintext_padded, i32_plainlen_padded))
   {
      printf("<ERROR> Could not update Encrypt Routine!!\n");
      return CRYPTO_ERR_SSL;
   }
   *pi32_cipherlen = outlen;

   if (1 != EVP_EncryptFinal_ex(ctx, pu8_ciphertext_temp + outlen, &outlen))
   {
      printf("<ERROR> Could not Finish Encrypt Routine!!\n");
      return CRYPTO_ERR_SSL;
   }
   *pi32_cipherlen += outlen;

   pu8_ciphertext_temp[*pi32_cipherlen] = '\0';

   EVP_CIPHER_CTX_free(ctx);
   if (pu8_plaintext_padded)
   {
      free(pu8_plaintext_padded);
      pu8_plaintext_padded = NULL;
   }

   *ppu8_cipherext = pu8_ciphertext_temp;
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

   if (pu8_curr_block)
      free(pu8_curr_block);

   return CRYPTO_NO_DETECTED;
}

crypto_status PKCS7_pad(uint8_t const * const pu8_buf, uint32_t const u32_buf_size, uint16_t const u16_block_size,
                        uint8_t ** pu8_outbuf, uint32_t * pu32_padded_size)
{
   uint8_t *pu8_temp_buf = NULL;

   if (pu8_buf == NULL || pu32_padded_size == NULL)
      return CRYPTO_ERR;

   uint8_t u16_num_pads = 0;
   if (u32_buf_size < u16_block_size)
      u16_num_pads = u16_block_size - u32_buf_size;
   else if (0 == (u32_buf_size % u16_block_size))
      u16_num_pads = u16_block_size;
   else
      u16_num_pads =  u16_block_size - (u32_buf_size % u16_block_size);
   
   pu8_temp_buf = realloc(pu8_temp_buf, (u32_buf_size + u16_num_pads) * sizeof(uint8_t));
   if (pu8_temp_buf == NULL)
      return CRYPTO_ERR;
   
   memcpy(pu8_temp_buf, pu8_buf, u32_buf_size);
   for (int i = 0; i < u16_num_pads; ++i)
      pu8_temp_buf[u32_buf_size+i] = u16_num_pads;
   
   *pu32_padded_size = u32_buf_size + u16_num_pads;
   *pu8_outbuf = pu8_temp_buf;
   return CRYPTO_OK;
}

crypto_status PCKS7_pad_validation(uint8_t const * const pu8_buf, uint32_t const u32_buf_sz, 
                                    uint16_t const u16_block_size, uint16_t * const pu16_pad_size)
{
   crypto_status e_status = CRYPTO_ERR;

   if (pu8_buf == NULL || u16_block_size == 0 || u32_buf_sz == 0)
   {
      e_status = CRYPTO_INVAL;
   }
   else if (u32_buf_sz % u16_block_size != 0)
   {
      e_status = CRYPTO_PKCS7_ERR;
   }
   else
   {
      uint8_t u8_num_pads = pu8_buf[u32_buf_sz-1];
      if (u8_num_pads > u16_block_size || u8_num_pads == 0)
      {
         e_status = CRYPTO_PKCS7_ERR;
      }
      else
      {
         uint8_t u8_idx = 0;
         for (; u8_idx < u8_num_pads; u8_idx++)
         {
            if (pu8_buf[u32_buf_sz-1-u8_idx] != u8_num_pads)
            {
               e_status = CRYPTO_PKCS7_ERR;
               break;
            }
         }
         if (u8_idx == u8_num_pads)
         {
            if (pu16_pad_size)
               *pu16_pad_size = u8_num_pads;
            e_status = CRYPTO_OK;
         }
      }
   }

   return e_status;
}

crypto_status PKCS7_pad_strip(uint8_t const * const pu8_buf, uint32_t const u32_buf_size, uint16_t const u16_block_size,
                              uint8_t ** ppu8_outbuf, uint32_t * const pu32_stripped_size)
{
   crypto_status e_status = CRYPTO_ERR;

   if (pu8_buf == NULL || u16_block_size == 0 || ppu8_outbuf == NULL || pu32_stripped_size == NULL)
   {
      e_status = CRYPTO_INVAL;
   }
   else
   {
      uint16_t u16_pad_size = 0;
      e_status = PCKS7_pad_validation(pu8_buf, u32_buf_size, u16_block_size, &u16_pad_size);
      if (e_status == CRYPTO_OK)
      {
         uint8_t * pu8_stripped_buf = (uint8_t *) calloc(u32_buf_size - u16_pad_size + 1, sizeof(uint8_t));
         memcpy(pu8_stripped_buf, pu8_buf, u32_buf_size-u16_pad_size);
         *pu32_stripped_size = u32_buf_size - u16_pad_size;
         pu8_stripped_buf[*pu32_stripped_size] = '\0';
         *ppu8_outbuf = pu8_stripped_buf;
      }
      
   }

   return e_status;
}

static uint8_t vf_u8_seed_initialized = 0;
crypto_status GeneratePseudoRandomBytes(uint8_t * const rnd_buf, 
                                          uint16_t const n_bytes)
{
   crypto_status status = CRYPTO_ERR;

   if (rnd_buf == NULL)
   {
      status = CRYPTO_ERR;
   }
   else
   {
      if (!vf_u8_seed_initialized)
      {
         srandom(time(0));
         vf_u8_seed_initialized = 0xFF;
      }
      
      for (int i = 0; i < n_bytes; ++i)
      {
         rnd_buf[i] = (uint8_t) (random() % (255 + 1));
      }
      status = CRYPTO_OK;
   }

   return status;
}

crypto_status GenRndAES128Key(uint8_t * const rnd_buf)
{
   return GeneratePseudoRandomBytes(rnd_buf, AES128_KEY_SIZE);
}

crypto_status OracleAES128_ECB_CBC(uint8_t const * const pu8_message, 
                                    uint16_t const u16_msg_sz,
                                    crypto_aes_mode_t * const e_detected_mode)
{
   crypto_status SStatus = CRYPTO_ERR;
   uint8_t * pu8_ciphertext = NULL;
   uint16_t u16_cipherlen = 0;

   if (pu8_message == NULL || e_detected_mode == NULL)
   {
      SStatus = CRYPTO_ERR;
   }
   else
   {
      uint8_t au8_rnd_aes128_key[AES128_KEY_SIZE] = {0};
      uint8_t au8_rnd_aes128_iv[AES128_KEY_SIZE] = {0};
      uint8_t u8_rnd_prepend = 0;
      uint8_t u8_rnd_append = 0;
      uint8_t * pu8_msg_alt = NULL;

      u8_rnd_prepend = (random() % (10 - 5 + 1)) + 5;
      u8_rnd_append = (random() % (10 - 5 + 1)) + 5;
      pu8_msg_alt = (uint8_t *) malloc((u8_rnd_prepend + u16_msg_sz + u8_rnd_append) * sizeof(uint8_t));
      GeneratePseudoRandomBytes(pu8_msg_alt, u8_rnd_prepend);
      memcpy(pu8_msg_alt+u8_rnd_prepend, pu8_message, u16_msg_sz);
      GeneratePseudoRandomBytes(pu8_msg_alt+u8_rnd_prepend+u16_msg_sz, u8_rnd_append);

      SStatus = GenRndAES128Key(au8_rnd_aes128_key);
      if (SStatus == CRYPTO_OK)
      {
         crypto_aes_mode_t e_local_mode = rand() % 2;
         
         switch (e_local_mode)
         {
            case E_AES128_ECB:
               printf("[INFO] Using ECB\n");
               SStatus = EncryptAES128_ECB_OpenSSL(pu8_msg_alt, u16_msg_sz, au8_rnd_aes128_key, &pu8_ciphertext, 
                                                      (int32_t *) &u16_cipherlen);
               break;
            
            case E_AES128_CBC:
               printf("[INFO] Using CBC\n");
               SStatus = GeneratePseudoRandomBytes(au8_rnd_aes128_iv, AES128_KEY_SIZE);
               if (SStatus != CRYPTO_OK)
                  break;

               SStatus = AES128CBC_encrypt_OpenSSL(pu8_msg_alt, u16_msg_sz, au8_rnd_aes128_key, au8_rnd_aes128_iv, 
                                                   &pu8_ciphertext, &u16_cipherlen);
               break;

            default:
               SStatus = CRYPTO_ERR;
               break;
         }
      }

      if (SStatus == CRYPTO_OK)
      {
         SStatus = Detect_AES_ECB(pu8_ciphertext, u16_cipherlen, AES128_KEY_SIZE);
      }

      if (SStatus == CRYPTO_OK)
      {
         *e_detected_mode = E_AES128_ECB;
      }
      else if (SStatus == CRYPTO_NO_DETECTED)
      {
         *e_detected_mode = E_AES128_CBC;
         SStatus= CRYPTO_OK;
      }
      else
      {
         SStatus = CRYPTO_ERR;
      }
      
      if (pu8_msg_alt)
         free(pu8_msg_alt);
      if (pu8_ciphertext)
         free(pu8_ciphertext);
   }

   return SStatus;
}

static uint8_t * vf_pu8_static_key = NULL;
crypto_status staticAesKeyCheckAndInit(void)
{
   crypto_status e_status = CRYPTO_ERR;

   if (vf_pu8_static_key == NULL)
   {
      vf_pu8_static_key = (uint8_t *) calloc(AES128_KEY_SIZE, sizeof(uint8_t));
      e_status = GenRndAES128Key(vf_pu8_static_key);
   }
   else
      e_status = CRYPTO_OK;

   return e_status;
}

void staticAesKeyRemove(void)
{
   if (vf_pu8_static_key)
   {
      memset(vf_pu8_static_key, 0, AES128_KEY_SIZE);
      free(vf_pu8_static_key);
      vf_pu8_static_key = NULL;
   }
}

crypto_status encryptBufferAesEcbStaticKey(uint8_t const * const pu8_buffer,
                                             uint16_t const u16_bufferlen,
                                             uint8_t ** pu8_ciphertext,
                                             int32_t * const i32_cipherlen)
{
   crypto_status e_status = CRYPTO_ERR;
   uint8_t * pu8_temp_buffer = NULL;
   int32_t i32_temp_cipherlen = 0;

   e_status = staticAesKeyCheckAndInit();
   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error initializing AES ECB Static key...\n");
      return e_status;
   }

   if (pu8_buffer == NULL || u16_bufferlen == 0)
   {
      DEBUG_CRYPTO("Error with input parameters...\n");
      return CRYPTO_ERR;
   }

   e_status = EncryptAES128_ECB_OpenSSL(pu8_buffer, u16_bufferlen, vf_pu8_static_key, &pu8_temp_buffer, &i32_temp_cipherlen);

   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error with AES ECB encryption process...\n");
      return e_status;
   }

   *pu8_ciphertext = pu8_temp_buffer;
   *i32_cipherlen = i32_temp_cipherlen;

   return e_status;
}

crypto_status decryptBufferAesEcbStaticKey(uint8_t const * const pu8_ciphertext,
                                             uint16_t const u16_cipherlen,
                                             uint8_t ** ppu8_plaintext,
                                             int32_t * const pi32_plainlen)
{
   crypto_status e_status = CRYPTO_ERR;
   uint8_t * pu8_temp_buffer = NULL;
   int32_t i32_temp_plainlen = 0;

   e_status = staticAesKeyCheckAndInit();
   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error initializing AES ECB Static key...\n");
      return e_status;
   }

   if (pu8_ciphertext == NULL || u16_cipherlen == 0)
   {
      DEBUG_CRYPTO("Error with input parameters...\n");
      return CRYPTO_ERR;
   }

   e_status = DecryptAES128_ECB_OpenSSL(pu8_ciphertext, u16_cipherlen, vf_pu8_static_key, &pu8_temp_buffer, &i32_temp_plainlen);

   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error with AES ECB encryption process...\n");
      return e_status;
   }

   *ppu8_plaintext = pu8_temp_buffer;
   *pi32_plainlen = i32_temp_plainlen;

   return e_status;
}

crypto_status encryptBufferAesCbcStaticKey(uint8_t const * const pu8_buffer,
                                             uint16_t const u16_bufferlen,
                                             uint8_t * pu8_iv,
                                             uint8_t ** pu8_ciphertext,
                                             uint16_t * const u16_cipherlen)
{
   crypto_status e_status = CRYPTO_ERR;
   uint8_t * pu8_temp_buffer = NULL;
   uint16_t u16_temp_cipherlen = 0;

   e_status = staticAesKeyCheckAndInit();
   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error initializing AES ECB Static key...\n");
      return e_status;
   }

   if (pu8_buffer == NULL || u16_bufferlen == 0)
   {
      DEBUG_CRYPTO("Error with input parameters...\n");
      return CRYPTO_ERR;
   }

   if (pu8_iv == NULL)
   {
      e_status = GeneratePseudoRandomBytes(pu8_iv, AES128_KEY_SIZE);
   }

   e_status = AES128CBC_encrypt_OpenSSL(pu8_buffer, u16_bufferlen, 
                                          vf_pu8_static_key, pu8_iv, 
                                          &pu8_temp_buffer, &u16_temp_cipherlen);

   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error with AES ECB encryption process...\n");
      return e_status;
   }

   *pu8_ciphertext = pu8_temp_buffer;
   *u16_cipherlen = u16_temp_cipherlen;

   return e_status;
}

crypto_status decryptBufferAesCbcStaticKey(uint8_t const * const pu8_ciphertext,
                                             uint16_t const u16_cipherlen,
                                             uint8_t const * const pu8_iv,
                                             uint8_t ** ppu8_plaintext,
                                             int32_t * const pi32_plainlen)
{
   crypto_status e_status = CRYPTO_ERR;
   uint8_t * pu8_temp_buffer = NULL;
   uint16_t u16_temp_plainlen = 0;

   e_status = staticAesKeyCheckAndInit();
   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error initializing AES ECB Static key...\n");
      return e_status;
   }

   if (pu8_ciphertext == NULL || u16_cipherlen == 0 || pu8_iv == NULL)
   {
      DEBUG_CRYPTO("Error with input parameters...\n");
      return CRYPTO_ERR;
   }

   e_status = AES128CBC_decrypt_OpenSSL(pu8_ciphertext, u16_cipherlen, 
                                          vf_pu8_static_key, pu8_iv, 
                                          &pu8_temp_buffer, &u16_temp_plainlen);

   if (e_status != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error with AES ECB encryption process...\n");
      return e_status;
   }

   *ppu8_plaintext = pu8_temp_buffer;
   *pi32_plainlen = u16_temp_plainlen;

   return e_status;
}

uint8_t * vf_pu8_unknown_str = NULL;
crypto_status baatOracleUnknownStrInit(uint8_t const * const pu8_unknown_str, uint16_t u16_len)
{
   if (pu8_unknown_str == NULL || u16_len == 0)
   {
      DEBUG_CRYPTO("Error with input values...\n");
      return CRYPTO_INVAL;
   }
   else if (vf_pu8_unknown_str == NULL)
   {
      vf_pu8_unknown_str = (uint8_t *)calloc(u16_len+1, sizeof(uint8_t));
      memcpy(vf_pu8_unknown_str, pu8_unknown_str, u16_len);
      vf_pu8_unknown_str[u16_len] = '\0';
   }

   return CRYPTO_OK;
}

void baatOracleUnknownStrDeinit(void)
{
   if (vf_pu8_unknown_str)
      free(vf_pu8_unknown_str);
   vf_pu8_unknown_str = NULL;
}

crypto_status baatOracle(uint8_t const * const pu8_msg, 
                           uint16_t const u16_msg_len,
                           uint8_t ** pu8_enc_out,
                           int32_t * pi32_enc_out_len)
{
   crypto_status e_status = CRYPTO_ERR;

   if (vf_pu8_unknown_str == NULL)
   {
      DEBUG_CRYPTO("Unknown string not initialized...\n");
   }
   else
   {
      e_status = staticAesKeyCheckAndInit();
      if (e_status == CRYPTO_OK)
      {
         uint8_t * pu8_concat_msg = NULL;
         pu8_concat_msg = (uint8_t *) calloc(u16_msg_len + strlen(vf_pu8_unknown_str) + 1, sizeof(uint8_t));
         if (pu8_msg != NULL && u16_msg_len != 0)
            memcpy(pu8_concat_msg, pu8_msg, u16_msg_len);
         memcpy(&pu8_concat_msg[u16_msg_len], vf_pu8_unknown_str, strlen(vf_pu8_unknown_str));
         pu8_concat_msg[u16_msg_len+strlen(vf_pu8_unknown_str)] = '\0';
         //DEBUG_CRYPTO("The concatenated str is: %s\n", pu8_concat_msg);

         uint8_t * pu8_temp_encryption = NULL;
         int32_t i32_temp_encryption_len = 0;
         e_status = encryptBufferAesEcbStaticKey(pu8_concat_msg, u16_msg_len+strlen(vf_pu8_unknown_str), &pu8_temp_encryption, &i32_temp_encryption_len);

         if (pu8_concat_msg)
            free(pu8_concat_msg);
         pu8_concat_msg = NULL;

         if (e_status != CRYPTO_OK)
         {
            DEBUG_CRYPTO("Error while encrypting concatenated message...\n");
            *pu8_enc_out = NULL;
            *pi32_enc_out_len = 0;
         }
         else
         {
            if (pu8_enc_out != NULL)
               *pu8_enc_out = pu8_temp_encryption;
            else
            {
               if (pu8_temp_encryption)
                  free(pu8_temp_encryption);
               pu8_temp_encryption = NULL;
            }
            *pi32_enc_out_len = i32_temp_encryption_len;
         }
      }
   }

   return e_status;
}

crypto_status guessOracleBlockSize(uint16_t * u16_guessed_blocksize)
{
   crypto_status EStatus = CRYPTO_ERR;
   uint8_t * pu8_msg = NULL;
   uint8_t * pu8_temp_cipher = NULL;
   uint8_t * pu8_prev_cipher = NULL;
   int32_t i32_temp_cipherlen = 0;
   uint16_t u16_blocksize = 1;

   while (u16_blocksize < 1024)
   {
      pu8_msg = (uint8_t *) realloc(pu8_msg, u16_blocksize);
      memset(pu8_msg, 'A', u16_blocksize);
      EStatus = baatOracle(pu8_msg, u16_blocksize, &pu8_temp_cipher, &i32_temp_cipherlen);
      if (EStatus != CRYPTO_OK)
      {
         u16_blocksize = 0;
         break;
      }

      if (u16_blocksize != 1)
      {
         if(0 == memcmp(pu8_temp_cipher, pu8_prev_cipher, 4))
         {
            u16_blocksize--;
            break;
         }
      }
      pu8_prev_cipher = (uint8_t *) realloc(pu8_prev_cipher, i32_temp_cipherlen);
      memcpy(pu8_prev_cipher, pu8_temp_cipher, i32_temp_cipherlen);

      if (pu8_temp_cipher)
         free(pu8_temp_cipher);
      pu8_temp_cipher = NULL;

      u16_blocksize++;
   }

   if (pu8_msg)
      free(pu8_msg);
   pu8_msg = NULL;

   if (pu8_temp_cipher)
      free(pu8_temp_cipher);
   pu8_temp_cipher = NULL;

   if (pu8_prev_cipher)
      free(pu8_prev_cipher);
   pu8_prev_cipher = NULL;

   *u16_guessed_blocksize = u16_blocksize;
   return EStatus;
}

crypto_status oneByteAtATime_ECB_Decryption(uint8_t const * const pu8_unknown_msg, uint16_t const u16_msg_len,
                                             uint8_t const * const pu8_rand_prepend, 
                                             uint8_t u8_rand_prepend_len,
                                             uint8_t ** ppu8_obtained_unknown_msg)
{
   crypto_status EStatus = CRYPTO_ERR;

   // Initialize unknown string
   EStatus = baatOracleUnknownStrInit(pu8_unknown_msg, u16_msg_len);

   // Guess key blocksize
   uint16_t u16_guessed_blocksize = 0;
   EStatus = guessOracleBlockSize(&u16_guessed_blocksize);
   if (EStatus != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error guessing the key blocksize!\n");
      return EStatus;
   }

   DEBUG_CRYPTO("<INFO> The guessed blocksize is: %d\n", u16_guessed_blocksize);

   // Now We want to know the length of the plaintext. As the Oracle uses PKCS#7 padding, the
   // padding will add the number of bytes necessaries to complete a block. So, we will encrypt
   // an empty message (only the unknown message) and store the size. Then, increment the plaintext
   // one by one and when a size increase is observed, means we filled a block.
   int32_t i32_plaintext_len = 0;
   EStatus = baatOracle(NULL, 0, NULL, &i32_plaintext_len);

   uint8_t * pu8_temp = NULL;

   for (uint16_t u16_cont = 1; u16_cont < u16_guessed_blocksize; u16_cont++)
   {
      int32_t i32_actual_len = 0;
      pu8_temp = (uint8_t *) realloc(pu8_temp, u16_cont);
      memset(pu8_temp, 'S', u16_cont);
      EStatus = baatOracle(pu8_temp, u16_cont, NULL, &i32_actual_len);

      if (i32_actual_len != i32_plaintext_len)
      {
         i32_plaintext_len -= u16_cont;
         break;
      }
   }
   if (pu8_temp)
      free(pu8_temp);
   pu8_temp = NULL;

   DEBUG_CRYPTO("<INFO> Plaintext length calculated --> %d\n", i32_plaintext_len);

   // Detect ECB mode
   // Minimum 2 equal blocks to get same encryption of 2 blocks.
   uint8_t *pu8_my_ecb_detection_str = (uint8_t *) calloc(u16_guessed_blocksize*2, sizeof(uint8_t));
   memset(pu8_my_ecb_detection_str, 'A', u16_guessed_blocksize*2);
   uint8_t * pu8_ecb_detection_input_cipher = NULL;
   int32_t i32_ecb_detection_input_cipherlen = 0;

   EStatus = baatOracle(pu8_my_ecb_detection_str, u16_guessed_blocksize*2, &pu8_ecb_detection_input_cipher, &i32_ecb_detection_input_cipherlen);
   if (pu8_my_ecb_detection_str)
      free(pu8_my_ecb_detection_str);
   pu8_my_ecb_detection_str = NULL;
   if (EStatus != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Error with encription for AES mode detection...\n");
      if (pu8_ecb_detection_input_cipher)
         free(pu8_ecb_detection_input_cipher);
      pu8_ecb_detection_input_cipher = NULL;
      return EStatus;
   }

   EStatus = Detect_AES_ECB(pu8_ecb_detection_input_cipher, i32_ecb_detection_input_cipherlen, u16_guessed_blocksize);
   if (pu8_ecb_detection_input_cipher)
      free(pu8_ecb_detection_input_cipher);
   pu8_ecb_detection_input_cipher = NULL;
   if (EStatus != CRYPTO_OK)
   {
      DEBUG_CRYPTO("Not ECB detected, cannot use One-byte-at-a-time option...\n");
      return EStatus;
   }

   DEBUG_CRYPTO("<INFO> Detected ECB cipher mode!\n");

   // Now finally, we can proceed to break the oracle
   // i32_idx is the byte we are trying to get from the unkbown string...
   uint8_t * pu8_discovered_text = NULL;
   int32_t i32_discovered_len = 0;
   uint16_t u16_guessing_block = 0;

   if (pu8_rand_prepend == NULL)
      u8_rand_prepend_len = 0;

   for (int32_t i32_idx = 0; i32_idx < i32_plaintext_len; i32_idx++)
   {
      uint16_t u16_inv_padding_len;
      uint16_t u16_padding_len;
      if (0 != i32_discovered_len)
      {
         if (u16_guessing_block == 0 && (i32_discovered_len % (u16_guessed_blocksize - u8_rand_prepend_len)) == 0)
            u16_guessing_block++;
         else if ((i32_discovered_len % u16_guessed_blocksize) == 0)
            u16_guessing_block++;
      }

      u16_inv_padding_len = i32_idx % (u16_guessed_blocksize-u8_rand_prepend_len);
      u16_padding_len = u16_guessed_blocksize-u16_inv_padding_len-u8_rand_prepend_len-1;
      if (u8_rand_prepend_len != 0 && u16_guessing_block != 0)
      {
         u16_inv_padding_len = i32_idx % u16_guessed_blocksize;
      u16_padding_len = (u16_guessed_blocksize - u8_rand_prepend_len) + u16_guessed_blocksize-u16_inv_padding_len-1;
      }

      uint16_t u16_my_str_len = u8_rand_prepend_len + u16_padding_len;
      DEBUG_CRYPTO("Rnd_len : %d, u16_inv_padding: %d, i32_discovred: %d\n", u8_rand_prepend_len, u16_inv_padding_len, i32_discovered_len);
      DEBUG_CRYPTO("Padding length: %d\n", u16_padding_len);
      uint8_t * pu8_my_str = (uint8_t *) calloc(u16_my_str_len, sizeof(uint8_t));
      if(pu8_rand_prepend)
         memcpy(pu8_my_str, pu8_rand_prepend, u8_rand_prepend_len);
      memset(&pu8_my_str[u8_rand_prepend_len], 'A', u16_padding_len);

      uint8_t * pu8_oracle_output = NULL;
      int32_t i32_oracle_outlen = 0;
      EStatus = baatOracle(pu8_my_str, u16_my_str_len, &pu8_oracle_output, &i32_oracle_outlen);

      uint8_t * pu8_dictionary = (uint8_t *) calloc(u16_my_str_len+i32_discovered_len+1, sizeof(uint8_t));
      if(pu8_rand_prepend)
         memcpy(pu8_dictionary, pu8_rand_prepend, u8_rand_prepend_len);
      memset(&pu8_dictionary[u8_rand_prepend_len], 'A', u16_padding_len);
      if (i32_discovered_len != 0)
      {
         memcpy(&pu8_dictionary[u16_my_str_len], pu8_discovered_text, i32_discovered_len);
      }

      DEBUG_CRYPTO("Dictionary base str is: %s\n", pu8_dictionary);

      uint8_t * pu8_oracle_dictionary_out = NULL;
      for (uint16_t u16_idx = 0; u16_idx < 256; u16_idx++)
      {
         int32_t i32_oracle_dictionary_outlen = 0;
         pu8_dictionary[u16_my_str_len+i32_discovered_len] = u16_idx;
         //DEBUG_CRYPTO("Trying dictionary attempt: %s\n", pu8_dictionary);
         EStatus = baatOracle(pu8_dictionary, u16_my_str_len+i32_discovered_len+1, &pu8_oracle_dictionary_out, &i32_oracle_dictionary_outlen);

         if (0 == memcmp(&pu8_oracle_dictionary_out[u16_guessing_block*u16_guessed_blocksize], &pu8_oracle_output[u16_guessing_block*u16_guessed_blocksize], u16_guessed_blocksize))
         {
            DEBUG_CRYPTO("Found character %d (block #%d) of unknown str! --> %c\n", i32_idx, u16_guessing_block, u16_idx);
            pu8_discovered_text = (uint8_t *) realloc(pu8_discovered_text, (i32_discovered_len+1) * sizeof (uint8_t));
            pu8_discovered_text[i32_discovered_len] = u16_idx;
            i32_discovered_len += 1;

            if (pu8_oracle_dictionary_out)
               free(pu8_oracle_dictionary_out);
            pu8_oracle_dictionary_out = NULL;

            break;
         }

         if (pu8_oracle_dictionary_out)
            free(pu8_oracle_dictionary_out);
         pu8_oracle_dictionary_out = NULL;
      }

      if (pu8_dictionary)
         free(pu8_dictionary);
      pu8_dictionary = NULL;

      if (pu8_my_str)
         free(pu8_my_str);
      pu8_my_str = NULL; 

      if (pu8_oracle_output)
         free(pu8_oracle_output);
      pu8_oracle_output = NULL;     
   }

   pu8_discovered_text = (uint8_t *) realloc(pu8_discovered_text, (i32_discovered_len+1) * sizeof (uint8_t));
   pu8_discovered_text[i32_discovered_len] = '\0';

   *ppu8_obtained_unknown_msg = pu8_discovered_text;

   baatOracleUnknownStrDeinit();
   staticAesKeyRemove();
   
   return EStatus;
}

crypto_status oneByteAtATime_ECB_Decryption_Harder(uint8_t const * const pu8_unknown_msg, uint16_t const u16_msg_len,
                                                   uint8_t ** ppu8_obtained_unknown_msg)
{
   crypto_status e_status = CRYPTO_ERR;

   uint8_t u8_rnd_prepend_len = 0;
   // We will assume that the random prepend length will be smaller than the block size, and at least of 1 byte.
   // In this case prepend contained [1, 15].
   srandom(time(NULL));
   u8_rnd_prepend_len = (random() % ((AES128_KEY_SIZE - 1) - 1 + 1)) + 1;
   uint8_t * pu8_rnd_prepend = (uint8_t *) calloc(u8_rnd_prepend_len, sizeof(uint8_t));
   GeneratePseudoRandomBytes(pu8_rnd_prepend, u8_rnd_prepend_len);
   DEBUG_CRYPTO("Random bytes number: %d\n", u8_rnd_prepend_len);

   // Initialize unknown string
   e_status = baatOracleUnknownStrInit(pu8_unknown_msg, u16_msg_len);

   // Obtain random prepend length by seeing when does the first block maintain equal
   uint8_t u8_guessed_rnd_len = 0;

   uint8_t u8_temp_str_len = 1;
   uint8_t a16_pu8_prev_result[AES128_KEY_SIZE] = {0};
   // One full block of iterations
   while (u8_temp_str_len <= AES128_KEY_SIZE)
   {
      uint8_t * pu8_temp_str = NULL;
      uint8_t * pu8_result = NULL;
      int32_t i32_resulting_len = 0;

      pu8_temp_str = (uint8_t *) calloc(u8_rnd_prepend_len + u8_temp_str_len, sizeof(uint8_t));
      memcpy(pu8_temp_str, pu8_rnd_prepend, u8_rnd_prepend_len);
      memset(pu8_temp_str+u8_rnd_prepend_len, 'A', u8_temp_str_len);
      e_status = baatOracle(pu8_temp_str, u8_rnd_prepend_len+u8_temp_str_len, &pu8_result, &i32_resulting_len);

      if (u8_temp_str_len > 1 && 0 == memcmp(a16_pu8_prev_result, pu8_result, AES128_KEY_SIZE))
      {
         u8_guessed_rnd_len = (AES128_KEY_SIZE - (u8_temp_str_len - 1));
         DEBUG_CRYPTO("Found random prepend length candidate --> %" PRIu8 " (real rnd lenght = %" PRIu8 ")\n", 
                        u8_guessed_rnd_len,
                        u8_rnd_prepend_len);
         if (pu8_result)
            free(pu8_result);
         pu8_result = NULL;

         if (pu8_temp_str)
            free(pu8_temp_str);
         pu8_temp_str = NULL;
         break;
      }

      memcpy(a16_pu8_prev_result, pu8_result, AES128_KEY_SIZE);
      if (pu8_result)
         free(pu8_result);

      if (pu8_temp_str)
         free(pu8_temp_str);
      pu8_temp_str = NULL;

      u8_temp_str_len++;
   }

   e_status = oneByteAtATime_ECB_Decryption(pu8_unknown_msg, u16_msg_len, pu8_rnd_prepend, u8_guessed_rnd_len, ppu8_obtained_unknown_msg);
   
   /* Clean-up */
   baatOracleUnknownStrDeinit();
   staticAesKeyRemove();

   if (pu8_rnd_prepend)
      free(pu8_rnd_prepend);
   pu8_rnd_prepend = NULL;

   return e_status;
}

crypto_status AES128CBC_decrypt_OpenSSL(uint8_t const * const pu8_ciphertxt,
                                       uint16_t const u16_cipherlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t const * const pu8_initial_iv,
                                       uint8_t ** const ppu8_plaintxt,
                                       uint16_t * const pu16_plainlen)
{
   crypto_status e_status = CRYPTO_ERR;

   uint8_t a16_u8_iv[AES128_KEY_SIZE] = {0};
   memcpy(a16_u8_iv, pu8_initial_iv, AES128_KEY_SIZE);

   if (0 != (u16_cipherlen % AES128_KEY_SIZE))
   {
      LOG_CRYPTO_ERROR("Ciphertext is not a multiple of the AES128 block size (16)...\n");
      return e_status;
   }

   uint16_t u16_num_iter = u16_cipherlen / AES128_KEY_SIZE;
   uint8_t * pu8_temp_buf = NULL;
   int i_templen = 0;

   e_status = DecryptAES128_ECB_OpenSSL(pu8_ciphertxt, u16_cipherlen, pu8_key, &pu8_temp_buf, &i_templen);
   if (e_status != CRYPTO_OK)
   {
      LOG_CRYPTO_ERROR("Could not decrypt ciphertext...\n");
      if (pu8_temp_buf)
      {
         free(pu8_temp_buf);
         pu8_temp_buf = NULL;
      }
      return e_status;
   }

   for (int i = 0; i < u16_num_iter; ++i)
   {

      e_status = FixedXOR(a16_u8_iv, &pu8_temp_buf[i*AES128_KEY_SIZE], AES128_KEY_SIZE, AES128_KEY_SIZE, &pu8_temp_buf[i*AES128_KEY_SIZE]);
      if (e_status != CRYPTO_OK)
      {
         LOG_CRYPTO_ERROR("Fixed XOR went wrong...\n");
         if (pu8_temp_buf)
         {
            free(pu8_temp_buf);
            pu8_temp_buf = NULL;
         }
         break;
      }
      
      memcpy(a16_u8_iv, &pu8_ciphertxt[i*AES128_KEY_SIZE], AES128_KEY_SIZE);
   }

   *ppu8_plaintxt = pu8_temp_buf;
   *pu16_plainlen = i_templen;
   return e_status;
}

crypto_status AES128CBC_encrypt_OpenSSL(uint8_t const * const pu8_plaintxt,
                                       uint16_t const u16_plainlen,
                                       uint8_t const * const pu8_key,
                                       uint8_t const * const pu8_initial_iv,
                                       uint8_t ** const ppu8_ciphertxt,
                                       uint16_t * const pu16_cipherlen
                                       )
{
   crypto_status e_status = CRYPTO_ERR;

   uint8_t * pu8_plaintxt_pad = NULL;
   uint8_t a16_u8_iv[AES128_KEY_SIZE] = {0};
   uint32_t u32_plainlen_pad = 0;

   memcpy(a16_u8_iv, pu8_initial_iv, AES128_KEY_SIZE);

   if (CRYPTO_OK != PCKS7_pad_validation(pu8_plaintxt, u16_plainlen, AES128_KEY_SIZE, NULL))
   {
      // Not padded, padding...
      e_status = PKCS7_pad(pu8_plaintxt, u16_plainlen, AES128_KEY_SIZE, &pu8_plaintxt_pad, &u32_plainlen_pad);
      if (e_status != CRYPTO_OK)
         return e_status;
   }
   else
   {
      // Valid pad already, no need to pad...
      u32_plainlen_pad = u16_plainlen;
      pu8_plaintxt_pad = (uint8_t *) calloc(u16_plainlen, sizeof(uint8_t));
      memcpy(pu8_plaintxt_pad, pu8_plaintxt, u16_plainlen);
   }

   uint16_t u16_num_iter = u32_plainlen_pad / AES128_KEY_SIZE;
   uint8_t * pu8_temp_result = (uint8_t *) calloc(u32_plainlen_pad, sizeof(uint8_t));
   uint8_t * pu8_block_cipher_feed = (uint8_t *) calloc(AES128_KEY_SIZE, sizeof(uint8_t));
   uint8_t * pu8_block_cipher_res = NULL;
   uint16_t u16_cipherlen_res = 0;
   
   for (int i = 0; i < u16_num_iter; ++i)
   {
      
      uint8_t a16_u8_plain_block[AES128_KEY_SIZE] = {0};
      memcpy(a16_u8_plain_block, &pu8_plaintxt_pad[i*AES128_KEY_SIZE], AES128_KEY_SIZE);
      e_status = FixedXOR(a16_u8_iv, a16_u8_plain_block, AES128_KEY_SIZE, AES128_KEY_SIZE, pu8_block_cipher_feed);
      if (e_status != CRYPTO_OK)
      {
         break;
      }

      int32_t i32_cipher_res_len = 0;
      e_status = EncryptAES128_ECB_OpenSSL(pu8_block_cipher_feed, AES128_KEY_SIZE, pu8_key, &pu8_block_cipher_res, &i32_cipher_res_len);
      if (e_status != CRYPTO_OK)
      {
         break;
      }
      
      memcpy(&pu8_temp_result[i*AES128_KEY_SIZE], pu8_block_cipher_res, AES128_KEY_SIZE);
      memcpy(a16_u8_iv, pu8_block_cipher_res, AES128_KEY_SIZE);
      u16_cipherlen_res += AES128_KEY_SIZE;

      free(pu8_block_cipher_res);
      pu8_block_cipher_res = NULL;
      
   }

   if (pu8_block_cipher_feed)
   {
      free(pu8_block_cipher_feed);
   }
   pu8_block_cipher_feed = NULL;

   if (pu8_block_cipher_res)
   {
      free(pu8_block_cipher_res);
   }
   pu8_block_cipher_res = NULL;

   if (pu8_plaintxt_pad)
   {
      free(pu8_plaintxt_pad);
   }
   pu8_plaintxt_pad = NULL;

   if (e_status == CRYPTO_OK)
   {
      *ppu8_ciphertxt = pu8_temp_result;
      *pu16_cipherlen = u16_cipherlen_res;
   }
   
   return e_status;
}

crypto_status AES128CBC_decrypt_and_validate_padding(uint8_t const * const pu8_ciphertext, 
                                                      uint16_t const u16_cipherlen,
                                                      uint8_t a16_u8_iv[AES128_KEY_SIZE])
{
   crypto_status e_retval = CRYPTO_PKCS7_ERR;

   if (pu8_ciphertext == NULL || a16_u8_iv == NULL)
   {
      e_retval = CRYPTO_INVAL;
   }
   else
   {
      uint8_t * pu8_plaintext = NULL;
      int32_t i32_plainlen = 0;
      e_retval = decryptBufferAesCbcStaticKey(pu8_ciphertext, u16_cipherlen,
                                                   a16_u8_iv, &pu8_plaintext, &i32_plainlen);

      if (CRYPTO_OK == e_retval)
      {
         uint16_t u16_pad_count = 0;
         e_retval = PCKS7_pad_validation(pu8_plaintext, i32_plainlen, AES128_KEY_SIZE, &u16_pad_count);
      }
      else
      {
         e_retval = CRYPTO_ERR_SSL;
      }

      if (pu8_plaintext)
         free(pu8_plaintext);
   }

   return e_retval;
}

crypto_status AES128CBC_get_padding_byte_count(uint8_t const * const pu8_ciphertext, 
                                                uint16_t const u16_cipherlen,
                                                uint8_t a16_u8_iv[AES128_KEY_SIZE])
{
   crypto_status e_retval = CRYPTO_ERR;
   
   if (pu8_ciphertext == NULL)
   {
      e_retval = CRYPTO_INVAL;
   }
   else
   {
      uint8_t * pu8_temp_cipher = (uint8_t *) calloc(u16_cipherlen, sizeof(uint8_t));
      memcpy(pu8_temp_cipher, pu8_ciphertext, u16_cipherlen);

      e_retval = AES128CBC_decrypt_and_validate_padding(pu8_temp_cipher, u16_cipherlen, a16_u8_iv);
      if (e_retval == CRYPTO_OK)
      {
         for (uint8_t u8_idx = 1; u8_idx <= AES128_KEY_SIZE + 1; u8_idx++)
         {
            uint16_t u16_ciph_idx = u16_cipherlen - (AES128_KEY_SIZE + u8_idx);
            pu8_temp_cipher[u16_ciph_idx] ^= 0xff;

            e_retval = AES128CBC_decrypt_and_validate_padding(pu8_temp_cipher, u16_cipherlen, a16_u8_iv);
            if (e_retval == CRYPTO_PKCS7_ERR)
            {
               memcpy(pu8_temp_cipher, pu8_ciphertext, u16_cipherlen);
               continue;
            }
            else
            {
               pu8_temp_cipher[u16_ciph_idx] ^= 0x11;
               e_retval = AES128CBC_decrypt_and_validate_padding(pu8_temp_cipher, u16_cipherlen, a16_u8_iv);
               if (e_retval == CRYPTO_PKCS7_ERR)
               {
                  memcpy(pu8_temp_cipher, pu8_ciphertext, u16_cipherlen);
                  continue;
               }
               else
               {
                  e_retval = u8_idx - 1;
                  break;
               }
            }
         }
         if (pu8_temp_cipher)
            free(pu8_temp_cipher);
      }
      else
      {
         LOG_CRYPTO_ERROR("Error, original encrypted text has no valid padding...\n");
      }
   }

   return e_retval;
}

crypto_status AES128CBC_padding_oracle_single_block_attack(uint8_t const * const pu8_cipherblock,
                                                            uint8_t * pu8_cipher_out)
{
   crypto_status e_retval = CRYPTO_ERR;

   if (pu8_cipherblock == NULL || pu8_cipher_out == NULL)
   {
      e_retval = CRYPTO_INVAL;
   }
   else
   {
      uint8_t a16_u8_zeroing_iv[AES128_KEY_SIZE] = {0};
      uint8_t a16_u8_padding_iv[AES128_KEY_SIZE] = {0};

      for (uint8_t u8_pad_val = 1; u8_pad_val <= AES128_KEY_SIZE; u8_pad_val++)
      {
         uint8_t u8_finding_idx = AES128_KEY_SIZE - u8_pad_val;
         FixedXOR_SingleCharASCII(&a16_u8_zeroing_iv[u8_finding_idx], u8_pad_val, u8_pad_val, &a16_u8_padding_iv[u8_finding_idx]);

         for (int16_t u16_candidate = 0; u16_candidate <= 0xFF; u16_candidate++)
         {
            a16_u8_padding_iv[u8_finding_idx] = u16_candidate;
            e_retval = AES128CBC_decrypt_and_validate_padding(pu8_cipherblock, AES128_KEY_SIZE, a16_u8_padding_iv);
            if (e_retval == CRYPTO_OK)
            {
               if (u8_pad_val == 1)
               {
                  a16_u8_padding_iv[u8_finding_idx-1] ^= 0x01;
                  e_retval = AES128CBC_decrypt_and_validate_padding(pu8_cipherblock, AES128_KEY_SIZE,
                                                                     a16_u8_padding_iv);
                  if (e_retval != CRYPTO_OK)
                  {
                     // False positive, cointinue searching...
                     continue;
                  }
               }
               a16_u8_zeroing_iv[u8_finding_idx] = u16_candidate ^ u8_pad_val;
               break;
            }
            if (u16_candidate == 0xFF)
            {
               LOG_CRYPTO_ERROR("Error - Could not find byte #%d... I do not know why...\n", u8_pad_val);
               return CRYPTO_ERR;
            }
         }
      }
      memcpy(pu8_cipher_out, a16_u8_zeroing_iv, AES128_KEY_SIZE);
   }

   return e_retval;
}

crypto_status AES128CBC_padding_oracle_attack(uint8_t const * const pu8_ciphertext,
                                                uint16_t const u16_cipherlen,
                                                uint8_t a16_u8_iv[AES128_KEY_SIZE],
                                                uint8_t ** ppu8_obt_plaintxt,
                                                uint16_t * pu16_obt_plainlen)
{
   crypto_status e_retval = CRYPTO_ERR;

   if (pu8_ciphertext == NULL || a16_u8_iv == NULL)
   {
      e_retval = CRYPTO_INVAL;
   }
   else
   {
      uint16_t u16_num_blocks = u16_cipherlen / AES128_KEY_SIZE;
      uint8_t * pu8_temp_result = (uint8_t *) calloc(u16_cipherlen, sizeof(uint8_t));

      for (uint16_t u16_idx = 0; u16_idx < u16_num_blocks; u16_idx++)
      {
         uint8_t a16_u8_cipher_out[AES128_KEY_SIZE] = {0};
         uint8_t a16_u8_plainblock[AES128_KEY_SIZE] = {0};
         uint8_t a16_u8_prev_block[AES128_KEY_SIZE] = {0};

         e_retval = AES128CBC_padding_oracle_single_block_attack(&pu8_ciphertext[u16_idx * AES128_KEY_SIZE], 
                                                                  a16_u8_cipher_out);
         if (e_retval == CRYPTO_OK)
         {
            if (u16_idx == 0)
            {
               memcpy(a16_u8_prev_block, a16_u8_iv, AES128_KEY_SIZE);
            }
            else
            {
               uint16_t u16_pev_block_idx = u16_idx - 1;
               memcpy(a16_u8_prev_block, &pu8_ciphertext[u16_pev_block_idx * AES128_KEY_SIZE], AES128_KEY_SIZE);
            }
            FixedXOR(a16_u8_prev_block, a16_u8_cipher_out, AES128_KEY_SIZE, AES128_KEY_SIZE, a16_u8_plainblock);
            memcpy(&pu8_temp_result[u16_idx * AES128_KEY_SIZE], a16_u8_plainblock, AES128_KEY_SIZE);
         }
         else
         {
            if (pu8_temp_result)
               free(pu8_temp_result);
            break;
         }
      }

      if (e_retval == CRYPTO_OK)
      {
         uint8_t * pu8_unpad_result = NULL;
         int32_t i32_unpad_result_len = 0;
         e_retval = PKCS7_pad_strip(pu8_temp_result, u16_cipherlen, AES128_KEY_SIZE, 
                                       &pu8_unpad_result, &i32_unpad_result_len);
         if (CRYPTO_OK == e_retval)
         {
            *ppu8_obt_plaintxt = pu8_unpad_result;
            *pu16_obt_plainlen = (uint16_t)i32_unpad_result_len;
            if (pu8_temp_result)
               free(pu8_temp_result);
         }
         else
         {
            if (pu8_temp_result)
               free(pu8_temp_result);
            if (pu8_unpad_result)
               free(pu8_unpad_result);
         }
      }
   }

   return e_retval;
}

crypto_status AES128CTR_gen_ctr_buff(struct SAES128CTR_config const s_ctr_config,
                                       uint32_t const u32_length,
                                       uint8_t ** ppu8_ctr_buff)
{
   crypto_status e_retval = CRYPTO_ERR;

   if (ppu8_ctr_buff == NULL)
   {
      e_retval = CRYPTO_INVAL;
   }
   else
   {
      uint32_t u32_ctr_buff_len = ((u32_length/8) + 1);
      u32_ctr_buff_len = u32_ctr_buff_len % 2 ? u32_ctr_buff_len + 1 : u32_ctr_buff_len;
      uint64_t * pu64_temp_buf = (uint64_t *) calloc(u32_ctr_buff_len, sizeof(uint64_t));

      uint64_t u64_counter = 0;
      for (uint32_t u32_idx = 0; u32_idx < u32_ctr_buff_len; u32_idx+=2)
      {
         pu64_temp_buf[u32_idx] = s_ctr_config.m_u64_nonce;
         pu64_temp_buf[u32_idx+1] = u64_counter;
         u64_counter++;
      }

      uint8_t * pu8_local_ctr_buff = NULL;
      int32_t i32_local_ctr_bufflen = 0;
      e_retval = EncryptAES128_ECB_OpenSSL((uint8_t *)pu64_temp_buf, u32_ctr_buff_len * 8,
                                             s_ctr_config.m_au8_key, &pu8_local_ctr_buff, &i32_local_ctr_bufflen);

      if (e_retval == CRYPTO_OK)
      {
         *ppu8_ctr_buff = pu8_local_ctr_buff;
      }
      else
      {
         if (pu8_local_ctr_buff)
            free(pu8_local_ctr_buff);
      }
      
      if (pu64_temp_buf)
         free(pu64_temp_buf);
      pu64_temp_buf = NULL;
   }

   return e_retval;
}

crypto_status AES128CTR_function(uint8_t const * const pu8_buffer_in,
                                 uint32_t const u32_buffer_in_len,
                                 struct SAES128CTR_config const s_config,
                                 uint8_t ** ppu8_buffer_out)
{
   crypto_status e_retval = CRYPTO_ERR;

   if (pu8_buffer_in == NULL || u32_buffer_in_len == 0 || ppu8_buffer_out == NULL)
   {
      e_retval = CRYPTO_INVAL;
   }
   else
   {
      uint8_t * pu8_ctr_buffer = NULL;
      e_retval = AES128CTR_gen_ctr_buff(s_config, u32_buffer_in_len, &pu8_ctr_buffer);
      
      if (e_retval == CRYPTO_OK)
      {
         uint8_t * pu8_obt_plaintxt = (uint8_t *) calloc(u32_buffer_in_len + 1, sizeof(uint8_t));
         e_retval = FixedXOR(pu8_buffer_in, pu8_ctr_buffer, u32_buffer_in_len, u32_buffer_in_len, pu8_obt_plaintxt);
         if (e_retval == CRYPTO_OK)
         {
            pu8_obt_plaintxt[u32_buffer_in_len] = '\0';
            *ppu8_buffer_out = pu8_obt_plaintxt;
         }
         else
         {
            if (pu8_obt_plaintxt)
               free(pu8_obt_plaintxt);
         }

         if (pu8_ctr_buffer)
            free(pu8_ctr_buffer);
      }
   }

   return e_retval;
}

crypto_status AES128CTR_break_fixed_nonce(struct OArray const * const po_cipherpool,
                                          uint16_t const u16_cipherpool_rows,
                                          uint8_t *** pppu8_plaintxt_pool)
{
   crypto_status e_retval = CRYPTO_ERR;

   if (po_cipherpool == NULL || u16_cipherpool_rows == 0 || pppu8_plaintxt_pool == NULL)
   {
      e_retval = CRYPTO_INVAL;
   }
   else
   {
      // Get the ciphertext with smallest length.
      uint32_t u32_smallest_length = UINT32_MAX;
      for (uint16_t u16_idx = 0; u16_idx < u16_cipherpool_rows; u16_idx++)
      {
         if (po_cipherpool[u16_idx].m_u32_length < u32_smallest_length)
            u32_smallest_length = po_cipherpool[u16_idx].m_u32_length;
      }

      // Reserve memory for the plaintext pool
      uint8_t ** ppu8_aux_plaintext = (uint8_t **) calloc(u16_cipherpool_rows, sizeof(uint8_t *));
      for (uint16_t u16_idx = 0; u16_idx < u16_cipherpool_rows; u16_idx++)
      {
         ppu8_aux_plaintext[u16_idx] = (uint8_t *) calloc(u32_smallest_length + 1, sizeof(uint8_t));
      }

      // Get plaintexts
      uint8_t * pu8_aux_buffer = malloc(u16_cipherpool_rows * sizeof(uint8_t));
      for (uint32_t u32_idx = 0; u32_idx < u32_smallest_length; u32_idx++)
      {
         uint8_t u8_current_idx_key = 0;
         
         for (uint16_t u16_idx = 0; u16_idx < u16_cipherpool_rows; u16_idx++)
         {
            pu8_aux_buffer[u16_idx] = po_cipherpool[u16_idx].m_pu8_data[u32_idx];
         }
         
         e_retval = BreakFixedASCIIXOR_Key(pu8_aux_buffer, u32_smallest_length, &u8_current_idx_key);
         memset(pu8_aux_buffer, 0, u32_smallest_length);
         
         if (e_retval == CRYPTO_OK)
         {
            for (uint16_t u16_idx = 0; u16_idx < u16_cipherpool_rows; u16_idx++)
            {
               ppu8_aux_plaintext[u16_idx][u32_idx] = po_cipherpool[u16_idx].m_pu8_data[u32_idx] ^ u8_current_idx_key;
            }
         }
         else
         {
            break;
         }
      }

      if (pu8_aux_buffer != NULL)
         free(pu8_aux_buffer);
      pu8_aux_buffer = NULL;

      if (e_retval == CRYPTO_OK)
      {
         for (uint16_t u16_idx = 0; u16_idx < u16_cipherpool_rows; u16_idx++)
         {
            ppu8_aux_plaintext[u16_idx][u32_smallest_length] = '\0';
         }
         *pppu8_plaintxt_pool = ppu8_aux_plaintext;
      }
      else
      {
         // Clean-up
         for (uint16_t u16_idx = 0; u16_idx < u16_cipherpool_rows; u16_idx++)
         {
            free(ppu8_aux_plaintext[u16_idx]);
            ppu8_aux_plaintext[u16_idx] = NULL;
         }
         free(ppu8_aux_plaintext);
         ppu8_aux_plaintext = NULL;
      }
   }

   return e_retval;
}

uint32_t MT19937_32_untemper_fnct(uint32_t const u32_original_mt_val)
{
   #define OMT19937_U   11U
   #define OMT19937_D   0xFFFFFFFF

   #define OMT19937_S   7U
   #define OMT19937_B   0x9D2C5680

   #define OMT19937_T   15U
   #define OMT19937_C   0xEFC60000

   #define OMT19937_L   18U

   uint32_t u32_ret_val = 0;

   u32_ret_val = MT19937_32_untemper_right_shift(u32_original_mt_val, OMT19937_L, 0xFFFFFFFF);
   u32_ret_val = MT19937_32_untemper_left_shift(u32_ret_val, OMT19937_T, OMT19937_C);
   u32_ret_val = MT19937_32_untemper_left_shift(u32_ret_val, OMT19937_S, OMT19937_B);
   u32_ret_val = MT19937_32_untemper_right_shift(u32_ret_val, OMT19937_U, OMT19937_D);

   return u32_ret_val;
}

static uint32_t MT19937_32_untemper_right_shift(uint32_t const u32_num, 
                                                uint32_t const u32_shift, 
                                                uint32_t const u32_mask)
{
   uint32_t u32_result = 0;
   for (int8_t i8_bit = 31; i8_bit >= 0; i8_bit--)
   {
      if (i8_bit >= (32 - u32_shift))
      {
         u32_result |= ((1 << i8_bit) & u32_num);
      }
      else
      {
         uint32_t u32_shifted_known = u32_result & (1 << (i8_bit + u32_shift));
         u32_result |= (((u32_shifted_known & u32_mask) >> u32_shift) ^ (u32_num & (1 << i8_bit)));
      }
   }

   return u32_result;
}

static uint32_t MT19937_32_untemper_left_shift(uint32_t const u32_num, 
                                                uint32_t const u32_shift, 
                                                uint32_t const u32_mask)
{
   uint32_t u32_result = 0;
   for (int8_t i8_bit = 0; i8_bit < 32; i8_bit++)
   {
      if (i8_bit < u32_shift)
      {
         u32_result |= ((1 << i8_bit) & u32_num);
      }
      else
      {
         uint32_t u32_shifted_known = (u32_result & (1 << (i8_bit - u32_shift))) << u32_shift;
         u32_result |= (((u32_shifted_known & u32_mask)) ^ (u32_num & (1 << i8_bit)));
      }
   }

   return u32_result;
}

static crypto_status MT19937_32_fnct(uint8_t const * const pu8_buffer,
                                       uint32_t const u32_bufferlen,
                                       struct OMT19937 * const po_mt,
                                       uint8_t ** ppu8_result)
{
   crypto_status e_ret = CRYPTO_ERR;

   if (pu8_buffer == NULL || u32_bufferlen == 0 || ppu8_result == NULL || po_mt == NULL)
   {
      e_ret = CRYPTO_INVAL;
   }
   else
   {
      uint8_t u8_round = 0;
      if (u32_bufferlen < 4)
      {
         u8_round = 4 - u32_bufferlen;
      }
      else if ((u32_bufferlen % 4) != 0)
      {
         u8_round = 4 - (u32_bufferlen % 4);
      }
      uint8_t * pu8_stream_seq = (uint8_t *) calloc(u32_bufferlen + u8_round, sizeof(uint8_t));
      for (uint32_t u32_idx = 0; u32_idx < u32_bufferlen; u32_idx += 4)
      {
         uint32_t u32_rnd_num = OMT19937_get_num(po_mt);
         pu8_stream_seq[u32_idx]    = (u32_rnd_num & 0xFF000000) >> 24;
         pu8_stream_seq[u32_idx+1]  = (u32_rnd_num & 0x00FF0000) >> 16;
         pu8_stream_seq[u32_idx+2]  = (u32_rnd_num & 0x0000FF00) >> 8;
         pu8_stream_seq[u32_idx+3]  = (u32_rnd_num & 0x000000FF);
      }

      uint8_t * pu8_auxbuf = (uint8_t *) calloc(u32_bufferlen+1, sizeof(uint8_t));
      e_ret = FixedXOR(pu8_buffer, pu8_stream_seq, u32_bufferlen, u32_bufferlen, pu8_auxbuf);

      if (e_ret == CRYPTO_OK)
      {
         pu8_auxbuf[u32_bufferlen] = '\0';
         *ppu8_result = pu8_auxbuf;
      }
      else
      {
         free(pu8_auxbuf);
         pu8_auxbuf = NULL;
      }

      free(pu8_stream_seq);
      pu8_stream_seq = NULL;
   }

   return e_ret;
}

struct OMT19937 * pv_o_mt_cipher = NULL;
crypto_status MT19937_32_cipher(uint8_t const * const pu8_plaintxt,
                                 uint32_t const u32_plainlen,
                                 uint16_t const u16_seed,
                                 uint8_t ** ppu8_ciphertext)
{
   if (pv_o_mt_cipher == NULL)
   {
      struct OMT19937 o_mt_temp;
      OMT19937_init(&o_mt_temp);
      OMT19937_seed_mt(&o_mt_temp, u16_seed);

      pv_o_mt_cipher = (struct OMT19937 *) malloc(sizeof(struct OMT19937));
      memcpy(pv_o_mt_cipher, &o_mt_temp, sizeof(struct OMT19937));
   }

   return MT19937_32_fnct(pu8_plaintxt, u32_plainlen, pv_o_mt_cipher, ppu8_ciphertext);
}

struct OMT19937 * pv_o_mt_decipher = NULL;
crypto_status MT19937_32_decipher(uint8_t const * const pu8_ciphertext,
                                 uint32_t const u32_cipherlen,
                                 uint16_t const u16_seed,
                                 uint8_t ** ppu8_plaintxt)
{
   if (pv_o_mt_decipher == NULL)
   {
      struct OMT19937 o_mt_temp;
      OMT19937_init(&o_mt_temp);
      OMT19937_seed_mt(&o_mt_temp, u16_seed);

      pv_o_mt_decipher = (struct OMT19937 *) malloc(sizeof(struct OMT19937));
      memcpy(pv_o_mt_decipher, &o_mt_temp, sizeof(struct OMT19937));
   }

   return MT19937_32_fnct(pu8_ciphertext, u32_cipherlen, pv_o_mt_decipher, ppu8_plaintxt);
}

crypto_status MT19937_32_break_16bit_seed(uint8_t const * const pu8_ciphertxt,
                                          uint32_t const u32_cipherlen,
                                          uint8_t const * const pu8_known_plaintext,
                                          uint16_t * const pu16_found_seed,
                                          uint8_t ** ppu8_plaintext)
{
   crypto_status e_res = CRYPTO_ERR;

   if (pu8_ciphertxt == NULL || pu8_known_plaintext == NULL || ppu8_plaintext == NULL || pu16_found_seed == NULL)
   {
      e_res = CRYPTO_INVAL;
   }
   else
   {
      uint8_t * pu8_deciphertxt = NULL;
      uint16_t u16_found_seed = 0;
      for (uint16_t u16_idx = 0;; u16_idx++)
      {
         struct OMT19937 o_aux_mt;
         OMT19937_init(&o_aux_mt);
         OMT19937_seed_mt(&o_aux_mt, u16_idx);
         if (pu8_deciphertxt)
            free(pu8_deciphertxt);
         e_res = MT19937_32_fnct(pu8_ciphertxt, u32_cipherlen, &o_aux_mt, &pu8_deciphertxt);

         if (NULL != memmem(pu8_deciphertxt, u32_cipherlen, pu8_known_plaintext, strlen(pu8_known_plaintext)))
         {
            u16_found_seed = u16_idx;
            break;
         }

         if (u16_idx == UINT16_MAX - 1 || e_res != CRYPTO_OK)
         {
            e_res = CRYPTO_ERR;
            break;
         }
      }

      if (e_res == CRYPTO_OK)
      {
         *ppu8_plaintext = pu8_deciphertxt;
         *pu16_found_seed = u16_found_seed;
      }
   }

   return e_res;
}

crypto_status MT19937_32_gen_16byte_token(uint8_t ** ppu8_token)
{
   crypto_status e_res = CRYPTO_ERR;

   if (ppu8_token == NULL)
   {
      e_res = CRYPTO_INVAL;
   }
   else
   {
      struct OMT19937 o_loc_mt;
      OMT19937_init(&o_loc_mt);

      uint16_t u16_seed = (time(0) & 0xFFFF);
      OMT19937_seed_mt(&o_loc_mt, u16_seed);

      uint8_t * pu8_aux_token = (uint8_t *) calloc(16, sizeof(uint8_t));

      for (uint32_t u32_idx = 0; u32_idx < 16; u32_idx += 4)
      {
         uint32_t u32_rnd_num = OMT19937_get_num(&o_loc_mt);
         pu8_aux_token[u32_idx]    = (u32_rnd_num & 0xFF000000) >> 24;
         pu8_aux_token[u32_idx+1]  = (u32_rnd_num & 0x00FF0000) >> 16;
         pu8_aux_token[u32_idx+2]  = (u32_rnd_num & 0x0000FF00) >> 8;
         pu8_aux_token[u32_idx+3]  = (u32_rnd_num & 0x000000FF);
      }

      *ppu8_token = pu8_aux_token;
      e_res = CRYPTO_OK;
   }

   return e_res;
}

crypto_status MT19937_32_verify_token(uint8_t const a16u8_token[16])
{
   crypto_status e_ret = CRYPTO_ERR;

   for (uint32_t u32_idx = 0; u32_idx < UINT16_MAX; ++u32_idx)
   {
      struct OMT19937 o_loc_mt;
      OMT19937_init(&o_loc_mt);
      OMT19937_seed_mt(&o_loc_mt, u32_idx);

      for (uint8_t u8_sub_idx = 0; u8_sub_idx < 16; u8_sub_idx += 4)
      {
         uint32_t u32_rng_gen = OMT19937_get_num(&o_loc_mt);
         uint32_t u32_token_num = 0;
         u32_token_num |= a16u8_token[u8_sub_idx] << 24;
         u32_token_num |= a16u8_token[u8_sub_idx+1] << 16;
         u32_token_num |= a16u8_token[u8_sub_idx+2] << 8;
         u32_token_num |= a16u8_token[u8_sub_idx+3];

         if (u32_rng_gen != u32_token_num)
         {
            break;
         }
         else if (u8_sub_idx == 12)
         {
            e_ret = CRYPTO_OK;
         }
      }

      if (CRYPTO_OK == e_ret)
      {
         break;
      }
   }

   return e_ret;
}