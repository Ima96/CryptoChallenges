#include <iostream>
#include <fstream>
#include <string.h>
#include <math.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define BLOCK_SIZE 16

using namespace std;

// Function declarations
string base64Decode(string enc_str, unsigned char* u_decoded);
string add_pad(string msg_to_pad, int block_size);
string decrypt_ECB(unsigned char* ciphertext, unsigned char* key, int len);
string encrypt_ECB(unsigned char* message, unsigned char* key, int len);
string decrypt_CBC(unsigned char* str_ciphertext, unsigned char* key, string iv, int len, int block_size);
string encrypt_CBC(string message, unsigned char* key, string iv, int len, int block_size);
string XOR(string a, string b, int size);

void handleOpenSSLErrors(void);

// Global variables
static string Base64Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main(){

	// Initialize error functions
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	// The key for decryption
	unsigned char key[16] = {'Y','E','L','L','O','W',' ','S','U','B','M','A','R','I','N','E'};
	// Initialization Vector - IV
	// All ASCII 0 (NULL) characters
	string IV = {'\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0', '\0'};

	ifstream file;
	file.open("input.txt");

	string temp, input;
	while(!file.eof()){

		file >> temp;
		input.append(temp);
	}
	file.close();

	string message = 
	"This message is a test, this message will be encrypted using a manually programmed CBC mode.\nThis message will be then decrypted again using a manually programmed CBC mode and if it is\ncorrect, both functions are working fine. After this message, the input file coded in Base64\nwill be streamed into and will be decoded and decrypted using the CBC mode function.";

	cout << "The message to encrypt is: " << endl << message << endl;
	string enc_cbc = encrypt_CBC(message, key, IV, message.length(), BLOCK_SIZE);

	string dec_cbc = decrypt_CBC((unsigned char*)enc_cbc.c_str(), key, IV, enc_cbc.length(), BLOCK_SIZE);
	cout << endl << "The obtained message after encryption and decryption is: " << endl << dec_cbc << endl;

	// Decode the base64 input string;
	int b64_enc_len = input.length();
	int cipher_len = b64_enc_len*3/4;
	unsigned char ciphertext[cipher_len];
	string str_ciphertext = base64Decode(input, ciphertext);

	string res = decrypt_CBC(ciphertext, key, IV, cipher_len, BLOCK_SIZE);

	cout << endl << "***** CBC DECRYPTED MESSAGE IN THE FILE IS *****" << endl << res << endl;
	return 0;
}

string decrypt_CBC(unsigned char* u_ciphertext, unsigned char* key, string iv, int len, int block_size){

	string ciphertext((char*)u_ciphertext, len);

	// Decrypt whole ciphertext at once
	string decrypted_ecb = decrypt_ECB(u_ciphertext, key, len);

	// Loop through the ciphertext/decrypted text in 16byte steps and XOR the current
	// decrypted block with the previous ciphertext block. (For the first block the 
	// initialization vector is used).
	string decrypt_block, decrypted_cbc, XORed;
	for(int i=0; i<len; i += block_size){
		// Take corresponding decrypted block
		decrypt_block = decrypted_ecb.substr(i, block_size);
		// XOR the decrypted block with the IV variable
		XORed = XOR(decrypt_block, iv, block_size);
		// Store the result
		decrypted_cbc.append(XORed);
		// Update the IV variable with the previous ciphertext block
		iv = ciphertext.substr(i, block_size);
	}

	return decrypted_cbc;
}

// Decryption function description
string decrypt_ECB(unsigned char* ciphertext, unsigned char* key, int len){

	// Declaration of decrypted message variable
	unsigned char* plaintext = new unsigned char[len];

	//cout << "Cipher len: " << len << " VS ciphertext length: " << strlen((char*)ciphertext) << endl;

	// Create and initialize the context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	// Initialize the Openssl decryption operation with options:
	//   -Specify AES-128-ESC mode - EVP_aes_128_ecb()
	//	 -Engine - NULL
	//	 -Key - key
	// 	 -No Initialization Vector (iv) - NULL
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
    	handleOpenSSLErrors();

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Declare variables of the obtained length of decryption and the final
    // length of the plaintext message
	int outlen;
	int plaintext_len;

	// Perform the decrption process providing the encrypted message(ciphertext) 
	// and its length(len) to obtain the decrypted message(plaintext) and its
	// length(outlen)
   	if(1 != EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, len)) handleOpenSSLErrors();
    plaintext_len = outlen;

    // Finish the decryption process, where additional plaintext bytes can be written.
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen)) handleOpenSSLErrors();
  	plaintext_len += outlen;

  	// Add the null terminator
	plaintext[plaintext_len] = 0;

	// Free the context
	EVP_CIPHER_CTX_free(ctx);

	// Assign the decrypted message to string variable and free the memory
	// The string is assigned this way because there might exist some NULL
	// characters in the unsigned char* plaintext variable that make the 
	// string stop taking following characters, loosing info.
  	string ret((char*)plaintext, plaintext_len);
  	delete [] plaintext;

   	return ret;
}

// Encrypt using CBC mode
string encrypt_CBC(string message, unsigned char* key, string iv, int len, int block_size){

	string msg_padded = add_pad(message, block_size);
	string encrypted_cbc, encrypted_ecb;
	string plaintxt_block, XORed;
	
	unsigned char* u_XORed = new unsigned char[block_size];
	for(int i=0; i<msg_padded.length(); i += block_size){
		
		plaintxt_block = msg_padded.substr(i, block_size);

		XORed = XOR(plaintxt_block, iv, block_size);

		memcpy(u_XORed, XORed.c_str(), block_size);

		encrypted_ecb = encrypt_ECB(u_XORed, key, block_size);

		encrypted_cbc.append(encrypted_ecb);
		iv = encrypted_ecb;
	}

	return encrypted_cbc;
}

// Encryption function description
string encrypt_ECB(unsigned char* message, unsigned char* key, int len){

	// Declaration of decrypted message variable
	unsigned char* ciphertext = new unsigned char[len];

	// Create and initialize the context
	EVP_CIPHER_CTX* enc_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(enc_ctx);

	// Initialize the Openssl decryption operation with options:
	//   -Specify AES-128-ESC mode - EVP_aes_128_ecb()
	//	 -Engine - NULL
	//	 -Key - key
	// 	 -No Initialization Vector (iv) - NULL
	if(1 != EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_ecb(), NULL, key, NULL)) handleOpenSSLErrors();

	EVP_CIPHER_CTX_set_padding(enc_ctx, 0);

    // Declare variables of the obtained length of decryption and the final
    // length of the plaintext message
	int outlen;
	int ciphertext_len;

	// Perform the decrption process providing the encrypted message(ciphertext) 
	// and its length(len) to obtain the decrypted message(plaintext) and its
	// length(outlen)
   	if(1 != EVP_EncryptUpdate(enc_ctx, ciphertext, &outlen, message, len)) handleOpenSSLErrors();
    ciphertext_len = outlen;

    // Finish the decryption process, where additional plaintext bytes can be written.
    if(1 != EVP_EncryptFinal_ex(enc_ctx, ciphertext + outlen, &outlen)) handleOpenSSLErrors();
  	ciphertext_len += outlen;

  	// Add the null terminator
	ciphertext[ciphertext_len] = 0;

	// Free the context
	EVP_CIPHER_CTX_free(enc_ctx);

	// Assign the decrypted message to string variable and free the memory
  	string ret((char*)ciphertext, ciphertext_len);
  	delete [] ciphertext;

   	return ret;
}

// Base64 Decoding function description.
string base64Decode(string enc_str, unsigned char* u_decoded){
	int len = enc_str.length();
	unsigned char enc[4];
	int cont = 0;

	// Loop through each base64 encoded character in the message, in groups of 4
	// in order to obtain 6*4 = 24 bits and this way obtaining 3 decoded bytes
	// (3*8 = 24 bits) at once.
	for(int i=0; i<len; i+=4){

		// Store temporarily the 4 base64 encoded characters.
		enc[0] = Base64Digits.find(enc_str[i]);
		enc[1] = Base64Digits.find(enc_str[i+1]);
		enc[2] = Base64Digits.find(enc_str[i+2]);
		enc[3] = Base64Digits.find(enc_str[i+3]);

		// Take the 6 bits of the decoded base64 first character, and take the first 2 bits
		// of the next one.
		u_decoded[cont] = (enc[0] << 2) + (enc[1] >> 4);
		cont++;
		// Take the LSB 4 bits of the second base64 encoded character, and the 4 MSB of the
		// third b64 character
		u_decoded[cont] = (enc[1] << 4) + (enc[2] >> 2);
		cont++;
		// Take the 2 LSB of the third b64 character and the 6 bits of the 4th character.
		u_decoded[cont] = (enc[2] << 6) + enc[3];
		cont++;
	}

	string ret((char*)u_decoded, cont-1);
	return ret;
}

string add_pad(string msg_to_pad, int block_size){
	int msg_len = msg_to_pad.length();
	string ret_padded;

	/*	1.- If the message length is smaller than the block_size then is as simple as
			substracting the message length from the block_size to obtain the padding
			value.
		2.- If the message length is equal or bigger than the block_size, then there are
			two different cases:

			-If the message length is an integer multiple of block_size, an aditional block
		 		of length "block_size" with byte values of "block_size" is appended, to delimit
		 		that the last byte of the message is not a padding byte.

			-If the message is not a integer multiple of block_size, then the padding value
		   		must be obtained and added. This has been done calculating in how many block_size
		   		groups the message will be divided and then obtaining the length of the last
		   		message block. Substract this value from the block_size and the result is the 
		   		padding value.
	*/
	if(msg_len < block_size){
		int pad_val = block_size - msg_len;
		ret_padded = msg_to_pad;
		for(int i=0; i<pad_val; i++) ret_padded += (char)pad_val;

	}
	else if(msg_len >= block_size){

		if(msg_len % block_size == 0){
			ret_padded = msg_to_pad;
			for(int i=0; i<block_size; i++) ret_padded += (char)block_size;

		}
		else{
			int group_num = ceil((double)msg_len/(double)block_size);
			int last_byte_len = (msg_to_pad.substr((group_num-1)*block_size)).length();
			int pad_val = block_size - last_byte_len;
			ret_padded = msg_to_pad;
			for(int i=0; i<pad_val; i++) ret_padded += pad_val;	

		}
	}

	return ret_padded;
}

// Function to perform a XOR between two strings, and added functionality to 
// return in string and unsigned char* formats.
string XOR(string a, string b, int size){

	unsigned char u_res[size];

	for(int i=0; i<size; i++) u_res[i] = a[i] xor b[i];

	string res((char*)u_res, size);
	return res;
}

// Handle Errors
void handleOpenSSLErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
