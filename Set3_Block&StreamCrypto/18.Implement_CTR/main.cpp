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
string decrypt_ECB(unsigned char* ciphertext, unsigned char* key, int len);
string encrypt_ECB(unsigned char* message, unsigned char* key, int len);
string enc_dec_CTR(string input, unsigned char* key, string nonce);
string XOR(string a, string b, int size);

void handleOpenSSLErrors(void);

// Global variables
// Added the '=' character to decode with padding.
static string Base64Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

int main(){

	// Initialize error functions
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	// The key for decryption
	unsigned char key[16] = {'Y','E','L','L','O','W',' ','S','U','B','M','A','R','I','N','E'};
	// Initialization Vector - IV
	// All ASCII 0 (NULL) characters
	string nonce = {'\0','\0','\0','\0','\0','\0','\0','\0'};

	string message = 
	"This message is a test, this message will be encrypted using CTR mode.\nThis message will be then decrypted again using the CTR mode and if it is correct, the function\nis working fine. After this message, the message provided in the challenge, coded in Base64 will be\ninput to the function and will be decoded and decrypted using the CTR mode function.";

	cout << "The message to encrypt is: " << endl << message << endl;
	string enc_CTR = enc_dec_CTR(message, key, nonce);

	string dec_CTR = enc_dec_CTR(enc_CTR, key, nonce);
	cout << endl << "The obtained message after encryption and decryption is: " << endl << dec_CTR << endl << endl;


	string input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

	int cipher_len = input.length()*3/4;
	unsigned char u_ciphertext[cipher_len];
	string ciphertext = base64Decode(input, u_ciphertext);

	string decrypted = enc_dec_CTR(ciphertext, key, nonce);
	cout << decrypted << endl;

	return 0;
}

/* 	CTR encryption/decription function. The CTR mode is the same for encryption and decryption,
	the only thing that has to be changed is the "input" parameter that is passed to the function.
	If the input is a plaintext, the function will return a CTR encrypted ciphertext string.
	If the input is a ciphertext, the function will return a CTR decrypted plaintext string*/
string enc_dec_CTR(string input, unsigned char* key, string	nonce){

	int in_len = input.length();
	int cont = 0, index = 0;
	string keystream;
	unsigned char counter[8] = {'\0','\0','\0','\0','\0','\0','\0','\0'};
	for(int i=0; i<in_len; i += 16){
		string temp((char*)counter, 8);
		keystream.append(nonce);
		keystream.append(temp);
		cont++;
		counter[index] = (char)cont;

		if(cont == 256){
			cont = 0;
			counter[0] = '\0';
			index++;
		}
		if(index == 8) index = 0;
	}

	string encrypted_keystream = encrypt_ECB((unsigned char*)keystream.c_str(), key, keystream.length());

	string output = XOR(encrypted_keystream, input, in_len);
	return output;
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

		if(i < len-4){
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
		else{
			if((int)enc[2] != 64 && (int)enc[3] != 64){
				// No padding, decode normally to add 3 new characters.
				u_decoded[cont] = (enc[0] << 2) + (enc[1] >> 4);
				cont++;

				u_decoded[cont] = (enc[1] << 4) + (enc[2] >> 2);
				cont++;

				u_decoded[cont] = (enc[2] << 6) + enc[3];
				cont++;
			}
			else if(enc[2] != 64 && enc[3] == 64){
				// 1 padding character, so only 2 new characters added.
				u_decoded[cont] = (enc[0] << 2) + (enc[1] >> 4);
				cont++;

				u_decoded[cont] = (enc[1] << 4) + (enc[2] >> 2);
				cont++;
			}
			else if(enc[2] == 64 && enc[3] == 64){
				// 2 padding characters, only 1 new character added.
				u_decoded[cont] = (enc[0] << 2) + (enc[1] >> 4);
				cont++;
			}
		}

	}

	string ret((char*)u_decoded, cont);
	return ret;
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