#include <iostream>
#include <fstream>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

void handleOpenSSLErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

// Function declaration
string decrypt(unsigned char* ciphertext, unsigned char* key, int len);
string base64Decode(string enc_str, unsigned char* u_decoded);

// Global variables
static string Base64Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main(){

	// Initialize error functions
	SSL_load_error_strings();
	ERR_load_crypto_strings();

	// Input file reading
	ifstream file;
	file.open("input.txt");
	string temp, input;

	while(!file.eof()){
		file >> temp;
		input.append(temp);
	}

	// The key for decryption
	unsigned char key[16] = {'Y','E','L','L','O','W',' ','S','U','B','M','A','R','I','N','E'};

	// Length of input message
	int len = input.length();

	// Decode input from Base64
	int dec_len = len*3/4;
	unsigned char u_ciphertext[dec_len];
	base64Decode(input, u_ciphertext);

	// Decrypt the decoded encrypted message using the key and its length.
	string message = decrypt(u_ciphertext, key, dec_len);

	// Output the decrypted message
	cout << "The obtained decrypted message is:\n" << message << endl;

	return 0;
}

// Decryption function description
string decrypt(unsigned char* ciphertext, unsigned char* key, int len){

	// Declaration of decrypted message variable
	unsigned char* plaintext = new unsigned char[len];

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
  	string ret = (char*)plaintext;
  	delete [] plaintext;

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

	return (char*)u_decoded;
}