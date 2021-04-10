#include <iostream>
#include <fstream>
#include <string.h>
#include <bitset>
#include <math.h>
using namespace std;

// Declaration of functions
int hammingDistance(string a, string b);
string base64ToBin(string str);
string crack_Key(string message_bin, char& key, double& most_English);
string stringXOR(string a, string b);
string decrypt(string message, string key);
double englishness(string attempt);

string binToBase64(string);
int binaryToDecimal(int);

// Global variables
static char Base64Digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// English letter frequency mapping table from Wikipedia
static double letterFreq[26] = {0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966,\
						 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,\
						 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074};


// Main function
int main(void){

	// Testing the Hamming distance calculation function with given examples
	string str1 = "this is a test";
	string str2 = "wokka wokka!!!";

	int hamming_dis = hammingDistance(str1, str2);
	cout << "Hamming distance between \"" << str1 << "\" and \"" << str2 << "\" is " << hamming_dis << endl;

	// File reading and data storing
	ifstream file;
	string data, temp;

	file.open("input.txt");

	while(!file.eof()){
		file >> temp;
		data.append(temp);
	}

	file.close();

	//cout << data << endl << endl;

	// Actual decryption
	int KEYSIZE_tries[4];
	double thresholds[4] = {500, 500, 500, 500};
	string bin_data;

	// Convert Base64 to Binary
	bin_data = base64ToBin(data);

	string text_try = binToBase64(bin_data);
	//cout << text_try << endl;

	//cout << bin_data << endl;
	int len = bin_data.length();

	for(int KEYSIZE=2; KEYSIZE<41; KEYSIZE++){
		double sum_norm_HD = 0.0;
		for(int i=0; i<(bin_data.length()/(KEYSIZE*8)); i+=2){
			str1 = bin_data.substr(i*8*KEYSIZE, KEYSIZE*8);
			str2 = bin_data.substr((i+1)*8*KEYSIZE, KEYSIZE*8);

			// Calculate Hamming distance between the two consecutive byte*KEYSIZE
			sum_norm_HD += double(hammingDistance(str1, str2))/double(KEYSIZE);
			
		}

		// Average the total value of the total normalized distance
		double avg_distance = sum_norm_HD/(bin_data.length()/(KEYSIZE*8));

		// Store the most probable KEYSIZEs and update the thresholds
		if(avg_distance < thresholds[0]){ 
			KEYSIZE_tries[3] = KEYSIZE_tries[2]; thresholds[3] = thresholds[2];
			KEYSIZE_tries[2] = KEYSIZE_tries[1]; thresholds[2] = thresholds[1];
			KEYSIZE_tries[1] = KEYSIZE_tries[0]; thresholds[1] = thresholds[0];
			KEYSIZE_tries[0] = KEYSIZE; thresholds[0] = avg_distance;
		}
		else if(avg_distance < thresholds[1]){ 
			KEYSIZE_tries[3] = KEYSIZE_tries[2]; thresholds[3] = thresholds[2];
			KEYSIZE_tries[2] = KEYSIZE_tries[1]; thresholds[2] = thresholds[1];
			KEYSIZE_tries[1] = KEYSIZE; thresholds[1] = avg_distance;
		}
		else if(avg_distance < thresholds[2]){ 
			KEYSIZE_tries[3] = KEYSIZE_tries[2]; thresholds[3] = thresholds[2];
			KEYSIZE_tries[2] = KEYSIZE; thresholds[2] = avg_distance;
		}
		else if(avg_distance < thresholds[3]){ 
			KEYSIZE_tries[3] = KEYSIZE; thresholds[3] = avg_distance;
		}

		//cout << "KEYSIZE: " << KEYSIZE << " --> avg_distance: " << avg_distance << endl;
	}

	cout << "The possible Keysizes are: " << KEYSIZE_tries[0] << " " << KEYSIZE_tries[1]\
	<< " " << KEYSIZE_tries[2] << " " << KEYSIZE_tries[3] << endl;
	cout << "Their thresholds are: " << thresholds[0] << " " << thresholds[1]\
	<< " " << thresholds[2] << " " << thresholds[3] << endl;

	// Attempting with the most probable keysize
	int keysize = KEYSIZE_tries[0];
	int keysize_size = keysize*8;
	int size = ceil(double(len)/double(keysize_size));
	string blocks[size];
	
	int cont = 0;
	for(int i=0; i<bin_data.length(); i += keysize_size){
		blocks[cont] = bin_data.substr(i, keysize_size);
		//cout << blocks[cont] << endl;
		cont++;
	}
	string bytes[keysize];
	char key_char;
	string key;
	for(int i=0; i<keysize; i++){
		double englishness = 0;
		for(int j=0; j<cont-1; j++){
			bytes[i].append(blocks[j].substr(i*8, 8));
			//cout << bytes[i][j] << endl;
		}
		crack_Key(bytes[i], key_char, englishness);
		key.push_back(key_char);
	}
	//cout << char(::tolower(key[0])) << endl;

	cout << "The obtained key is \"" << key << "\" for KEYSIZE = " << keysize << endl;
	//cout << decrypted_message << endl;
	
}

// Function to calculate Hamming distance between 2 strings
int hammingDistance(string a, string b){
	
	string a_bin, b_bin;
	int dist = 0;

	// Loop through each character of the strings
	for(int i=0; i<a.length(); i++){
		a_bin = bitset<8>(a[i]).to_string();
		b_bin = bitset<8>(b[i]).to_string();

		// Loop through the obtained bytes and compare the bits
		for(int j=0; j<8; j++){
			if(a_bin[j] != b_bin[j]) dist++;
		}
	}

	return dist;
}

// Function to convert Base64 to Binary, getting the index to the matching characters value
// and converting this index to a 6 bit binary number.
string base64ToBin(string str){

	string bin_str;
	char* finding;
	int index;

	for(int i=0; i<str.length(); i++){
		if(str[i] != '='){
			finding = strchr(Base64Digits, str[i]);
			index = (int)(finding - Base64Digits);
			bin_str.append(bitset<6>(index).to_string());
		}
	}

	return bin_str;
}


// Binary to Base64 conversion function
string binToBase64(string BinEncoded){

	string Base64Encoded;
	// Loop through the binary string with a gap of value 6
	// (because for Base64 6 bits are needed)
	for(int i=0; i<BinEncoded.length(); i += 6){
		// Get a substring of 6 characters
		string Digit = BinEncoded.substr(i, 6);
		// Convert the 6 binary string into an integer
		int int_bin_Digit = stoi(Digit);
		// Convert the integer (still in binary format) to Decimal
		int Dec_Digit = binaryToDecimal(int_bin_Digit);
		// Use the obtained decimal value to map the corresponding character
		// from the static char Base64Digits
		char temp = Base64Digits[Dec_Digit];
		// Convert the char into a string and append it in the end of the 
		// final result
		Base64Encoded.push_back(temp);
	}
	return Base64Encoded;
}

// Binary to Decimal conversion function
int binaryToDecimal(int n){
	// Variable declaration
    int dec_Out = 0;
    int base = 1;
 
    while (n) {
    	// Base 10 reminder calculation
        int reminder = n % 10;
        // Ignore last digit
        n = n / 10;
 		
 		// Decimal calculation
        dec_Out += reminder * base;
 		// Base actualization
        base = base * 2;
    }
 
    return dec_Out;
}

string crack_Key(string message_bin, char& key, double& most_English){
	
	unsigned long decrypt_temp;
	string key_bin;
	string res, attempt;
	double score;

	// Loop through all the printable ASCII characters
	//32 --> 127
	for(int i=32; i<127; i++){

		attempt = "";
		int freq[26] = {}, ignored = 0;
		key_bin = bitset<8>(i).to_string();

		// XOR the corresponding message byte with the actual test key
		for(int j=0; j<message_bin.length(); j+=8){
			string byte = message_bin.substr(j, 8);
			decrypt_temp = bitset<8>(stringXOR(byte, key_bin)).to_ulong();
			attempt.push_back(char(decrypt_temp));
		}

		// Calculate English text score.
		// First, obtain letter frecuency in the plain text.
		for(int i=0; i<attempt.length(); i++){
			int character = int(attempt[i]);
			if (character >= 65 && character <= 90) freq[character-65]++; // Mayus. A-Z stored throug 0-25
			else if(character >= 97 && character <= 122) freq[character-97]++; // Minus. a-z stored through 0-25
			//else if(character == 32) freq[26]++; // SPACE character
			else if(character >= 32 && character <= 126) ignored++; // Punctuation marks 
			else if(character == 9 || character == 10 || character == 13) ignored++; // Punctuation marks
		}

		// Use of Bhattacharyya Coefficient to evaluate how english the plain text is.
		// Coefficient between 0 and 1. Closer to 1, more english.
		score = 0.0;
		for(int i=0; i<26; i++){
			double c=double(freq[i])/double(attempt.length());
			score += sqrt(letterFreq[i]*c);
		}

		
		// Get best score, attempt and key; and update most English value.
		if(score > most_English){
			most_English = score;
			res = attempt;
			key = i;
		}

	}

	return res;

}

string stringXOR(string a, string b){

	string res;

	for (int i=0; i<a.length(); i++){
		if (a[i] == b[i]) res.append("0");
		else res.append("1");
	}

	return res;
}

// Function to decrypt a message
string decrypt(string bin_message, string key){

	string decrypted_message;
	int cont = 0;

	for(int i=0; i<bin_message.length(); i+=8){
		string key_bin = bitset<8>(key[cont]).to_string();

		decrypted_message.push_back(char(bitset<8>(stringXOR(bin_message.substr(i, 8), key_bin)).to_ulong()));
		cont++;
		if(cont >= key.length()) cont = 0;
	}

	return decrypted_message;
}

double englishness(string attempt){

	int freq[26] = {}, ignored = 0;

	for(int i=0; i<attempt.length(); i++){
			int character = int(attempt[i]);
			if (character >= 65 && character <= 90) freq[character-65]++; // Mayus. A-Z stored throug 0-25
			else if(character >= 97 && character <= 122) freq[character-97]++; // Minus. a-z stored through 0-25
			//else if(character == 32) freq[26]++; // SPACE character
			else if(character >= 32 && character <= 126) ignored++; // Punctuation marks 
			else if(character == 9 || character == 10 || character == 13) ignored++; // Punctuation marks
		}

		// Use of Bhattacharyya Coefficient to evaluate how english the plain text is.
		// Coefficient between 0 and 1. Closer to 1, more english.
		double score = 0.0;
		for(int i=0; i<26; i++){
			double c=double(freq[i])/double(attempt.length());
			score += sqrt(letterFreq[i]*c);
		}

	return score;
}