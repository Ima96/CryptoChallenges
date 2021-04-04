#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
#include <math.h>
using namespace std;

// Declare function names
string hexToBin(string);
string stringXOR(string a, string b);
string decrypt(string message, char& key, double& score);

// English letter frequency mapping table from Wikipedia
static double letterFreq[26] = {0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966,\
						 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,\
						 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074};

// Main function
int main(void) {

	// File handling and input data reading
	ifstream file;
	string encoded_str;
	char key;
	double englishness;
	int counter = 1;

	file.open("./input.txt");
	while(!file.eof()){
		// Encrypted message
		file >> encoded_str; 
		// Decrypt message
		string decrypted_message = decrypt(encoded_str, key, englishness);

		// The threshold could be increased and be more accurate including the 
		// SPACE character frequency when calculating the english score.
		if(englishness > 0.7){
			cout << "********** Line #" << counter << " *************" << endl;
			cout << "Given encrypted message is: " << encoded_str << endl;
			cout << "The decrypted message is: " << decrypted_message << endl;
			cout << "With score of: " << englishness << endl;
			cout << "The key for encryption/decryption is: " << key << endl << endl;
		}
		counter++;
	}

	return 0;
}

string decrypt(string message, char& key, double& most_English){
	
	unsigned long decrypt_temp;
	string key_bin;
	string res, attempt;
	double score;
	most_English = 0;

	string message_bin = hexToBin(message);

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

// Hexadecimal to Binary conversion function
string hexToBin(string HexEncoded){

	string BinEncoded;
	// Map each character of the string to its corresponding Binary value
	for (int i = 0; i < HexEncoded.length(); i++){
		switch(HexEncoded[i]){
			case '0':
				BinEncoded.append("0000");
				break;

			case '1':
				BinEncoded.append("0001");
				break;

			case '2':
				BinEncoded.append("0010");
				break;

			case '3':
				BinEncoded.append("0011");
				break;

			case '4':
				BinEncoded.append("0100");
				break;

			case '5':
				BinEncoded.append("0101");
				break;

			case '6':
				BinEncoded.append("0110");
				break;

			case '7':
				BinEncoded.append("0111");
				break;

			case '8':
				BinEncoded.append("1000");
				break;

			case '9':
				BinEncoded.append("1001");
				break;

			case 'A':
			case 'a':
				BinEncoded.append("1010");
				break;

			case 'B':
			case 'b':
				BinEncoded.append("1011");
				break;

			case 'C':
			case 'c':
				BinEncoded.append("1100");
				break;

			case 'D':
			case 'd':
				BinEncoded.append("1101");
				break;

			case 'E':
			case 'e':
				BinEncoded.append("1110");
				break;

			case 'F':
			case 'f':
				BinEncoded.append("1111");
				break;
		}
	}

	return BinEncoded;
}

string stringXOR(string a, string b){

	string res;

	for (int i=0; i<a.length(); i++){
		if (a[i] == b[i]) res.append("0");
		else res.append("1");
	}

	return res;
}


