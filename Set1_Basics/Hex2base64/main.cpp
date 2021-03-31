#include <iostream>
#include <fstream>
#include <string>
using namespace std;

// Declare function names
string hexToBin(string);
string binToBase64(string);
int binaryToDecimal(int);

// Global variables
static char Base64Digits[] =
 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Main function
int main(void) {

	// Get the hexadecimal string from string.txt file
	ifstream file;
	string HexEncoded;

	file.open("string.txt");
	if (file.is_open()) {
		while (!file.eof()) {
			file >> HexEncoded;
		}
	}

	file.close();

	// Convert from Hexadecimal to Binary
	string BinEncoded = hexToBin(HexEncoded);

	// Encode into Base64
	string Base64Encoded = binToBase64(BinEncoded);

	// Print result
	cout << "The Base64 encoded string is: " << Base64Encoded << endl;

	return 0;
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