#include <iostream>
#include <string>
#include <bitset>
using namespace std;

// Declare function names
string stringXOR(string a, string b);
string encrypt(string message, string key);
string binToHex(string str);
// For testing obtained result
string hexToBin(string HexEncoded);
string decrypt(string message, string key);

// Main function
int main(void) {

	string str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	string key = "ICE";


	string encrypted_message;
	encrypted_message = encrypt(str, key);

	cout << "The encrypted version is: \n" << encrypted_message << endl;

	// For ensuring that the obtained encrypted message is correct in just one line.
	string test = decrypt(encrypted_message, key);
	cout << "The obtained encrypted message is decrypted as:" << endl << test << endl;

	return 0;
}

// Function to encrypt a message
string encrypt(string message, string key){

	string encrypted_message_bin, encrypted_message_hex;
	int cont = 0;

	for(int i=0; i<message.length(); i++){
		string character = bitset<8>(message[i]).to_string();
		string key_bin = bitset<8>(key[cont]).to_string();

		encrypted_message_bin.append(stringXOR(character, key_bin));
		cont++;
		if(cont >= 3) cont = 0;
	}
	encrypted_message_hex = binToHex(encrypted_message_bin);
	return encrypted_message_hex;
}

// Function to decrypt a message
string decrypt(string message, string key){

	string bin_message = hexToBin(message);
	string decrypted_message;
	int cont = 0;

	for(int i=0; i<bin_message.length(); i+=8){
		string key_bin = bitset<8>(key[cont]).to_string();

		decrypted_message.push_back(char(bitset<8>(stringXOR(bin_message.substr(i, 8), key_bin)).to_ulong()));
		cont++;
		if(cont >= 3) cont = 0;
	}

	return decrypted_message;
}

// Function to perform a XOR between two binary strings
string stringXOR(string a, string b){

	string res;

	for (int i=0; i<a.length(); i++){
		if (a[i] == b[i]) res.append("0");
		else res.append("1");
	}

	return res;
}

// Function to convert from binary to hexadecimal
string binToHex(string str){
	string res;
	for (int i=0; i<str.length(); i +=4){
		int digit = stoi(str.substr(i, 4));
		switch(digit){
			case 0:
				res.append("0");
				break;
			case 1:
				res.append("1");
				break;
			case 10:
				res.append("2");
				break;
			case 11:
				res.append("3");
				break;
			case 100:
				res.append("4");
				break;
			case 101:
				res.append("5");
				break;
			case 110:
				res.append("6");
				break;
			case 111:
				res.append("7");
				break;
			case 1000:
				res.append("8");
				break;
			case 1001:
				res.append("9");
				break;
			case 1010:
				res.append("a");
				break;
			case 1011:
				res.append("b");
				break;
			case 1100:
				res.append("c");
				break;
			case 1101:
				res.append("d");
				break;
			case 1110:
				res.append("e");
				break;
			case 1111:
				res.append("f");
				break;
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