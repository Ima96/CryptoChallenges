#include <iostream>
#include <fstream>
#include <string>
using namespace std;

// Declare function names
string hexToBin(string);
string stringXOR(string a, string b);
string binToHex(string str);

// Main function
int main(void) {

	string buffer1_in = "1c0111001f010100061a024b53535009181c";
	string buffer2_in = "686974207468652062756c6c277320657965";

	string buff1_bin = hexToBin(buffer1_in);
	string buff2_bin = hexToBin(buffer2_in);

	string res = stringXOR(buff1_bin, buff2_bin);
	string res_hex = binToHex(res);
	
	cout << "Buffer in 1: " << buffer1_in << endl;
	cout << "Buffer in 2: " << buffer2_in << endl;
	cout << "Result in Hex is: " << res_hex << endl;

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

string stringXOR(string a, string b){

	string res;

	for (int i=0; i<a.length(); i++){
		if (a[i] == b[i]) res.append("0");
		else res.append("1");
	}

	return res;
}

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
