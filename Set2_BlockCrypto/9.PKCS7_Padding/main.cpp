#include <iostream>
#include <fstream>
#include <string.h>
#include <math.h>

using namespace std;

string add_pad(string msg_to_pad, int block_size);

int main(){

	int block_size;
	string message;

	// Ask for message to be padded
	cout << "Insert message to be padded: ";
	getline(cin, message);
	int msg_len = message.length();
	cout << message << endl;

	// Ask for block_size
	cout << "Insert the block size to be padded: ";
	cin >> block_size;

	string padded_msg;
	padded_msg = add_pad(message, block_size);

	ofstream padded;
	padded.open("padded.txt");
	padded << padded_msg;
	padded.close();

	return 0;
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
			cout << group_num << endl;
			int last_byte_len = (msg_to_pad.substr((group_num-1)*block_size)).length();
			cout << last_byte_len << endl;
			int pad_val = block_size - last_byte_len;
			ret_padded = msg_to_pad;
			for(int i=0; i<pad_val; i++) ret_padded += pad_val;	

		}
	}

	return ret_padded;
}