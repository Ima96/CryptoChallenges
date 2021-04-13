#include <iostream>
#include <string.h>
#include <RandomLib/Random.hpp>

using namespace std;
using namespace RandomLib;


int main(){

	Random r;

	for(int i=0; i<40; i++){
		cout << r.Integer() << endl;
	}

	return 0;
}