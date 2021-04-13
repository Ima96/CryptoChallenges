#include <iostream>
#include <unistd.h>
#include <chrono>
#include <RandomLib/Random.hpp>
#include <RandomLib/RandomAlgorithm.hpp>

using namespace std;
using namespace RandomLib;

int generateRandInt();

const auto p1 = chrono::system_clock::now();

int main(){

	int rnd_num = generateRandInt();

	cout << rnd_num << endl;

	return 0;
}

int generateRandInt(){

	typedef RandomEngine<MT19937  <Random_u32>, MixerSFMT> MRandomGenerator32;
	typedef RandomCanonical<MRandomGenerator32> MRandom32;
	MRandom32 r;

	time_t timer;

	sleep(r.IntegerC(40,1000));
	cout << "Debug 1" << endl;

	r.Reseed((long int)&timer);

	sleep(r.IntegerC(40,1000));
	cout << "Debug 2" << endl;

	return r.Integer();
}