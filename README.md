# CryptoChallenges
## General Information
- *Author*	: Imanol Etxezarreta
- *Purpose*	: Learn about cryptographics trying to solve different problems derived from weaknesses in real world and modern cryptographic constructions. Trying to do it implementing it in C.
- [State of completion](#the-cryptopals-crypto-challenges)
- [Usage instructions](#usage-instructions)

## [The CryptoPals Crypto Challenges](https://www.cryptopals.com/)
### Set 1: Basics
- [x] Challenge 1: Convert hex to base64
- [x] Challenge 2: Fixed XOR
- [x] Challenge 3: Single-byte XOR cipher
- [x] Challenge 4: Detect single-character XOR
- [x] Challenge 5: Implement repeating-key XOR
- [x] Challenge 6: Break repeating-key XOR
- [x] Challenge 7: AES in ECB mode
- [x] Challenge 8: Detect AES in ECB mode

### Set 2: Block crypto
- [x] Challenge 9: Implement PKCS#7 padding
- [x] Challenge 10: Implement CBC mode
- [x] Challenge 11: An ECB/CBC detection oracle
- [x] Challenge 12: Byte-at-a-time ECB decryption (Simple)
- [x] Challenge 13: ECB cut-and-paste
- [x] Challenge 14: Byte-at-a-time ECB decryption (Harder)
- [x] Challenge 15: PKCS#7 padding validation
- [x] Challenge 16: CBC bitflipping attacks

### Set 3: Block & stream crypto
- [x] Challenge 17: The CBC padding oracle
- [ ] Challenge 18: Implement CTR, the stream cipher mode
- [ ] Challenge 19: Break fixed-nonce CTR mode using substitutions
- [ ] Challenge 20: Break fixed-nonce CTR statistically
- [ ] Challenge 21: Implement the MT19937 Mersenne Twister RNG
- [ ] Challenge 22: Crack an MT19937 seed
- [ ] Challenge 23: Clone an MT19937 RNG from its outputs
- [ ] Challenge 24: Create the MT 19937 stream cipher and break it

## Make instructions
*Currently only for linux systems*
### Dependencies
- cmake (>= 3.8)
- openssl1.1.1
- make

### Usage instructions
With the following commands, a new folder will be generated inside `build/` folder named `bin/` with all the challenge binaries. Every challenge has a prefix with the form "ch##" where ## is the challenge number. Adittionally, some challenges use some files that are in their respective developing folders, and post-build commands copy those files to `build/bin/resources/` folder.
```bash
git clone https://github.com/Ima96/CryptoChallenges.git
cd CryptoChallenges
mkdir build && cd build
cmake ..
make
```

