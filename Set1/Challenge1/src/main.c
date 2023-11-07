/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Author: 		Imanol Etxezarreta									 *
 * Description: Challenge 1 of CryptoPals crypto challenges			 *
 * 				which consist on performing a conversion from		 *
 * 				hex encoding to base64 enconding.					 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <stdlib.h>
#include "encodings.h"

int main(void)
{
	FILE *fin = NULL;
	int hex_str_size = 0, ascii_str_size = 0;
	uint8_t *hex_string = NULL, *ascii_string = NULL;
	uint8_t *base64_string = NULL;

	fin = fopen("./resources/The_String.txt", "r");

	if (fin == NULL)
	{
		printf("Error openning the file! Please execute from the folder ${PROJECT_ROOT_DIR}/build/bin...\n");
		exit(EXIT_FAILURE);
	}

	fseek(fin, 0L, SEEK_END);
	ascii_str_size = ftell(fin);
	rewind(fin);

	hex_str_size = ascii_str_size;

	ascii_string = malloc(ascii_str_size+1);

	while(fscanf(fin, "%s", ascii_string) != EOF);
   fclose(fin);

	printf("The hex(ascii) string: %s\n", ascii_string);

	hex_string = AsciiHex2Bin(ascii_string, ascii_str_size);

	base64_string = Hex2Base64(hex_string, hex_str_size);

	printf("The converted base64 string: %s\n", base64_string);

   free(ascii_string);
   ascii_string = NULL;
   free(hex_string);
   hex_string = NULL;
   free(base64_string);
   base64_string = NULL;

	return 0;
}

