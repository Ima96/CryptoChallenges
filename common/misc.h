
#include <stdio.h>
#include <stdint.h>

uint16_t readFile(FILE *fip, uint8_t **outbuf, uint8_t const filter);

uint8_t **readFileLines(FILE *fip, uint16_t *line_count);