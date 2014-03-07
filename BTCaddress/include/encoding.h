#include <gmp.h>

#ifndef ENCODINGS_INCLUDED
#define ENCODINGS_INCLUDED

void byte2hex(unsigned char *in, char *out, int N);
void hex2byte(char *in, unsigned char *out, int N);
void convert_bytes_to_big_int2(mpz_t u, unsigned char *bytes, int N);
void convert_bytes_to_big_int(mpz_t u, unsigned char *bytes, int N);
void base58encode(mpz_t U, char *addr);
void flip_str(char *str, char *str2, int N);

#endif
