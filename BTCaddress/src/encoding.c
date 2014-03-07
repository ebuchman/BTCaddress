#include <stdio.h>
#include "encoding.h"


// where N is the length of the input
void byte2hex(unsigned char *in, char *out, int N){
    int i;
    for(i=0; i < N; i++){
        sprintf(out + (i*2), "%02x", in[i]);
    }
    out[N*2] = '\0';
}

// where N is the length of the output
void hex2byte(char *in, unsigned char *out, int N){
    int i;
    unsigned const char *pos = in;
    char  *endptr;
    pos = in;
    for(i=0; i<N; i++){
       char buf[5] = {'0', 'x', pos[0], pos[1], 0};
       out[i] = strtol(buf, &endptr, 0);
       pos += 2*sizeof(char);
    }
}

void convert_bytes_to_big_int2(mpz_t u, unsigned char *bytes, int N){
    int i,j, flag;
    mpz_t p;
    
    for (i=0;i<N;i++){
        mpz_init_set_ui(p, 1);
        for(j=0;j<i;j++)
            mpz_mul_ui(p, p, 256);
        mpz_mul_ui(p, p, bytes[N-1-i]);
        mpz_add(u, u, p);
    }
    mpz_clear(p);
}

void convert_bytes_to_big_int(mpz_t u, unsigned char *bytes, int N){
    int i;
    
    for (i=0;i<N;i++){
        mpz_mul_ui(u, u, 256);
        mpz_add_ui(u, u, (int) bytes[i]);
    }
}

void base58encode(mpz_t U, char *addr){ 
    char base58[58] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";    
    int i, rem;

    for(i=0; mpz_sgn(U); i++){
        rem = mpz_fdiv_q_ui(U, U, 58);
        addr[i] = base58[rem];
    }
    addr[i]='\0';
}

void flip_str(char *str, char *str2, int N){
    int i;
    for (i=0;i<N;i++)
       str2[i] = str[N-1-i];
    str2[N] = '\0';
}

