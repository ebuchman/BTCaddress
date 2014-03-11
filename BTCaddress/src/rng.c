#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "rng.h"


#define IA 16807
#define IM 2147483647
#define AM (1.0/IM)
#define IQ 127773
#define IR 2836
#define NTAB 32
#define NDIV (1 + (IM-1)/NTAB)
#define EPS 1.2E-7
#define RNMX (1.0 - EPS)

long *idum;

void rng_seed(long seed){
    idum = (long *)malloc(sizeof(long));
    *idum = seed;
}

void rng_free(){
    free(idum);
}

/* Random number generator from Numerical Recipes*/

float rng_ran1(){
  int j;
  long k;
  static long iy = 0;
  static long iv[NTAB];
  float temp;

  if (*idum <= 0 || !iy) 
    {
      if (-(*idum) < 1) *idum = 1;
      else *idum = -(*idum);

      for (j = NTAB+7; j>=0; j--)
	{
	  k = (*idum)/IQ;
	  *idum = IA*(*idum - k*IQ) - IR*k;

	  if (*idum < 0) *idum += IM;
	  if (j < NTAB) iv[j] = *idum;
	}
      iy = iv[0];
    }

  k = (*idum)/IQ;
  *idum = IA*(*idum - k*IQ) - IR*k;

  if ( *idum < 0) *idum += IM;
  
  j = iy/NDIV;
  iy = iv[j];
  iv[j] = *idum;
   
  if ( (temp = AM*iy) > RNMX) return RNMX;
  else return temp;
}
   

void rng_dev(unsigned char *seed, int byte_length){
    FILE * fp;
    int n, i;
    unsigned char *byte_seed = malloc(sizeof(unsigned char)*byte_length);
    //    printf("generating random numbers ...\n");
    if((fp = fopen("/dev/urandom", "r")) == NULL){
        printf("failed to open /dev/urandom\n");
        exit(-1);
    }

    n = fread(byte_seed, 1, byte_length, fp);

    if (n < 1){
        printf("failed to read from /dev/urandom\n");
        exit(-1);
    }
    else
        printf("read %d bytes from /dev/urandom\n", n);

    byte2hex(byte_seed, seed, byte_length);
    fclose(fp);
    free(byte_seed);
}
