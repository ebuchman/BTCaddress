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

void seed_rng(long seed){
    idum = (long *)malloc(sizeof(long));
    *idum = seed;
}

void free_rng(){
    free(idum);
}

/* Random number generator from Numerical Recipes*/

float ran1(){
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
   

