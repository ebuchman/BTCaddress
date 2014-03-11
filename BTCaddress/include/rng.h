#ifndef RNG_INCLUDED
#define RNG_INCLUDED

void rng_seed(long seed);
void rng_free();
float rng_ran1();

void rng_dev(unsigned char *seed, int byte_length);

#endif
