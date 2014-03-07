
#ifndef CRYPTO_INCLUDED
#define CRYPTO_INCLUDED

void sha256(char *string, unsigned char *hash, size_t N);
void ripemd160(char *string, unsigned char *hash, size_t N);
char *ec_genPubFromPriv(char *priv);

#endif
