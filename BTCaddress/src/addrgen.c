#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <gmp.h>
#include "encoding.h"
#include "crypto.h"

/*  make sure to hash byte strings, not hex strings!
    0 - private ecdsa key
    1 - public ecdsa key
    2 - sha256((1))
    3 - ripemd160((2))
    4 - add version byte (0x00) infront of 3
    5 - sha256((4))
    6 - sha256((5))
    7 - checksum: first 4 bytes of (6)
    8 - add (7) to end of (4)
    9 - base58encode((8))
*/

int main(){

    int i;
    unsigned char *brain_pass, *ec_pub;
    unsigned char hash256[SHA256_DIGEST_LENGTH]; // 32 bytes
    unsigned char hash160[RIPEMD160_DIGEST_LENGTH]; // 20 bytes
    unsigned char ec_priv[SHA256_DIGEST_LENGTH];

    unsigned char addr25[51], addr[34];
    unsigned char buff[100], buff2[100];
    unsigned char checksum[9];

    size_t EC_PRIV_KEY_LENGTH = SHA256_DIGEST_LENGTH;
    size_t EC_PUB_KEY_LENGTH = EC_PRIV_KEY_LENGTH*2+1;


    brain_pass = "abcdefghijklmnopqrstuvwxyz";
    sha256(brain_pass, ec_priv, strlen(brain_pass));
    byte2hex(ec_priv, buff, EC_PRIV_KEY_LENGTH);
    printf("ecdsa private key: %s\n", buff);
    //private key, public key.  convert public key to bytes
    strcpy(buff, "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725");
    ec_pub = ec_genPubFromPriv(buff);
    printf("ecdsa public key: %s\n", ec_pub);
    hex2byte(ec_pub, buff, EC_PUB_KEY_LENGTH);
    free(ec_pub);

    // compute 160 hash
    sha256(buff, hash256, EC_PUB_KEY_LENGTH);
    ripemd160(hash256, hash160, SHA256_DIGEST_LENGTH);

    // convert to hex, add version number (network byte), convert back
    byte2hex(hash160, buff, RIPEMD160_DIGEST_LENGTH);
    strcpy(buff2, "00"); 
    strcat(buff2, buff);
    hex2byte(buff2, addr25, RIPEMD160_DIGEST_LENGTH+1);

    // double sha256 to get the checksum
    sha256(addr25, hash256, RIPEMD160_DIGEST_LENGTH+1);
    sha256(hash256, hash256, SHA256_DIGEST_LENGTH);
    byte2hex(hash256, buff, SHA256_DIGEST_LENGTH);
    for (i=0; i < 8; i++)
        checksum[i] = buff[i];
    checksum[8] = '\0';
    // add checksum to end of hex encoded ripemd hash with version 
    byte2hex(addr25, buff, RIPEMD160_DIGEST_LENGTH+1);
    strcpy(addr25, buff);
    strcat(addr25, checksum);
    hex2byte(addr25, buff, 25);

    // big nums
    mpz_t n;
    mpz_init(n);
    mpz_set_ui(n, 0);

    // base58 encode
    convert_bytes_to_big_int(n, buff, 25);    
    base58encode(n, addr);

    flip_str(addr, buff, strlen(addr));
    strcpy(buff2, "1");
    strcat(buff2, buff);

    printf("bitcoin address:\t%s\n", buff2);

    mpz_clear(n);

    return 0;
}

