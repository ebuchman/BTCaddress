#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <assert.h>
#include "crypto.h"

void sha256(char *string, unsigned char *hash, size_t N){
    SHA256_CTX sha256;
    SHA256_Init (&sha256);
    SHA256_Update(&sha256, string, N);
    SHA256_Final(hash, &sha256);
}

void ripemd160(char *string, unsigned char *hash, size_t N){
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, string, N);
    RIPEMD160_Final(hash, &ripemd160);    
}


char *ec_genPubFromPriv(char *priv){
    EC_KEY *eckey = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = NULL;
    BIGNUM start;
    BIGNUM *res;
    BN_CTX *ctx;
    char * pub;

    BN_init(&start);
    ctx = BN_CTX_new();

    res = &start;
    BN_hex2bn(&res, priv); 
    eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    group = EC_KEY_get0_group(eckey);
    pub_key = EC_POINT_new(group);

    EC_KEY_set_private_key(eckey, res);

    if (1 != EC_POINT_mul(group, pub_key, res, NULL, NULL, ctx))
        printf("Error at EC_POINT_mul\n");

   //assert(EC_POINT_bn2point(group, &res, pub_key, ctx));

    EC_KEY_set_public_key(eckey, pub_key);

    pub = EC_POINT_point2hex(group, pub_key, 4, ctx);

    BN_CTX_free(ctx);
    return pub;
}
