#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <gmp.h>
#include <assert.h>



char * sha256(char *string, size_t N){
    unsigned char *hash = malloc(sizeof(unsigned char)*SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init (&sha256);
    SHA256_Update(&sha256, string, N);
    SHA256_Final(hash, &sha256);
    return hash;
}

char * ripemd160(char *string, size_t N){
    unsigned char *hash = malloc(sizeof(unsigned char)*RIPEMD160_DIGEST_LENGTH);   
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, string, N);
    RIPEMD160_Final(hash, &ripemd160);    
    return hash;
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

// where N is the length of the input
int byte2hex(unsigned char *in, char *out, int N){
    int i;
    for(i=0; i < N; i++){
        sprintf(out + (i*2), "%02x", in[i]);
    }
    out[N*2] = '\0';
    return 0;
}

// where N is the length of the output
int hex2byte(char *in, unsigned char *out, int N){
    int i;
    unsigned const char *pos = in;
    char  *endptr;
    pos = in;
    for(i=0; i<N; i++){
       char buf[5] = {'0', 'x', pos[0], pos[1], 0};
       out[i] = strtol(buf, &endptr, 0);
       pos += 2*sizeof(char);
    }
    return 0;
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
}
void convert_bytes_to_big_int(mpz_t u, unsigned char *bytes, int N){
    int i, flag;
    
    for (i=0;i<N;i++){
        mpz_mul_ui(u, u, 256);
        //printf("%d ", bytes[i]);
        mpz_add_ui(u, u, (int) bytes[i]);
    }
    printf("\n");
}

void base58encode(mpz_t U, char *addr){ 
    char base58[58] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";    
    int i;
    mpz_t r;
    mpz_init(r);
    int rem;

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

int main(){

    char *pass;
    char * priv; // 65
    char *pubkey; // 130
    int i;
    char withVersion[25];
    char addr25[51], addr[34];
    char *buf1, *buf2;
    unsigned const char buff[100], buff2[100];
    unsigned const char *pubkeyBYTE=malloc(sizeof(unsigned char)*65);
    unsigned const char *privHEX = malloc(sizeof(unsigned char)*33);
    char checksum[9];

    pass = "fucker yeh";
    priv = sha256(pass,strlen(pass));
    byte2hex(priv, privHEX, 32);
    printf("ecdsa private key: %s\n", privHEX);
    //private key, public key.  convert public key to bytes
    //priv = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    pubkey = ec_genPubFromPriv(privHEX);
    printf("ecdsa public key: %s\n", pubkey);
    hex2byte(pubkey, pubkeyBYTE, 65);

    // compute 160 hash
    buf1 = sha256(pubkeyBYTE, 65);
    buf2 = ripemd160(buf1, 32);

    // convert to hex, add version number, convert back
    byte2hex(buf2, buff, 20);
    strcpy(buff2, "00"); 
    strcat(buff2, buff);
    hex2byte(buff2, withVersion, 22);

    // double sha256 to get the checksum
    buf1 = sha256(withVersion, 21);
    buf1 = sha256(buf1, 32);
    byte2hex(buf1, buff, 32);
    for (i=0; i < 8; i++)
        checksum[i] = buff[i];
    checksum[8] = '\0';
  
    // add checksum to end of hex encoded ripemd hash with version 
    byte2hex(withVersion, buff, 21);
    strcpy(addr25, buff);
    strcat(addr25, checksum);
    
    hex2byte(addr25, buff, 50);

    mpz_t n;
    mpz_init(n);
    mpz_set_ui(n, 0);

    // base58 encode
    convert_bytes_to_big_int(&n, buff, 25);    
    base58encode(n, addr);

    char addr_right[strlen(addr)];
    flip_str(addr, addr_right, strlen(addr));

    printf("bitcoin address:\t%s\n", addr_right);

    mpz_clear(n);
    free(pubkeyBYTE);
    free(privHEX);
    free(priv);
    free(buf1);
    free(buf2);

    return 0;
}

