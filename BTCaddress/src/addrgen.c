#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <gmp.h>
#include <time.h>
#include <python2.7/Python.h>
#include "encoding.h"
#include "crypto.h"
#include "rng.h"

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
typedef unsigned char uchar;

int genAddr(uchar privBuff[64], uchar pubBuff[36], uchar pass[128]){

    int i;
    uchar *ec_pub;
    uchar hash256[SHA256_DIGEST_LENGTH]; // 32 bytes
    uchar hash160[RIPEMD160_DIGEST_LENGTH]; // 20 bytes
    uchar ec_priv[SHA256_DIGEST_LENGTH];

    uchar addr25[51], addr[34];
    uchar buff[100], buff2[100];
    uchar checksum[9];

    size_t EC_PRIV_KEY_LENGTH = SHA256_DIGEST_LENGTH;
    size_t EC_PUB_KEY_LENGTH = EC_PRIV_KEY_LENGTH*2+1;
    
    double r;

    // if there is a passphrase, generate a private key from it.  else, assume private key is provided
    if (pass != NULL)
        sha256(pass, ec_priv, strlen(pass));
        byte2hex(ec_priv, buff, EC_PRIV_KEY_LENGTH);

        strcpy(privBuff, buff);

   // printf("ecdsa private key: %s\n", privBuff);

    //private key, public key.  convert public key to bytes
    ec_pub = ec_genPubFromPriv(privBuff);
    //printf("ecdsa public key: %s\n", ec_pub);
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

    strcpy(pubBuff, buff2);
    strcat(pubBuff, "\0");
    //printf("bitcoin address:\t%s\n", buff2);

    mpz_clear(n);

    return 0;
}

void dev_random(uchar *seed, int byte_length){
    FILE * fp;
    int n, i;
    uchar *byte_seed = malloc(sizeof(uchar)*byte_length);
    //    printf("generating random numbers ...\n");
    if((fp = fopen("/dev/urandom", "r")) == NULL){
        printf("failed to open /dev/urandom\n");
        exit(-1);
    };

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

void print_bytes(uchar *bytes, int byte_length){
    int i;
    for(i=0;i<byte_length;i++)
        printf("%d ", bytes[i]);
    printf("\n");

}

int main(int argc, char *argv[]){
    char target[8];
    if (argc == 2){
        if (strlen(argv[1]) > 8){
            printf("target too long (max 8) \n");
            exit(0);
        }
        strcpy(target, argv[1]);
    }
    else{
        printf("usage: ./crypt me\n");
        exit(0);
    }
        
    int N;
    int i;
    FILE *fp;
    int byte_length = 64;
    //uchar *seed = malloc(sizeof(uchar)*byte_length);;
    uchar seed[byte_length*2];
    uchar pubBuff[36], privBuff[65], passBuff[128];
    PyObject *main_module, *global_dict, *function;
    PyObject *success;
    long successes = 0;

    printf("searching for vanity address beginning with: %s ...\n", target);

    // entropy...
    Py_Initialize();
    fp = fopen("src/check.py", "r");
    PyRun_SimpleFile(fp, "src/check.py");

    main_module = PyImport_AddModule("__main__");
    global_dict = PyModule_GetDict(main_module);

    function = PyDict_GetItemString(global_dict, "check_vanity");

    int r;
    seed_rng(271828);
    //for(i=0;i<10000;i++){
    for(i=0; successes < 1; i++){
        if (i % 10000 == 0){
            printf("iteration: %d\tsuccesses: %ld\n", i, successes);
            dev_random(seed, byte_length);
        }
        r = (int) byte_length*ran1();
        
        seed[r] = (seed[r] + 1)%256;
//        print_bytes(seed, 64);
        genAddr(privBuff, pubBuff, seed);
//        printf("%s\n%s\n%s\n%s\n\n", privBuff,pubBuff,passBuff, target);
        //printf("%ld, %ld, %ld, %ld\n", strlen(privBuff), strlen(pubBuff), strlen(passBuff), strlen(target));
        success=PyObject_CallFunction(function, "sss", pubBuff, privBuff, target);
        PyErr_Print();
        successes += PyInt_AsLong(success);

    }

    Py_Finalize();

    return 0;
}





