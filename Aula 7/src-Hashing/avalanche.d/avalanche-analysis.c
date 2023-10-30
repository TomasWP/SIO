#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>

// gcc -O2 -Wall sha256.c md5.c avalanche-analysis.c -o avalanche-analysis


// if you want the best (fast!) implementations of cryptographic hash functions,
// check for openssl! For our propose let's continue with:
#include "sha256.h"
#include "md5.h"


// this is big enough for all our targets: sha256 and md5
#define HASH_OUTPUT_MAX_BITS   256
#define HASH_OUTPUT_BLOCK_SIZE (HASH_OUTPUT_MAX_BITS/8)

// basic definitions for sha256 and md5
#define BYTES_NEED_FOR_SHA256 SHA256_BLOCK_SIZE
#define BYTES_NEED_FOR_MD5    MD5_BLOCK_SIZE


int badUsage(const char *p) {
/*
 * TODO
 * you may want to give more options and details here!
 */
    fprintf(stderr, "Usage:\n\t%s  M  N\n\n"
                    "\tM: the size in bytes of the initial source message\n"
                    "\tN: the number of one-bit altered messages\n"
                    "\n",p);
    return -2;
}

int iWouldPreferNotToContinue(const int l) {
    fprintf(stderr, "This was not suppose to happen at line %d of %s!\n", l, __FILE__);
    exit(-1);
}

int count1s(uint8_t c) {
// couts 1's in a byte
    return __builtin_popcount(c);
    int n=0;
    while(c) {
        n+=(c&1);
        c>>=1;
    }
    return n;
}

int countDiffBits(const uint8_t *h1, const uint8_t *h2, const uint32_t size) {
// returns the number of bits at 1 within the first `size` bytes

    int n = 0;
    for(int i=0;i<size;i++) {
        n+=count1s(h1[i] ^ h2[i]);
    }

    if(n>8*size) iWouldPreferNotToContinue(__LINE__);
    return n;
}

void changeMeAByte(const uint8_t *source, const uint32_t source_size, uint8_t *track_mods, uint8_t *working_buf) {
/*
 * TODO similar to changeMeABit but a byte!
 */
    iWouldPreferNotToContinue(__LINE__);
}

void changeMeABit(const uint8_t *source, const uint32_t source_size, uint8_t *track_mods, uint8_t *working_buf) {
// copies `source` to `working_buf` and changes a bit on `working_buf`
// also writes the index of the bit changed to `track_mods`

    memcpy(working_buf, source, source_size);

    uint32_t idx = rand()%source_size; // the byte index
    uint8_t bmask= 1<<(rand()%8); // a mask with 1 bit set

    uint32_t try=0;
    while(track_mods[idx]&bmask) { // while we hit in a bit that was already changed
        bmask=(uint8_t)(bmask<<1);
        if(!bmask) {
            bmask=1;
            idx=(idx+1)%source_size;
        }
        if(try++==source_size*8) { // if all bits were already modified
            // this is not suppose to happen due to a validation in main(...) args
            iWouldPreferNotToContinue(__LINE__);
        }
    }

    working_buf[idx]^=(bmask); // change the bit
    track_mods[idx]|=(bmask); // stores the action

    if(1!=countDiffBits(source,working_buf,source_size)) {
        iWouldPreferNotToContinue(__LINE__);
    }
}

void sha256(const uint8_t *data, const uint32_t data_size, uint8_t *output_hash) {
// produces sha256 from `data` with `data_size` bytes and writes the output to `output_hash`
// see "sha256.h" for detauls

    SHA256_CTX ctx;
    sha256_init(&ctx);
	sha256_update(&ctx, data, data_size);
	sha256_final(&ctx, output_hash);
}

void md5(const uint8_t *data, const uint32_t data_size, uint8_t *output_hash) {
// produces md5 from `data` with `data_size` bytes and writes the output to `output_hash`
// see "md5.h"

/**
 * TODO 
 */
    iWouldPreferNotToContinue(__LINE__);
}


int main(int argc, char *argv[]) {

    if(argc==2) {
        // this is an undocumented feature!
        // with a single argument, this will print out the sha256 and md5 of the argument
        // try:
        //     ./avalanche-analysis "You should ONLY use this if you’re 100% absolutely sure that you know what you’re doing"
        uint8_t source_hash[HASH_OUTPUT_BLOCK_SIZE];
        sha256((uint8_t *)argv[1], strlen(argv[1]), source_hash);
        printf("SHA256 (-) = ");
        for(int i=0;i<SHA256_BLOCK_SIZE;i++) {
            printf("%02X", source_hash[i]);
        }
        printf("\n");

        /*
         * TODO md5 needs to be implemented
         */
        //md5((uint8_t *)argv[1], strlen(argv[1]), source_hash);
        //printf("MD5 (-)    = ");
        //for(int i=0;i<MD5_BLOCK_SIZE;i++) {
        //    printf("%02X", source_hash[i]);
        //}
        //printf("\n");
    }

    if(argc!=3) {
        // we want 2 arguments
        return badUsage(argv[0]);
    }

    // get the numbers
    const uint32_t source_size  = atoi(argv[1]);
    const uint32_t n_variations = atoi(argv[2]);

    fprintf(stderr,"Working with M=%d and N=%d...\n",source_size,n_variations);

    // check the numbers
    if(!source_size || !n_variations || n_variations>source_size<<3) {
        return badUsage(argv[0]);
    }

    // get some space for histogram
    uint32_t histogram[HASH_OUTPUT_MAX_BITS];
    memset(histogram,0,HASH_OUTPUT_MAX_BITS*sizeof(histogram[0]));

    // space for source
    uint8_t *source = malloc(source_size);
    if (!source) iWouldPreferNotToContinue(__LINE__);

    // space for 1bit variation
    uint8_t *bit_mod = malloc(source_size);
    if (!bit_mod) iWouldPreferNotToContinue(__LINE__);

    // used to avoid repetition on the 1bit modification...
    uint8_t *track_mods = malloc(source_size);
    if(!track_mods) iWouldPreferNotToContinue(__LINE__);

    srand(getpid()+time(NULL)); // initialize pseudo-random gen with a different seed each time
    for(int i=0;i<source_size;i++) {
        source[i]=(uint8_t)rand();
        bit_mod[i]=0;
        track_mods[i]=0;
    }

    uint8_t source_hash[HASH_OUTPUT_BLOCK_SIZE];
    uint8_t bit_mod_hash[HASH_OUTPUT_BLOCK_SIZE];

    memset(source_hash,0,HASH_OUTPUT_BLOCK_SIZE);
    memset(bit_mod_hash,0,HASH_OUTPUT_BLOCK_SIZE);


/**
 *  TODO
 *      probably you will start from here...
 *      without any modification it will just work for N = 1
 */

    const int size_of_hash = BYTES_NEED_FOR_SHA256;
    sha256(source, source_size, source_hash);

    changeMeABit(source, source_size, track_mods, bit_mod);

    sha256(bit_mod, source_size, bit_mod_hash);

    const int n = countDiffBits(source_hash, bit_mod_hash, size_of_hash);

    histogram[n]++;


    { // make sure we have used N different 1bit mods
        int changed = 0;
        for(int i=0;i<source_size;i++) {
            changed += count1s(track_mods[i]);
        }
        if(changed!=n_variations) {
            iWouldPreferNotToContinue(__LINE__);
        }
    }

    printf("The results are...\n");
    // you may want to sort values...
    // try:
    //      ./avalanche-analysis 1024 1 | grep '\[' | sort -nk3

    for(int i=0;i<size_of_hash*8;i++) {
        printf("[%3d] = %d\n", i, histogram[i]);
    }


/**
 *
 *  probably there is nothing to do bellow...
 *
 */
    free(source);
    free(bit_mod);
    free(track_mods);

}
