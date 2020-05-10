#ifndef __SHA3_H__
#define __SHA3_H__

#include <stdint.h>
#include "options.h"

#ifdef __cplusplus
extern "C" {
#endif

#define sha3_224_hash_size 28
#define sha3_256_hash_size 32
#define sha3_384_hash_size 48
#define sha3_512_hash_size 64
#define sha3_max_permutation_size 25
#define sha3_max_rate_in_qwords 24

#define SHA3_224_BLOCK_LENGTH 144
#define SHA3_256_BLOCK_LENGTH 136
#define SHA3_384_BLOCK_LENGTH 104
#define SHA3_512_BLOCK_LENGTH 72

#define SHA3_224_DIGEST_LENGTH sha3_224_hash_size
#define SHA3_256_DIGEST_LENGTH sha3_256_hash_size
#define SHA3_384_DIGEST_LENGTH sha3_384_hash_size
#define SHA3_512_DIGEST_LENGTH sha3_512_hash_size

/**
 * SHA3 Algorithm context.
 */
typedef struct SHA3_CTX
{
    /* 1600 bits algorithm hashing state */
    uint64_t hash[sha3_max_permutation_size];
    /* 1536-bit buffer for leftovers */
    uint64_t message[sha3_max_rate_in_qwords];
    /* count of bytes in the message[] buffer */
    unsigned rest;
    /* size of a message block processed at once */
    unsigned block_size;
} SHA3_CTX;

/* methods for calculating the hash function */

void sha3_224_Init(SHA3_CTX *ctx);
void sha3_256_Init(SHA3_CTX *ctx);
void sha3_384_Init(SHA3_CTX *ctx);
void sha3_512_Init(SHA3_CTX *ctx);
void sha3_Update(SHA3_CTX *ctx, const unsigned char* msg, size_t size);
void sha3_Final(SHA3_CTX *ctx, unsigned char* result);

#if USE_KECCAK
#define keccak_224_Init sha3_224_Init
#define keccak_256_Init sha3_256_Init
#define keccak_384_Init sha3_384_Init
#define keccak_512_Init sha3_512_Init
#define keccak_Update sha3_Update
void keccak_Final(SHA3_CTX *ctx, unsigned char* result);
void keccak_256(const unsigned char* data, size_t len, unsigned char* digest);
void keccak_512(const unsigned char* data, size_t len, unsigned char* digest);
#endif

void sha3_256(const unsigned char* data, size_t len, unsigned char* digest);
void sha3_512(const unsigned char* data, size_t len, unsigned char* digest);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* __SHA3_H__ */
