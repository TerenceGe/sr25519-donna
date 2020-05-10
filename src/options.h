#ifndef __OPTIONS_H__
#define __OPTIONS_H__

// use precomputed Curve Points (some scalar multiples of curve base point G)
#ifndef USE_PRECOMPUTED_CP
#define USE_PRECOMPUTED_CP 1
#endif

// use fast inverse method
#ifndef USE_INVERSE_FAST
#define USE_INVERSE_FAST 1
#endif

// support for printing bignum256 structures via printf
#ifndef USE_BN_PRINT
#define USE_BN_PRINT 0
#endif

// use deterministic signatures
#ifndef USE_RFC6979
#define USE_RFC6979 1
#endif

// implement BIP32 caching
#ifndef USE_BIP32_CACHE
#define USE_BIP32_CACHE 1
#define BIP32_CACHE_SIZE 10
#define BIP32_CACHE_MAXDEPTH 8
#endif

// support constructing BIP32 nodes from ed25519 and curve25519 curves.
#ifndef USE_BIP32_25519_CURVES
#define USE_BIP32_25519_CURVES 1
#endif

// implement BIP39 caching
#ifndef USE_BIP39_CACHE
#define USE_BIP39_CACHE 1
#define BIP39_CACHE_SIZE 4
#endif

// support Ethereum operations
#ifndef USE_ETHEREUM
#define USE_ETHEREUM 0
#endif

// support Graphene operations (STEEM, BitShares)
#ifndef USE_GRAPHENE
#define USE_GRAPHENE 0
#endif

// support NEM operations
#ifndef USE_NEM
#define USE_NEM 0
#endif

// support MONERO operations
#ifndef USE_MONERO
#define USE_MONERO 0
#endif

// support CARDANO operations
#ifndef USE_CARDANO
#define USE_CARDANO 0
#endif

// support Keccak hashing
#ifndef USE_KECCAK
#define USE_KECCAK 1
#endif

// add way how to mark confidential data
#ifndef CONFIDENTIAL
#define CONFIDENTIAL
#endif

#endif
