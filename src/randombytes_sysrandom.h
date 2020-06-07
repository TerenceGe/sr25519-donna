#ifndef randombytes_sysrandom_H
#define randombytes_sysrandom_H

#include "sr25519-randombytes-default.h"

#ifdef __cplusplus
extern "C" {
#endif

SODIUM_EXPORT
extern struct randombytes_implementation randombytes_sysrandom_implementation;

#ifdef __cplusplus
}
#endif

#endif
