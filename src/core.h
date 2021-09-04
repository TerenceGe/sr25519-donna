#ifndef sr25519_donna_core_H
#define sr25519_donna_core_H

#include "sr25519-randombytes-default.h"

#ifdef __cplusplus
extern "C" {
#endif

SR25519_DONNA_EXPORT
void sr25519_donna_misuse(void)
            __attribute__ ((noreturn));

#ifdef __cplusplus
}
#endif

#endif
