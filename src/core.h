#ifndef sodium_core_H
#define sodium_core_H

#include "sr25519-randombytes-default.h"

#ifdef __cplusplus
extern "C" {
#endif

SODIUM_EXPORT
void sodium_misuse(void)
            __attribute__ ((noreturn));

#ifdef __cplusplus
}
#endif

#endif
