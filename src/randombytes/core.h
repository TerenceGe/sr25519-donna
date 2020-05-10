#ifndef sodium_core_H
#define sodium_core_H

#include "randombytes/randombytes.h"

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
