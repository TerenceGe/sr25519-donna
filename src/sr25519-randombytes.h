#ifndef __SR25519_RANDOM_H__
#define __SR25519_RANDOM_H__

#if defined(SR25519_CUSTOMRANDOM)

#include "sr25519-randombytes-custom.h"

#else

#include "randombytes/randombytes.h"

static void sr25519_randombytes(void *p, size_t len) {
  randombytes_buf(p, len);
}

#endif

#endif
