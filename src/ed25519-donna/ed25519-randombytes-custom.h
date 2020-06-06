/*
	a custom randombytes must implement:

	void ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len);

	ed25519_randombytes_unsafe is used by the batch verification function
	to create random scalars
*/
#include "sr25519-randombytes.h"

void ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len) {
    sr25519_randombytes(p, len);
}
