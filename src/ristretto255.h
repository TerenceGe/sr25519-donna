#ifndef __ristretto255_H__
#define __ristretto255_H__

#include "ed25519-donna/ed25519-donna.h"

/**
 * A `ristretto_point_t` internally holds an Edwards point in extended twisted
 * Edwards coordinates.
 */
typedef struct ristretto_point_s {
  ge25519 point;
} ristretto_point_t;

uint8_t uint8_32_ct_eq(const unsigned char a[32], const unsigned char b[32]);

int ristretto_decode(ge25519 *element, const unsigned char bytes[32]);
void ristretto_encode(unsigned char bytes[32], const ge25519 element);
int ristretto_from_uniform_bytes(ristretto_point_t *element, const unsigned char bytes[64]);
int ristretto_ct_eq(const ristretto_point_t *a, const ristretto_point_t *b);
void ge25519_pack_without_parity(unsigned char bytes[32], const ge25519 *p);

#endif
