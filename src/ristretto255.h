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

/**
 * The Ristretto basepoint in compressed form.
 */
static unsigned char RISTRETTO_BASEPOINT_COMPRESSED[32] = {
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
    0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
    0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
};

static unsigned char RISTRETTO_IDENTITY_COMPRESSED[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

uint8_t uint8_32_ct_eq(const unsigned char a[32], const unsigned char b[32]);

int ristretto_decode(ge25519 *element, const unsigned char bytes[32]);
void ristretto_encode(unsigned char bytes[32], const ge25519 element);
int ristretto_from_uniform_bytes(ristretto_point_t *element, const unsigned char bytes[64]);
int ristretto_ct_eq(const ristretto_point_t *a, const ristretto_point_t *b);
void ge25519_pack_without_parity(unsigned char bytes[32], const ge25519 *p);

#endif
