#include "ristretto255.h"
#include "memzero.h"

/**
 * Edwards `d` value from the curve equation, equal to `-121665/121666 (mod p)`.
 */
#if defined(ED25519_64BIT)
const bignum25519 EDWARDS_D = {
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
};
#else
const bignum25519 EDWARDS_D = {
    56195235, 13857412, 51736253,  6949390,   114729,
    24766616, 60832955, 30306712, 48412415, 21499315,
};
#endif

/**
 * Precomputed value of one of the square roots of -1 (mod p)
 */
#if defined(ED25519_64BIT)
const bignum25519 SQRT_M1 = {
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
};
#else
const bignum25519 SQRT_M1 = {
    34513072, 25610706,  9377949, 3500415, 12389472,
    33281959, 41962654, 31548777,  326685, 11406482,
};
#endif

#if defined(ED25519_64BIT)
const bignum25519 one = {0x01, 0x00, 0x00, 0x00, 0x00};
const bignum25519 zero = {0, 0, 0, 0, 0};
#else
const bignum25519 one = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const bignum25519 zero = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
#endif

#if defined(ED25519_64BIT)
const bignum25519 INVSQRT_A_MINUS_D = {
  278908739862762,
  821645201101625,
  8113234426968,
  1777959178193151,
  2118520810568447,
};
#else
const bignum25519 INVSQRT_A_MINUS_D = {
  6111466,  4156064, 39310137, 12243467, 41204824,
  120896, 20826367, 26493656,  6093567, 31568420,
};
#endif

static uint8_t uchar_ct_eq(const uint8_t a, const uint8_t b);
static uint8_t bignum25519_is_negative(unsigned char bytes[32]);

/**
 * Check if two bytes are equal in constant time.
 *
 * Returns 1 iff the bytes are equals and 0 otherwise.
 */
static uint8_t uchar_ct_eq(const unsigned char a, const unsigned char b) {
    unsigned char x = ~(a ^ b);

    x &= x >> 4;
    x &= x >> 2;
    x &= x >> 1;

    return (uint8_t)x;
}

/**
 * Check if two 32 bytes arrays are equal in constant time.
 *
 * Returns 1 iff the bytes are equals and 0 otherwise.
 */
uint8_t uint8_32_ct_eq(const unsigned char a[32], const unsigned char b[32]) {
    unsigned char x = 1;
    unsigned char i;

    for (i=0; i<32; i++) {
        x &= uchar_ct_eq(a[i], b[i]);
    }

    return (uint8_t)x;
}

/**
 * Check if two field elements are equal in constant time.
 *
 * Returns 1 iff the elements are equals and 0 otherwise.
 */
uint8_t bignum25519_ct_eq(const bignum25519 a, const bignum25519 b) {
    unsigned char c[32] = {0};
    unsigned char d[32] = {0};

    curve25519_contract(c, a);
    curve25519_contract(d, b);

    uint8_t result = uint8_32_ct_eq(c, d);

    memzero(c, sizeof(c));
    memzero(d, sizeof(d));

    return result;
}

/**
 * Ascertain if a field element (encoded as bytes) is negative.
 *
 * Returns 1 iff the element is negative and 0 otherwise.
 */
static uint8_t bignum25519_is_negative(unsigned char bytes[32]) {
    uint8_t low_bit_is_set = bytes[0] & 1;

    return low_bit_is_set;
}

uint8_t curve25519_sqrt_ratio_i(bignum25519 out, const bignum25519 u, const bignum25519 v) {
    bignum25519 tmp = {0}, v3 = {0}, v7 = {0}, r = {0}, r_prime = {0}, r_negative = {0}, check = {0}, i = {0}, u_neg = {0}, u_neg_i = {0};
    unsigned char r_bytes[32] = {0};
    uint8_t r_is_negative;
    uint8_t correct_sign_sqrt;
    uint8_t flipped_sign_sqrt;
    uint8_t flipped_sign_sqrt_i;
    uint8_t was_nonzero_square;
    uint8_t should_rotate;

    curve25519_square(tmp, v);      // v²
    curve25519_mul(v3, tmp, v);     // v³
    curve25519_square(tmp, v3);      // v⁶
    curve25519_mul(v7, tmp, v);     // v⁷
    curve25519_mul(tmp, u, v7);     // u*v^7
    curve25519_pow_two252m3(r, tmp); // (u*v^7)^{(p-5)/8}
    curve25519_mul(r, r, u);        // (u)*(u*v^7)^{(p-5)/8}
    curve25519_mul(r, r, v3);        // (u)*(u*v^7)^{(p-5)/8}
    curve25519_square(tmp, r);       // tmp = r^2
    curve25519_mul(check, v, tmp);  // check = r^2 * v

    curve25519_neg(u_neg, u);
    curve25519_mul(u_neg_i, u_neg, SQRT_M1);

    correct_sign_sqrt = bignum25519_ct_eq(check, u);
    flipped_sign_sqrt = bignum25519_ct_eq(check, u_neg);
    flipped_sign_sqrt_i = bignum25519_ct_eq(check, u_neg_i);

    curve25519_mul(r_prime, r, SQRT_M1);
    should_rotate = flipped_sign_sqrt | flipped_sign_sqrt_i;
    curve25519_swap_conditional(r, r_prime, should_rotate);

    // Choose the non-negative square root
    curve25519_contract(r_bytes, r);
    r_is_negative = bignum25519_is_negative(r_bytes);
    curve25519_neg(r_negative, r);
    curve25519_swap_conditional(r, r_negative, r_is_negative);

    was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

    curve25519_copy(out, r);

    memzero(tmp, sizeof(tmp));
    memzero(v3, sizeof(v3));
    memzero(v7, sizeof(v7));
    memzero(r, sizeof(r));
    memzero(r_prime, sizeof(r_prime));
    memzero(r_negative, sizeof(r_negative));
    memzero(check, sizeof(check));
    memzero(i, sizeof(i));
    memzero(u_neg, sizeof(u_neg));
    memzero(u_neg_i, sizeof(u_neg_i));
    memzero(r_bytes, sizeof(r_bytes));

    return was_nonzero_square;
}

/**
 * Calculate either `sqrt(1/v)` for a field element `v`.
 *
 * Returns:
 *  - 1 and stores `+sqrt(1/v)` in `out` if `v` was a non-zero square,
 *  - 0 and stores `0` in `out` if `v` was zero,
 *  - 0 and stores `+sqrt(i/v)` in `out` if `v` was a non-zero non-square.
 */
uint8_t curve25519_invsqrt(bignum25519 out, const bignum25519 v) {
    return curve25519_sqrt_ratio_i(out, one, v);
}

/**
 * Attempt to decompress `bytes` to a Ristretto group `element`.
 *
 * Returns 0 if the point could not be decoded and 1 otherwise.
 */
int ristretto_decode(ge25519 *element, const unsigned char bytes[32]) {
    bignum25519 s = {0}, ss = {0};
    bignum25519 u1 = {0}, u1_sqr = {0}, u2 = {0}, u2_sqr = {0};
    bignum25519 v = {0}, i = {0}, minus_d = {0}, dx = {0}, dy = {0}, x = {0}, y = {0}, t = {0};
    bignum25519 tmp = {0};
    unsigned char s_bytes_check[32] = {0};
    unsigned char x_bytes[32] = {0};
    unsigned char t_bytes[32] = {0};
    uint8_t s_encoding_is_canonical;
    uint8_t s_is_negative;
    uint8_t x_is_negative;
    uint8_t t_is_negative;
    uint8_t y_is_zero;
    uint8_t ok;

    // Step 1: Check that the encoding of the field element is canonical
    curve25519_expand(s, bytes);
    curve25519_contract(s_bytes_check, s);

    s_encoding_is_canonical = uint8_32_ct_eq(bytes, s_bytes_check);
    s_is_negative = bignum25519_is_negative(s_bytes_check);

    // Bail out if the field element encoding was non-canonical or negative
    /* printf("s_encoding_is_canonical: %i\n", s_encoding_is_canonical); */
    /* printf("s_is_negative: %i\n", s_is_negative); */
    if (s_encoding_is_canonical == 0 || s_is_negative == 1) {
        memzero(s, sizeof(s));
        memzero(ss, sizeof(ss));
        memzero(u1, sizeof(u1));
        memzero(u1_sqr, sizeof(u1_sqr));
        memzero(u2, sizeof(u2));
        memzero(u2_sqr, sizeof(u2_sqr));
        memzero(v, sizeof(v));
        memzero(i, sizeof(i));
        memzero(minus_d, sizeof(minus_d));
        memzero(dx, sizeof(dx));
        memzero(dy, sizeof(dy));
        memzero(tmp, sizeof(tmp));
        memzero(s_bytes_check, sizeof(s_bytes_check));
        memzero(x_bytes, sizeof(x_bytes));
        memzero(t_bytes, sizeof(t_bytes));
        memzero(x, sizeof(x));
        memzero(y, sizeof(y));
        memzero(t, sizeof(t));

        return 0;
    }

    // Step 2: Compute (X:Y:Z:T)
    // XXX can we eliminate these reductions
    curve25519_square(ss, s);
    curve25519_sub_reduce(u1, one, ss);    //  1 + as², where a = -1, d = -121665/121666
    curve25519_add_reduce(u2, one, ss);    //  1 - as²
    curve25519_square(u1_sqr, u1);         // (1 + as²)²
    curve25519_square(u2_sqr, u2);         // (1 - as²)²
    /* printf("u2_sqr: "); */
    /* print_bignum25519(u2_sqr); */
    curve25519_neg(minus_d, EDWARDS_D);    // -d               // XXX store as const?
    curve25519_mul(tmp, minus_d, u1_sqr);  // ad(1+as²)²
    curve25519_sub_reduce(v, tmp, u2_sqr); // ad(1+as²)² - (1-as²)²
    curve25519_mul(tmp, v, u2_sqr);        // v = (ad(1+as²)² - (1-as²)²)(1-as²)²

    ok = curve25519_invsqrt(i, tmp);       // i = 1/sqrt{(ad(1+as²)² - (1-as²)²)(1-as²)²}

    // Step 3: Calculate x and y denominators, then compute x.
    curve25519_mul(dx, i, u2);             // 1/sqrt(v)
    curve25519_mul(tmp, dx, v);            // v/sqrt(v)
    curve25519_mul(dy, i, tmp);            // 1/(1-as²)
    curve25519_add_reduce(tmp, s, s);      // 2s
    curve25519_mul(x, tmp, dx);            // x = |2s/sqrt(v)| = +sqrt(4s²/(ad(1+as²)² - (1-as²)²))
    curve25519_contract(x_bytes, x);

    // Step 4: Conditionally negate x if it's negative.
    x_is_negative = bignum25519_is_negative(x_bytes);

    curve25519_neg(tmp, x);
    curve25519_swap_conditional(x, tmp, x_is_negative);

    // Step 5: Compute y = (1-as²)/(1+as²) and t = {(1+as²)sqrt(4s²/(ad(1+as²)²-(1-as²)²))}/(1-as²)
    curve25519_mul(y, u1, dy);
    curve25519_mul(t, x, y);
    curve25519_contract(t_bytes, t);

    t_is_negative = bignum25519_is_negative(t_bytes);
    y_is_zero = bignum25519_ct_eq(zero, y);

    if (ok == 0 || t_is_negative == 1 || y_is_zero == 1) {
        memzero(s, sizeof(s));
        memzero(ss, sizeof(ss));
        memzero(u1, sizeof(u1));
        memzero(u1_sqr, sizeof(u1_sqr));
        memzero(u2, sizeof(u2));
        memzero(u2_sqr, sizeof(u2_sqr));
        memzero(v, sizeof(v));
        memzero(i, sizeof(i));
        memzero(minus_d, sizeof(minus_d));
        memzero(dx, sizeof(dx));
        memzero(dy, sizeof(dy));
        memzero(tmp, sizeof(tmp));
        memzero(s_bytes_check, sizeof(s_bytes_check));
        memzero(x_bytes, sizeof(x_bytes));
        memzero(t_bytes, sizeof(t_bytes));
        memzero(x, sizeof(x));
        memzero(y, sizeof(y));
        memzero(t, sizeof(t));

        return 0;
    }

    curve25519_copy(element->x, x);
    curve25519_copy(element->y, y);
    curve25519_copy(element->z, one);
    curve25519_copy(element->t, t);

    memzero(s, sizeof(s));
    memzero(ss, sizeof(ss));
    memzero(u1, sizeof(u1));
    memzero(u1_sqr, sizeof(u1_sqr));
    memzero(u2, sizeof(u2));
    memzero(u2_sqr, sizeof(u2_sqr));
    memzero(v, sizeof(v));
    memzero(i, sizeof(i));
    memzero(minus_d, sizeof(minus_d));
    memzero(dx, sizeof(dx));
    memzero(dy, sizeof(dy));
    memzero(tmp, sizeof(tmp));
    memzero(s_bytes_check, sizeof(s_bytes_check));
    memzero(x_bytes, sizeof(x_bytes));
    memzero(t_bytes, sizeof(t_bytes));
    memzero(x, sizeof(x));
    memzero(y, sizeof(y));
    memzero(t, sizeof(t));

    return 1;
}

void ristretto_encode(unsigned char bytes[32], const ge25519 element) {
    bignum25519 u1 = {0}, u2 = {0}, u22 = {0}, i1 = {0}, i2 = {0}, z_inv = {0}, den_inv = {0}, ix = {0}, iy = {0}, invsqrt = {0}, tmp1 = {0}, tmp2 = {0};
    bignum25519 x = {0}, y = {0}, y_neg = {0}, s = {0}, s_neg = {0};
    bignum25519 enchanted_denominator = {0};
    unsigned char contracted[32] = {0};
    uint8_t x_zinv_is_negative;
    uint8_t s_is_negative;
    uint8_t rotate;

    curve25519_add_reduce(tmp1, element.z, element.y);
    curve25519_sub_reduce(tmp2, element.z, element.y);
    curve25519_mul(u1, tmp1, tmp2);
    curve25519_mul(u2, element.x, element.y);

    curve25519_square(u22, u2);
    curve25519_mul(tmp1, u1, u22);

    // This is always square so we don't need to check the return value
    int ok = curve25519_invsqrt(invsqrt, tmp1);

    curve25519_mul(i1, invsqrt, u1);
    curve25519_mul(i2, invsqrt, u2);
    curve25519_mul(tmp1, i2, element.t);
    curve25519_mul(z_inv, tmp1, i1);
    curve25519_mul(ix, element.x, SQRT_M1);
    curve25519_mul(iy, element.y, SQRT_M1);
    curve25519_mul(enchanted_denominator, i1, INVSQRT_A_MINUS_D);
    curve25519_mul(tmp1, element.t, z_inv);
    curve25519_contract(contracted, tmp1);

    rotate = bignum25519_is_negative(contracted);

    curve25519_copy(x, element.x);
    curve25519_copy(y, element.y);

    // Rotate into the distinguished Jacobi quartic quadrant
    curve25519_swap_conditional(x, iy, rotate);
    curve25519_swap_conditional(y, ix, rotate);
    curve25519_swap_conditional(i2, enchanted_denominator, rotate);

    // Next we torque the points to be non-negative

    // Conditionally flip the sign of y to be positive
    curve25519_mul(tmp1, x, z_inv);
    curve25519_contract(contracted, tmp1);

    x_zinv_is_negative = bignum25519_is_negative(contracted);

    curve25519_neg(y_neg, y);
    curve25519_swap_conditional(y, y_neg, x_zinv_is_negative);

    curve25519_sub_reduce(tmp1, element.z, y);
    curve25519_mul(s, i2, tmp1);
    curve25519_contract(contracted, s);

    // Conditionally flip the sign of s to be positive
    s_is_negative = bignum25519_is_negative(contracted);

    curve25519_neg(s_neg, s);
    curve25519_swap_conditional(s, s_neg, s_is_negative);

    // Output the compressed form of s
    curve25519_contract(bytes, s);

    memzero(u1, sizeof(u1));
    memzero(u2, sizeof(u2));
    memzero(u22, sizeof(u22));
    memzero(i1, sizeof(i1));
    memzero(i2, sizeof(i2));
    memzero(z_inv, sizeof(z_inv));
    memzero(den_inv, sizeof(den_inv));
    memzero(ix, sizeof(ix));
    memzero(iy, sizeof(iy));
    memzero(invsqrt, sizeof(invsqrt));
    memzero(tmp1, sizeof(tmp1));
    memzero(tmp2, sizeof(tmp2));
    memzero(x, sizeof(x));
    memzero(y, sizeof(y));
    memzero(y_neg, sizeof(y_neg));
    memzero(s, sizeof(s));
    memzero(s_neg, sizeof(s_neg));
    memzero(enchanted_denominator, sizeof(enchanted_denominator));
    memzero(contracted, sizeof(contracted));
}

/**
 * Produce a Ristretto group element from a 512-bit hash digest.
 *
 * Returns 1 on success, otherwise returns 0.
 */
int ristretto_from_uniform_bytes(ristretto_point_t *element, const unsigned char bytes[64]) {
    return 1;
}

/**
 * Test equality of two `ristretto_point_t`s in constant time.
 *
 * Returns 1 if the two points are equal, and 0 otherwise.
 */
int ristretto_ct_eq(const ristretto_point_t *a, const ristretto_point_t *b) {
    bignum25519 x1y2 = {0}, y1x2 = {0}, x1x2 = {0}, y1y2 = {0};
    uint8_t check_one, check_two;

    curve25519_mul(x1y2, a->point.x, b->point.y);
    curve25519_mul(y1x2, a->point.y, b->point.x);
    curve25519_mul(x1x2, a->point.x, b->point.x);
    curve25519_mul(y1y2, a->point.y, b->point.y);

    check_one = bignum25519_ct_eq(x1y2, y1x2);
    check_two = bignum25519_ct_eq(x1x2, y1y2);

    memzero(x1y2, sizeof(x1y2));
    memzero(y1x2, sizeof(y1x2));
    memzero(x1x2, sizeof(x1x2));
    memzero(y1y2, sizeof(y1y2));

    return check_one | check_two;
}
