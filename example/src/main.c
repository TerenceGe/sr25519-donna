#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sr25519-donna.h"
#include "print.h"

#define FROMHEX_MAXLEN 512

char *result_map[8] = {"Ok", "EquationFalse", "PointDecompressionError", "ScalarFormatError", "BytesLengthError", "NotMarkedSchnorrkel", "MuSigAbsent", "MuSigInconsistent"};

const uint8_t *fromhex(const char *str) {
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}

void creates_pair_from_known_seed() {
    printf("creates_pair_from_known_seed: \n");

    sr25519_mini_secret_key seed = {0};
    memcpy(seed, fromhex("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"), 32);
    sr25519_public_key expected = {0};
    memcpy(expected, fromhex("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"), 32);
    sr25519_keypair keypair = {0};
    sr25519_keypair_from_seed(keypair, seed);
    sr25519_public_key public_key = {0};
    memcpy(public_key, keypair + 64, 32);

    printf("public_key: ");
    print_hash(public_key, 32);
    printf("expected: ");
    print_hash(expected, 32);
}

void can_sign_and_verify_message() {
    printf("can_sign_and_verify_message: \n");

    sr25519_mini_secret_key seed = {0};
    sr25519_randombytes(seed, 32);
    sr25519_keypair keypair = {0};
    sr25519_keypair_from_seed(keypair, seed);
    sr25519_secret_key private = {0};
    memcpy(private, keypair, 64);
    sr25519_public_key public_key = {0};
    memcpy(public_key, keypair + 64, 32);
    uint8_t *message = "this is a message";
    sr25519_signature signature = {0};
    sr25519_sign(signature, public_key, private, message, strlen(message));
    bool is_valid = sr25519_verify(signature, message, strlen(message), public_key);

    printf("is_valid: %i\n", is_valid);
}

void can_verify_known_message() {
    printf("can_verify_known_message: \n");

    uint8_t *message = "I hereby verify that I control 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    sr25519_public_key public_key = {0};
    memcpy(public_key, fromhex("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"), 32);
    sr25519_signature signature = {0};
    memcpy(signature, fromhex("1037eb7e51613d0dcf5930ae518819c87d655056605764840d9280984e1b7063c4566b55bf292fcab07b369d01095879b50517beca4d26e6a65866e25fec0d83"), 64);
    bool is_valid = sr25519_verify(signature, message, strlen(message), public_key);

    printf("is_valid: %i\n", is_valid);
}

void soft_derives_pair() {
    printf("soft_derives_pair: \n");

    sr25519_chain_code cc = {0};
    memcpy(cc, fromhex("0c666f6f00000000000000000000000000000000000000000000000000000000"), 32);
    sr25519_mini_secret_key seed = {0};
    memcpy(seed, fromhex("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"), 32);
    sr25519_public_key expected = {0};
    memcpy(expected, fromhex("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a"), 32);
    sr25519_keypair keypair = {0};
    sr25519_keypair_from_seed(keypair, seed);
    sr25519_keypair derived = {0};
    sr25519_derive_keypair_soft(derived, keypair, cc);
    sr25519_public_key public_key = {0};
    memcpy(public_key, derived + 64, 32);

    printf("public_key: ");
    print_hash(public_key, 32);
    printf("expected: ");
    print_hash(expected, 32);

}

void soft_derives_public() {
    printf("soft_derives_public: \n");

    sr25519_chain_code cc = {0};
    memcpy(cc, fromhex("0c666f6f00000000000000000000000000000000000000000000000000000000"), 32);
    sr25519_public_key public_key = {0};
    memcpy(public_key, fromhex("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"), 32);
    sr25519_public_key expected = {0};
    memcpy(expected, fromhex("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a"), 32);
    sr25519_public_key derived = {0};
    sr25519_derive_public_soft(derived, public_key, cc);

    printf("derived_key: ");
    print_hash(derived, 32);
    printf("expected: ");
    print_hash(expected, 32);
}

void hard_derives_pair() {
    printf("hard_derives_pair: \n");

    sr25519_chain_code cc = {0};
    memcpy(cc, fromhex("14416c6963650000000000000000000000000000000000000000000000000000"), 32);
    sr25519_mini_secret_key seed = {0};
    memcpy(seed, fromhex("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"), 32);
    sr25519_public_key expected = {0};
    memcpy(expected, fromhex("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"), 32);
    sr25519_keypair keypair = {0};
    sr25519_keypair_from_seed(keypair, seed);
    sr25519_keypair derived = {0};
    sr25519_derive_keypair_hard(derived, keypair, cc);
    sr25519_public_key public_key = {0};
    memcpy(public_key, derived + 64, 32);

    printf("public_key: ");
    print_hash(public_key, 32);
    printf("expected: ");
    print_hash(expected, 32);
}

void vrf_verify() {
    printf("test vrf verify: \n");

    sr25519_mini_secret_key seed = {0};
    sr25519_randombytes(seed, 32);

    sr25519_keypair keypair = {0};
    sr25519_uniform_keypair_from_seed(keypair, seed);

    // sr25519_keypair ed25519_keypair = {0};
    // sr25519_keypair_from_seed(ed25519_keypair, seed);
    // sr25519_keypair keypair = {0};
    // sr25519_keypair_ed25519_to_uniform(keypair, ed25519_keypair);

    sr25519_public_key public_key = {0};
    memcpy(public_key, keypair + 64, 32);

    sr25519_vrf_threshold limit = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    sr25519_vrf_out_and_proof out_and_proof  = {0};
    VrfResult res1 = sr25519_vrf_sign_if_less(out_and_proof, keypair, (uint8_t *)"Hello, world!", 13, limit);

    printf("result1 result: %s\n", (char *)result_map[res1.result]);
    printf("result1 is less: %i\n", res1.is_less);

    sr25519_vrf_output output = {0};
    memcpy(output, out_and_proof, 32);
    printf("vrf output: ");
    print_hash(output, 32);
    sr25519_vrf_proof proof = {0};
    memcpy(proof, out_and_proof + 32, 64);
    printf("vrf proof: ");
    print_hash(proof, 64);

    VrfResult res2 = sr25519_vrf_verify(public_key, (uint8_t *)"Hello, world!", 13, output, proof, limit);

    printf("result2 result: %s\n", (char *)result_map[res2.result]);
    printf("result2 is less: %i\n", res2.is_less);

    output[5] += 3;
    VrfResult res3 = sr25519_vrf_verify(public_key, (uint8_t *)"Hello, world!", 13, output, proof, limit);

    printf("result3 result: %s\n", (char *)result_map[res3.result]);
    printf("result3 is less: %i\n", res3.is_less);
}

void vrf_result_not_less() {
    printf("test vrf result not less: \n");

    sr25519_keypair keypair = {0};
    memcpy(keypair, fromhex("915bb406968655c3412df5773c3de3dee9f6da84668b5de8d2f34d0304d20b0bac5ea3a293dfd93859ee64a5b825937753864c19be857f045758dcae10259ba1049b21bb9cb88471b9dadb50b925135cfb291a463043635b58599a2d01b1fd18"), 96);
    sr25519_vrf_out_and_proof out_and_proof  = {0};
    sr25519_vrf_threshold limit = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

    VrfResult res1 = sr25519_vrf_sign_if_less(out_and_proof, keypair, (uint8_t *)"Hello, world!", 13, limit);

    sr25519_vrf_output output = {0};
    memcpy(output, out_and_proof, 32);
    printf("vrf output: ");
    print_hash(output, 32);
    sr25519_vrf_proof proof = {0};
    memcpy(proof, out_and_proof + 32, 64);
    printf("vrf proof: ");
    print_hash(proof, 64);

    printf("result1 result: %s\n", (char *)result_map[res1.result]);
    printf("result1 is less: %i\n", res1.is_less);
}

void vrf_sign_and_check() {
    printf("test vrf sign and check: \n");

    sr25519_keypair keypair = {0};
    memcpy(keypair, fromhex("915bb406968655c3412df5773c3de3dee9f6da84668b5de8d2f34d0304d20b0bac5ea3a293dfd93859ee64a5b825937753864c19be857f045758dcae10259ba1049b21bb9cb88471b9dadb50b925135cfb291a463043635b58599a2d01b1fd18"), 96);
    sr25519_vrf_out_and_proof out_and_proof  = {0};
    sr25519_vrf_threshold limit = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

    VrfResult res1 = sr25519_vrf_sign_if_less(out_and_proof, keypair, (uint8_t *)"Hello, world!", 13, limit);

    sr25519_vrf_output output = {0};
    memcpy(output, out_and_proof, 32);
    printf("vrf output: ");
    print_hash(output, 32);
    sr25519_vrf_proof proof = {0};
    memcpy(proof, out_and_proof + 32, 64);
    printf("vrf proof: ");
    print_hash(proof, 64);

    printf("result1 result: %s\n", (char *)result_map[res1.result]);
    printf("result1 is less: %i\n", res1.is_less);
}

int main(int argc, char *argv[]) {
    creates_pair_from_known_seed();
    printf("\n");
    can_sign_and_verify_message();
    printf("\n");
    can_verify_known_message();
    printf("\n");
    soft_derives_pair();
    printf("\n");
    soft_derives_public();
    printf("\n");
    hard_derives_pair();
    printf("\n");
    vrf_verify();
    printf("\n");
    vrf_result_not_less();
    printf("\n");
    vrf_sign_and_check();

    return 0;
}
