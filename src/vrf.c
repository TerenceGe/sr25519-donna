#include <stdio.h>
#include "vrf.h"
#include "ristretto255.h"
#include "sr25519-randombytes.h"

#define KUSAMA_VRF 1

Sr25519SignatureResult vrf_sign(sr25519_vrf_io inout, sr25519_vrf_proof proof, sr25519_vrf_proof_batchable proof_batchable, const sr25519_keypair keypair, const merlin_transcript *t) {
    sr25519_secret_key_key secret_key = {0};
    memcpy(secret_key, keypair, 32);
    sr25519_secret_key_nonce secret_nonce = {0};
    memcpy(secret_nonce, keypair + 32, 32);
    sr25519_public_key public = {0};
    memcpy(public, keypair + 64, 32);

    merlin_transcript_commit_bytes(t, (uint8_t *)"vrf-nm-pk", 9, public, 32);
    uint8_t b[64] = {0};
    merlin_transcript_challenge_bytes(t, (uint8_t *)"VRFHash", 7, b, 64);

    ge25519 input = {0};
    ristretto_from_uniform_bytes(&input, b);
    uint8_t input_compressed[32] = {0};
    ristretto_encode(input_compressed, input);

    ge25519 output = {0};
    bignum256modm secret_key_scalar = {0};
    expand_raw256_modm(secret_key_scalar, secret_key);

    int is_canonical = is_reduced256_modm(secret_key_scalar);
    if (!is_canonical) {
        Sr25519SignatureResult result = ScalarFormatError;
        return result;
    }

    ge25519_scalarmult_tg(&output, &input, secret_key_scalar);

    uint8_t output_compressed[32] = {0};
    ristretto_encode(output_compressed, output);

    memcpy(inout, input_compressed, 32);
    memcpy(inout + 32, output_compressed, 32);

    merlin_transcript e = {0};
    merlin_transcript_init(&e, (uint8_t *)"VRF", 3);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"proto-name", 10, (uint8_t *)"DLEQProof", 9);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h", 5, input_compressed, 32);
    if (!KUSAMA_VRF) {
        merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:pk", 6, public, 32);
    }

    bignum256modm r_scalar = {0};
    uint8_t scalar_bytes[64] = {0};

    merlin_rng mrng = {0};
    merlin_rng_init(&mrng, &e);
    merlin_rng_commit_witness_bytes(&mrng, (uint8_t *)"proving\00", 10, secret_nonce, 32);
    uint8_t entropy[32] = {0};
    sr25519_randombytes(entropy, 32);
    merlin_rng_finalize(&mrng, entropy);
    merlin_rng_random_bytes(&mrng, scalar_bytes, 32);

    expand256_modm(r_scalar, scalar_bytes, 64);

    ge25519 R = {0};
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r_scalar);
    uint8_t R_compressed[32] = {0};
    ristretto_encode(R_compressed, R);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:R=g^r", 9, R_compressed, 32);

    ge25519 Hr = {0};
    ge25519_scalarmult_tg(&Hr, &input, r_scalar);
    uint8_t Hr_compressed[32] = {0};
    ristretto_encode(Hr_compressed, Hr);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h^r", 7, Hr_compressed, 32);

    if (KUSAMA_VRF) {
        merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:pk", 6, public, 32);
    }

    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h^sk", 8, output_compressed, 32);

    bignum256modm c_scalar = {0};
    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(&e, (uint8_t *)"prove", 5, buf, 64);
    expand256_modm(c_scalar, buf, 64);

    bignum256modm c_secret_key_scalar = {0};
    mul256_modm(c_secret_key_scalar, c_scalar, secret_key_scalar);

    bignum256modm s_scalar = {0};
    sub256_modm(s_scalar, r_scalar, c_secret_key_scalar);

    uint8_t c[32] = {0};
    contract256_modm(c, c_scalar);

    uint8_t s[32] = {0};
    contract256_modm(s, s_scalar);

    memcpy(proof, c, 32);
    memcpy(proof + 32, s, 32);

    memcpy(proof_batchable, R_compressed, 32);
    memcpy(proof_batchable + 32, Hr_compressed, 32);
    memcpy(proof_batchable + 64, s, 32);

    Sr25519SignatureResult result = Ok;
    return result;
}

Sr25519SignatureResult shorten_vrf(sr25519_vrf_proof proof, const sr25519_vrf_proof_batchable proof_batchable, const sr25519_public_key public, const merlin_transcript *t, const sr25519_vrf_output preout) {
    merlin_transcript_commit_bytes(t, (uint8_t *)"vrf-nm-pk", 9, public, 32);
    uint8_t b[64] = {0};
    merlin_transcript_challenge_bytes(t, (uint8_t *)"VRFHash", 7, b, 64);
    ge25519 input = {0};
    ristretto_from_uniform_bytes(&input, b);

    uint8_t input_compressed[32] = {0};
    ristretto_encode(input_compressed, input);
    uint8_t output_compressed[32] = {0};
    memcpy(output_compressed, preout, 32);

    merlin_transcript e = {0};
    merlin_transcript_init(&e, (uint8_t *)"VRF", 3);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"proto-name", 10, (uint8_t *)"DLEQProof", 9);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h", 5, input_compressed, 32);
    if (!KUSAMA_VRF) {
        merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:pk", 6, public, 32);
    }

    uint8_t R[32] = {0};
    memcpy(R, proof_batchable, 32);
    uint8_t Hr[32] = {0};
    memcpy(Hr, proof_batchable + 32, 32);
    uint8_t s[32] = {0};
    memcpy(s, proof_batchable + 64, 32);

    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:R=g^r", 9, R, 32);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h^r", 7, Hr, 32);
    if (KUSAMA_VRF) {
        merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:pk", 6, public, 32);
    }
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h^sk", 8, output_compressed, 32);

    bignum256modm c_scalar = {0};
    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(&e, (uint8_t *)"prove", 5, buf, 64);
    expand256_modm(c_scalar, buf, 64);

    uint8_t c[32] = {0};
    contract256_modm(c, c_scalar);

    memcpy(proof, c, 32);
    memcpy(proof + 32, s, 32);

    Sr25519SignatureResult result = Ok;
    return result;
}

Sr25519SignatureResult vrf_verify(sr25519_vrf_io inout, sr25519_vrf_proof_batchable proof_batchable, const sr25519_public_key public, const merlin_transcript *t, const sr25519_vrf_output preout, const sr25519_vrf_proof proof) {
    uint8_t c[32] = {0};
    memcpy(c, proof, 32);
    uint8_t s[32] = {0};
    memcpy(s, proof + 32, 32);

    merlin_transcript_commit_bytes(t, (uint8_t *)"vrf-nm-pk", 9, public, 32);
    uint8_t b[64] = {0};
    merlin_transcript_challenge_bytes(t, (uint8_t *)"VRFHash", 7, b, 64);
    ge25519 input = {0};
    ristretto_from_uniform_bytes(&input, b);

    uint8_t input_compressed[32] = {0};
    ristretto_encode(input_compressed, input);
    uint8_t output_compressed[32] = {0};
    memcpy(output_compressed, preout, 32);

    memcpy(inout, input_compressed, 32);
    memcpy(inout + 32, output_compressed, 32);

    merlin_transcript e = {0};
    merlin_transcript_init(&e, (uint8_t *)"VRF", 3);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"proto-name", 10, (uint8_t *)"DLEQProof", 9);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h", 5, input_compressed, 32);
    if (!KUSAMA_VRF) {
        merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:pk", 6, public, 32);
    }

    ge25519 R, P = {0};
    ristretto_decode(&P, public);
    bignum256modm c_scalar = {0};
    expand_raw256_modm(c_scalar, c);
    bignum256modm s_scalar = {0};
    expand_raw256_modm(s_scalar, s);
    ge25519_double_scalarmult_vartime(&R, &P, c_scalar, s_scalar);
    sr25519_public_key R_compressed = {0};
    ristretto_encode(R_compressed, R);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:R=g^r", 9, R_compressed, 32);

    ge25519 Hr, CP, SP, output = {0};
    ristretto_decode(&output, output_compressed);
    ge25519_scalarmult_tg(&CP, &output, c_scalar);
    ge25519_scalarmult_tg(&SP, &input, s_scalar);
    ge25519_add(&Hr, &CP, &SP);
    sr25519_public_key Hr_compressed = {0};
    ristretto_encode(Hr_compressed, Hr);
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h^r", 7, Hr_compressed, 32);

    if (KUSAMA_VRF) {
        merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:pk", 6, public, 32);
    }
    merlin_transcript_commit_bytes(&e, (uint8_t *)"vrf:h^sk", 8, output_compressed, 32);

    bignum256modm verify_c_scalar = {0};
    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(&e, (uint8_t *)"prove", 5, buf, 64);
    expand256_modm(verify_c_scalar, buf, 64);
    uint8_t verify_c[32] = {0};
    contract256_modm(verify_c, verify_c_scalar);

    uint8_t is_valid = uint8_32_ct_eq(verify_c, c);

    if (is_valid) {
        memcpy(proof_batchable, R_compressed, 32);
        memcpy(proof_batchable + 32, Hr_compressed, 32);
        memcpy(proof_batchable + 64, s, 32);

        Sr25519SignatureResult result = Ok;
        return result;
    } else {

        Sr25519SignatureResult result = EquationFalse;
        return result;
    }
}

void io_make_bytes(sr25519_vrf_raw_output raw_output, const sr25519_vrf_io inout, const uint8_t *context, const size_t context_length) {
    merlin_transcript t = {0};
    merlin_transcript_init(&t, (uint8_t *)"VRFResult", 9);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"", 0, context, context_length);
    uint8_t input[32] = {0};
    memcpy(input, inout, 32);
    uint8_t output[32] = {0};
    memcpy(output, inout + 32, 32);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"vrf-in", 6, input, 32);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"vrf-out", 7, output, 32);
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"", 0, raw_output, 16);
}
