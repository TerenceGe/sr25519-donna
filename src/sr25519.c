#include <string.h>
#include "sr25519.h"
#include "sr25519-randombytes.h"
#include "sr25519-hash.h"
#include "ristretto255.h"
#include "merlin.h"
#include "memzero.h"
#include "vrf.h"

void divide_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len) {
    uint8_t low = 0;

    for (int i = scalar_len - 1; i >= 0; i--) {
        uint8_t r = scalar[i] & 7;
        scalar[i] >>= 3;
        scalar[i] += low;
        low = r << 5;
    }
}

void multiply_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len) {
    uint8_t high = 0;

    for (int i = 0; i < scalar_len; i++) {
        uint8_t r = scalar[i] & (7 << 5);
        scalar[i] <<= 3;
        scalar[i] += high;
        high = r >> 5;
    }
}

void expand_ed25519(sr25519_secret_key_key key, sr25519_secret_key_nonce nonce, sr25519_mini_secret_key mini_secret_key) {
    uint8_t hash[64] = {0};
    sr25519_hash(hash, mini_secret_key, 32);
    memcpy(key, hash, 32);
    key[0]  &= 248;
    key[31] &= 63;
    key[31] |= 64;
    divide_scalar_bytes_by_cofactor(key, 32);
    key[31] &= 0b1111111;
    memcpy(nonce, hash + 32, 32);
    memzero(hash, sizeof(hash));
}

void expand_uniform(sr25519_secret_key_key key, sr25519_secret_key_nonce nonce, sr25519_mini_secret_key mini_secret_key) {
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"ExpandSecretKeys", 16);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"mini", 4, mini_secret_key, 32);

    bignum256modm scalar = {0};
    uint8_t scalar_bytes[64] = {0};
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"sk", 2, scalar_bytes, 64);
    expand256_modm(scalar, scalar_bytes, 64);
    contract256_modm(key, scalar);
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"no", 2, nonce, 32);

    memzero(&t, sizeof(t));
}

void hard_derive_mini_secret_key(sr25519_mini_secret_key key_out, sr25519_chain_code chain_code_out, const sr25519_mini_secret_key key_in, const sr25519_chain_code chain_code_in) {
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"SchnorrRistrettoHDKD", 20);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, (uint8_t *)"", 0);
    if (chain_code_in != NULL) merlin_transcript_commit_bytes(&t, (uint8_t *)"chain-code", 10, chain_code_in, 32);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"secret-key", 10, key_in, 32);
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"HDKD-hard", 9, key_out, 32);
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"HDKD-chaincode", 14, chain_code_out, 32);

    memzero(&t, sizeof(t));
}

void derive_scalar_and_chaincode(merlin_transcript *t, bignum256modm *scalar, sr25519_chain_code chain_code_out, const sr25519_public_key public, const sr25519_chain_code chain_code_in) {
    if (chain_code_in != NULL) merlin_transcript_commit_bytes(t, (uint8_t *)"chain-code", 10, chain_code_in, 32);
    merlin_transcript_commit_bytes(t, (uint8_t *)"public-key", 10, public, 32);

    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(t, (uint8_t *)"HDKD-scalar", 11, buf, 64);
    expand256_modm(scalar, buf, 64);

    merlin_transcript_challenge_bytes(t, (uint8_t *)"HDKD-chaincode", 14, chain_code_out, 32);

    memzero(buf, sizeof(buf));
}

void derived_secret_key_simple(sr25519_secret_key_key key_out, sr25519_secret_key_nonce nonce_out, sr25519_chain_code chain_code_out, const sr25519_public_key public, const sr25519_secret_key_key key_in, const sr25519_secret_key_nonce nonce_in, const sr25519_chain_code chain_code_in) {
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"SchnorrRistrettoHDKD", 20);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, (uint8_t *)"", 0);

    bignum256modm scalar = {0};

    derive_scalar_and_chaincode(&t, &scalar, chain_code_out, public, chain_code_in);

    bignum256modm original_scalar = {0};
    bignum256modm final_scalar = {0};
    expand_raw256_modm(original_scalar, key_in);
    add256_modm(final_scalar, original_scalar, scalar);
    contract256_modm(key_out, final_scalar);

    uint8_t witness_data[64] = {0};
    memcpy(witness_data, key_in, 32);
    memcpy(witness_data + 32, nonce_in, 32);

    merlin_rng mrng = {0};
    merlin_rng_init(&mrng, &t);
    merlin_rng_commit_witness_bytes(&mrng, (uint8_t *)"HDKD-nonce", 10, nonce_in, 32);
    merlin_rng_commit_witness_bytes(&mrng, (uint8_t *)"HDKD-nonce", 10, witness_data, 64);

    uint8_t entropy[32] = {0};
    sr25519_randombytes(entropy, 32);
    merlin_rng_finalize(&mrng, entropy);
    merlin_rng_random_bytes(&mrng, nonce_out, 32);

    memzero(scalar, sizeof(scalar));
    memzero(original_scalar, sizeof(original_scalar));
    memzero(final_scalar, sizeof(final_scalar));
    memzero(&mrng, sizeof(mrng));
    memzero(entropy, sizeof(entropy));
    memzero(witness_data, sizeof(witness_data));
    memzero(&t, sizeof(t));
}

void private_key_to_publuc_key(sr25519_public_key public_key, sr25519_secret_key private_key) {
    ge25519 P = {0};
    bignum256modm s = {0};
    expand_raw256_modm(s, private_key);

    ge25519_scalarmult_base_niels(&P, ge25519_niels_base_multiples, s);
    ristretto_encode(public_key, P);

    memzero(&P, sizeof(P));
    memzero(s, sizeof(s));
}

void sr25519_keypair_from_seed(sr25519_keypair keypair, const sr25519_mini_secret_key mini_secret_key) {
    sr25519_secret_key_key secret_key_key = {0};
    sr25519_secret_key_nonce secret_key_nonce = {0};
    expand_ed25519(secret_key_key, secret_key_nonce, mini_secret_key);
    sr25519_public_key public_key = {0};
    private_key_to_publuc_key(public_key, secret_key_key);
    multiply_scalar_bytes_by_cofactor(secret_key_key, 32);

    memcpy(keypair, secret_key_key, 32);
    memcpy(keypair + 32, secret_key_nonce, 32);
    memcpy(keypair + 64, public_key, 32);

    memzero(secret_key_key, sizeof(secret_key_key));
    memzero(secret_key_nonce, sizeof(secret_key_nonce));
    memzero(public_key, sizeof(public_key));
}

void sr25519_uniform_keypair_from_seed(sr25519_keypair keypair, const sr25519_mini_secret_key mini_secret_key) {
    sr25519_secret_key_key secret_key_key = {0};
    sr25519_secret_key_nonce secret_key_nonce = {0};
    expand_ed25519(secret_key_key, secret_key_nonce, mini_secret_key);
    sr25519_public_key public_key = {0};
    private_key_to_publuc_key(public_key, secret_key_key);

    memcpy(keypair, secret_key_key, 32);
    memcpy(keypair + 32, secret_key_nonce, 32);
    memcpy(keypair + 64, public_key, 32);

    memzero(secret_key_key, sizeof(secret_key_key));
    memzero(secret_key_nonce, sizeof(secret_key_nonce));
    memzero(public_key, sizeof(public_key));
}

void sr25519_keypair_ed25519_to_uniform(sr25519_keypair uniform_keypair, const sr25519_keypair ed25519_keypair) {
    sr25519_secret_key_key secret_key_key = {0};
    memcpy(secret_key_key, ed25519_keypair, 32);
    divide_scalar_bytes_by_cofactor(secret_key_key, 32);

    memcpy(uniform_keypair, secret_key_key, 32);
    memcpy(uniform_keypair + 32, ed25519_keypair + 32, 64);

    memzero(secret_key_key, sizeof(secret_key_key));
}

void sr25519_derive_keypair_hard(sr25519_keypair keypair_out, const sr25519_keypair keypair_in, const sr25519_chain_code chain_code_in) {
    sr25519_mini_secret_key key_in = {0};
    memcpy(key_in, keypair_in, 32);
    divide_scalar_bytes_by_cofactor(key_in, 32);

    sr25519_mini_secret_key key_out = {0};
    sr25519_chain_code chain_code_out = {0};

    hard_derive_mini_secret_key(key_out, chain_code_out, key_in, chain_code_in);

    sr25519_keypair_from_seed(keypair_out, key_out);

    memzero(key_in, sizeof(key_in));
    memzero(key_out, sizeof(key_out));
    memzero(chain_code_out, sizeof(chain_code_out));
}

void sr25519_derive_keypair_soft(sr25519_keypair keypair_out, const sr25519_keypair keypair_in, const sr25519_chain_code chain_code_in) {
    sr25519_secret_key_key key_in = {0};
    memcpy(key_in, keypair_in, 32);
    divide_scalar_bytes_by_cofactor(key_in, 32);
    sr25519_secret_key_nonce nonce_in = {0};
    memcpy(nonce_in, keypair_in + 32, 32);
    sr25519_public_key public = {0};
    memcpy(public, keypair_in + 64, 32);

    sr25519_secret_key_key key_out = {0};
    sr25519_secret_key_nonce nonce_out = {0};
    sr25519_public_key public_out = {0};
    sr25519_chain_code chain_code_out = {0};

    derived_secret_key_simple(key_out, nonce_out, chain_code_out, public, key_in, nonce_in, chain_code_in);

    private_key_to_publuc_key(public_out, key_out);
    multiply_scalar_bytes_by_cofactor(key_out, 32);

    memcpy(keypair_out, key_out, 32);
    memcpy(keypair_out + 32, nonce_out, 32);
    memcpy(keypair_out + 64, public_out, 32);

    memzero(key_in, sizeof(key_in));
    memzero(nonce_in, sizeof(nonce_in));
    memzero(public, sizeof(public));
    memzero(key_out, sizeof(key_out));
    memzero(public_out, sizeof(public_out));
    memzero(nonce_out, sizeof(nonce_out));
    memzero(chain_code_out, sizeof(chain_code_out));
}

void sr25519_derive_public_soft(sr25519_public_key public_out, const sr25519_public_key public_in, const sr25519_chain_code chain_code_in) {
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"SchnorrRistrettoHDKD", 20);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, (uint8_t *)"", 0);

    bignum256modm scalar = {0};
    uint8_t chain_code_out[32] = {0};
    derive_scalar_and_chaincode(&t, &scalar, chain_code_out, public_in, chain_code_in);

    ge25519 P1 = {0}, P2 ={0}, P = {0};
    ge25519_scalarmult_base_niels(&P1, ge25519_niels_base_multiples, scalar);
    ristretto_decode(&P2, public_in);
    ge25519_add(&P, &P1, &P2);
    ristretto_encode(public_out, P);

    memzero(scalar, sizeof(scalar));
    memzero(chain_code_out, sizeof(chain_code_out));
    memzero(&t, sizeof(t));
    memzero(&P, sizeof(P));
    memzero(&P1, sizeof(P1));
    memzero(&P2, sizeof(P2));
}

void sr25519_sign(sr25519_signature signature_out, const sr25519_public_key public, const sr25519_secret_key secret, const uint8_t *message, unsigned long message_length) {
    sr25519_secret_key_key secret_key = {0};
    sr25519_secret_key_nonce secret_nonce = {0};
    memcpy(secret_key, secret, 32);
    memcpy(secret_nonce, secret + 32, 32);
    divide_scalar_bytes_by_cofactor(secret_key, 32);

    merlin_transcript t = {0};
    merlin_transcript_init(&t, (uint8_t *)"SigningContext", 14);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"", 0, (uint8_t *)"substrate", 9);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, message, message_length);

    merlin_transcript_commit_bytes(&t, (uint8_t *)"proto-name", 10, (uint8_t *)"Schnorr-sig", 11);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:pk", 7, public, 32);

    bignum256modm r = {0};
    uint8_t scalar_bytes[64] = {0};
    merlin_rng mrng = {0};
    merlin_rng_init(&mrng, &t);
    merlin_rng_commit_witness_bytes(&mrng, (uint8_t *)"signing", 7, secret_nonce, 32);
    uint8_t entropy[32] = {0};
    sr25519_randombytes(entropy, 32);
    merlin_rng_finalize(&mrng, entropy);
    merlin_rng_random_bytes(&mrng, scalar_bytes, 32);
    expand256_modm(r, scalar_bytes, 64);

    ge25519 R = {0};
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
    uint8_t R_compressed[32] = {0};
    ristretto_encode(R_compressed, R);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:R", 6, R_compressed, 32);

    bignum256modm k = {0};
    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"sign:c", 6, buf, 64);
    expand256_modm(k, buf, 64);

    bignum256modm secret_key_scalar = {0};
    expand_raw256_modm(secret_key_scalar, secret_key);

    bignum256modm k_secret_key_scalar = {0};
    mul256_modm(k_secret_key_scalar, k, secret_key_scalar);

    bignum256modm s = {0};
    add256_modm(s, k_secret_key_scalar, r);

    uint8_t s_bytes[32] = {0};
    contract256_modm(s_bytes, s);

    memcpy(signature_out, R_compressed, 32);
    memcpy(signature_out + 32, s_bytes, 32);
    signature_out[63] |= 128;

    memzero(&t, sizeof(t));
    memzero(secret_key, sizeof(secret_key));
    memzero(secret_nonce, sizeof(secret_nonce));
    memzero(r, sizeof(r));
    memzero(scalar_bytes, sizeof(scalar_bytes));
    memzero(&mrng, sizeof(mrng));
    memzero(entropy, sizeof(entropy));
    memzero(&R, sizeof(R));
    memzero(R_compressed, sizeof(R_compressed));
    memzero(k, sizeof(k));
    memzero(buf, sizeof(buf));
    memzero(secret_key_scalar, sizeof(secret_key_scalar));
    memzero(k_secret_key_scalar, sizeof(k_secret_key_scalar));
    memzero(s, sizeof(s));
    memzero(s_bytes, sizeof(s_bytes));
}

bool sr25519_verify(const sr25519_signature signature, const uint8_t *message, unsigned long message_length, const sr25519_public_key public) {
    uint8_t signature_s[32] = {0};
    memcpy(signature_s, signature + 32, 32);

    if ((signature_s[31] & 128) == 0) {
        memzero(signature_s, sizeof(signature_s));

        return false;
    }

    signature_s[31] &= 127;
    if ((signature_s[31] & 240) == 0) {
        signature_s[31] &= 0b01111111;
    }

    if ((signature_s[31] >> 7) != 0) {
        memzero(signature_s, sizeof(signature_s));

        return false;
    }

    signature_s[31] &= 0b01111111;

    uint8_t signature_R[32] = {0};
    memcpy(signature_R, signature, 32);

    merlin_transcript t = {0};
    merlin_transcript_init(&t, (uint8_t *)"SigningContext", 14);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"", 0, (uint8_t *)"substrate", 9);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, message, message_length);

    merlin_transcript_commit_bytes(&t, (uint8_t *)"proto-name", 10, (uint8_t *)"Schnorr-sig", 11);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:pk", 7, public, 32);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:R", 6, signature_R, 32);

    bignum256modm k = {0}, s = {0};
    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"sign:c", 6, buf, 64);
    expand256_modm(k, buf, 64);
    expand_raw256_modm(s, signature_s);

    int is_canonical = is_reduced256_modm(s);

    if (!is_canonical) {
        memzero(&t, sizeof(t));
        memzero(signature_R, sizeof(signature_R));
        memzero(signature_s, sizeof(signature_s));
        memzero(k, sizeof(k));
        memzero(s, sizeof(s));
        memzero(buf, sizeof(buf));

        return false;
    }

    ge25519 A = {0}, R = {0};
    ristretto_decode(&A, public);
    curve25519_neg(A.x, A.x);
    curve25519_neg(A.t, A.t);
    ge25519_double_scalarmult_vartime(&R, &A, k, s);

    uint8_t R_compressed[32] = {0};
    ristretto_encode(R_compressed, R);
    uint8_t valid = uint8_32_ct_eq(R_compressed, signature_R);

    memzero(&t, sizeof(t));
    memzero(signature_R, sizeof(signature_R));
    memzero(signature_s, sizeof(signature_s));
    memzero(k, sizeof(k));
    memzero(s, sizeof(s));
    memzero(buf, sizeof(buf));
    memzero(&A, sizeof(A));
    memzero(&R, sizeof(R));
    memzero(R_compressed, sizeof(R_compressed));

    return valid;
}

void from_le_bytes(uint8_t *out, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[len - 1 - i] = in[i];
    }
}

VrfResult sr25519_vrf_sign_if_less(sr25519_vrf_out_and_proof out_and_proof, const sr25519_keypair keypair, const uint8_t *message, unsigned long message_length, const sr25519_vrf_threshold threshold) {
    merlin_transcript t = {0};
    merlin_transcript_init(&t, (uint8_t *)"SigningContext", 14);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"", 0, (uint8_t *)"substrate", 9);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, message, message_length);

    sr25519_vrf_io io = {0};
    sr25519_vrf_proof proof = {0};
    sr25519_vrf_proof_batchable proof_batchable = {0};
    Sr25519SignatureResult sign_result = vrf_sign(io, proof, proof_batchable, keypair, &t);
    if (sign_result != Ok) {
        VrfResult vrf_result = {0};
        vrf_result.result = sign_result;
        vrf_result.is_less = false;

        memzero(&t, sizeof(merlin_transcript));
        memzero(io, 64);
        memzero(proof, 64);
        memzero(proof_batchable, 96);

        return vrf_result;
    }

    sr25519_vrf_raw_output raw_output = {0};
    io_make_bytes(raw_output, io, (uint8_t *)"substrate-babe-vrf", 18);

    uint8_t raw_output_le[16] = {0};
    from_le_bytes(raw_output_le, raw_output, 16);
    uint8_t threshold_le[16] = {0};
    from_le_bytes(threshold_le, threshold, 16);

    bool check = memcmp(raw_output_le, threshold_le, 16) < 0;

    memcpy(out_and_proof, io + 32, 32);
    memcpy(out_and_proof + 32, proof, 64);

    if (check) {
        VrfResult vrf_result = {0};
        vrf_result.result = Ok;
        vrf_result.is_less = true;

        memzero(&t, sizeof(merlin_transcript));
        memzero(io, 64);
        memzero(proof, 64);
        memzero(proof_batchable, 96);
        memzero(raw_output, 16);
        memzero(raw_output_le, 16);
        memzero(threshold_le, 16);

        return vrf_result;
    } else {
        VrfResult vrf_result = {0};
        vrf_result.result = Ok;
        vrf_result.is_less = false;

        memzero(&t, sizeof(merlin_transcript));
        memzero(io, 64);
        memzero(proof, 64);
        memzero(proof_batchable, 96);
        memzero(raw_output, 16);
        memzero(raw_output_le, 16);
        memzero(threshold_le, 16);

        return vrf_result;
    }
}

VrfResult sr25519_vrf_verify(const sr25519_public_key public, const uint8_t *message, unsigned long message_length, const sr25519_vrf_output output, const sr25519_vrf_proof proof, const sr25519_vrf_threshold threshold) {
    merlin_transcript t1 = {0};
    merlin_transcript_init(&t1, (uint8_t *)"SigningContext", 14);
    merlin_transcript_commit_bytes(&t1, (uint8_t *)"", 0, (uint8_t *)"substrate", 9);
    merlin_transcript_commit_bytes(&t1, (uint8_t *)"sign-bytes", 10, message, message_length);

    sr25519_vrf_io inout = {0};
    sr25519_vrf_proof_batchable proof_batchable = {0};
    Sr25519SignatureResult verify_result = vrf_verify(inout, proof_batchable, public, &t1, output, proof);

    if (verify_result != Ok) {
        VrfResult vrf_result = {0};
        vrf_result.result = verify_result;
        vrf_result.is_less = false;

        memzero(&t1, sizeof(merlin_transcript));
        memzero(inout, 64);
        memzero(proof_batchable, 96);

        return vrf_result;
    }

    sr25519_vrf_raw_output raw_output = {0};
    io_make_bytes(raw_output, inout, (uint8_t *)"substrate-babe-vrf", 18);

    uint8_t raw_output_le[16] = {0};
    from_le_bytes(raw_output_le, raw_output, 16);
    uint8_t threshold_le[16] = {0};
    from_le_bytes(threshold_le, threshold, 16);

    bool check = memcmp(raw_output_le, threshold_le, 16) < 0;

    sr25519_vrf_output verify_output = {0};
    memcpy(verify_output, inout + 32, 32);

    merlin_transcript t2 = {0};
    merlin_transcript_init(&t2, (uint8_t *)"SigningContext", 14);
    merlin_transcript_commit_bytes(&t2, (uint8_t *)"", 0, (uint8_t *)"substrate", 9);
    merlin_transcript_commit_bytes(&t2, (uint8_t *)"sign-bytes", 10, message, message_length);
    sr25519_vrf_proof decomp_proof = {0};
    Sr25519SignatureResult shorten_result = shorten_vrf(decomp_proof, proof_batchable, public, &t2, verify_output);

    if (shorten_result != Ok) {
        VrfResult vrf_result = {0};
        vrf_result.result = shorten_result;
        vrf_result.is_less = false;

        memzero(&t1, sizeof(merlin_transcript));
        memzero(&t2, sizeof(merlin_transcript));
        memzero(inout, 64);
        memzero(proof_batchable, 96);
        memzero(raw_output, 16);
        memzero(raw_output_le, 16);
        memzero(threshold_le, 16);
        memzero(verify_output, 32);
        memzero(decomp_proof, 64);

        return vrf_result;
    }

    if (memcmp(output, verify_output, 32) == 0 && memcmp(proof, decomp_proof, 32) == 0) {
        VrfResult vrf_result = {0};
        vrf_result.result = Ok;
        vrf_result.is_less = check;

        memzero(&t1, sizeof(merlin_transcript));
        memzero(&t2, sizeof(merlin_transcript));
        memzero(inout, 64);
        memzero(proof_batchable, 96);
        memzero(raw_output, 16);
        memzero(raw_output_le, 16);
        memzero(threshold_le, 16);
        memzero(verify_output, 32);
        memzero(decomp_proof, 64);

        return vrf_result;
    } else {
        VrfResult vrf_result = {0};
        vrf_result.result = EquationFalse;
        vrf_result.is_less = false;

        memzero(&t1, sizeof(merlin_transcript));
        memzero(&t2, sizeof(merlin_transcript));
        memzero(inout, 64);
        memzero(proof_batchable, 96);
        memzero(raw_output, 16);
        memzero(raw_output_le, 16);
        memzero(threshold_le, 16);
        memzero(verify_output, 32);
        memzero(decomp_proof, 64);

        return vrf_result;
    }
}
