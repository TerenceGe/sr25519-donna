#ifndef __SR25519_H__
#define __SR25519_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t sr25519_mini_secret_key[32];
typedef uint8_t sr25519_secret_key[64];
typedef uint8_t sr25519_secret_key_key[32];
typedef uint8_t sr25519_secret_key_nonce[32];
typedef uint8_t sr25519_chain_code[32];
typedef uint8_t sr25519_public_key[32];
typedef uint8_t sr25519_keypair[96];
typedef uint8_t sr25519_signature[64];
typedef uint8_t sr25519_vrf_output[32];
typedef uint8_t sr25519_vrf_io[64];
typedef uint8_t sr25519_vrf_proof[64];
typedef uint8_t sr25519_vrf_out_and_proof[96];
typedef uint8_t sr25519_vrf_proof_batchable[96];
typedef uint8_t sr25519_vrf_raw_output[16];
typedef uint8_t sr25519_vrf_threshold[16];

typedef enum Sr25519SignatureResult {
  Ok,
  EquationFalse,
  PointDecompressionError,
  ScalarFormatError,
  BytesLengthError,
  NotMarkedSchnorrkel,
  MuSigAbsent,
  MuSigInconsistent,
} Sr25519SignatureResult;

typedef enum sr25519_expansion_mode {
  Ed25519Expansion,
  UniformExpansion
} sr25519_expansion_mode;

typedef struct VrfResult {
  Sr25519SignatureResult result;
  bool is_less;
} VrfResult;

void sr25519_keypair_from_seed(sr25519_keypair keypair, const sr25519_mini_secret_key seed);
void sr25519_uniform_keypair_from_seed(sr25519_keypair keypair, const sr25519_mini_secret_key seed);
void sr25519_keypair_ed25519_to_uniform(sr25519_keypair uniform_keypair, const sr25519_keypair ed25519_keypair);
void sr25519_sign(sr25519_signature signature, const sr25519_public_key public, const sr25519_secret_key secret, const uint8_t *message, unsigned long message_length);
bool sr25519_verify(const sr25519_signature signature, const uint8_t *message, unsigned long message_length, const sr25519_public_key public);
void sr25519_derive_keypair_soft(sr25519_keypair derived, const sr25519_keypair keypair, const sr25519_chain_code chain_code);
void sr25519_derive_public_soft(sr25519_public_key derived_public, const sr25519_public_key public, const sr25519_chain_code chain_code);
void sr25519_derive_keypair_hard(sr25519_keypair derived, const sr25519_keypair keypair, const sr25519_chain_code chain_code);
VrfResult sr25519_vrf_sign_if_less(sr25519_vrf_out_and_proof out_and_proof, const sr25519_keypair keypair, const uint8_t *message, unsigned long message_length, const uint8_t *limit);
VrfResult sr25519_vrf_verify(const sr25519_public_key public, const uint8_t *message, unsigned long message_length, const uint8_t *output, const uint8_t *proof, const uint8_t *threshold);

#endif
