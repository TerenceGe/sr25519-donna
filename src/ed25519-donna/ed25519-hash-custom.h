/*
	a custom hash must have a 512bit digest and implement:

	struct ed25519_hash_context;

	void ed25519_hash_init(ed25519_hash_context *ctx);
	void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen);
	void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash);
	void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
*/

#include "sr25519-hash.h"

typedef sr25519_hash_context ed25519_hash_context;

static void
ed25519_hash_init(ed25519_hash_context *ctx) {
    sr25519_hash_init(ctx);
}

static void
ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
    sr25519_hash_update(ctx, in, inlen);
}

static void
ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
    sr25519_hash_final(ctx, hash);
}

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
    sr25519_hash(hash, in, inlen);
}
