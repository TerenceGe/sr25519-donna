/*
    a custom hash must have a 512bit digest and implement:

    struct sr25519_hash_context;

    void sr25519_hash_init(sr25519_hash_context *ctx);
    void sr25519_hash_update(sr25519_hash_context *ctx, const uint8_t *in, size_t inlen);
    void sr25519_hash_final(sr25519_hash_context *ctx, uint8_t *hash);
    void sr25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen);
*/
