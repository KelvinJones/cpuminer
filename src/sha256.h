/*
 * sha256.h - portable SHA-256 (FIPS 180-4), reference implementation
 */
#ifndef MINER_SHA256_H
#define MINER_SHA256_H

#include <stddef.h>
#include <stdint.h>

extern const uint32_t sha256_k[64];
extern const uint32_t sha256_iv[8];

typedef struct {
    uint32_t state[8];
    uint64_t nbytes;
    uint8_t  buf[64];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t out[32]);

void sha256_hash(const void *data, size_t len, uint8_t out[32]);
/* double SHA-256: sha256(sha256(data)) - the Bitcoin proof-of-work hash */
void sha256d_hash(const void *data, size_t len, uint8_t out[32]);

/* one SHA-256 compression of a single 64-byte block into state */
void sha256_transform(uint32_t state[8], const uint8_t block[64]);

#endif /* MINER_SHA256_H */
