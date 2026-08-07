#include "sha256.h"

#include <string.h>

const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

const uint32_t sha256_iv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}
static inline uint32_t big_s0(uint32_t x)
{
    return ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22);
}
static inline uint32_t big_s1(uint32_t x)
{
    return ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25);
}
static inline uint32_t sm_s0(uint32_t x)
{
    return ROR32(x, 7) ^ ROR32(x, 18) ^ (x >> 3);
}
static inline uint32_t sm_s1(uint32_t x)
{
    return ROR32(x, 17) ^ ROR32(x, 19) ^ (x >> 10);
}

void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[4 * i] << 24) |
               ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) |
               (uint32_t)block[4 * i + 3];
    }
    for (int i = 16; i < 64; i++)
        w[i] = sm_s1(w[i - 2]) + w[i - 7] + sm_s0(w[i - 15]) + w[i - 16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + big_s1(e) + ch(e, f, g) + sha256_k[i] + w[i];
        uint32_t t2 = big_s0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(sha256_ctx *ctx)
{
    memcpy(ctx->state, sha256_iv, sizeof(ctx->state));
    ctx->nbytes = 0;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t have = (size_t)(ctx->nbytes & 63);
    ctx->nbytes += len;

    if (have) {
        size_t need = 64 - have;
        if (len < need) {
            memcpy(ctx->buf + have, p, len);
            return;
        }
        memcpy(ctx->buf + have, p, need);
        sha256_transform(ctx->state, ctx->buf);
        p += need;
        len -= need;
    }
    while (len >= 64) {
        sha256_transform(ctx->state, p);
        p += 64;
        len -= 64;
    }
    if (len)
        memcpy(ctx->buf, p, len);
}

void sha256_final(sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bits = ctx->nbytes * 8;
    size_t have = (size_t)(ctx->nbytes & 63);

    ctx->buf[have++] = 0x80;
    if (have > 56) {
        memset(ctx->buf + have, 0, 64 - have);
        sha256_transform(ctx->state, ctx->buf);
        have = 0;
    }
    memset(ctx->buf + have, 0, 56 - have);
    for (int i = 0; i < 8; i++)
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_transform(ctx->state, ctx->buf);

    for (int i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(ctx->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256_hash(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

void sha256d_hash(const void *data, size_t len, uint8_t out[32])
{
    uint8_t tmp[32];
    sha256_hash(data, len, tmp);
    sha256_hash(tmp, 32, out);
}
