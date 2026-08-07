/*
 * util.h - small helpers: byte order, hex conversion, time
 */
#ifndef MINER_UTIL_H
#define MINER_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static inline uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }

static inline uint32_t le32_load(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline void le32_store(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void le64_store(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static inline uint32_t be32_load(const uint8_t *p)
{
    return (uint32_t)p[3] | (uint32_t)p[2] << 8 |
           (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

/* hex string -> bytes. hex must contain exactly 2*out_len valid hex chars. */
bool hex2bin(uint8_t *dst, const char *hex, size_t out_len);

/* bytes -> lowercase hex. dst must have room for 2*len + 1 chars. */
void bin2hex(char *dst, const uint8_t *src, size_t len);

/* monotonic milliseconds */
int64_t now_ms(void);

/* base64-encode `len` bytes into out (out must fit 4*((len+2)/3)+1 chars) */
void b64_encode(char *out, const uint8_t *in, size_t len);

/* bitcoin "compact size" varint; returns bytes written (1, 3, 5 or 9) */
size_t put_compact_size(uint8_t *out, uint64_t v);

/* decode 64-hex display-order hash into 32-byte internal order (reversed) */
bool hex2bin_reversed(uint8_t out[32], const char *hex);

#endif /* MINER_UTIL_H */
