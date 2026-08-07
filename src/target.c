#include "target.h"
#include "util.h"

#include <string.h>

void bits_to_target(uint32_t bits, uint32_t target[8])
{
    uint8_t t[32];
    memset(t, 0, sizeof(t));

    int exponent = (int)(bits >> 24);
    uint32_t mantissa = bits & 0x7fffff;
    if (bits & 0x800000)
        mantissa >>= 8; /* sign bit - never used by real chains */

    /* target = mantissa * 256^(exponent - 3); the mantissa is big-endian,
     * so its least significant byte sits at byte index (exponent - 3)
     * counting from the least significant end, with the higher mantissa
     * bytes above it */
    int lsb = exponent - 3;
    if (lsb >= 0 && lsb < 32)
        t[lsb] = (uint8_t)(mantissa & 0xff);
    if (lsb + 1 >= 0 && lsb + 1 < 32)
        t[lsb + 1] = (uint8_t)((mantissa >> 8) & 0xff);
    if (lsb + 2 >= 0 && lsb + 2 < 32)
        t[lsb + 2] = (uint8_t)((mantissa >> 16) & 0xff);

    for (int i = 0; i < 8; i++)
        target[i] = (uint32_t)t[4 * i] | (uint32_t)t[4 * i + 1] << 8 |
                    (uint32_t)t[4 * i + 2] << 16 | (uint32_t)t[4 * i + 3] << 24;
}

void diff_to_target(uint32_t target[8], double diff)
{
    uint64_t m;
    int k;

    /* classic cpuminer algorithm: place 0xFFFF0000 / diff at the
     * right 32-bit word slot */
    for (k = 6; k > 0 && diff > 1.0; k--)
        diff /= 4294967296.0;
    m = 4294901760.0 / diff; /* 0xFFFF0000 << 0 */

    if (m == 0 && k == 6) {
        memset(target, 0xff, 32);
    } else {
        memset(target, 0, 32);
        target[k] = (uint32_t)m;
        target[k + 1] = (uint32_t)(m >> 32);
    }
}

int u256_cmp(const uint32_t a[8], const uint32_t b[8])
{
    for (int i = 7; i >= 0; i--) {
        if (a[i] != b[i])
            return a[i] > b[i] ? 1 : -1;
    }
    return 0;
}

/*
 * digest_words[0..7] are the SHA-256 state words of the final double-hash,
 * i.e. big-endian words of the 32-byte digest (digest_words[0] covers digest
 * bytes 0..3). Bitcoin compares the hash as a little-endian 256-bit number,
 * whose least-significant word is the byte-swapped first digest word. So hash
 * LE-word i = bswap32(digest_words[i]), compared against target[] (LE words,
 * target[0] least significant) from the most significant word down.
 */
bool digest_below_target(const uint32_t digest_words[8], const uint32_t target[8])
{
    for (int i = 7; i >= 0; i--) {
        uint32_t hw = bswap32(digest_words[i]); /* hash LE word i */
        if (hw != target[i])
            return hw < target[i];
    }
    return true; /* equal satisfies "below or equal" */
}

void target_to_hex(const uint32_t target[8], char out[65])
{
    uint8_t bytes[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w = target[7 - i]; /* most significant word first */
        bytes[4 * i]     = (uint8_t)(w >> 24);
        bytes[4 * i + 1] = (uint8_t)(w >> 16);
        bytes[4 * i + 2] = (uint8_t)(w >> 8);
        bytes[4 * i + 3] = (uint8_t)(w);
    }
    bin2hex(out, bytes, 32);
}
