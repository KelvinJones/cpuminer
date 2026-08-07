/*
 * dbg_ni.c - diagnostic: compare portable vs SHA-NI compression block by
 * block. Compiled by pulling the .c files in directly so the static
 * transform_ni is reachable.
 *
 * build: cc -O2 -Isrc tests/dbg_ni.c build/miner.o build/util.o -o dbg_ni -lpthread
 */
#include <stdio.h>
#include <string.h>

#include "miner.h"
#include "sha256.h"
#include "util.h"

#include "../src/sha256.c"
#include "../src/sha256d_ni.c"

static void show(const char *tag, const uint32_t s[8])
{
    printf("%s: ", tag);
    for (int i = 0; i < 8; i++)
        printf("%08x ", s[i]);
    printf("\n");
}

int main(void)
{
    if (!sha_ni_supported()) {
        printf("no SHA-NI support here\n");
        return 2;
    }

    /* 1) single-block compression, patterned block */
    uint8_t blk[64];
    for (int i = 0; i < 64; i++)
        blk[i] = (uint8_t)(i * 7 + 3);

    uint32_t a[8], b[8];
    memcpy(a, sha256_iv, sizeof(a));
    memcpy(b, sha256_iv, sizeof(b));
    sha256_transform(a, blk);
    transform_ni(b, blk);
    show("portable ", a);
    show("ni         ", b);
    printf("single block: %s\n\n", memcmp(a, b, 32) == 0 ? "MATCH" : "DIFFER");

    /* 1b) same block but words fed directly (no byte-swap load) */
    uint32_t words[16];
    for (int i = 0; i < 16; i++)
        words[i] = be32_load(blk + 4 * i);
    uint32_t c[8];
    memcpy(c, sha256_iv, sizeof(c));
    __m128i m0 = _mm_set_epi32((int)words[3], (int)words[2], (int)words[1], (int)words[0]);
    __m128i m1 = _mm_set_epi32((int)words[7], (int)words[6], (int)words[5], (int)words[4]);
    __m128i m2 = _mm_set_epi32((int)words[11], (int)words[10], (int)words[9], (int)words[8]);
    __m128i m3 = _mm_set_epi32((int)words[15], (int)words[14], (int)words[13], (int)words[12]);
    compress_ni_words(c, m0, m1, m2, m3);
    show("ni-direct  ", c);
    printf("direct words vs portable: %s\n\n",
           memcmp(a, c, 32) == 0 ? "MATCH" : "DIFFER");

    /* 1c) inspect load_be output directly */
    uint8_t pat[16];
    for (int i = 0; i < 16; i++)
        pat[i] = (uint8_t)i;
    __m128i maskv = _mm_load_si128((const __m128i *)MASK_BYTES);
    __m128i sw = load_be(pat, maskv);
    uint32_t sw_words[4];
    _mm_storeu_si128((__m128i *)sw_words, sw);
    printf("load_be(00..0f): %08x %08x %08x %08x (expect 00010203 04050607 08090a0b 0c0d0e0f)\n\n",
           sw_words[0], sw_words[1], sw_words[2], sw_words[3]);

    /* 2) full sha256d of an 80-byte header, zero + patterned */
    for (int variant = 0; variant < 2; variant++) {
        uint8_t h[80];
        if (variant == 0)
            memset(h, 0, sizeof(h));
        else
            for (int i = 0; i < 80; i++)
                h[i] = (uint8_t)(i * 13 + 5);

        uint8_t d_ref[32], d_ni[32];
        sha256d_hash(h, 80, d_ref);
        sha256d_80_ni(h, d_ni);
        char h1[65], h2[65];
        bin2hex(h1, d_ref, 32);
        bin2hex(h2, d_ni, 32);
        printf("variant %d portable: %s\n", variant, h1);
        printf("variant %d ni:       %s\n", variant, h2);
        printf("variant %d: %s\n\n", variant,
               memcmp(d_ref, d_ni, 32) == 0 ? "MATCH" : "DIFFER");
    }
    return 0;
}
