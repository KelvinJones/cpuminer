/*
 * sha256d_ni.c - SHA-256 accelerated with the x86 SHA extensions
 * (SHA-NI: sha256rnds2 / sha256msg1 / sha256msg2).
 *
 * The round sequence, Shuffle/Unshuffle state transforms and K-pair
 * constants follow the public-domain SHA-Intrinsics code by Jeffrey
 * Walton (noloader/SHA-Intrinsics), as also used by Bitcoin Core in
 * src/crypto/sha256_x86_shani.cpp (MIT).
 *
 * On top of the generic transform we build the sha256d-of-80-byte-header
 * hot loop used for mining: the midstate of the first header block is
 * precomputed once per work item, and only the nonce-dependent tail and
 * the outer hash run per candidate.
 */
#include "miner.h"
#include "target.h"
#include "util.h"

#include <string.h>

#if defined(__x86_64__) && defined(__GNUC__)

#include <immintrin.h>

#define NI_FN __attribute__((target("sha,ssse3,sse4.1")))
#define NI_STACK_ALIGN __attribute__((aligned(16)))

/* byte-swap mask: little-endian memory -> big-endian SHA words */
__attribute__((aligned(16))) static const uint8_t MASK_BYTES[16] = {
    0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,
    0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c,
};

static inline __m128i load_be(const void *p, __m128i mask) NI_FN;
static inline __m128i load_be(const void *p, __m128i mask)
{
    return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)p), mask);
}

/* state entry: (a,b,c,d),(e,f,g,h) words -> s0 = [f,e,b,a], s1 = [h,g,d,c] */
static inline void shuf_state(__m128i *s0, __m128i *s1) NI_FN;
static inline void shuf_state(__m128i *s0, __m128i *s1)
{
    __m128i t1 = _mm_shuffle_epi32(*s0, 0xB1);
    __m128i t2 = _mm_shuffle_epi32(*s1, 0x1B);
    *s0 = _mm_alignr_epi8(t1, t2, 0x08);
    *s1 = _mm_blend_epi16(t2, t1, 0xF0);
}

/* state exit: exact inverse of shuf_state */
static inline void unshuf_state(__m128i *s0, __m128i *s1) NI_FN;
static inline void unshuf_state(__m128i *s0, __m128i *s1)
{
    __m128i t1 = _mm_shuffle_epi32(*s0, 0x1B);
    __m128i t2 = _mm_shuffle_epi32(*s1, 0xB1);
    *s0 = _mm_blend_epi16(t1, t2, 0xF0);
    *s1 = _mm_alignr_epi8(t2, t1, 0x08);
}

/* 4 rounds consuming one message vector; k0/k1 hold the K-pairs:
 * lane0 = K[4i], lane1 = K[4i+1], lane2 = K[4i+2], lane3 = K[4i+3] */
static inline void quad_round(__m128i *s0, __m128i *s1, __m128i m,
                              uint64_t k1, uint64_t k0) NI_FN;
static inline void quad_round(__m128i *s0, __m128i *s1, __m128i m,
                              uint64_t k1, uint64_t k0)
{
    __m128i msg = _mm_add_epi32(m, _mm_set_epi64x((long long)k1, (long long)k0));
    *s1 = _mm_sha256rnds2_epu32(*s1, *s0, msg);
    *s0 = _mm_sha256rnds2_epu32(*s0, *s1, _mm_shuffle_epi32(msg, 0x0E));
}

/* message schedule steps */
static inline void shift_msg_a(__m128i *m0, __m128i m1) NI_FN;
static inline void shift_msg_a(__m128i *m0, __m128i m1)
{
    *m0 = _mm_sha256msg1_epu32(*m0, m1);
}

static inline void shift_msg_c(__m128i m0, __m128i m1, __m128i *m2) NI_FN;
static inline void shift_msg_c(__m128i m0, __m128i m1, __m128i *m2)
{
    *m2 = _mm_sha256msg2_epu32(_mm_add_epi32(*m2, _mm_alignr_epi8(m1, m0, 4)), m1);
}

static inline void shift_msg_b(__m128i *m0, __m128i m1, __m128i *m2) NI_FN;
static inline void shift_msg_b(__m128i *m0, __m128i m1, __m128i *m2)
{
    shift_msg_c(*m0, m1, m2);
    shift_msg_a(m0, m1);
}

/* all 64 rounds over message vectors m0..m3 (big-endian word lanes) */
static inline void rounds64(__m128i *s0, __m128i *s1,
                            __m128i m0, __m128i m1,
                            __m128i m2, __m128i m3) NI_FN;
static inline void rounds64(__m128i *s0, __m128i *s1,
                            __m128i m0, __m128i m1,
                            __m128i m2, __m128i m3)
{
    quad_round(s0, s1, m0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
    quad_round(s0, s1, m1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
    shift_msg_a(&m0, m1);
    quad_round(s0, s1, m2, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
    shift_msg_a(&m1, m2);
    quad_round(s0, s1, m3, 0xc19bf1749bdc06a7ull, 0x80deb1fe72be5d74ull);
    shift_msg_b(&m2, m3, &m0);

    quad_round(s0, s1, m0, 0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull);
    shift_msg_b(&m3, m0, &m1);
    quad_round(s0, s1, m1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
    shift_msg_b(&m0, m1, &m2);
    quad_round(s0, s1, m2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
    shift_msg_b(&m1, m2, &m3);
    quad_round(s0, s1, m3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
    shift_msg_b(&m2, m3, &m0);

    quad_round(s0, s1, m0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
    shift_msg_b(&m3, m0, &m1);
    quad_round(s0, s1, m1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
    shift_msg_b(&m0, m1, &m2);
    quad_round(s0, s1, m2, 0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
    shift_msg_b(&m1, m2, &m3);
    quad_round(s0, s1, m3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
    shift_msg_b(&m2, m3, &m0);

    quad_round(s0, s1, m0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
    shift_msg_b(&m3, m0, &m1);
    quad_round(s0, s1, m1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
    shift_msg_c(m0, m1, &m2);
    quad_round(s0, s1, m2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
    shift_msg_c(m1, m2, &m3);
    quad_round(s0, s1, m3, 0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull);
}

/* SHA-256 compression from state[] over four ready-made word vectors */
static void compress_ni_words(uint32_t state[8], __m128i m0, __m128i m1,
                              __m128i m2, __m128i m3) NI_FN;
static void compress_ni_words(uint32_t state[8], __m128i m0, __m128i m1,
                              __m128i m2, __m128i m3)
{
    __m128i s0 = _mm_loadu_si128((const __m128i *)state);
    __m128i s1 = _mm_loadu_si128((const __m128i *)(state + 4));

    shuf_state(&s0, &s1);
    const __m128i so0 = s0, so1 = s1; /* saved in shuffled space */
    rounds64(&s0, &s1, m0, m1, m2, m3);

    s0 = _mm_add_epi32(s0, so0);
    s1 = _mm_add_epi32(s1, so1);
    unshuf_state(&s0, &s1);
    _mm_storeu_si128((__m128i *)state, s0);
    _mm_storeu_si128((__m128i *)(state + 4), s1);
}

/* SHA-256 compression from state[] over one 64-byte block */
static void transform_ni(uint32_t state[8], const uint8_t block[64]) NI_FN;
static void transform_ni(uint32_t state[8], const uint8_t block[64])
{
    __m128i mask = _mm_load_si128((const __m128i *)MASK_BYTES);
    compress_ni_words(state,
                      load_be(block, mask), load_be(block + 16, mask),
                      load_be(block + 32, mask), load_be(block + 48, mask));
}

bool sha_ni_supported(void)
{
    return __builtin_cpu_supports("sha");
}

/* full double-SHA256 of an 80-byte header (verification path) */
void sha256d_80_ni(const uint8_t header[80], uint8_t out[32])
{
    uint32_t st[8];
    uint8_t blk[64];

    /* inner hash: block 1 = header bytes 0..63, block 2 = tail + padding */
    memcpy(st, sha256_iv, sizeof(st));
    transform_ni(st, header);

    memset(blk, 0, sizeof(blk));
    memcpy(blk, header + 64, 16);
    blk[16] = 0x80;
    blk[62] = 0x02; /* bit length 640 = 0x280, big-endian */
    blk[63] = 0x80;
    transform_ni(st, blk);

    /* outer hash: 32-byte digest + padding (256 bits) */
    for (int i = 0; i < 8; i++) {
        blk[4 * i]     = (uint8_t)(st[i] >> 24);
        blk[4 * i + 1] = (uint8_t)(st[i] >> 16);
        blk[4 * i + 2] = (uint8_t)(st[i] >> 8);
        blk[4 * i + 3] = (uint8_t)(st[i]);
    }
    memset(blk + 32, 0, 32);
    blk[32] = 0x80;
    blk[62] = 0x01; /* bit length 256 = 0x100, big-endian */

    uint32_t fin[8];
    memcpy(fin, sha256_iv, sizeof(fin));
    transform_ni(fin, blk);

    for (int i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(fin[i] >> 24);
        out[4 * i + 1] = (uint8_t)(fin[i] >> 16);
        out[4 * i + 2] = (uint8_t)(fin[i] >> 8);
        out[4 * i + 3] = (uint8_t)(fin[i]);
    }
}

/*
 * The mining hot loop. Per work item we hoist the shuffled midstate
 * (first 64 header bytes are fixed) and the shuffled IV for the outer
 * hash. Per nonce only two compressions run: the header tail block and
 * the outer hash.
 */
bool scanhash_ni(const struct work *w, uint32_t start,
                 uint32_t count, uint32_t *nonce_out) NI_FN;
bool scanhash_ni(const struct work *w, uint32_t start,
                 uint32_t count, uint32_t *nonce_out)
{
    if (!sha_ni_supported())
        return scanhash_portable(w, start, count, nonce_out);

    /* hoisted state: midstate after header bytes 0..63 */
    __m128i ms0 = _mm_loadu_si128((const __m128i *)w->midstate);
    __m128i ms1 = _mm_loadu_si128((const __m128i *)(w->midstate + 4));
    shuf_state(&ms0, &ms1);

    /* hoisted state: IV for the outer hash */
    __m128i iv0 = _mm_loadu_si128((const __m128i *)sha256_iv);
    __m128i iv1 = _mm_loadu_si128((const __m128i *)(sha256_iv + 4));
    shuf_state(&iv0, &iv1);

    /* fixed message vectors of the tail block */
    const __m128i m1c = _mm_set_epi32(0, 0, 0, (int)0x80000000);
    const __m128i m2c = _mm_setzero_si128();
    const __m128i m3c = _mm_set_epi32(640, 0, 0, 0);

    /* fixed message vectors of the outer hash tail */
    const __m128i o2c = _mm_set_epi32(0, 0, 0, (int)0x80000000);
    const __m128i o3c = _mm_set_epi32(256, 0, 0, 0);

    const uint32_t t0 = w->tail_words[0];
    const uint32_t t1 = w->tail_words[1];
    const uint32_t t2 = w->tail_words[2];

    uint32_t st[8] NI_STACK_ALIGN;
    uint32_t fin[8] NI_STACK_ALIGN;

    bool found = false;
    for (uint64_t i = 0; i < count; i++) {
        uint32_t nonce = start + (uint32_t)i;

        /* inner hash, block 2: tail words + nonce + padding */
        __m128i s0 = ms0, s1 = ms1;
        __m128i m0 = _mm_set_epi32((int)bswap32(nonce),
                                   (int)t2, (int)t1, (int)t0);
        rounds64(&s0, &s1, m0, m1c, m2c, m3c);
        s0 = _mm_add_epi32(s0, ms0);
        s1 = _mm_add_epi32(s1, ms1);
        unshuf_state(&s0, &s1);
        _mm_storeu_si128((__m128i *)st, s0);
        _mm_storeu_si128((__m128i *)(st + 4), s1);

        /* outer hash: digest + padding */
        __m128i u0 = iv0, u1 = iv1;
        __m128i d0 = _mm_loadu_si128((const __m128i *)st);
        __m128i d1 = _mm_loadu_si128((const __m128i *)(st + 4));
        rounds64(&u0, &u1, d0, d1, o2c, o3c);
        u0 = _mm_add_epi32(u0, iv0);
        u1 = _mm_add_epi32(u1, iv1);
        unshuf_state(&u0, &u1);
        _mm_storeu_si128((__m128i *)fin, u0);
        _mm_storeu_si128((__m128i *)(fin + 4), u1);

        if (digest_below_target(fin, w->target)) {
            *nonce_out = nonce;
            found = true;
            break;
        }
    }

    atomic_fetch_add(&g_hashes, count);
    return found;
}

#else /* non-x86 or non-GNU: SHA-NI unavailable */

bool sha_ni_supported(void) { return false; }

void sha256d_80_ni(const uint8_t header[80], uint8_t out[32])
{
    sha256d_hash(header, 80, out);
}

bool scanhash_ni(const struct work *w, uint32_t start,
                 uint32_t count, uint32_t *nonce_out)
{
    return scanhash_portable(w, start, count, nonce_out);
}

#endif
