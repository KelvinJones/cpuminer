/*
 * miner.c - portable sha256d scan engine + mining thread runner
 */
#include "miner.h"
#include "target.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

atomic_ullong g_hashes = 0;

void work_prepare(struct work *w)
{
    uint32_t st[8];
    memcpy(st, sha256_iv, sizeof(st));
    sha256_transform(st, w->header); /* header bytes 0..63 */
    memcpy(w->midstate, st, sizeof(st));
    w->tail_words[0] = be32_load(w->header + 64);
    w->tail_words[1] = be32_load(w->header + 68);
    w->tail_words[2] = be32_load(w->header + 72);
}

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

/* compress from state using 16 ready-made big-endian words */
static void compress_words(uint32_t state[8], const uint32_t w16[16])
{
    uint32_t w[64];
    memcpy(w, w16, 64);
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

bool scanhash_portable(const struct work *w, uint32_t start,
                       uint32_t count, uint32_t *nonce_out)
{
    /* inner (2nd) sha256 block of the 80-byte header:
     * words 0..2 fixed tail, word 3 = nonce, then padding (len 640 bits) */
    uint32_t blk[16];
    memset(blk, 0, sizeof(blk));
    blk[0] = w->tail_words[0];
    blk[1] = w->tail_words[1];
    blk[2] = w->tail_words[2];
    blk[4] = 0x80000000u;
    blk[15] = 640;

    /* outer sha256 block: digest words 0..7 + padding (len 256 bits) */
    uint32_t oblk[16];
    memset(oblk, 0, sizeof(oblk));
    oblk[8] = 0x80000000u;
    oblk[15] = 256;

    bool found = false;
    for (uint64_t i = 0; i < count; i++) {
        uint32_t nonce = start + (uint32_t)i;
        /* header stores nonce little-endian => big-endian message word
         * is byte-swapped */
        blk[3] = bswap32(nonce);

        uint32_t st[8];
        memcpy(st, w->midstate, sizeof(st));
        compress_words(st, blk); /* inner hash complete: st = digest (BE words) */

        uint32_t ob[16];
        memcpy(ob, oblk, sizeof(ob));
        memcpy(ob, st, 32); /* digest words 0..7 */

        uint32_t fin[8];
        memcpy(fin, sha256_iv, sizeof(fin));
        compress_words(fin, ob);

        if (digest_below_target(fin, w->target)) {
            *nonce_out = nonce;
            found = true;
            break;
        }
    }

    atomic_fetch_add(&g_hashes, count);
    return found;
}

/* ---- mining thread ---- */

/* nonce range scanned per work fetch before rechecking for new jobs */
#define CHUNK_NONCES (1u << 18)

void *miner_thread(void *arg)
{
    struct miner_cfg *mc = arg;
    struct work w;
    char thr_buf[128];

    while (atomic_load(mc->running)) {
        if (!mc->get_work(&w, mc->arg)) {
            /* no job yet - pool still negotiating */
            struct timespec ts = {0, 200 * 1000 * 1000};
            nanosleep(&ts, NULL);
            continue;
        }

        uint64_t gen = w.gen;
        uint64_t pos = 0; /* position within the 32-bit nonce space */

        while (atomic_load(mc->running) && pos < 0x100000000ull) {
            if (mc->current_gen(mc->arg) != gen)
                break; /* new job from pool - abandon this unit */

            uint32_t count = CHUNK_NONCES;
            if (pos + count > 0x100000000ull)
                count = (uint32_t)(0x100000000ull - pos);

            uint32_t nonce;
            if (mc->scan(&w, (uint32_t)pos, count, &nonce)) {
                snprintf(thr_buf, sizeof(thr_buf),
                         "thread %d: share found (nonce %08x)",
                         mc->id, nonce);
                fprintf(stderr, "%s\n", thr_buf);
                mc->submit(&w, nonce, mc->arg);
            }
            pos += count;
        }
        /* unit exhausted or stale -> fetch fresh work unit */
    }
    return NULL;
}
