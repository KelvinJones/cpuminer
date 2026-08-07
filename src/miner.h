/*
 * miner.h - work unit, scanning engines, mining threads
 */
#ifndef MINER_MINER_H
#define MINER_MINER_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "sha256.h"

/* maximum mining threads the program will start (CLI -t is clamped to this) */
#define MAX_THREADS 256

struct work {
    uint8_t  header[80];      /* serialized header, nonce slot (76..79) zeroed */
    uint32_t midstate[8];     /* SHA-256 state after header bytes 0..63 */
    uint32_t tail_words[3];   /* big-endian words of header bytes 64..75 */
    uint32_t target[8];       /* LE words, target[0] = least significant */
    double   difficulty;
    uint64_t gen;             /* job generation this unit belongs to */
    uint32_t ntime;           /* ntime used in header (BE value, also submitted) */
    char     job_id[160];
    char     extranonce2_hex[33];

    /* gbt solo-mining only: full witness coinbase + metadata for submitblock */
    uint8_t  coinbase[1024];
    uint32_t coinbase_len;
    uint32_t height;
};

/* fill midstate / tail_words from header */
void work_prepare(struct work *w);

/*
 * Scan nonce range [start, start + count). Returns true and stores the
 * first satisfying nonce in *nonce_out when hash(header) <= target.
 */
typedef bool (*scanhash_fn)(const struct work *w, uint32_t start,
                            uint32_t count, uint32_t *nonce_out);

bool scanhash_portable(const struct work *w, uint32_t start,
                       uint32_t count, uint32_t *nonce_out);
bool scanhash_ni(const struct work *w, uint32_t start,
                 uint32_t count, uint32_t *nonce_out);

/* double-SHA256 of an 80-byte header using the SHA-NI engine */
void sha256d_80_ni(const uint8_t header[80], uint8_t out[32]);

/* true when the CPU supports Intel SHA extensions (and they were compiled) */
bool sha_ni_supported(void);

/* global hash counter maintained by the scan functions */
extern atomic_ullong g_hashes;

/* ---- mining thread runner ---- */

struct miner_cfg {
    int id;
    scanhash_fn scan;
    /* obtain a fresh work unit; false when no job available yet */
    bool (*get_work)(struct work *w, void *arg);
    /* submit a found share */
    void (*submit)(const struct work *w, uint32_t nonce, void *arg);
    /* current job generation (work is stale when it changes) */
    uint64_t (*current_gen)(void *arg);
    void *arg;
    atomic_bool *running;
};

void *miner_thread(void *arg); /* struct miner_cfg * */

#endif /* MINER_MINER_H */
