/*
 * stratum.h - Stratum v1 mining protocol client
 */
#ifndef MINER_STRATUM_H
#define MINER_STRATUM_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "miner.h"

struct stratum_cfg {
    const char *url;  /* stratum+tcp://host:port or host:port */
    const char *user;
    const char *pass;
};

/* connect + subscribe + authorize. false on failure (message logged). */
bool stratum_connect(const struct stratum_cfg *cfg);

/* close connection, stop worker threads */
void stratum_close(void);

/* run the session: starts reader + miner threads, blocks until the
 * connection dies or running becomes false. */
void stratum_run(int nthreads, scanhash_fn scan, atomic_bool *running);

/* work provider / submitter used by miner threads (miner_cfg callbacks) */
bool stratum_get_work(struct work *w, void *arg);
void stratum_submit(const struct work *w, uint32_t nonce, void *arg);
uint64_t stratum_current_gen(void *arg);

/* live stats */
extern atomic_ullong g_submitted, g_accepted, g_rejected;

#endif /* MINER_STRATUM_H */
