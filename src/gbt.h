/*
 * gbt.h - getblocktemplate (GBT) solo mining directly against a node
 *         (bitcoind RPC). Used for regtest/signet/local demos where the
 *         miner itself finds and submits real blocks.
 */
#ifndef MINER_GBT_H
#define MINER_GBT_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "miner.h"

struct gbt_cfg {
    const char *rpc_url;  /* http://host:port */
    const char *rpc_user;
    const char *rpc_pass;
    const char *address;  /* payout address, or NULL to fetch one from node */
};

/* connect, sanity-check the chain, resolve payout script, fetch first template */
bool gbt_init(const struct gbt_cfg *cfg);

/* run the mining session (starts miner threads, prints stats, blocks until
 * running becomes false) */
void gbt_run(int nthreads, scanhash_fn scan, atomic_bool *running);

/* miner_cfg callbacks */
bool gbt_get_work(struct work *w, void *arg);
void gbt_submit(const struct work *w, uint32_t nonce, void *arg);
uint64_t gbt_current_gen(void *arg);

extern atomic_ullong g_gbt_blocks; /* blocks accepted by the node */

#endif /* MINER_GBT_H */
