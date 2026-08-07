/*
 * main.c - CPU Bitcoin miner: CLI, offline bench, live Stratum session
 *
 * Usage examples:
 *   ./cpuminer -b                       offline benchmark (no network)
 *   ./cpuminer -o stratum+tcp://solo.ckpool.org:3333 -u YOUR_BTC_ADDRESS -t 4
 */
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "miner.h"
#include "sha256.h"
#include "stratum.h"
#include "gbt.h"
#include "target.h"
#include "util.h"

static atomic_bool g_running = ATOMIC_VAR_INIT(true);

static void on_signal(int sig)
{
    (void)sig;
    atomic_store(&g_running, false);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "CPU Bitcoin miner (sha256d)\n"
        "usage: %s [options]\n"
        "  -g          node (getblocktemplate) solo mode vs bitcoind RPC\n"
        "  -o <url>    pool/node URL\n"
        "              (stratum default: stratum+tcp://solo.ckpool.org:3333)\n"
        "              (gbt default:     http://127.0.0.1:18443)\n"
        "  -u <user>   stratum: username/BTC address | gbt: rpc username\n"
        "  -p <pass>   stratum: worker password      | gbt: rpc password\n"
        "  -A <addr>   gbt: payout address (default: fetch from node wallet)\n"
        "  -t <n>      number of mining threads (default: 4, max 256)\n"
        "  -e <eng>    engine: auto | ni | portable (default: auto)\n"
        "  -b          offline benchmark mode (no network)\n"
        "  -d <diff>   bench share difficulty (default 0.0001)\n"
        "  -T <secs>   bench duration in seconds (default 15)\n"
        "  -h          this help\n", prog);
}

/* ---------------- offline benchmark ---------------- */

static atomic_uint bench_unit = ATOMIC_VAR_INIT(0);
static atomic_uint bench_shares = ATOMIC_VAR_INIT(0);
static uint32_t bench_target[8];

static bool bench_get_work(struct work *w, void *arg)
{
    (void)arg;
    unsigned u = atomic_fetch_add(&bench_unit, 1);

    memset(w, 0, sizeof(*w));
    le32_store(w->header + 0, 0x20000000u);
    memset(w->header + 4, 0x11, 32); /* fake prevhash */
    for (int i = 0; i < 32; i++)     /* unique merkle root per unit */
        w->header[36 + i] = (uint8_t)(u * 31 + i * 7);
    le32_store(w->header + 68, (uint32_t)time(NULL));
    le32_store(w->header + 72, 0x1d00ffffu);

    memcpy(w->target, bench_target, sizeof(bench_target));
    w->gen = 1;
    snprintf(w->job_id, sizeof(w->job_id), "bench");
    work_prepare(w);
    return true;
}

static void bench_submit(const struct work *w, uint32_t nonce, void *arg)
{
    (void)arg;
    /* independent verification with the slow portable double-hash */
    uint8_t h[80];
    memcpy(h, w->header, 80);
    le32_store(h + 76, nonce);

    uint8_t d[32];
    sha256d_hash(h, 80, d);

    uint32_t dw[8];
    for (int i = 0; i < 8; i++)
        dw[i] = be32_load(d + 4 * i);

    bool ok = digest_below_target(dw, w->target);
    char hex[65];
    bin2hex(hex, d, 32);
    fprintf(stderr, "bench: share nonce=%08x %s hash=%s\n",
            nonce, ok ? "VALID" : "INVALID(!)", hex);
    if (ok)
        atomic_fetch_add(&bench_shares, 1);
    else
        atomic_store(&g_running, false); /* correctness failure: stop */
}

static uint64_t bench_gen(void *arg)
{
    (void)arg;
    return 1;
}


static int run_bench(int nthreads, scanhash_fn scan, double diff, int secs)
{
    diff_to_target(bench_target, diff);
    char th[65];
    target_to_hex(bench_target, th);
    fprintf(stderr, "bench: %d threads, share difficulty %g (target %s)\n",
            nthreads, diff, th);

    pthread_t tids[MAX_THREADS];
    struct miner_cfg cfgs[MAX_THREADS];
    for (int i = 0; i < nthreads; i++) {
        cfgs[i].id = i;
        cfgs[i].scan = scan;
        cfgs[i].get_work = bench_get_work;
        cfgs[i].submit = bench_submit;
        cfgs[i].current_gen = bench_gen;
        cfgs[i].arg = NULL;
        cfgs[i].running = &g_running;
        pthread_create(&tids[i], NULL, miner_thread, &cfgs[i]);
    }

    int64_t t0 = now_ms();
    unsigned long long last = 0;
    int64_t last_t = t0;
    while (atomic_load(&g_running) && now_ms() - t0 < (int64_t)secs * 1000) {
        struct timespec ts = {0, 200 * 1000 * 1000};
        nanosleep(&ts, NULL);
        int64_t now = now_ms();
        if (now - last_t >= 2000) {
            unsigned long long h = atomic_load(&g_hashes);
            double rate = (double)(h - last) / ((double)(now - last_t) / 1000.0);
            fprintf(stderr, "bench: %.2f MH/s (shares: %u)\n", rate / 1e6,
                    atomic_load(&bench_shares));
            last = h;
            last_t = now;
        }
    }

    atomic_store(&g_running, false);
    for (int i = 0; i < nthreads; i++)
        pthread_join(tids[i], NULL);

    unsigned long long total = atomic_load(&g_hashes);
    double elapsed = (double)(now_ms() - t0) / 1000.0;
    fprintf(stderr,
            "bench: done in %.1fs - %llu hashes, avg %.2f MH/s, %u shares\n",
            elapsed, total, (double)total / elapsed / 1e6,
            atomic_load(&bench_shares));
    return atomic_load(&bench_shares) > 0 ? 0 : 1;
}

/* ---------------- live mining ---------------- */

static int run_live(const char *url, const char *user, const char *pass,
                    int nthreads, scanhash_fn scan)
{
    struct stratum_cfg cfg = { .url = url, .user = user, .pass = pass };

    while (atomic_load(&g_running)) {
        if (!stratum_connect(&cfg)) {
            stratum_close();
            if (!atomic_load(&g_running))
                break;
            fprintf(stderr, "main: retrying in 5 seconds...\n");
            for (int i = 0; i < 5 && atomic_load(&g_running); i++)
                sleep(1);
            continue;
        }

        stratum_run(nthreads, scan, &g_running);
        stratum_close();

        if (atomic_load(&g_running)) {
            fprintf(stderr, "main: connection lost, retrying in 5 seconds...\n");
            for (int i = 0; i < 5 && atomic_load(&g_running); i++)
                sleep(1);
        }
    }

    fprintf(stderr,
            "main: session over - submitted %llu, accepted %llu, rejected %llu\n",
            (unsigned long long)atomic_load(&g_submitted),
            (unsigned long long)atomic_load(&g_accepted),
            (unsigned long long)atomic_load(&g_rejected));
    return 0;
}

/* ---------------- gbt (node) mining ---------------- */

static int run_gbt(const char *url, const char *user, const char *pass,
                   const char *address, int nthreads, scanhash_fn scan)
{
    if (!strcmp(user, "cpuminer.benchmark")) {
        fprintf(stderr,
                "main: gbt mode needs node credentials: -u <rpcuser> "
                "-p <rpcpassword>\n");
        return 2;
    }
    struct gbt_cfg cfg = {
        .rpc_url = url, .rpc_user = user, .rpc_pass = pass,
        .address = address,
    };
    if (!gbt_init(&cfg))
        return 2;
    gbt_run(nthreads, scan, &g_running);
    fprintf(stderr, "main: gbt session over - blocks found %llu\n",
            (unsigned long long)atomic_load(&g_gbt_blocks));
    return 0;
}

/* ---------------- main ---------------- */

int main(int argc, char **argv)
{
    const char *url = "stratum+tcp://solo.ckpool.org:3333";
    const char *user = "cpuminer.benchmark";
    const char *pass = "x";
    const char *engine = "auto";
    int nthreads = 4;
    int bench = 0;
    double bench_diff = 0.0001;
    int bench_secs = 15;
    int gbt = 0;
    int url_set = 0;
    const char *address = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "o:u:p:t:e:bd:T:hgA:")) != -1) {
        switch (opt) {
        case 'o': url = optarg; url_set = 1; break;
        case 'u': user = optarg; break;
        case 'p': pass = optarg; break;
        case 't': nthreads = atoi(optarg); break;
        case 'e': engine = optarg; break;
        case 'b': bench = 1; break;
        case 'd': bench_diff = atof(optarg); break;
        case 'T': bench_secs = atoi(optarg); break;
        case 'g': gbt = 1; break;
        case 'A': address = optarg; break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }

    if (nthreads < 1)
        nthreads = 1;
    if (nthreads > MAX_THREADS)
        nthreads = MAX_THREADS;
    if (bench_secs < 1)
        bench_secs = 1;

    bool have_ni = sha_ni_supported();
    scanhash_fn scan;
    const char *engine_name;
    if (!strcmp(engine, "ni")) {
        if (!have_ni) {
            fprintf(stderr, "main: CPU does not support SHA-NI\n");
            return 2;
        }
        scan = scanhash_ni;
        engine_name = "sha-ni";
    } else if (!strcmp(engine, "portable")) {
        scan = scanhash_portable;
        engine_name = "portable";
    } else {
        scan = have_ni ? scanhash_ni : scanhash_portable;
        engine_name = have_ni ? "sha-ni" : "portable";
    }

    fprintf(stderr, "main: CPU bitcoin miner | engine=%s | threads=%d\n",
            engine_name, nthreads);
    fprintf(stderr, "main: SHA-NI hardware acceleration %s\n",
            have_ni ? "available" : "NOT available");

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (bench)
        return run_bench(nthreads, scan, bench_diff, bench_secs);

    if (gbt) {
        const char *rurl = url_set ? url : "http://127.0.0.1:18443";
        if (!url_set)
            fprintf(stderr, "main: gbt mode, rpc url %s\n", rurl);
        return run_gbt(rurl, user, pass, address, nthreads, scan);
    }

    if (!strcmp(user, "cpuminer.benchmark"))
        fprintf(stderr,
                "main: WARNING - default user, shares will not be credited.\n"
                "main: use -u <your BTC address> to claim rewards.\n");

    return run_live(url, user, pass, nthreads, scan);
}
