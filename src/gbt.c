/*
 * gbt.c - getblocktemplate solo mining against a local bitcoind over RPC.
 *
 * Flow: getblocktemplate -> build coinbase (BIP34 height + extranonce +
 * witness commitment) -> merkle root over txids -> mine header -> on a hit,
 * assemble the full block and submitblock. On regtest this finds real blocks.
 */
#define _GNU_SOURCE /* strcasestr */

#include "gbt.h"

#include "cJSON.h"
#include "sha256.h"
#include "target.h"
#include "util.h"

#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_GBT_TXS   4096
#define GBT_MAX_BODY  (48u * 1024u * 1024u)
#define GBT_STALE_MS  10000   /* refetch template if older than this */

static struct {
    char host[128];
    char port[8];
    char auth_header[832];          /* "Basic <base64(user:pass)>" */

    uint8_t pay_script[128];
    size_t  pay_script_len;

    pthread_mutex_t lock;
    bool     have_tmpl;
    uint8_t  prevhash[32];          /* internal order */
    uint32_t version, nbits, curtime;
    uint32_t height;
    int64_t  coinbasevalue;
    uint32_t target[8];
    double   diff;
    uint8_t  witness_commit[64];
    size_t   wc_len;
    bool     has_wc;

    int      n_txs;
    uint8_t  txids[MAX_GBT_TXS][32]; /* internal order */
    uint8_t *txdata;                 /* concatenated wire-format txs */
    size_t   txdata_len;
    size_t   txdata_cap;

    int64_t  fetched_ms;
    atomic_ullong gen;
    uint64_t unit_counter;
    uint32_t last_ntime;
} G = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .gen = ATOMIC_VAR_INIT(1),
};

atomic_ullong g_gbt_blocks = 0;

/* ---------------- low-level TCP + HTTP ---------------- */

static int tcp_connect_host(const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    int s = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    return s;
}

static bool send_all_fd(int fd, const char *buf, size_t len)
{
    while (len) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

/* read an entire HTTP response until the server closes (Connection: close) */
static char *read_all_fd(int fd, size_t *out_len)
{
    size_t cap = 1u << 16, len = 0;
    char *buf = malloc(cap);
    if (!buf)
        return NULL;
    for (;;) {
        if (len + 65536 > cap) {
            if (cap >= GBT_MAX_BODY) { free(buf); return NULL; }
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        ssize_t n = recv(fd, buf + len, cap - len, 0);
        if (n <= 0)
            break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

/* remove HTTP chunked transfer-encoding from body (in place, malloc'd copy) */
static char *dechunk(const char *body, size_t body_len, size_t *out_len)
{
    char *out = malloc(body_len + 1);
    if (!out)
        return NULL;
    size_t o = 0, i = 0;
    while (i < body_len) {
        /* parse chunk size line */
        size_t sz = 0;
        bool any = false;
        while (i < body_len && body[i] != '\r') {
            char c = body[i++];
            int v = (c >= '0' && c <= '9') ? c - '0'
                  : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                  : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (v < 0)
                break;
            sz = (sz << 4) | (unsigned)v;
            any = true;
        }
        if (!any)
            break;
        if (i < body_len && body[i] == '\r') i++;
        if (i < body_len && body[i] == '\n') i++;
        if (sz == 0)
            break;
        if (i + sz > body_len)
            sz = body_len - i;
        memcpy(out + o, body + i, sz);
        o += sz;
        i += sz;
        if (i < body_len && body[i] == '\r') i++;
        if (i < body_len && body[i] == '\n') i++;
    }
    out[o] = '\0';
    *out_len = o;
    return out;
}

/* ---------------- JSON-RPC ---------------- */

/* params_json is a complete JSON params value (usually an array string).
 * Returns the detached "result" cJSON, or NULL on transport/RPC error. */
static cJSON *rpc_call(const char *method, const char *params_json)
{
    size_t blen = strlen(params_json) + 160;
    char *body = malloc(blen);
    if (!body)
        return NULL;
    int bn = snprintf(body, blen,
        "{\"jsonrpc\":\"1.0\",\"id\":\"cpuminer\",\"method\":\"%s\",\"params\":%s}",
        method, params_json);

    int fd = tcp_connect_host(G.host, G.port);
    if (fd < 0) {
        fprintf(stderr, "gbt: cannot connect to %s:%s\n", G.host, G.port);
        free(body);
        return NULL;
    }

    const char *fmt =
        "POST / HTTP/1.1\r\nHost: %s:%s\r\nAuthorization: %s\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\n"
        "Connection: close\r\n\r\n";
    size_t hlen = strlen(fmt) + strlen(G.host) + strlen(G.port) +
                  strlen(G.auth_header) + 32;
    char *head = malloc(hlen);
    snprintf(head, hlen, fmt, G.host, G.port, G.auth_header, bn);

    bool ok = send_all_fd(fd, head, strlen(head)) &&
              send_all_fd(fd, body, (size_t)bn);
    free(head);
    free(body);
    if (!ok) {
        close(fd);
        fprintf(stderr, "gbt: rpc send failed\n");
        return NULL;
    }

    size_t rawlen = 0;
    char *raw = read_all_fd(fd, &rawlen);
    close(fd);
    if (!raw)
        return NULL;

    char *sep = strstr(raw, "\r\n\r\n");
    if (!sep) { free(raw); return NULL; }
    char *bstart = sep + 4;

    char *json_body = bstart;
    size_t jlen = rawlen - (size_t)(bstart - raw);
    if (strcasestr(raw, "transfer-encoding:") && strcasestr(raw, "chunked")) {
        size_t dlen = 0;
        char *dc = dechunk(bstart, jlen, &dlen);
        if (dc) {
            json_body = dc;
            jlen = dlen;
        }
    }
    (void)jlen;

    cJSON *msg = cJSON_Parse(json_body);
    cJSON *result = NULL;
    if (msg) {
        cJSON *err = cJSON_GetObjectItem(msg, "error");
        if (err && !cJSON_IsNull(err)) {
            char *es = cJSON_Print(err);
            fprintf(stderr, "gbt: rpc '%s' error: %s\n", method, es ? es : "?");
            free(es);
        } else {
            result = cJSON_DetachItemFromObject(msg, "result");
        }
        cJSON_Delete(msg);
    }
    if (json_body != bstart)
        free(json_body);
    free(raw);
    return result;
}

/* ---------------- bitcoin serialization helpers ---------------- */

/* regtest/mainnet subsidy schedule (sats): 50 BTC, halving every 210000 */
static int64_t subsidy_for_height(uint32_t height)
{
    uint32_t halv = height / 210000u;
    if (halv >= 64)
        return 0;
    return (int64_t)5000000000LL >> halv;
}

/* BIP34 block-height push, matching CScript() << CScriptNum(height):
 * 0 -> OP_0, 1..16 -> OP_1..OP_16 single-byte opcodes, else minimal push */
static size_t bip34_push(uint8_t *out, uint32_t v)
{
    if (v == 0) {
        out[0] = 0x00; /* OP_0 */
        return 1;
    }
    if (v <= 16) {
        out[0] = (uint8_t)(0x50 + v); /* OP_1 .. OP_16 */
        return 1;
    }
    uint8_t tmp[5];
    int n = 0;
    while (v) {
        tmp[n++] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    if (tmp[n - 1] & 0x80)
        tmp[n++] = 0x00; /* sign pad */
    out[0] = (uint8_t)n;
    memcpy(out + 1, tmp, (size_t)n);
    return (size_t)(1 + n);
}

/*
 * Serialize the coinbase. with_witness=false gives the legacy form used for
 * the txid/merkle; with_witness=true gives the full form included in blocks.
 */
static size_t build_coinbase(uint8_t *out, bool with_witness,
                             uint32_t height, uint64_t extranonce,
                             const uint8_t *pay_script, size_t pay_len,
                             int64_t value,
                             const uint8_t *wc, size_t wc_len)
{
    uint8_t *p = out;
    le32_store(p, 2);
    p += 4;                              /* nVersion = 2 */
    if (with_witness) {
        *p++ = 0x00;                     /* segwit marker */
        *p++ = 0x01;                     /* segwit flag */
    }
    p += put_compact_size(p, 1);         /* 1 input */
    memset(p, 0, 32);
    p += 32;                             /* null prevhash */
    le32_store(p, 0xffffffff);
    p += 4;                              /* vout = -1 */

    /* scriptSig = push(height) || extranonce || tag */
    uint8_t ss[128];
    size_t sl = 0;
    sl += bip34_push(ss + sl, height);
    for (int i = 0; i < 8; i++)
        ss[sl++] = (uint8_t)(extranonce >> (8 * i));
    const char *tag = "/cpuminer-cpu/";
    size_t tl = strlen(tag);
    memcpy(ss + sl, tag, tl);
    sl += tl;

    p += put_compact_size(p, sl);
    memcpy(p, ss, sl);
    p += sl;
    le32_store(p, 0xffffffff);
    p += 4;                              /* sequence */

    int nouts = wc ? 2 : 1;
    p += put_compact_size(p, (uint64_t)nouts);

    le64_store(p, (uint64_t)value);      /* reward output */
    p += 8;
    p += put_compact_size(p, pay_len);
    memcpy(p, pay_script, pay_len);
    p += pay_len;

    if (wc) {                            /* witness commitment output */
        le64_store(p, 0);
        p += 8;
        p += put_compact_size(p, wc_len);
        memcpy(p, wc, wc_len);
        p += wc_len;
    }

    if (with_witness) {
        p += put_compact_size(p, 1);     /* 1 witness stack item */
        p += put_compact_size(p, 32);    /* 32-byte reserved value */
        memset(p, 0, 32);
        p += 32;
    }
    le32_store(p, 0);
    p += 4;                              /* locktime */
    return (size_t)(p - out);
}

/* standard bitcoin merkle root over internal-order 32-byte hashes */
static void compute_merkle(uint8_t out[32], const uint8_t items[][32], int n)
{
    if (n <= 1) {
        memcpy(out, items[0], 32);
        return;
    }
    uint8_t(*level)[32] = malloc((size_t)n * 32);
    memcpy(level, items, (size_t)n * 32);
    int count = n;
    while (count > 1) {
        int next = 0;
        for (int i = 0; i < count; i += 2) {
            uint8_t pair[64];
            memcpy(pair, level[i], 32);
            memcpy(pair + 32, (i + 1 < count) ? level[i + 1] : level[i], 32);
            sha256d_hash(pair, 64, level[next]);
            next++;
        }
        count = next;
    }
    memcpy(out, level[0], 32);
    free(level);
}

/* ---------------- template fetch ---------------- */

static const char *jstr_(const cJSON *obj, const char *name)
{
    const cJSON *it = cJSON_GetObjectItem(obj, name);
    return cJSON_IsString(it) ? it->valuestring : NULL;
}

/* fetch + parse a getblocktemplate into G. Caller holds G.lock. */
static bool fetch_template_locked(void)
{
    cJSON *res = rpc_call("getblocktemplate", "[{\"rules\":[\"segwit\"]}]");
    if (!res)
        return false;

    const char *prev = jstr_(res, "previousblockhash");
    const char *bits = jstr_(res, "bits");
    const char *wcs  = jstr_(res, "default_witness_commitment");
    cJSON *cur = cJSON_GetObjectItem(res, "curtime");
    cJSON *h   = cJSON_GetObjectItem(res, "height");
    cJSON *cv  = cJSON_GetObjectItem(res, "coinbasevalue");
    cJSON *ver = cJSON_GetObjectItem(res, "version");
    cJSON *txs = cJSON_GetObjectItem(res, "transactions");

    if (!prev || !bits || !cJSON_IsNumber(h)) {
        fprintf(stderr, "gbt: malformed template\n");
        cJSON_Delete(res);
        return false;
    }
    if (!hex2bin_reversed(G.prevhash, prev)) {
        fprintf(stderr, "gbt: bad previousblockhash\n");
        cJSON_Delete(res);
        return false;
    }
    G.nbits   = (uint32_t)strtoul(bits, NULL, 16);
    G.curtime = cJSON_IsNumber(cur) ? (uint32_t)cur->valuedouble
                                    : (uint32_t)time(NULL);
    G.height  = (uint32_t)h->valuedouble;
    G.version = cJSON_IsNumber(ver) ? (uint32_t)ver->valuedouble : 0x20000000u;
    G.coinbasevalue = cJSON_IsNumber(cv) ? (int64_t)cv->valuedouble
                                         : subsidy_for_height(G.height);

    G.has_wc = false;
    G.wc_len = 0;
    if (wcs) {
        size_t l = strlen(wcs) / 2;
        if (l <= sizeof(G.witness_commit) &&
            hex2bin(G.witness_commit, wcs, l)) {
            G.wc_len = l;
            G.has_wc = true;
        }
    }

    /* transactions: store txids (internal) + concatenated wire data */
    G.n_txs = 0;
    G.txdata_len = 0;
    int n = cJSON_IsArray(txs) ? cJSON_GetArraySize(txs) : 0;
    if (n > MAX_GBT_TXS)
        n = MAX_GBT_TXS;

    size_t total = 0;
    for (int i = 0; i < n; i++) {
        const char *data = jstr_(cJSON_GetArrayItem(txs, i), "data");
        if (data)
            total += strlen(data) / 2;
    }
    if (total > G.txdata_cap) {
        uint8_t *nb = realloc(G.txdata, total);
        if (!nb) {
            fprintf(stderr, "gbt: tx buffer alloc failed, mining coinbase-only\n");
            n = 0;
        } else {
            G.txdata = nb;
            G.txdata_cap = total;
        }
    }

    for (int i = 0; i < n; i++) {
        cJSON *tx = cJSON_GetArrayItem(txs, i);
        const char *txid = jstr_(tx, "txid");
        const char *data = jstr_(tx, "data");
        if (!txid || !data)
            continue;
        size_t dl = strlen(data) / 2;
        if (!hex2bin_reversed(G.txids[G.n_txs], txid) ||
            !hex2bin(G.txdata + G.txdata_len, data, dl))
            continue;
        G.txdata_len += dl;
        G.n_txs++;
    }

    bits_to_target(G.nbits, G.target);
    double tnum = 0.0;
    for (int i = 7; i >= 0; i--)
        tnum = tnum * 4294967296.0 + (double)G.target[i];
    G.diff = tnum > 0.0 ? 2.695994666715063e67 / tnum : 0.0;
    G.have_tmpl = true;
    G.fetched_ms = now_ms();
    atomic_fetch_add(&G.gen, 1);

    fprintf(stderr, "gbt: template height=%u txs=%d coinbase=%lld sats bits=%s\n",
            G.height, G.n_txs, (long long)G.coinbasevalue, bits);
    cJSON_Delete(res);
    return true;
}

/* ---------------- miner callbacks ---------------- */

bool gbt_get_work(struct work *w, void *arg)
{
    (void)arg;
    pthread_mutex_lock(&G.lock);
    if (!G.have_tmpl || now_ms() - G.fetched_ms > GBT_STALE_MS) {
        if (!fetch_template_locked()) {
            pthread_mutex_unlock(&G.lock);
            return false;
        }
    }

    uint64_t ex = ++G.unit_counter;
    int64_t value = G.coinbasevalue;
    const uint8_t *wc = G.has_wc ? G.witness_commit : NULL;
    size_t wc_len = G.has_wc ? G.wc_len : 0;

    /* legacy coinbase -> txid (no witness) */
    uint8_t cb_legacy[1024];
    size_t cb_legacy_len = build_coinbase(cb_legacy, false, G.height, ex,
                                          G.pay_script, G.pay_script_len,
                                          value, wc, wc_len);
    uint8_t cb_txid[32];
    sha256d_hash(cb_legacy, cb_legacy_len, cb_txid);

    /* merkle root over [coinbase_txid, template txids] (internal order) */
    uint8_t root[32];
    if (G.n_txs == 0) {
        memcpy(root, cb_txid, 32);
    } else {
        uint8_t(*items)[32] = malloc((size_t)(G.n_txs + 1) * 32);
        memcpy(items[0], cb_txid, 32);
        for (int i = 0; i < G.n_txs; i++)
            memcpy(items[i + 1], G.txids[i], 32);
        compute_merkle(root, (const uint8_t(*)[32])items, G.n_txs + 1);
        free(items);
    }

    memset(w, 0, sizeof(*w));
    /* full witness coinbase stored for block assembly at submit time */
    w->coinbase_len = (uint32_t)build_coinbase(w->coinbase, true, G.height, ex,
                                               G.pay_script, G.pay_script_len,
                                               value, wc, wc_len);

    le32_store(w->header + 0, G.version);
    memcpy(w->header + 4, G.prevhash, 32);
    memcpy(w->header + 36, root, 32);

    uint32_t ntime = G.curtime;
    uint32_t now32 = (uint32_t)time(NULL);
    if (now32 > ntime)
        ntime = now32;
    if (ntime <= G.last_ntime)
        ntime = G.last_ntime + 1; /* keep ntime above median-time-past */
    G.last_ntime = ntime;
    le32_store(w->header + 68, ntime);
    le32_store(w->header + 72, G.nbits);

    memcpy(w->target, G.target, sizeof(w->target));
    w->difficulty = G.diff;
    w->ntime = ntime;
    w->height = G.height;
    w->gen = atomic_load(&G.gen);
    snprintf(w->job_id, sizeof(w->job_id), "gbt-%u", G.height);

    work_prepare(w);
    pthread_mutex_unlock(&G.lock);
    return true;
}

void gbt_submit(const struct work *w, uint32_t nonce, void *arg)
{
    (void)arg;
    pthread_mutex_lock(&G.lock);
    if (w->gen != atomic_load(&G.gen)) {
        pthread_mutex_unlock(&G.lock);
        fprintf(stderr, "gbt: stale block discarded (tip moved)\n");
        return;
    }

    size_t cap = 80 + 9 + w->coinbase_len + G.txdata_len;
    uint8_t *blk = malloc(cap);
    uint8_t *p = blk;
    memcpy(p, w->header, 80);
    le32_store(p + 76, nonce);
    p += 80;
    p += put_compact_size(p, (uint64_t)(1 + G.n_txs));
    memcpy(p, w->coinbase, w->coinbase_len);
    p += w->coinbase_len;
    if (G.n_txs > 0) {
        memcpy(p, G.txdata, G.txdata_len);
        p += G.txdata_len;
    }
    size_t blklen = (size_t)(p - blk);
    uint32_t height = w->height;
    pthread_mutex_unlock(&G.lock);

    /* header hash for display */
    uint8_t hdr[80], hh[32], rev[32];
    char disp[65];
    memcpy(hdr, w->header, 80);
    le32_store(hdr + 76, nonce);
    sha256d_hash(hdr, 80, hh);
    for (int i = 0; i < 32; i++)
        rev[i] = hh[31 - i];
    bin2hex(disp, rev, 32);

    char *hex = malloc(blklen * 2 + 1);
    bin2hex(hex, blk, blklen);
    free(blk);
    if (getenv("MINER_DEBUG"))
        fprintf(stderr, "DBG blockhex=%s\n", hex);
    char *params = malloc(blklen * 2 + 8);
    snprintf(params, blklen * 2 + 8, "[\"%s\"]", hex);
    free(hex);

    cJSON *res = rpc_call("submitblock", params);
    free(params);
    if (!res) {
        fprintf(stderr, "gbt: submitblock transport error\n");
        return;
    }
    if (cJSON_IsNull(res)) {
        atomic_fetch_add(&g_gbt_blocks, 1);
        fprintf(stderr,
            "\n*** BLOCK ACCEPTED *** height=%u hash=%s nonce=%08x "
            "(total %llu)\n\n",
            height, disp, nonce,
            (unsigned long long)atomic_load(&g_gbt_blocks));
        /* immediately build on the new tip */
        pthread_mutex_lock(&G.lock);
        fetch_template_locked();
        pthread_mutex_unlock(&G.lock);
    } else {
        fprintf(stderr, "gbt: submitblock rejected: %s\n",
                cJSON_IsString(res) ? res->valuestring : "?");
    }
    cJSON_Delete(res);
}

uint64_t gbt_current_gen(void *arg)
{
    (void)arg;
    return atomic_load(&G.gen);
}

/* ---------------- init + session ---------------- */

bool gbt_init(const struct gbt_cfg *cfg)
{
    /* parse http://host:port */
    const char *p = cfg->rpc_url;
    if (!strncmp(p, "http://", 7))
        p += 7;
    const char *colon = strrchr(p, ':');
    if (!colon || colon == p) {
        fprintf(stderr, "gbt: bad rpc url '%s'\n", cfg->rpc_url);
        return false;
    }
    size_t hl = (size_t)(colon - p);
    if (hl >= sizeof(G.host))
        return false;
    memcpy(G.host, p, hl);
    G.host[hl] = '\0';
    snprintf(G.port, sizeof(G.port), "%s", colon + 1);
    for (char *q = G.port; *q; q++) {  /* strip any trailing path */
        if (*q == '/') { *q = '\0'; break; }
    }

    char up[512];
    snprintf(up, sizeof(up), "%s:%s", cfg->rpc_user, cfg->rpc_pass);
    char b64[768];
    b64_encode(b64, (const uint8_t *)up, strlen(up));
    snprintf(G.auth_header, sizeof(G.auth_header), "Basic %s", b64);

    /* chain sanity */
    cJSON *info = rpc_call("getblockchaininfo", "[]");
    if (!info) {
        fprintf(stderr, "gbt: node not reachable or still warming up\n");
        return false;
    }
    const char *chain = jstr_(info, "chain");
    cJSON *b = cJSON_GetObjectItem(info, "blocks");
    double blocks = cJSON_IsNumber(b) ? b->valuedouble : 0.0;
    fprintf(stderr, "gbt: node chain=%s blocks=%.0f\n",
            chain ? chain : "?", blocks);
    if (chain && strcmp(chain, "regtest") && strcmp(chain, "signet") &&
        strcmp(chain, "test"))
        fprintf(stderr, "gbt: WARNING - chain '%s' is a MAIN network!\n",
                chain);
    cJSON_Delete(info);

    /* payout script */
    char addr[128];
    addr[0] = '\0';
    if (cfg->address) {
        snprintf(addr, sizeof(addr), "%s", cfg->address);
    } else {
        cJSON *a = rpc_call("getnewaddress", "[]");
        if (!a || !cJSON_IsString(a)) {
            fprintf(stderr,
                    "gbt: getnewaddress failed - create a wallet first "
                    "(bitcoin-cli createwallet ...) or pass -A <address>\n");
            if (a) cJSON_Delete(a);
            return false;
        }
        snprintf(addr, sizeof(addr), "%s", a->valuestring);
        cJSON_Delete(a);
    }
    char ai_params[256];
    snprintf(ai_params, sizeof(ai_params), "[\"%s\"]", addr);
    cJSON *ai = rpc_call("getaddressinfo", ai_params);
    if (!ai) {
        fprintf(stderr, "gbt: getaddressinfo failed\n");
        return false;
    }
    const char *spk = jstr_(ai, "scriptPubKey");
    size_t sl = spk ? strlen(spk) / 2 : 0;
    if (!spk || sl > sizeof(G.pay_script) || !hex2bin(G.pay_script, spk, sl)) {
        fprintf(stderr, "gbt: could not resolve scriptPubKey\n");
        cJSON_Delete(ai);
        return false;
    }
    G.pay_script_len = sl;
    fprintf(stderr, "gbt: payout address %s (%zu-byte script)\n", addr, sl);
    cJSON_Delete(ai);

    pthread_mutex_lock(&G.lock);
    bool ok = fetch_template_locked();
    pthread_mutex_unlock(&G.lock);
    if (!ok)
        fprintf(stderr, "gbt: could not fetch a block template\n");
    return ok;
}

void gbt_run(int nthreads, scanhash_fn scan, atomic_bool *running)
{
    pthread_t tids[MAX_THREADS];
    struct miner_cfg cfgs[MAX_THREADS];
    for (int i = 0; i < nthreads; i++) {
        cfgs[i].id = i;
        cfgs[i].scan = scan;
        cfgs[i].get_work = gbt_get_work;
        cfgs[i].submit = gbt_submit;
        cfgs[i].current_gen = gbt_current_gen;
        cfgs[i].arg = NULL;
        cfgs[i].running = running;
        if (pthread_create(&tids[i], NULL, miner_thread, &cfgs[i]) != 0) {
            fprintf(stderr, "gbt: cannot start miner thread %d\n", i);
            nthreads = i;
            break;
        }
    }
    fprintf(stderr, "miner: %d threads hashing (gbt solo mode)\n", nthreads);

    int64_t t0 = now_ms();
    unsigned long long last = atomic_load(&g_hashes);
    int64_t last_t = t0;
    while (atomic_load(running)) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        int64_t now = now_ms();
        if (now - last_t >= 5000) {
            unsigned long long h = atomic_load(&g_hashes);
            double rate =
                (double)(h - last) / ((double)(now - last_t) / 1000.0);
            fprintf(stderr,
                    "[%5.0fs] hashrate %7.2f MH/s | blocks found %llu\n",
                    (double)(now - t0) / 1000.0, rate / 1e6,
                    (unsigned long long)atomic_load(&g_gbt_blocks));
            last = h;
            last_t = now;
        }
    }

    atomic_store(running, false);
    for (int i = 0; i < nthreads; i++)
        pthread_join(tids[i], NULL);
    free(G.txdata);
    G.txdata = NULL;
    G.txdata_cap = 0;
}
