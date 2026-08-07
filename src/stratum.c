/*
 * stratum.c - Stratum v1 mining protocol client (newline-delimited JSON)
 */
#include "stratum.h"

#include "cJSON.h"
#include "sha256.h"
#include "target.h"
#include "util.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RECV_BUF_SIZE (64 * 1024)
#define MAX_MERKLE 64
#define MAX_COINBASE 2048
#define SUBMIT_ID_BASE 1000

struct stratum_job {
    char    job_id[160];
    uint8_t prevhash[32];            /* display (big-endian) order */
    uint8_t coinbase1[MAX_COINBASE];
    size_t  cb1_len;
    uint8_t coinbase2[MAX_COINBASE];
    size_t  cb2_len;
    uint8_t merkle[MAX_MERKLE][32];
    int     n_merkle;
    uint32_t version;
    uint32_t nbits;
    uint32_t ntime;
};

static struct {
    int sock;
    char user[256];
    char pass[256];

    uint8_t extranonce1[32];
    size_t  en1_len;
    size_t  en2_size;
    uint64_t en2_counter;

    double   difficulty;
    uint32_t target[8];

    pthread_mutex_t job_lock;    /* protects job + counter + target */
    pthread_mutex_t send_lock;
    struct stratum_job job;
    bool have_job;
    atomic_ullong gen;
    atomic_uint next_submit_id;

    char   recv_buf[RECV_BUF_SIZE];
    size_t recv_len;

    pthread_t reader_tid;
    atomic_bool reader_dead;
} S = {
    .sock = -1,
    .job_lock = PTHREAD_MUTEX_INITIALIZER,
    .send_lock = PTHREAD_MUTEX_INITIALIZER,
    .difficulty = 1.0,
    .gen = ATOMIC_VAR_INIT(1),
    .next_submit_id = ATOMIC_VAR_INIT(SUBMIT_ID_BASE),
    .reader_dead = ATOMIC_VAR_INIT(false),
};

atomic_ullong g_submitted = 0;
atomic_ullong g_accepted = 0;
atomic_ullong g_rejected = 0;

/* pointer to the global run flag, installed by stratum_run */
static atomic_bool *g_running_ref = NULL;

/* ---------- low level io ---------- */

static bool send_all(const char *buf, size_t len)
{
    while (len) {
        ssize_t n = send(S.sock, buf, len, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

static bool send_line(const char *line)
{
    pthread_mutex_lock(&S.send_lock);
    bool ok = send_all(line, strlen(line)) && send_all("\n", 1);
    pthread_mutex_unlock(&S.send_lock);
    return ok;
}

/* returns malloc'd line (without newline) or NULL on EOF/error */
static char *recv_line(void)
{
    for (;;) {
        char *nl = memchr(S.recv_buf, '\n', S.recv_len);
        if (nl) {
            size_t len = (size_t)(nl - S.recv_buf);
            char *line = malloc(len + 1);
            if (!line)
                return NULL;
            memcpy(line, S.recv_buf, len);
            line[len] = '\0';
            /* strip trailing CR */
            if (len && line[len - 1] == '\r')
                line[len - 1] = '\0';
            size_t rest = S.recv_len - len - 1;
            memmove(S.recv_buf, nl + 1, rest);
            S.recv_len = rest;
            return line;
        }
        if (S.recv_len >= RECV_BUF_SIZE) {
            fprintf(stderr, "stratum: line too long, dropping connection\n");
            return NULL;
        }
        ssize_t n = recv(S.sock, S.recv_buf + S.recv_len,
                         RECV_BUF_SIZE - S.recv_len, 0);
        if (n <= 0)
            return NULL;
        S.recv_len += (size_t)n;
    }
}

/* ---------- job handling ---------- */

static bool valid_job_id_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

static const char *jstr(const cJSON *arr, int idx)
{
    const cJSON *it = cJSON_GetArrayItem(arr, idx);
    return cJSON_IsString(it) ? it->valuestring : NULL;
}

static void handle_notify(cJSON *params)
{
    const char *job_id = jstr(params, 0);
    const char *prevhash = jstr(params, 1);
    const char *cb1 = jstr(params, 2);
    const char *cb2 = jstr(params, 3);
    cJSON *branches = cJSON_GetArrayItem(params, 4);
    const char *version = jstr(params, 5);
    const char *nbits = jstr(params, 6);
    const char *ntime = jstr(params, 7);

    if (!job_id || !prevhash || !cb1 || !cb2 || !cJSON_IsArray(branches) ||
        !version || !nbits || !ntime) {
        fprintf(stderr, "stratum: malformed mining.notify, ignored\n");
        return;
    }
    for (const char *p = job_id; *p; p++) {
        if (!valid_job_id_char(*p)) {
            fprintf(stderr, "stratum: bad job_id charset, ignored\n");
            return;
        }
    }

    struct stratum_job job;
    memset(&job, 0, sizeof(job));
    snprintf(job.job_id, sizeof(job.job_id), "%s", job_id);

    if (strlen(prevhash) != 64 || !hex2bin(job.prevhash, prevhash, 32)) {
        fprintf(stderr, "stratum: bad prevhash, ignored\n");
        return;
    }
    job.cb1_len = strlen(cb1) / 2;
    job.cb2_len = strlen(cb2) / 2;
    if (job.cb1_len > MAX_COINBASE || job.cb2_len > MAX_COINBASE ||
        !hex2bin(job.coinbase1, cb1, job.cb1_len) ||
        !hex2bin(job.coinbase2, cb2, job.cb2_len)) {
        fprintf(stderr, "stratum: bad coinbase, ignored\n");
        return;
    }

    int n = cJSON_GetArraySize(branches);
    if (n > MAX_MERKLE) {
        fprintf(stderr, "stratum: too many merkle branches, ignored\n");
        return;
    }
    for (int i = 0; i < n; i++) {
        const char *h = jstr(branches, i);
        if (!h || strlen(h) != 64 || !hex2bin(job.merkle[i], h, 32)) {
            fprintf(stderr, "stratum: bad merkle branch, ignored\n");
            return;
        }
    }
    job.n_merkle = n;

    job.version = (uint32_t)strtoul(version, NULL, 16);
    job.nbits = (uint32_t)strtoul(nbits, NULL, 16);
    job.ntime = (uint32_t)strtoul(ntime, NULL, 16);

    pthread_mutex_lock(&S.job_lock);
    memcpy(&S.job, &job, sizeof(job));
    S.have_job = true;
    pthread_mutex_unlock(&S.job_lock);
    atomic_fetch_add(&S.gen, 1);

    fprintf(stderr, "stratum: new job %s (diff %.6g, %d branches)\n",
            job.job_id, S.difficulty, n);
}

static void handle_set_difficulty(cJSON *params)
{
    cJSON *d = cJSON_GetArrayItem(params, 0);
    if (!cJSON_IsNumber(d) || d->valuedouble <= 0.0)
        return;
    pthread_mutex_lock(&S.job_lock);
    S.difficulty = d->valuedouble;
    diff_to_target(S.target, S.difficulty);
    pthread_mutex_unlock(&S.job_lock);
    fprintf(stderr, "stratum: difficulty set to %.6g\n", d->valuedouble);
}

static void handle_set_extranonce(cJSON *params)
{
    const char *en1 = jstr(params, 0);
    if (!en1)
        return;
    pthread_mutex_lock(&S.job_lock);
    size_t len = strlen(en1) / 2;
    if (len <= sizeof(S.extranonce1) && hex2bin(S.extranonce1, en1, len))
        S.en1_len = len;
    cJSON *sz = cJSON_GetArrayItem(params, 1);
    if (cJSON_IsNumber(sz) && sz->valueint >= 2 && sz->valueint <= 8)
        S.en2_size = (size_t)sz->valueint;
    pthread_mutex_unlock(&S.job_lock);
}

/* opt-in debug dump (MINER_DEBUG=1): prints everything an independent
 * implementation needs to rebuild the header, for cross-validation */
static void dbg_dump_work(const struct stratum_job *job,
                          const uint8_t *en1, size_t en1_len,
                          const uint8_t *en2, size_t en2_size,
                          const uint8_t root[32], const struct work *w)
{
    char hx[2 * MAX_COINBASE + 1];
    fprintf(stderr, "DBG job_id=%s\n", job->job_id);
    bin2hex(hx, en1, en1_len);   hx[en1_len * 2] = 0;
    fprintf(stderr, "DBG en1=%s\n", hx);
    bin2hex(hx, en2, en2_size);  hx[en2_size * 2] = 0;
    fprintf(stderr, "DBG en2=%s\n", hx);
    bin2hex(hx, job->prevhash, 32); hx[64] = 0;
    fprintf(stderr, "DBG prevhash_display=%s\n", hx);
    bin2hex(hx, job->coinbase1, job->cb1_len); hx[job->cb1_len * 2] = 0;
    fprintf(stderr, "DBG cb1=%s\n", hx);
    bin2hex(hx, job->coinbase2, job->cb2_len); hx[job->cb2_len * 2] = 0;
    fprintf(stderr, "DBG cb2=%s\n", hx);
    for (int i = 0; i < job->n_merkle; i++) {
        bin2hex(hx, job->merkle[i], 32); hx[64] = 0;
        fprintf(stderr, "DBG branch%d=%s\n", i, hx);
    }
    fprintf(stderr, "DBG version=%08x nbits=%08x ntime=%08x\n",
            job->version, job->nbits, job->ntime);
    bin2hex(hx, root, 32); hx[64] = 0;
    fprintf(stderr, "DBG merkleroot_internal=%s\n", hx);
    bin2hex(hx, w->header, 80); hx[160] = 0;
    fprintf(stderr, "DBG header80=%s\n", hx);
}

/* build a fresh work unit from the current job */
bool stratum_get_work(struct work *w, void *arg)
{
    (void)arg;
    struct stratum_job job;
    uint8_t en2[8];
    uint8_t en1[32];
    size_t en1_len, en2_size;
    uint32_t target[8];
    double diff;
    uint64_t en2_val;

    pthread_mutex_lock(&S.job_lock);
    if (!S.have_job) {
        pthread_mutex_unlock(&S.job_lock);
        return false;
    }
    memcpy(&job, &S.job, sizeof(job));
    memcpy(target, S.target, sizeof(target));
    diff = S.difficulty;
    if (S.en2_counter == 0)
        S.en2_counter = 1;
    en2_val = S.en2_counter++;
    en1_len = S.en1_len;
    memcpy(en1, S.extranonce1, en1_len);
    en2_size = S.en2_size;
    pthread_mutex_unlock(&S.job_lock);

    for (size_t i = 0; i < en2_size; i++)
        en2[en2_size - 1 - i] = (uint8_t)(en2_val >> (8 * i));

    /* coinbase = coinbase1 || extranonce1 || extranonce2 || coinbase2 */
    uint8_t coinbase[2 * MAX_COINBASE + 64];
    size_t cb_len = 0;
    memcpy(coinbase, job.coinbase1, job.cb1_len);
    cb_len += job.cb1_len;
    memcpy(coinbase + cb_len, en1, en1_len);
    cb_len += en1_len;
    memcpy(coinbase + cb_len, en2, en2_size);
    cb_len += en2_size;
    memcpy(coinbase + cb_len, job.coinbase2, job.cb2_len);
    cb_len += job.cb2_len;

    /* merkle root from coinbase hash folded with the branches */
    uint8_t root[64]; /* room for root || branch */
    sha256d_hash(coinbase, cb_len, root);
    for (int i = 0; i < job.n_merkle; i++) {
        memcpy(root + 32, job.merkle[i], 32);
        sha256d_hash(root, 64, root);
    }

    memset(w, 0, sizeof(*w));
    le32_store(w->header + 0, job.version);
    for (int i = 0; i < 32; i++) /* display order -> internal order */
        w->header[4 + i] = job.prevhash[31 - i];
    memcpy(w->header + 36, root, 32);

    uint32_t ntime = job.ntime;
    uint32_t now32 = (uint32_t)time(NULL);
    if (now32 > ntime)
        ntime = now32; /* keep shares fresh */
    le32_store(w->header + 68, ntime);
    le32_store(w->header + 72, job.nbits);

    memcpy(w->target, target, sizeof(target));
    w->difficulty = diff;
    w->ntime = ntime;
    w->gen = atomic_load(&S.gen);
    snprintf(w->job_id, sizeof(w->job_id), "%s", job.job_id);
    bin2hex(w->extranonce2_hex, en2, en2_size);

    if (en2_val == 1 && getenv("MINER_DEBUG"))
        dbg_dump_work(&job, en1, en1_len, en2, en2_size, root, w);

    work_prepare(w);
    return true;
}

uint64_t stratum_current_gen(void *arg)
{
    (void)arg;
    return atomic_load(&S.gen);
}

void stratum_submit(const struct work *w, uint32_t nonce, void *arg)
{
    (void)arg;
    unsigned id = atomic_fetch_add(&S.next_submit_id, 1);
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"id\":%u,\"method\":\"mining.submit\",\"params\":"
             "[\"%s\",\"%s\",\"%s\",\"%08x\",\"%08x\"]}",
             id, S.user, w->job_id, w->extranonce2_hex, w->ntime, nonce);
    if (send_line(buf))
        atomic_fetch_add(&g_submitted, 1);
    else
        fprintf(stderr, "stratum: share send failed\n");
}

/* ---------- reader thread + session ---------- */

static void dispatch_msg(cJSON *msg)
{

    cJSON *method = cJSON_GetObjectItem(msg, "method");
    if (cJSON_IsString(method)) {
        cJSON *params = cJSON_GetObjectItem(msg, "params");
        if (!strcmp(method->valuestring, "mining.notify")) {
            handle_notify(params);
        } else if (!strcmp(method->valuestring, "mining.set_difficulty")) {
            handle_set_difficulty(params);
        } else if (!strcmp(method->valuestring, "mining.set_extranonce")) {
            handle_set_extranonce(params);
        } else if (!strcmp(method->valuestring, "mining.set_version_mask")) {
            fprintf(stderr, "stratum: version mask noted (rolling not used)\n");
        } else if (!strcmp(method->valuestring, "client.reconnect")) {
            fprintf(stderr, "stratum: server asked to reconnect\n");
            /* handled by dropping the connection */
            shutdown(S.sock, SHUT_RDWR);
        }
        return;
    }

    /* responses to our requests */
    cJSON *id = cJSON_GetObjectItem(msg, "id");
    if (cJSON_IsNumber(id) && id->valueint >= SUBMIT_ID_BASE) {
        cJSON *result = cJSON_GetObjectItem(msg, "result");
        cJSON *error = cJSON_GetObjectItem(msg, "error");
        if (cJSON_IsTrue(result)) {
            atomic_fetch_add(&g_accepted, 1);
            fprintf(stderr, "stratum: share accepted\n");
        } else {
            atomic_fetch_add(&g_rejected, 1);
            const char *why = "unknown";
            if (cJSON_IsArray(error)) {
                cJSON *e = cJSON_GetArrayItem(error, 1);
                if (cJSON_IsString(e))
                    why = e->valuestring;
            }
            fprintf(stderr, "stratum: share REJECTED (%s)\n", why);
        }
    }
}

static void dispatch_line(const char *line)
{
    cJSON *msg = cJSON_Parse(line);
    if (!msg)
        return;
    dispatch_msg(msg);
    cJSON_Delete(msg);
}

static void *reader_thread(void *arg)
{
    (void)arg;
    while (atomic_load(g_running_ref)) {
        char *line = recv_line();
        if (!line)
            break;
        dispatch_line(line);
        free(line);
    }
    atomic_store(&S.reader_dead, true);
    return NULL;
}

/* ---------- connect + handshake ---------- */

static bool parse_url(const char *url, char *host, size_t hostlen,
                      char *port, size_t portlen)
{
    const char *p = url;
    if (!strncmp(p, "stratum+tcp://", 14))
        p += 14;
    else if (!strncmp(p, "tcp://", 6))
        p += 6;

    const char *colon = strrchr(p, ':');
    if (!colon || colon == p)
        return false;
    size_t hl = (size_t)(colon - p);
    if (hl >= hostlen)
        return false;
    memcpy(host, p, hl);
    host[hl] = '\0';
    snprintf(port, portlen, "%s", colon + 1);
    return port[0] != '\0';
}

static bool tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "net: cannot resolve %s: %s\n", host, gai_strerror(rc));
        return false;
    }

    int sock = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        fprintf(stderr, "net: cannot connect to %s:%s\n", host, port);
        return false;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    S.sock = sock;
    fprintf(stderr, "net: connected to %s:%s\n", host, port);
    return true;
}

/* read lines until a response with the given id arrives; method messages
 * arriving in between are dispatched. Returns the parsed response. */
static cJSON *wait_response(int want_id)
{
    for (;;) {
        char *line = recv_line();
        if (!line)
            return NULL;
        cJSON *msg = cJSON_Parse(line);
        free(line);
        if (!msg)
            continue;
        cJSON *id = cJSON_GetObjectItem(msg, "id");
        if (cJSON_IsNumber(id) && id->valueint == want_id)
            return msg;
        dispatch_msg(msg);
        cJSON_Delete(msg);
    }
}

bool stratum_connect(const struct stratum_cfg *cfg)
{
    char host[256], port[16];
    if (!parse_url(cfg->url, host, sizeof(host), port, sizeof(port))) {
        fprintf(stderr, "config: bad pool URL '%s'\n", cfg->url);
        return false;
    }
    if (!tcp_connect(host, port))
        return false;

    snprintf(S.user, sizeof(S.user), "%s", cfg->user);
    snprintf(S.pass, sizeof(S.pass), "%s", cfg->pass);

    /* reset session state */
    S.recv_len = 0;
    S.en1_len = 0;
    S.en2_size = 4;
    S.en2_counter = 0;
    S.have_job = false;
    atomic_store(&S.reader_dead, false);

    /* mining.subscribe */
    if (!send_line("{\"id\":1,\"method\":\"mining.subscribe\","
                   "\"params\":[\"cpuminer-cpu/1.0\"]}"))
        return false;
    cJSON *resp = wait_response(1);
    if (!resp) {
        fprintf(stderr, "stratum: no subscribe response\n");
        return false;
    }
    cJSON *err = cJSON_GetObjectItem(resp, "error");
    if (err && !cJSON_IsNull(err)) {
        fprintf(stderr, "stratum: subscribe rejected by pool\n");
        cJSON_Delete(resp);
        return false;
    }
    cJSON *result = cJSON_GetObjectItem(resp, "result");
    if (cJSON_IsArray(result)) {
        /* result = [sessions, extranonce1, extranonce2_size] */
        cJSON *en1 = cJSON_GetArrayItem(result, 1);
        if (cJSON_IsString(en1)) {
            size_t len = strlen(en1->valuestring) / 2;
            if (len <= sizeof(S.extranonce1) &&
                hex2bin(S.extranonce1, en1->valuestring, len))
                S.en1_len = len;
        }
        cJSON *sz = cJSON_GetArrayItem(result, 2);
        if (cJSON_IsNumber(sz) && sz->valueint >= 2 && sz->valueint <= 8)
            S.en2_size = (size_t)sz->valueint;
    }
    cJSON_Delete(resp);
    fprintf(stderr, "stratum: subscribed (extranonce1 %zu B, extranonce2 %zu B)\n",
            S.en1_len, S.en2_size);

    /* mining.authorize */
    char auth[600];
    snprintf(auth, sizeof(auth),
             "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}",
             S.user, S.pass);
    if (!send_line(auth))
        return false;
    resp = wait_response(2);
    if (!resp) {
        fprintf(stderr, "stratum: no authorize response\n");
        return false;
    }
    bool ok = cJSON_IsTrue(cJSON_GetObjectItem(resp, "result"));
    cJSON_Delete(resp);
    if (!ok) {
        fprintf(stderr, "stratum: authorization FAILED for '%s'\n", S.user);
        return false;
    }
    fprintf(stderr, "stratum: authorized as %s\n", S.user);
    return true;
}

/* MAX_THREADS comes from miner.h */

void stratum_run(int nthreads, scanhash_fn scan, atomic_bool *running)
{
    g_running_ref = running;

    if (pthread_create(&S.reader_tid, NULL, reader_thread, NULL) != 0) {
        fprintf(stderr, "stratum: cannot start reader thread\n");
        return;
    }

    pthread_t tids[MAX_THREADS];
    struct miner_cfg cfgs[MAX_THREADS]; /* alive until join */
    for (int i = 0; i < nthreads; i++) {
        cfgs[i].id = i;
        cfgs[i].scan = scan;
        cfgs[i].get_work = stratum_get_work;
        cfgs[i].submit = stratum_submit;
        cfgs[i].current_gen = stratum_current_gen;
        cfgs[i].arg = NULL;
        cfgs[i].running = running;
        if (pthread_create(&tids[i], NULL, miner_thread, &cfgs[i]) != 0) {
            fprintf(stderr, "stratum: cannot start miner thread %d\n", i);
            nthreads = i;
            break;
        }
    }
    fprintf(stderr, "miner: %d threads hashing\n", nthreads);

    int64_t t0 = now_ms();
    unsigned long long last_hashes = atomic_load(&g_hashes);
    int64_t last_t = t0;

    while (atomic_load(running) && !atomic_load(&S.reader_dead)) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        int64_t now = now_ms();
        if (now - last_t >= 5000) {
            unsigned long long h = atomic_load(&g_hashes);
            double rate = (double)(h - last_hashes) / ((double)(now - last_t) / 1000.0);
            pthread_mutex_lock(&S.job_lock);
            double diff = S.difficulty;
            pthread_mutex_unlock(&S.job_lock);
            fprintf(stderr,
                    "[%5.0fs] hashrate %7.2f MH/s | submitted %llu "
                    "accepted %llu rejected %llu | pool diff %.6g\n",
                    (double)(now - t0) / 1000.0, rate / 1e6,
                    (unsigned long long)atomic_load(&g_submitted),
                    (unsigned long long)atomic_load(&g_accepted),
                    (unsigned long long)atomic_load(&g_rejected),
                    diff);
            last_hashes = h;
            last_t = now;
        }
    }

    atomic_store(running, false);
    if (S.sock >= 0)
        shutdown(S.sock, SHUT_RDWR); /* unblock reader recv() */
    for (int i = 0; i < nthreads; i++)
        pthread_join(tids[i], NULL);
    pthread_join(S.reader_tid, NULL);
}

void stratum_close(void)
{
    if (S.sock >= 0) {
        close(S.sock);
        S.sock = -1;
    }
    S.have_job = false;
    S.recv_len = 0;
}

