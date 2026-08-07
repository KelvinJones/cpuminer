/*
 * test_vectors.c - known-answer and cross-engine tests
 *
 * Anchors:
 *  - FIPS 180-4 SHA-256 test vectors
 *  - real Bitcoin block 125552 header -> its known block hash
 *  - compact-bits and difficulty target decoding
 *  - portable vs SHA-NI engine equivalence on random headers
 *  - both scan engines finding the same first nonce on an easy target
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miner.h"
#include "sha256.h"
#include "target.h"
#include "util.h"

static int failures = 0;

#define CHECK(cond, name)                                             \
    do {                                                              \
        if (cond) {                                                   \
            printf("ok   %s\n", name);                                \
        } else {                                                      \
            printf("FAIL %s\n", name);                                \
            failures++;                                               \
        }                                                             \
    } while (0)

static void sha_hex(const char *msg, char out[65])
{
    uint8_t d[32];
    sha256_hash(msg, strlen(msg), d);
    bin2hex(out, d, 32);
}

static void test_sha256_kat(void)
{
    char hex[65];

    sha_hex("", hex);
    CHECK(!strcmp(hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "sha256(\"\")");

    sha_hex("abc", hex);
    CHECK(!strcmp(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "sha256(\"abc\")");

    sha_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hex);
    CHECK(!strcmp(hex,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        "sha256(448-bit two-block message)");

    /* one million 'a' */
    char *buf = malloc(1000000);
    memset(buf, 'a', 1000000);
    uint8_t d[32];
    sha256_hash(buf, 1000000, d);
    bin2hex(hex, d, 32);
    free(buf);
    CHECK(!strcmp(hex,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        "sha256(one million 'a')");

    uint8_t d2[32];
    sha256d_hash("hello", 5, d2);
    bin2hex(hex, d2, 32);
    CHECK(!strcmp(hex,
        "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"),
        "sha256d(\"hello\")");
}

/* real block 125552: reconstruct the header, double-hash it, byte-reverse,
 * and compare against the known block hash */
static void test_block_125552(void)
{
    const char *header_hex =
        "01000000"
        "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
        "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
        "c7f5d74d"
        "f2b9441a"
        "42a14695";
    uint8_t header[80];
    CHECK(hex2bin(header, header_hex, 80), "block 125552 header parses");

    uint8_t d[32];
    sha256d_hash(header, 80, d);

    uint8_t rev[32];
    for (int i = 0; i < 32; i++)
        rev[i] = d[31 - i];
    char hex[65];
    bin2hex(hex, rev, 32);
    CHECK(!strcmp(hex,
        "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d"),
        "block 125552 hash");
}

static void test_block_125552_target(void)
{
    /* A genuinely independent check: the real block 125552's hash must
     * satisfy the target declared in its own nbits field. This catches
     * byte-order bugs in digest_below_target that circular scan/verify
     * tests cannot. */
    const char *header_hex =
        "01000000"
        "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
        "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
        "c7f5d74d"
        "f2b9441a"
        "42a14695";
    uint8_t header[80];
    hex2bin(header, header_hex, 80);
    uint8_t d[32];
    sha256d_hash(header, 80, d);
    uint32_t dw[8];
    for (int i = 0; i < 8; i++)
        dw[i] = be32_load(d + 4 * i);
    uint32_t tgt[8];
    bits_to_target(0x1a44b9f2, tgt); /* this block's declared nbits */
    CHECK(digest_below_target(dw, tgt),
          "block 125552 hash meets its own target");
}

static void test_targets(void)
{
    uint32_t t[8];
    char hex[65];

    bits_to_target(0x1d00ffff, t);
    target_to_hex(t, hex);
    CHECK(!strcmp(hex,
        "00000000ffff0000000000000000000000000000000000000000000000000000"),
        "bits 0x1d00ffff -> difficulty-1 target");

    bits_to_target(0x1b0404cb, t);
    target_to_hex(t, hex);
    CHECK(!strcmp(hex,
        "00000000000404cb000000000000000000000000000000000000000000000000"),
        "bits 0x1b0404cb -> early-era target");

    diff_to_target(t, 1.0);
    target_to_hex(t, hex);
    CHECK(!strcmp(hex,
        "00000000ffff0000000000000000000000000000000000000000000000000000"),
        "diff_to_target(1.0)");

    /* higher difficulty => smaller target */
    uint32_t t1[8], t2[8];
    diff_to_target(t1, 1.0);
    diff_to_target(t2, 256.0);
    CHECK(u256_cmp(t2, t1) < 0, "difficulty 256 target < difficulty 1 target");
}

static void test_ni_equivalence(void)
{
    if (!sha_ni_supported()) {
        printf("skip SHA-NI equivalence (not supported on this CPU)\n");
        return;
    }

    srand(12345);
    uint8_t header[80];
    bool all_ok = true;
    for (int i = 0; i < 512; i++) {
        for (int j = 0; j < 80; j++)
            header[j] = (uint8_t)rand();
        uint8_t d_ref[32], d_ni[32];
        sha256d_hash(header, 80, d_ref);
        sha256d_80_ni(header, d_ni);
        if (memcmp(d_ref, d_ni, 32) != 0)
            all_ok = false;
    }
    CHECK(all_ok, "SHA-NI sha256d(header80) == portable on 512 random headers");
}

/* find the first nonce meeting an easy target with both engines and
 * verify independently; both engines must agree on the first hit */
static void test_scanhash(void)
{
    struct work w;
    memset(&w, 0, sizeof(w));
    le32_store(w.header + 0, 0x20000000u);
    for (int i = 4; i < 76; i++)
        w.header[i] = (uint8_t)(i * 13 + 7);
    diff_to_target(w.target, 1.0 / 65536.0); /* ~65k hashes expected */
    work_prepare(&w);

    uint32_t nonce_p = 0, nonce_n = 0;
    bool found_p = false, found_n = false;
    uint32_t cap = 1u << 24; /* generous cap */

    for (uint32_t base = 0; base < cap && !found_p; base += (1u << 18))
        found_p = scanhash_portable(&w, base, 1u << 18, &nonce_p);
    CHECK(found_p, "portable scan finds a nonce");

    if (sha_ni_supported()) {
        for (uint32_t base = 0; base < cap && !found_n; base += (1u << 18))
            found_n = scanhash_ni(&w, base, 1u << 18, &nonce_n);
        CHECK(found_n, "SHA-NI scan finds a nonce");
        CHECK(found_p && found_n && nonce_p == nonce_n,
              "portable and SHA-NI find the SAME first nonce");
    }

    if (found_p) {
        /* independent full recomputation */
        uint8_t h[80];
        memcpy(h, w.header, 80);
        le32_store(h + 76, nonce_p);
        uint8_t d[32];
        sha256d_hash(h, 80, d);
        uint32_t dw[8];
        for (int i = 0; i < 8; i++)
            dw[i] = be32_load(d + 4 * i);
        CHECK(digest_below_target(dw, w.target),
              "found nonce verifies independently");
    }
}

int main(void)
{
    test_sha256_kat();
    test_block_125552();
    test_block_125552_target();
    test_targets();
    test_ni_equivalence();
    test_scanhash();

    if (failures) {
        printf("\n%d TEST(S) FAILED\n", failures);
        return 1;
    }
    printf("\nall tests passed\n");
    return 0;
}
