/*
 * target.h - Bitcoin target / difficulty arithmetic
 *
 * A target is a 256-bit number stored as eight uint32 words,
 * target[0] = least significant word (cpuminer convention).
 */
#ifndef MINER_TARGET_H
#define MINER_TARGET_H

#include <stdbool.h>
#include <stdint.h>

/* decode compact "bits" field (e.g. 0x1d00ffff) into a target */
void bits_to_target(uint32_t bits, uint32_t target[8]);

/* pool difficulty -> target (classic pdiff-approximation, as cpuminer) */
void diff_to_target(uint32_t target[8], double diff);

/* a > b ? +1 : a < b ? -1 : 0 */
int u256_cmp(const uint32_t a[8], const uint32_t b[8]);

/*
 * digest_words[0..7] are the final double-SHA256 digest as big-endian
 * words, digest_words[0] = most significant. Returns digest <= target.
 */
bool digest_below_target(const uint32_t digest_words[8], const uint32_t target[8]);

/* render target as 64-char big-endian hex string (+ NUL) */
void target_to_hex(const uint32_t target[8], char out[65]);

#endif /* MINER_TARGET_H */
