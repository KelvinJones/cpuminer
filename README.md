# cpuminer — a Bitcoin CPU miner in C

A from-scratch Bitcoin (SHA-256d) miner for CPUs, built as an educational
deep-dive into proof-of-work. It implements the full pipeline:

```
Stratum pool ──> coinbase + merkle root ──> 80-byte block header
                                              │
                              midstate precomputation (per job)
                                              │
                    per-nonce double SHA-256 with SHA-NI hardware
                                              │
                                   hash ≤ target ? ──> submit share
```

Yes, a CPU is hilariously outgunned by ASICs (see the reality check below).
The point is the challenge: a correct, self-contained, *fast* implementation
of the same algorithm ASICs run, validated against real Bitcoin data and a
real mining pool.

## Performance (AMD Ryzen 7 4800H)

| engine                   | 4 threads  | per thread |
|--------------------------|------------|------------|
| SHA-NI (`-e ni`)         | ~92 MH/s   | ~23 MH/s   |
| portable (`-e portable`) | ~10 MH/s   | ~2.5 MH/s  |

SHA-NI (hardware SHA-256 instructions, `sha_ni` CPU flag) gives a ~9x
speedup. The miner auto-detects and uses it (`-e auto`, the default).

## Build & test

```sh
make            # builds ./cpuminer
make test       # builds ./run_tests and runs the known-answer suite
```

Requires gcc (or clang) and GNU make. The SHA-NI path compiles via function
target attributes; no special flags needed. On non-x86 builds the portable
engine is used automatically.

## Usage

Offline benchmark (no network needed):

```sh
./cpuminer -b -t 4            # 15s bench, 4 threads, finds+verifies shares
./cpuminer -b -t 4 -T 30 -d 0.001
```

Live solo mining against solo.ckpool (username must be a BTC address that
would receive any block reward):

```sh
./cpuminer -o stratum+tcp://solo.ckpool.org:3333 -u <YOUR_BTC_ADDRESS> -t 4
```

```
-g          node (getblocktemplate) solo mode vs bitcoind RPC
-o <url>    pool/node URL (stratum default solo.ckpool.org:3333;
            gbt default http://127.0.0.1:18443)
-u <user>   stratum: username/BTC address | gbt: rpc username
-p <pass>   stratum: worker password      | gbt: rpc password
-A <addr>   gbt: payout address (default: fetch from node wallet)
-t <n>      mining threads (default 4, max 256)
-e <eng>    auto | ni | portable
-b          offline benchmark mode
-d <diff>   bench share difficulty (default 0.0001)
-T <secs>   bench duration (default 15)
```

## Solo-mine real blocks on regtest (no blockchain download)

`regtest` is a private network you generate yourself — no peers, no chain
download, trivial difficulty. This proves the full pipeline: the miner
fetches a template, builds the coinbase/merkle/header, mines it with SHA-NI,
and `submitblock`s a block the node actually accepts.

```sh
# 1. install Bitcoin Core (bitcoincore.org), then start a regtest node:
bitcoind -regtest -daemon -server -rpcuser=miner -rpcpassword=minerpass -fallbackfee=0.0001

# 2. one-time wallet setup (so rewards have somewhere to go):
bitcoin-cli -regtest -rpcuser=miner -rpcpassword=minerpass createwallet miner

# 3. mine! (auto-fetches a payout address from the wallet)
./cpuminer -g -u miner -p minerpass -t 4

# 4. watch it work:
bitcoin-cli -regtest -rpcuser=miner -rpcpassword=minerpass getblockcount
bitcoin-cli -regtest -rpcuser=miner -rpcpassword=minerpass getbalances
```

Measured here: ~190-290 blocks accepted in ~30s on a 4800H; a couple of
thousand regtest BTC in spendable balance within a minute. The same `-g` mode
works against `signet`, `testnet3`, or (if you're patient and have the chain)
mainnet.

## Correctness

`make test` runs `tests/test_vectors.c`:

- FIPS 180-4 SHA-256 known-answer vectors (incl. one million 'a')
- double-SHA256 vectors
- **real Bitcoin block 125552**: header reconstructed from its fields must
  double-hash to the actual block hash
  `00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d`
- compact-bits (`0x1d00ffff`, `0x1b0404cb`) and pool-difficulty target decoding
- **block 125552's hash must satisfy its own declared target** — an independent
  (non-circular) check of the hash↔target byte order, the classic mining bug
- SHA-NI engine vs portable engine: identical digests on 512 random headers
- both scan engines must find the *same* first nonce on an easy target, and
  the nonce is re-verified with an independent full double-hash
- plus a live end-to-end proof: real blocks accepted by `bitcoind` on regtest

## How it works

### Proof-of-work
A block header is 80 bytes: `version | prev_block_hash | merkle_root |
time | bits | nonce` (all little-endian in serialization). The PoW is
`SHA256(SHA256(header))` interpreted as a little-endian 256-bit number that
must be ≤ the target (encoded in `bits`, or set by the pool via share
difficulty). The miner sweeps the 32-bit nonce space.

### Stratum v1
Implemented in `src/stratum.c` with cJSON: `mining.subscribe`,
`mining.authorize`, `mining.notify` (builds coinbase from
`coinbase1 || extranonce1 || extranonce2 || coinbase2`, folds the merkle
branches with double-SHA256), `mining.set_difficulty`,
`mining.set_extranonce`, `mining.submit`. Each work unit gets a fresh
`extranonce2` and rolled `ntime`, so units never collide across threads or
sessions. Reconnect with backoff is automatic.

### The hot loop (`src/sha256d_ni.c`)
- The first 64 header bytes are fixed per job, so their SHA-256 **midstate**
  is computed once (`work_prepare`) and reused for every nonce.
- Per nonce only two compressions run: the header tail block (64..79 +
  padding) and the outer hash.
- With SHA-NI each 64-round compression is 32 `sha256rnds2` instructions
  plus `sha256msg1/msg2` message scheduling (sequence after Jeffrey Walton's
  public-domain SHA-Intrinsics code, as used by Bitcoin Core). The shuffled
  state is hoisted per job/IV.
- `src/miner.c` contains the portable fallback: same midstate trick in plain C.

### Threading
Each mining thread claims full 2^32-nonce work units (unique merkle roots via
`extranonce2`), scans in 256K-nonce chunks, and re-checks the job generation
so pool-new-block notifications interrupt scanning promptly. Found shares are
submitted thread-safely over the single Stratum connection.

## Reality check (economics)

- Network hashrate ≈ 10^21 H/s. The CPU this was coded on does ≈ 10^8 H/s.
- Expected time to find a block solo: difficulty × 2^32 / hashrate
  ≈ **billions of years**. It is a lottery ticket that redraws ~90 million
  times per second.
- Even pool shares are slow at CPU scale: at diff 10000 a ~70 MH/s miner
  finds one share roughly weekly. ckpool's vardiff may lower the difficulty
  for slow miners.
- Electricity cost will exceed any realistic reward by many orders of
  magnitude. **Run this for the joy of it, not for profit.** Mining is
  CPU-bound, so `-t` beyond your physical core count only oversubscribes —
  extra threads (up to 256) are accepted but add no hashrate.

## Source layout

```
Makefile
src/
  main.c         CLI, offline bench, live session loop, stats
  sha256.[ch]    portable SHA-256 (reference)
  sha256d_ni.c   SHA-NI engine: generic transform + mining hot loop
  miner.[ch]     work unit, portable scanhash, mining threads
  target.[ch]    bits/difficulty -> 256-bit target math
  stratum.[ch]   Stratum v1 client (JSON-RPC over TCP)
  gbt.[ch]       getblocktemplate solo mining vs bitcoind RPC
  cJSON.[ch]     vendored MIT JSON parser
  util.[ch]      hex, byte order, time helpers
tests/
  test_vectors.c known-answer + cross-engine tests
  dbg_ni.c       optional NI-vs-portable diagnostic harness
```

## Ideas for later

- version rolling via `mining.set_version_mask` for more search space
- AVX2 4/8-lane engine for CPUs without SHA-NI
- GBT longpolling so template refreshes are push-driven instead of timed

## License

MIT — see [LICENSE](LICENSE). The vendored cJSON parser in `src/` is also
MIT-licensed (see its source headers).

