# Sizing

TX_MLSC was designed for size from the wire format up. Outputs are
**8 bytes on the wire** (value only — the script is synthesised on
deserialisation from a tx-level `conditions_root`), and the 32-byte
`conditions_root` is carried **once per transaction**, not once per
output. Every batch tx, every UTXO, and every block of chainstate
inherits that saving.

All numbers below are measured on the current build and reproduce
exactly via the boost tests linked in the last section. `vsize` is
BIP 141 weight reinterpreted as virtual bytes (`(weight + 3) / 4`).
Fee figures assume 1 sat/vB unless stated — scale linearly.

## Headline

| metric                                  | MLSC | P2WPKH | P2TR | MLSC vs Taproot |
|-----------------------------------------|-----:|-------:|-----:|----------------:|
| Chainstate per coin (compressed)        |  3 B |   24 B | 36 B | **12&times; smaller** |
| 100-output batch tx (vsize)             | 911  | 3,179  | 4,369 | **4.8&times; smaller** |
| Single payment, key-path (vsize)        | 109  |   110  |  111 | parity          |
| Per-output asymptote (large N, vsize)   | ~8   |   ~31  |  ~43 | **5&times; smaller** |

## 1. Chainstate per coin

The chainstate is the live UTXO database. It lives in RAM on every
full node, so per-coin cost is the most expensive byte in Bitcoin.

| output type     | per-coin bytes | notes                                                 |
|-----------------|---------------:|-------------------------------------------------------|
| MLSC (compact)  |              3 | 1-byte SPK after compression; root in synthetic entry |
| P2WPKH          |             24 | 22-byte SPK stored fully                              |
| P2TR            |             36 | 34-byte SPK stored fully                              |

Per tx, MLSC total UTXO cost is `N × 3 + 33` — the `+33` is the
one-time synthetic `(txid, MLSC_ROOT_VOUT)` entry storing
`0xDF || conditions_root` once for the whole tx.

| N coins | MLSC total | P2WPKH | P2TR  |
|--------:|-----------:|-------:|------:|
| 10      |     63 B   |  240 B |  360 B |
| 100     |    333 B   | 2,400 B | 3,600 B |
| 1,000   |  3,033 B   | 24,000 B | 36,000 B |

The MLSC UTXO set grows roughly at the rate of the coinbase script
cost alone — each additional coin reuses the root entry.

## 2. Batch tx wire size

A standard wallet spending one P2WPKH UTXO into N new MLSC outputs
with a single shared `conditions_root`.

| N   | MLSC vB | P2WPKH vB | P2TR vB | MLSC vB/out |
|----:|--------:|----------:|--------:|------------:|
| 1   | 119     | 110       | 112     | 119.00      |
| 2   | 127     | 141       | 155     | 63.50       |
| 5   | 151     | 234       | 284     | 30.20       |
| 10  | 191     | 389       | 499     | 19.10       |
| 25  | 311     | 854       | 1,144   | 12.44       |
| 50  | 511     | 1,629     | 2,219   | 10.22       |
| 100 | 911     | 3,179     | 4,369   | 9.11        |

**Observations:**

- MLSC has a small baseline penalty at N=1 (+9 vB vs P2WPKH, ~8%)
  for the tx-level `conditions_root` (32 B) and the v4 format flags.
- MLSC **overtakes P2WPKH at N=2** (127 vs 141 vB) and the gap
  widens linearly.
- At N=100, MLSC is **3.5&times; smaller than P2WPKH** and
  **4.8&times; smaller than P2TR**.
- Per-output marginal cost asymptotes to **8 vB** (MLSC),
  ~31 vB (P2WPKH), ~43 vB (P2TR).

## 3. Spend tx (1 MLSC input → N MLSC outputs)

The "spend and re-lock" shape: funding → fan-out → refund. Input 0
is an MLSC UTXO spent via a 1-rung 1-block SIG ladder witness. The
input witness (LadderWitness + MLSCProof) is ~200 B, amortised once
per tx.

| N   | tx B | vsize | vB/out |
|----:|-----:|------:|-------:|
| 1   |  316 |   148 | 148.00 |
| 5   |  348 |   180 |  36.00 |
| 10  |  388 |   220 |  22.00 |
| 50  |  708 |   540 |  10.80 |
| 100 | 1108 |   940 |   9.40 |

## 4. Spend-path breakdown

MLSC supports three witness shapes. At 1-input/1-output:

| path                          | vsize | comparison                                  |
|-------------------------------|------:|---------------------------------------------|
| (A) key-path                  |  109  | 2 vB **smaller** than P2TR key-path (111)   |
| (B) script-path, no tweak     |  148  | ~19 vB more than P2TR script-path (129)     |
| (C) script-path, with tweak   |  156  | adds 33 B for the internal pubkey           |

**Key-path matches a P2WPKH payment.** The richer block-typed
semantics cost nothing in the simplest case. Script-path carries
~19 vB more than a raw Tapscript leaf — that is the cost of the
LadderWitness + MLSCProof pair, which gives you the full
block/rung/coil model in exchange.

## 5. Post-quantum signatures

A bare FALCON-512 signature is ~666 B. Per-input PQ verification
is the cost driver for any naive PQ migration.

**PQ_BATCH** commits `SHA256(falcon_pubkey)` per output. One anchor
input in the spend tx reveals the pubkey + signature once; every
other input gated by the same hash short-circuits via a tx-local
verify cache.

- Anchor input: ~666 B sig + ~897 B pubkey = full PQ cost paid once.
- Subsequent inputs: ~55 vB amortised — about **12&times; cheaper**
  than per-input FALCON.
- No coordinator, no priming round. Built for exchange sweeps,
  co-owned UTXO pools, recurring subscription drains.

**QABIO** commits a coordinator FALCON-512 pubkey, the full
participant set, and the output set at fund time. Each participant
primes their UTXO independently; the coordinator then signs a
single FALCON aggregate covering every input. One verify per tx.

| N inputs | tx vsize | per-input vB |
|---------:|---------:|-------------:|
| 1        |     592  |       592    |
| 10       |   1,836  |       184    |
| 50       |   7,366  |       147    |
| 100      |  14,279  |       143    |
| 500      |  69,707  |       139    |
| 1,000    | 139,082  |       139    |

At N=100, **~143 vB per cosigner** — roughly equivalent to a
P2WPKH payment, fully PQ-safe and atomically settled.

## 6. Fee economics

**Single-output payment (N=1):** MLSC and P2TR key-path within
2 vB (109 vs 111). **Not** a cost regression for the simplest case.

**Wallet fan-out (N=10 outputs):** MLSC 191 vB vs P2WPKH 389 vB =
**50.9% smaller**. At 10 sat/vB, saves 1,980 sats per fan-out.

**Batch payout (N=100 outputs):** MLSC 911 vB vs P2WPKH 3,179 vB =
**71.3% smaller**. At 10 sat/vB, saves 22,680 sats per batch.

**QABIO batch (N=100 inputs):** ~143 vB per participant. Each
participant pays ~143 sats at 1 sat/vB — roughly equivalent to a
P2WPKH payment, amortised across cosigners.

## 7. How to reproduce

Every table on this page is regenerated from a boost test in the
reference implementation. Run any of:

```bash
./build/bin/test_bitcoin --run_test=qabi_tests/mlsc_creation_tx_size_sweep --log_level=message
./build/bin/test_bitcoin --run_test=qabi_tests/mlsc_spend_tx_size_sweep      --log_level=message
./build/bin/test_bitcoin --run_test=qabi_tests/mlsc_spend_path_sweep         --log_level=message
./build/bin/test_bitcoin --run_test=qabi_tests/mlsc_utxo_storage_size        --log_level=message
./build/bin/test_bitcoin --run_test=qabi_tests/qabi_tx_size_sweep            --log_level=message
```

Source-of-truth doc in the repository:
[`doc/ladder-script/MEASUREMENTS.md`](https://github.com/defenwycke/bitcoin-core-ladder-script/blob/ladder-script/doc/ladder-script/MEASUREMENTS.md).
If any wire-format serialisation changes, every sweep above is
re-run and the BIP draft is updated to match.
