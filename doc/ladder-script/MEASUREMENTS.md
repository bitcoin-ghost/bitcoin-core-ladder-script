# Ladder Script — empirical tx and UTXO sizes

**Status:** reference numbers for the BIP draft and integrator docs.
**Measured on:** commit `1dd8f562a5` (post Stage 2 tidy).
**Re-verified at:** v0.14 (`v30.0-ladder-0.14`, 2026-04-30) — every
table below reproduces bit-for-bit on the v0.14 binary. No size drift
across v0.7–v0.14 (canonical encodings + tagged-hash domains added in
the audit campaign do not change wire size).
**Companion tests (reproducible):**
- `rung_tests/mlsc_creation_tx_size_sweep`
- `rung_tests/mlsc_spend_tx_size_sweep`
- `rung_tests/mlsc_spend_path_sweep`
- `rung_tests/mlsc_utxo_storage_size`
- `qabi_tests/qabi_tx_size_sweep`

Regenerate any table in this doc by running the matching test with
`--log_level=message`.

All sizes are serialised bytes on the wire. `vsize` is BIP 141
weight reinterpreted as virtual bytes (`(weight + 3) / 4`). Fee
economics below assume a flat 1 sat/vB fee — scale linearly for
other rates.

## 1. Creation tx (1 wallet input → N MLSC outputs)

A standard wallet spending a P2WPKH UTXO into N new MLSC outputs
with a single shared `conditions_root`. The non-witness section
on the wire is value-only per output — the scriptPubKey is
synthesised on deserialisation from the tx-level `conditions_root`.

| N   | MLSC B | MLSC vB | P2WPKH B | P2WPKH vB | P2TR B | P2TR vB | MLSC B/out | MLSC vB/out |
|-----|--------|---------|----------|-----------|--------|---------|-----------:|------------:|
| 1   | 203    | 119     | 192      | 110       | 163    | 112     | 203.0      | 119.00      |
| 2   | 211    | 127     | 223      | 141       | 206    | 155     | 105.5      |  63.50      |
| 3   | 219    | 135     | 254      | 172       | 249    | 198     |  73.0      |  45.00      |
| 5   | 235    | 151     | 316      | 234       | 335    | 284     |  47.0      |  30.20      |
| 10  | 275    | 191     | 471      | 389       | 550    | 499     |  27.5      |  19.10      |
| 25  | 395    | 311     | 936      | 854       | 1195   | 1144    |  15.8      |  12.44      |
| 50  | 595    | 511     | 1711     | 1629      | 2270   | 2219    |  11.9      |  10.22      |
| 100 | 995    | 911     | 3261     | 3179      | 4420   | 4369    |   9.9      |   9.11      |

**Key observations:**

- MLSC has **higher baseline** than P2WPKH at N=1 (+9 vB, ~8%),
  because of the extra tx-level `conditions_root` (32 B) and v4
  format flags.
- MLSC **overtakes P2WPKH at N=2** (127 vs 141 vB) and the gap
  widens linearly.
- At N=100, MLSC is **3.5× smaller than P2WPKH** and **4.8×
  smaller than P2TR**. The per-output marginal cost asymptotes to
  **8 vB/out** for MLSC vs ~31 vB/out for P2WPKH vs ~43 vB/out
  for P2TR.
- The vsize gap at N=100 is 2,268 vB of savings vs P2WPKH — at
  1 sat/vB, **2,268 sats per tx** avoided, scaling linearly with
  fee rate.

## 2. Spend tx (1 MLSC input → N MLSC outputs)

The common "spend and re-lock" shape: funding → fan-out → refund.
Input 0 is an MLSC UTXO spent via a 1-rung 1-block SIG ladder
witness. Outputs all share a single fresh `conditions_root`.

| N   | tx B | vsize | B/out | vB/out |
|-----|------|-------|-------|-------:|
| 1   | 316  | 148   | 316.0 | 148.00 |
| 2   | 324  | 156   | 162.0 |  78.00 |
| 3   | 332  | 164   | 110.7 |  54.67 |
| 5   | 348  | 180   |  69.6 |  36.00 |
| 10  | 388  | 220   |  38.8 |  22.00 |
| 25  | 508  | 340   |  20.3 |  13.60 |
| 50  | 708  | 540   |  14.2 |  10.80 |
| 100 | 1108 | 940   |  11.1 |   9.40 |

The input witness (LadderWitness + MLSCProof for a single-rung
single-block SIG spend) is ~200 B, amortised once per tx.

## 3. Spend-path breakdown (MLSC)

MLSC supports three witness shapes. At 1-input/1-output:

| path                         | witness elements                                | vsize |
|------------------------------|-------------------------------------------------|------:|
| (A) key-path                 | [schnorr_sig(64)]                               |  109  |
| (B) script-path, no tweak    | [LadderWitness, MLSCProof]                      |  148  |
| (C) script-path, with tweak  | [LadderWitness, MLSCProof, internal_pubkey(33)] |  156  |

Compared to 1-input/1-output Bitcoin baselines:

| path                      | vsize |
|---------------------------|------:|
| P2TR key-path             |  111  |
| P2TR script-path          |  129  |
| P2WPKH                    |  110  |
| MLSC key-path             |  109  |
| MLSC script-path no-tweak |  148  |

**Observations:**

- MLSC **key-path is 2 vB smaller than P2TR key-path** and
  matches P2WPKH at 1 input/1 output — there is no amortised
  overhead when the spender wants the simplest path.
- MLSC script-path carries **~19 vB more than P2TR script-path**
  because the LadderWitness + MLSCProof together are ~39 B more
  than a raw Tapscript + control block for the equivalent 1-leaf
  case. This is the cost of the richer semantics (block types,
  relays, coil).

## 4. UTXO storage cost per coin

Measured after Core's UTXO compression. MLSC outputs dedupe the
`conditions_root` across all outputs of the same creating tx via
a synthetic entry at `(txid, MLSC_ROOT_VOUT)`.

| output type   | per-coin B | notes                                               |
|---------------|-----------:|-----------------------------------------------------|
| MLSC (compact)| 3          | 1-byte SPK after compression; root in synthetic entry |
| P2WPKH        | 24         | 22-byte SPK stored fully                            |
| P2TR          | 36         | 34-byte SPK stored fully                            |

Per tx, MLSC total UTXO cost is `N × 3 + 33` (the +33 is the
one-time synthetic `0xDF || conditions_root` entry). At large N:

- N=10: MLSC = 63 B, P2WPKH = 240 B, P2TR = 360 B.
- N=100: MLSC = 333 B, P2WPKH = 2,400 B, P2TR = 3,600 B.
- N=1000: MLSC = 3,033 B, P2WPKH = 24,000 B, P2TR = 36,000 B.

**UTXO-set savings:** **~8–12× smaller** than Taproot for the
same number of coins. The MLSC UTXO set grows roughly at the
rate of the coinbase script cost alone — each additional coin
reuses the root entry.

## 5. QABIO batch spend

- **Per-input asymptotic cost:** ~409 B on the wire, ~139 vB
  after witness discount, converges from N≈50 upward.
- **Standard-relay ceiling (400 kWU = 100,000 vB):** hits at ~720
  inputs at current per-input cost (~139 vB). Above that the tx is
  non-standard and needs direct-to-miner submission.
- **QABI block hard cap (262,144 B):** binds first at ~3,500
  participants — still well above any realistic batch shape.

## 6. Fee economics at a glance

**Single-output payment (N=1):** MLSC and P2TR key-path are
within 2 vB of each other (109 vs 111). MLSC is not a cost
regression for the simplest case.

**Wallet fan-out (N=10 outputs):** MLSC 191 vB vs P2WPKH 389 vB
= **50.9% smaller**. At 10 sat/vB, this saves 1,980 sats per
fan-out.

**Batch payout (N=100 outputs):** MLSC 911 vB vs P2WPKH 3,179 vB
= **71.3% smaller**. At 10 sat/vB, saves 22,680 sats per batch.

**QABIO batch (N=100 inputs):** ~14,279 vB total, ~143 vB per
participant. Each participant pays ~143 sats at 1 sat/vB —
**roughly equivalent to a P2WPKH payment**, amortised across the
cosigners.

## 7. How to regenerate

```bash
# One-tx-shape sweep:
./build/bin/test_bitcoin --run_test=*/mlsc_creation_tx_size_sweep --log_level=message
./build/bin/test_bitcoin --run_test=*/mlsc_spend_tx_size_sweep --log_level=message
./build/bin/test_bitcoin --run_test=*/mlsc_spend_path_sweep --log_level=message
./build/bin/test_bitcoin --run_test=*/mlsc_utxo_storage_size --log_level=message

# QABIO:
./build/bin/test_bitcoin --run_test=qabi_tests/qabi_tx_size_sweep --log_level=message
```

If you change any serialisation, run every sweep in this doc and
update the tables. The BIP draft cites these numbers, so drift
here is drift in the BIP.
