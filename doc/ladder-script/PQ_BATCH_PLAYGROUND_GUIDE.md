# PQ Batch Playground Guide

A focused tool for the **`PQ_BATCH`** primitive: generate one
post-quantum keypair, fund N UTXOs gated by the same
`SHA256(falcon_pubkey)` commit, and watch the spend amortise via the
tx-local cache.

Live URL: <https://ladder-script.org/pq-batch-playground/>
Source: `tools/pq-batch-playground/index.html`

## What it shows

`PQ_BATCH` lets multiple UTXOs share **one** committed PQ pubkey hash
without paying a per-input PQ verification cost. In the spending tx:

- **Input 0 = anchor.** Reveals the canonical PQ pubkey + a FALCON-512
  signature over the per-input ladder sighash. The library verifies
  once, populates a tx-local `PQBatchCache` keyed by the commit.
- **Inputs 1..N-1 = cache reads.** Empty witness. The evaluator looks
  up the commit, finds the cached "anchor verified" verdict, and
  short-circuits at **~14 vB per non-anchor input**. At N=100 the
  per-input mean is **~17.8 vB** &mdash; about **22&times; cheaper**
  than a per-input FALCON-512 sig (~666 B sig + ~897 B pubkey ≈ 392 vB
  per input even with SegWit witness discount).

No coordinator, no priming round. The simple "key-sharing pool"
complement to QABIO.

## What you'll do

The page is a four-step linear flow:

1. **Choose N** (1..100). The default is 5.
2. **Generate FALCON-512 keypair.** One call to `/api/ladder/pq/keypair`
   — produces `pubkey` (897 bytes) and `commitHex = SHA256(pubkey)`.
3. **Fund N UTXOs.** Wallet pulls `(N × per-utxo amount + 2,000 sats fee)`
   into a self UTXO, then `createrungtx` splits it across N
   `PQ_BATCH(commit)` outputs (one rung per output, all gated by the
   same commit).
4. **Batch spend.** Drain all N UTXOs into one sink output. Input 0
   carries `[PUBKEY(897), SIGNATURE(666)]` as the anchor witness;
   inputs 1..N-1 carry empty PQ_BATCH witnesses. The library verifies
   once, reads the cache N-1 times.

Each step shows the JSON exchanged with `/api/ladder/*` endpoints in a
collapsible panel below the action buttons (`fund_create_req`,
`fund_create_resp`, `spend_create_req`, `spend_sign_req`, `spend_sign_resp`,
`broadcast_req`, `broadcast_resp`). Use `Download all` to dump every
JSON for offline inspection.

## What to look for

- **Witness size per input.** The anchor input witness is ~1,567
  bytes (PUBKEY 897 + SIGNATURE 666 + ~4 framing) which is **~392 vB**
  after the SegWit witness discount (BIP-141 weight / 4). Non-anchor
  inputs are **~14 vB each** (just the MLSC proof scaffolding). The
  total **anchor cost amortises** across N &mdash; at N=10 you save
  ~3,500 vB vs N independent FALCON sigs; at N=100 you save ~38,200 vB.
- **One verify call.** The proxy log shows exactly one
  `VerifyPQSignature` call per spend tx, regardless of N. Compare to
  N independent SIG(FALCON-512) inputs which cost N verifies.
- **Order matters.** The anchor must be at the **lowest-index input**
  per commit group. The library walks inputs in order; a non-anchor
  input at a lower index than its anchor returns UNSATISFIED (no
  cache entry yet). The playground always builds input 0 as the
  anchor.

## Comparison numbers

For the typical "drain N UTXOs to one sink" shape (FALCON-512). Per
[`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md): anchor input ~392 vB
(witness, SegWit-discounted), non-anchor input ~14 vB.

| N     | PQ_BATCH total (vB) | per-input (vB) | vs N &times; SIG(FALCON-512) at ~400 vB |
|------:|--------------------:|---------------:|------------------------------------------|
| 1     |             ~392    |           392  | parity                                   |
| 10    |             ~518    |          ~52   | ~8&times; cheaper                        |
| 100   |             ~1,778  |          ~17.8 | **~22&times; cheaper**                   |
| 500   |             ~7,378  |          ~15   | ~27&times; cheaper                       |
| 1,000 |            ~14,378  |          ~14   | ~28&times; cheaper                       |

Asymptote: **~14 vB per non-anchor input**. The anchor input pays
the FALCON witness cost once (~392 vB after the SegWit 4&times;
discount on 666 B sig + 897 B pubkey + scaffolding); every cache-
read input pays only the PQ_BATCH micro-header + the rung's MLSC
proof scaffolding (~14 vB). (Per-input figures from PQ_BATCH_SPEC.md
&mdash; mirrors the audited `pq-batch.html` block doc.)

## When to use it

- **Exchange sweeps.** A custodian holds many UTXOs all spendable by the
  same FALCON key; `PQ_BATCH` collapses the consolidation cost.
- **Co-owned pools.** Multiple addresses derived from the same PQ
  master key.
- **Recurring drains.** A subscription escrow that periodically batches
  small UTXOs into a single PQ-authorised sweep.

For **multi-party** ceremonies (different signers, atomic settlement,
output-set binding), use **QABIO** instead — see
[`QABIO_PLAYGROUND_GUIDE.md`](QABIO_PLAYGROUND_GUIDE.md). PQ_BATCH and
QABIO can also coexist in the same tx (PQ_BATCH gates the inputs;
QABIO carries the coordinator's tx-level signature).

## Cross-references

- Wire format and consensus rules: [`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md).
- Per-block evaluator: `src/rung/blocks/qabi.cpp::EvalPQBatchBlock`.
- Cache type: `rung::PQBatchCache` (`src/rung/evaluator.h`).
- Boost test: `qabi_tests/pq_batch_*` in `src/test/rung_tests.cpp`.
- Functional tests: `feature_rung_pq_batch.py`,
  `feature_rung_pq_batch_stress.py`.
