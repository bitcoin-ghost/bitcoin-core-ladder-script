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
  short-circuits at **~55 vB amortised** per input — about an order of
  magnitude cheaper than a per-input FALCON sig (~666 B sig + ~897 B
  pubkey).

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

- **Witness size per input.** The anchor input is ~1,575 vB
  (PUBKEY 897 + SIGNATURE 666 + framing). Non-anchor inputs are
  ~30-50 vB each (just the PQ_BATCH micro-header + scaffolding).
  The total **anchor cost amortises** across N — at N=10 you're
  already saving ~5,500 vB vs N independent FALCON sigs.
- **One verify call.** The proxy log shows exactly one
  `VerifyPQSignature` call per spend tx, regardless of N. Compare to
  N independent SIG(FALCON-512) inputs which cost N verifies.
- **Order matters.** The anchor must be at the **lowest-index input**
  per commit group. The library walks inputs in order; a non-anchor
  input at a lower index than its anchor returns UNSATISFIED (no
  cache entry yet). The playground always builds input 0 as the
  anchor.

## Comparison numbers

For the typical "drain N UTXOs to one sink" shape:

| N    | PQ_BATCH total (vB) | per-input (vB) | vs N × SIG(FALCON-512) |
|-----:|--------------------:|---------------:|------------------------|
| 1    |             ~1,610  |          1,610 | parity                 |
| 10   |             ~2,160  |            216 | ~7× cheaper            |
| 100  |             ~6,890  |             69 | ~10× cheaper           |
| 500  |            ~30,070  |             60 | ~11× cheaper           |
| 1000 |            ~58,900  |             59 | ~11× cheaper           |

Asymptote: ~55 vB per non-anchor input. (Per-input figures from
`mlsc_spend_path_sweep` — see [`SIZING.md`](SIZING.md).)

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
