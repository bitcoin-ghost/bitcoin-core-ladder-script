# QABIO Playground Guide

A multi-party batch-ceremony walkthrough. Pick a scenario, step the
participants through priming, coordinator signing, and batch broadcast,
or watch the escape-rung sweep when the coordinator bails.

Live URL: <https://ladder-script.org/qabio-playground/>
Source: `tools/qabio-playground/index.html`

## What it shows

QABIO (Quantum Atomic Batch I/O) is the multi-party PQ batch ceremony
spec — see [`QABIO.md`](QABIO.md). Each participant funds an MLSC UTXO
gated on three rungs:

```
Rung 0: SIG(@self_falcon)              -- escape sweep (always available)
Rung 1: QABI_PRIME                     -- priming state transition
Rung 2: QABI_SPEND                     -- batch spend (committed_root, etc.)
```

The ceremony is:

1. **Setup.** Each participant generates a FALCON-512 keypair and
   computes an auth-chain `auth_tip = H^N(seed)` (default N = 100).
2. **Coordinator builds the QABIBlock.** Includes the participant set
   (with `auth_tip`s, `owner_id`s, contributions) and the destination
   output set. Hash this → `committed_root`.
3. **Priming round.** Each participant broadcasts a priming tx
   spending their UTXO via Rung 1 (`QABI_PRIME`). The covenant mutates
   the UTXO's `committed_root` from `0` to the agreed root.
4. **Coordinator signs.** Coordinator computes `SIGHASH_QABO` over the
   batch tx and produces a single FALCON-512 signature
   (`aggregated_sig`).
5. **Batch broadcast.** One tx spends all primed UTXOs via Rung 2
   (`QABI_SPEND`); the library verifies the coordinator's sig **once**
   for the whole tx via the `QABOSigCache`.

If the coordinator never broadcasts, every participant escapes via
Rung 0 (`SIG`) — funds always recoverable.

## What you'll do

The playground exposes six prebuilt scenarios. Click one and a single
**Run full flow** button walks the entire ceremony with a live log.

| Scenario | N | Failures | Description |
|---|---:|---|---|
| 3-of-3 Happy Path | 3 | none | All sign, clean batch broadcast |
| 5 Users, 1 Fails | 5 | P2 | 5 participants, P2 flagged failing → escape sweep after batch |
| 10-User Realistic | 10 | none | Realistic batch, varied contributions, all sign |
| 20-User Mega Batch | 20 | none | Max playground size — amortised cost approaches asymptote (~162 vB/input) |
| Coordinator Bails | 5 | all | Every participant primes; coordinator never broadcasts; everyone escapes |
| Replace-By-Depth (3) | 3 | none | After initial prime, P1 re-primes at deeper depth before batch (RBD policy demo) |

You can also build a custom scenario: set N (1..20), toggle individual
participants' "fail on demand" flags, and step through the flow.

Each step records both human-readable log lines and the JSON exchanged
with `/api/ladder/*` and `/api/ladder/qabi/*` endpoints
(`participant_keypair_*`, `qabi_buildblock_req`, `qabi_buildblock_resp`,
`prime_create_req_*`, `coord_sign_req`, `coord_sign_resp`,
`batch_create_req`, `batch_signed_hex`, `escape_*` for the bails path).
Use **Download all** to dump the complete ceremony state.

## What to look for

- **Per-cosigner cost asymptotes.** At small N each batch tx looks
  expensive (the FALCON-512 aggregate signature is ~666 B fixed
  overhead). At N=10 you're at ~184 vB/input; at N=100 it's ~143 vB
  (matching a P2WPKH payment per cosigner). See
  [`SIZING.md`](SIZING.md) for the full curve.
- **One verify per tx.** The batch spend triggers exactly one
  FALCON-512 verify regardless of N — the QABOSigCache amortises.
- **Replace-By-Depth.** In the RBD scenario, P1's deeper-depth prime
  evicts the shallower one from the mempool. Only the legitimate
  owner can produce a deeper preimage (one-way hash) — see
  `policy.h::IsValidRBDReplacement`.
- **Atomic settlement.** The "5 Users, 1 Fails" scenario shows what
  happens when one participant goes silent at the priming stage:
  every other participant's priming TX still confirms (the rungs are
  per-UTXO, not coupled), then the batch can't settle, then everyone
  falls back to Rung 0 escape. **No participant ever loses funds.**
- **Coordinator output-set binding.** The `qabi_block` carries the
  output set directly; the consensus check enforces tx.vout
  bit-for-bit matches it. The coordinator can't substitute their own
  destination after participants prime.

## When to use it

- **Exchange settlement.** N withdrawals batched atomically under one
  PQ-safe coordinator sig.
- **Atomic issuance.** Mint N tokens to N recipients in one tx; either
  all happen or all escape.
- **Pooled custody.** Members pool deposits, coordinator drives the
  payout, members retain unilateral exit.

If you only need single-key PQ batches (no coordination, no output-set
binding), use **`PQ_BATCH`** instead — see
[`PQ_BATCH_PLAYGROUND_GUIDE.md`](PQ_BATCH_PLAYGROUND_GUIDE.md).

## Cross-references

- Protocol spec: [`QABIO.md`](QABIO.md).
- Block evaluators: `src/rung/blocks/qabi.cpp::EvalQABIPrimeBlock` /
  `EvalQABISpendBlock`.
- State types: `src/rung/qabi.h` (`QABIBlock`, `QABIEntry`,
  auth-chain helpers).
- RBD mempool policy: `src/rung/policy.h::IsValidRBDReplacement`.
- Coordinator sighash: `src/rung/qabi.h::ComputeSighashQABO`.
- Boost tests: `qabi_tests/multi_party_*` in `src/test/rung_tests.cpp`.
- Functional test: `feature_qabi.py` (24 test methods covering all six
  scenarios end-to-end).
