# PQ_BATCH block type — design spec

**Status**: SHIPPED 2026-04-24 (wire ID 0x0A03). Consensus, signer, functional
test (`test/functional/feature_rung_pq_batch.py`), and engine block def
present. Auto-fund of the PQ keypair from the engine UI is a follow-on; the
block can be exercised today via `signrungtx` with a pre-supplied pubkey +
privkey or `pq_pubkey` + `pq_privkey` pair.

## Motivation

Ladder Script currently has two patterns for post-quantum batched spend authorisation:

1. **QABIO** (`QABI_SPEND` + `QABI_PRIME`): coordinator-run with priming. Every input carries ~50 vB of per-input state (`auth_tip`, `committed_root`, `spend_preimage`, etc) plus requires a separate priming tx per participant. Governance-heavy — the coordinator specifies `committed_root` and only primed inputs can join.

2. **MULTISIG** / per-input PQ `SIG`: each input carries its own full FALCON signature. Linear cost — 666 bytes per input.

Neither is ideal for the simple case: "a pool of UTXOs share a PQ key; spend any subset in one tx with a single shared signature". That case wants:

- **1 tx** (no priming).
- **1 PQ signature** (not N).
- **No coordinator election** (whichever participant builds the tx attaches the sig).
- **No governance** over composition (any PQ_BATCH-gated input with the matching pubkey hash joins).

`PQ_BATCH` is designed for exactly this case.

## Semantics

Block type: `PQ_BATCH` (wire ID: **0x0A03** — QABI family slot, alongside `QABI_PRIME` (0x0A01) and `QABI_SPEND` (0x0A02)). Fits the "PQ batch primitives" family even though its mechanics differ from QABI's priming model.

### Conditions layout

```cpp
inline constexpr ImplicitFieldLayout PQ_BATCH_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},   // SHA256(falcon_pubkey_bytes)
}};
```

The committed hash is `SHA256(canonical_falcon_pubkey_encoding)`. Fund time commits just 32 bytes per input — same as any hash-bound block.

### Witness layout

At spend, the **anchor input** (exactly one input in the tx) carries:

```cpp
[PUBKEY    (falcon_pubkey_bytes, canonical 897 B for F-512 / 1793 B for F-1024 / 1952 B for Dilithium3),
 SIGNATURE (falcon_sig_bytes, variable 1..666 B for F-512 / 1..1280 B for F-1024 / 3293 B fixed for Dilithium3)]
```

The on-block field shape after `MergeConditionsAndWitness` is therefore `[HASH256, PUBKEY, SIGNATURE]` (3 fields) for the anchor and `[HASH256]` (1 field) for non-anchors — `EvalPQBatchBlock` pins these two exact shapes (E-020 / E-021).

Every **other** `PQ_BATCH`-gated input with the **same** `HASH256` just carries its MLSC proof — no per-input witness cost beyond the proof path.

### Evaluation rule (per-input)

```
EvalPQBatch(block, ctx):
    commit = FindField(block, HASH256)  // 32 bytes
    pubkey = FindField(block, PUBKEY)
    sig    = FindField(block, SIGNATURE)
    if pubkey && sig:
        // This input is the anchor (3-field shape).
        if SHA256(pubkey) != commit: return UNSATISFIED
        scheme = derive_scheme_from_pubkey_size(pubkey)   // 897/1793/1952 → F-512/F-1024/Dilithium3
        if !PQVerify(scheme, pubkey, ctx.tx.sighash, sig): return UNSATISFIED
        // Cache verified verdict by commit for sibling inputs.
        cache_set(commit, verified=true)
        return SATISFIED
    else:
        // Non-anchor input (1-field shape) — look up the cache.
        if cache_get(commit) == true: return SATISFIED
        return UNSATISFIED
```

Evaluator caches verification results at the tx level keyed by `(commit, sighash)`. First `PQ_BATCH` input in evaluation order with witness becomes the anchor; subsequent inputs with matching `commit` reuse the cached result without re-verifying.

### Canonical pubkey encoding

FALCON and Dilithium have multiple serialisation formats. We pin a canonical encoding for hash consistency:

- **FALCON-512**: 897-byte reference encoding (NIST round 3 submission format).
- **FALCON-1024**: 1793-byte reference encoding.
- **Dilithium3**: 1952-byte reference encoding.
- **SPHINCS+**: excluded — SPHINCS+ is stateless, signatures are ~13 kB each; aggregation has no meaningful cost benefit.

The PQ scheme is derived from witness `PUBKEY` size at evaluation time (pk_size → scheme: 897 → FALCON-512, 1793 → FALCON-1024, 1952 → Dilithium3). The committed `HASH256` binds the exact pubkey bytes (length included), so an attacker cannot equivocate the scheme via a SHA256 collision. Pubkey sizes are canonical per scheme; FALCON/Dilithium signatures are variable-length up to a per-scheme maximum, so pubkey-size discrimination keeps the evaluator correct regardless of the signer's compaction choice.

## Scope & constraints

- **One anchor per `HASH256` value per tx.** The anchor must be the
  lowest-index `PQ_BATCH` input for that commit (`EvalPQBatchBlock`
  in `src/rung/blocks/qabi.cpp` documents the ordering requirement);
  later anchors for the same commit waste witness bytes but are not
  consensus-invalid — the evaluator uses the cached verdict.
- **Multiple distinct `HASH256` values in one tx are allowed.** Each commit group has its own anchor. Evaluator caches per `(commit, sighash)` key.
- **PQ_BATCH and QABI_SPEND can coexist** in the same tx provided they don't fight over the tx-level signature slot. QABI_SPEND uses `tx.aggregated_sig` (666B dedicated slot). PQ_BATCH uses input-level witness fields — no conflict.
- **No signature aggregation across distinct keys.** If 3 pubkey groups appear, 3 signatures are needed. This is a proto-level aggregation, not crypto-level.

## Cost model

Fund time, per input gated by `PQ_BATCH`:
- Conditions: 32 bytes (HASH256 commit).
- No pubkey fold into Merkle leaf.

Spend time, per tx carrying N inputs all gated by the same `PQ_BATCH(hash)`:
- Anchor input witness: `PREIMAGE_SIZE + SIGNATURE_SIZE + framing`.
  - FALCON-512: 897 + 666 + ~4 ≈ 1,567 bytes ≈ 392 vB.
- Non-anchor inputs: just the MLSC proof path ≈ 14 vB each.

For N=100 inputs:
- Anchor: 392 vB.
- Non-anchors: 99 × 14 = 1,386 vB.
- Total: **1,778 vB**, amortised **17.8 vB per input**.

Compare:
- 100 separate FALCON-512 per-input sigs: ~400 vB each = 40,000 vB (22× worse).
- QABIO batch: ~52 vB per input = 5,200 vB (2.9× worse).
- PQ_BATCH: 17.8 vB per input (best).

## Resolved design questions

1. **Anchor input election.** Resolved: lowest-index `PQ_BATCH` input
   per commit is the anchor. Implicit, no flag — script verification
   already runs in input order. The signer is responsible for placing
   the anchor first.

2. **Cache scope.** Resolved: the cache is keyed per-tx by
   `(commit, sighash)`. Multiple `PQ_BATCH` blocks with the same
   commit across different rungs of the same input share the verdict.

3. **Replay protection.** Resolved: the tx sighash is part of the
   signature, so a valid sig is bound to this specific tx. No replay
   risk.

4. **PQ scheme heterogeneity.** Resolved: `PQ_BATCH(F512)` and
   `PQ_BATCH(F1024)` can coexist in the same tx — they have distinct
   `HASH256` commits and distinct anchors. The scheme is derived
   from the anchor's `PUBKEY` size (897 / 1793 / 1952), and the
   committed hash binds the exact pubkey bytes.

5. **Soft-fork deployment.** Resolved: shipped 2026-04-24 as a new
   block type at wire ID **0x0A03** in the QABI family. Clean
   soft-fork addition — pre-v4 clients never see RUNG_TX outputs at
   all; v4 clients without `PQ_BATCH` support reject the block.

6. **Pubkey size limits.** Resolved by E-020 / E-021: the
   evaluator pins `PQ_BATCH` to one of two exact field shapes
   (`[HASH256]` non-anchor or `[HASH256, PUBKEY, SIGNATURE]` anchor)
   and then derives the scheme from the canonical PUBKEY length. A
   pubkey that doesn't match a known scheme size fails verification,
   so no separate `MAX_PQ_PUBKEY_SIZE` constant is needed.

## Implementation status (shipped 2026-04-24)

| Step | File(s) | Status |
|------|---------|--------|
| 1. Wire ID + enum + layout | `src/rung/types.h` | shipped |
| 2. Block evaluator + cache | `src/rung/blocks/qabi.cpp::EvalPQBatchBlock` | shipped |
| 3. Block registration + dispatch | `src/rung/blocks/qabi.cpp` registrar | shipped |
| 4. Sighash/serialization updates | `src/rung/serialize.cpp`, `src/rung/rpc.cpp` | shipped |
| 5. Engine block def + preset | `tools/ladder-engine/index.html` | shipped |
| 6. Functional test | `test/functional/feature_rung_pq_batch.py` + `feature_rung_pq_batch_stress.py` | shipped |
| 7. Documentation | `doc/ladder-script/BLOCK_LIBRARY.md`, `RUNG_TX_SPEC.md`, this spec | shipped |

## Comparison with existing primitives

| Use case | Best primitive |
|----------|----------------|
| Coordinator-governed batch (Ark, pools, issuance) | QABIO |
| Simple key-sharing pool (co-owned UTXOs, exchange sweeps) | **PQ_BATCH** |
| Single-signer PQ spend | `SIG` with scheme=FALCON |
| Threshold PQ | (not supported; see research dropped item #3) |
| Adversarial multi-party | (out of scope; Lightning-style) |

## Deferred (v2)

- Signature aggregation across distinct keys within a single tx (would require lattice-aware sig folding — not known to be safe).
- Cross-tx sig reuse (out of scope; each tx has its own sighash).
- Non-FALCON/Dilithium schemes beyond the currently-supported set.
