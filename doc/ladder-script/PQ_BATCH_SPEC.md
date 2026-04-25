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
[PREIMAGE (falcon_pubkey_bytes, variable 897B for F-512 / 1793B for F-1024 / 1952B for Dilithium3),
 SIGNATURE (falcon_sig_bytes, variable 666B for F-512 / 1280B for F-1024 / 3293B for Dilithium3)]
```

Every **other** `PQ_BATCH`-gated input with the **same** `HASH256` just carries its MLSC proof — no per-input witness cost beyond the proof path.

### Evaluation rule (per-input)

```
EvalPQBatch(block, ctx):
    commit = FindField(block, HASH256)  // 32 bytes
    if block has witness PREIMAGE + SIGNATURE:
        // This input is the anchor.
        if SHA256(preimage) != commit: return UNSATISFIED
        if !PQVerify(preimage_as_pubkey, ctx.tx.sighash, signature): return UNSATISFIED
        // Cache (commit, tx_sighash, verified=true) in ctx for siblings.
        cache_set(commit, verified)
        return SATISFIED
    else:
        // Non-anchor input — look up the cache.
        if cache_get(commit) == verified: return SATISFIED
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

- **One anchor per `HASH256` value per tx.** Multiple anchors for the same commit would waste witness bytes but are not consensus-invalid — evaluator uses first-seen.
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

## Open design questions

1. **Anchor input election.** First-seen in evaluation order? Or require an explicit "anchor" flag? First-seen is simpler; explicit flag is safer if block ordering ever changes.

2. **Cache scope.** Should the cache survive across `PQ_BATCH` blocks in different rungs of the same input? Probably yes — one input could have multiple `PQ_BATCH` blocks with the same hash (pointless but legal).

3. **Replay protection.** The tx sighash is part of the signature, so a valid sig is bound to this specific tx. No replay risk.

4. **PQ scheme heterogeneity.** Can `PQ_BATCH(F512)` and `PQ_BATCH(F1024)` coexist in the same tx? Yes — they have distinct `HASH256` commits and distinct anchors. Evaluator just processes them separately.

5. **Soft-fork deployment.** Since this is a new block type in an unused wire slot (0x0301), it's a clean soft-fork addition. No existing clients would accept `PQ_BATCH` blocks; new clients reject if the block evaluator rejects.

6. **Pubkey size limits.** The `PREIMAGE` field type currently has no fixed upper bound. We should cap at `MAX_PQ_PUBKEY_SIZE = 2048 bytes` to prevent abuse. Anything larger than 1793 (FALCON-1024) is a waste.

## Implementation plan

| Step | File(s) | Est. effort |
|------|---------|-------------|
| 1. Wire ID + enum + layout | `src/rung/types.h` | 15 min |
| 2. Block evaluator + cache | `src/rung/blocks/pq_batch.cpp` (new) | 2-3 hours |
| 3. Block registration + dispatch | `src/rung/blocks/*.cpp` registrars | 10 min |
| 4. Sighash/serialization updates | `src/rung/serialize.cpp`, `src/rung/rpc.cpp` (ParseBlockSpec) | 1 hour |
| 5. Engine block def + preset | `tools/ladder-engine/index.html` | 1 hour |
| 6. Functional test | `test/functional/feature_rung_pq_batch.py` (new) | 2 hours |
| 7. Documentation | `doc/ladder-script/BLOCK_LIBRARY.md`, `RUNG_TX_SPEC.md` | 30 min |

Total: ~7 hours across a full day with review + rebuild cycles.

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
