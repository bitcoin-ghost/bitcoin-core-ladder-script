# TX_MLSC — Transaction Format for v4 RUNG_TX

**Status:** Implemented in v4 RUNG_TX · 2026

> **Scope.** This document specifies the **transaction-level wire
> format** that wraps the MLSC commitment scheme — the `nVersion`,
> flag byte, output encoding, `qabi_block` / `aggregated_sig` tail,
> sizing relative to other Bitcoin output formats, soft-fork impact,
> and tx-level embedding-surface analysis.
>
> The lower-level **MLSC primitive itself** — leaf hashing,
> `merkle_pub_key`, `MLSCProof` structure, `VerifyMLSCProof`
> verification flow, coil layout, security properties of the Merkle
> construction, and the relevant constants — lives in
> [`MERKLE-UTXO-SPEC.md`](MERKLE-UTXO-SPEC.md). This doc references
> it rather than restating it.

---

## 1. Overview

A v4 RUNG_TX commits one shared MLSC `conditions_root` per transaction
(prefix byte `0xDF`). Each output is just a value (8 bytes on the
wire); the spending conditions are recovered from the commitment at
spend time via the `MLSCProof` carried in each input's witness
`stack[1]`. Each rung's coil declares which output it governs — the
output-to-rung binding is cryptographic (committed in the Merkle leaf
hash via the structural template), not a stored bitmask.

This is the PLC model applied to Bitcoin outputs: one ladder program
per transaction, multiple output coils.

---

## 2. Wire Format

```
nVersion:           int32 (= 4, RUNG_TX_VERSION)
dummy:              uint8 (= 0x00)
flags:              uint8 (= 0x02, TX_MLSC + witness)
vin_count:          varint
vin[]:              prevout(36) + scriptSig_len(1) + nSequence(4) per input
conditions_root:    32 bytes                       ← ONE root for entire tx
vout_count:         varint
vout[]:             nValue(8) per output            ← just values, nothing else
                    (if nValue == 0: data_len varint + data[1..40] for DATA_RETURN)
witness[]:          per-input spending witness — each contains
                    stack[0] LadderWitness + stack[1] MLSCProof
qabi_block_len:     CompactSize (0 if not a QABIO tx)
qabi_block[]:       QABIO tx-level batch block (0..QABI_BLOCK_MAX_HARD = 262,144 B)
aggregated_sig_len: CompactSize (0 if not a QABIO tx)
aggregated_sig[]:   FALCON-512 coordinator signature (1..666 B when present)
nLockTime:          uint32
```

**Source**: `primitives/transaction.h:213-265`.

### Output encoding

```
nValue:    int64    (8 bytes, little-endian satoshi amount)
```

Each non-DATA_RETURN output is exactly 8 bytes on the wire. No
scriptPubKey, no MLSC root, no rung_mask. Consensus requires
`nValue >= MIN_RUNG_OUTPUT_VALUE = 546 sats` for non-DATA_RETURN
outputs.

### DATA_RETURN encoding

DATA_RETURN is signalled wire-side by `nValue == 0` (the only legal
zero-value output type in v4). The deserialiser then reads:

```
nValue:      int64    (must be 0)
data_len:    varint   (1-40 bytes)
data:        bytes
```

On deserialisation the output is reconstructed as
`CTxOut(0, 0xDF || conditions_root || data)`. Maximum 1 DATA_RETURN
per transaction (`evaluator.cpp:537`).

### conditions_root

A 32-byte Merkle root over all rung and relay leaves in the shared
tree. Protocol-derived — not user-supplied. The leaf hashing,
verification, and proof structure are specified in
[`MERKLE-UTXO-SPEC.md`](MERKLE-UTXO-SPEC.md) §2-§7.

### qabi_block / aggregated_sig

The `qabi_block_len + qabi_block` and `aggregated_sig_len +
aggregated_sig` fields are zero-length in non-QABIO transactions (the
common case). For QABIO transactions, `qabi_block` carries the
coordinator's batch block (entries, output set, sighash binding) and
`aggregated_sig` carries the FALCON-512 coordinator signature. See
[`QABIO.md`](QABIO.md) for the QABIO ceremony.

---

## 3. Per-tx vs Per-input Validation

Validation runs at two layers:

- **Per-tx** (`CheckRungTxLevel` in `validation.cpp:2469`):
  - `ValidateRungOutputs`: every output is MLSC, ≤ 1 DATA_RETURN,
    every non-DATA_RETURN output ≥ `MIN_RUNG_OUTPUT_VALUE = 546 sats`.
  - PREIMAGE / SCRIPT_BODY count across all MLSC-spending inputs is
    bounded by the per-tx caps (see §6).
  - `qabi_block` / `aggregated_sig` coherence (length within bounds,
    FALCON sig parses) when present.

- **Per-input** (`VerifyRungTx`):
  - Witness stack must be 1, 2, or 3 elements.
  - Key-path (1 element): Schnorr against `conditions_root` as x-only
    pubkey, sighash via `LadderKeyPathSighash/v1`.
  - Script-path (2-3 elements): the proof verification and ladder
    evaluation flow specified in
    [`MERKLE-UTXO-SPEC.md`](MERKLE-UTXO-SPEC.md) §8.

---

## 4. Size and Fee Analysis

All vBytes are measured on the live build via the `mlsc_*_size_sweep`
boost tests in `src/test/rung_tests.cpp` and reproduced in
[`SIZING.md`](SIZING.md) and [`MEASUREMENTS.md`](MEASUREMENTS.md).
The numbers below match those tables row-for-row.

### Single payment (1 input, 1 output)

| Format | Signature | vBytes | Fee (10 sat/vB) |
|--------|-----------|--------|-----------------|
| P2PKH | ECDSA | 192 | 1,920 sats |
| P2WPKH | ECDSA | 110 | 1,100 sats |
| P2TR key-path | Schnorr | 111 | 1,110 sats |
| **TX_MLSC key-path** | **Schnorr** | **109** | **1,090 sats** |

### Standard payment (1 input, 2 outputs)

| Format | Signature | vBytes | Fee (10 sat/vB) |
|--------|-----------|--------|-----------------|
| P2PKH | ECDSA | 226 | 2,260 sats |
| P2WPKH | ECDSA | 141 | 1,410 sats |
| P2TR key-path | Schnorr | 155 | 1,550 sats |
| **TX_MLSC key-path** | **Schnorr** | **127** | **1,270 sats** |
| TX_MLSC script-path (no tweak) | Schnorr | 148 | 1,480 sats |

### Batch payment (1 input, N MLSC outputs)

| Outputs | P2WPKH | P2TR | **TX_MLSC** | Saving vs P2WPKH |
|---------|--------|------|-------------|------------------|
| 2 | 141 vB | 155 vB | **127 vB** | 10% |
| 10 | 389 vB | 499 vB | **191 vB** | 51% |
| 100 | 3,179 vB | 4,369 vB | **911 vB** | 71% |

TX_MLSC is the cheapest format for 2+ MLSC outputs. At N=100, **71%
cheaper than P2WPKH** and **79% cheaper than P2TR**.

### Per-output asymptote

Per-output marginal cost asymptotes to ~8 vB (TX_MLSC) vs ~31 vB
(P2WPKH) and ~43 vB (P2TR) — a 4-5× per-output saving at large N.

### Chainstate per coin

Per `MERKLE-UTXO-SPEC.md` §11 (Chainstate Compression): TX_MLSC coins
compress to **3 bytes** in chainstate, vs 24 B (P2WPKH) and 36 B
(P2TR) — 8-12× smaller per coin. The 32-byte `conditions_root` is
stored once per transaction in the synthetic UTXO entry at
`(txid, MLSC_ROOT_VOUT = 0xFFFFFFFF)`.

### Post-quantum

PQ signatures (FALCON-512, FALCON-1024, Dilithium3, SPHINCS+) are
supported via the SCHEME byte. Per-input PQ signatures inflate the
witness; the `PQ_BATCH` and `QABIO` blocks amortise that cost across
N inputs (see [`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md) and
[`QABIO.md`](QABIO.md) for amortised vB tables).

---

## 5. Privacy Analysis

### What is visible at creation time

| Data | Visible | Notes |
|------|---------|-------|
| Output values | Yes | 8 bytes each, on the wire |
| `conditions_root` | Yes | 32 bytes, protocol-derived |
| Number of outputs | Yes | varint count |
| Number of rungs | No | Hidden inside the Merkle tree |
| Block types per rung | No | Revealed only on spend |
| Field values | No | Hidden in `value_commitment` until spend |
| Pubkeys / key identities | No | Folded into the leaf hash via `merkle_pub_key`, never on-chain at fund time |
| Hash commitments | No | Hidden in `value_commitment` |
| Timelock values | No | Hidden in `value_commitment` |

### What is visible at spend time

Only the exercised rung's full conditions (block types, field values)
and the witness pubkeys feeding `merkle_pub_key`. All other rungs
remain hidden behind their leaf hashes (revealed only as `proof_hashes`
in the `MLSCProof`).

### Position

Structure visible, identity hidden. Comparable to a Taproot
script-path spend (which reveals the script structure), except
applied uniformly across every output of the transaction rather than
per-output. The sensitive data — who controls the funds, which
spending paths exist — remains private until each path is taken.

---

## 6. Embedding Surface

The protocol bounds attacker-controllable bytes per transaction but
does not zero them — every commit-reveal scheme is structurally the
same in this respect (P2WSH commits 32 B per output, P2TR commits 32 B
per output, TX_MLSC commits 32 B per tx).

Per-tx caps relevant at the transaction level:

| Channel | Per-instance | Per-tx cap | Notes |
|---------|--------------|------------|-------|
| `conditions_root` | 32 B | 1 per tx | Protocol-derived, recomputed and compared on spend |
| `DATA_RETURN` block | up to 40 B | 1 block per tx | Zero-value output, payload is the application-defined commitment |
| `PREIMAGE` (witness) | up to 32 B | `MAX_PREIMAGE_FIELDS_PER_TX = 2` | Hash-bound to a HASH256 in conditions |
| `SCRIPT_BODY` (witness) | up to 80 B | `MAX_SCRIPT_BODY_FIELDS_PER_TX = 1` | Hash-bound, used by legacy P2SH/P2WSH/P2TR_SCRIPT wrappers |
| `qabi_block` (QABIO only) | up to 262,144 B | 1 per tx | Bounded by `QABI_BLOCK_MAX_HARD`; consensus-checked against the per-input committed root |
| `aggregated_sig` (QABIO only) | up to 666 B | 1 per tx | FALCON-512 coordinator sig, bounded by `QABI_AGGREGATED_SIG_MAX` |
| MLSC proof sibling hashes | 32 B per sibling | depth ≤ log₂(`MAX_RUNGS`) = 4 per input | Each sibling hashes an attacker-chosen subtree; bound by tree depth |
| `nLockTime` + `nSequence` | 4 + 4 per input | standard Bitcoin | Inherited from base tx format |

The MLSC-primitive level caps (per-block field counts, leaf-side
pubkey embedding, `IsDataEmbeddingType` rejection rules) live in
[`MERKLE-UTXO-SPEC.md`](MERKLE-UTXO-SPEC.md) §11. Full empirical
analysis in [`EMBEDDING_CHALLENGE.md`](EMBEDDING_CHALLENGE.md).

---

## 7. Impact on Existing Systems

| System | Change |
|--------|--------|
| Block types and evaluator | **No change.** All 65 block types and the AND-within-rung / OR-across-rungs evaluator are version-agnostic. |
| Sighash | **Two new tagged hashes** (`LadderSighash/v1`, `LadderKeyPathSighash/v1`) for v4 only. Pre-v4 sighash unchanged. |
| Descriptor language | **Extended** with the `output()` wrapper that maps each output index to its rung set. |
| RPC | New `createrungtx` / `signrungtx` / `signladder` / `parseladder` / `formatladder` etc. — see [`RPC_REFERENCE.md`](RPC_REFERENCE.md). Existing RPCs unchanged. |
| MLSC Merkle tree | New code path under `src/rung/conditions.cpp`; not invoked by pre-v4 tx validation. |
| Witness reference / diff witness | Cross-input diff witnesses share the same `conditions_root` — see [`MERKLE-UTXO-SPEC.md`](MERKLE-UTXO-SPEC.md) §14. |
| Block validation performance | Per tx: R template validations + R SHA256 (leaf hashes) + (R-1) SHA256 (tree) + 1 comparison. 100-rung tx ≈ 200 SHA256 ops — negligible. |
| Pruning | Spending-side `MLSCProof` lives in the witness — prunable after validation. |
| Light clients / SPV | No effect — light clients trust full nodes' verification, same as signatures. |
| Backwards compatibility | v4 RUNG_TX is additive; v1/v2/v3 transactions continue to work unchanged. The Legacy block family (P2PK_LEGACY..P2TR_SCRIPT_LEGACY) provides the bridge for pre-v4 outputs. |

---

## 8. Implementation Checklist

Reference items, ticked against the canonical
`bitcoin-core-ladder-script` repository:

### Core integration (`src/rung_shims.h` + ~1,600-line patch across 32 modified files)

- [x] Transaction serialisation: `conditions_root` field, 8-byte
  output format, `qabi_block` + `aggregated_sig` tail.
- [x] DATA_RETURN detection via `nValue == 0` (no separate sentinel).
- [x] UTXO set: synthetic root entry at
  `(txid, MLSC_ROOT_VOUT = 0xFFFFFFFF)`, prefix byte `0xDE`
  (compressor-resistant).
- [x] Compressor type `0x06` → 1-byte SPK marker for MLSC coins.
- [x] `CheckRungTxLevel` per-tx hook (`validation.cpp:2469`).
- [x] `VerifyRungTx` per-input (script verification, key-path /
  script-path dispatch, MLSCProof verification).

### MLSC primitive (`src/rung/conditions.{h,cpp}`)

- [x] Tagged-hash domains (`LadderLeaf/v1`, `LadderInternal/v1`,
  `LadderRelayLeaf/v1`).
- [x] `BuildMerkleTree` with sorted-pair interior and `MLSC_EMPTY_LEAF`
  padding.
- [x] `MLSCProof` (de)serialisation in three modes (FULL_LEAVES /
  MERKLE_PATH / SHARED).
- [x] `VerifyMLSCProof` with optional `MLSCVerifiedLeaves` capture for
  covenant evaluators.
- [x] `ExtractBlockPubkeys` / `merkle_pub_key` fold.
- [x] LadderTweak / `CheckLadderTweak` for key-path enablement.

### RPC + descriptor (`src/rung/rpc.cpp`, `src/rung/descriptor.{h,cpp}`)

- [x] `createrungtx` builds v4 transactions with the shared-tree shape.
- [x] `signrungtx` / `signladder` produce per-input `MLSCProof` in
  witness `stack[1]`.
- [x] `parseladder` / `formatladder` round-trip the descriptor with
  `output()` wrappers.

### Tests

- [x] Positive vector fixtures (`rung_tx_vectors.json`, 68 vectors)
  covering ~25 block types across the eight witness-rule families.
- [x] Negative vectors (`rung_tx_neg_vectors.json`, 76 vectors).
- [x] Fund+spend vectors (`rung_tx_spend_vectors.json`, 26 vectors).
- [x] Sizing sweeps (`mlsc_creation_tx_size_sweep`,
  `mlsc_spend_tx_size_sweep`, `mlsc_spend_path_sweep`,
  `mlsc_utxo_storage_size`, `qabi_tx_size_sweep`).
- [x] Anti-spam coverage (`feature_rung_anti_embedding`).
- [x] Cross-rung mutation, RECURSE_* covenant, and TLA+ specs (27
  models under `spec/`).

---

## 9. Open Questions

1. **Tree leaf ordering.** The current canonical order is
   `[rung_leaf[0..N-1], relay_leaf[0..M-1]]`. Output-grouped ordering
   (all rungs for output 0 before all rungs for output 1) would
   shorten typical proof paths but complicates relay positioning.
   Resolution deferred — current order is locked for v1.0.

2. **Rung sharing across outputs.** Each rung's coil carries a single
   `output_index`. Two outputs that share spending logic must each
   carry their own copy of the rung with a different `output_index`.
   This is a minor duplication. Recommendation: no rung sharing,
   duplicate if needed; the inner-Merkle-pubkey commitment in
   MULTISIG already provides the equivalent of rung-sharing for the
   most common case (N-of-M shared signers).

3. **Activation parameters.** The deployment bit, start time, and
   timeout are out of scope for this BIP. They will be specified in
   a separate activation document at the time of mainnet proposal.

4. **`UNLOCK_TO` coil type.** Reserved (`0x02`) but not yet wired to
   any consensus check. A future wire-format upgrade may bind output
   structure on-chain via a CTV-style template hash on the coil.

---

*TX_MLSC Specification · Ladder Script Project · 2026*
