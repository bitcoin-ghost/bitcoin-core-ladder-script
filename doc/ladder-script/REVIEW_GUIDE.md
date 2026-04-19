# Ladder Script Review Guide

This guide walks code reviewers through the Ladder Script implementation. The system
comprises 64 block types across 10 families, implemented in
22 source files under `src/rung/`.

## File-by-File Walkthrough

### types.h (single source of truth)
The largest header. Defines all block types (`RungBlockType` enum), all data types
(`RungDataType` enum), structural types (`RungCoil`, `RungField`, `RungBlock`, `Rung`,
`Relay`, `LadderWitness`, `WitnessReference`), and metadata functions:
- `IsKnownBlockType()` — allowlist of 64 types (codes 0x0201/0x0202 reserved, not known)
- `IsInvertibleBlockType()` — explicit allowlist; key-consuming blocks excluded
- `IsKeyConsumingBlockType()` — blocks whose pubkeys fold into Merkle leaves
- `PubkeyCountForBlock()` — fixed or variable pubkey count per block type
- `IsDataEmbeddingType()` — high-bandwidth types blocked in layout-less blocks
- Micro-header table (128 slots, 63 assigned, 2 reserved as 0xFFFF)
- Implicit field layouts (per block type, per context)
- `BlockDescriptor` table and `LookupBlockDescriptor()`
- `VerifyImplicitLayoutPairing()` — runtime init check for layout consistency

**What to look for:** Ensure every new block type is added to `IsKnownBlockType`, the
micro-header table, the implicit layout switch, the `BlockDescriptor` table, and
`VerifyImplicitLayoutPairing`'s whitelist if conditions-only.

### evaluator.h / evaluator.cpp
Core evaluation engine. Key review points:
- `EvalBlock()` dispatch: every block type must have a case; unknown types return `UNKNOWN_BLOCK_TYPE`
- `EvalRung()`: AND logic; all blocks must be SATISFIED; checks relay_refs against cached relay results
- `EvalLadder()`: OR logic; evaluates relays first via `EvalRelays()`, then tries rungs; `satisfied_rung_out` reports which rung passed
- `VerifyRungTx()`: top-level entry point. Per-tx (first input only): `ValidateRungOutputs()`, creation proof (3+ outputs), PREIMAGE count. Per-input: key-path (1 elem) or script-path (2-3 elem), Merkle proof, merge, evaluate.
- `ValidateRungOutputs()`: consensus rule — every output must be MLSC (`0xDF`), max 1 DATA_RETURN, dust threshold (546 sats). Runs first, not last.
- `api::LadderSigChecker` (in `rung/api.h`): adapter interface for Ladder-native sig verification. Core-side impl is `CoreLadderSigChecker` in `rung_shims.h`. Library computes the Ladder sighash via `api::SignatureHashLadder`; the checker no longer carries conditions.
- `ApplyInversion()`: ERROR unchanged; UNKNOWN inverted becomes ERROR

**What to look for:** Fail-closed behaviour for unknown types. Correct relay evaluation
order (index 0 first, forward-only).

### sighash.h / sighash.cpp
Sighash computation. Tagged hash `"LadderSighash"`. Commits to epoch, hash_type, tx data,
conditions hash (unless ANYPREVOUTANYSCRIPT).
- Valid hash types: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`
- ANYPREVOUT (0x40): skips prevout hash, keeps amounts/sequences/conditions
- ANYPREVOUTANYSCRIPT (0xC0): skips prevout and conditions

**What to look for:** MLSC outputs use `conditions_root` directly as the conditions hash
(no re-serialisation). Key-path uses `SignatureHashLadderKeyPath` (separate tagged hash
`"LadderKeyPathSighash"` — does not commit to conditions). All outputs use MLSC (`0xDF`).

### serialize.h / serialize.cpp
Wire format. Key constants: MAX_RUNGS=16, MAX_BLOCKS_PER_RUNG=8, MAX_FIELDS_PER_BLOCK=16,
MAX_LADDER_WITNESS_SIZE=100000, MAX_PREIMAGE_FIELDS_PER_WITNESS=2 (per-input),
MAX_PREIMAGE_FIELDS_PER_TX=2 (per-transaction, binding), MAX_RELAYS=8,
MAX_RELAY_DEPTH=4.
- `DeserializeLadderWitness()`: fail-closed; rejects unknown types, deprecated blocks, non-invertible inversion, data-embedding types in layout-less blocks, trailing bytes
- Diff witness mode: `n_rungs == 0` signals witness reference; diffs restricted to PUBKEY/SIGNATURE/PREIMAGE/SCRIPT_BODY/SCHEME
- `DeserializeBlock()`: shared by witness and MLSC proof deserialization
- Implicit field encoding: micro-header + layout match = omit field count/types

**What to look for:** Strict field enforcement in explicit mode (count and types must match
layout when layout exists). DATA type restricted to DATA_RETURN. ACCUMULATOR whitelisted
from IsDataEmbeddingType check.

### conditions.h / conditions.cpp
MLSC conditions system. MLSC prefix `0xDF`. Inline conditions 0xC1 removed (stubs return false). Creation proof validated at block acceptance. Leaf computation uses `TaggedHash("LadderLeaf", structural_template || value_commitment)`. Each rung's coil has `output_index` declaring which output it governs.
- `IsConditionDataType()`: HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX, DATA allowed; PUBKEY_COMMIT removed
- Merkle tree: sorted interior hashing, `MLSC_EMPTY_LEAF` padding
- Leaf order: rungs, then relays, then coil
- `VerifyMLSCProof()`: reconstructs leaf array, builds tree, compares root
- `MLSCVerifiedLeaves`: cached for covenant evaluators (avoids recomputing from all pubkeys)
- `ResolveTemplateReference()`: copies conditions from referenced input, applies diffs, no chaining

**What to look for:** Proof verification must reject mismatched total_rungs/total_relays.
Template references cannot chain (source must not be a template ref).

### descriptor.h / descriptor.cpp
Human-readable descriptor language. Grammar: `ladder(or(...))` with blocks as lowercase
functions. Supports `!block` for inversion. Scheme names: schnorr, ecdsa, falcon512,
falcon1024, dilithium3, sphincs_sha.

### policy.h / policy.cpp
Mempool policy. `IsStandardRungTx()` delegates to the consensus deserializer for structural
validation, then checks all outputs are MLSC. Classification functions: `IsBaseBlockType()`,
`IsCovenantBlockType()`, `IsStatefulBlockType()`.

### pq_verify.h / pq_verify.cpp
Post-quantum signature verification for FALCON-512, FALCON-1024, Dilithium3, SPHINCS+.

### aggregate.h / aggregate.cpp
Half-aggregated Schnorr signature computation. Aggregates per-input R-values with a
shared s-value at the transaction level. Used by `AGGREGATE` attestation mode.

### rpc.cpp
15 RPC commands: decoderung, createrung, validateladder, createtxmlsc, signladder,
createrungtx (legacy), signrungtx (legacy), computectvhash, computemutation,
generatepqkeypair, pqpubkeycommit, extractadaptorsecret, verifyadaptorpresig,
parseladder, formatladder.

**What to look for:** Auto-conversion in `createrung`: PUBKEY in conditions becomes Merkle
leaf entry; PREIMAGE/SCRIPT_BODY becomes HASH256/HASH160; blanket HASH256 rejection with
whitelist (CTV, TAGGED_HASH, ACCUMULATOR, COSIGN, OUTPUT_CHECK).

## User-Chosen Arbitrary Data Limits (112 bytes per transaction)

Total user-chosen arbitrary data: 64 bytes (PREIMAGE) + 40 bytes (DATA_RETURN) + 8 bytes
(nLockTime + nSequence) = 112 bytes, flat regardless of output count.

1. **Fail-closed deserialisation.** Unknown block types, unknown data types, and deprecated
   blocks are rejected. Trailing bytes cause failure.
2. **Selective inversion.** Explicit allowlist. Key-consuming blocks never invertible.
3. **IsDataEmbeddingType.** PUBKEY_COMMIT, HASH256, HASH160, and DATA blocked in blocks
   without implicit layouts.
4. **PREIMAGE/SCRIPT_BODY cap.** Maximum 2 per witness and 2 per transaction (combined).
5. **DATA type restriction.** Only allowed in DATA_RETURN blocks (max 40 bytes).
6. **merkle_pub_key.** Pubkeys in Merkle leaves, not condition fields.
7. **Blanket HASH256 rejection in RPC.** Whitelisted block types only.

## TLA+ Formal Specifications

21 specs in `spec/` with 197 checked properties (2.5B states verified, zero errors):

| Spec | Focus |
|------|-------|
| LadderEval.tla | Rung/ladder evaluation, inversion, recursion termination |
| LadderEvalCheck.tla | Type invariants and safety for evaluation |
| LadderBlockEval.tla | Individual block evaluation |
| LadderComposition.tla | AND/OR composition with relays |
| LadderAntiSpam.tla | User-chosen data field limits |
| LadderWireFormat.tla | Wire format serialization invariants |
| LadderMerkle.tla | Merkle tree construction and verification |
| LadderSighash.tla | Sighash computation properties |
| LadderCovenant.tla | Covenant/recursion termination and safety |
| LadderCrossInput.tla | Cross-input (COSIGN) dependencies |
