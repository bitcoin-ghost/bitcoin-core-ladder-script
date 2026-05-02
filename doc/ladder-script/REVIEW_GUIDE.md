# Ladder Script Reviewer Guide

Audience: Bitcoin Core developers, BIP reviewers, security researchers.

Purpose: map the code a reviewer must verify, distinguish **load-bearing** consensus
surface from **optional** convenience code, and cross-reference the per-section prose in
`ANNOTATED_DIFF.md` with the library files.

## The Two Artefacts

Ladder Script ships as two distinct things:

| Artefact | LOC | Scope | Reviewer doc |
|----------|-----|-------|--------------|
| **Core Integration Patch** | 961 (insertions) | 33 modified Bitcoin Core files (`src/primitives/`, `src/script/`, `src/validation.*`, `src/policy/`, `src/coins.*`, `src/compressor.*`, `src/core_write.cpp`, `src/key.*`, `src/pubkey.*`, `src/rpc/*`) | [`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md) |
| **Ladder Library** | 21,251 | Self-contained module: 38 files under `src/rung/` plus the `src/rung_shims.h` boundary header | [`ANNOTATED_LIBRARY.md`](ANNOTATED_LIBRARY.md) and this document |

No existing Bitcoin Core function signatures change. The `CScriptCheck` constructor
gains four defaulted parameters (block height + three per-tx cache `shared_ptr`s); every
existing call site continues to compile unchanged. No existing opcode is modified.
Transaction version 4 is additive.

## Suggested Reading Order

1. `TLDR.md` — one-page summary.
2. [`SIZING.md`](SIZING.md) — measured wire sizes and chainstate cost.
3. `RUNG_TX_SPEC.md` — the new transaction format.
4. `TX_MLSC_SPEC.md` — the MLSC output format and Merkle tree.
5. [`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md) — per-section walkthrough of the Core Integration Patch.
6. [`ANNOTATED_LIBRARY.md`](ANNOTATED_LIBRARY.md) — file-by-file library reference.
7. [`RPC_REFERENCE.md`](RPC_REFERENCE.md) — every RPC the library adds.
8. This document — library walkthrough with load-bearing vs optional callouts.

## Legend

Every file entry below uses this structure:

- **Path** — absolute path within repo.
- **Purpose** — what this file *is*.
- **Behaviour** — what this file *does* at runtime.
- **Load-bearing invariants** — properties that *cannot* change without changing
  consensus semantics. A reviewer must verify these.
- **Optional / removable** — sections that can be trimmed from a minimum-viable BIP
  submission without breaking the core surface. Each item names what would be lost.

---

# Part 1 — Boundary

## `src/rung_shims.h` (353 LOC)

- **Purpose**: the one-way Core↔library boundary. All includes of Core headers
  (`<primitives/transaction.h>`, `<script/interpreter.h>`, `<consensus/validation.h>`)
  from the library must go through this file. The library is otherwise Core-free.
- **Behaviour**: adapter types and inline functions that map Core's
  transaction/script/signature objects onto the library's span-based
  public API (`rung/api.h`). Notable members:
  - `CoreLadderSigChecker` — adapts `BaseSignatureChecker` to
    `rung::api::LadderSigChecker`.
  - `LadderTxViewBuilder` — constructs a `LadderTxView` from a
    `CTransaction` (no copy; spans into the source).
  - `LadderPrecomputedBuilder` — wraps `PrecomputedTransactionData` for the
    library's sighash midstate.
  - Inline script recognisers/constructors: `IsMLSCScript`, `IsLadderScript`,
    `IsCompactMLSC`, `GetMLSCRoot`, `CreateMLSCScript`, plus the conditions
    parse/serialise overloads, the QABIO state checks, and sighash entries
    (`SignatureHashLadder`, `SignatureHashLadderKeyPath`, `ComputeSighashQABO`,
    `ComputeCTVHash`).
- **Load-bearing invariants**:
  - The boundary is *one-way*: Core code includes `rung_shims.h`; library code does not.
    If the library ever included a Core header directly, it becomes unshippable as a
    self-contained module.
  - Adapter types must copy by value or wrap spans; they must not hold references to
    stack-local Core objects beyond the immediate call.
- **Optional / removable**: none. This file is the entire reason the library compiles
  against a stable public API rather than Core's entire header tree.

## `src/rung/api.h` (528 LOC)

- **Purpose**: the library's **public** interface. Declares span-based data views
  (`LadderTxView`, `LadderSigChecker`), the evaluator context (`LadderEvalContext`), the
  top-level entry point (`VerifyRungTx`), and the `LadderScriptError` enum.
- **Behaviour**: compile-time contract between Core and the library. Adding any
  non-span types here couples the library back to Core.
- **Load-bearing invariants**:
  - `LadderScriptError` enum values are wire-stable; never renumber.
  - `VerifyRungTx` must remain the single entry point for script validation.
- **Optional / removable**: the `QABI*` surface (≈40 lines) is optional — see QABIO
  section below.

---

# Part 2 — Central Types

## `src/rung/types.h` (1566 LOC) / `types.cpp` (46 LOC)

- **Purpose**: single source of truth for block types, data types, structural types, and
  metadata tables. Every other file depends on these.
- **Behaviour**:
  - `enum class RungBlockType : uint16_t` — 65 block types across 11 families.
  - `enum class RungDataType : uint8_t` — field data types (PUBKEY, SIGNATURE, NUMERIC,
    HASH256, HASH160, PREIMAGE, SCRIPT_BODY, DATA, SCHEME, SPEND_INDEX, PUBKEY_COMMIT).
  - Structural types: `RungCoil`, `RungField`, `RungBlock`, `Rung`, `Relay`,
    `LadderWitness`.
  - Metadata tables and predicates: `IsKnownBlockType`, `IsInvertibleBlockType`,
    `IsKeyConsumingBlockType`, `IsDataEmbeddingType`, `PubkeyCountForBlock`,
    `MicroHeaderSlot`, `LookupBlockDescriptor`, `VerifyImplicitLayoutPairing`.
- **Load-bearing invariants**:
  - Every `RungBlockType` enum value is on the wire. **Never renumber**. Reserved slots
    (`0x0201`, `0x0202`) stay reserved — they were previously occupied and must never be
    reused to prevent cross-version collisions.
  - `IsKnownBlockType` is the authoritative allowlist. If a block type is not here,
    consensus rejects it.
  - `IsInvertibleBlockType` must remain an **allowlist** (deny by default). Key-consuming
    blocks (SIG, MULTISIG, etc.) are *never* invertible — flipping a sig check upside
    down would break soundness.
  - `MicroHeaderSlot` table must match `ImplicitLayoutFor(type, context)`. The runtime
    check `VerifyImplicitLayoutPairing()` enforces this on library init — don't disable
    it.
  - `IsDataEmbeddingType` gates anti-spam: DATA, HASH256, HASH160, PUBKEY_COMMIT are
    blocked in blocks without implicit layouts.
- **Optional / removable** (block families you could trim for a minimum-viable BIP):
  - **Legacy family** (`0x0900-0x0907`): P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR,
    P2TR_SCRIPT wrappers. Removing them drops the ability to bridge legacy scripts into
    MLSC inputs; core functionality intact.
  - **PLC family** (`0x0600-0x06FF`): hysteresis, timers, latches, counters, sequencer,
    one-shot, rate-limit, cosign. These are programmable covenants built on NUMERIC
    field comparisons. A minimum-viable BIP could ship with just SIG/CSV/CLTV/CTV + the
    base recurse blocks. PLC adds roughly half the expressiveness of the system.
  - **Anchor family** (`0x0500-0x05FF`): ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE,
    ANCHOR_SEAL, ANCHOR_ORACLE. Optional — used for L2 bridges and oracle patterns.
  - **Governance family** (`0x0800-0x08FF`): EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT,
    OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK. Removing these drops tx-
    shape introspection.
  - **QABIO** (`QABI_PRIME`, `QABI_SPEND`): see QABIO section. Bounded by
    `#ifdef LADDER_ENABLE_QABIO`.
  - **Advanced recurses**: `RECURSE_COUNT`, `RECURSE_SPLIT`, `RECURSE_DECAY` are
    variations on `RECURSE_MODIFIED`. The minimum-viable covenant surface is
    `RECURSE_SAME` + `RECURSE_MODIFIED` + `RECURSE_UNTIL`.
  - **Compound blocks** (`0x0700-0x07FF`, except where structurally needed): HTLC, PTLC,
    TIMELOCKED_SIG, etc. can be implemented as compositions of base blocks. The compound
    encoding is a size optimisation.

---

# Part 3 — Consensus Surface (load-bearing)

## `src/rung/evaluator.h` (369 LOC) / `evaluator.cpp` (1301 LOC)

- **Purpose**: top-level validation. This is the entry point Bitcoin Core calls to
  validate a v4 input.
- **Behaviour**:
  - `VerifyRungTx(tx, input_idx, spent_output, ctx, error_out)` — the single consensus
    entry point. Handles both key-path (1-element witness) and script-path (2 or 3
    element witness) spends.
  - `EvalLadder(...)` — OR logic: tries rungs in order, first SATISFIED wins.
  - `EvalRung(...)` — AND logic: every block must be SATISFIED.
  - `EvalBlock(...)` — dispatches to the registered evaluator for the block's type.
  - `ApplyInversion(...)` — only valid for types in `IsInvertibleBlockType`; UNKNOWN
    inverted becomes ERROR (fail-closed).
  - Per-tx checks (run once per v4 tx via `validation.cpp:2406`; redundant
    safety net inside the evaluator on `input_index == 0`):
    `ValidateRungOutputs` (all outputs must be MLSC, max 1 DATA_RETURN, dust
    threshold), creation proof (3+ outputs), PREIMAGE / SCRIPT_BODY count
    (anti-spam cap, summed across MLSC-spending inputs only since v0.10
    audit #6 F-2).
  - Merkle proof verification via `VerifyMerklePath` or `BuildMerkleTree` +
    `CheckLadderTweakRaw` (the latter for key-path spends using libsecp256k1's
    `xonly_pubkey_tweak_add_check`).
- **Load-bearing invariants**:
  - Every rejected spend returns `false` with `error_out` set. Never `return true` on an
    error path.
  - Unknown block types fail-closed (`ApplyInversion` turns UNKNOWN into ERROR for
    inverted blocks; non-inverted UNKNOWN is treated as UNSATISFIED so a rung's OR
    siblings can still satisfy — this mirrors Taproot's forward-compat behaviour for
    unknown leaf versions).
  - Tweak verification uses libsecp256k1 primitives, never a hand-rolled curve math
    path. `CheckLadderTweakRaw` mirrors `XOnlyPubKey::ComputeLadderTweakHash` in
    `src/pubkey.cpp` **byte-for-byte**; any divergence splits the network.
  - Per-tx checks run **before** per-input evaluation.
- **Optional / removable**: diagnostic `LogPrintf` calls on error paths help debugging
  but are not consensus-critical. They can be removed or gated behind a category.

## `src/rung/conditions.h` (310 LOC) / `conditions.cpp` (1078 LOC)

- **Purpose**: MLSC (Merkle Ladder Script Conditions) — the output format and Merkle
  tree. Leaves commit to rung structure + value_commitment. `ComputeValueCommitment`
  folds pubkeys into each leaf (merkle_pub_key binding).
- **Behaviour**:
  - `IsMLSCScript` / `GetMLSCRoot` / `HasMLSCData` — scriptPubKey classification
    (0xDF prefix).
  - `ComputeTxMLSCLeaf` — `TaggedHash("LadderLeaf/v1", structural_template || value_commitment)`.
  - `ComputeTxMLSCRoot` — builds the Merkle tree from leaves.
  - `BuildMerkleTree` / `VerifyMerklePath` — sorted interior hashing with tag
    `TaggedHash("LadderInternal/v1")`, empty-leaf padding via `MLSC_EMPTY_LEAF`.
  - `ComputeTweakedConditionsRoot` — key-path tweak: `output_pk = internal_pk + H("LadderTweak/v1", internal_pk || merkle_root) * G`.
  - `SerializeMLSCProof` / `DeserializeMLSCProof` — wire-format of the proof witness.
- **Load-bearing invariants**:
  - Tagged hash domain strings are versioned (`/v1`). Changing them splits consensus.
  - Merkle tree uses **sorted-pair** interior hashing (the smaller sibling is hashed
    first). This is distinct from BIP-340 taproot's parity-based hashing — ensures
    commutative proofs.
  - Leaf padding uses `MLSC_EMPTY_LEAF` (a specific all-zero tagged hash), not raw
    zeros. Don't substitute.
  - PUBKEY fields are stripped from `block.fields` during conditions parsing and folded
    into the value_commitment via `rung_pks` in positional order. Changing the order
    changes the leaf → changes the root.
- **Optional / removable**:
  - `SHARED` proof mode (cached-tree cross-input reference) is an optimisation for
    multi-input MLSC txs. `MERKLE_PATH` and `FULL_LEAVES` are the minimum set.
  - Mutation-target serialisation (trailing field of `MLSCProof`) is only needed if
    covenants with cross-rung mutation (RECURSE_MODIFIED pointing at non-self rungs) are
    in scope.

## `src/rung/serialize.h` (129 LOC) / `serialize.cpp` (1051 LOC)

- **Purpose**: wire format for `LadderWitness` (the per-input witness stream). Handles
  serialization and fail-closed deserialization of blocks, rungs, relays, and the
  MLSC proof.
- **Behaviour**:
  - `DeserializeLadderWitness` — parses a full witness stream, rejects unknown types /
    deprecated blocks / invalid inversion / data-embedding violations / trailing bytes.
  - `DeserializeBlock` — shared by witness and MLSC-proof paths. Accepts either the
    *micro-header* encoding (1 byte, indexed into `MicroHeaderSlot` table, omits field
    types/counts) or the *explicit* encoding.
  - `SerializeBlock` / `SerializeLadderWitness` — forward direction.
  - Diff witness: `n_rungs == 0` signals a template-diff reference to another input;
    diffs restricted to witness-only field types.
- **Load-bearing invariants**:
  - Size caps (`MAX_RUNGS`, `MAX_BLOCKS_PER_RUNG`, `MAX_FIELDS_PER_BLOCK`,
    `MAX_LADDER_WITNESS_SIZE`, `MAX_PREIMAGE_FIELDS_PER_*`, `MAX_RELAYS`,
    `MAX_RELAY_DEPTH`) are consensus rules. Changing them changes the anti-spam
    surface.
  - Fail-closed: anything not in an allowlist rejects. Never "try to be helpful".
  - PREIMAGE fields are capped to 2 per witness and 2 per transaction (binding). This
    closes the data-embedding vector.
  - Explicit encoding must match implicit layout when a layout exists (runtime check in
    `VerifyImplicitLayoutPairing`).
- **Optional / removable**: the micro-header encoding is a *size optimisation* for the
  common case. Removing it costs ~2 bytes per block; consensus semantics unchanged if
  kept consistent. A minimum-viable BIP could specify explicit-only encoding.

## `src/rung/sighash.h` (66 LOC) / `sighash.cpp` (224 LOC)

- **Purpose**: Ladder-specific signature hash. Tagged hashes
  `TaggedHash("LadderSighash/v1")` (script-path) and `TaggedHash("LadderKeyPathSighash/v1")`
  (key-path, does NOT commit to conditions).
- **Behaviour**: commits to epoch, hash_type, tx metadata (version, locktime), amounts
  and sequences via extension data, and the spent output's conditions_root.
- **Load-bearing invariants**:
  - Tagged hash domains are versioned.
  - Hash type set: `{0x00-0x03, 0x81-0x83}` — anything outside is rejected. The BIP-118
    ANYPREVOUT family (`0x40-0x43`) and ANYPREVOUTANYSCRIPT family (`0xC0-0xC3`) are
    unconditionally rejected pending a future opt-in mechanism (a dedicated block type
    or pubkey-prefix scheme); both flags allow signature replay against UTXOs the
    signer did not intend to spend, and Ladder Script does not currently provide the
    pubkey-prefix mitigation BIP-118 uses.
  - For MLSC outputs: `conditions_root` is hashed *as-is* (no re-serialisation). This is
    a consequence of the one-shared-root-per-tx wire format.
  - Key-path sighash deliberately *omits* conditions — the tweak already commits to
    them via the x-only tweak, so including them again is redundant and creates a
    cross-protocol signing-oracle risk.

## `src/rung/block_dispatch.h` (81 LOC) / `block_helpers.h` (107 LOC) / `block_helpers.cpp`

- **Purpose**: registry + helpers. Every block evaluator self-registers via
  `RegisterBlock(type, fn)`; `LookupBlockEvaluator(type)` returns it. Helpers:
  `FindField`, `FindAllFields`, `ReadNumeric`, `WriteNumericField`, `ParseMutationSpecs`,
  `VerifyMutatedLeaves`, `BuildCPRung`.
- **Load-bearing invariants**:
  - Every `IsKnownBlockType` entry must have a registered evaluator by the time the
    library is used. `VerifyImplicitLayoutPairing` doubles as a registration audit.
  - Numeric fields are normalised: `WriteNumericField` writes 4-byte little-endian;
    `ReadNumeric` reads up to 8 bytes signed. The value_commitment hasher also pads
    sub-4-byte NUMERIC fields to 4 bytes. Don't allow divergence.
- **Optional / removable**: none. These are the glue that makes the block registry
  work.

## `src/rung/blocks/sig.cpp` (334 LOC)

- **Purpose**: signature-family evaluators (SIG, MULTISIG, ADAPTOR_SIG,
  MUSIG_THRESHOLD, KEY_REF_SIG).
- **Behaviour**: each evaluator:
  1. Pulls PUBKEY + SIGNATURE from the merged witness.
  2. Calls `ctx.sig_checker` (the `LadderSigChecker` adapter) to verify.
  3. Returns `SATISFIED` / `UNSATISFIED` / `ERROR`.
- **Load-bearing invariants**:
  - Signature size validation (64 or 65 bytes for Schnorr depending on hash type) runs
    before the curve math, per BIP-340.
  - KEY_REF_SIG resolves against cached relay results — must check relay index bounds.
- **Optional / removable**:
  - ADAPTOR_SIG only supports Schnorr (no PQ path) by design — the PQ scheme rejection
    there is load-bearing.
  - MUSIG_THRESHOLD is a client-side-aggregated Schnorr; the library just verifies one
    signature against the aggregated key. Removing this block type drops MuSig2/FROST
    path.

## `src/rung/blocks/timelock.cpp` (161 LOC)

- **Purpose**: CSV, CSV_TIME, CLTV, CLTV_TIME.
- **Behaviour**: each consults `ctx.spending_sequence` (relative) or `ctx.tx->nLockTime`
  / `ctx.median_time_past` (absolute) and compares against the NUMERIC field.
- **Load-bearing invariants**: timelock arithmetic must mirror BIP-65 / BIP-112 exactly.
- **Optional / removable**: the `_TIME` variants (median-time-past-based) could be
  omitted for a height-only BIP; CSV/CLTV height-based are the minimum set.

## `src/rung/blocks/hash.cpp` (121 LOC)

- **Purpose**: TAGGED_HASH, HASH_GUARDED (raw SHA256 preimage check).
- **Load-bearing invariants**: HASH_GUARDED is non-invertible (see `IsInvertibleBlockType`).
- **Optional / removable**: HASH_GUARDED can be removed; TAGGED_HASH can be built from
  PREIMAGE+HASH256 composition if needed.

## `src/rung/blocks/covenant.cpp` (240 LOC)

- **Purpose**: CTV (BIP-119-compatible), VAULT_LOCK, AMOUNT_LOCK.
- **Behaviour**:
  - CTV computes the template hash over the tx (excluding witness + scriptSig) and
    compares against the field value.
  - VAULT_LOCK enforces either (recovery key, no delay) or (hot key + CSV delay).
  - AMOUNT_LOCK bounds `ctx.output_amount` between min and max NUMERIC fields.
- **Load-bearing invariants**: CTV hash must use `WriteLE32`/`WriteLE64` exactly per
  BIP-119. Don't hand-roll endianness.

## `src/rung/blocks/recursion.cpp` (351 LOC)

- **Purpose**: RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT,
  RECURSE_SPLIT, RECURSE_DECAY.
- **Behaviour**:
  - SAME / UNTIL — identity recurse: output root must equal input root.
  - MODIFIED / COUNT / DECAY — leaf-centric: expected root is the input tree with one
    leaf mutated per `MutationSpec`.
  - SPLIT — leaf-centric with 2-way output split.
- **Load-bearing invariants**:
  - `max_depth` field is the covenant termination guard. Reject if 0.
  - `VerifyMutatedLeaves` must use `BuildCPRung` + `ComputeTxMLSCLeaf` to recompute the
    mutated leaf; no shortcuts.
- **Optional / removable**: RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY are syntactic
  sugar over MODIFIED with a convention (decrement-by-1, 2-way split, negate-delta).
  Minimum-viable: SAME + MODIFIED + UNTIL.

## `src/rung/blocks/compound.cpp` (307 LOC)

- **Purpose**: TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG.
- **Behaviour**: each is a composition — e.g. HTLC = PREIMAGE reveal + CSV delay + SIG
  on receiver key, plus a cross-branch for the refund path.
- **Optional / removable**: all compound blocks can be expressed as compositions of
  base blocks at larger witness cost. Compound encoding is a size optimisation with its
  own implicit layout.

## `src/rung/blocks/plc.cpp` (429 LOC)

- **Purpose**: Programmable Logic Controller family — HYSTERESIS_FEE, HYSTERESIS_VALUE,
  TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET,
  COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN.
- **Behaviour**: stateful or state-like comparators over NUMERIC fields; `COSIGN`
  requires another input in the same tx whose spent SPK hashes to the given
  `conditions_hash`.
- **Optional / removable**: the whole family is optional for a minimum-viable BIP.
  Their existence is what lets users express "rate-limit wallet", "dead-man's switch",
  "counter-down DCA", etc. — the system is significantly less useful without them, but
  they are *not* consensus-critical for non-PLC tx patterns.

## `src/rung/blocks/anchor.cpp` (268 LOC)

- **Purpose**: ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL,
  ANCHOR_ORACLE, DATA_RETURN.
- **Behaviour**: bridge primitives for L2 / oracle patterns. DATA_RETURN is the MLSC
  equivalent of OP_RETURN.
- **Load-bearing invariants**: DATA_RETURN is the *only* block where a DATA field is
  valid (enforced in `IsDataEmbeddingType`). Max 40 bytes.
- **Optional / removable**: everything except DATA_RETURN is optional.

## `src/rung/blocks/governance.cpp` (328 LOC)

- **Purpose**: EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE,
  ACCUMULATOR, OUTPUT_CHECK.
- **Behaviour**: tx-shape introspection. Checks tx weight, input count, output count,
  relative value across outputs, Merkle membership proofs, per-output structural
  checks.
- **Optional / removable**: entire family is optional.

## `src/rung/blocks/legacy.cpp` (326 LOC)

- **Purpose**: P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT wrappers.
- **Behaviour**: each reproduces the respective Core script-verification semantics
  against the Ladder witness.
- **Load-bearing invariants**: these wrappers share the Ladder `LadderSigChecker`
  (not Core's `BaseSignatureChecker`) to avoid the TAPROOT-only assertion trap in
  `CheckSchnorrSignature`.
- **Optional / removable**: entire family is optional. Removing it drops the ability
  to embed a legacy script inside an MLSC rung.

## `src/rung/blocks/qabi.cpp` (784 LOC) — `#ifdef LADDER_ENABLE_QABIO`

- **Purpose**: QABIO (Quantum-resistant Authenticated Batch Input Output) blocks —
  `QABI_PRIME`, `QABI_SPEND`. Enables PQ-safe batch payout patterns.
- **Optional / removable**: the whole file + the corresponding `src/rung/qabi.{h,cpp}`
  (~649 LOC) + the descriptor parser's qabi path + the `QABI*` error codes are gated
  behind `LADDER_ENABLE_QABIO`. Remove the define for a minimum-viable BIP that doesn't
  include QABIO.

---

# Part 4 — Supporting Surface

## `src/rung/pq_verify.h` (52 LOC) / `pq_verify.cpp` (146 LOC)

- **Purpose**: post-quantum signature verification wrappers for FALCON-512,
  FALCON-1024, Dilithium3, SPHINCS+.
- **Optional / removable**: entire file. Remove to drop PQ paths; SIG/MULTISIG/etc.
  would reject PQ schemes at `ParsePQScheme` time.

## `src/rung/adaptor.h` (58 LOC) / `adaptor.cpp`

- **Purpose**: adaptor signature primitives used by ADAPTOR_SIG and PTLC.
- **Optional / removable**: remove if ADAPTOR_SIG and PTLC are dropped.

## `src/rung/policy.h` (100 LOC) / `policy.cpp` (339 LOC)

- **Purpose**: mempool policy. `IsStandardRungTx` delegates structural validation to
  the consensus deserializer then checks all outputs are MLSC. Block-type
  classification helpers: `IsBaseBlockType`, `IsCovenantBlockType`, `IsStatefulBlockType`.
- **Load-bearing invariants**: mempool policy is stricter than consensus. Must never
  accept txs that consensus would reject.
- **Optional / removable**: relay-policy tightening (beyond the "all-MLSC" check) is
  implementation choice.

## `src/rung/descriptor.h` (170 LOC) / `descriptor.cpp`

- **Purpose**: human-readable descriptor parser. Grammar:
  `ladder(or(rung1, rung2, ...))` with lowercase function-style blocks and optional `!`
  for inversion.
- **Optional / removable**: entire file. Developer convenience, never runs in
  consensus. A minimum-viable BIP could ship JSON-only.

## `src/rung/rpc.cpp` (4217 LOC)

- **Purpose**: 20 JSON-RPC commands across six groups: descriptor authoring
  (`parseladder`, `formatladder`, `signladder`), construction and signing
  (`createrungtx`, `signrungtx`, `createrung`), inspection
  (`serialiseconditions`, `decoderung`, `validateladder`, `computemutation`),
  templates and commitments (`computectvhash`, `pqpubkeycommit`), PQ helpers
  (`generatepqkeypair`, `extractadaptorsecret`, `verifyadaptorpresig`), and
  the QABIO suite (`qabi_buildblock`, `qabi_blockinfo`, `qabi_authchain`,
  `qabi_signqabo`, `qabi_sighash`). Full per-RPC reference in
  [`RPC_REFERENCE.md`](RPC_REFERENCE.md).
- **Optional / removable**: entire file. Developer tooling, never runs in consensus.
  Remove to drop RPC support.

## `src/rung/write_helpers.h` (103 LOC)

- **Purpose**: inline serialization helpers (`WriteLE32`, `WriteLE64`, etc.) — no Core
  dependency.
- **Load-bearing invariants**: endianness must match BIP-119 / BIP-340 where applicable.

---

# Part 5 — What a Minimum-Viable BIP Could Look Like

A reviewer evaluating "what's the smallest Ladder Script I could soft-fork?" should
consider:

**Required (cannot be removed)**
- `types.h` core enums + structural types
- `api.h`, `rung_shims.h`
- `evaluator.{h,cpp}` in full
- `conditions.{h,cpp}` in full
- `serialize.{h,cpp}` in full
- `sighash.{h,cpp}` (can trim ANYPREVOUT variants)
- `block_dispatch.h`, `block_helpers.{h,cpp}`
- `blocks/sig.cpp`, `blocks/timelock.cpp`, `blocks/covenant.cpp` (CTV + AMOUNT_LOCK),
  `blocks/recursion.cpp` (SAME + MODIFIED + UNTIL only), `blocks/anchor.cpp`
  (DATA_RETURN only)
- Core Integration Patch in full (the 805-LOC delta is already minimum)

**Droppable for a conservative first soft-fork**
- `blocks/plc.cpp` (entire PLC family)
- `blocks/compound.cpp` (all compound encodings — express as compositions)
- `blocks/governance.cpp` (tx-shape introspection)
- `blocks/legacy.cpp` (P2* wrappers)
- `blocks/qabi.cpp` + `qabi.{h,cpp}` + QABIO block evaluators
- `pq_verify.{h,cpp}` (no PQ paths → no FALCON/Dilithium/SPHINCS)
- `adaptor.{h,cpp}` + ADAPTOR_SIG + PTLC
- Advanced recurses (COUNT, SPLIT, DECAY)
- Hash family HASH_GUARDED
- Anchor family minus DATA_RETURN
- `descriptor.{h,cpp}` (developer convenience)
- `rpc.cpp` (developer convenience)

Dropping all droppable components yields approximately **~5,000–6,000 LOC** of library
code versus the full 21,251 — the same 961-LOC Core Integration Patch in both cases.

---

# Part 6 — Anti-Spam Properties

A reviewer verifying the embedding surface should confirm:

The minimum spendable v4 transaction has approximately 11 bytes of
attacker-controllable content (`nLockTime`, `nSequence`, the Schnorr
nonce — same floor every Bitcoin tx has). Above that floor, the
per-tx ceiling depends on which block types are revealed at spend
time and is bounded structurally by per-block field-count enforcement
plus the per-tx caps below. There is no `OP_DROP` / `OP_FALSE OP_IF`
dead-code channel — every byte in an MLSC witness is consumed by a
typed evaluator.

Per-tx caps (consensus):
- `MAX_PREIMAGE_FIELDS_PER_TX = 2` × 32 B = 64 B of preimage.
- `MAX_SCRIPT_BODY_FIELDS_PER_TX = 1` × ≤80 B of script body.
- `DATA_RETURN`: at most one per tx, payload 1..40 B.
- `MAX_LADDER_WITNESS_SIZE = 100 KB` per input.

The 11 B floor matches every Bitcoin transaction format. The
per-input MLSC reveal scales with the spent rung's block count and
field shapes. Full empirical analysis in
[`EMBEDDING_CHALLENGE.md`](EMBEDDING_CHALLENGE.md).

Mechanisms that enforce these caps:

1. **Fail-closed deserialisation** (`serialize.cpp`) — unknown types, deprecated blocks,
   non-invertible inversion, trailing bytes all reject.
2. **Selective inversion** (`types.h`) — explicit allowlist, key-consuming blocks
   never invertible.
3. **`IsDataEmbeddingType`** (`types.h`) — blocks without implicit layouts cannot carry
   HASH256, HASH160, PUBKEY_COMMIT, or DATA.
4. **PREIMAGE/SCRIPT_BODY cap** (`serialize.cpp`) — max 2 per witness, 2 per tx
   (binding).
5. **DATA type restriction** — only DATA_RETURN (40-byte cap, one per tx).
6. **merkle_pub_key** — pubkeys fold into Merkle leaves, not condition fields. Prevents
   pubkey-as-storage exfiltration.
7. **Blanket HASH256 rejection in RPC** (`rpc.cpp`) — HASH256 fields in conditions are
   whitelisted to CTV, TAGGED_HASH, ACCUMULATOR, COSIGN, OUTPUT_CHECK only. Users
   provide PREIMAGE and the library computes the hash.

---

# Part 7 — Formal Verification

27 TLA+ specs under `spec/` covering the consensus surface — evaluation
semantics, anti-spam, wire format, Merkle proof security, sighash binding,
covenant termination, cross-input rules, and per-family block evaluators.

A representative subset:

| Spec | Focus |
|------|-------|
| `LadderEval.tla` | Rung/ladder evaluation, inversion, recursion termination |
| `LadderEvalCheck.tla` | Type invariants and safety for evaluation |
| `LadderBlockEval.tla` | Individual block evaluation |
| `LadderComposition.tla` | AND/OR composition with relays |
| `LadderAntiSpam.tla` | User-chosen data field limits |
| `LadderWireFormat.tla` | Wire format serialization invariants |
| `LadderMerkle.tla` | Merkle tree construction and verification |
| `LadderSighash.tla` | Sighash computation properties |
| `LadderCovenant.tla` | Covenant/recursion termination and safety |
| `LadderCrossInput.tla` | Cross-input (COSIGN) dependencies |
| `Block{Sig,Timelock,Hash,Covenant,Recursion,Anchor,PLC,Compound,Governance,Legacy}.tla` | Per-family block evaluators |
| `SharedProof.tla`, `UTXODedup.tla`, `AutoKeyPath.tla`, `RecursiveCovenant.tla`, `HybridCreationProof.tla`, `LadderTxMLSC.tla`, `AnchorFee.tla` | Specialised consensus invariants |

Bounded-state model checks pass cleanly. Full-constant runs on a higher-RAM
host are in progress (see [`SIZING.md`](SIZING.md) for the consensus-level
constants that drive the run cost).

---

# Part 8 — Test Coverage

Reviewers can re-run:

- **Boost unit tests**: `build/bin/test_bitcoin --run_test=rung_tests` plus
  `qabi_tests` and `tx_mlsc_tests` — **619 cases total** across the three
  suites.
- **Functional tests**: `test/functional/feature_rung_tx.py`,
  `feature_rung_p2p.py`, `feature_rung_legacy.py`, `feature_rung_fuzz.py`,
  `feature_rung_pq_batch.py`, `feature_rung_pq_batch_stress.py`,
  `feature_qabi.py`, `feature_qabi_size.py` — 8 files, 52 distinct test
  methods.
- **Preset end-to-end**: `tools/test-presets.py --api <proxy>` — 56 presets
  exercise fund + spend on live signet.

---

# Part 9 — Where to Start Reviewing

For a reviewer with limited time, the fastest path to a meaningful audit:

1. Read `TLDR.md` (5 minutes).
2. Read [`SIZING.md`](SIZING.md) (10 minutes) — measured wire and chainstate
   costs, so the design choices have economic ground truth.
3. Read `RUNG_TX_SPEC.md` and `TX_MLSC_SPEC.md` (30 minutes).
4. Read [`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md) sections 1-7 (validation,
   primitives, interpreter, compressor). These contain the entire consensus
   seam.
5. Read [`ANNOTATED_LIBRARY.md`](ANNOTATED_LIBRARY.md) Part 1 (the narrative
   tour) — one transaction's path from authoring through spend.
6. Read `src/rung/evaluator.cpp` `VerifyRungTx` + `ValidateRungOutputs`
   (60 minutes).
7. Read `src/rung/conditions.cpp` `VerifyMerklePath` + `ComputeTxMLSCLeaf` +
   `ComputeTweakedConditionsRoot` + `ComputeValueCommitment` (30 minutes).
8. Read `src/rung/serialize.cpp` `DeserializeLadderWitness` + `DeserializeBlock`
   (30 minutes).
9. Spot-check one block evaluator per family (e.g. `blocks/sig.cpp::EvalSigBlock`,
   `blocks/timelock.cpp::EvalCSVBlock`, `blocks/covenant.cpp::EvalCTVBlock`).

That's roughly 3-4 hours of focused review to cover the entire consensus
surface. The remaining ~15,000 LOC of library is developer tooling (RPC,
descriptor parser, block evaluators for optional families) — the Annotated
Library walks each file in Part 2 if you want full coverage.
