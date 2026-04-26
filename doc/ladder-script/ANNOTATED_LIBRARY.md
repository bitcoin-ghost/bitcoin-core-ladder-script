# Ladder Script: Annotated Library

This document explains the internals of the Ladder Script reference
implementation: 19,336 lines across 39 files in `src/rung/`, plus the
353-line `src/rung_shims.h` boundary header.

It complements [`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md), which covers
the 805-line patch to existing Bitcoin Core code. The patch is the
hooks; this is the engine.

> **Reading order.** Part 1 is the narrative tour (how a single
> RUNG_TX flows from authoring to spend). Parts 2a–2c are the
> file-by-file reference. New reviewers should read Part 1 first
> and use Part 2 as a lookup. Each Part 2 section follows the same
> template: purpose, key types/functions, invariants, gotchas,
> cross-references.

## Repository layout

```
src/
├── rung_shims.h              353 LOC — Core ↔ library boundary (the ONE adapter)
└── rung/                          ── 19,336 LOC, 39 files
    ├── CMakeLists.txt          97
    │
    ├── api.h                  528  — adapter types (LadderScript, LadderTxView, ...)
    ├── types.h              1,566  — RungBlockType enum, BlockTypeInfo registry
    ├── types.cpp               46
    │
    ├── conditions.h          310  — RungConditions, parsing, conditions_root
    ├── conditions.cpp      1,078
    │
    ├── descriptor.h          170  — descriptor language (sig(@k), or(...), etc.)
    ├── descriptor.cpp      1,866
    │
    ├── evaluator.h           369  — VerifyRungTx + caches (Shared/QABO/PQBatch)
    ├── evaluator.cpp       1,301
    │
    ├── block_dispatch.h       81  — per-block-type evaluator registry
    ├── block_helpers.h       107
    ├── block_helpers.cpp     475
    │
    ├── sighash.h              66  — SIGHASH_LADDER + SIGHASH_QABO
    ├── sighash.cpp           224
    │
    ├── pq_verify.h            52  — FALCON / Dilithium3 / SPHINCS+ wrappers
    ├── pq_verify.cpp         146
    │
    ├── qabi.h                233  — QABIO state (auth chain, batch block, sig)
    ├── qabi.cpp              416
    │
    ├── adaptor.h              58  — adaptor sigs (PTLC)
    ├── adaptor.cpp           188
    │
    ├── policy.h              100  — IsStandardRungTx + structural anti-spam
    ├── policy.cpp            339
    │
    ├── serialize.h           129  — wire-format read/write
    ├── serialize.cpp       1,051
    │
    ├── write_helpers.h       103
    │
    ├── rpc.cpp             4,217  — every RPC: createrungtx, signrungtx, qabi_*
    │
    └── blocks/                  ── 11 files, 3,649 LOC — per-family block evaluators
        ├── sig.cpp             334  — SIG, KEY_REF_SIG, MULTISIG, MUSIG_THRESHOLD
        ├── timelock.cpp        161  — CSV, CLTV, CSV_TIME, CLTV_TIME
        ├── hash.cpp            121  — TAGGED_HASH, HASH_GUARDED
        ├── covenant.cpp        240  — CTV, VAULT_LOCK, AMOUNT_LOCK
        ├── recursion.cpp       351  — RECURSE_SAME / UNTIL / COUNT / SPLIT / MODIFIED / DECAY
        ├── anchor.cpp          268  — ANCHOR family + DATA_RETURN
        ├── plc.cpp             429  — PLC family (HYSTERESIS, TIMER, LATCH, RATE_LIMIT, COSIGN, ...)
        ├── compound.cpp        307  — TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG
        ├── governance.cpp      328  — EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, ACCUMULATOR, OUTPUT_CHECK
        ├── legacy.cpp          326  — P2PK_LEGACY, P2PKH_LEGACY, P2WPKH_LEGACY, P2TR_LEGACY, ...
        └── qabi.cpp            784  — QABI_PRIME, QABI_SPEND, PQ_BATCH evaluators
```

The library has **one** dependency from outside its directory:
`src/rung_shims.h`. Core code includes that header; the library never
includes Core headers. This is the boundary that allows the library to
be ported to any consensus engine that can wire the adapter types.

---

# Part 1 — Narrative tour

We follow one transaction from authoring through to a successful spend
two hops later. Each hop names the file and function involved.

## 1. Author the conditions

The user types a descriptor:

```text
ladder(or(
  and(sig(@hot), csv(144)),
  multisig(2, @key_a, @key_b, @key_c)
))
```

`ParseDescriptor` (`descriptor.cpp:1010-1115`) tokenises the string,
substitutes alias→pubkey via the `keys` map, and walks the recursive
descent grammar in `ParseBlock` (`descriptor.cpp:1008`). It produces a
`RungConditions` (defined in `conditions.h:50`) — the in-memory
representation: rungs of blocks, each block carrying typed fields.

The descriptor uses a register of per-family parsers (`ParseSig`,
`ParseTimelock`, `ParseQABISpend`, `ParsePqBatch`, ...) that all share
the same `ParseContext` and resource limits (max 32 nesting depth, max
1000 items, max 4096 output index — `descriptor.cpp:25-27`). Each
parser pushes a `RungBlock` with the right type and field layout.

Rungs are OR; blocks within a rung are AND. The grammar's `or(...)`
emits one `Rung` per argument; the grammar's `and(...)` emits one rung
containing all the ANDed blocks. Anything else is a single block in a
single rung — the simplest descriptors `sig(@alice)` and `csv(144)` are
1-rung, 1-block.

## 2. Compute the conditions_root

`ComputeConditionsRoot(conditions, output_index)` in `conditions.cpp`
folds the rungs into a per-output Merkle root. Each leaf is an
`MLSCLeaf` carrying the rung index and a hash of the rung's blocks
plus the output index. The leaves are Merkelised with the standard
BIP 340-style tagged-hash construction.

The output index is mixed into every leaf so two different outputs of
the same tx with otherwise identical conditions produce different roots.
This is the structural reason an attacker can't smuggle arbitrary data
by replicating one output across N: the leaves are bound to position.

## 3. Build the transaction (`createrungtx`)

The user calls `createrungtx` (RPC implementation in `rpc.cpp`,
~lines 1100-1500). The RPC takes:

- `inputs` — the UTXOs to consume (any mix of MLSC, P2WPKH, P2TR).
- `amounts` — the output values.
- `rungs` — the per-output condition tree (or a single shared tree).
- `locktime` — optional.

Internally it:

1. Builds a `CMutableTransaction` with `version = 4`.
2. Computes the conditions_root (per-output if heterogeneous, shared
   if every output has the same conditions — the common case).
3. Sets `mtx.conditions_root` and constructs `vout` entries with
   `scriptPubKey = 0xDF || conditions_root` and the requested values.
4. Returns the serialised hex.

DATA_RETURN outputs are signalled by `value == 0` — the RPC accepts
them as a special case and writes the marker into the wire format
(`primitives/transaction.h:251-260`).

For QABIO transactions the same RPC writes the `qabi_block` field
(consumed from a separate argument); for non-QABIO v4 txs the field is
empty and serialises as a 1-byte zero-length varint.

## 4. Sign each input (`signrungtx`)

`signrungtx` (`rpc.cpp`) takes the unsigned tx, the signers (alias →
key), and the spent outputs (needed for sighash computation). For each
MLSC input it:

1. Loads the conditions used to fund the UTXO (passed in by the caller).
2. Picks a satisfying rung (the user can hint, otherwise the first
   passing rung wins).
3. Computes `SIGHASH_LADDER` over the tx (`sighash.cpp:30`).
4. Calls into `SignSingleKey` (and any block-specific signer like the
   PQ_BATCH anchor signer).
5. Builds the LadderWitness + MLSCProof and packs them into the input's
   witness stack.

For QABIO inputs the per-input witness is just the per-rung satisfaction
proof; the FALCON aggregate signature lives in the tx-level
`aggregated_sig` field, signed once over `SIGHASH_QABO`
(`sighash.cpp:90`) and supplied separately by the coordinator.

## 5. Broadcast and mempool admission

The signed tx is sent to the network. A receiving node parses it
(`primitives/transaction.h:266-330`), recognises `version == 4 && flags
== 0x02`, and reads the TX_MLSC layout. The reconstructed
`vout[i].scriptPubKey` is `0xDF || conditions_root` so all downstream
code that touches scriptPubKeys sees a normal 33-byte SPK.

Mempool admission goes through `IsStandardTx` in
`policy/policy.cpp:101-105`, which routes v4 to
`rung::IsStandardRungTx` (`policy.cpp` in the library). Structural
checks fire here:

- `n_outputs ≤ 252`
- per-rung block cap (8)
- per-block field cap (16)
- per-tx rung cap (16) and preimage-field cap

If the tx survives standardness, full validation runs in
`CheckInputScripts` (`validation.cpp:2277-2400` in Core). For each
input, `CScriptCheck` dispatches:

- Classical input → existing `VerifyScript`.
- MLSC input on a v4 tx → `rung::VerifyRungTx` (the library entry).

After every input passes, a final `rung::CheckRungTxLevel` run does the
cross-input checks (output validation, preimage-field count).

## 6. Per-input verification (`VerifyRungTx`)

`VerifyRungTx` (`evaluator.cpp:1127`) is the library's main
verification entrypoint when called from Core (Core types in, error
out). It immediately delegates to the adapter-typed entrypoint at
`evaluator.cpp:623` after constructing a `LadderTxView` from the
`CTransaction`.

The adapter version:

1. Validates the witness count (1 = key-path, 2 = script-path no
   tweak, 3 = script-path with tweak).
2. For input 0, runs the tx-level safety net (`CheckRungTxLevel`).
3. Parses the LadderWitness + MLSCProof from the witness stack.
4. Verifies the MLSCProof against the conditions_root (recovered from
   the synthetic coin entry the host fetched).
5. Picks the asserted rung from the witness and dispatches each block
   to its evaluator via the registry in `block_dispatch.h`.
6. AND-folds the per-block results; the rung passes if every block
   returns SATISFIED.

The block evaluator gets a `RungEvalContext` containing the spending
tx, input index, spent-output amount, block height, the optional
PQ_BATCH/QABO caches, and (for cross-input checks) the full spent-
output array.

## 7. Per-block evaluation

The dispatcher in `block_dispatch.h` is a flat registry: one function
per `RungBlockType`, registered at static-init time by
`RegisterBlock(...)` calls scattered across `src/rung/blocks/*.cpp`.
Each evaluator returns one of `SATISFIED / UNSATISFIED / ERROR /
UNKNOWN_BLOCK_TYPE`.

Examples:

- `SIG` evaluator (`blocks/sig.cpp`) computes the sighash, verifies
  the witness signature against the committed pubkey, returns
  SATISFIED on success.
- `CSV` evaluator (`blocks/timelock.cpp`) compares the input's
  sequence number to the rung's CSV value.
- `PQ_BATCH` evaluator (`blocks/qabi.cpp:764`) uses the per-tx cache:
  if this is the anchor input, verify the FALCON sig, populate the
  cache, return SATISFIED. If not the anchor, look up the cache and
  return SATISFIED if the anchor verified for the same commit.
- `QABI_SPEND` evaluator (`blocks/qabi.cpp`) checks the auth chain
  position, validates the committed root, looks up the QABO sig cache
  for the per-tx FALCON aggregate verification.

## 8. UTXO write at block accept

When the block containing the tx is accepted, `AddCoins`
(`coins.cpp:125-145`) writes a regular `Coin` for every vout, then —
for v4 txs — a synthetic root coin at `(txid, MLSC_ROOT_VOUT)` carrying
`0xDE || conditions_root`. The `0xDE` marker is critical: the
compressor (`compressor.cpp:107`) recognises only `0xDF` as MLSC and
strips the payload. Using `0xDE` keeps the synthetic entry's payload
verbatim in the database.

Per-output `Coin` records compress to a single `0x06` marker via the
compressor's special-script type 7 (`compressor.cpp`). The 32-byte
root lives once per tx in the synthetic entry.

## 9. Spend on the next hop

A future spender retrieves the UTXO. The chainstate gives them a
1-byte SPK (`0xDF`) and they need the root. They:

1. Look up `(creating_txid, MLSC_ROOT_VOUT)` in chainstate → get
   `0xDE || root[32]`.
2. Use `root` as the conditions_root for sighash computation and
   MLSC proof verification.

The same path applies inside the validator: when a node validates a
spend, it fetches the synthetic entry from its own chainstate. Pruned
nodes keep the creating block's undo data while any spawned UTXO is
unspent (`compressor.cpp` invariant comment), so the recovery path is
always available.

---

# Part 2 — File-by-file reference

## `evaluator.cpp` (1,301 lines)

The central verification engine. Everything that actually executes a
ladder script flows through this file.

### Purpose

- Provide the canonical `VerifyRungTx` entrypoint (Core-typed
  overload + adapter-typed inner) used by `CScriptCheck` in Core.
- Implement `CheckRungTxLevel` for cross-input invariants that don't
  fit into the per-input pipeline.
- Own the per-tx caches (`SharedTreeCache`, `QABOSigCache`,
  `PQBatchCache`) defined in `evaluator.h` and threaded through the
  context.
- Own the `BlockEvaluator` registry — a flat `std::array` indexed by
  `RungBlockType`, populated by `RegisterBlock(...)` calls from
  `blocks/*.cpp` at static-init time.

### Key functions

| Function | Lines | Purpose |
|----------|------:|---------|
| `RegisterBlock(type, fn)`              | 1200 | Static-init registration: stores `fn` at `s_block_evaluators[type]`. Called from every `blocks/*.cpp` `RegisterXxxBlocks()` function. |
| `EvaluateBlock(block, ctx)`            | ~250 | Look up the registered evaluator for `block.type`, invoke it. Returns `UNKNOWN_BLOCK_TYPE` if no evaluator registered (forward-compat). |
| `EvaluateRung(rung, ctx)`              | ~310 | AND-fold: evaluates every block in the rung, returns SATISFIED only if all return SATISFIED. ERROR is sticky. |
| `VerifyMLSCProof(proof, root, ...)`    | ~420 | Check that the asserted rung's leaf hashes Merkelise to the committed `conditions_root`. |
| `CheckRungTxLevel(tx, error)`          |  602 | Tx-level pass: validate output structure (`ValidateRungOutputs`), enforce per-tx preimage-field cap. |
| `VerifyRungTx(tx, idx, out, ctx, err)` |  623 | Adapter-typed inner. Witness count check, MLSC proof check, rung dispatch. |
| `VerifyRungTx(CTransaction, ...)`      | 1127 | Core-typed overload. Builds a `LadderTxView` from the `CTransaction`, populates the `LadderEvalContext`, calls the adapter version. The shim where Core types meet adapter types — every concrete production call enters here. |

### Invariants

- **Dispatch gate.** `VerifyRungTx` is only ever called for inputs
  spending an MLSC scriptPubKey on a v4 tx. The gate lives in
  `validation.cpp` (`tx.version == RUNG_TX_VERSION && IsMLSCScript`)
  and is documented inline at `evaluator.cpp:664-680`. P2TR (`OP_1` +
  32 B) and MLSC (`0xDF` + 32 B) have disjoint SPK prefixes, so
  cross-protocol witness mixing is structurally impossible.
- **Witness count = path.** 1 element = key-path, 2 = script-path no
  tweak, 3 = script-path with tweak. Anything else fails immediately
  with `WITNESS_PROGRAM_WITNESS_EMPTY`.
- **Per-tx-level checks fire on input 0 as a safety net.** The host
  is *required* to call `CheckRungTxLevel` separately at the tx level
  (so it runs even for wallet-funded v4 txs where input 0 is a
  P2WPKH/P2TR spend that never enters `VerifyRungTx`). The input-0
  call inside `VerifyRungTx` is redundant when the host is correct
  and harmless when the host has already run it.
- **Cache ordering.** PQ_BATCH and QABIO caches must be populated by
  the lowest-index input that triggers verification. Non-anchor
  inputs at lower indices return UNSATISFIED (no cache entry yet);
  signers must place the anchor at the lowest matching index. This
  is documented at `evaluator.h:128-134`.

### Gotchas

- `RegisterBlock` is called at static-init time. The order is
  unspecified — no evaluator may depend on another being registered
  first. Cross-evaluator dependencies (e.g. PQ_BATCH cache shared
  with QABI_SPEND) go through the per-tx context, not the registry.
- The Core-typed `VerifyRungTx` overload constructs a fresh
  `LadderTxView` on every call. For a multi-input tx this builds N
  views from the same `CTransaction`. Cheap (no copying), but the
  cost is real on tight loops — the cost amortises across the per-tx
  caches.
- `EvaluateBlock` swallows non-fatal evaluator errors into
  `UNSATISFIED` rather than `ERROR`. This is intentional:
  consensus-fatal errors (malformed witness, bad proof) are caught
  earlier by `VerifyMLSCProof`; per-block "this branch doesn't
  satisfy" failures are not consensus-fatal and must let the rung
  AND-fold complete.

### Cross-references

- Caches defined in `evaluator.h:55-135` — see those types' docstrings
  for the cross-input cache rules.
- Block evaluators registered in `blocks/*.cpp` — each calls
  `RegisterBlock` from a free function invoked at static-init.
- Adapter types (`LadderTxView`, `LadderOutputView`,
  `LadderEvalContext`) defined in `api.h`.
- The Core-side dispatch gate is in `validation.cpp` — see
  [`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md#1-srcvalidationcpp-224--15).

---

## `api.h` (528 lines)

The library's public surface — the **only** header Core code includes.
Read this header first; everything else is internal.

### Purpose

- Define adapter types that decouple the library from Core's concrete
  C++ types (`CTransaction`, `CTxOut`, `CScript`, `BaseSignatureChecker`,
  `XOnlyPubKey`, etc.). The library accepts byte spans, primitives, and
  the structs declared here.
- Define the `LadderScriptError` enum — independent of Core's
  `SCRIPT_ERR_*`. `rung_shims.h` translates between the two.
- Declare the host callbacks (`LadderSigChecker`,
  `LadderBlockAccessor`) so the library never reaches into Core's
  global state (chainstate, mempool, net, wallet, RPC server).

### Key types

| Symbol                            | Lines | Purpose |
|-----------------------------------|------:|---------|
| `enum class LadderScriptError`    |   ~70 | Library-internal error codes. Translated to `SCRIPT_ERR_*` at the boundary. |
| `struct LadderScript`             |   143 | A typed view of a scriptPubKey: a byte span + a "kind" tag (MLSC, P2WPKH, etc.). |
| `struct LadderWitnessElement`     |   154 | One stack item: byte span. |
| `struct LadderWitnessStack`       |   160 | Vector of witness elements with a count. |
| `struct LadderInputView`          |   172 | One input: outpoint + sequence + witness stack. |
| `struct LadderOutputView`         |   180 | One output: value + scriptPubKey span. |
| `struct LadderTxView`             |   189 | Whole transaction: version, vin, vout, locktime, qabi_block, aggregated_sig. |
| `struct LadderPrecomputedTxData`  |   232 | Sighash midstate caches — the adapter equivalent of `PrecomputedTransactionData`. |
| `class LadderSigChecker`          |   267 | Virtual: how the library asks the host to verify a Schnorr/ECDSA signature. |
| `class LadderBlockAccessor`       |   295 | Virtual: how the library asks the host to fetch the synthetic root coin (`GetMLSCRoot(txid) → uint256`). |
| `struct LadderEvalContext`        |   326 | Per-input evaluation context: `tx`, `input_index`, `sig_checker`, `block_accessor`, optional caches, weight, height, etc. |
| `using LadderBlockEvalFn = ...`   |   393 | Function pointer type for block evaluators. Each block-type registers one of these. |
| `struct LadderBlockDescriptor`    |   416 | The per-block-type registration record: type id, name, eval fn, validate fn, conditions/witness layouts. |

### Design rules

The header's top comment states three rules explicitly:

1. **No Core types in this header.** Every external type crosses the
   boundary as a byte span, a primitive, or an adapter struct defined
   here.
2. **No Core global state.** The library never touches chainstate,
   mempool, net, wallet, or RPC server directly. Everything comes in
   via callback or explicit value.
3. **Each block type lives in its own translation unit.** Under
   `src/rung/blocks/`, exporting a `register_XYZ_block()` function the
   host calls from `ladder_init()`. A block compiled out never
   registers; transactions using it are rejected with
   `LADDER_ERR_UNKNOWN_BLOCK_TYPE`. This is what makes selective
   activation possible — a BIP sub-proposal can be declined by
   disabling its blocks, with no Core integration change.

The header uses C++ (namespaces, references, virtual classes for
callbacks). Deliberately conservative: no templates at the ABI
surface, no exceptions, no STL containers in function signatures. A
narrow `extern "C"` wrapper for language bindings is anticipated
(libsecp256k1 pattern) but not yet present.

### Gotchas

- `LadderTxView` is a **view**, not an owner. The lifetime of the
  underlying `CTransaction` (or whatever the host passes) must outlast
  the view. The Core-typed `VerifyRungTx` overload in `evaluator.cpp`
  constructs a view per call — fine because the `CTransaction` is
  stack-allocated by the caller.
- `LadderBlockAccessor::GetMLSCRoot(txid)` is the load-bearing
  callback. If the host can't fetch the root (snapshot loading without
  conditions_root reconstruction, library used standalone), the
  evaluator returns `MLSC_ROOT_UNAVAILABLE`. See the invariant in
  [`ANNOTATED_DIFF.md` §3](ANNOTATED_DIFF.md#3-srccompressorcpp-68--1-and-srccompressorh-1--1).
- Forward-compatibility: an unknown block type returns
  `UNKNOWN_BLOCK_TYPE` (NOT a consensus error). This lets future
  block additions activate as a soft fork — old nodes treat unknown
  blocks as failing, but they don't crash.

### Cross-references

- `LadderScriptError` translation table: `rung_shims.h` (the
  boundary header).
- Block registration: `block_dispatch.h` + `RegisterBlock` in
  `evaluator.cpp:1200`.
- Concrete eval entry: `VerifyRungTx` in `evaluator.cpp:623`.

---

## `types.h` (1,566 lines)

The library's master type registry. Defines `RungBlockType`,
`RungDataType`, the in-memory `RungBlock` / `Rung` / `LadderWitness`
structs, and — critically — the **`ImplicitFieldLayout` table** and
the **`BlockTypeInfo` registry** that together drive the structural
anti-spam regime.

### Key types

| Symbol                            | Lines | Purpose |
|-----------------------------------|------:|---------|
| `enum class RungBlockType`        |    80 | Every block type id. 16-bit enum with explicit hex values (`0x01XX` for sig family, `0x09XX` for legacy, `0x0AXX` for QABIO/PQ_BATCH, etc.). 65 active values. |
| `enum class RungDataType`         |   176 | Field types: `PUBKEY`, `SIGNATURE`, `NUMERIC`, `HASH256`, `PREIMAGE`, `SCHEME`, `PUBKEY_COMMIT`, `SCRIPT_BODY`, etc. |
| `enum class RungCoilType`         |   536 | Coil types: `UNLOCK`, `RECURSE_*`. The "output" of a rung. |
| `enum class RungAttestationMode`  |   542 | Witness attestation modes (INLINE / NONE etc.). |
| `enum class RungScheme`           |   547 | Signature scheme: `SCHNORR`, `ECDSA`, `FALCON512`, `FALCON1024`, `DILITHIUM3`, `SPHINCS_SHA`. |
| `struct RungCoil`                 |   601 | Coil = `{type, output_index, scheme, attestation}`. |
| `struct RungField`                |   611 | One field: `{type, data}`. |
| `struct RungBlock`                |   621 | One block: `{type, fields[]}`. |
| `struct Rung`                     |   628 | One rung: `{blocks[], relay_refs[]}`. |
| `struct Relay`                    |   637 | Reusable pubkey/script reference indexed by `KEY_REF_SIG`. |
| `struct LadderWitness`            |   717 | Top-level witness: `{rungs[], coil, relays[], commitments[]}`. |
| `struct ImplicitFieldEntry`       |   846 | One row in a layout: `{type, size}`. |
| `struct ImplicitFieldLayout`      |   855 | A block's implicit field layout: count + entries. Used to validate field shape without explicit per-block parsers. |
| `struct BlockTypeInfo`            |  ~1490| Per-type metadata record: name, conditions/witness layouts, flags. |

### The two registry tables

Two compile-time tables drive almost every consensus check:

**`*_CONDITIONS` constants** (lines 866 onward) — one
`ImplicitFieldLayout` per block type, declaring exactly what fields
appear in the conditions context. Example:

```cpp
inline constexpr ImplicitFieldLayout SIG_CONDITIONS = {1, {
    {RungDataType::PUBKEY, 0}     // size 0 = variable
}};
inline constexpr ImplicitFieldLayout HTLC_CONDITIONS = {3, {
    {RungDataType::PUBKEY, 0},    // sender
    {RungDataType::PUBKEY, 0},    // receiver
    {RungDataType::HASH256, 32}   // hashlock
}};
```

The deserialiser uses these layouts to validate field count, type, and
size as it reads — no per-block bespoke parser. Adding a new block
type means adding one `ImplicitFieldLayout` and registering an
evaluator; the wire format and anti-spam coverage come for free.

**`BlockTypeInfo` registry** (line ~1490) — the master table mapping
each `RungBlockType` to its metadata: human-readable name, conditions
layout, witness layout, and flags (e.g. `is_pq` for blocks that
require PQ scheme support).

### Invariants

- **Every active block type must have a `*_CONDITIONS` layout.**
  If a deserialised block doesn't match its layout (wrong count,
  wrong type, wrong size), the conditions deserialise rejects with
  `FIELD_*_INVALID`. This is the structural anti-spam: every byte in
  every field is type-checked.
- **PQ_BATCH witness layout is `nullptr` (variable-length).** Only
  exception in the table — the witness for the anchor input has 2
  fields (PUBKEY + SIGNATURE), the witness for non-anchor inputs has
  0 fields. The evaluator enforces the 0-or-2 rule. Documented in the
  `PQ_BATCH_CONDITIONS` comment block (line 1257).
- **The block-type enum is forward-compatible.** Unknown types
  deserialise OK (the layout lookup returns nullptr, the evaluator
  returns `UNKNOWN_BLOCK_TYPE`). Activation by soft fork doesn't
  break existing wire-format readers.

### Cross-references

- Layouts are consumed by `DeserializeRungConditions` in
  `conditions.cpp` and by the per-field parsers in `serialize.cpp`.
- The `BlockTypeInfo` registry is the source of truth for what's
  "active" — disabling a block (compile-time) removes its
  `register_*_block()` call, and the registry entry stays but no
  evaluator backs it. The block becomes UNKNOWN_BLOCK_TYPE in
  practice.

---

## `conditions.h` (310 lines) and `conditions.cpp` (1,078 lines)

The **conditions_root** is the 32-byte commitment that lives at the
tx level. This pair of files defines `RungConditions`, the
in-memory representation, and the Merkle-tree machinery that
collapses it to a root. They also define `MLSCProof` — the
spend-time witness companion that proves a particular rung is in
the committed tree — and `VerifyMLSCProof`, the function that
checks it.

### Key types and functions

| Symbol                             | File:Line | Purpose |
|------------------------------------|-----------|---------|
| `struct RungConditions`            | h:60      | `{rungs[], relays[], commitments[], template_diffs[]}`. The full in-memory condition tree. |
| `IsRungConditionsScript(span)`     | h:77      | Recogniser for the wire-format conditions byte. |
| `DeserializeRungConditions(...)`   | h:78      | Parse a span into `RungConditions`. Validates against `*_CONDITIONS` layouts as it goes. |
| `IsMLSCScript(span)`               | h:109     | True iff `script.size()==33 && script[0]==0xDF`. |
| `IsLadderScript(span)`             | h:112     | True for any ladder-recognised SPK (MLSC, conditions, compact). |
| `IsCompactMLSC(span)`              | h:116     | True iff the SPK is the 1-byte 0xDF form (UTXO-compressor compact). |
| `GetMLSCRoot(span, root_out)`      | h:120     | Extract the 32-byte root from a 33-byte MLSC SPK. |
| `ComputeRungLeaf(rung, ...)`       | h:141     | One Merkle leaf: tagged-hash of the rung's blocks + output_index. |
| `ComputeCoilLeaf(coil)`            | h:145     | Coil-specific leaf for the coil position in the tree. |
| `ComputeRelayLeaf(relay, ...)`     | h:148     | Relay leaf — relays go into the tree alongside rungs. |
| `BuildMerkleTree(leaves)`          | h:155     | Standard binary Merkle tree. Returns the root. |
| `VerifyMerklePath(leaf, ...)`      | h:172     | Check that a leaf + path hashes to the claimed root. |
| `ComputeMerkleRootFromPath(...)`   | h:187     | Inverse: rebuild the root from a leaf + path. |
| `ComputeConditionsRoot(c, idx)`    | h:193     | The headline function: `RungConditions` → `uint256` for output `idx`. |
| `enum class MLSCProofMode`         | h:210     | `MERKLE_PATH` (full path) or `LEAF_REVEAL` (relay-only). |
| `struct MLSCProof`                 | h:236     | The spend-time witness companion. |
| `DeserializeMLSCProof(...)`        | h:249     | Parse proof bytes from the witness stack. |
| `VerifyMLSCProof(proof, root, ...)`| h:265     | Check that the asserted rung's leaf hashes to the committed root. Populates `MLSCVerifiedLeaves` for downstream covenant checks. |

### Invariants

- **Output index is mixed into every leaf.** Two outputs of the same
  tx with otherwise identical rungs produce different leaves (and
  different roots). This is the structural reason an attacker can't
  smuggle data by replicating one output across N — see
  [`feedback_mlsc_witness_coil`](../../../../.claude/projects/-home-defenwycke/memory/feedback_mlsc_witness_coil.md)
  and the `MLSCWitnessCoil` invariants (per-rung output_index,
  witness coil = spent_vout, auto-tweak detection).
- **`ComputeConditionsRoot` is deterministic.** Two callers with the
  same `RungConditions` and `output_index` always produce the same
  root. Construction-side (RPC) and verification-side (evaluator)
  rely on this.
- **`VerifyMLSCProof` is the single gate** for "this rung is
  authorised to spend". The block evaluators run after this returns
  SATISFIED; if the proof fails, no evaluator runs.

### Gotchas

- `MLSCProof` carries the **revealed rung in full**, not just its
  leaf hash. The verifier needs the rung's blocks to dispatch the
  evaluators. The Merkle path verifies the rung's leaf hash; the
  evaluators then run on the revealed rung's blocks.
- `MLSCProofMode::LEAF_REVEAL` skips the Merkle path verification —
  used by single-rung descriptors where the entire conditions tree
  is the revealed rung itself. The proof carries `proof_mode` so the
  evaluator picks the right code path.
- `template_diffs` and `commitments` in `RungConditions` are
  optional sub-tree compression mechanisms for repeated patterns.
  Empty for most txs.
- `CreationProofRung` (h:283) and `ComputeTxMLSCRoot` (h:300) are
  used by the v4 wire-format helpers — historically related to the
  removed `creation_proof` field, kept around for the few internal
  callers that still need them.

### Cross-references

- The `*_CONDITIONS` layouts consumed by `DeserializeRungConditions`
  live in `types.h` (lines 866+).
- `IsLadderScript` is the recogniser used by Core's policy.cpp
  (`AreInputsStandard`, `IsWitnessStandard`) to skip MLSC inputs —
  see [`ANNOTATED_DIFF.md` §6](ANNOTATED_DIFF.md#6-srcpolicypolicycpp-14).
- `VerifyMLSCProof` is called from `VerifyRungTx`
  (`evaluator.cpp:623`) before any block evaluator runs.

---
## `block_dispatch.h` (81 lines)

The block-evaluator registry. Each `RungBlockType` maps to one
function pointer; per-family translation units register their
evaluators at startup via the `register_*_blocks()` functions.

### Key types

| Symbol                          | Purpose |
|---------------------------------|---------|
| `struct BlockDispatchContext`   | Bundle: `sig_checker`, `legacy_checker`, `sigversion`, `execdata`, `ctx` (`RungEvalContext`), `depth`. Passed uniformly to every evaluator. |
| `using BlockEvaluator`          | `EvalResult (*)(const RungBlock&, const BlockDispatchContext&)`. The function-pointer type. |
| `RegisterBlock(type, fn)`       | Stores `fn` in the registry slot for `type`. Later calls overwrite earlier ones (useful for test stubs). |
| `LookupBlockEvaluator(type)`    | Returns the registered evaluator or `nullptr`. |
| `register_*_blocks()`           | One per family: `sig`, `timelock`, `hash`, `covenant`, `anchor`, `recursion`, `plc`, `compound`, `governance`, `legacy`, `qabi` (when `ENABLE_QABIO`). Each calls `RegisterBlock` for the types it owns. |

### Invariants

- **A block type with no registered evaluator returns
  `UNKNOWN_BLOCK_TYPE`** — same semantics as the old `default:` arm
  in a switch statement, and the same forward-compatibility rule.
  Disabling QABIO at compile time removes the `register_qabi_blocks()`
  call; QABI_PRIME and QABI_SPEND become unknown to the evaluator,
  and txs using them are rejected.
- **Initialisation is one-shot.** The host calls
  `rung::api::ladder_init()` (declared in `api.h`); `EvalBlock` calls
  it on first dispatch as a safety net.

### Cross-references

- The evaluator function lives in `evaluator.cpp:~250` (`EvaluateBlock`).
- Each `register_*_blocks()` definition lives in the matching
  `blocks/*.cpp` file.

---

## `block_helpers.h` (107 lines) and `block_helpers.cpp` (475 lines)

Shared utilities used by multiple block evaluators. Lives outside
`blocks/` because cross-family helpers don't belong to any one
family.

### Key functions

| Function                                    | Purpose |
|---------------------------------------------|---------|
| `HasRequiredPubkeys(block, count)`          | Witness check: block carries at least `count` PUBKEY fields. |
| `HasRequiredHashes(block, count)`           | Witness check: block carries at least `count` HASH256 fields. |
| `VerifyHashPreimageBinding(block)`          | Validate that a HASH_GUARDED-style block's preimage hashes to the committed value. |
| `FetchLadderSighash(ctx, ...)`              | Compute or retrieve the sighash for the current input. Used by every signature-bearing evaluator. |
| `ExtractSchnorrHashType(sig, hash_type)`    | Strip the trailing sighash byte from a 65-byte Schnorr sig if present; default to SIGHASH_DEFAULT (0x00) for 64-byte sigs. |
| `OutputRootMatchesInput(output, input)`     | RECURSE_SAME-style covenant check: spending output's conditions_root matches input's. |
| `ComputeConditionsRootMLSC(c, output_idx)`  | Wrapper around `ComputeConditionsRoot` that also handles MLSC SPK reconstruction. |
| `ComputeExpectedRoot(verified, ...)`        | RECURSE_MODIFIED helper: rebuild a target rung's leaf after applying a mutation. |
| `WriteNumericField(field, val)`             | Serialise an int into a NUMERIC field's data bytes. |
| `ParseMutationSpecs(numerics, ...)`         | Decode RECURSE_MODIFIED mutation specs (block_idx, param_idx, delta) from a list of NUMERIC fields. |
| `struct MutationSpec`                       | `{block_idx, param_idx, delta}`. The mutation tuple. |

### Invariants

- **Sighash must be computed once per input.** `FetchLadderSighash`
  consults the precomputed cache in `LadderEvalContext` and only
  re-computes on cache miss. Sigs across the same rung share the
  same sighash.
- **`OutputRootMatchesInput` enforces the covenant carry rule.** See
  [`feedback_recurse_covenants`](../../../../.claude/projects/-home-defenwycke/memory/feedback_recurse_covenants.md) — RECURSE_SAME / UNTIL preserve
  the full tree (pad outputs); leaf-centric recurses reduce to the
  mutated target rung.

### Cross-references

- `MutationSpec` consumed by recursion blocks (`blocks/recursion.cpp`).
- `FetchLadderSighash` used by `blocks/sig.cpp`, `blocks/compound.cpp`,
  `blocks/qabi.cpp`.

---

## `evaluator.h` (369 lines)

The header complement to `evaluator.cpp`. Defines the per-tx caches
and the `RungEvalContext` consumed by every block evaluator.

### Key types

| Symbol                     | Lines | Purpose |
|----------------------------|------:|---------|
| `struct QABIUint256Hasher` |    62 | Hash functor for unordered_set of `uint256`. Used for O(1) participant-id lookup in QABO cache. |
| `struct QABOVerifiedEntry` |    94 | Per-tx QABIO cache value: `sig_ok`, `computed_root`, `parsed` block (shared_ptr), `vout_matches_outputs`, hash-indexed `entries_set`. |
| `using QABOSigCache`       |   108 | `std::map<uint256, QABOVerifiedEntry>` keyed by sighash. |
| `using PQBatchCache`       |   135 | `std::map<uint256, bool>` keyed by `SHA256(falcon_pubkey)` commit. |
| `struct RungEvalContext`   |   140 | Per-input context: `tx`, `tx_weight`, `precomputed`, `input_index`, `input_amount`, `output_amount`, `block_height`, `spending_output`, `input_conditions`, `spent_outputs`, `spent_output_count`, `relays`, `rung_relay_refs`, `rung_pubkeys`, `verified_leaves`, `mlsc_proof`, `qabo_sig_cache`, `pq_batch_cache`. |
| `enum class EvalResult`    |   174 | `SATISFIED`, `UNSATISFIED`, `ERROR`, `UNKNOWN_BLOCK_TYPE`. |
| `EvalRelays(...)`          |   290 | Validate the relay table referenced by KEY_REF_SIG blocks. |
| `EvalLadder(ladder, ...)`  |   311 | Top-level rung-AND-fold: the loop that picks the satisfying rung. |
| `struct SharedTreeEntry`   |   323 | Cache value: parsed conditions + verified leaves for a tx-source. |
| `using SharedTreeCache`    |   331 | `std::map<Txid, SharedTreeEntry>`. Reused across inputs that spend MLSC outputs from the same creating tx. |
| `VerifyRungTx(CTransaction, ...)` | 355 | Core-typed entrypoint declaration — definition in `evaluator.cpp:1127`. |

### Invariants

- **Cache ordering rules** (lines 95-135 docstrings): the QABO sig
  verify happens once, on the first input that triggers it. The
  PQ_BATCH cache is populated by the lowest-index input carrying
  the anchor witness; lower-indexed non-anchor inputs return
  UNSATISFIED (no cache entry yet). Signers must place anchors at
  the lowest index per commit group.
- **`QABOSigCache` is conditionally compiled.** When `ENABLE_QABIO`
  is off, the type is an empty struct so `RungEvalContext` and
  `VerifyRungTx` signatures stay stable. Callers always pass
  `nullptr` when the extension is disabled.
- **`SharedTreeCache` is keyed by `Txid` of the creating tx.**
  When N inputs spend MLSC outputs from the same fund tx, the
  conditions tree is parsed and verified once.

### Cross-references

- Cache plumbing into Core: `validation.h`'s `ThreadSafeXxxCache`
  wrappers — see [`ANNOTATED_DIFF.md` §4](ANNOTATED_DIFF.md#4-srcvalidationh-54--2).
- Cache use sites: `blocks/qabi.cpp` (PQ_BATCH and QABI_SPEND
  evaluators) and `evaluator.cpp` (per-input dispatch).

---

## `sighash.h` (66 lines) and `sighash.cpp` (224 lines)

Defines `SIGHASH_LADDER` (BIP341-derived, no annex/tapscript/
codeseparator) and `SIGHASH_QABO` (the QABIO coordinator's tx-level
sighash). Two tagged hashes: `LadderSighash/v1` for script-path,
`LadderKeyPathSighash/v1` for key-path.

### Key declarations

| Symbol                                       | Purpose |
|----------------------------------------------|---------|
| `LADDER_SIGHASH_ANYPREVOUT = 0x40`           | BIP-118 analogue: skip prevout commitment. Enables LN-Symmetry / eltoo. |
| `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT = 0xC0`  | Skip prevout AND conditions commitment. Rebindable signatures across scripts. |
| `SignatureHashLadder(cache, tx, nIn, ht, conditions, out)` | Script-path sighash. Tagged hash `LadderSighash/v1`. Commits to conditions hash from spent output. |
| `SignatureHashLadderKeyPath(cache, tx, nIn, ht, out)` | Key-path sighash. Tagged hash `LadderKeyPathSighash/v1`. Does NOT commit to conditions (not revealed in key-path). |

### What's in the sighash

- Epoch (constant 0).
- `hash_type` byte.
- `tx.version`, `tx.locktime`.
- `prevouts`, `amounts`, `sequences` hashes (unless `ANYONECANPAY`).
- `outputs` hash (unless `NONE`).
- `spend_type` (always 0 for ladder — no annex, no extensions).
- Input-specific data (prevout or input index).
- Conditions hash (script-path only): `SHA256(serialised_conditions)`.
- The signed output (`SIGHASH_SINGLE` only).

### Invariants

- **Domain separation.** Ladder sighash never collides with a
  Taproot sighash because the tagged-hash tag string differs. A sig
  valid under `TapSighash` can't validate under `LadderSighash` and
  vice versa. See [`ANNOTATED_DIFF.md` §14](ANNOTATED_DIFF.md#14-srcscriptinterpreterh-4) for
  the SigVersion separation.
- **Key-path sighash drops the conditions commit on purpose.** The
  conditions tree isn't revealed in key-path spends, so binding to
  it would break the spend. The trade-off: a key-path signature is
  rebindable across different conditions trees with the same key.
  This is acceptable because the key-path is by definition a
  trusted-key spend.
- **`SIGHASH_QABO` is defined separately in `sighash.cpp`** (not in
  the header — it's not part of the public ladder sighash surface).
  Used only by QABIO coordinator signing. See `qabi.{h,cpp}` for
  the QABO-specific commitments.

---

## `pq_verify.h` (52 lines) and `pq_verify.cpp` (146 lines)

Thin wrapper around `liboqs` — the only PQ-aware compilation unit in
the library. Every PQ block evaluator (`SIG` with PQ scheme,
`PQ_BATCH`, `QABI_SPEND` FALCON aggregate, etc.) calls
`VerifyPQSignature` here.

### Key functions

| Function                                              | Purpose |
|-------------------------------------------------------|---------|
| `HasPQSupport()`                                      | True if the build has `liboqs` linked. False → all PQ paths fail closed. |
| `VerifyPQSignature(scheme, sig, msg, pubkey)`         | Verify under FALCON-512, FALCON-1024, Dilithium3, or SPHINCS+/SHA. Returns false if the scheme is not compiled in. |
| `SignPQ(scheme, privkey, msg, sig_out)`               | Sign with a PQ private key. Used by RPCs (`signrungtx`, `qabi_signqabo`) and by the test harness. |
| `GeneratePQKeypair(scheme, pubkey_out, privkey_out)`  | Keypair generation for `generatepqkeypair` RPC and tests. |

### Invariants

- **Fail-closed when liboqs missing.** `HasPQSupport()` returns
  false; every verify returns false. A v4 tx that gates an input
  on a PQ signature can never satisfy on a build without PQ
  support — the structural check is the only protection against
  "accidentally permissive" PQ paths in non-PQ builds.
- **Canonical pubkey encoding.** The wrapper does not normalise
  pubkey bytes — callers (and the wire-format reader) are
  responsible for passing the canonical encoding for each scheme.
  PQ_BATCH commits use `SHA256(canonical_pubkey_bytes)`; mismatch
  here is a silent verify failure.

### Cross-references

- Schemes enumerated in `types.h` (`enum class RungScheme`).
- Used by `blocks/sig.cpp`, `blocks/qabi.cpp`, `rpc.cpp`.

---

## `qabi.h` (233 lines) and `qabi.cpp` (416 lines)

QABIO state types and helpers: the `qabi_block` data structure,
serialisation, the auth hash chain, and `SIGHASH_QABO`.

### Key constants

| Constant                              | Value     | Purpose |
|---------------------------------------|----------:|---------|
| `QABI_BLOCK_VERSION_CURRENT`          | 0x01      | Wire-format version of the qabi_block. |
| `QABI_COORDINATOR_PUBKEY_SIZE`        | 897       | FALCON-512 pubkey byte size. |
| `QABI_AGGREGATED_SIG_MAX`             | 666       | FALCON-512 signature byte size (worst case). |
| `QABI_BLOCK_MAX_SOFT`                 | 65,536    | Soft cap — standardness reject above this. |
| `QABI_BLOCK_MAX_HARD`                 | 262,144   | Hard cap — consensus reject above this. ~3,500 participants. |
| `QABI_AUTH_CHAIN_DEFAULT_LENGTH`      | 20,000    | Default chain depth: ~20K hashes ≈ ~150 days at 10-min blocks. |

### Key types and functions

| Symbol                                              | Purpose |
|-----------------------------------------------------|---------|
| `struct QABIEntry`                                  | One participant: `{participant_id, prevout, preimage_commit, output_idx}`. |
| `struct QABIBlock`                                  | Top-level: `{version, batch_id, coord_pubkey, prime_expiry_height, entries[], outputs[]}`. |
| `ComputeQABIRoot(block)` / `(bytes)`                | SHA256 of the canonical serialised block. The committed_root every participant binds to. |
| `ComputeAuthChainTip(seed, length)`                 | `H^length(seed)`. The auth_tip committed in QABI_SPEND. |
| `ComputeAuthChainPreimageAt(seed, length, depth)`   | The preimage at `depth`: `H^(length - depth)(seed)`. Revealed at priming/spend. |
| `ComputeSighashQABO(tx)`                            | Tx-level QABIO sighash. Single coordinator sig covers it for every input. |

### Invariants

- **Auth chain is one-way.** A participant who knows the seed can
  produce a preimage at any depth; an observer who scrapes a depth-N
  preimage from the mempool cannot produce a depth-(N+1) preimage.
  This is what makes Replace-By-Depth (`policy.h::IsValidRBDReplacement`)
  cryptographically meaningful.
- **`ComputeQABIRoot` is canonical.** Two coordinators with the same
  participants and outputs produce the same root iff they serialise
  the same bytes. Block ordering and field encoding are deterministic
  by design.
- **`SIGHASH_QABO` covers `tx.qabi_block`.** Coordinator's signature
  is rebinding-resistant: changing any participant or output entry
  changes the qabi_block bytes and invalidates the sig.

### Cross-references

- Per-input QABI_SPEND evaluator: `blocks/qabi.cpp` (also handles
  PQ_BATCH).
- QABO sig cache: `evaluator.h::QABOSigCache`.
- Coordinator RPCs: `qabi_buildblock`, `qabi_signqabo`,
  `qabi_authchain` — see [`RPC_REFERENCE.md`](RPC_REFERENCE.md#6-qabio-suite).

---

## `serialize.h` (129 lines) and `serialize.cpp` (1,051 lines)

Wire-format read/write for `LadderWitness`, `RungBlock`, `RungCoil`,
`Relay`. The serialiser uses the `*_CONDITIONS` and `*_WITNESS`
implicit field layouts from `types.h` to validate field shape as it
reads — no bespoke per-block parsers.

### Key types and functions

| Symbol                                                 | Purpose |
|--------------------------------------------------------|---------|
| `enum class SerializationContext`                      | `WITNESS` (full witness, includes coil + relays) or `CONDITIONS` (conditions-only, used for sighash). |
| `DeserializeLadderWitness(bytes, ladder, error)`       | Parse witness bytes into `LadderWitness`. Validates against implicit layouts. |
| `SerializeLadderWitness(ladder, ctx)`                  | Inverse: produce wire bytes. |
| `DeserializeBlock(stream, block_out, ...)`             | Parse one block from a data stream. |
| `SerializeRungBlocks(rung, ctx)`                       | Serialise all blocks in a rung. |
| `SerializeCoilData(coil)`                              | Serialise the coil (output_index, scheme, attestation). |
| `SerializeRelayBlocks(relay, ctx)`                     | Relays use the same wire shape as blocks. |

### Invariants

- **Implicit field layouts are the validator.** A block whose bytes
  don't match its layout (wrong count, wrong type, wrong size) is
  rejected at deserialise — never reaches an evaluator. Adding a new
  block type means defining its layout in `types.h`; the deserialiser
  picks it up automatically.
- **CONDITIONS context omits the coil and witness-only fields.** The
  conditions hash used in sighash is computed over the conditions
  serialisation only — committing to witness data would make every
  spend bind to its own witness (chicken-and-egg).
- **PQ_BATCH is the variable-length exception.** Its witness layout
  is `nullptr` (see `types.h` line 1257); the deserialiser accepts
  0 fields (non-anchor) or 2 fields (anchor: PUBKEY + SIGNATURE)
  and the evaluator enforces the 0-or-2 rule.

### Cross-references

- Implicit layouts: `types.h` lines 866+.
- Sighash callers: `sighash.cpp::SignatureHashLadder` reads conditions
  via `SerializeRungBlocks(..., CONDITIONS)`.

---

## `descriptor.h` (170 lines) and `descriptor.cpp` (1,866 lines)

The descriptor language: human-friendly compact notation that
parses to `RungConditions` and formats back. The "front door" for
authoring conditions.

### Key functions

| Function                                                       | Purpose |
|----------------------------------------------------------------|---------|
| `ParseDescriptor(desc, keys, conditions, pubkeys, error)`      | Parse a descriptor string + alias→pubkey map into `RungConditions`. |
| `FormatDescriptor(conditions, pubkeys)`                        | Inverse: produce a descriptor string from conditions. |
| `ParseTxMLSCDescriptor(desc, ...)`                             | Variant for tx-shape descriptors (multiple outputs in one descriptor). |
| `FormatTxMLSCDescriptor(rungs)`                                | Inverse for tx-shape. |

### Key internals (in the .cpp)

- `ParseContext` (line 29) — recursive-descent parser state with
  resource limits: `MAX_PARSE_DEPTH = 32`, `MAX_PARSE_ITEMS = 1000`,
  `MAX_OUTPUT_INDEX = 4096`. Without these a malicious descriptor
  could DoS the parser via deep nesting.
- `ParseBlock(ctx, block, rung_pks)` (line 1008) — the block-name
  dispatch. One `else if` per block name (`sig`, `csv`, `cltv`,
  `multisig`, `qabi_prime`, `qabi_spend`, `pq_batch`, ...).
- `FormatBlock` (~line 1250) — the inverse: a switch on
  `RungBlockType` emits the descriptor form for that block.

### Invariants

- **Round-trip stability.** `Format(Parse(desc))` → equivalent
  conditions. The boost test `descriptor_roundtrip` and
  `descriptor_*_parse_format_roundtrip` enforce this for every block
  type. Adding a new block name to `ParseBlock` requires a matching
  `FormatBlock` arm, or the round-trip test fails.
- **Resource limits are tight.** A descriptor exceeding any of
  `MAX_PARSE_DEPTH`, `MAX_PARSE_ITEMS`, `MAX_OUTPUT_INDEX` is
  rejected with an `error` message naming the limit.
- **Aliases are required for pubkeys.** A descriptor like `sig(@alice)`
  references a pubkey by alias; the caller must provide
  `keys["alice"]` or the parse fails. Hex pubkeys inline are
  rejected to discourage copy-paste mistakes.

### Cross-references

- Used by RPCs: `parseladder`, `formatladder`, `signladder`,
  `computemutation`. See [`RPC_REFERENCE.md`](RPC_REFERENCE.md#1-descriptor-based-authoring).
- Block-name table maintained in lockstep with `RungBlockType` and
  `BlockTypeInfo` in `types.h`.

---

## `policy.h` (100 lines) and `policy.cpp` (339 lines)

Mempool standardness and QABIO Replace-By-Depth (RBD) policy. Pure
predicates — no Core types, no global state.

### Key functions

| Function                                       | Purpose |
|------------------------------------------------|---------|
| `IsBaseBlockType(type)`                        | sig / timelock / hash / compound family. |
| `IsCovenantBlockType(type)`                    | covenant / anchor / governance family. |
| `IsStatefulBlockType(type)`                    | recursion / PLC family. |
| `api::IsStandardRungTx(tx, reason)`            | Mempool policy entry: per-output MLSC format check, qabi_block soft cap, structural. |
| `ExtractQABIPrimeDepth(tx, depth)`             | Pull `committed_depth` from a QABI_PRIME block. |
| `IsQABIPrimingTx(tx)`                          | True if the tx is a QABIO priming. |
| `IsValidRBDReplacement(new_tx, old_tx, reason)`| True iff `new_tx` is a valid RBD replacement of `old_tx`. |

### Invariants

- **RBD asymmetry is cryptographic.** Only the UTXO owner (who knows
  the auth seed) can produce a deeper preimage. A sniper who scrapes
  a shallower preimage from the mempool can be displaced by the
  legitimate owner with one block of delay. This is what makes RBD
  policy meaningful — without the asymmetry, RBD would be a free
  fee-bump griefing primitive.
- **Standardness wraps consensus.** Most structural rejects
  (`MAX_RUNGS`, `MAX_BLOCKS_PER_RUNG`, unknown block types) come
  from the consensus deserialiser. Standardness adds the
  policy-level "this tx will get accepted into mempool" checks on
  top: per-output MLSC format, qabi_block soft cap, etc.

### Cross-references

- Wired into Core via `policy/policy.cpp` — see
  [`ANNOTATED_DIFF.md` §6](ANNOTATED_DIFF.md#6-srcpolicypolicycpp-14).
- RBD called from `validation.cpp::MemPoolAccept::ReplacementChecks` —
  see [`ANNOTATED_DIFF.md` §1](ANNOTATED_DIFF.md#1-srcvalidationcpp-224--15).

---

## `adaptor.h` (58 lines) and `adaptor.cpp` (188 lines)

Adaptor signatures for PTLC (Point Time-Locked Contracts). Three
operations: create an adapted signature, extract the adaptor secret
from a sig pair, verify a pre-signature.

### Key functions

| Function                                                            | Purpose |
|---------------------------------------------------------------------|---------|
| `CreateAdaptedSignature(privkey, sighash, t, sig_out)`              | Produce a BIP-340 sig that uses tweaked nonce `k+t`. The result is a valid Schnorr sig — releases nothing on its own. |
| `ExtractAdaptorSecret(pre_sig, adapted_sig, secret_out)`            | Given the pre-sig `(R, s')` and adapted sig `(R+T, s'+t)`, recover `t = s_adapted - s_pre` (scalar mod n). |
| `VerifyAdaptorPreSignature(pubkey, adaptor_point, pre_sig, sighash)`| Verify that `s'·G == R + e·P` where `e = H(R+T || P || m)`. |

### Invariants

- **The adapted signature is a normal Schnorr signature.** Once
  published, it verifies as `(R+T, s'+t)` against `pubkey` — no
  observer can tell it's adapted. Only the holder of the pre-sig can
  extract `t` from it.
- **Pre-sig verification commits to `R+T`, not to `R`.** This is what
  makes pre-sigs useful: the verifier knows what the eventual
  publication will look like before the secret is revealed.
- **PTLC vs HTLC.** PTLCs use this adaptor scheme; the secret `t` is
  a 32-byte scalar (vs HTLC's hash preimage). The library exposes
  PTLC via the `PTLC` block type; the adaptor crypto here is the
  underlying primitive.

### Cross-references

- PTLC block evaluator: `blocks/compound.cpp`.
- RPCs: `extractadaptorsecret`, `verifyadaptorpresig` in
  [`RPC_REFERENCE.md`](RPC_REFERENCE.md#5-post-quantum-helpers).

---

# Part 2b — Block evaluators (`src/rung/blocks/`)

Each file in `blocks/` owns one block family. The family's
translation unit exports `register_<family>_blocks()`, which the
host's `ladder_init()` calls at startup. The function calls
`RegisterBlock(type, lambda)` once per type it implements; the
lambda forwards `(block, dispatchContext)` to the family's
`Eval<Type>Block` static function.

Files are listed in dependency order: signature blocks first
(used by every other family), then time/hash/covenant/etc.

---

## `blocks/sig.cpp` (334 lines)

Signature-bearing blocks. The most-used block in the library.

### Evaluators

| `RungBlockType` | Function                       | Purpose |
|-----------------|--------------------------------|---------|
| `SIG`           | `EvalSigBlock`                 | One pubkey + one signature. Schnorr (default), ECDSA, or any registered PQ scheme. |
| `MULTISIG`      | `EvalMultisigBlock`            | M-of-N with a fixed pubkey set. |
| `MUSIG_THRESHOLD` | `EvalMusigThresholdBlock`    | M-of-N with MuSig2 aggregation (single Schnorr sig in witness). |
| `ADAPTOR_SIG`   | `EvalAdaptorSigBlock`          | A SIG block whose signature was produced via the adaptor scheme — verified as a normal Schnorr sig. |
| `KEY_REF_SIG`   | `EvalKeyRefSigBlock`           | SIG that references a relay (reusable pubkey table) instead of carrying the pubkey inline. Saves bytes when the same key signs many rungs. |

Two extra helpers stay in this TU:
- `EvalHashPreimageBlock` — used by HASH_SIG and HTLC.
- `EvalHash160PreimageBlock` — same for HASH160 variants.

### Invariants

- **Sighash always comes from `FetchLadderSighash`.** Direct
  computation in this file would bypass the precomputed cache and
  break amortisation across the same input's multiple sig blocks.
- **PQ schemes route through `pq_verify.cpp`.** The `SIG` evaluator
  branches on `scheme`: classical schemes call into the host's
  `LadderSigChecker`; PQ schemes call `VerifyPQSignature`.
- **`KEY_REF_SIG` validates relay bounds.** The relay index in the
  block must point to a relay declared in the witness, with
  matching `relay_refs` for the rung. Out-of-bounds indices fail
  the deserialiser before reaching the evaluator.

---

## `blocks/timelock.cpp` (161 lines)

Pure functional blocks: the input's nSequence (CSV) or the
chainstate's height/time (CLTV) is compared to a constant. No
witness fields, no signature.

### Evaluators

| `RungBlockType` | Purpose |
|-----------------|---------|
| `CSV`           | `nSequence`'s relative-block field ≥ value. |
| `CSV_TIME`      | `nSequence`'s relative-time field ≥ value. |
| `CLTV`          | Block height ≥ value. |
| `CLTV_TIME`     | Block time ≥ value. |

### Invariants

- **Locktime fields are stored as uint32_t, not int.** The library
  internally widens to int64 for comparison; a regression here
  caused a consensus bug in Stage 1 (`1a23fa32c8` — CSV/CLTV uint32
  truncation). See [`feedback`](../../../../.claude/projects/-home-defenwycke/memory/MEMORY.md) for the full incident.

---

## `blocks/hash.cpp` (121 lines)

Hash-equality blocks. Deterministic, no signature.

### Evaluators

| `RungBlockType` | Purpose |
|-----------------|---------|
| `TAGGED_HASH`   | `TaggedHash(tag, preimage) == expected`. Tag and expected are committed in conditions; preimage is in the witness. |
| `HASH_GUARDED`  | `SHA256(preimage) == hash`. The simplest hash gate. |

### Invariants

- **Tag must be a non-empty bytestring.** Empty tag → reject.
- **Preimage size cap:** structurally bounded by the witness max
  preimage size declared in `types.h`.

---

## `blocks/covenant.cpp` (240 lines)

Output-shape covenants: gates that constrain what shape the spending
transaction must have.

### Evaluators

| `RungBlockType` | Purpose |
|-----------------|---------|
| `CTV`           | BIP-119 OP_CHECKTEMPLATEVERIFY: tx commits to template hash. |
| `VAULT_LOCK`    | Two-key vault: hot key + delay vs cold key (no delay). Combines a SIG, a CSV, and a recovery key check in one block. |
| `AMOUNT_LOCK`   | Spending output's value is in `[min, max]`. Used to constrain channel close amounts and similar. |
| `DATA_RETURN`   | **Always returns ERROR.** DATA_RETURN outputs are unspendable by design — the block's purpose is purely to mark the output as unspendable and to carry the data payload (1..40 bytes after the conditions_root). |

### Invariants

- **`VAULT_LOCK` is the canonical hot/cold pattern in one block.**
  Without it, the same effect requires 2 rungs (SIG+CSV on rung 0,
  recovery SIG on rung 1) with the descriptor `or(and(sig(@hot), csv(N)), sig(@cold))`.
  VAULT_LOCK is the compact form, also better for static analysis.
- **`AMOUNT_LOCK` operates on the spending output, not the input.**
  Combined with RECURSE_SAME this gives "spending child UTXO must
  carry the full balance forward, modulo fees".
- **`DATA_RETURN` evaluator is a sentinel.** Returns ERROR
  unconditionally so any spend attempt fails. The output is also
  marked unspendable in `script.h::IsUnspendable` (see
  [`ANNOTATED_DIFF.md` §17](ANNOTATED_DIFF.md#17-srcscriptscripth-17--1)) so it never enters the UTXO set.

---

## `blocks/recursion.cpp` (351 lines)

Self-referential covenants: the spending output's conditions must
match (or modify) the input's. The trickiest family — the spending
output's conditions_root is recovered, recomputed, and compared.

### Evaluators

| `RungBlockType`     | Purpose |
|---------------------|---------|
| `RECURSE_SAME`      | Spending output's conditions_root == input's. The pure carry. |
| `RECURSE_UNTIL`     | Same as RECURSE_SAME, but the recursion stops at a height. After the height, any conditions are allowed. |
| `RECURSE_COUNT`     | Counter decrements by 1 per hop; recursion stops at 0. |
| `RECURSE_SPLIT`     | Lets the UTXO split into multiple re-encumbered outputs, each below `min_sats`. |
| `RECURSE_MODIFIED`  | Same conditions, but with one specified field mutated by `delta`. |
| `RECURSE_DECAY`     | RECURSE_MODIFIED with `delta` decreasing per hop. |

### Invariants

- **Same-tree carry vs leaf-centric mutation.** RECURSE_SAME and
  RECURSE_UNTIL preserve the **full conditions tree**. Leaf-centric
  recurses (RECURSE_MODIFIED, RECURSE_DECAY, RECURSE_COUNT) reduce
  to "the mutated target rung must appear in the spending output's
  tree". See [`feedback_recurse_covenants`](../../../../.claude/projects/-home-defenwycke/memory/feedback_recurse_covenants.md) for the
  exact carry semantics.
- **`param_idx` counts post-fold condition fields.** This is the
  source of two prior bugs (RELATIVE_VALUE int64 overflow, VAULT_LOCK
  hot_delay truncation). The library now derives the field offset
  via the implicit layouts, not by index arithmetic.
- **Recursion has a depth limit** (`max_depth` field). Without it a
  malicious UTXO could create an infinite chain of identical UTXOs
  for a constant fee — the depth field bounds this.

### Cross-references

- Output-conditions recovery: `block_helpers.cpp::OutputRootMatchesInput`.
- Mutation specs: `block_helpers.cpp::ParseMutationSpecs`.

---

## `blocks/anchor.cpp` (268 lines)

Anchor outputs and ancillary "I'm here" markers. Most are
informational — they pass unless their commit/limit fails.

### Evaluators

| `RungBlockType`    | Purpose |
|--------------------|---------|
| `ANCHOR`           | Plain anchor — always passes. Used as a fee-bump attachment point. |
| `ANCHOR_CHANNEL`   | Anchor scoped to a payment channel. |
| `ANCHOR_FEE`       | Bound to a fee constraint (commits to fee in tx). |
| `ANCHOR_POOL`      | Pool-shared anchor (e.g. ghost-pool style). |
| `ANCHOR_RESERVE`   | Reserve marker — proof of liquidity. |
| `ANCHOR_SEAL`      | Single-use seal (cannot be re-anchored). |
| `ANCHOR_ORACLE`    | Oracle attestation marker. |

### Invariants

- **Most anchors are pure — passes unconditionally.** The structural
  checks happen at conditions parse time (field shape) and tx-level
  (one ANCHOR_FEE per tx, ANCHOR_SEAL non-reusable, etc.).
- **ANCHOR_FEE is the one with active logic.** Validates the fee
  constraint against the tx's actual fee (computed from spent
  outputs minus tx outputs).

---

## `blocks/plc.cpp` (429 lines)

Programmable Logic Controller-inspired blocks: hysteresis bands,
timers, latches, counters. Borrowed from the PLC programming model
the descriptor language is named after.

### Evaluators

| `RungBlockType`        | Purpose |
|------------------------|---------|
| `HYSTERESIS_FEE`       | Band gate on fee — passes when fee is in [low, high] band. |
| `HYSTERESIS_VALUE`     | Band gate on output value. |
| `TIMER_CONTINUOUS`     | Timer accumulator (off-chain state). |
| `TIMER_OFF_DELAY`      | Off-delay timer. |
| `LATCH_SET` / `LATCH_RESET` | Memory cell with set/reset semantics. |
| `COUNTER_DOWN` / `COUNTER_PRESET` / `COUNTER_UP` | Counter primitives. |
| `COMPARE`              | Comparator: `value op constant` (op = LT, GT, EQ, etc.). |
| `SEQUENCER`            | Step gate: passes only at the right step number. |
| `ONE_SHOT`             | Edge-triggered: passes once per rising edge. |
| `RATE_LIMIT`           | Wallet rate limit: max satoshis per block window. |
| `COSIGN`               | Cross-input dependency: another UTXO with a specified script hash must be spent in the same tx. |

### Invariants

- **Most PLC blocks are stateless from the chain's perspective.**
  Their "state" is committed in the conditions (the constant) and
  evaluated against the current tx context (input/output values,
  block height). Real PLC-style state machines would need wallet-
  side state tracking; the chain-side check is the snapshot.
- **`COSIGN` reads `spent_outputs`** from the eval context to look
  up the other input being spent. Cross-input dependency — needs
  `RungEvalContext::spent_outputs` populated by the host.
- **`RATE_LIMIT` consults block height** to compute the window.

---

## `blocks/compound.cpp` (307 lines)

Higher-level patterns built from base blocks. Each compound block
is a single descriptor primitive that expands into multiple gates.

### Evaluators

| `RungBlockType`         | Purpose |
|-------------------------|---------|
| `TIMELOCKED_SIG`        | SIG + CSV in one block. |
| `CLTV_SIG`              | SIG + CLTV in one block. |
| `HTLC`                  | Hash Time-Locked Contract: hash preimage OR sig + timelock. |
| `HASH_SIG`              | Hash preimage AND signature. |
| `PTLC`                  | Point Time-Locked Contract — uses the adaptor scheme from `adaptor.{h,cpp}`. |
| `TIMELOCKED_MULTISIG`   | M-of-N + CSV in one block. |

### Invariants

- **Compound blocks are not just descriptor sugar.** They have
  their own consensus-defined evaluation, so the descriptor
  `htlc(@s, @r, P, N)` and the manual expansion `or(and(hash_sig(@r, P)), and(sig(@s), csv(N)))`
  produce **different** wire-format conditions and different
  conditions_roots. Use the compound form for Lightning channels
  and similar to interop with other implementations.

---

## `blocks/governance.cpp` (328 lines)

Tx-shape governance blocks: introspection on tx-level structure
(input count, output count, weight, etc.).

### Evaluators

| `RungBlockType`     | Purpose |
|---------------------|---------|
| `EPOCH_GATE`        | Allow spends only inside a (epoch_size-block) window every epoch. |
| `WEIGHT_LIMIT`      | Max BIP-141 weight of the spending tx. |
| `INPUT_COUNT`       | tx.vin.size() in `[min, max]`. |
| `OUTPUT_COUNT`      | tx.vout.size() in `[min, max]`. |
| `RELATIVE_VALUE`    | Spending output value vs input value: `output >= input * num/den`. |
| `ACCUMULATOR`       | Roll-up commitment: a Merkle root over a witness-supplied set of items. |
| `OUTPUT_CHECK`      | Specific output (by index) must have value in range AND scriptPubKey matching a committed hash. |

### Invariants

- **`OUTPUT_CHECK` is the canonical "treasury must pay X" pattern.**
  Combined with RECURSE_SAME on the change output, it forms the
  basis of vault-with-routing patterns.
- **`RELATIVE_VALUE` arithmetic uses int64.** Earlier int32 caused
  overflow on large values (`a4782caa8e`).
- **`WEIGHT_LIMIT` reads `RungEvalContext::tx_weight`** which the
  host populates via `GetTransactionWeight(tx)` (Core-side helper).
  Zero weight = "host didn't populate" = block fails closed.

---

## `blocks/legacy.cpp` (326 lines)

Wrapper blocks for Bitcoin's pre-v4 script types. These let an MLSC
UTXO contain a P2PKH or P2WSH or P2TR-like spending path — useful
for migration scenarios and for "any of [classic types, new
ladder]" patterns.

### Evaluators

| `RungBlockType`        | Wraps              |
|------------------------|--------------------|
| `P2PK_LEGACY`          | P2PK (raw pubkey + ECDSA sig). |
| `P2PKH_LEGACY`         | P2PKH (HASH160 + ECDSA sig). |
| `P2WPKH_LEGACY`        | P2WPKH (delegates to P2PKH). |
| `P2TR_LEGACY`          | P2TR key-path (XOnlyPubKey + Schnorr sig). |
| `P2SH_LEGACY`          | P2SH wrapper: HASH160 of inner script + inner witness. |
| `P2WSH_LEGACY`         | P2WSH wrapper: HASH256 of inner script + inner witness. |
| `P2TR_SCRIPT_LEGACY`   | P2TR script-path: HASH256 + XOnlyPubKey + inner script + control block. |

A static helper `EvalInnerConditions` (line 63) handles the
P2SH/P2WSH/P2TR_SCRIPT inner-script evaluation by recursively
calling back into the ladder evaluator with the inner conditions.

### Invariants

- **Legacy wrappers don't change classical script semantics.** A
  P2WPKH_LEGACY block with the right HASH160 and witness verifies
  iff the equivalent standalone P2WPKH would verify. The wrapper
  is a routing layer.
- **Inner conditions for P2SH/P2WSH go through the same
  evaluator.** Recursion depth is bounded — see `BlockDispatchContext::depth`
  in `block_dispatch.h`.

---

## `blocks/qabi.cpp` (784 lines — the largest block file)

QABIO + PQ_BATCH evaluators. The most complex per-block code in
the library because it threads the per-tx caches and enforces the
cross-input ordering rules.

### Evaluators

| `RungBlockType` | Purpose |
|-----------------|---------|
| `QABI_PRIME`    | Priming UTXO marker. Validates auth-chain preimage at the priming depth. |
| `QABI_SPEND`    | Batch-spend gate. Validates auth_tip, committed_root, owner_id, expiry; consults the QABO sig cache. |
| `PQ_BATCH`      | The PQ-batch gate. Anchor input verifies pubkey + FALCON sig, populates the cache; non-anchor inputs read the cache. |

When `ENABLE_QABIO` is off, all three are registered with stubs
that return `LADDER_ERR_QABI_DISABLED`.

### Invariants

- **PQ_BATCH ordering.** Anchor input must be at the lowest-index
  PQ_BATCH input per commit group. Non-anchor inputs at lower
  indices return UNSATISFIED (no cache entry yet). See
  `evaluator.h::PQBatchCache` doc.
- **QABI_SPEND derives scheme from pubkey size, not sig size.**
  FALCON sigs are variable-length, so deriving from sig size was
  ambiguous. Stage 1 fix: derive from pubkey size (canonical per
  scheme).
- **QABI_PRIME and QABI_SPEND share the auth chain.** The chain's
  `auth_tip = H^N(seed)` is committed at fund time; priming reveals
  preimage at depth D, spending reveals preimage at depth D+1+.

### Cross-references

- QABIO state types: `qabi.{h,cpp}`.
- Cache plumbing: `evaluator.h::QABOSigCache`, `PQBatchCache`,
  threaded through `validation.cpp` (see [`ANNOTATED_DIFF.md` §1](ANNOTATED_DIFF.md#1-srcvalidationcpp-224--15)).

---

# Part 2c — Boundary, RPC, and small files

## `src/rung_shims.h` (353 lines — lives in `src/`, not `src/rung/`)

The **only** file that crosses the Core ↔ library boundary. Every
function here is `inline` and header-only — there's nothing to link
against. `bitcoin_rung`'s link deps stay limited to crypto, util,
secp256k1, and oqs.

### Purpose

The library is written against adapter types (`LadderTxView`,
`LadderOutputView`, byte spans). Core code uses `CTransaction`,
`CTxOut`, `CScript`, `XOnlyPubKey`, etc. This header provides thin
inline overloads that accept the Core types, build the adapter view,
and forward to the library entry points. It is the **only** way Core
code calls into the library.

### Structure

The file is organised into sections matching the library's surface:

| Section                                | Functions |
|----------------------------------------|-----------|
| Script recognisers                     | `IsMLSCScript(CScript)`, `IsLadderScript(CScript)`, `IsCompactMLSC(CScript)`, `GetMLSCRoot(CScript, uint256&)`, `GetMLSCData(CScript)`, `HasMLSCData(CScript)` |
| Script construction                    | `CreateMLSCScript(root)`, `CreateMLSCScript(root, data)` |
| Conditions parse/serialise             | `IsRungConditionsScript(CScript)`, `DeserializeRungConditions(CScript, ...)`, `SerializeRungConditions(...)` |
| Tx-level checks                        | `IsStandardRungTx(CTransaction, ...)`, `CheckRungTxLevel(CTransaction, ...)`, `ValidateRungOutputs(CTransaction, ...)` |
| QABIO state                            | `ExtractQABIPrimeDepth(CTransaction, ...)`, `IsQABIPrimingTx(CTransaction)`, `IsValidRBDReplacement(CTransaction, CTransaction, ...)` |
| Sighash                                | `SignatureHashLadder(PrecomputedTransactionData, ...)`, `SignatureHashLadderKeyPath(...)`, `ComputeSighashQABO<T>(T)`, `ComputeCTVHash(CTransaction, idx)` |

### Invariants

- **Header-only is load-bearing.** If anything here had to link, the
  boundary would leak: Core's link graph would include library
  internals. The inline-only rule keeps the library a clean
  dependency.
- **No Core type appears in `src/rung/`.** Every Core type that the
  library "sees" goes through one of these adapters. Grep verifies
  this — `grep -rn "CTransaction\|CTxOut\|CScript" src/rung/` should
  return nothing.
- **`ToLadderScript(CScript)`** is the canonical adapter (line 51) —
  reinterprets the `CScript` byte storage as a `std::span<const
  uint8_t>` without copying.

### Why this matters for ports

The library can be wired into a different consensus engine (e.g. a
research codebase, a wallet-only verifier, a different fork's
ancestor) by writing a parallel `<their_shims>.h` with their types.
The library itself never has to change.

---

## `rpc.cpp` (4,217 lines — the largest single file)

All 21 RPC commands plus the dispatch table and registration
function. Organised by RPC suite, each suite contiguous.

### Layout

| Lines       | Suite              | RPCs |
|-------------|--------------------|------|
| 538..789    | Witness inspection | `decoderung`, `createrung`, `serialiseconditions`, `validateladder` |
| 1018..2748  | Construction       | `createrungtx`, `signrungtx` |
| 2749..2796  | CTV                | `computectvhash` |
| 2797..2876  | PQ helpers         | `generatepqkeypair`, `pqpubkeycommit` |
| 2877..2966  | Adaptor signatures | `extractadaptorsecret`, `verifyadaptorpresig` |
| 2967..3209  | Descriptor I/O     | `parseladder`, `formatladder`, `computemutation` |
| 3210..3723  | Descriptor signing | `signladder` |
| 3727..4028  | TX_MLSC modern     | `createrungtx` |
| 4029..4397  | QABIO              | `qabi_buildblock`, `qabi_blockinfo`, `qabi_authchain`, `qabi_signqabo`, `qabi_sighash` |
| 4399..end   | Registration       | `RegisterRungRPCCommands(CRPCTable&)` |

### Design notes

- **Each RPC is `static RPCHelpMan name() { return RPCHelpMan{...}; }`.**
  Standard Core RPC pattern. The lambda inside performs argument
  parsing, calls library functions, and packs UniValue results.
- **Helpers are at the top of the file** (lines 1..537) — JSON →
  RungBlock parsers, hex codec helpers, error formatters. Reused
  across multiple RPCs.
- **`signladder` (513 lines) is the largest.** It walks the
  descriptor, computes per-input sighashes, runs per-block signers,
  builds the witness stack, and returns the signed tx. The
  one-shot RPC for the common case.
- **QABIO RPCs are `#ifdef ENABLE_QABIO`-gated.** When the build
  excludes QABIO, the registration function skips them and callers
  get "method not found".

### Cross-references

- Every RPC documented in [`RPC_REFERENCE.md`](RPC_REFERENCE.md).
- Hooked into Core via `src/rpc/register.h` (one line) — see
  [`ANNOTATED_DIFF.md` §32](ANNOTATED_DIFF.md#32-srcrpcregisterh-3).
- CLI argument types in `src/rpc/client.cpp` — see
  [`ANNOTATED_DIFF.md` §9](ANNOTATED_DIFF.md#9-srcrpcclientcpp-16).

---

## `write_helpers.h` (103 lines)

Library-internal byte-level serialisation helpers. Produces exactly
the bytes Bitcoin Core's `<<` operator would write for the
equivalent types (`int32`, `uint32`, `uint64`, `COutPoint`, `CTxOut`,
CompactSize). **Consensus equivalence depends on this.**

### Why it exists

The library can't `#include <streams.h>` without dragging in Core
types. So `write_helpers.h` reimplements the byte-level encoders
in terms of `std::span<uint8_t>` — independent of Core's stream
abstraction.

### Used by

`sighash.cpp` and `qabi.cpp` — anywhere the library needs to
produce sighash bytes that match what Core's serialiser would have
written. Pure functions, no state.

---

## `types.cpp` (46 lines)

Tiny — implements `RungField::IsValid(reason)`, the per-field
sanity check used by the deserialiser. Validates field size against
the type's min/max, plus two type-specific checks:

- **PUBKEY 33-byte form must start with 0x02 or 0x03** (compressed
  SEC). Other sizes (32 for x-only, 897 for FALCON-512, etc.) skip
  this check.
- **SCHEME must be a known value** (FALCON512, FALCON1024,
  DILITHIUM3, SPHINCS_SHA, SCHNORR, ECDSA).

The rest of the type machinery is header-only in `types.h`.

---

## `CMakeLists.txt` (97 lines)

The library's CMake target. Defines `bitcoin_rung` as a static
library, wires in source files (top-level `src/rung/*.cpp` plus
`blocks/*.cpp`), and declares conditional compilation flags
(`ENABLE_QABIO`, `LADDER_PQ_FALCON`, `LADDER_PQ_DILITHIUM`,
`LADDER_PQ_SPHINCS`).

### Link deps

- `bitcoin_crypto` — SHA256, RIPEMD160, etc.
- `bitcoin_util` — logger, span helpers.
- `secp256k1` — Schnorr/ECDSA verification.
- `liboqs` (optional, when any PQ scheme is enabled).

Critically: **no `bitcoin_consensus`, no `bitcoin_node`.** The
library does not link against Core. The Core side links against
the library via `src/CMakeLists.txt` (one
`add_subdirectory(rung)` + four `target_link_libraries(... bitcoin_rung)`
calls) — see [`ANNOTATED_DIFF.md` §28](ANNOTATED_DIFF.md#28-srccmakeliststxt-5-and-srctestcmakeliststxt-2).

