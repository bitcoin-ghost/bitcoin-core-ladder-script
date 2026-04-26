# Ladder Script: Annotated Library

This document explains the internals of the Ladder Script reference
implementation: 19,533 lines across 39 files in `src/rung/`, plus the
353-line `src/rung_shims.h` boundary header.

It complements [`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md), which covers
the 805-line patch to existing Bitcoin Core code. The patch is the
hooks; this is the engine.

> **Style sample.** This document is being built up incrementally. Part 1
> (the narrative tour) is complete and shows the mental model. Part 2
> ships with one full file section as a style sample
> ([`evaluator.cpp`](#evaluatorcpp-1301-lines)) — the rest will be
> filled in over the next few iterations. If the per-file format isn't
> what you want, this is the moment to redirect.

## Repository layout

```
src/
├── rung_shims.h              353 LOC — Core ↔ library boundary (the ONE adapter)
└── rung/                          ── 19,533 LOC, 39 files
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
    ├── rpc.cpp             4,432  — every RPC: createtxmlsc, signrungtx, qabi_*
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

## 3. Build the transaction (`createtxmlsc`)

The user calls `createtxmlsc` (RPC implementation in `rpc.cpp`,
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
## Files awaiting documentation

Sections complete: `evaluator.cpp`, `api.h`, `types.h`, `conditions.{h,cpp}`.

Next batches in priority order:

- **Tier 2:** `block_dispatch.h`, `block_helpers.{h,cpp}`, `evaluator.h`, `sighash.{h,cpp}`, `pq_verify.{h,cpp}`
- **Tier 3:** `qabi.{h,cpp}`, `serialize.{h,cpp}`, `descriptor.{h,cpp}`, `policy.{h,cpp}`, `adaptor.{h,cpp}`
- **Tier 4:** `blocks/*.cpp` (one section per family — sig, timelock, hash, covenant, recursion, anchor, plc, compound, governance, legacy, qabi)
- **Tier 5:** `rung_shims.h` (the boundary), `rpc.cpp` (4,432 LOC, organised by suite), `write_helpers.h`, `types.cpp`, `CMakeLists.txt`
