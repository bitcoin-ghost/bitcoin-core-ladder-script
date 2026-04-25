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

## Files awaiting documentation

The remaining 38 files will be filled in following the same template:
purpose, key functions, invariants, gotchas, cross-references. Order
of priority for completion:

1. `api.h` — adapter types; gate to understanding everything else.
2. `types.h` — block-type registry and field layouts.
3. `conditions.h` / `conditions.cpp` — root computation.
4. `block_dispatch.h` + `block_helpers.{h,cpp}` — registry plumbing.
5. `sighash.{h,cpp}` — SIGHASH_LADDER + SIGHASH_QABO domain definitions.
6. `pq_verify.{h,cpp}` — FALCON / Dilithium / SPHINCS+ wrappers.
7. `qabi.{h,cpp}` — QABIO state types.
8. `serialize.{h,cpp}` — wire format read/write.
9. `descriptor.{h,cpp}` — descriptor parser and formatter.
10. `policy.{h,cpp}` — `IsStandardRungTx` and structural anti-spam.
11. `rpc.cpp` — every RPC, in suite order.
12. `blocks/*.cpp` — one section per family.
13. `adaptor.{h,cpp}` — adaptor signatures (PTLC).
14. `write_helpers.h`, `types.cpp`, `CMakeLists.txt` — small files,
    grouped at the end.
15. `rung_shims.h` (lives in `src/`, not `src/rung/`) — the boundary.
