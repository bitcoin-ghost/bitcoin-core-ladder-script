# Ladder Script: Annotated Diff Against Bitcoin Core v30.0

This document explains every change made to Bitcoin Core v30.0 to integrate
Ladder Script. It is a review aid for Bitcoin Core developers evaluating the
architectural choices, alternatives considered, and security properties of
each modification.

> **Source-of-truth note.** Line numbers cited here are approximate and drift as
> the code evolves. Use file paths and function names for navigation. The
> authoritative reference is `git diff v30.0..HEAD -- src/`. The library
> internals (everything under `src/rung/`) are documented in the companion
> [Annotated Library](ANNOTATED_LIBRARY.md).

## Overview

| Category                         | Files | Lines added |
|----------------------------------|------:|------------:|
| Modified Bitcoin Core files      |    29 |       +805  |
| New library code (`src/rung/`)   |    39 |    +19,318  |
| New tests (`src/test/rung_tests.cpp`) |    1 |    +16,945  |
| **Total surface change**         |    69 |    +37,068  |

The design principle is **minimal core intrusion**: the 805 patched lines
add hooks, types, and routing — all real logic lives in the self-contained
`src/rung/` library which Core treats as just another linked dependency
(`bitcoin_rung`).

The patch never modifies existing Bitcoin Script evaluation, signature
verification, or consensus logic for non-v4 transactions. Two existing
function signatures gain defaulted parameters (`block_height` plumbing on
`CScriptCheck`) — every existing call site continues to compile unchanged.
No existing transaction version is reinterpreted; v4 is additive.

---

## Core Integration Points (29 files, +805 lines)

The sections below are ordered by impact (highest LOC first) so that a
reviewer scanning the patch sees the architectural changes before the
bookkeeping ones.

### 1. `src/validation.cpp` (+224 / -15)

The largest single Core change. Wires v4 transactions into the existing
script-verification pipeline at four points and threads three per-tx caches
through the check queue.

**Insertions:**

- `CScriptCheck::operator()` (around line 2152). The standard
  `VerifyScript` call is the default path. When the spent output's scriptPubKey
  is MLSC (0xDF prefix) **and** the spending tx is v4, control routes into
  `rung::VerifyRungTx(...)` instead. Mixed-input v4 transactions (some
  MLSC inputs, some classical) work transparently — each input takes its
  own path based on its prevout type, not the spending tx version alone.
- `CheckInputScripts` (around line 2309). After all per-input checks
  succeed, v4 transactions get a tx-level pass: `rung::CheckRungTxLevel`
  validates the conditions_root, the qabi_block layout, and any
  cross-input invariants (PQ_BATCH cache consistency, QABIO output-set
  binding). This runs once per tx, not per input.
- `MemPoolAccept::ReplacementChecks` (around line 1099). RBF behaviour is
  extended for QABIO priming transactions — `rung::IsValidRBDReplacement`
  enforces that a primed UTXO can only be replaced under the deterministic
  rules in the QABIO spec. Standard BIP125 RBF still applies to
  non-priming v4 txs.
- `Chainstate::DisconnectBlock` (around line 2510). When unwinding a v4
  tx during a reorg, the synthetic root coin entry written at
  `(txid, MLSC_ROOT_VOUT)` is removed alongside the regular vouts.

**Cache plumbing.** Three per-tx caches are constructed in
`CheckInputScripts` and passed by `shared_ptr` into every `CScriptCheck`
for that tx:

- `ThreadSafeSharedTreeCache` — same-source proof sharing. When multiple
  inputs spend MLSC outputs created by the same tx, the conditions_root
  and inflated leaves are computed once and reused.
- `ThreadSafeQABOSigCache` — QABIO FALCON-512 verify cache. All inputs of
  a QABIO tx share one coordinator signature over `SIGHASH_QABO`; one
  verify per tx, not per input.
- `ThreadSafePQBatchCache` — PQ_BATCH anchor-verified cache. The lowest-
  index input gated by a given `SHA256(falcon_pubkey)` does the verify;
  every other input gated by the same hash short-circuits via the cache.

The shared_ptr lifetime matches the tx's script-verification work unit.
After the check queue drains, the caches go out of scope.

**Why a tx-level pass on top of per-input checks.** Some v4 invariants
are inherently cross-input (the PQ_BATCH anchor must exist before non-
anchor inputs are validated; QABIO requires the coordinator signature to
match the committed output set). The per-input pipeline can't express
"this input depends on another input's verdict". `CheckRungTxLevel` runs
after every input has individually passed and validates the cross-input
shape.

---

### 2. `src/primitives/transaction.h` (+207 / -9)

Adds the v4 wire format and the three new transaction-level fields. The
file's existing serialisation templates are extended — no existing v1/v2/
v3 path is touched.

**Constants and fields:**

- `RUNG_TX_VERSION = 4` on `CTransaction`.
- Three new fields on both `CTransaction` and `CMutableTransaction`:
  - `uint256 conditions_root` — shared MLSC root for every output in the tx.
  - `std::vector<uint8_t> qabi_block` — tx-level QABIO batch block (empty for non-QABIO v4 txs).
  - `std::vector<uint8_t> aggregated_sig` — QABIO coordinator FALCON-512 signature, exactly 666 bytes when present.

**Wire format (full, witness-carrying)** — triggered when
`(allow_witness && version == 4)`, flag byte = `0x02`:

```
uint32_t  version (=4)
uint8_t   dummy = 0x00
uint8_t   flags = 0x02
vin       std::vector<CTxIn>
uint256   conditions_root                 (32 bytes — shared across all outputs)
varint    n_outputs
per output:
  int64_t nValue                          (8 bytes)
  if nValue == 0:                         (DATA_RETURN marker)
    varint   data_len (1..40)
    uint8_t  data[data_len]
per input:
  CScriptWitness witness
varint    qabi_block_len
uint8_t   qabi_block[]                    (QABIO tx-level block)
varint    aggregated_sig_len
uint8_t   aggregated_sig[]                (FALCON-512, exactly 666 B when present)
uint32_t  nLockTime
```

**Stripped form (no-witness, txid input)** — triggered when
`(!allow_witness && version == 4)`, no flag byte:

```
uint32_t  version (=4)
vin       std::vector<CTxIn>
uint256   conditions_root
varint    n_outputs
per output: nValue + (if zero: DATA_RETURN data_len + data)
uint32_t  nLockTime
```

**Why value-only outputs (8 bytes on the wire).** Every MLSC output has
the same scriptPubKey: `0xDF || conditions_root`. Storing the 33-byte SPK
per output would waste 32 bytes per output for a value the tx already
carries once. The stripped form puts the conditions_root once and writes
only the 8-byte value per output — this is what makes the asymptotic
8 vB/output cost (and the 12× UTXO-set saving in the chainstate; see
`compressor.cpp` below). On deserialisation, each `vout[i].scriptPubKey`
is reconstructed as `0xDF || conditions_root`, so all downstream code
that touches `tx.vout[i].scriptPubKey` sees a normal-looking 33-byte SPK.

**Why a new flag byte (`0x02`) rather than extending SegWit (`0x01`).**
SegWit's witness stack is per-input. The TX_MLSC `conditions_root` and
`qabi_block` are per-tx. Cramming per-tx data into per-input witness
structures would require a synthetic "transaction witness" that doesn't
map to any vin index. Flag `0x02` is a clean extension point — BIP 141
explicitly reserves non-`0x01` flag values for future use. The
deserialiser explicitly throws on flag `0x03` (SegWit + TX_MLSC
combined): if a future format wants both, it needs its own format
specification, and silent acceptance of `0x03` could create
deserialisation mismatches between nodes.

**Why DATA_RETURN is signalled by `nValue == 0`.** Consensus requires
non-DATA_RETURN MLSC outputs to be ≥ `MIN_RUNG_OUTPUT_VALUE` (546 sats),
so a zero-value output is a structurally unique wire-level marker. The
deserialiser reads `data_len` (1..40) followed by the payload and
reconstructs `vout[i].scriptPubKey = 0xDF || conditions_root || data`.
This means normal outputs pay zero overhead for the mechanism — the
"cheapest tx type at N=1" claim (109 vB vs P2WPKH's 110 vB) is preserved.
A DATA_RETURN output costs ~41 vB for 40 bytes of data, comparable to
OP_RETURN's ~43 vB.

**Why `aggregated_sig` is FALCON-specific now.** An earlier design
reserved this field for half-aggregated Schnorr `s` values. That role is
served by per-input signatures inside the witness stacks. The field's
current purpose is the QABIO coordinator FALCON-512 signature — present
only when the tx contains QABIO inputs. Empty for any other v4 tx.

---

### 3. `src/compressor.cpp` (+68 / -1) and `src/compressor.h` (+1 / -1)

Adds **special script type `0x06`** for MLSC outputs in the chainstate.
The compressed form is one byte (the `0x06` marker); the 32-byte
`conditions_root` is **not** stored per-coin. This is the load-bearing
mechanism behind the chainstate UTXO economy.

**Implementation:**

- `ScriptCompression::nSpecialScripts` bumped from 6 to 7.
- `IsToMLSC(...)` recognises a 33-byte `0xDF || root[32]` script.
- `CompressScript(...)` writes a single `0x06` byte for any MLSC SPK.
- `GetSpecialScriptSize(0x06)` returns 0 — no payload bytes follow the
  marker.
- `DecompressScript(...)` for type `0x06` returns just the 1-byte
  `0xDF`. The root is recovered separately at spend time via the block
  database.

**Per-coin chainstate cost:** ~3 bytes for an MLSC coin (1-byte SPK
after compression + the value varint + the height/coinbase byte) versus
24 for P2WPKH and 36 for P2TR. At scale this is the headline UTXO-set
saving.

**The load-bearing invariant** — a long block comment at the top of the
file states it explicitly:

> v4 UTXOs cannot be validated without access to the creating block.
> Any validation path that treats UTXOs as self-describing is incorrect
> for v4.

Three call sites must respect this:

1. **`assumeutxo` / snapshot loading** must carry or reconstruct the
   conditions_root for every MLSC UTXO in the snapshot, or reject
   snapshots that include any MLSC UTXO.
2. **Stateless library verifiers** must accept the conditions_root via
   an explicit accessor — see libladder's `fetch_conditions_root`
   callback. This is the one piece of state that prevents libladder
   from being pure byte-in / byte-out (analogous to how `libsecp256k1`
   takes a `SigVersion`).
3. **Pruned nodes** keep the creating tx's block indefinitely while any
   spawned MLSC UTXO is unspent, via the standard undo-data retention
   path. This works today, but it is load-bearing — any change to
   pruning around MLSC UTXOs must replace the access path first.

A change to type-`0x06` semantics that breaks the recovery path is a
**silent consensus divergence**: nodes that can recover the root accept
spends that nodes that cannot recover it reject.

---

### 4. `src/validation.h` (+54 / -2)

Type definitions and constructor extension to support the cache plumbing
in `validation.cpp`.

**Three thread-safe cache wrappers:**

```cpp
struct ThreadSafeSharedTreeCache  { mutable Mutex mutex; rung::SharedTreeCache cache; };
struct ThreadSafeQABOSigCache     { mutable Mutex mutex; rung::QABOSigCache    cache; }; // ENABLE_QABIO
struct ThreadSafePQBatchCache     { mutable Mutex mutex; rung::PQBatchCache    cache; };
```

Each is per-tx and lives only as long as the script-verification work
unit. The wrappers exist in Core because `CScriptCheck` ships them
between worker threads in the script check queue — Core owns the
threading, the library owns the cache logic.

The QABIO cache is conditionally compiled. When `ENABLE_QABIO` is off,
`ThreadSafeQABOSigCache` is an empty struct so that `shared_ptr` members
and constructor parameters on `CScriptCheck` stay compilable without
`#ifdef`s at every call site. Code that touches `.mutex` or `.cache` is
still guarded.

**`CScriptCheck` constructor extension:** adds four parameters with
default values — `block_height = 0`, three `nullptr` cache pointers.
Existing call sites continue to compile unchanged; v4-aware call sites
populate the parameters.

```cpp
CScriptCheck(const CTxOut& outIn, const CTransaction& txToIn,
             SignatureCache& signature_cache,
             unsigned int nInIn, unsigned int nFlagsIn, bool cacheIn,
             PrecomputedTransactionData* txdataIn,
             int32_t block_height = 0,
             std::shared_ptr<ThreadSafeSharedTreeCache> shared_tree_cache = nullptr,
             std::shared_ptr<ThreadSafeQABOSigCache>    qabo_sig_cache    = nullptr,
             std::shared_ptr<ThreadSafePQBatchCache>    pq_batch_cache    = nullptr);
```

The `block_height` parameter is consumed by timelock evaluators (CSV,
CLTV, CLTV_TIME, etc.) inside the ladder block dispatcher.

---

### 5. `src/compressor.h` (+1 / -1)

Single-line change: bumps `nSpecialScripts` from 6 to 7. The new value
is 0x06 = MLSC. The full mechanism lives in the `.cpp` (section 3).

---

### 6. `src/policy/policy.cpp` (+14)

Three insertions, all routing-only:

- `IsStandardTx(...)` — at the top of the function, v4 transactions
  delegate to `rung::IsStandardRungTx(tx, reason)`. Ladder's
  per-tx-version policy is structural (per-tx caps on rungs, blocks,
  fields, preimage count); the existing standardness checks for v1-v3
  don't apply.
- `AreInputsStandard(...)` — `if (rung::IsLadderScript(prev.scriptPubKey)) continue;`.
  MLSC inputs are validated by the ladder evaluator, not by the
  classical input-standardness rules that look for known TxoutTypes.
- `IsWitnessStandard(...)` — same skip for MLSC inputs. The ladder
  witness has its own structural checks.

These are skips, not parallel implementations: if a tx contains a mix of
MLSC and classical inputs, each is validated by the right path.

---

### 7. `src/rpc/mining.cpp` (+18 / -1)

Pure operability fix unrelated to v4 consensus. `generatetoaddress`'s
`maxtries` parameter is documented as per-block but is actually a shared
nonce-attempt budget across every requested block. On signet/testnet/
mainnet the default budget runs out partway through a multi-block
request and the caller silently sees fewer block hashes than requested.

The patch:

- Logs `"generatetoaddress: maxtries exhausted after %d of %d blocks"`
  whenever the inner loop breaks early, so operators see the cause.
- Updates the RPC help text to describe `maxtries` as the shared budget
  it actually is.

This was added during signet bringup of the ladder-script node and is
unrelated to consensus. Kept in the patch because it affects every
multi-block test run against a live signet.

---

### 8. `src/coins.cpp` (+14) and `src/coins.h` (+4)

Defines and writes the **synthetic root coin entry**.

In `coins.h`:

```cpp
//! Sentinel vout index for TX_MLSC root entry.
static constexpr uint32_t MLSC_ROOT_VOUT = 0xFFFFFFFF;
```

`AddCoins` in `coins.cpp` writes the regular vouts as before, then for
v4 transactions also writes a special coin at `(txid, MLSC_ROOT_VOUT)`:

```cpp
CTxOut root_out;
root_out.nValue = 0;
root_out.scriptPubKey.resize(33);
root_out.scriptPubKey[0] = 0xDE;            // synthetic root marker — NOT 0xDF
memcpy(&root_out.scriptPubKey[1], tx.conditions_root.data(), 32);
cache.AddCoin(COutPoint(txid, MLSC_ROOT_VOUT),
              Coin(std::move(root_out), nHeight, false), false);
```

**Why prefix `0xDE`, not `0xDF`.** The compressor recognises `0xDF` as a
real MLSC SPK and would strip the 32-byte payload (section 3). The
synthetic entry must keep its payload, so it uses `0xDE` — invisible to
the compressor's special-case path and stored verbatim. At spend time,
the validator looks up `(txid, MLSC_ROOT_VOUT)`, asserts the marker
byte, and reads the 32-byte root.

**Why a coin entry, not a separate database.** Reuses the existing
chainstate machinery — atomic with regular vout writes, automatically
rolled back on `DisconnectBlock`, picked up by snapshots. Costs one
extra cache entry per v4 tx; pays for itself ~10× on a 10-output tx via
the per-coin compression saving.

---

### 9. `src/rpc/client.cpp` (+16)

Adds RPC argument-type entries for the ladder RPCs. Without these,
`bitcoin-cli` forwards numeric/array/object arguments as JSON strings
and the server-side type check rejects them with
`"JSON value of type string is not of expected type number"`.

Covers every non-string positional arg for `createrungtx`, `signrungtx`,
`qabi_authchain`, and `qabi_buildblock`. No effect on validation; this
is purely the CLI-to-RPC type bridge.

---

### 10. `src/script/interpreter.cpp` (+14)

Inside `PrecomputedTransactionData::Init()`, after the existing BIP143
and BIP341 precomputation blocks, a new block computes ladder-specific
cached hashes when the tx is v4 and spent outputs are available:

```cpp
if (txTo.version == CTransaction::RUNG_TX_VERSION && m_spent_outputs_ready) {
    if (!uses_bip143_segwit && !uses_bip341_taproot) {
        m_prevouts_single_hash = GetPrevoutsSHA256(txTo);
        m_sequences_single_hash = GetSequencesSHA256(txTo);
        m_outputs_single_hash = GetOutputsSHA256(txTo);
    }
    m_spent_amounts_single_hash = GetSpentAmountsSHA256(m_spent_outputs);
    m_ladder_ready = true;
}
```

The guards reuse the existing single-SHA256 hash fields rather than
duplicating storage. `GetPrevoutsSHA256(...)` etc. produce identical
results regardless of which protocol asks; if BIP143 or BIP341 already
populated them, the ladder block reuses those values.

`m_spent_amounts_single_hash` is computed unconditionally for v4 because
the existing code only computes it inside the BIP341 branch.

---

### 11. `src/policy/policy.cpp` — see section 6 above.

---

### 12. `src/coins.cpp` — see section 8 above.

---

### 13. `src/rpc/util.cpp` (+9 / -3)

Pure correctness fix: `RPCArg::ToStringObj(...)` previously hit
`NONFATAL_UNREACHABLE()` for `OBJ` and `OBJ_USER_KEYS` types. The ladder
RPCs use nested objects in their argument schemas (`createrungtx`'s
`rungs` array is an array of objects with nested arrays of blocks with
nested arrays of fields), so the help text generator started exercising
this code path for the first time.

The fix recursively serialises `m_inner` for `OBJ`, `OBJ_NAMED_PARAMS`,
and `OBJ_USER_KEYS`. No behavioural change for non-nested RPC arg
schemas.

---

### 14. `src/script/interpreter.h` (+4)

Two additions to support the v4 sighash domain:

- `m_ladder_ready` flag on `PrecomputedTransactionData` — true after
  `Init()` populated the ladder-specific hashes (see section 10).
- `SigVersion::LADDER = 4` — separate `SigVersion` enum value for
  Ladder Script.

**Why a new SigVersion rather than reusing TAPROOT.** Ladder uses the
tagged hash `TaggedHash("LadderSighash")`; Taproot uses
`TaggedHash("TapSighash")`. If both shared a SigVersion the evaluator
would need to inspect the tx version to choose which tag to use. Domain
separation via SigVersion is the standard idiom — a signature valid
under TapSighash must never validate under LadderSighash, and the
type-level separation guarantees that. Forward compatibility: future
ladder sighash evolutions don't couple to BIP 341 changes.

---

### 15. `src/pubkey.h` (+9) and `src/pubkey.cpp` (+35)

Adds the **LadderTweak/v1** scheme: a Taproot-style key tweaking
mechanism with a separate tag.

```cpp
class XOnlyPubKey {
    uint256 ComputeLadderTweakHash(const uint256* merkle_root) const;
    bool    CheckLadderTweak(const XOnlyPubKey& internal,
                             const uint256& merkle_root, bool parity) const;
    std::optional<std::pair<XOnlyPubKey, bool>>
            CreateLadderTweak(const uint256* merkle_root) const;
};
```

The implementation mirrors `ComputeTapTweakHash` /  `CreateTapTweak` /
`CheckTapTweak` byte-for-byte except for the tag string. A single
`HashWriter HASHER_LADDERTWEAK{TaggedHash("LadderTweak/v1")}` is
constructed once at namespace scope and reused.

**Why a separate tag.** Same domain-separation argument as `SigVersion`:
a key tweaked under `LadderTweak/v1` must not match a key tweaked under
`TapTweak`. The "/v1" suffix gives a clean upgrade path if the scheme
ever rev's.

---

### 16. `src/key.cpp` (+17) and `src/key.h` (+3)

Adds `CKey::SignSchnorrLadder(...)` — a Schnorr signer that applies the
LadderTweak before signing. Identical structure to the existing
`SignSchnorr` but calls `XOnlyPubKey::ComputeLadderTweakHash` for the
tweak instead of `ComputeTapTweakHash`. Used by the ladder evaluator
when verifying tweaked-key paths and by `signrungtx` when producing
signatures for funding-time tweaked outputs.

---

### 17. `src/script/script.h` (+17 / -1)

Extends `CScript::IsUnspendable()` to recognise MLSC DATA_RETURN
outputs. Today the test is:

```cpp
return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
```

The patch adds a third clause:

```cpp
if (size() > 33 && size() <= 73 && (*this)[0] == 0xDF) return true;
```

The size band 34..73 is exactly DATA_RETURN: 1 marker + 32-byte root +
1..40 bytes of data. Bare MLSC (33 bytes: 0xDF + root) is **not**
matched — those are normal spendable outputs. Matching DATA_RETURN
keeps these outputs out of the UTXO set (parity with OP_RETURN) and
exempts them from the dust-threshold standard policy check.

The DATA_RETURN block evaluator returns ERROR for every spend attempt,
so these outputs are consensus-unspendable regardless. Marking them
unspendable here is the optimisation: the chainstate never has to
hold them.

---

### 18. `src/test/coins_tests.cpp` (+18 / -3)

Test updates for the new synthetic root entry behaviour. Existing
coin-cache tests asserted on cache size before/after `AddCoins`; v4
transactions now write `n_outputs + 1` entries, so the assertions are
extended to handle both pre- and post-v4 paths.

---

### 19. `src/rpc/mining.cpp` — see section 7 above.

---

### 20. `src/script/script_error.h` and `src/script/script_error.cpp` (+8 total)

Two new error codes:

```cpp
SCRIPT_ERR_LADDER_INVALID_WITNESS,  // "Invalid ladder witness format"
SCRIPT_ERR_LADDER_EVAL_FALSE,       // "Ladder script evaluation returned false"
```

Returned by `rung::VerifyRungTx`. Surfaced through the standard
`ScriptError` channel so tools that already format script errors
(`bitcoin-cli`, RPCs, GUI debug log) handle them with no code changes.

---

### 21. `src/key.h` and `src/key.cpp` — see section 16 above.

---

### 22. `src/rpc/client.cpp` — see section 9 above.

---

### 23. `src/script/interpreter.cpp` — see section 10 above.

---

### 24. `src/policy/policy.cpp` — see section 6 above.

---

### 25. `src/coins.cpp` — see section 8 above.

---

### 26. `src/pubkey.h` — see section 15 above.

---

### 27. `src/rpc/mempool.cpp` (+5)

`sendrawtransaction` and `submitpackage` both check `out.scriptPubKey.IsUnspendable()`
against `max_burn_amount` to refuse accidentally large burns. MLSC
outputs use the non-standard `0xDF` opcode and would trip the unspendable
check on any non-DATA_RETURN MLSC output. The patch skips the burn check
for MLSC outputs explicitly:

```cpp
if (rung::IsLadderScript(out.scriptPubKey)) continue;
```

---

### 28. `src/CMakeLists.txt` (+5) and `src/test/CMakeLists.txt` (+2)

Build-system glue:

- `add_subdirectory(rung)` to descend into the library.
- `bitcoin_rung` linked into `bitcoin_common`, `bitcoin_node`, `bitcoind`,
  and (when `ENABLE_IPC`) `bitcoin-node`.
- `rung_tests.cpp` added to the unit-test executable, with `bitcoin_rung`
  linked into `test_bitcoin`.

The library is a normal CMake target, so reviewers can build it in
isolation:

```bash
cmake --build build --target bitcoin_rung
```

---

### 29. `src/script/script_error.h` and `src/script/script_error.cpp` — see section 20 above.

---

### 30. `src/coins.h` — see section 8 above.

---

### 31. `src/primitives/transaction.cpp` (+3 / -3)

Constructor plumbing for the three new fields. Without explicit
initialisation, `CMutableTransaction` and `CTransaction` copy/move
constructors would default-construct the new fields and silently lose
v4 data, producing wtxid mismatches and consensus failures.

```cpp
CMutableTransaction::CMutableTransaction(const CTransaction& tx) :
    vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime},
    conditions_root{tx.conditions_root},
    qabi_block{tx.qabi_block},
    aggregated_sig{tx.aggregated_sig} {}

CTransaction::CTransaction(CMutableTransaction&& tx) :
    vin(std::move(tx.vin)), vout(std::move(tx.vout)),
    version{tx.version}, nLockTime{tx.nLockTime},
    conditions_root{tx.conditions_root},
    qabi_block{std::move(tx.qabi_block)},
    aggregated_sig{std::move(tx.aggregated_sig)},
    m_has_witness{ComputeHasWitness()}, hash{ComputeHash()},
    m_witness_hash{ComputeWitnessHash()} {}
```

`conditions_root` is copied by value (uint256 is trivially copyable);
the two vectors are moved in the move constructor.

---

### 32. `src/rpc/register.h` (+3)

Registers `RegisterRungRPCCommands(CRPCTable&)` alongside the other
core RPC registrations. Implementation lives in `src/rung/rpc.cpp` —
`createrungtx`, `signrungtx`, `qabi_*`, `serialiseconditions`, etc.

---

### 33. `src/key.h` — see section 16 above.

---

### 34. `src/test/txvalidationcache_tests.cpp` (+2 / -1)

Test surface adjustment: a v4 transaction is constructed in the
existing cache test, so the `CScriptCheck` constructor now needs the
new defaulted parameters. Single test signature update.

---

### 35. `src/test/CMakeLists.txt` — see section 28 above.

---

### 36. `src/compressor.h` — see section 5 above.

---

## Tests

`src/test/rung_tests.cpp` — **16,945 lines, 619 unit tests** organised
into multiple boost test suites:

- `rung_tests` — block evaluator unit tests, descriptor parser, witness
  serialisation, anti-spam, sighash binding.
- `qabi_tests` — QABIO + PQ_BATCH evaluator tests, multi-party scale
  scenarios, size-sweep measurements (`mlsc_creation_tx_size_sweep`,
  `qabi_tx_size_sweep`, etc. — see `MEASUREMENTS.md`).
- `tx_mlsc_tests` — wire-format roundtrips for the v4 transaction
  serialiser.

Plus 8 functional tests (52 distinct test methods) under `test/functional/`:
`feature_rung_tx.py`, `feature_rung_p2p.py`, `feature_rung_legacy.py`,
`feature_rung_pq_batch.py`, `feature_rung_pq_batch_stress.py`,
`feature_rung_fuzz.py`, `feature_qabi.py`, `feature_qabi_size.py`.

---

## Security properties summary

Every change in this patch is one of:

- **Additive routing.** A new code path for `tx.version == 4` with no
  effect on v1/v2/v3. Sections 1, 6, 14, 17, 27 fall here.
- **Type definition.** New constants, fields, error codes, sigversion
  values. Sections 2, 4, 5, 14, 20 fall here.
- **Build wiring.** `CMakeLists.txt`, RPC registration. Sections 28, 32.
- **Standalone helper.** New schemes (LadderTweak), CLI bridge
  (RPC arg types), pretty-printing (`core_write.cpp` MLSC display).
  Sections 9, 15, 16, 36 fall here.

No existing function changes behaviour for non-v4 transactions. The two
defaulted-parameter additions (`CScriptCheck` constructor) are
source-compatible — every existing call site continues to work without
modification.

The single load-bearing **invariant outside the library** is the UTXO
recovery path: v4 coins compress to 1 byte and require the creating
block to recover the conditions_root. `assumeutxo`, stateless
verifiers, and pruning logic must respect this. The invariant is
documented in `src/compressor.cpp`'s top-of-file comment and re-stated
in section 3 above.

---

## Reading order for a reviewer

If you have one hour:

1. This document, sections 1–4 (the four largest patches).
2. `compressor.cpp`'s top-of-file invariant comment.
3. The TX_MLSC wire format spec in `primitives/transaction.h:215-265`.
4. [`ANNOTATED_LIBRARY.md`](ANNOTATED_LIBRARY.md) Part 1 — narrative
   tour of one RUNG_TX from fund to consensus.

If you have a day:

1. Everything above.
2. The full per-file walkthrough in this document.
3. [`ANNOTATED_LIBRARY.md`](ANNOTATED_LIBRARY.md) Part 2 — file-by-file
   library reference.
4. [`MEASUREMENTS.md`](MEASUREMENTS.md) — empirical sizes against the
   reference implementation.

If you are deep-reviewing for soft-fork activation: read the BIP draft
(`BIP-XXXX.md`), then this document, then the library, then the TLA+
specs in `tla/`.
