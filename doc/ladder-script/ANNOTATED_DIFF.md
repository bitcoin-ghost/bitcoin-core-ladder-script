# Ladder Script: Annotated Diff Against Bitcoin Core v30.0

This document explains every change made to Bitcoin Core v30.0 to integrate Ladder Script.
It is intended as a review aid for Bitcoin Core developers evaluating the architectural
choices, alternatives considered, and security properties of each modification.

The patch file is `ladder-script-v30.0.patch` (29,081 lines, 48 files).

> **Note:** Source line numbers cited in this document are approximate and may drift as the
> code evolves. Use function names and file paths for navigation. The patch file is the
> authoritative reference for the exact diff.

## Overview

| Category | Files changed | Lines added |
|----------|--------------|-------------|
| New module (src/rung/) | 22 (incl. CMakeLists.txt) | ~14,771 |
| Tests | 2 (unit + functional) | ~13,208 |
| Core integration | 24 | ~411 |
| **Total** | **48** | **~28,390** |

The design principle is **minimal core intrusion**: ~411 lines across 24 existing Bitcoin
Core files, with all Ladder Script logic contained in a self-standing `src/rung/` module.
No existing Bitcoin Core function signatures are changed (two gain defaulted parameters for block_height plumbing). No existing opcodes are modified.
No existing transaction versions are reinterpreted. The v4 transaction format is additive.

---

## Core Integration Points (24 files, ~411 lines)

### 1. src/primitives/transaction.h (~112 lines added)

#### What was added

- **`RUNG_TX_VERSION = 4`** constant on `CTransaction` (line 393)
- Three new fields on both `CTransaction` and `CMutableTransaction`:
  - `conditions_root` (`uint256`): shared Merkle root for all TX_MLSC outputs
  - `creation_proof` (`vector<uint8_t>`): leaf hashes proving the conditions_root (required for 3+ outputs)
  - `aggregated_sig` (`vector<uint8_t>`): half-aggregated Schnorr s-value (32 bytes max)
- **RUNG_TX serialization format** (flag byte `0x02`): complete serialize/deserialize templates
- **Flag `0x03` rejection**: explicit `throw` if SegWit (0x01) + RUNG_TX (0x02) are combined
- **UTXO inflation**: on deserialization, 8-byte value-only outputs are inflated to `CTxOut(value, 0xDF + root)`
- **No-witness serialization**: uses standard `vout` format (parseable by all existing tools)

#### Why version 4 (not version 3)

BIP 431 claims version 3 for TRUC (Topologically Restricted Until Confirmation). Using v3
would create a consensus conflict. Version 4 is the next unclaimed version number. The
`RUNG_TX_VERSION` constant is defined explicitly rather than incrementing
`TX_MAX_STANDARD_VERSION` to avoid accidentally making v3 standard.

#### Why a new flag byte (0x02) rather than extending SegWit (0x01)

**Alternative considered**: Encode TX_MLSC data inside SegWit witness fields. This was
rejected because:

1. **Parsing ambiguity**: SegWit witness stack is per-input. TX_MLSC's `conditions_root` and
   `aggregated_sig` are per-transaction. Cramming per-tx data into per-input witness structures
   would require a synthetic "transaction witness" that doesn't map to any input.
2. **Backward compatibility**: Existing tools that parse SegWit witnesses would break on the
   new structure. Flag 0x02 is a clean, documented extension point (BIP 141 reserves flags
   other than 0x01 for future use).
3. **Explicit rejection of 0x03**: If a future extension uses both SegWit and TX_MLSC
   simultaneously, it needs its own format specification. Silently accepting 0x03 could lead
   to deserialization mismatches. The explicit `throw` at `transaction.h:250` ensures this
   is a hard failure rather than undefined behaviour.

#### Why value-only outputs (8 bytes on wire)

**Alternative considered**: Store full `CTxOut(value, scriptPubKey)` for each output.
This was rejected because TX_MLSC outputs all share the same `conditions_root` -- storing
the 33-byte scriptPubKey (0xDF + root) per output wastes 32 bytes per output. For a
transaction with 10 outputs, that is 320 bytes of redundant data.

Instead, the conditions_root is stored once (32 bytes), and each output contributes only
its 8-byte `nValue`. On deserialization, the scriptPubKey is reconstructed as `0xDF + root`
for all outputs (`transaction.h:259-265`). This means all internal Bitcoin Core code that
accesses `tx.vout[i].scriptPubKey` gets a valid 33-byte MLSC scriptPubKey without any
changes to downstream consumers.

#### Why creation_proof has a max of 8,065 bytes

The creation proof contains leaf hashes (32 bytes each) for a maximum of 252 leaves
(CompactSize encoding: 1 byte for count). This limits tree size while allowing substantial
multi-output transactions. The 252-leaf limit means max 252 spendable outputs per RUNG_TX transaction,
which is well above practical needs but below the point where Merkle proof verification
becomes expensive.

#### Why aggregated_sig is capped at 32 bytes

Half-aggregation of Schnorr signatures produces a single 32-byte `s` value. Each individual
signature's `R` point (32 bytes) remains per-input in the witness. The aggregate `s` replaces
N individual `s` values with one, saving 32*(N-1) bytes. The 32-byte cap at `transaction.h:295`
is not arbitrary -- it is the exact size of a scalar field element.

#### Security implications

- **No effect on non-v4 transactions**: The deserialization path only enters RUNG_TX format
  when `flags == 0x02 && tx.version == 4` (`transaction.h:254`). All other transactions
  follow the existing code path unchanged.
- **txid stability**: No-witness serialization (`TX_NO_WITNESS`) writes standard `vout`
  format. The txid hash is computed from the no-witness form, so TX_MLSC outputs have
  the same txid computation as standard transactions. The wtxid includes the TX_MLSC
  witness data (conditions_root, creation_proof, aggregated_sig).

---

### 2. src/primitives/transaction.cpp (~3 lines modified)

#### What was added

- `CMutableTransaction` copy constructor and `CTransaction` constructors now initialize
  `conditions_root`, `creation_proof`, and `aggregated_sig` from the source transaction.

#### Why this is necessary

Without explicit initialization in the constructor initializer list, the new fields would
be default-constructed (null/empty), and any copy/move of a transaction object would silently
lose TX_MLSC data. This would cause wtxid mismatches and consensus failures.

The copy constructor at `transaction.cpp:67` and move constructor at `transaction.cpp:96`
both explicitly include all three fields. The `conditions_root` is copied by value (uint256
is trivially copyable). The `creation_proof` and `aggregated_sig` vectors are moved in
the move constructor for efficiency.

---

### 3. src/script/interpreter.h (~4 lines added)

#### What was added

- **`SigVersion::LADDER = 4`** in the `SigVersion` enum (`interpreter.h:199`)
- **`m_ladder_ready` flag** in `PrecomputedTransactionData` (`interpreter.h:175`)

#### Why a new SigVersion rather than reusing TAPROOT

**Alternative considered**: Use `SigVersion::TAPROOT` for Ladder Script signatures.
Rejected because:

1. **Different tagged hash**: Ladder uses `TaggedHash("LadderSighash")` while Taproot uses
   `TaggedHash("TapSighash")`. If both used the same SigVersion, the evaluator would need
   to inspect the transaction version to determine which hash to compute. This is fragile
   and violates the principle that SigVersion should fully determine the sighash algorithm.
2. **Domain separation**: A signature valid under TapSighash must never validate under
   LadderSighash. Separate SigVersion values guarantee this at the type level.
3. **Forward compatibility**: If Ladder Script evolves its sighash algorithm independently
   of Taproot, having a separate SigVersion avoids any coupling.

#### Why m_ladder_ready is a separate flag (not just m_spent_outputs_ready)

The `m_spent_outputs_ready` flag indicates that spent output data is available, but Ladder
Script also requires precomputed hashes (prevouts, sequences, outputs, amounts) to be
initialized. A transaction might have `m_spent_outputs_ready = true` without being a v4
transaction. The `m_ladder_ready` flag explicitly tracks that the ladder-specific hash
caches are initialized, preventing the evaluator from using uninitialized data if called
on a non-v4 transaction due to a bug.

---

### 4. src/script/interpreter.cpp (~14 lines added)

#### What was added

In `PrecomputedTransactionData::Init()`, after the existing BIP143/BIP341 precomputation
blocks, a new block (`interpreter.cpp:1451-1460`) computes ladder-specific cached hashes:

```
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

#### Why reuse existing hash cache fields

**Alternative considered**: Add separate `m_ladder_prevouts_hash`, etc. fields. Rejected
because the ladder sighash uses the same underlying data (prevouts, sequences, outputs)
as BIP143 and BIP341. The precomputed SHA256 hashes are identical -- only the final
tagged hash wrapping differs. Adding duplicate fields would waste memory for no benefit.

The guard `if (!uses_bip143_segwit && !uses_bip341_taproot)` ensures hashes are computed
only once. If SegWit or Taproot already computed them (because the tx also has SegWit
inputs), the ladder code reuses those values. This is safe because `GetPrevoutsSHA256`,
`GetSequencesSHA256`, etc. produce identical results regardless of which code path
invokes them.

#### Why m_spent_amounts_single_hash is always computed

The `m_spent_amounts_single_hash` is specific to BIP341/Ladder (not part of BIP143).
It is always computed for ladder transactions even if BIP341 already computed it, because
the conditional structure in the existing code only computes it inside the taproot branch.
The ladder block computes it unconditionally when `m_spent_outputs_ready` is true.

---

### 5. src/script/script_error.h/cpp (~7 lines added)

#### What was added

Two new error codes:
- `SCRIPT_ERR_LADDER_INVALID_WITNESS` ("Invalid ladder witness format")
- `SCRIPT_ERR_LADDER_EVAL_FALSE` ("Ladder script evaluation returned false")

#### Why distinct error codes rather than reusing existing ones

**Alternative considered**: Reuse `SCRIPT_ERR_EVAL_FALSE` for ladder failures. Rejected
because:

1. **Diagnostics**: When a transaction fails validation, the error code is the primary
   debugging signal. `SCRIPT_ERR_EVAL_FALSE` would be ambiguous -- was it a Script failure
   or a Ladder failure?
2. **Policy differentiation**: Mempool policy may want to treat ladder failures differently
   from script failures (e.g., different ban scores). Distinct codes enable this.
3. **INVALID_WITNESS vs EVAL_FALSE**: These represent different failure modes.
   `INVALID_WITNESS` means the witness data is malformed (cannot be deserialized).
   `EVAL_FALSE` means the witness is structurally valid but the conditions are not
   satisfied. This distinction matters for debugging and for potential future relay policies.

---

### 6. src/validation.cpp (~96 lines added)

This is the largest integration point and contains the most critical consensus logic.

#### 6a. CScriptCheck::operator() -- v4 routing (`validation.cpp:2106-2131`)

**What**: When `ptxTo->version == RUNG_TX_VERSION` and the spent output has an MLSC
scriptPubKey (0xDF prefix), the validation is routed to `rung::VerifyRungTx()` instead
of the standard `VerifyScript()`.

**Why this routing approach**:
- **Alternative considered**: Add a branch inside `VerifyScript()` itself. Rejected because
  `VerifyScript()` is the most security-critical function in Bitcoin Core. Adding a branch
  inside it increases the attack surface for all transaction types. The external routing
  keeps the blast radius contained: if `VerifyRungTx` has a bug, it cannot affect non-v4
  transactions.
- **Alternative considered**: Use a separate validation pipeline entirely (skip CScriptCheck).
  Rejected because CScriptCheck provides the threading infrastructure (CheckQueue) for
  parallel verification. Reusing it means ladder verification benefits from the same
  parallelism without duplicating the thread pool logic.

**SharedTreeCache bridging** (`validation.cpp:2112-2128`): The shared tree cache enables
proof sharing across inputs from the same source transaction. The bridge code copies the
cache under a mutex, runs verification on the local copy, then writes new entries back.
This is lock-free during the actual verification work and only holds the mutex briefly
for copy-in and write-back.

**Fallthrough for non-MLSC outputs**: Standard inputs (P2WPKH, P2TR, etc.) in v4
transactions fall through to `VerifyScript()`. This enables v4 transactions to spend
standard UTXOs for bootstrap funding without requiring any changes to the standard
verification path.

#### 6b. CheckInputScripts -- UTXO inflation (`validation.cpp:2218-2252`)

**What**: Before precomputing transaction data, compact MLSC coins (1-byte scriptPubKey
= `0xDF` only) are inflated to their full 33-byte form (`0xDF` + 32-byte root). The root
is recovered from the synthetic entry at `(txid, MLSC_ROOT_VOUT)` in the UTXO cache.

**Why not store the full scriptPubKey in the UTXO set**:
- Per-output UTXO cost with full scriptPubKey: ~48 bytes (8 value + 33 script + overhead)
- Per-output UTXO cost with compression: ~8 bytes (8 value + 1-byte compressed type)
- For a transaction with 10 MLSC outputs, this saves ~400 bytes of UTXO set bloat
- The root is stored once per transaction in the synthetic entry, amortizing the 32-byte
  cost across all outputs

**Root cache per source txid** (`validation.cpp:2223`): Multiple inputs might spend outputs
from the same source transaction. The `root_cache` map avoids redundant UTXO lookups for
the synthetic root entry. This is a local optimization that doesn't affect correctness.

**Security**: The synthetic root entry uses marker byte `0xDE` (not `0xDF`) to prevent
the compressor from stripping the root data. The inflation code checks for `0xDE` at
`validation.cpp:2235` before extracting the root. If the synthetic entry is missing or
malformed, the root remains null and the output cannot be spent (fail-closed).

#### 6c. SharedTreeCache creation (`validation.cpp:2264-2266`)

**What**: For v4 transactions, a `ThreadSafeSharedTreeCache` is created and shared across
all `CScriptCheck` instances for that transaction's inputs.

**Why**: When multiple inputs spend outputs from the same source transaction, the first
input verifies the full Merkle proof and caches the tree structure. Subsequent inputs can
use `SHARED` proof mode, referencing the cached tree. This is a witness-size optimization:
a full proof is O(leaves), a Merkle path is O(log leaves), and a shared reference is O(1).

The cache is wrapped in `ThreadSafeSharedTreeCache` (a struct with a `Mutex` and
`GUARDED_BY` annotation) because CScriptCheck instances run in parallel on the CheckQueue
worker threads.

#### 6d. ConnectBlock -- block_height passing (`validation.cpp:2740-2743`)

**What**: `pindex->nHeight` is passed to `CheckInputScripts` and forwarded to the
ladder evaluator via `CScriptCheck::m_block_height`.

**Why**: Two block types need the current block height:
- `EPOCH_GATE`: spendable only during specific block-height windows (e.g., every 144 blocks)
- `RECURSE_UNTIL`: recursive covenant that terminates at a target block height

Without block_height, these evaluators would need to access chain state, which is not
available inside CScriptCheck (it runs on worker threads without access to `cs_main`).
Passing the height as a value avoids any locking issues.

#### 6e. DisconnectBlock -- synthetic root cleanup (`validation.cpp:2395-2397`)

**What**: On block disconnect (reorg), the synthetic root entry at
`(txid, MLSC_ROOT_VOUT)` is removed from the UTXO cache.

**Why**: Without cleanup, disconnected TX_MLSC transactions would leave orphaned synthetic
entries in the UTXO set. These entries have `nValue = 0` and are not spendable, but they
would permanently bloat the UTXO set. The cleanup ensures the UTXO set is identical
whether a block was never connected or was connected and then disconnected.

---

### 7. src/validation.h (~23 lines added)

#### What was added

- `ThreadSafeSharedTreeCache` struct: mutex-protected wrapper around `rung::SharedTreeCache`
- `CScriptCheck::m_block_height` field (int32_t)
- `CScriptCheck::m_shared_tree_cache` field (shared_ptr)
- Updated `CScriptCheck` constructor to accept `block_height` and `shared_tree_cache`
- `#include <rung/evaluator.h>` at top of file

#### Why include rung/evaluator.h in validation.h

**Alternative considered**: Forward-declare `rung::SharedTreeCache` in validation.h and
include the full header only in validation.cpp. This would reduce header dependencies.
However, `ThreadSafeSharedTreeCache` contains a `rung::SharedTreeCache cache` member by
value (not by pointer), which requires the complete type definition. Using a pointer would
add an indirection and heap allocation. The include was chosen for simplicity and
performance since validation.h is not included by many other files.

#### Why shared_ptr for the tree cache

`CScriptCheck` objects are moved into the `CheckQueue` and executed on worker threads.
The shared_ptr ensures the cache survives as long as any worker thread holds a reference.
When all inputs for a transaction are verified, the refcount drops to zero and the cache
is freed. This is simpler and safer than manual lifetime management.

---

### 8. src/policy/policy.cpp (~13 lines added)

#### What was added

**In policy.cpp**:
- Early return for v4 transactions: `if (tx.version == CTransaction::RUNG_TX_VERSION) return rung::IsStandardRungTx(tx, reason);` (`policy.cpp:104-105`)
- Skip MLSC inputs in `AreInputsStandard` and `IsWitnessStandard`: `if (rung::IsLadderScript(prev.scriptPubKey)) continue;` (`policy.cpp:234`, `policy.cpp:276`)

#### Why early-return rather than raising TX_MAX_STANDARD_VERSION

**Alternative considered**: Change `TX_MAX_STANDARD_VERSION` from 2 to 4. Rejected
because this would also make v3 (TRUC) standard, which has different semantics and
should require its own activation logic. The early-return pattern is surgical:
only v4 transactions with valid ladder structure are accepted.

#### Why skip MLSC inputs in AreInputsStandard

The existing `AreInputsStandard` function uses `Solver()` to classify the spent
scriptPubKey. An MLSC scriptPubKey (0xDF prefix) is not P2PKH, P2SH, P2WPKH, P2WSH,
or P2TR -- it would be classified as `TxoutType::NONSTANDARD` and rejected. Rather
than adding MLSC as a new `TxoutType` (which would require changes throughout the
codebase), the check simply skips MLSC inputs. Their policy validation is handled
by `rung::IsStandardRungTx()`.

---

### 9. src/rpc/register.h (~2 lines added)

#### What was added

- Declaration: `void RegisterRungRPCCommands(CRPCTable&);`
- Call: `RegisterRungRPCCommands(t);` in `RegisterAllCoreRPCCommands()`

#### Why register alongside other RPC commands

**Alternative considered**: Register RPCs via a plugin or separate binary. Rejected
because Ladder Script is a consensus feature, not an optional plugin. The RPCs
(createrungtx, signrungtx, signladder, createtxmlsc, decoderung, validateladder, etc.)
are needed for wallet integration and testing. They follow the same registration
pattern as all other Bitcoin Core RPCs.

---

### 10. src/CMakeLists.txt (~6 lines added)

#### What was added

- `add_subdirectory(rung)` after `add_subdirectory(util)` (`CMakeLists.txt:57`)
- `bitcoin_rung` linked to `bitcoin_common`, `bitcoin_node`, `bitcoind`, and `bitcoin-node`

#### Why a separate static library

**Alternative considered**: Add rung source files directly to `bitcoin_common` or
`bitcoin_consensus`. Rejected because:

1. **Build isolation**: The rung module has its own dependencies (optionally liboqs).
   A separate library keeps these dependencies from leaking into unrelated targets.
2. **No circular dependencies**: `bitcoin_rung` depends on `bitcoin_consensus`,
   `bitcoin_util`, and `secp256k1`. It does not depend on `bitcoin_node` or wallet
   code. The reverse link (node depends on rung) is for RPC registration and
   validation integration only.
3. **Optional PQ support**: The `CMakeLists.txt` in `src/rung/` uses
   `find_package(liboqs QUIET)` to optionally link post-quantum signature support.
   If liboqs is not available, PQ verification returns UNSATISFIED (fail-closed).

---

### 11. src/compressor.h/cpp (~31 lines added)

#### What was added

**In compressor.h**:
- `nSpecialScripts` changed from 6 to 7 (adding type 0x06 for MLSC)

**In compressor.cpp**:
- `IsToMLSC()` helper: detects 33-byte `0xDF + root` scriptPubKeys (`compressor.cpp:55-62`)
- `CompressScript()`: MLSC compressed as type 0x06 with **zero bytes** of script data (`compressor.cpp:66-76`)
- `GetSpecialScriptSize(6)`: returns 0 (no additional data stored) (`compressor.cpp:113`)
- `DecompressScript(0x06)`: reconstructs a 1-byte `0xDF` scriptPubKey (`compressor.cpp:159-165`)

#### Why zero bytes of compressed data

This is the core of the UTXO deduplication strategy. Every MLSC output in the same
transaction shares the same conditions_root. Storing the root per-coin would duplicate
it N times. Instead:

1. **At creation** (`coins.cpp:134-141`): A synthetic entry at `(txid, MLSC_ROOT_VOUT)`
   stores the root once with a `0xDE` marker.
2. **In the UTXO set**: Each output is compressed to just the type byte (0x06).
   Decompression produces a 1-byte scriptPubKey (`0xDF`).
3. **At spend time** (`validation.cpp:2225-2247`): The compact 1-byte scriptPubKey is
   inflated to the full 33-byte form by looking up the synthetic entry.

**Net effect**: Per-output UTXO cost drops from ~48 bytes to ~8 bytes (6x improvement
over Taproot). For a 10-output TX_MLSC transaction, this saves ~400 bytes of UTXO set.

#### Why 0xDF for MLSC and 0xDE for synthetic entry

`0xDF` was chosen as the MLSC prefix because:
- It is not a valid first byte for any existing scriptPubKey type (P2PKH uses 0x76,
  P2SH uses 0xa9, P2WPKH/P2WSH use 0x00, P2TR uses 0x51)
- It is above 0xCE (OP_UNKNOWN), so Bitcoin Script would treat it as a single-opcode
  script that fails (forward-compatible soft fork)
- SegWit v1 uses program bytes 0x51..0xB2. 0xDF is well outside this range.

`0xDE` was chosen for the synthetic entry to avoid colliding with `0xDF`. The
compressor's `IsToMLSC()` check only matches `0xDF`, so synthetic entries (0xDE)
are never compressed away. This is critical: if the synthetic entry were compressed,
the root would be lost and MLSC outputs could never be spent.

#### Security implications

- The compressor only handles MLSC outputs. Non-MLSC outputs use existing compression
  types 0x00-0x05 unchanged.
- The zero-data compression means MLSC coins in the UTXO set cannot be distinguished
  from each other by scriptPubKey alone. An attacker who knows a txid can compute the
  MLSC scriptPubKey for all its outputs. This is by design: MLSC outputs are all
  fungible within a transaction.

---

### 12. src/coins.h/cpp (~16 lines added)

#### What was added

**In coins.h**:
- `MLSC_ROOT_VOUT = 0xFFFFFFFF` sentinel constant (`coins.h:492`)

**In coins.cpp**:
- In `AddCoins()`: for v4 transactions with non-null conditions_root, create a synthetic
  coin at `(txid, 0xFFFFFFFF)` containing a 33-byte scriptPubKey: `0xDE + conditions_root`
  (`coins.cpp:134-141`)

#### Why 0xFFFFFFFF as the vout index

**Alternative considered**: Use a vout index just past the actual output count (e.g.,
`tx.vout.size()`). Rejected because this could collide with a real vout index in a
transaction with exactly that many outputs. `0xFFFFFFFF` is `COutPoint::NULL_INDEX`,
which can never be a valid output index (CompactSize encoding in the transaction format
prevents vout arrays from reaching this size).

#### Why store as a Coin (not a separate database)

**Alternative considered**: Add a new database table mapping `txid -> conditions_root`.
Rejected because:

1. **Existing infrastructure**: `CCoinsViewCache` already handles UTXO storage, caching,
   flushing, and pruning. Using a Coin entry gets all this for free.
2. **Atomicity**: The synthetic entry is written in the same `AddCoins()` call as the
   actual outputs. If the block is disconnected, `DisconnectBlock` removes it in the
   same pass. No separate cleanup logic needed.
3. **Pruned node compatibility**: The UTXO set is always available, even on pruned nodes.
   A block database lookup would require the full block data.

#### Why nValue = 0 on the synthetic entry

The synthetic entry is not a real output and should never be "spent" for value. Setting
`nValue = 0` ensures that even if something tries to spend it, no value flows. The entry
is only spent during `DisconnectBlock` cleanup.

#### Security implications

- The synthetic entry is created for every v4 transaction with a non-null conditions_root.
  An attacker cannot create a synthetic entry for a non-v4 transaction because the check
  `tx.version == CTransaction::RUNG_TX_VERSION` is explicit.
- The `0xDE` marker prevents the synthetic entry from being mistaken for an MLSC output
  (which uses `0xDF`). The compressor does not compress `0xDE` scripts.

---

### 13. src/pubkey.h/cpp (~38 lines added)

#### What was added

**In pubkey.h** (`XOnlyPubKey` class):
- `ComputeLadderTweakHash(const uint256* merkle_root)`: compute tweak hash using
  `TaggedHash("LadderTweak")`
- `CheckLadderTweak(internal, merkle_root, parity)`: verify a Ladder-tweaked output point
- `CreateLadderTweak(merkle_root)`: construct a Ladder-tweaked output point

**In pubkey.cpp**:
- `HASHER_LADDERTWEAK`: pre-initialized tagged hash writer (`pubkey.cpp:282`)
- Full implementations of all three functions using `secp256k1_xonly_pubkey_tweak_add`
  and `secp256k1_xonly_pubkey_tweak_add_check`

#### Why a separate tag ("LadderTweak") instead of reusing ("TapTweak")

This is the most critical domain separation in the entire design.

**If the same tag were used**: A Taproot output `P_tap = P + H_TapTweak(P || root) * G`
and a Ladder output `P_lad = P + H_LadderTweak(P || root) * G` with the same internal
key and the same Merkle root would produce different output keys. But if both used
`H_TapTweak`, they would produce the **same** output key, and a Taproot key-path
signature could spend a Ladder output (or vice versa).

Separate tags guarantee:
1. A Taproot signature cannot spend a Ladder output
2. A Ladder signature cannot spend a Taproot output
3. The tweaked keys are different even with identical internal keys and Merkle roots

The implementation mirrors Taproot's tweak exactly (same secp256k1 functions, same
structure) -- only the tag string differs. This makes the code easy to review: any
reviewer familiar with BIP341's tweak can verify the Ladder tweak by comparing the
two implementations.

#### Security implications

- The tagged hash uses SHA256 with domain separation. Even if an attacker controls
  the internal key and Merkle root, they cannot produce a LadderTweak output that
  collides with a TapTweak output.
- `CheckLadderTweak` and `CheckTapTweak` can be called on the same `XOnlyPubKey`
  without interference. They operate on independent hash domains.

---

### 14. src/key.h/cpp (~18 lines added)

#### What was added

**In key.h**:
- `CKey::SignSchnorrLadder(hash, sig, merkle_root, aux)` declaration

**In key.cpp** (`key.cpp:278-293`):
- Full implementation: creates a keypair, applies the LadderTweak, and signs using
  `secp256k1_schnorrsig_sign32`

#### Why a separate signing function (not reusing SignSchnorr)

`CKey::SignSchnorr()` uses `ComputeKeyPair(merkle_root)` which internally applies
`TapTweak`. `SignSchnorrLadder()` must apply `LadderTweak` instead.

**Alternative considered**: Add a `tweak_tag` parameter to `SignSchnorr`. Rejected because:
1. It would change the signature of an existing security-critical function
2. Every existing caller would need to be updated (even if just to pass the default)
3. A separate function makes the intent explicit at every call site

The implementation at `key.cpp:284-290` manually applies the tweak:
```
uint256 tweak = XOnlyPubKey(pubkey_bytes).ComputeLadderTweakHash(
    merkle_root->IsNull() ? nullptr : merkle_root);
secp256k1_keypair_xonly_tweak_add(secp256k1_context_static, &keypair, tweak.data());
```

This is identical to the Taproot signing path except it calls `ComputeLadderTweakHash`
instead of `ComputeTapTweakHash`.

---

### 15. src/rpc/util.cpp (~9 lines added)

#### What was added

Implemented the `Type::OBJ` / `Type::OBJ_NAMED_PARAMS` / `Type::OBJ_USER_KEYS` cases
in `RPCArg::ToStringObj()` (`rpc/util.cpp:1249-1257`). Previously these hit
`NONFATAL_UNREACHABLE()` because no upstream Bitcoin Core RPC had nested object arguments
deep enough to trigger this code path.

#### Why this is necessary

Ladder Script RPCs (`signrungtx`, `createtxmlsc`) have 4-level nested argument schemas
(e.g., `signers[].conditions[].blocks[].fields[]`). When `help signrungtx` is called,
the help serializer recursively walks the argument tree. `ToString()` handles OBJ types
by calling `ToStringObj()` on children, but `ToStringObj()` itself could not serialize
OBJ children — causing a crash.

The fix mirrors the existing `ToString()` OBJ handling (lines 1276-1286), making the
two functions consistent. This is a general Bitcoin Core improvement, not Ladder
Script-specific.

#### Security implications

None. This only affects the `help` RPC output serialization. No consensus, validation,
or transaction processing code is changed.

### 16. Minor changes (6 files, ~25 lines total)

| File | Lines | Change |
|------|-------|--------|
| `src/rpc/mempool.cpp` | +4 | Skip burn-amount check for MLSC outputs in `sendrawtransaction` and `submitpackage` |
| `src/script/script_error.cpp` | +4 | Ladder error strings (`SCRIPT_ERR_LADDER_INVALID_WITNESS`, `SCRIPT_ERR_LADDER_EVAL_FALSE`) |
| `src/script/script_error.h` | +4 | Ladder error code enum values |
| `src/rpc/register.h` | +3 | Register rung RPC commands via `RegisterRungRPCCommands()` |
| `src/test/txvalidationcache_tests.cpp` | +2 | Update CheckInputScripts forward declaration to match new signature |
| `src/test/CMakeLists.txt` | +1 | Add `rung_tests.cpp` to test binary |
| `test/functional/test_runner.py` | +1 | Register `feature_rung_tx.py` functional test |

---

## New Module: src/rung/ (22 files incl. CMakeLists.txt, ~14,771 lines)

Self-contained module implementing the Ladder Script evaluator, type system, serialization,
Merkle tree, sighash, descriptors, policy, RPC commands, and post-quantum signature support.
All public APIs are in the `rung::` namespace.

### Module Architecture

```
                     +-----------+
                     | evaluator | ← Top-level: VerifyRungTx, EvalLadder, EvalRung, EvalBlock
                     +-----+-----+
                           |
              +------------+------------+
              |            |            |
        +-----+-----+ +---+---+ +------+------+
        | conditions | | types | | serialize   |
        +-----+------+ +---+---+ +------+------+
              |            |            |
              +-----+------+-----+------+
                    |            |
              +-----+-----+ +---+---+
              |  sighash   | |adaptor|
              +------------+ +---+---+
                                 |
              +---------+--------+--------+---------+
              |         |        |        |         |
          +---+---+ +---+--+ +--+--+ +---+---+ +---+---+
          |  rpc  | |policy| |  pq | |aggreg.| |descrip.|
          +-------+ +------+ +-----+ +-------+ +-------+
```

### types.h/cpp (1,473 lines) -- Type System

#### Purpose and scope

Defines the complete type system for Ladder Script: 64 block types across 10 families,
11 data types, and all structural types (RungBlock, RungField, Rung, Relay, RungCoil,
LadderWitness).

#### Key design decisions

**Block type encoding as uint16_t** (`types.h:31`): Block types are encoded as 16-bit
integers with the high byte indicating the family (0x00 = Signature, 0x01 = Timelock,
etc.) and the low byte indicating the specific block within that family. This allows
efficient range checks for family membership and reserves space for future block types
within each family.

**Alternative considered**: Use uint8_t (256 max types). Rejected because 64 types are
already defined and future expansion (especially in the PLC family with 14 types) would
quickly exhaust the space.

**Alternative considered**: Use string identifiers. Rejected because string comparison
is expensive in consensus code and would increase witness size.

**11 data types** (`types.h:121-133`): Every byte in a Ladder Script witness belongs to
one of 11 typed fields. There are no arbitrary data pushes. This is a fundamental
difference from Bitcoin Script, where `OP_PUSH` can push arbitrary data. The type system
enables:
- **User-chosen data limits**: `IsDataEmbeddingType()` identifies types that could carry arbitrary data
  (PUBKEY_COMMIT, HASH256, HASH160, DATA). These are blocked in blocks without implicit
  layouts to prevent data embedding.
- **Bounded verification**: The evaluator knows exactly what data to expect in each field
  position, eliminating the unbounded loop of Script's stack machine.

**Coil structure** (`types.h:538-545`): Each output has a coil that determines unlock
semantics (UNLOCK vs UNLOCK_TO), attestation mode (INLINE vs AGGREGATE), signature scheme
(SCHNORR/ECDSA/PQ), destination address (as SHA256 hash -- raw address never on-chain),
and per-rung destination overrides. The `output_index` field ties the coil to a specific
TX_MLSC output and is committed in the Merkle leaf, preventing output-index swapping attacks.

**Relay structure** (`types.h:577-580`): Relays enable DRY (Don't Repeat Yourself)
condition reuse. A relay is a set of blocks that can be referenced by multiple rungs via
`relay_refs`. Forward-only indexing (relay N can only reference relays 0..N-1) prevents
cycles. Maximum relay depth is 4, preventing deep transitive chains.

**merkle_pub_key design**: Public keys are NOT stored in the conditions (locking side).
Instead, they are folded into the Merkle leaf hash: `leaf = SHA256(serialized_blocks ||
pubkey_0 || pubkey_1 || ...)`. This prevents arbitrary data embedding via PUBKEY fields
while still binding the pubkeys to the conditions cryptographically. At spend time, the
witness provides the pubkeys, and the evaluator recomputes the leaf hash to verify they
match.

### evaluator.h/cpp (4,534 lines) -- Block Evaluator

#### Purpose and scope

The evaluator is the consensus engine. It implements:
- `VerifyRungTx()`: top-level entry point called from `validation.cpp`
- `EvalLadder()`: evaluates all rungs (OR logic -- first satisfied rung wins)
- `EvalRung()`: evaluates all blocks in a rung (AND logic -- all must pass)
- `EvalBlock()`: dispatches to the appropriate block-type evaluator
- 63 individual block evaluators across `src/rung/blocks/*.cpp` (each block
  family is a self-registering translation unit; see `block_registry.cpp`)

#### Key design decisions

**Deterministic evaluation order**: Relays are evaluated first (index 0 to N), then rungs
are evaluated in order. The first satisfied rung wins. This is deterministic and
reproducible across all nodes. There is no "score" or "best match" -- the first passing
rung is canonical.

**Adapter sig checker** (`src/rung/api.h`): Ladder-native blocks take an
`api::LadderSigChecker` abstract interface. The Core-side implementation
`CoreLadderSigChecker` in `src/rung_shims.h` wraps a standard
`BaseSignatureChecker`. The library computes the Ladder sighash itself via
`api::SignatureHashLadder` and passes it to the checker — the checker is
stateless w.r.t. conditions, which keeps the library Core-type-free.

**RungEvalContext** (`evaluator.h`): Extended context for block types that need
transaction data. Not all blocks need this (simple signature blocks don't), so it's passed
separately to avoid bloating the common case. Contains:
- Transaction and amount data for covenants (CTV, AMOUNT_LOCK)
- Block height for time-dependent blocks (EPOCH_GATE, RECURSE_UNTIL)
- Spent outputs for cross-input checks (COSIGN)
- Verified leaf array for covenant checks (enables leaf-centric Merkle mutations)

**EvalResult enum** (`evaluator.h:122-127`): Four-valued result type:
- `SATISFIED`: conditions met
- `UNSATISFIED`: conditions not met (valid but fails)
- `ERROR`: malformed block (consensus failure)
- `UNKNOWN_BLOCK_TYPE`: forward compatibility -- unknown types return UNSATISFIED, not ERROR

This design enables soft-fork upgradability: new block types can be added without
consensus-breaking older nodes. Unknown types simply fail to satisfy, which is safe
because the OR logic across rungs means a transaction can include a new-type rung
alongside a backward-compatible rung.

**Block inversion** (`evaluator.h:131`): Any block can be inverted (NOT gate). The
`inverted` flag on `RungBlock` flips SATISFIED to UNSATISFIED and vice versa. This
enables "spend unless" conditions without dedicated block types.

**SharedTreeCache** (`evaluator.h:257-266`): Maps source txid to verified tree data
(root + all leaf hashes). When multiple inputs spend outputs from the same source
transaction, the first input verifies the full proof and caches the result. Subsequent
inputs use SHARED proof mode, which only needs to prove their specific leaf is in the
cached tree.

#### Integration with Bitcoin Core

`VerifyRungTx()` is the only entry point called from `validation.cpp`. It:
1. Checks MLSC output format (0xDF prefix, 33 bytes)
2. Deserializes the witness (stack[0] = ladder witness, stack[1] = MLSC proof)
3. Verifies the MLSC Merkle proof against the conditions_root
4. Evaluates the revealed rung and relays
5. Verifies creation proof (if present, for 3+ output transactions)
6. Returns success/failure with appropriate ScriptError

### conditions.h/cpp (1,347 lines) -- Merkle Tree and MLSC Proofs

#### Purpose and scope

Implements the Merkelised Ladder Script Conditions (MLSC) system:
- Merkle tree construction with sorted interior nodes
- Three proof modes (FULL_LEAVES, MERKLE_PATH, SHARED)
- Conditions root computation
- Creation proof validation
- Key-path tweak computation

#### Key design decisions

**Sorted interior nodes** (`conditions.h:207-143`): Interior hashing uses
`SHA256(0x01 || sort(left, right))`. Sorting children lexicographically eliminates the
need for direction bits in Merkle proofs. This saves 1 bit per proof level (log2(N) bits
total). The `0x01` prefix provides domain separation from leaf nodes (which use the raw
hash of their content without a prefix byte).

**Alternative considered**: Use Bitcoin's existing Merkle tree (unsorted, with direction
bits). Rejected because direction bits increase proof size and complicate proof
verification. The sorted approach is used by several other projects (e.g., Ethereum's
MPT) and is well-understood.

**MLSC_EMPTY_LEAF padding** (`conditions.h:31-31`): Trees are padded to the next power
of 2 using `SHA256("LADDER_EMPTY_LEAF")`. This is a nothing-up-my-sleeve constant that
cannot collide with valid serialized rung data (the preimage is known and short).

**Three proof modes** (`conditions.h:199-203`):
- `FULL_LEAVES` (0x00): All unrevealed leaf hashes in the proof. O(N) witness size.
  Simplest to verify but largest witness.
- `MERKLE_PATH` (0x01): Sibling hashes from leaf to root. O(log N) witness size.
  Optimal for deep trees.
- `SHARED` (0x02): References another input's proof from the same source tx. O(1)
  witness size. Requires SharedTreeCache.

The evaluator accepts all three modes and verifies them identically (rebuild the tree,
compare the root). The choice of mode is the spender's optimization decision, not a
consensus parameter.

**Leaf order** (`conditions.h:190`): Leaves are ordered as
`[rung_0, ..., rung_N, relay_0, ..., relay_M, coil]`. This fixed order means the
prover and verifier agree on which leaf index corresponds to which component without
any additional metadata.

**MLSCVerifiedLeaves** (`conditions.h:190-196`): After proof verification, the full leaf
array is captured. Covenant evaluators (RECURSE_SAME, RECURSE_MODIFIED, RECURSE_DECAY)
use this array to mutate a specific leaf and rebuild the tree to check the output root.
This avoids re-verification of the entire proof for each covenant check.

**Creation proof** (`conditions.h:302-298`): For transactions with 3+ outputs, a creation
proof is required to bind the leaf hashes to the conditions_root. This prevents an
attacker from creating outputs whose leaf hashes do not correspond to any valid rung
structure. The creation proof is a simple list of leaf hashes that must rebuild to the
declared root.

### serialize.h/cpp (1,112 lines) -- Wire Format

#### Purpose and scope

Serialization and deserialization of ladder witnesses, blocks, coils, and relays.
Implements the micro-header optimization for compact encoding.

#### Key design decisions

**Micro-headers** (`serialize.h:73-78`): The 128 most common block-type + field-layout
combinations are assigned single-byte codes (0x00-0x7F). This replaces the full header
(2-byte block type + per-field type bytes) with a single byte. For common patterns like
`SIG(SIGNATURE)` or `CSV(NUMERIC)`, this saves 3-4 bytes per block.

Escape codes 0x80 (not inverted) and 0x81 (inverted) signal that a full header follows.
This handles rare block types and custom field layouts without any ambiguity.

**Implicit field layouts** (`serialize.h:58-62`): When a micro-header has an implicit
layout, field count and type bytes are omitted entirely. The deserializer knows exactly
which fields to expect (type and count) from the micro-header alone. Field data is
still present (values, not types). This achieves maximum compression: the entire block
metadata is a single byte.

There are 31 distinct implicit layouts covering all standard block-type usage patterns.
Non-standard field layouts fall back to explicit encoding.

**Context-aware deserialization** (`serialize.h:59-62`): `SerializationContext::WITNESS`
allows SIGNATURE, PREIMAGE, PUBKEY fields. `SerializationContext::CONDITIONS` restricts
to condition-safe types (HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX). This prevents
embedding arbitrary data in conditions, which would be permanent on-chain data.

**Strict consensus limits** (`serialize.h:23-53`):
- `MAX_RUNGS = 16`: Sufficient for institutional custody (multisig tiers + PQ fallbacks +
  timelocked recovery + inheritance). Only adds 1 Merkle proof hash vs 8 rungs.
- `MAX_BLOCKS_PER_RUNG = 8`: Prevents combinatorial explosion in evaluation
- `MAX_FIELDS_PER_BLOCK = 16`: Bounded per-block data
- `MAX_LADDER_WITNESS_SIZE = 100,000`: Must accommodate PQ signatures (SPHINCS+ up to ~49KB)
- `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`: Fast reject for data embedding via preimages
- `MAX_PREIMAGE_FIELDS_PER_TX = 2`: Cross-input data embedding prevention
- `MIN_RUNG_OUTPUT_VALUE = 546 sats`: Consensus dust threshold matching Bitcoin's P2PKH dust threshold

**Compact coil sentinel** (`serialize.h:56`): `0x00` at the coil position expands to a
default coil (UNLOCK + INLINE + SCHNORR + no address). This saves ~5 bytes for the
common case of a simple spend output.

### sighash.h/cpp (313 lines) -- Signature Hash

#### Purpose and scope

Computes signature hashes for Ladder Script transactions, analogous to BIP341's
`SignatureHashSchnorr` but with a different tagged hash and additional fields.

#### Key design decisions

**TaggedHash("LadderSighash")** (`sighash.h:28`): Domain separation from Taproot.
Pre-initialized in a static `HashWriter` for efficiency.

**ANYPREVOUT support** (`sighash.h:21-25`): Ladder Script natively supports BIP-118
ANYPREVOUT semantics via flag bytes `0x40` (ANYPREVOUT) and `0xC0` (ANYPREVOUTANYSCRIPT).
This enables LN-Symmetry/eltoo without requiring a separate soft fork. The sighash skips
the prevout commitment when ANYPREVOUT is set, and additionally skips the conditions
commitment when ANYPREVOUTANYSCRIPT is set.

**Alternative considered**: Wait for BIP-118 activation and use its sighash. Rejected
because BIP-118 is defined for SegWit v1 (Taproot) only. Ladder Script uses v4
transactions and its own sighash, so there is no conflict.

**Conditions hash commitment**: Unlike Taproot (which commits to the tapleaf hash),
Ladder Script's sighash commits to `SHA256(serialized_conditions)`. This binds the
signature to the specific spending conditions, preventing condition substitution attacks.

**Key-path sighash** (`sighash.h:65-75`): A separate `SignatureHashLadderKeyPath` uses
`TaggedHash("LadderKeyPathSighash")` and does NOT commit to conditions (because in
key-path spending, conditions are not revealed). This is analogous to Taproot's key-path
spending where the script tree is not committed.

### descriptor.h/cpp (1,853 lines) -- Human-Readable Descriptors

#### Purpose and scope

Parser and formatter for Ladder Script descriptors. Enables human-readable condition
specification in RPC commands and wallet configuration.

#### Key design decisions

**Grammar**: `ladder(or(rung1, rung2, ...))` with `rung = block | and(block, block, ...)`.
This mirrors the evaluation semantics: OR across rungs, AND within rungs. Blocks can be
inverted with `!block`.

**Key aliases** (`descriptor.h:84`): Keys are referenced by alias (`@alice`, `@bob`)
rather than raw hex. This makes descriptors readable and reduces errors. The alias map
is provided at parse time.

**Scheme names**: `schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`.
These map to the `RungScheme` enum. PQ schemes are supported in descriptors even if
liboqs is not compiled in (parsing succeeds; verification fails at runtime).

**TX_MLSC descriptors** (`descriptor.h:108-138`): Multi-output descriptors use
`ladder(output(0, or(...)), output(1, or(...)))` syntax. Each output specifies its
output_index and its rungs.

### rpc.cpp (3,400 lines) -- RPC Commands

#### Purpose and scope

15 RPC commands for creating, signing, inspecting, and validating Ladder Script
transactions. These are the primary interface for wallet software and testing.

#### Integration

Registered via `RegisterRungRPCCommands()` called from `RegisterAllCoreRPCCommands()`.
All commands operate on serialized transaction data (hex strings) and return JSON.
No wallet locking or chain state access beyond what standard RPCs require.

### policy.h/cpp (172 lines) -- Mempool Policy

#### Purpose and scope

Thin policy layer for v4 transaction standardness checks. Delegates to the consensus
deserializer, which enforces all structural limits.

#### Key design decisions

**Deserialize-only check** (`policy.h:28`): Rather than duplicating validation logic,
`IsStandardRungTx` simply attempts to deserialize the witness. If deserialization succeeds
(all structural limits pass, all field types known, all field sizes valid), the transaction
is standard. This ensures policy and consensus never diverge.

Block type classification functions (`IsBaseBlockType`, `IsCovenantBlockType`,
`IsStatefulBlockType`) enable future policy differentiation (e.g., restricting stateful
blocks to confirmed transactions).

### adaptor.h/cpp (244 lines) -- Adaptor Signatures

#### Purpose and scope

Implements adaptor signature creation, verification, and secret extraction for atomic
swaps and PTLCs (Point Time-Locked Contracts).

#### Key design decisions

Uses standard BIP-340 compatible adaptor signatures. The adapted signature
`(R+T, k_tweaked + e*x)` is a valid BIP-340 signature against the signing pubkey.
Secret extraction computes `t = s_adapted - s_pre` (scalar subtraction mod n).

### pq_verify.h/cpp (196 lines) -- Post-Quantum Signatures

#### Purpose and scope

Optional post-quantum signature verification using liboqs. Supports FALCON-512,
FALCON-1024, Dilithium3, and SPHINCS+-SHA2.

#### Key design decisions

**Optional dependency**: PQ support is compile-time optional via `find_package(liboqs QUIET)`.
If not available, `VerifyPQSignature` returns false (UNSATISFIED), which is fail-closed.
Nodes without liboqs simply cannot verify PQ signatures, but they can still validate
all other block types.

**Signature size**: PQ signatures are large (SPHINCS+ up to ~49KB). This is why
`MAX_LADDER_WITNESS_SIZE = 100,000` bytes -- it must accommodate PQ signatures.
The `RungDataType::SIGNATURE` field allows up to 50,000 bytes (`types.h:127`).

### aggregate.h/cpp (82 lines) -- Signature Aggregation

#### Purpose and scope

Block-level aggregate proof verification. When multiple outputs use AGGREGATE attestation
mode, a single aggregate signature covers all of them.

#### Key design decisions

`VerifyDeferredAttestation` always returns false (`aggregate.h:37`). Deferred attestation
is not yet supported and fails closed. This is a deliberate safety decision: the code path
exists for forward compatibility but is not activated.

---

## Tests: src/test/rung_tests.cpp (17,053 lines, 517 test cases in rung_tests; 86 in qabi_tests; 10 in tx_mlsc_tests)

Covers:
- All 63 block type evaluators individually
- Serialization roundtrips (witness + conditions, all implicit layouts)
- Merkle tree construction, path generation, and verification
- User-chosen data field restrictions (IsDataEmbeddingType, MAX_PREIMAGE_FIELDS)
- Policy validation (IsStandardRungTx)
- All 3 MLSC proof modes (FULL_LEAVES, MERKLE_PATH, SHARED)
- TX_MLSC leaf/root computation with creation proofs
- Key-path and script-path spending
- Compact coil encoding/decoding
- Half-aggregated signature verification
- ANYPREVOUT sighash variants
- Template references and witness references
- Relay evaluation with forward-only indexing
- Block inversion (NOT gate)
- Covenant evaluation (CTV, RECURSE_SAME, RECURSE_MODIFIED, RECURSE_DECAY)
- PLC family (hysteresis, timers, latches, counters, comparators, sequencers)
- Legacy wrapper blocks (P2PK through P2TR_SCRIPT)
- Boundary conditions (MAX_RUNGS, MAX_BLOCKS, MAX_FIELDS, MAX_LADDER_WITNESS_SIZE)
- Descriptor parsing and formatting
- Cross-input COSIGN verification
- Creation proof validation with 3+ outputs

---

## Security Properties Summary

1. **Non-v4 transactions completely unaffected**: Every ladder code path is gated on
   `tx.version == CTransaction::RUNG_TX_VERSION` (4) AND MLSC scriptPubKey (0xDF prefix).
   No existing Script opcodes are modified. No existing transaction versions are
   reinterpreted. The changes to existing Bitcoin Core files are purely additive.

2. **No new opcodes, no stack machine**: 64 typed blocks replace opcodes entirely.
   Evaluation is a bounded loop: for each rung, for each block, check typed fields.
   No stack manipulation, no `OP_IF` nesting, no `OP_CODESEPARATOR`. The absence of
   a stack eliminates entire classes of bugs (stack overflow, alt-stack confusion,
   CLEANSTACK violations).

3. **Bounded execution**: O(rungs * blocks * fields). With limits MAX_RUNGS=16,
   MAX_BLOCKS_PER_RUNG=8, MAX_FIELDS_PER_BLOCK=16, the worst case is
   16 * 8 * 16 = 2,048 field checks per input. Compare to Script where a single
   input can execute up to 201 opcodes with unbounded stack operations.

4. **User-chosen data structurally limited**: Every witness byte belongs to a typed field. Data
   embedding types (PUBKEY_COMMIT, HASH256, HASH160, DATA) are rejected in blocks
   without implicit layouts. MAX_PREIMAGE_FIELDS_PER_TX=2 prevents multi-input data
   embedding. DATA_RETURN payload is capped at 40 bytes. Net embeddable data per
   transaction: 112 bytes (flat: 64 PREIMAGE + 40 DATA_RETURN + 8 nLockTime/nSequence),
   far less than the ~80 bytes per OP_RETURN output that can be
   multiplied across outputs in standard Script.

5. **UTXO efficient**: ~8 bytes per output (vs ~48 bytes for P2TR Taproot, ~34 bytes
   for P2WPKH). The synthetic root entry adds 33 bytes per transaction (amortized
   across all outputs). For a 10-output transaction: 8*10 + 33 = 113 bytes vs
   48*10 = 480 bytes for Taproot (76% reduction).

6. **Domain separation**: Three tagged hashes provide complete domain isolation:
   - `TaggedHash("LadderTweak")`: key-path output tweaking
   - `TaggedHash("LadderSighash")`: script-path signature hashing
   - `TaggedHash("LadderKeyPathSighash")`: key-path signature hashing
   No cross-protocol replay is possible between Taproot and Ladder Script.

7. **Fail-closed defaults**:
   - Unknown block types return UNSATISFIED (not ERROR)
   - PQ verification without liboqs returns false
   - Deferred attestation returns false
   - Missing synthetic root entry prevents spending (inflation produces null root)
   - Flag 0x03 throws an exception (not silently accepted)

8. **Soft-fork compatible**: The 0xDF scriptPubKey falls in the "OP_UNKNOWN" range.
   Pre-Ladder-activation nodes treat these outputs as anyone-can-spend (SegWit-style
   upgrade mechanism). Post-activation, the ladder evaluator enforces the conditions.
   Unknown block types within an activated Ladder evaluation return UNSATISFIED,
   enabling sub-protocol soft forks.

---

## Part 2 — Additional Patch Sections (not previously enumerated)

### 17. src/core_write.cpp (~26 lines added) — MLSC decoder shims

#### What was added

Two guards before the generic opcode walker, teaching Core's JSON/ASM decoders to
recognise MLSC scriptPubKeys (0xDF prefix):

- **`ScriptToAsmStr`** (`core_write.cpp:97`): short-circuits the opcode walker. Before
  the change, `decoderawtransaction` would render an MLSC output as
  `OP_UNKNOWN <garbage-push>` because 0xDF isn't a known opcode. Now it renders
  `MLSC <root-hex>` (or `MLSC <root-hex> DATA_RETURN <data-hex>` when a data tail is
  present, or `MLSC <compact>` when the UTXO compressor has stripped the root).

- **`ScriptToUniv`** (`core_write.cpp:159`): emits `"type": "mlsc"` for MLSC
  scriptPubKeys. Without this, the Solver-backed path tags them as `"nonstandard"`,
  which is correct from Core's opcode-perspective but misleading for Ladder-aware
  tooling.

#### Why both paths

`ScriptToAsmStr` is consumed by `decodescript`, block explorers, and wallet UI
tooling that wants a human-readable asm rendering. `ScriptToUniv` is consumed by
`decoderawtransaction`, `getrawtransaction verbose`, and all JSON serialisation of
`CTxOut::scriptPubKey`. Both paths must recognise MLSC or tooling diverges.

#### Output type naming (`"mlsc"`)

Matches Core's lowercase convention for script types (e.g. `witness_v0_keyhash`,
`witness_v1_taproot`). The transaction type (RUNG_TX, v4) is carried separately in
`tx.version`; this field is strictly the *script-level* output type.

#### Load-bearing vs Optional

- **Load-bearing**: neither section is consensus-critical. MLSC outputs would validate
  and spend fine without either change — this only affects *reporting*.
- **Optional**: both sections are convenience shims for Core-only tooling. For a
  BIP submission, they can be omitted; reviewers who want to see MLSC decoded
  properly would need a Ladder-aware tool instead. Keeping them in the reference
  implementation is recommended because they cost ~26 LOC and remove a frequent
  point of confusion.

---

### 18. src/rpc/client.cpp (~16 lines added) — RPC argument converter

#### What was added

Entries in `vRPCConvertParams` for the Ladder/QABIO RPCs (`createtxmlsc`,
`signrungtx`, `qabi_authchain`, `qabi_buildblock`) specifying which positional args
are numbers / arrays / objects rather than strings.

#### Why this is necessary

`bitcoin-cli` receives all args as strings from the shell. Without converter entries,
it forwards them verbatim to the server, which rejects them with
`JSON value of type string is not of expected type number`. Every new RPC that takes
non-string args needs entries here.

#### Load-bearing vs Optional

- **Load-bearing**: this is ergonomics for CLI users. Not consensus-critical.
- **Optional**: can be omitted if reviewers reach the Ladder RPCs via JSON-RPC
  directly (e.g. `curl`) rather than `bitcoin-cli`. Strongly recommended for a
  reference implementation — debugging without it is painful.

---

### 19. src/rpc/mining.cpp (~19 lines modified) — generatetoaddress operator note

#### What was added

A `LogPrintf` in `generateBlocks` that fires when the shared `nMaxTries` budget is
exhausted mid-batch, plus an expanded docstring on `generatetoaddress`'s `maxtries`
argument explaining the shared-budget semantics.

#### Why this was needed

On chains harder than regtest (signet, testnet, mainnet) a `generatetoaddress N addr`
call frequently returns fewer than N block hashes with no error — the nonce-attempt
budget is a *total*, not a per-block, so difficult blocks exhaust it early. Test
infrastructure on signet was tripping on this silently. The log line makes the
early exit visible; the docstring tells operators to raise `maxtries` or loop on
single blocks.

#### Load-bearing vs Optional

- **Load-bearing**: zero consensus impact. This is a pure operator-quality-of-life
  improvement.
- **Optional**: can be dropped entirely. Recommended to keep because it prevents
  silent test-infrastructure failures and costs ~19 LOC.

---

### 20. src/script/script.h — IsUnspendable extension for MLSC DATA_RETURN

#### What was added

`CScript::IsUnspendable()` now additionally returns true for scripts matching the
pattern `0xDF` prefix with size in `(33, 73]` — i.e. `0xDF` + 32-byte conditions_root
+ 1-to-40-byte data tail. Bare MLSC (exactly 33 bytes: prefix + root) is **not**
marked unspendable (those are normal MLSC outputs).

#### Why this specific size range

- MLSC DATA_RETURN: 1 marker byte + 32-byte root + 1..40 bytes DATA payload.
  Total range: 34..73 bytes.
- Bare MLSC: exactly 33 bytes (no data tail). Spendable.
- The DATA_RETURN block evaluator returns `ERROR` on every spend attempt, so outputs
  of this shape are *consensus-unspendable*. Marking them so via `IsUnspendable`
  keeps them out of the UTXO set (parity with OP_RETURN).

#### Why out-of-UTXO matters

Unspendable outputs are pruned immediately on block connection and don't contribute
to the UTXO set's memory footprint. For MLSC+DATA_RETURN (a common pattern for
anchoring / commitment payloads) this matters — without the exemption, every
DATA_RETURN output would sit in the UTXO set forever.

#### Load-bearing vs Optional

- **Load-bearing for economic soundness**: without this, DATA_RETURN payloads would
  bloat the UTXO set forever. With it, they behave exactly like OP_RETURN — stored in
  block data, not in the UTXO set.
- **Load-bearing for policy**: also exempts these outputs from the dust-threshold
  check in `sendrawtransaction` (standard policy refuses dust, but unspendable
  outputs are exempted by definition).
- **Not strictly consensus**: transactions with DATA_RETURN would still validate
  without this change. The UTXO-set implication is the reason this matters.

---

### 21. src/rpc/mempool.cpp (~5 lines added) — MLSC burn-amount exemption

#### What was added

Skip the "burn-amount" check for MLSC outputs in `sendrawtransaction` and
`submitpackage`. The burn check rejects txs that send more than some threshold to
`IsUnspendable()` scripts; with MLSC DATA_RETURN now in `IsUnspendable()`, normal
MLSC data-anchor txs would hit it.

#### Load-bearing vs Optional

- **Load-bearing**: without this, MLSC DATA_RETURN txs with non-zero output amounts
  get rejected by the relay policy, even though they're valid at consensus level.
- **Optional**: the burn check itself is policy, not consensus. A node could relax
  it differently.

---

## Part 3 — Load-Bearing vs Optional Summary

For a BIP reviewer deciding what must appear in the reference implementation vs what
can be trimmed:

### Must keep (consensus or economic soundness)

| File | Sections | Reason |
|------|----------|--------|
| `src/primitives/transaction.{h,cpp}` | RUNG_TX wire format, flag byte 0x02, UTXO inflation | Consensus tx format |
| `src/script/interpreter.{h,cpp}` | `SigVersion::LADDER`, `m_ladder_ready` | Consensus sig dispatch |
| `src/script/script.h` | `IsUnspendable` extension for DATA_RETURN | UTXO-set economic soundness |
| `src/script/script_error.{h,cpp}` | Ladder error codes | Consensus error propagation |
| `src/validation.{cpp,h}` | TX_MLSC dispatch into `VerifyRungTx`, block-height plumbing | Consensus validation seam |
| `src/policy/policy.cpp` | MLSC standardness gate | Mempool policy |
| `src/compressor.{h,cpp}` | MLSC output compression for UTXO set | UTXO-set compression (breaks fork if diverges) |
| `src/coins.{h,cpp}` | UTXO set handling for MLSC | Consensus UTXO semantics |
| `src/pubkey.{h,cpp}` | `ComputeLadderTweak`, x-only Ladder tweak check | Consensus key-path spend |
| `src/key.{h,cpp}` | Ladder-signature signing helpers | Wallet-side parity |
| `src/rpc/register.h` | Register rung RPC | RPC surface |
| `src/rpc/mempool.cpp` | Burn-amount exemption for MLSC | Relay policy |

### Can be omitted from a minimum-viable BIP

| File | Sections | What is lost |
|------|----------|--------------|
| `src/core_write.cpp` | MLSC decoder shims | Human-readable JSON/ASM output — ladder-aware tooling still works |
| `src/rpc/client.cpp` | ConvertParams entries | `bitcoin-cli` ergonomics for Ladder/QABIO RPCs |
| `src/rpc/mining.cpp` | `generatetoaddress` operator note | Operator quality-of-life (exhaustion log + clarified docstring) |
| `src/rpc/util.cpp` | Help-output formatting tweak | Minor help-text cosmetic |

Removing everything in the "can be omitted" column saves ~66 LOC from the 740-LOC
patch, leaving ~674 LOC of consensus-critical / economic-soundness material.

---

## Part 4 — Cross-References

For library-side review, see [`REVIEW_GUIDE.md`](REVIEW_GUIDE.md), which annotates
every file under `src/rung/` with the same Load-bearing / Optional structure.

For the full transaction-format specification, see [`RUNG_TX_SPEC.md`](RUNG_TX_SPEC.md).

For the MLSC output format and Merkle tree spec, see [`TX_MLSC_SPEC.md`](TX_MLSC_SPEC.md).

For the soft-fork activation path, see [`SOFT_FORK_GUIDE.md`](SOFT_FORK_GUIDE.md).
