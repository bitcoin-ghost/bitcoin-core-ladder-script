# Ladder Script: Annotated Diff Against Bitcoin Core v30.0

This document explains every change made to Bitcoin Core to integrate Ladder Script.
The patch file is `ladder-script-v30.0.patch` (29,742 lines, 52 files).

## Overview

| Category | Files changed | Lines added |
|----------|--------------|-------------|
| New module (src/rung/) | 22 | ~14,000 |
| Tests (src/test/) | 2 | ~11,640 |
| Core integration | 12 | ~300 |
| Documentation | 8 | ~3,580 |
| **Total** | **52** | **~29,742** |

---

## Core Integration Points (12 files, ~300 lines)

### 1. src/primitives/transaction.h — TX_MLSC wire format

**What:** Adds v4 transaction format with shared conditions_root and value-only outputs.

- `RUNG_TX_VERSION = 4`: new transaction version constant
- `conditions_root` (uint256): shared Merkle root for all outputs
- `aggregated_sig` (vector<uint8_t>): half-aggregated Schnorr signature
- Flag byte `0x02` in serialization signals TX_MLSC format
- Flag `0x03` (SegWit + TX_MLSC combined) explicitly rejected
- Deserialization inflates 8-byte outputs to CTxOut(value, 0xDF + root)
- No-witness serialization uses standard vout format (parseable by all tools)

**Why:** TX_MLSC outputs are 8 bytes on the wire (value only) vs 31-43 bytes for legacy types. The shared root amortizes the 32-byte commitment across all outputs. Flag 0x02 is a clean extension point (0x01 is SegWit, documented in BIP 141).

### 2. src/primitives/transaction.cpp — constructor initializers

**What:** Adds `conditions_root` and `aggregated_sig` to CTransaction and CMutableTransaction constructors.

**Why:** New fields must be copied/moved in constructors for correct transaction lifecycle.

### 3. src/script/interpreter.h — SigVersion::LADDER

**What:** Adds `LADDER = 4` to the SigVersion enum and `m_ladder_ready` to PrecomputedTransactionData.

**Why:** Ladder Script uses a different sighash algorithm (TaggedHash("LadderSighash")) than Taproot (TaggedHash("TapSighash")). The evaluator needs to distinguish ladder signatures from taproot signatures. The `m_ladder_ready` flag tracks whether ladder-specific hash caches are initialized.

### 4. src/script/interpreter.cpp — ladder sighash precomputation

**What:** In `PrecomputedTransactionData::Init()`, adds precomputation for v4 transactions. Computes prevouts, sequences, outputs, and spent amounts hashes for the ladder sighash algorithm.

**Why:** Avoids recomputing these hashes for every input. Same optimization pattern as BIP143 (SegWit) and BIP341 (Taproot).

### 5. src/script/script_error.h/cpp — error codes

**What:** Adds `SCRIPT_ERR_LADDER_INVALID_WITNESS` and `SCRIPT_ERR_LADDER_EVAL_FALSE` with descriptive error strings.

**Why:** Distinct error codes for ladder-specific failures enable better diagnostics.

### 6. src/validation.cpp — consensus routing and UTXO inflation

**What:**
- `CScriptCheck::operator()`: routes v4 MLSC outputs to `rung::VerifyRungTx()` instead of `VerifyScript()`
- `CheckInputScripts`: inflates compact MLSC coins from UTXO dedup (looks up synthetic root entry)
- `ConnectBlock`: passes `pindex->nHeight` for block_height-dependent evaluators (EPOCH_GATE, RECURSE_UNTIL)

**Why:** v4 transactions with MLSC outputs use the ladder evaluator (61 typed blocks) instead of the stack-based Script interpreter. Standard inputs in v4 transactions (P2WPKH bootstrap funding) still use VerifyScript. UTXO inflation recovers the conditions_root from the synthetic entry for compact MLSC coins.

**Security:** Only MLSC outputs (0xDF prefix) are routed to the ladder evaluator. Non-MLSC outputs in v4 transactions fall through to standard verification. Non-v4 transactions are completely unaffected.

### 7. src/validation.h — CScriptCheck block_height

**What:** Adds `m_block_height` field to CScriptCheck and passes it to the ladder evaluator.

**Why:** EPOCH_GATE and RECURSE_UNTIL blocks need the chain tip height for correct evaluation.

### 8. src/policy/policy.cpp — v4 policy routing

**What:** Routes v4 transactions to `rung::IsStandardRungTx()` for policy checking before the standard version bounds check would reject them.

**Why:** v4 exceeds `TX_MAX_STANDARD_VERSION` (2). Without this routing, v4 transactions would be rejected by policy even though they're valid by consensus.

### 9. src/rpc/register.h — RPC registration

**What:** Declares `RegisterRungRPCCommands()` and calls it in `RegisterAllCoreRPCCommands()`.

**Why:** Exposes ladder-specific RPCs (createrungtx, signrungtx, signladder, createtxmlsc, decoderung, validateladder, etc.) to users.

### 10. src/CMakeLists.txt — build system

**What:** Adds `add_subdirectory(rung)` and links `bitcoin_rung` to `bitcoin_common`, `bitcoin_node`, `bitcoind`, and `bitcoin-node`.

**Why:** The rung module is a static library linked into the node. No circular dependencies.

### 11. src/compressor.h/cpp — UTXO deduplication

**What:** Adds compression type 0x06 for MLSC outputs. Stores 0 bytes of script data — the 33-byte scriptPubKey (0xDF + root) is compressed to just the type byte. Decompresses to a 1-byte scriptPubKey (0xDF) which is inflated from the synthetic root entry at validation time.

**Why:** TX_MLSC outputs all share the same conditions_root. Without compression, each output stores 33 bytes of identical scriptPubKey. With compression, each output stores ~1 byte + the root is stored once per transaction in a synthetic UTXO entry. Per-output UTXO cost drops from ~48 bytes to ~8 bytes.

### 12. src/coins.h/cpp — synthetic root entry

**What:** Defines `MLSC_ROOT_VOUT = 0xFFFFFFFF` sentinel. In `AddCoins()`, writes a synthetic coin at `(txid, 0xFFFFFFFF)` containing the full MLSC scriptPubKey for every TX_MLSC transaction.

**Why:** The synthetic entry stores the conditions_root once per transaction. Compact MLSC coins look it up from the UTXO cache at spend time. No block database dependency. Works for mempool, pruned nodes, and all validation paths.

### 13. src/pubkey.h/cpp — LadderTweak

**What:** Adds `ComputeLadderTweakHash()`, `CheckLadderTweak()`, `CreateLadderTweak()` to XOnlyPubKey. Uses TaggedHash("LadderTweak") instead of TaggedHash("TapTweak").

**Why:** Ladder key-path spending uses the same tweak mechanism as Taproot but with a distinct tag for domain separation. A Taproot signature cannot be replayed against a Ladder output and vice versa.

### 14. src/key.h/cpp — SignSchnorrLadder

**What:** Adds `CKey::SignSchnorrLadder()` for Schnorr signing with LadderTweak.

**Why:** Wallet signing for ladder key-path spends.

---

## New Module: src/rung/ (22 files, ~14,000 lines)

Self-contained module implementing the Ladder Script evaluator, serialization,
Merkle tree, sighash, descriptors, policy, RPC commands, and post-quantum support.

| File | Lines | Purpose |
|------|-------|---------|
| types.h/cpp | 1,457 | 61 block types, 11 data types, field layouts, descriptors |
| evaluator.h/cpp | 4,301 | Block evaluation, rung/ladder logic, batch verification |
| serialize.h/cpp | 1,106 | Wire format, micro-headers, implicit layouts |
| conditions.h/cpp | 1,261 | Merkle tree, MLSC proofs, leaf computation |
| sighash.h/cpp | 310 | Tagged sighash, ANYPREVOUT, key-path sighash |
| descriptor.h/cpp | 1,823 | Human-readable descriptors, TX_MLSC parser |
| rpc.cpp | 3,219 | 15 RPC commands |
| policy.h/cpp | 171 | Standard transaction checks |
| adaptor.h/cpp | 244 | Adaptor signature support |
| aggregate.h/cpp | 82 | Signature aggregation |
| pq_verify.h/cpp | 196 | Post-quantum verification (FALCON, Dilithium, SPHINCS+) |
| CMakeLists.txt | 45 | Build configuration |

---

## Tests: src/test/rung_tests.cpp (11,631 lines)

486 test cases covering:
- All 61 block type evaluators
- Serialization roundtrips (witness + conditions)
- Merkle tree construction and verification
- Anti-spam field restrictions
- Policy validation
- MLSC proof modes (FULL_LEAVES, MERKLE_PATH, SHARED)
- TX_MLSC leaf/root computation
- Key-path and script-path spending
- Compact coil encoding
- Half-aggregated signature verification
- Boundary conditions (MAX_RUNGS, MAX_BLOCKS, MAX_FIELDS, etc.)

---

## Security Properties

1. **Non-v4 transactions unaffected**: all ladder code gated on version == 4 AND MLSC scriptPubKey
2. **No new opcodes**: 61 typed blocks replace opcodes entirely
3. **Bounded execution**: O(blocks × fields), no loops, no stack manipulation
4. **Anti-spam**: 144 bytes embeddable data per tx (flat), 546 sat consensus dust
5. **UTXO efficient**: ~8 bytes per output (6× better than Taproot)
6. **Domain separation**: LadderSighash and LadderTweak tags prevent cross-protocol replay
