# RUNG_TX Specification

**Status:** Draft v1.0 · April 2026
**Base:** Bitcoin Core v30.0

> Every claim traces to `src/rung/conditions.{h,cpp}`, `src/rung/serialize.{h,cpp}`,
> `src/rung/types.h`, `src/rung/evaluator.cpp`, or `src/primitives/transaction.h`.

---

## 1. Wire Format

A RUNG_TX is a version 4 Bitcoin transaction. Flag byte `0x02` signals the format
(distinct from SegWit's `0x01`; `0x03` combined is rejected).

```
nVersion:           int32 (= 4, RUNG_TX_VERSION)
dummy:              uint8 (= 0x00)
flags:              uint8 (= 0x02)
vin_count:          varint
vin[]:              prevout(36) + scriptSig_len(1) + nSequence(4) per input
conditions_root:    32 bytes                     ← ONE root for entire tx
vout_count:         varint
vout[]:             nValue(8) per output          ← just values, nothing else
witness[]:          per-input spending witness
aggregated_sig_len: varint (0 if no aggregation)
aggregated_sig:     half-aggregated Schnorr s value (32 bytes if present)
nLockTime:          uint32
```

Each output is 8 bytes (value only, no scriptPubKey on the wire). On deserialisation,
outputs are inflated to `CTxOut(value, 0xDF + conditions_root)` for compatibility with
existing Bitcoin Core code.

**Source**: `primitives/transaction.h:254-266`.

### DATA_RETURN Outputs

Identified by `nValue == 0`. Maximum 1 per transaction. Payload up to 40 bytes.

**Source**: `conditions.cpp:181` (`IsMLSCScript` accepts up to 73 bytes = 1 + 32 + 40).

---

## 2. Merkle Tree

### Leaf Order

```
[ rung_leaf[0], ..., rung_leaf[N-1],
  relay_leaf[0], ..., relay_leaf[M-1],
  coil_leaf ]
```

Total leaves = `total_rungs + total_relays + 1`.

### Leaf Computation

**Rung leaf**: `TaggedHash("LadderLeaf", structural_template || value_commitment)`

The structural template encodes block types and inversion flags. The value commitment
binds the output value and pubkeys (`merkle_pub_key`) to the leaf.

**Functions**: `ComputeTxMLSCLeaf()`, `ComputeValueCommitment()` in `conditions.cpp`.

**Relay leaf**: `TaggedHash("LadderLeaf", SerializeRelayBlocks(relay, CONDITIONS) || pubkeys)`

**Coil leaf**: `TaggedHash("LadderLeaf", SerializeCoilData(coil))`

### Interior Nodes

Sorted child ordering for a canonical tree:

```
MerkleInterior(a, b) = TaggedHash("LadderInternal", min(a,b) || max(a,b))
```

Padded to next power of 2 with `MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")`.

**Source**: `conditions.cpp:154-314`.

### merkle_pub_key

Public keys are **not** stored in conditions. They are folded into the Merkle leaf hash
at creation time and extracted from the witness at spend time via `ExtractBlockPubkeys()`.
This eliminates PUBKEY_COMMIT as a data-embedding surface.

Allowed condition data types: HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX, DATA.
Rejected: PUBKEY, PUBKEY_COMMIT, SIGNATURE, PREIMAGE, SCRIPT_BODY.

`PubkeyCountForBlock()` determines how many pubkeys each block type contributes:
0 (non-key blocks), 1 (SIG, TIMELOCKED_SIG, etc.), 2 (HTLC, VAULT_LOCK, ADAPTOR_SIG),
or N (MULTISIG, TIMELOCKED_MULTISIG — counted dynamically).

**Source**: `types.h:595-643`, `evaluator.cpp:3292-3307`.

---

## 3. LadderTweak (Key-path Enablement)

When `createrungtx` detects a single-SIG ladder, it automatically tweaks the output:

```
conditions_root = internal_pubkey + H("LadderTweak", internal_pubkey || merkle_root) × G
```

This enables both key-path and script-path spending from the same output. Without the
tweak, `conditions_root` is the raw Merkle root and only script-path spending is possible.

**Functions**: `ComputeLadderTweakHash()`, `CheckLadderTweak()`, `CreateLadderTweak()`
in `pubkey.cpp`. `SignSchnorrLadder()` in `key.cpp`.

---

## 4. Spending Paths

### Key-path (1-element witness): `[signature(64)]`

The `conditions_root` is treated as an x-only public key. Schnorr signature verified
using `SignatureHashLadderKeyPath` (tagged hash `"LadderKeyPathSighash"`). No conditions
revealed. This is the 110 vB path (1-in, 1-out) or 118 vB for a standard 2-output payment.

### Script-path (2 or 3 element witness): `[LadderWitness, MLSCProof, (internal_pubkey)]`

Conditions revealed + Merkle proof against conditions_root. If 3 elements, the internal
pubkey proves the tweak relationship, allowing the node to recover the raw Merkle root.
The evaluator runs all blocks in the satisfied rung.

---

## 5. MLSC Proof

Carried in witness `stack[1]`. Structure:

```cpp
struct MLSCProof {
    uint16_t total_rungs;
    uint16_t total_relays;
    uint16_t rung_index;           // which rung is being revealed
    Rung revealed_rung;            // condition blocks for the spending rung
    vector<pair<uint16_t, Relay>> revealed_relays;
    vector<uint256> proof_hashes;  // leaf hashes for unrevealed leaves
    vector<pair<uint16_t, Rung>> revealed_mutation_targets;  // optional
};
```

### Proof Modes

**FULL_LEAVES (0x00)**: all unrevealed leaf hashes provided. O(N) witness size.

**MERKLE_PATH (0x01)**: O(log N) sibling hashes from leaf to root. Default mode.

**SHARED (0x02)**: references a previously verified input from the same source
transaction. Leaf membership verified against cached leaf set via `SharedTreeCache`.

### Proof Verification Algorithm

1. Allocate leaf array: size = `total_rungs + total_relays + 1`
2. Compute revealed rung leaf from conditions + pubkeys
3. Compute revealed relay leaves
4. Compute coil leaf (always revealed from witness)
5. Fill unrevealed slots with proof hashes
6. Verify mutation targets (if present)
7. Build Merkle tree → `computed_root`
8. Compare `computed_root == conditions_root` (or verify tweak for 3-element witness)

**Source**: `conditions.cpp:560-655`.

---

## 6. Verification Flow: `VerifyRungTx`

### Per-transaction (first input only)

1. `ValidateRungOutputs`: all outputs must be MLSC (`0xDF`), max 1 DATA_RETURN,
   dust threshold (546 sats)
2. Creation proof: required for 3+ spendable outputs. Validates leaf hashes build
   to conditions_root. Optional for 1-2 outputs (validated if present)
3. PREIMAGE/SCRIPT_BODY count across ALL inputs ≤ `MAX_PREIMAGE_FIELDS_PER_TX` (2)

### Per-input

4. Verify spent output is MLSC. Witness stack must be 1, 2, or 3 elements
5. **Key-path** (1 element): verify Schnorr signature against conditions_root as pubkey
6. **Script-path** (2-3 elements):
   - Deserialise `LadderWitness` from stack[0], `MLSCProof` from stack[1]
   - Resolve witness references (diff witness mode) if needed
   - Single rung rule: witness must contain exactly 1 rung
   - Extract pubkeys via `ExtractBlockPubkeys` (merkle_pub_key)
   - Compute revealed leaf via `ComputeTxMLSCLeaf`
   - Verify Merkle proof (FULL_LEAVES / MERKLE_PATH / SHARED)
   - If 3-element: verify tweak via `CheckLadderTweak`
   - Verify `coil.output_index` matches spent vout index
7. `MergeConditionsAndWitness`: combine conditions (from proof) with witness (from stack[0])
8. `EvalLadder`: relays first (cached), then rungs in order. First SATISFIED rung wins.

**Source**: `evaluator.cpp:3743-4248`.

---

## 7. UTXO Deduplication

RUNG_TX outputs share the same conditions_root. A synthetic UTXO entry stores the root
once per transaction:

```
Synthetic entry: (txid, 0xFFFFFFFF) → Coin(value=0, scriptPubKey=0xDE+root)
Real outputs:    (txid, 0..N)       → Coin(value, scriptPubKey=0xDF) [1 byte, compressed type 0x06]
```

At spend time, compact MLSC coins are inflated by looking up the synthetic root entry.

| Type | Per output | 100 outputs |
|------|-----------|-------------|
| P2PKH | ~40 B | ~4,000 B |
| P2WPKH | ~37 B | ~3,700 B |
| P2TR | ~49 B | ~4,900 B |
| **RUNG_TX** | **~8 B** | **~840 B** |

**Source**: `coins.cpp:129-140`, `compressor.cpp` (type 0x06 compression).

---

## 8. Size and Fee Analysis

### Minimal spend (1 input, 1 output)

| Format | vBytes | Fee (10 sat/vB) |
|--------|--------|-----------------|
| P2PKH | 192 | 1,920 sats |
| P2WPKH | 110 | 1,100 sats |
| P2TR key-path | 111 | 1,110 sats |
| **RUNG_TX key-path** | **110** | **1,100 sats** |

### Simple payment (1 input, 2 outputs)

| Format | vBytes | Fee (10 sat/vB) |
|--------|--------|-----------------|
| P2PKH | 226 | 2,260 sats |
| P2WPKH | 143 | 1,430 sats |
| P2TR key-path | 157 | 1,570 sats |
| **RUNG_TX key-path** | **118** | **1,180 sats** |
| **RUNG_TX script-path (SIG+CSV)** | **124** | **1,240 sats** |

### Batch payment (1 input, N outputs)

| Outputs | P2WPKH | P2TR | **RUNG_TX key** | Saving vs P2WPKH |
|---------|--------|------|-----------------|------------------|
| 2 | 143 vB | 167 vB | **118 vB** | 17% |
| 10 | 391 vB | 511 vB | **194 vB** | 50% |
| 100 | 3,181 vB | 4,381 vB | **914 vB** | 71% |
| 1000 | 31,081 vB | 43,081 vB | **8,114 vB** | 74% |

### Full lifecycle (create + spend)

| Type | Total | vs P2WPKH |
|------|-------|-----------|
| P2WPKH | 255 vB | baseline |
| P2TR key-path | 281 vB | -10% |
| **RUNG_TX key-path** | **241 vB** | **+6% cheaper** |

---

## 9. Anti-spam

### Embeddable data per transaction

| Channel | Bytes | Note |
|---------|-------|------|
| DATA_RETURN | 40 | Max 1 per tx, zero-value output |
| PREIMAGE fields | 64 max | 2 per tx × 32 bytes, hash-bound |
| nLockTime + nSequence | 8 | Standard Bitcoin fields |
| **Total** | **112** | Flat, regardless of output count |

The `conditions_root` is protocol-derived (not attacker-chosen).

### Defences

1. **merkle_pub_key**: pubkeys folded into leaf hash, not in conditions
2. **Key-consuming blocks never invertible**: prevents garbage-pubkey data embedding
3. **Implicit field layouts**: fixed field counts/types per block
4. **Fail-closed deserialisation**: unknown types/fields rejected
5. **IsDataEmbeddingType**: HASH256/HASH160/DATA rejected in layout-less blocks
6. **PREIMAGE cap**: `MAX_PREIMAGE_FIELDS_PER_TX = 2`
7. **DATA restriction**: DATA type only in DATA_RETURN blocks
8. **Dust threshold**: `MIN_RUNG_OUTPUT_VALUE = 546 sats` (consensus)

---

## 10. Coil

The coil commits output metadata in the Merkle tree:

| Field | Size | Values |
|-------|------|--------|
| coil_type | 1 B | UNLOCK (0x01), UNLOCK_TO (0x02) |
| attestation | 1 B | INLINE (0x01), AGGREGATE (0x02) |
| scheme | 1 B | SCHNORR, ECDSA, FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA |
| address_hash | 0 or 32 B | SHA256(destination) for UNLOCK_TO |
| rung_destinations | variable | Per-rung destination overrides |

---

## 11. Template and Witness References

### Template Reference

Conditions can inherit from another input with optional field-level diffs. Source must
not itself be a template reference (no chaining).

**Source**: `conditions.cpp:59-126`.

### Witness Reference (Diff Witness)

When `n_rungs == 0`, rungs and relays are inherited from another input's witness. Only
field-level diffs and a fresh coil are serialised. Allowed diff types: PUBKEY, SIGNATURE,
PREIMAGE, SCRIPT_BODY, SCHEME. The coil is never inherited.

**Source**: `serialize.cpp:381-523`.

---

## 12. Constants

| Constant | Value | Source |
|----------|-------|--------|
| `RUNG_MLSC_PREFIX` | `0xDF` | `conditions.h` |
| `RUNG_TX_VERSION` | 4 | `transaction.h` |
| `MAX_RUNGS` | 16 | `serialize.h` |
| `MAX_BLOCKS_PER_RUNG` | 8 | `serialize.h` |
| `MAX_FIELDS_PER_BLOCK` | 16 | `serialize.h` |
| `MAX_RELAYS` | 8 | `serialize.h` |
| `MAX_REQUIRES` | 8 | `serialize.h` |
| `MAX_RELAY_DEPTH` | 4 | `serialize.h` |
| `MAX_LADDER_WITNESS_SIZE` | 100,000 B | `serialize.h` |
| `MAX_PREIMAGE_FIELDS_PER_WITNESS` | 2 | `serialize.h` |
| `MAX_PREIMAGE_FIELDS_PER_TX` | 2 | `serialize.h` |
| `MAX_COIL_CONDITION_RUNGS` | 0 | `serialize.h` |
| `MIN_RUNG_OUTPUT_VALUE` | 546 sats | `serialize.h` |
| `MLSC_ROOT_VOUT` | 0xFFFFFFFF | `coins.h` |
