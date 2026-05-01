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
  relay_leaf[0], ..., relay_leaf[M-1] ]
```

Total leaves = `total_rungs + total_relays`.

Coil structural fields (type / attestation / scheme / output_index) are
folded into each rung leaf's structural template — there is no separate
coil leaf.

Relay leaves are folded into the same `conditions_root` tree as the rungs,
so a spender cannot swap in a different relay pubkey at spend time.

### Leaf Computation

**Rung leaf**: `TaggedHash("LadderLeaf/v1", structural_template || value_commitment)`

The structural template encodes block types and inversion flags plus the 4-byte
coil. The value commitment binds the output value and pubkeys
(`merkle_pub_key`) to the leaf.

**Relay leaf**: `TaggedHash("LadderRelayLeaf/v1", relay_template || value_commitment)`

Distinct tagged-hash domain so a relay leaf can never alias a rung leaf at the
same block layout.

**Functions**: `ComputeTxMLSCLeaf()`, `ComputeTxMLSCRelayLeaf()`,
`ComputeValueCommitment()` in `conditions.cpp`.

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

1. Allocate leaf array: size = `total_rungs + total_relays` (no
   coil leaf in the consensus path — coil bytes are folded into each
   rung leaf's structural template)
2. Compute revealed rung leaf from conditions + pubkeys (via
   `ComputeTxMLSCLeaf`)
3. Compute revealed relay leaves (via `ComputeTxMLSCRelayLeaf`)
4. Fill unrevealed slots with proof hashes
5. Verify mutation targets (if present)
6. Build Merkle tree → `computed_root`
7. Compare `computed_root == conditions_root` (or verify tweak for 3-element witness)

**Source**: `conditions.cpp:560-655`.

---

## 6. Verification Flow: `VerifyRungTx`

### Per-transaction (run once per v4 tx)

Production validation runs `CheckRungTxLevel` unconditionally per v4 tx
(`validation.cpp:2406`). The evaluator re-runs the same check on
`input_index == 0` as a redundant safety net for test paths.

1. `ValidateRungOutputs`: all outputs must be MLSC (`0xDF`), max 1 DATA_RETURN,
   dust threshold (546 sats)
2. Creation proof: required for 3+ spendable outputs. Validates leaf hashes build
   to conditions_root. Optional for 1-2 outputs (validated if present)
3. PREIMAGE/SCRIPT_BODY count across all MLSC-spending inputs ≤ `MAX_PREIMAGE_FIELDS_PER_TX` (2). The cap counts MLSC-spending inputs only — bootstrap inputs (P2WPKH/P2WSH/P2TR etc) are excluded since their witness bytes are not Ladder Script. Diff-witness overlays count too: an N-input tx with diff witnesses cannot use diffs to fan out fresh PREIMAGE/SCRIPT_BODY bytes past the cap.

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

### Attacker-controllable bytes per transaction

A spender that funds + spends their own MLSC UTXOs reveals committed
content at spend time. The protocol bounds this revelation but does not
zero it — every commit-reveal scheme is structurally the same in this
respect (P2WSH commits 32 B per output, P2TR commits 32 B per output,
MLSC commits 32 B per output via `conditions_root`).

| Channel | Per-instance | Per-tx cap | Notes |
|---------|--------------|------------|-------|
| `DATA_RETURN` block | up to 40 B | 1 block per tx | Zero-value output, payload is the application-defined commitment |
| `conditions_root` | 32 B | per MLSC output | Attacker-picked Merkle root; same shape as P2WSH script-hash |
| Conditions-side `HASH256` (TAGGED_HASH, CTV, COSIGN, HTLC etc) | 32 B per field | bound by per-block layout × `MAX_BLOCKS_PER_RUNG` × revealed rungs | Application-defined commitments |
| `PREIMAGE` (witness) | up to 32 B | `MAX_PREIMAGE_FIELDS_PER_TX = 2` | Hash-bound to a `HASH256` in conditions |
| `SCRIPT_BODY` (witness) | up to 80 B | `MAX_SCRIPT_BODY_FIELDS_PER_TX = 1` | Hash-bound, used by legacy P2SH/P2WSH/P2TR_SCRIPT wrappers |
| `PUBKEY` (witness, leaf reconstruction) | 32-65 B per pubkey | bounded by `PubkeyCountForBlock` per block | Must reproduce the committed leaf hash on validation |
| MLSC proof sibling hashes | 32 B per sibling | depth ≤ log₂(`MAX_RUNGS`) = 4 per input | Each sibling hashes an attacker-chosen subtree |
| `nLockTime` + `nSequence` | 4 + 4 per input | standard Bitcoin | Inherited from the base tx format |
| `OP_RETURN` outputs | up to 80 B (relay) / 10 KB (consensus) | standardness limit | Standard Bitcoin, not MLSC-specific |

Because MLSC bytes are typed (no `OP_DROP` / `OP_IF false` / push-and-
discard equivalents), every byte in an MLSC witness is consumed by
consensus — no "dead-code" channel exists. This is the structural
distinction from Taproot script-path tapscripts, where `OP_FALSE OP_IF
<arbitrary> OP_ENDIF` blocks (used by Ordinals inscriptions) embed
witness bytes that the executed path never reaches.

### Structural defences

1. **merkle_pub_key**: pubkeys folded into the leaf hash, not the
   conditions field stream — the wire only carries the hash root.
2. **Key-consuming blocks are never invertible**: prevents garbage-
   pubkey data embedding via the `inverted` flag.
3. **Implicit field layouts**: fixed field counts/types per block on
   both conditions and witness sides; explicit-encoded blocks must
   match the implicit layout exactly.
4. **Fail-closed deserialisation**: unknown block types, unknown data
   types, oversize fields, non-canonical `CompactSize` reject.
5. **`IsDataEmbeddingType`**: `HASH256` / `HASH160` / `PUBKEY_COMMIT` /
   `DATA` reject inside any layout-less block (`RECURSE_MODIFIED`,
   `RECURSE_DECAY`).
6. **Conditions-only witness whitelist**: block types whose evaluator
   reads only conditions-side fields accept witnesses containing only
   `PUBKEY` (count ≤ `PubkeyCountForBlock`) and `PREIMAGE` (count ≤ 2)
   — every other field type rejects.
7. **Per-tx caps**: `MAX_PREIMAGE_FIELDS_PER_TX = 2`,
   `MAX_SCRIPT_BODY_FIELDS_PER_TX = 1`,
   `MAX_LADDER_WITNESS_SIZE = 100 KB` per input. Caps count diff-
   witness overlays alongside direct witnesses — overlays cannot fan
   out fresh PREIMAGE/SCRIPT_BODY past the cap.
8. **`DATA` restriction**: `DATA` field type allowed only inside
   `DATA_RETURN` blocks.
9. **Dust threshold**: `MIN_RUNG_OUTPUT_VALUE = 546 sats` (consensus).

---

## 10. Coil

Fixed 4-byte tail. Each MLSC output ends with the coil; nothing else after.

| Field | Size | Values |
|-------|------|--------|
| coil_type | 1 B | UNLOCK (0x01), UNLOCK_TO (0x02) |
| attestation | 1 B | INLINE (0x01) |
| scheme | 1 B | SCHNORR, ECDSA, FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA |
| output_index | 1 B | Position of this output in the spending tx (0…255) |

The coil carries no `address_hash` or `rung_destinations`. Wallets that
need destination metadata track it locally. `UNLOCK_TO` is reserved for a
future wire format that binds output structure on-chain (e.g. via a
CTV-style template hash).

The compact-coil sentinel (`0x00 + output_index`) expands to the default
`UNLOCK + INLINE + SCHNORR` shape — saves 3 bytes per coil for the common
case.

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
| `MAX_SCRIPT_BODY_FIELDS_PER_TX` | 1 | `serialize.h` |
| `MAX_PUBKEYS_PER_MULTISIG` | 16 | `serialize.h` |
| `MAX_MULTISIG_TREE_DEPTH` | 4 | `serialize.h` |
| `MAX_MULTISIG_WITNESS_FIELDS` | 48 | `serialize.h` |
| `MAX_ACCUMULATOR_PROOF_DEPTH` | 4 | `serialize.h` |
| `MAX_ACCUMULATOR_BLOCKS_PER_RUNG` | 1 | `serialize.h` |
| `MAX_ACCUMULATOR_BLOCKS_PER_TX` | 2 | `serialize.h` |
| `MAX_ACCUMULATOR_ELEMENT_ID` | 0xFFFF | `serialize.h` |
| `COMPACT_COIL_SENTINEL` | 0x00 | `serialize.h` |
| `MIN_RUNG_OUTPUT_VALUE` | 546 sats | `serialize.h` |
| `MLSC_ROOT_VOUT` | 0xFFFFFFFF | `coins.h` |
