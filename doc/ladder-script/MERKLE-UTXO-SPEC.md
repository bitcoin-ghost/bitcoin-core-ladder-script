# Merkelised Ladder Script Conditions (MLSC)

## Specification v2.0

> Regenerated from source code. Every claim traces to
> `src/rung/conditions.{h,cpp}`, `src/rung/serialize.{h,cpp}`,
> `src/rung/types.h`, or `src/rung/evaluator.cpp`.

---

## 1. Output Format

TX_MLSC is the **only** accepted output format for v4 (rung) transactions.
Inline conditions (`0xC1`) and per-output MLSC (`0xC2`) are removed and always
rejected.

### TX_MLSC Layout

In the TX_MLSC model, there is one shared Merkle tree per transaction (PLC
model: one program, multiple output coils). Each output is **8 bytes** (value
only). The transaction carries a single shared `conditions_root` with prefix
byte `0xDF`. A creation proof in the witness section is validated at block
acceptance.

The transaction serialization uses flag byte `0x02` to signal TX_MLSC format.

Each rung's coil has an `output_index` field declaring which output it governs.

With optional DATA\_RETURN payload:

```
0xDF || conditions_root (32 bytes) || data (1-40 bytes)
```

**Source**: `IsMLSCScript()` in `conditions.cpp` checks `0xDF`
(`RUNG_MLSC_PREFIX`).

### Constants

```cpp
static constexpr uint8_t RUNG_MLSC_PREFIX = 0xdf;      // conditions.h (TX_MLSC prefix)
static constexpr uint8_t RUNG_CONDITIONS_PREFIX = 0xc1; // conditions.h (rejected — retained for test code)
```

### Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `CreateMLSCScript` | `CScript CreateMLSCScript(const uint256& conditions_root)` | Build TX_MLSC shared conditions_root |
| `CreateMLSCScript` | `CScript CreateMLSCScript(const uint256& conditions_root, const std::vector<uint8_t>& data)` | Build TX_MLSC with DATA\_RETURN payload |
| `IsMLSCScript` | `bool IsMLSCScript(const CScript& scriptPubKey)` | Check prefix `0xDF` |
| `IsLadderScript` | `bool IsLadderScript(const CScript& scriptPubKey)` | Alias for `IsMLSCScript` |
| `GetMLSCRoot` | `bool GetMLSCRoot(const CScript& scriptPubKey, uint256& root_out)` | Extract 32-byte root (bytes 1-32) |
| `GetMLSCData` | `std::vector<uint8_t> GetMLSCData(const CScript& scriptPubKey)` | Extract DATA\_RETURN payload (bytes 33+) |
| `HasMLSCData` | `bool HasMLSCData(const CScript& scriptPubKey)` | True if `size > 33` |

---

## 2. Merkle Tree Structure

### Leaf Order

The leaf array is constructed in fixed order:

```
[ rung_leaf[0], rung_leaf[1], ..., rung_leaf[N-1],
  relay_leaf[0], relay_leaf[1], ..., relay_leaf[M-1],
  coil_leaf ]
```

Total leaves = `total_rungs + total_relays + 1`.

**Source**: `ComputeConditionsRoot()` in `conditions.cpp:316-335`.

### Tagged Hashing (BIP-341 style)

All hashing uses domain-separated tagged hashes:

```
TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)
```

Two tag domains are defined with pre-computed hashers:

| Domain | Tag String | Hasher |
|--------|------------|--------|
| Leaf | `"LadderLeaf"` | `LEAF_HASHER` |
| Internal node | `"LadderInternal"` | `INTERNAL_HASHER` |

**Source**: `conditions.cpp:154-166`.

### Leaf Computation

**Rung leaf**: `ComputeRungLeaf(rung, value_commitment)`

```
TaggedHash("LadderLeaf", structural_template || value_commitment)
```

The structural template encodes the rung's condition blocks. The value commitment
binds the output value to the leaf. This replaces the previous
`TaggedHash("LadderLeaf", serialized_blocks || pubkeys)` format.

**Relay leaf**: `ComputeRelayLeaf(relay, pubkeys)`

```
TaggedHash("LadderLeaf", SerializeRelayBlocks(relay, CONDITIONS) || pk[0] || pk[1] || ... || pk[N])
```

**Coil leaf**: `ComputeCoilLeaf(coil)`

```
TaggedHash("LadderLeaf", SerializeCoilData(coil))
```

No pubkeys are appended to the coil leaf.

**Source**: `conditions.cpp:226-263`.

### Empty Leaf Padding

```
MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")
```

A nothing-up-my-sleeve constant. Cannot collide with any valid serialized
rung/coil/relay data.

**Source**: `conditions.cpp:168-174`, `conditions.h:30-31`.

### Internal Node Construction

Interior nodes use **sorted child ordering** to produce a canonical tree
regardless of child position:

```
MerkleInterior(a, b) = TaggedHash("LadderInternal", min(a,b) || max(a,b))
```

Children are sorted lexicographically by their 32-byte hash before
concatenation. This ensures the same two children always produce the same
parent regardless of left/right position.

**Source**: `conditions.cpp:267-282`.

### Tree Construction: `BuildMerkleTree(leaves)`

1. If `leaves` is empty, return `MLSC_EMPTY_LEAF`.
2. If `leaves` has 1 element, return it directly.
3. Pad `leaves` to the next power of 2 with `MLSC_EMPTY_LEAF`.
4. Build bottom-up: pair adjacent leaves, compute `MerkleInterior(left, right)`.
5. Repeat until one root remains.

**Source**: `conditions.cpp:292-314`.

---

## 3. merkle\_pub\_key

Public keys are **not** stored in condition fields. Instead, they are folded
directly into the Merkle leaf hash at creation time and extracted from the
witness at spend time. This eliminates `PUBKEY_COMMIT` as a data-embedding
surface.

### How It Works

1. **At output creation**: The creator serializes condition blocks (which
   contain only condition data types — no `PUBKEY`, no `PUBKEY_COMMIT`) and
   appends the raw pubkey bytes to the leaf hash input.

2. **At spend time**: `ExtractBlockPubkeys()` walks the witness blocks
   left-to-right, collecting `PUBKEY` fields from each block based on
   `PubkeyCountForBlock()`. These pubkeys are passed to `ComputeRungLeaf()`
   / `ComputeRelayLeaf()` during proof verification.

3. **Binding**: If the spender provides wrong pubkeys, the recomputed leaf
   hash will differ, the Merkle root will not match, and verification fails.

### Allowed Condition Data Types

```cpp
bool IsConditionDataType(RungDataType type)  // conditions.cpp:18-37
```

Allowed in conditions: `HASH256`, `HASH160`, `NUMERIC`, `SCHEME`, `SPEND_INDEX`, `DATA`.

Rejected in conditions: `PUBKEY_COMMIT`, `PUBKEY`, `SIGNATURE`, `PREIMAGE`, `SCRIPT_BODY`.

### `PubkeyCountForBlock(type, block)`

Determines how many pubkeys each block type contributes to the Merkle leaf:

| Count | Block Types |
|-------|-------------|
| 0 | `P2PKH_LEGACY`, `P2WPKH_LEGACY`, all non-key blocks (timelocks, hashes, covenants, anchors, etc.) |
| 1 | `SIG`, `TIMELOCKED_SIG`, `HASH_SIG`, `CLTV_SIG`, `MUSIG_THRESHOLD`, `P2PK_LEGACY`, `P2TR_LEGACY`, `P2TR_SCRIPT_LEGACY`, `ANCHOR_ORACLE`, `LATCH_SET`, `LATCH_RESET`, `COUNTER_DOWN`, `COUNTER_UP` |
| 2 | `HTLC`, `ANCHOR_CHANNEL`, `VAULT_LOCK`, `ADAPTOR_SIG`, `PTLC` |
| N (dynamic) | `MULTISIG`, `TIMELOCKED_MULTISIG` — counts actual `PUBKEY` fields in the witness block |

**Source**: `types.h:595-643`.

### `ExtractBlockPubkeys(blocks)`

Walks blocks left-to-right. For each block, calls `PubkeyCountForBlock()` to
determine how many pubkeys to extract, then collects that many `PUBKEY` fields
from the witness block using `FindAllFields(block, RungDataType::PUBKEY)`.

**Source**: `evaluator.cpp:3292-3307`.

---

## 4. Serialization for Leaf Computation

### `SerializeRungBlocks(rung, ctx)` / `SerializeRelayBlocks(relay, ctx)`

Wire format for Merkle leaf input:

```
CompactSize(n_blocks)
for each block:
    micro_header OR escape + block_type(uint16 LE)
    fields (implicit or explicit encoding)
CompactSize(n_relay_refs)
for each relay_ref:
    CompactSize(relay_index)
```

Relay refs are included in the leaf data so they are committed via the Merkle
tree.

**Source**: `serialize.cpp:867-942`.

### `SerializeCoilData(coil)`

Wire format:

```
coil_type       (1 byte)
attestation     (1 byte)
scheme          (1 byte)
address_len     (CompactSize)    — 0 or 32
address_hash    (address_len bytes)
n_conditions    (CompactSize)    — must be 0 (MAX_COIL_CONDITION_RUNGS = 0)
n_rung_destinations (CompactSize)
for each rung_destination:
    rung_index  (uint16 LE)
    addr_hash   (32 bytes)
```

**Source**: `serialize.cpp:889-921`.

---

## 5. Proof Structure: `MLSCProof`

The MLSC proof is carried in **witness stack\[1\]** when spending an MLSC output.

### Fields

```cpp
struct MLSCProof {                              // conditions.h:163-171
    uint16_t total_rungs;                       // Total rungs in the original conditions
    uint16_t total_relays;                      // Total relays in the original conditions
    uint16_t rung_index;                        // Which rung is being revealed (0-based)
    Rung revealed_rung;                         // Condition blocks for the revealed rung
    std::vector<std::pair<uint16_t, Relay>>
        revealed_relays;                        // (relay_index, relay) for each revealed relay
    std::vector<uint256> proof_hashes;          // Leaf hashes for unrevealed leaves (in leaf-order)
    std::vector<std::pair<uint16_t, Rung>>
        revealed_mutation_targets;              // (rung_index, rung) for cross-rung mutation (optional)
};
```

### Wire Format (serialized in `SerializeMLSCProof`)

```
total_rungs         (CompactSize)
total_relays        (CompactSize)
rung_index          (CompactSize)
--- revealed rung (via SerializeRungBlocks in CONDITIONS context) ---
n_revealed_relays   (CompactSize)
for each revealed relay:
    relay_index     (CompactSize)
    --- relay blocks (via SerializeRelayBlocks in CONDITIONS context) ---
n_proof_hashes      (CompactSize)
for each proof_hash:
    hash            (32 bytes)
--- optional trailing field (backward-compatible) ---
n_mutation_targets  (CompactSize)
for each mutation target:
    rung_index      (CompactSize)
    --- rung blocks (via SerializeRungBlocks in CONDITIONS context) ---
```

**Source**: `conditions.cpp:337-558`.

### Proof Hash Count

The number of proof hashes must equal the number of unrevealed leaves:

```
max_proofs = (total_rungs - 1) + (total_relays - n_revealed_relays)
```

The coil leaf is always revealed (from the witness), the spending rung is
always revealed, and each revealed relay displaces one proof hash.

**Source**: `conditions.cpp:449-455`.

---

## 6. Verified Leaves: `MLSCVerifiedLeaves`

After successful proof verification, an optional output struct captures the
full leaf array for use by covenant evaluators:

```cpp
struct MLSCVerifiedLeaves {                     // conditions.h:153-159
    std::vector<uint256> leaves;                // Full leaf array (rungs + relays + coil)
    uint256 root;                               // Verified conditions root
    uint16_t rung_index;                        // Which leaf is the revealed rung
    uint16_t total_rungs;                       // Number of rung leaves
    uint16_t total_relays;                      // Number of relay leaves
};
```

Covenant evaluators (RECURSE\_\*, CTV, VAULT\_LOCK) use this to compute
expected output roots by copying the leaf array, mutating the relevant leaf,
rebuilding the tree, and comparing against the output root.

---

## 7. Proof Verification: `VerifyMLSCProof`

### Signature

```cpp
bool VerifyMLSCProof(
    const MLSCProof& proof,
    const RungCoil& coil,
    const uint256& expected_root,
    const std::vector<std::vector<uint8_t>>& rung_pubkeys,
    const std::vector<std::vector<std::vector<uint8_t>>>& relay_pubkeys,
    std::string& error,
    MLSCVerifiedLeaves* verified_out = nullptr,
    const std::vector<std::vector<std::vector<uint8_t>>>& mutation_target_pubkeys = {});
```

### Algorithm

1. **Allocate leaf array**: size = `total_rungs + total_relays + 1`.

2. **Compute revealed rung leaf**: `leaves[rung_index] = ComputeRungLeaf(revealed_rung, rung_pubkeys)`.

3. **Compute revealed relay leaves**: For each `(relay_idx, relay)` in
   `revealed_relays`, set `leaves[total_rungs + relay_idx] = ComputeRelayLeaf(relay, relay_pubkeys[i])`.

4. **Compute coil leaf**: `leaves[total_leaves - 1] = ComputeCoilLeaf(coil)`.
   The coil is always the last leaf.

5. **Fill unrevealed leaves**: Walk the leaf array in order; for each
   unrevealed slot, assign the next proof hash from `proof_hashes`.
   If too few or too many proof hashes are provided, verification fails.

6. **Verify mutation targets**: For each revealed mutation target
   `(target_idx, target_rung)`, compute its leaf hash and verify it matches
   `leaves[target_idx]`. The target index must differ from `rung_index`.
   This enables cross-rung covenant checks without revealing the full rung.

7. **Populate `verified_out`** (if non-null): copy the leaf array before
   the tree build consumes it.

8. **Build Merkle tree**: `computed_root = BuildMerkleTree(leaves)`.

9. **Compare**: `computed_root == expected_root`. Fail if mismatch.

**Source**: `conditions.cpp:560-655`.

---

## 8. Verification Flow: `VerifyRungTx`

The complete MLSC verification path in `VerifyRungTx` (`evaluator.cpp:3309+`):

### Step 1: Validate Outputs

All transaction outputs must use valid TX_MLSC format (`0xDF`). Non-Ladder
outputs (OP\_RETURN, P2TR, P2WPKH, inline `0xC1`, legacy per-output) are rejected
in v4 transactions. At most one DATA\_RETURN output is allowed (must have zero
value). A creation proof in the witness is validated at block acceptance.

### Step 2: Enforce Witness Stack Size

```cpp
if (witness.stack.size() != 2)  // evaluator.cpp:3337
    return false;
```

Exactly 2 elements: `stack[0]` = LadderWitness, `stack[1]` = MLSCProof.
This prevents data stuffing via extra witness elements.

### Step 3: Deserialize LadderWitness

```cpp
DeserializeLadderWitness(witness.stack[0], witness_ladder, deser_error);
```

If the witness uses diff mode (`n_rungs == 0`), resolve via
`ResolveWitnessReference()`.

### Step 4: Reject Non-MLSC Outputs

```cpp
if (!IsMLSCScript(spent_output.scriptPubKey))
    return false;
```

### Step 5: Extract Conditions Root

```cpp
GetMLSCRoot(spent_output.scriptPubKey, conditions_root);
```

### Step 6: Deserialize MLSC Proof

```cpp
DeserializeMLSCProof(witness.stack[1], mlsc_proof, proof_error);
```

### Step 7: Single Rung Rule

```cpp
if (witness_ladder.rungs.size() != 1)
    return false;
```

The witness must contain exactly 1 rung (the one being spent).

### Step 8: Extract Pubkeys (merkle\_pub\_key)

```cpp
rung_pks = ExtractBlockPubkeys(witness_ladder.rungs[0].blocks);
```

For each revealed relay, extract pubkeys from the corresponding witness relay.

### Step 9: Verify MLSC Proof

```cpp
VerifyMLSCProof(mlsc_proof, witness_ladder.coil, conditions_root,
                rung_pks, relay_pks, verify_error,
                &verified_leaves_data, mutation_target_pks);
```

### Step 10: Build RungConditions

```cpp
conditions.rungs.push_back(mlsc_proof.revealed_rung);
conditions.coil = witness_ladder.coil;
conditions.conditions_root = conditions_root;
conditions.relays.resize(mlsc_proof.total_relays);
// Fill revealed relays at their indices
```

### Step 11: Merge Conditions and Witness

```cpp
MergeConditionsAndWitness(conditions, witness_ladder, eval_ladder, merge_error);
```

For each rung/block pair, condition fields (HASH256, HASH160, NUMERIC,
SCHEME, SPEND\_INDEX) come from the proof, and witness fields (PUBKEY,
SIGNATURE, PREIMAGE) come from the witness. Merged result goes to the
evaluator. The `inverted` flag is taken from conditions, not witness.

### Step 12: Evaluate Ladder

```cpp
EvalLadder(eval_ladder, ladder_checker, SigVersion::LADDER, execdata, eval_ctx);
```

The first satisfied rung wins (OR logic across rungs, AND logic across blocks
within a rung).

---

## 9. Coil Leaf

The coil leaf commits the output's metadata. `SerializeCoilData()` serializes:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `coil_type` | `RungCoilType` | 1 byte | `UNLOCK` (0x01), `UNLOCK_TO` (0x02) |
| `attestation` | `RungAttestationMode` | 1 byte | Attestation mode |
| `scheme` | `RungScheme` | 1 byte | Signature scheme (e.g., `SCHNORR`) |
| `address_hash` | bytes | 0 or 32 bytes | `SHA256(destination_address)` — raw address never on-chain |
| `conditions` | rungs | variable | Reserved, must be empty (`MAX_COIL_CONDITION_RUNGS = 0`) |
| `rung_destinations` | pairs | variable | Per-rung destination overrides |

### `rung_destinations`

Per-rung destination address overrides. Each entry is a pair:

```
(rung_index: uint16 LE, address_hash: 32 bytes)
```

This allows different rungs within the same MLSC tree to route funds to
different destinations. Bounded by `MAX_RUNGS`. Duplicate `rung_index`
values are rejected at deserialization.

Wire format within `SerializeCoilData`:

```
n_rung_destinations (CompactSize)
for each:
    rung_index      (uint16 LE, 2 bytes)
    addr_hash       (32 bytes)
```

**Source**: `serialize.cpp:910-916`, `types.h:557`.

---

## 10. DATA\_RETURN in MLSC Outputs

DATA\_RETURN payloads are encoded directly in the shared conditions section,
appended after the 32-byte conditions root:

```
0xDF || root (32 bytes) || data (1-40 bytes)
```

Consensus rules (`ValidateRungOutputs` in `evaluator.cpp`):

- DATA\_RETURN outputs **must have zero value** (unspendable).
- At most **1 DATA\_RETURN output per transaction**.
- Maximum payload: **40 bytes** (enforced by `IsMLSCScript` accepting
  `size <= 73`, i.e., 1 + 32 + 40).

Note: `CreateMLSCScript` accepts up to 80 bytes of data, but
`IsMLSCScript` rejects anything over 73 bytes total, effectively capping
the payload at 40 bytes at consensus level.

**Source**: `conditions.cpp:176-207`, `evaluator.cpp:3264-3287`.

---

## 11. Security Properties

### O(1) Output Size

Every TX_MLSC output is exactly 8 bytes (value only) regardless of the number
of spending paths, blocks, or fields. The shared conditions_root is stored once
per transaction. This is a constant-size commitment that does not leak the
complexity of the spending conditions. Anti-spam surface: 112 bytes per
transaction (flat, no contiguous block). Zero readable attacker data in UTXOs
(root is protocol-derived).

### Hidden Spending Paths

Only the exercised rung and its required relays are revealed at spend time.
All other rungs remain hidden behind opaque proof hashes. An observer cannot
determine how many alternative spending paths exist or what conditions they
require (beyond the `total_rungs` and `total_relays` counts in the proof).

### merkle\_pub\_key Anti-Spam

By folding pubkeys into the Merkle leaf hash rather than storing them in
condition fields:

- **PUBKEY\_COMMIT is eliminated** from conditions entirely. There is no
  field type in conditions that can carry arbitrary 33-byte blobs.
- **Data embedding via pubkey fields is impossible** because pubkeys are
  never serialized into condition blocks — they exist only in the witness
  at spend time and are bound to the leaf hash.
- The allowed condition data types (`HASH256`, `HASH160`, `NUMERIC`,
  `SCHEME`, `SPEND_INDEX`, `DATA`) are all validated for semantic
  correctness and bounded in size.

### Sorted Interior Nodes

Interior Merkle nodes sort children lexicographically before hashing
(`min(a,b) || max(a,b)`). This makes the tree canonical — there is only one
valid tree for any set of leaves, preventing proof ambiguity.

### Domain Separation

Tagged hashes (`"LadderLeaf"` and `"LadderInternal"`) prevent cross-domain
collisions. A leaf hash can never be confused with an internal node hash.

### Strict Field Enforcement

Blocks with implicit layouts have their field count and types enforced at
deserialization. Blocks without implicit layouts reject data-embedding types
(`IsDataEmbeddingType`). `PREIMAGE` and `SCRIPT_BODY` fields are capped at
`MAX_PREIMAGE_FIELDS_PER_WITNESS = 2` per input (fast reject) and
`MAX_PREIMAGE_FIELDS_PER_TX = 2` across all inputs in the transaction
(binding constraint). This prevents multi-input data embedding.

---

## 12. Constants

| Constant | Value | Location | Description |
|----------|-------|----------|-------------|
| `RUNG_MLSC_PREFIX` | `0xDF` | `conditions.h` | TX_MLSC prefix byte |
| `RUNG_CONDITIONS_PREFIX` | `0xC1` | `conditions.h:21` | Removed inline prefix (always rejected) |
| `MAX_RUNGS` | 16 | `serialize.h:23` | Maximum rungs per ladder |
| `MAX_BLOCKS_PER_RUNG` | 8 | `serialize.h:25` | Maximum blocks per rung |
| `MAX_FIELDS_PER_BLOCK` | 16 | `serialize.h:27` | Maximum fields per block |
| `MAX_RELAYS` | 8 | `serialize.h:44` | Maximum relays per ladder |
| `MAX_REQUIRES` | 8 | `serialize.h:46` | Maximum relay refs per rung or relay |
| `MAX_RELAY_DEPTH` | 4 | `serialize.h:48` | Maximum transitive relay chain depth |
| `MAX_LADDER_WITNESS_SIZE` | 100,000 | `serialize.h:29` | Maximum witness size in bytes |
| `MAX_PREIMAGE_FIELDS_PER_WITNESS` | 2 | `serialize.h:35` | Per-input PREIMAGE + SCRIPT\_BODY fast reject |
| `MAX_PREIMAGE_FIELDS_PER_TX` | 2 | `serialize.h:39` | Per-transaction PREIMAGE + SCRIPT\_BODY cap |
| `MAX_COIL_CONDITION_RUNGS` | 0 | `serialize.h:42` | Coil conditions reserved (never evaluated) |
| `COIL_ADDRESS_HASH_SIZE` | 32 | `serialize.h:38` | SHA256(address) fixed size |

---

## 13. Template References

Conditions can inherit from another input via `TemplateReference`:

```cpp
struct TemplateReference {                      // conditions.h:42-45
    uint32_t input_index;
    std::vector<TemplateDiff> diffs;
};

struct TemplateDiff {                           // conditions.h:34-39
    uint16_t rung_index;
    uint16_t block_index;
    uint16_t field_index;
    RungField new_field;                        // Must match original field type
};
```

Resolution via `ResolveTemplateReference()` copies rungs, coil, and relays
from the source input, applies field-level diffs (type must match), and
clears the template reference. Chaining is forbidden: the source must not
itself be a template reference.

**Source**: `conditions.cpp:59-126`.

---

## 14. Witness References (Diff Witness)

Witnesses can also inherit from another input via `WitnessReference`:

```cpp
struct WitnessReference {                       // types.h:656-659
    uint32_t input_index;
    std::vector<WitnessDiff> diffs;
};
```

On the wire, `n_rungs == 0` signals diff mode. Only diffs and a fresh coil
are serialized. Rungs and relays are inherited from the referenced input's
resolved witness. The coil is always fresh (never inherited — inheriting
destination addresses would be dangerous).

**Source**: `serialize.cpp:381-523`, `types.h:653-677`.
