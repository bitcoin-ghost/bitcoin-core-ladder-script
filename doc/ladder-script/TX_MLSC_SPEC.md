# TX_MLSC — Transaction-Level Merkelised Ladder Script Conditions

**Status:** Draft v0.2 · March 2026

---

## Overview

TX_MLSC moves the MLSC root from per-output scriptPubKeys to a single
per-transaction commitment. Each output is just a value (8 bytes). A
creation proof in the witness validates that the root was derived from
real, typed conditions. Each rung's coil declares which output it governs
— the output-to-rung binding is cryptographic (committed in the Merkle
tree), not a stored bitmask.

This is the PLC model applied to Bitcoin outputs: one ladder program per
transaction, multiple output coils. The architecture that Ladder Script
was originally designed around.

---

## Design

### Transaction format (v4 RUNG_TX with TX_MLSC)

```
nVersion:        int32 (= 4)
vin_count:       varint
vin[]:           prevout(36) + scriptSig_len(1) + nSequence(4) per input
vout_count:      varint
conditions_root: 32 bytes                          ← ONE root for entire tx
vout[]:          nValue(8) per output               ← just values, nothing else
nLockTime:       uint32
witness[]:       per-input spending witness
creation_proof:  structural templates + value commitments (once per tx)
```

### Output format

```
nValue:    int64    (8 bytes, little-endian satoshi amount)
```

8 bytes per output. No scriptPubKey. No MLSC root. No rung_mask.

Consensus: nValue >= MIN_RUNG_OUTPUT_VALUE (546 sats) for non-DATA_RETURN.

### DATA_RETURN outputs

DATA_RETURN is identified by nValue == 0 (only DATA_RETURN outputs may
have zero value):

```
nValue:      int64    (must be 0)
payload_len: varint   (0-40 bytes)
payload:     bytes
```

Maximum 1 DATA_RETURN output per transaction.

### conditions_root

A 32-byte Merkle root computed from all rung leaves in the shared tree.
Protocol-derived — not user-supplied. Computed during block validation
from the creation proof data and verified against the value in the
transaction body.

---

## Shared Condition Tree (PLC Model)

All rungs for all outputs live in ONE Merkle tree per transaction. Each
rung's coil carries an output_index field declaring which output it
governs. This binding is committed in the Merkle leaf — changing the
output_index would change the leaf hash, breaking the proof.

```
Example: 2 outputs, each with a primary and backup rung

         conditions_root
        /               \
    branch_01         branch_23
    /       \         /       \
rung_0   rung_1   rung_2   rung_3

rung_0 coil: output_index=0   (SIG Alice → output 0)
rung_1 coil: output_index=0   (MULTISIG backup → output 0)
rung_2 coil: output_index=1   (SIG Bob → output 1)
rung_3 coil: output_index=1   (SIG Carol + CSV → output 1)
```

No rung limit per transaction. The tree can hold any number of rungs.
The number of rungs is bounded only by MAX_LADDER_WITNESS_SIZE for the
creation proof and standard transaction weight limits.

### Leaf computation

```
rung_leaf = TaggedHash("LadderLeaf", structural_template || value_commitment)
```

Where:
- structural_template: block types, inverted flags, coil (incl output_index)
- value_commitment: SHA256(field_values || pubkeys) — 32 bytes, opaque

### Tree construction

Sorted interior nodes (same algorithm as current MLSC):

```
interior_node = TaggedHash("LadderBranch", min(left, right) || max(left, right))
```

### Output-to-rung binding

The binding between outputs and rungs is entirely within the Merkle tree:

1. Each rung's coil contains `output_index` (which output this rung governs).
2. The coil is part of the structural_template, which is part of the leaf hash.
3. The leaf hash is committed by conditions_root.
4. At spend time, the verifier reads the revealed rung's coil and checks
   `output_index` matches the output being spent.

No per-output rung_mask needed. The binding is cryptographic.

An attacker cannot claim a rung for the wrong output — changing the
output_index would change the leaf hash, which would invalidate the
Merkle proof against conditions_root.

---

## Creation Proof

The creation proof is a witness section that enables block-level validation
of the conditions_root. It appears once per transaction after all input
witness stacks.

### Format

```
n_rungs:    varint (total rungs in the shared tree)
per rung:
  structural_template:
    n_blocks:   varint
    per block:
      block_type:  uint16  (must be known — one of 61 types)
      inverted:    uint8   (0x00 or 0x01, validated per block type)
    coil:
      coil_type:     uint8 (UNLOCK=0x01, UNLOCK_TO=0x02)
      attestation:   uint8 (INLINE=0x01; AGGREGATE/DEFERRED reserved)
      scheme:        uint8
      output_index:  uint8 (which output this rung governs — must be < vout_count)
      has_address:   uint8 (0 or 1)
  value_commitment:  32 bytes (SHA256 of field values + pubkeys for this rung)
```

Typical size per rung: ~42 bytes (10 template + 32 commitment).
Witness weight: 1 WU per byte.

### Validation (block acceptance)

For each v4 transaction with outputs:

1. If creation proof is missing: **reject transaction**.
2. For each rung in the creation proof:
   a. Validate structural template:
      - block_type must be in the known set (IsKnownBlockType)
      - inverted flag must be valid for this type (IsInvertibleBlockType)
      - coil_type must be known (IsKnownCoilType)
      - attestation must be known (IsKnownAttestationMode)
      - output_index must be < vout_count
   b. Accept value_commitment as-is (opaque 32-byte hash)
3. Compute rung_leaf for each rung:
   `TaggedHash("LadderLeaf", template || value_commitment)`
4. Build Merkle tree from all rung_leaves using sorted interior nodes.
5. Verify computed root == conditions_root in the transaction body.
6. Verify every non-DATA_RETURN output has at least one rung assigned to it
   (at least one rung has coil.output_index pointing to it).
7. If any check fails: **reject transaction**.

---

## UTXO Set

### Entry format

```
conditions_root:  32 bytes  (shared across all outputs from same tx)
nValue:            8 bytes  (per output)
```

The conditions_root is stored once per transaction group. Individual
entries reference the shared root plus their value.

Effective per entry: 8 bytes + shared root reference.

### Comparison

| | Current per-output MLSC | TX_MLSC |
|---|---|---|
| UTXO per entry | mlsc_root(32) + value(8) = 40 bytes | value(8) + shared_root_ref |
| Attacker data per entry | 32 bytes (unverifiable root) | 0 bytes (protocol-derived root) |

---

## Spending

When spending output i from a TX_MLSC transaction:

### Witness stack

```
stack[0]: LadderWitness    (rung blocks + fields — signatures, pubkeys, preimages)
stack[1]: MLSCProof        (revealed rung conditions + Merkle proof in shared tree)
```

Same two-element stack as current. No change to witness structure.

### MLSCProof contents

```
rung_index:       varint (which rung in the shared tree)
revealed_rung:    full conditions data (block types, field values, coil)
n_proof_hashes:   varint
proof_hashes[]:   32 bytes each (siblings for Merkle path to conditions_root)
```

The proof_hashes prove the revealed rung is a leaf of conditions_root.
Depth = ceil(log2(total_rungs)).

### Verification (VerifyRungTx)

1. Read conditions_root from UTXO set (shared root for this tx group).
2. Deserialize MLSCProof: extract rung_index, revealed rung, proof_hashes.
3. Read the revealed rung's coil: check `output_index` == the output
   being spent. If mismatch: **reject**.
4. Compute rung_leaf from revealed conditions + witness pubkeys
   (same TaggedHash as creation proof leaf computation).
5. Walk proof_hashes to compute root. Verify == conditions_root.
6. Merge conditions with witness (same as current).
7. Evaluate rung blocks (same as current — all 61 block types unchanged).
8. If satisfied: spend authorized.

### Proof path reconstruction

The spender needs proof_hashes (sibling nodes in the shared tree). To
obtain them:

1. Look up the creating transaction from the block database (by txid from
   the spending input's prevout).
2. Read the creation proof from the creating tx's witness section.
3. Extract all structural_templates and value_commitments.
4. Recompute all rung_leaves.
5. Build the Merkle tree.
6. Extract the proof path for the target rung.

This requires one block database read per spend. On modern hardware
(NVMe SSD): ~0.1ms latency. Negligible.

---

## Size and Fee Analysis

### Transaction sizes

Simple payment (1 input, 2 outputs, 1 rung per output):

```
Base:    version(4) + marker(2) + vin_count(1) + input(41)
       + vout_count(1) + conditions_root(32) + 2×output(8) + locktime(4)
       = 101 bytes × 4 WU = 404 WU

Witness: LadderWitness(112) + MLSCProof(43) + overhead(4)
       + creation_proof(2 × 42 = 84)
       = 243 bytes × 1 WU = 243 WU

Total: 647 WU = 162 vB
Fee (10 sat/vB): 1,620 sats
```

Note: post-quantum signatures (FALCON-512, Dilithium3, etc.) are supported
via the SCHEME byte but produce larger witnesses due to larger signature and
key sizes. PQ migration is a security upgrade, not a fee reduction.

### Full comparison — simple payment (1 in, 2 out)

| Format | Signature | Weight | vBytes | Fee |
|--------|-----------|--------|--------|-----|
| P2PKH | ECDSA | 904 | 226 | 2,260 sats |
| P2SH 2-of-3 | ECDSA | 1,484 | 371 | 3,710 sats |
| P2WPKH | ECDSA | 568 | 142 | 1,420 sats |
| P2WSH 2-of-3 | ECDSA | 811 | 203 | 2,030 sats |
| P2TR key-path | Schnorr | 621 | 155 | 1,553 sats |
| P2TR script 2-of-3 | Schnorr | 854 | 214 | 2,135 sats |
| **TX_MLSC** | **Schnorr** | **647** | **162** | **1,620 sats** |

### Batch payment comparison (1 in, N out, 1 rung per out)

| Outputs | P2PKH | P2WPKH | P2TR | **TX_MLSC** |
|---------|-------|--------|------|-------------|
| 2 | 904 | 568 | 621 | **647** |
| 10 | 1,992 | 1,560 | 1,997 | **1,279** |
| 100 | 14,792 | 13,108 | 17,497 | **7,867** |

TX_MLSC is the cheapest format for 3+ outputs. For 100 outputs:
40% cheaper than P2WPKH, 55% cheaper than P2TR.

### Consolidation (5 in, 1 out)

| Format | Weight | vBytes | Fee |
|--------|--------|--------|-----|
| P2PKH | 3,136 | 784 | 7,840 sats |
| P2WPKH | 1,532 | 383 | 3,830 sats |
| P2TR key-path | 1,365 | 341 | 3,413 sats |
| **TX_MLSC** | **1,857** | **464** | **4,640 sats** |

TX_MLSC is more expensive for consolidation due to extra proof hashes
per input (~32 bytes each). Overhead: ~50 sats vs current Ladder.
Still cheaper than P2PKH.

---

## Security Analysis

### Attack 1: Embed readable data in conditions_root

**Method:** Put a chosen 32-byte message as conditions_root.

**Defense:** conditions_root is protocol-derived. The node recomputes it
from validated templates + value_commitments and checks it matches.
Attacker cannot supply an arbitrary root.

Root = MerkleRoot(TaggedHash(template_i || SHA256(values_i || pubkeys_i))).
To embed a specific message requires a preimage attack on nested SHA256.
**Infeasible (2^256 work).**

### Attack 2: Embed readable data in value_commitments

**Method:** Control value_commitment bytes in the creation proof witness.

**Defense:** value_commitment = SHA256(field_values || pubkeys). Hash
output. To embed a specific 32-byte message requires a preimage attack.
**Infeasible (2^256 work).**

### Attack 3: Embed readable data in structural templates

**Method:** Encode data in block_type choices and flags.

**Defense:** Validated enums. block_type must be one of 61 values (~6 bits
freedom), inverted must be 0/1 (1 bit), coil fields are constrained enums.
~4 bits of steganographic freedom per rung. For 100 rungs: ~50 bytes, not
readable without attacker's codebook. **Negligible.**

### Attack 4: Skip creation proof

**Defense:** Consensus rejects. **Blocked.**

### Attack 5: Mismatched creation proof

**Defense:** Root recomputed and compared. Mismatch = reject. **Blocked.**

### Attack 6: Valid but unspendable outputs

**Method:** Valid templates with random pubkey in value_commitment.

**Defense:** Economically constrained:
- 546 sats burned per output (consensus dust)
- 0 readable bytes (root and commitments are hash outputs)
- Same as Taproot output to random key

**Residual risk:** UTXO bloat from unspendable outputs. Defense is economic.

### Attack 7: Forge creation proof (collision)

**Defense:** Requires SHA256 collision (2^128 work). **Infeasible.**

### Attack 8: Spend wrong output (rung mismatch)

**Method:** Reveal a rung whose coil says output_index = 0 while spending
output 1.

**Defense:** Verifier reads coil.output_index from the revealed rung and
checks it matches the output being spent. The coil is committed in the
leaf hash → committed in conditions_root. Cannot be forged. **Blocked.**

### Attack 9: Output with no assigned rungs

**Method:** Create an output that no rung's coil points to. Output is
unspendable (no rung can authorize it).

**Defense:** Creation proof validation (step 6) requires every
non-DATA_RETURN output to have at least one rung assigned. **Blocked.**

### Attack 10: Multi-input preimage embedding

**Existing defense:** MAX_PREIMAGE_FIELDS_PER_TX = 2. **64 bytes/tx.**

### Attack 11: DATA_RETURN payload

**Existing defense:** Max 1 per tx, max 40 bytes, zero value. **Bounded.**

---

## Privacy Analysis

### What is visible at creation time

| Data | Visible | Content |
|------|---------|---------|
| Block types per rung | Yes | SIG, CSV, MULTISIG, CTV, etc. |
| Inverted flags | Yes | Which blocks are negated |
| Coil type and attestation | Yes | UNLOCK/UNLOCK_TO, INLINE only |
| Output assignments | Yes | Which rung governs which output |
| Rung count per output | Yes | Number of spending paths |
| Field values | **No** | Hidden in value_commitment |
| Pubkeys / key identities | **No** | Hidden in value_commitment |
| Hash commitments | **No** | Hidden in value_commitment |
| Timelock values | **No** | Hidden in value_commitment |

### What is visible at spend time

Only the exercised rung's full conditions (block types, field values) and
pubkeys. All other rungs remain hidden behind their value_commitments.

### Privacy position

Structure visible, identity hidden. Comparable to Taproot script-path
spend (which reveals the script structure). The sensitive data — who
controls the funds — remains private until spend time.

---

## Impact on Existing Systems

### Block types and evaluator

**No change.** All 61 block types, evaluation semantics, rung AND/OR logic,
coil processing, inversion — all identical. The evaluator receives merged
conditions + witness and evaluates exactly as today.

### Descriptor notation

**Extended.** Descriptors describe the transaction's condition set with
output assignments:

```
ladder(
  output(0,
    or(
      and(sig(@alice), csv(144)),
      multisig(2, @a, @b, @c)
    )
  ),
  output(1,
    sig(@bob)
  )
)
```

### RPC commands

- **signrungtx / signladder:** Generate creation proof alongside tx.
  The node already has templates and values — just new serialization.
- **createrungtx:** New output format (value only, no scriptPubKey).
- **decoderungtx:** Display shared tree, creation proof, rung assignments.

### MLSC Merkle tree (conditions.cpp)

**Same algorithm.** Sorted interior nodes, TaggedHash. Leaf data changes
from (full_rung_data || pubkeys) to (template || value_commitment).
Tree construction code is identical.

### Sighash computation

**Minor change.** Sighash includes Hash(conditions_root || output_values)
instead of Hash(output_scriptPubKeys).

### Witness reference / diff witness

**Works.** Multiple inputs from the same creating tx share conditions_root.
Witness references are more natural with the shared tree.

### Block validation performance

Per tx: R template validations (table lookups) + R SHA256 (leaf hashes) +
(R-1) SHA256 (tree construction) + 1 comparison.

2-rung tx: ~4 SHA256 ops. 100-rung tx: ~200 SHA256 ops. Negligible.

### Pruning

Creation proof is witness data — prunable after validation. Spenders
reconstruct proof paths from the creating tx (block database read).

### Light clients / SPV

No effect. Light clients trust full nodes validated creation proofs,
same as signatures.

### Backward compatibility

Pre-activation v4 MLSC outputs use per-output roots. Post-activation
uses TX_MLSC. Spending pre-activation outputs: unchanged (prove against
per-output root in UTXO set). Standard soft fork activation boundary.

---

## Residual Embeddable Surface

### At creation time

| Channel | Bytes | Readable? |
|---------|-------|-----------|
| conditions_root | 32 | No — protocol-derived, triple-hashed |
| value_commitments (witness) | 32/rung | No — SHA256 output |
| structural templates (witness) | ~10/rung | No — validated enums |
| output values | 8/output | No — constrained by dust (546 sats) |
| DATA_RETURN | 40 max | Yes — intentional, bounded |
| nLockTime | 4 | Yes — standard Bitcoin field |
| nSequence per input | 4/input | Yes — standard Bitcoin field |

**Readable attacker data at creation: 48 bytes per transaction (flat).**

### At spend time

| Channel | Bytes | Readable? |
|---------|-------|-----------|
| PREIMAGE fields | 64/tx max | Yes — hash-bound |
| Conditions HASH256 | ~32/block | Yes — revealed in MLSC proof |
| Nonce grinding | ~3/sig | Yes — unfixable |

### Comparison with all formats

| Format | Creation readable | Witness readable | UTXO spam |
|--------|-------------------|------------------|-----------|
| P2TR (Taproot) | 34 bytes/output | ~400,000 bytes/input | 34 bytes/output (unverifiable) |
| Per-output MLSC (current) | 32 bytes/output | ~117 bytes/tx | 32 bytes/output (unverifiable) |
| **TX_MLSC** | **48 bytes/tx (flat)** | **~117 bytes/tx** | **0 readable bytes** |

---

## Implementation Checklist

### Core (serialize.h / serialize.cpp / conditions.cpp / evaluator.cpp)

- [ ] Transaction serialization: conditions_root field, 8-byte output format
- [ ] DATA_RETURN detection via nValue == 0 (no rung_mask sentinel needed)
- [ ] CreationProof struct and deserialization
- [ ] ValidateCreationProof: template checks + root recomputation
- [ ] Verify every output has at least one rung (coil.output_index coverage)
- [ ] UTXO set: shared conditions_root + per-entry value
- [ ] VerifyRungTx: check coil.output_index matches spent output
- [ ] Leaf computation: TaggedHash("LadderLeaf", template || value_commitment)
- [ ] Sighash: Hash(conditions_root || output_values)

### RPC (rpc.cpp)

- [ ] signrungtx: generate creation proof from conditions
- [ ] signladder: generate creation proof from descriptor
- [ ] createrungtx: new output format (value only)
- [ ] decoderungtx: display shared tree + creation proof + output assignments

### Descriptor (descriptor.cpp / descriptor.h)

- [ ] output() wrapper in descriptor grammar
- [ ] parseladder: per-output rung assignment
- [ ] formatladder: emit output() wrappers

### Tests

- [ ] Creation proof: valid accepted
- [ ] Creation proof: missing rejected
- [ ] Creation proof: root mismatch rejected
- [ ] Creation proof: invalid block type rejected
- [ ] Creation proof: invalid inversion rejected
- [ ] Creation proof: output_index out of range rejected
- [ ] Creation proof: output with no rungs rejected
- [ ] Spend: coil output_index mismatch rejected
- [ ] Spend: valid Merkle proof accepted
- [ ] Spend: invalid Merkle proof rejected
- [ ] Spend from 1-output TX_MLSC (degenerate tree, 0 proof hashes)
- [ ] Spend from 10-output TX_MLSC (deep tree)
- [ ] Attestation mode enforcement (INLINE only, AGGREGATE/DEFERRED reserved)
- [ ] Backward compat: spend pre-activation per-output MLSC
- [ ] DATA_RETURN handling (nValue == 0)
- [ ] Dust threshold enforcement (nValue >= 546 for non-DATA_RETURN)
- [ ] MAX_PREIMAGE_FIELDS_PER_TX enforcement
- [ ] Spam: root not embeddable (protocol-derived)
- [ ] Spam: value_commitment not embeddable (hash output)
- [ ] Performance: validation overhead benchmark

---

## Open Questions

1. **Tree ordering.** Should rungs be ordered by output (all output 0 rungs
   first, then output 1) or by creation order? Output-grouped ordering
   means spending output 0 has shorter proofs (its rungs are adjacent in
   the tree). Creation order is simpler. Recommendation: output-grouped.

2. **Rung sharing.** Can two outputs share a rung? The coil has a single
   output_index. For shared spending paths (e.g., a MULTISIG backup that
   covers all outputs), each output needs its own copy of the rung with
   a different output_index. This is a minor duplication but keeps the
   model clean. Recommendation: no rung sharing, duplicate if needed.

3. **Maximum rungs per transaction.** No hard limit in this spec — bounded
   by creation proof witness size and tx weight. For a 400K WU standard
   tx: ~9,500 rungs maximum (each ~42 bytes at 1 WU). Practical limit
   is far lower. Consider a soft consensus limit (e.g., 256 rungs) for
   DoS protection.

4. **Activation.** Standard soft fork. Post-activation: v4 transactions
   must use TX_MLSC format. Pre-activation outputs remain spendable
   with the old per-output MLSC proof format.

---

*TX_MLSC Specification v0.2 · Ladder Script Project · March 2026*
