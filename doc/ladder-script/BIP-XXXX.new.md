```
BIP: XXXX
Layer: Consensus (soft fork)
Title: Ladder Script — Typed Spending Conditions and Merkelised Ladder Script Conditions (MLSC)
Author: Defenwycke <defenwycke@icloud.com>
Comments-Summary: No comments yet.
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXXX
Status: Draft
Type: Standards Track
Created: 2026-05-01
License: BSD-2-Clause
Requires: 141, 340, 341
```

## Abstract

This document specifies Ladder Script, a transaction format and
spending-condition language deployed as Bitcoin transaction version 4
(`RUNG_TX`). Ladder Script replaces stack-of-bytes Bitcoin Script with a
fixed registry of 65 typed spending blocks organised into rungs that
evaluate by AND-within-rung and OR-across-rungs. Every output in a v4
transaction is committed by a single transaction-level Merkle root —
Merkelised Ladder Script Conditions (MLSC) — encoded in 8 wire bytes
per output and 3 chainstate bytes per coin after the standard UTXO
compressor. The proposal includes one `SigVersion`, two sighash
variants for per-input signatures, a key-path tweak distinct from BIP
341, native post-quantum signature schemes (FALCON-512 and -1024,
Dilithium3, SPHINCS+), and an N-party batched-PQ extension (`QABIO`).
Activation deploys all 65 blocks together using BIP 9 version-bits
signalling; pre-activation nodes treat v4 as anyone-can-spend.

## Copyright

This BIP is licensed under the BSD-2-Clause license.

## Motivation

A Bitcoin transaction commits to a future spend through a script. Once
confirmed, that script's bytes sit unmoving in the chainstate of every
node on the network until the output is spent. Today the script is a
stack of opaque byte arrays. A 33-byte public key, a 32-byte hash, a
4-byte timelock, and a 32-byte image of an animated frog are
indistinguishable to the protocol — every byte's meaning lives in
unwritten convention between the wallet that wrote the script and the
wallet that will satisfy it. The protocol enforces no type, no shape,
no commitment beyond "execute these opcodes against this stack".

Three consequences fall out of that choice.

First, every new spending capability is its own multi-year coordination
problem. Adding a covenant primitive means defining an opcode, securing
review of its interaction with every other opcode in the wider script,
and persuading the network to activate a soft fork for one feature.
The cost of capability is so high that the network can only afford a
handful per decade.

Second, the protocol cannot tell instructions from data. A witness
that pushes 100 KB of arbitrary bytes onto the stack and uses
`OP_DROP` to discard them — or wraps them inside `OP_FALSE OP_IF
... OP_ENDIF` so they never execute — produces a transaction that
verifies and lands in a block. The bytes are paid for at the witness
discount rate and live on every full node forever. This is the
mechanism the Ordinals inscription pattern exploits inside Taproot
script-path spends, and the equivalent push-and-drop pattern exists in
P2WSH. The protocol has no way to refuse it because the bytes are
syntactically valid script, even though they have no semantic role.

Third, post-quantum signatures cannot be added by introducing new
schemes alone. Today's signature checks live inside opcodes
(`OP_CHECKSIG` and friends) that hard-code the signature shape. A
soft-fork that wants to accept FALCON-512 or Dilithium3 signatures
must either redefine those opcodes (consensus-changing in subtle
ways) or build parallel opcodes (a permanent maintenance tax). Neither
path lets a wallet make a per-output choice between classical Schnorr
and post-quantum schemes without coordination cost upstream.

Ladder Script addresses all three by replacing Bitcoin Script with a
registry of typed spending blocks. There are 65 blocks at activation,
covering signature checks (classical and post-quantum), timelocks,
hashlocks, covenants, recursive covenants, anchor markers, programmable
controllers (PLC-style latches, counters, hysteresis bands, rate
limiters), governance constraints, legacy script wrappers, and a
batched-PQ extension. Every block declares its field types and counts
at registration time. The deserialiser rejects any wire bytes that do
not match a known block layout. There is no field type that accepts
arbitrary unstructured bytes, no `OP_DROP` analogue, no `OP_IF false`
dead-code path. Adding a block type is a registry entry plus an
evaluator function — no opcode allocation, no script-execution
interaction analysis. Adding a post-quantum signature scheme is a
single `SCHEME` field byte on existing signature blocks.

The output format pushes the same typed discipline into the
transaction shape itself. A v4 transaction commits a single 32-byte
Merkle root over every output's spending conditions. Each output is 8
bytes on the wire (value only); the scriptPubKey is reconstructed at
deserialisation as `0xDF || conditions_root`. Only the rung exercised
at spend time is revealed, and the unrevealed rungs stay private behind
their leaf hashes — comparable to a Taproot script-path spend, but
applied uniformly across every output of the transaction rather than
per-output. After the standard UTXO compressor, an MLSC coin occupies
3 bytes in chainstate; the 32-byte root is recovered at spend time
from a synthetic UTXO entry.

The rest of this document specifies the wire format, the leaf hashing,
the witness shapes, the evaluator, and the activation path. The
Rationale answers, in numbered question form, the design decisions a
reviewer is most likely to challenge.

## Specification

### Definitions

The notation used throughout this document:

| Symbol | Meaning |
|---|---|
| `\|\|` | Byte concatenation. |
| `H(x)` | `SHA256(x)` — single SHA-256 over `x`. |
| `TaggedHash(tag, x)` | BIP 340 tagged hash: `SHA256(SHA256(tag) \|\| SHA256(tag) \|\| x)` where `tag` is interpreted as ASCII bytes. |
| `len(x)` | Byte length of `x`. |
| `LE(x, n)` | Unsigned integer `x` encoded little-endian in `n` bytes. |
| `CompactSize(x)` | Bitcoin's `CompactSize` integer encoding (BIP 144 / `serialize.h`); canonical-form is required at deserialisation. |
| `[]byte` | A variable-length byte string. |

All multi-byte integers in the wire format are little-endian unless
otherwise noted. `CompactSize` non-canonical encodings (e.g. encoding
the value 1 as `0xFD 0x01 0x00` rather than `0x01`) MUST be rejected at
deserialisation.

### Transaction format

A v4 RUNG_TX uses transaction version `4`. The version field is the
sole consensus marker — every check in this document fires for
`tx.version == 4` and for no other version.

There are two on-wire forms, matching the existing BIP 141 stripped /
witness pair.

#### Full form (witness-carrying)

Triggered by the deserialiser when `(allow_witness && version == 4)`.
The flag byte `0x02` distinguishes v4 from BIP 141 SegWit (`0x01`).
Combined `0x03` MUST be rejected.

```
int32  version                                = 4
uint8  dummy                                  = 0x00
uint8  flags                                  = 0x02
CompactSize(n_inputs)
for i in 0..n_inputs:
    OutPoint   prevout                          (36 bytes: 32 txid + 4 vout LE)
    CompactSize(scriptSig_len)
    bytes      scriptSig                        (typically empty for v4)
    uint32     nSequence                        (LE)
uint256 conditions_root                         (32 bytes — shared across all outputs)
CompactSize(n_outputs)
for j in 0..n_outputs:
    int64  nValue                               (LE, satoshis)
    if nValue == 0:                             (DATA_RETURN marker — see "Output reconstruction")
        CompactSize(data_len)                   (1..40)
        bytes  data                             (data_len bytes)
for i in 0..n_inputs:
    CompactSize(witness_count)                  (per-input witness stack)
    for k in 0..witness_count:
        CompactSize(elem_len)
        bytes  elem
CompactSize(qabi_block_len)
bytes   qabi_block                              (zero-length unless tx contains a QABI input)
CompactSize(aggregated_sig_len)
bytes   aggregated_sig                          (zero-length unless tx contains a QABI_SPEND input; otherwise exactly 666)
uint32  nLockTime                               (LE)
```

Source: `src/primitives/transaction.h` `UnserializeTransaction` /
`SerializeTransaction` in the reference implementation.

#### Stripped form (no witness, used for txid)

Triggered when `(!allow_witness && version == 4)`. There is no flag
byte.

```
int32  version                                = 4
CompactSize(n_inputs)
for i in 0..n_inputs:
    OutPoint   prevout                          (36 bytes)
    CompactSize(scriptSig_len)
    bytes      scriptSig
    uint32     nSequence                        (LE)
uint256 conditions_root                         (32 bytes)
CompactSize(n_outputs)
for j in 0..n_outputs:
    int64  nValue
    if nValue == 0:
        CompactSize(data_len)
        bytes  data
uint32  nLockTime                               (LE)
```

The txid of a v4 transaction is the SHA256d of its stripped form. The
wtxid is the SHA256d of its full form.

### Output reconstruction

On deserialisation, every output's scriptPubKey is synthesised from
the transaction-level `conditions_root` and any DATA_RETURN payload
attached to that output:

- Standard MLSC output (`nValue > 0`):
  `scriptPubKey = 0xDF || conditions_root`             (33 bytes)
- DATA_RETURN output (`nValue == 0`):
  `scriptPubKey = 0xDF || conditions_root || data`     (34..73 bytes)

Downstream code that holds a `CTxOut` after deserialisation sees a
populated 33–73 byte scriptPubKey, even though only 8 bytes
(plus optional `data_len + data`) reached the wire per output.

Consensus rules:

1. Every non-DATA_RETURN output MUST have `nValue >=
   MIN_RUNG_OUTPUT_VALUE = 546` satoshis. (This is the standard dust
   threshold; see `src/rung/serialize.h`.)
2. At most ONE DATA_RETURN output is permitted per transaction.
3. DATA_RETURN payloads are 1..40 bytes inclusive.
4. Every output MUST be MLSC. Raw `OP_RETURN` outputs and any other
   scriptPubKey shape are rejected on v4 transactions.

### Per-coin compressor

The standard Bitcoin UTXO compressor is extended with one new special
script type:

| Marker | Meaning |
|---|---|
| `0x06` | MLSC output. The stored payload is the 1-byte marker only. The 32-byte `conditions_root` is recovered at spend time from a separate synthetic UTXO entry. |

Each v4 transaction writes, in addition to its `n_outputs` regular
coins, ONE synthetic coin at `(txid, MLSC_ROOT_VOUT)` where
`MLSC_ROOT_VOUT = 0xFFFFFFFF`. The synthetic coin's scriptPubKey is
exactly:

```
0xDE || conditions_root            (33 bytes; marker byte 0xDE — see Rationale Q4)
```

Per-coin chainstate cost for an MLSC output is 3 bytes (1-byte SPK
marker + value varint + height/coinbase byte). Spending validates by
looking up the spent prevout AND looking up the creating transaction's
synthetic root entry to recover the 32-byte root.

### Conditions and the conditions root

A transaction's conditions are organised as a set of N rungs and M
relays. A rung is a list of typed condition blocks plus a coil; every
rung is anchored to a single output via its coil's `output_index`.
Relays are shared blocks that one or more rungs may reference, so two
or more rungs that share a common subexpression do not duplicate it on
the wire.

#### Leaf hashing

The conditions root is the Merkle root over a fixed leaf array:

```
leaves = [
    rung_leaf[0], rung_leaf[1], ..., rung_leaf[N-1],
    relay_leaf[0], relay_leaf[1], ..., relay_leaf[M-1],
]
```

The coil is folded into each rung leaf's structural template — there
is no separate coil leaf. Reference implementation:
`src/rung/conditions.cpp` `ComputeTxMLSCRoot`.

```
rung_leaf  = TaggedHash("LadderLeaf/v1",      structural_template_rung  || value_commitment)
relay_leaf = TaggedHash("LadderRelayLeaf/v1", structural_template_relay || value_commitment)
```

The two tags MUST be distinct so a relay leaf can never collide with a
rung leaf at an identical block layout.

#### Structural template — rung

```
uint8   n_blocks
for each block:
    uint16  block_type (LE)
    uint8   inverted        (0x00 or 0x01)
uint8   n_relay_refs
for each relay_ref:
    uint16  relay_index (LE)
uint8   coil_type           (UNLOCK = 0x01)
uint8   attestation         (INLINE = 0x01)
uint8   scheme              (RungScheme enum byte)
uint8   output_index        (which output this rung governs)
```

A single-block, no-relay rung's structural template is 9 bytes. The
relay refs are committed into the rung leaf so a spender cannot drop
relay dependencies at spend time.

#### Structural template — relay

```
uint8   n_blocks
for each block:
    uint16  block_type (LE)
    uint8   inverted
uint8   n_relay_refs
for each relay_ref:
    uint16  relay_index (LE)
```

Relays carry no coil.

#### Value commitment

```
value_commitment = SHA256(field_values || pubkeys)
```

`field_values` is the concatenation of every field's bytes from every
block in the rung (or relay), in declared order. `NUMERIC` fields are
normalised to 4-byte little-endian before hashing — this prevents
different `CompactSize` encodings of the same numeric value from
producing different commitments.

`pubkeys` is the concatenation of pubkeys folded out of key-consuming
blocks via `merkle_pub_key` (see "Block registry"). A spender that
provides the wrong pubkey at spend time fails leaf reconstruction and
the proof verification rejects.

#### Interior hashing — byte-sorted

```
interior_node = TaggedHash("LadderInternal/v1", min(left, right) || max(left, right))
```

Children are sorted lexicographically by their 32-byte hash before
concatenation. This makes the tree canonical: the same set of leaves
produces the same root regardless of which side of a parent each leaf
sits on.

#### Padding

Empty leaves use a fixed nothing-up-my-sleeve constant:

```
MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf/v1", "")
```

`BuildMerkleTree(leaves)`:

1. If `leaves` is empty, return `MLSC_EMPTY_LEAF`.
2. If `leaves` has exactly one element, return that element.
3. Pad `leaves` with `MLSC_EMPTY_LEAF` to the next power of two.
4. Pair adjacent leaves and compute the parent node via the byte-
   sorted interior rule. Repeat until one root remains.

### Witness format

Every script-path spend of an MLSC input carries a witness stack of 1,
2, or 3 elements. The element count discriminates the spend mode.

| Stack count | Mode |
|---|---|
| 1 | Key-path (single Schnorr signature against the conditions_root interpreted as an x-only public key). |
| 2 | Script-path, no tweak: `[LadderWitness, MLSCProof]`. |
| 3 | Script-path with internal-pubkey tweak: `[LadderWitness, MLSCProof, internal_pubkey (33 bytes)]`. |

Reference: `src/rung/evaluator.cpp` `VerifyRungTx` dispatch.

#### `LadderWitness`

```
CompactSize(n_rungs)
for each rung:
    CompactSize(n_blocks)
    for each block:
        block_header               (micro-header byte OR escape + uint16 LE block_type)
        block fields               (implicit layout OR explicit CompactSize(n_fields) + per-field type+data)
    CompactSize(n_relay_refs)
    for each relay_ref:
        uint16 relay_index (LE)
coil                                (4 bytes: type, attestation, scheme, output_index)
CompactSize(n_relays)
for each relay:
    CompactSize(n_blocks)
    for each block: block_header + fields
    CompactSize(n_relay_refs)
    for each relay_ref: uint16 (LE)
```

`n_rungs == 0` signals diff-witness mode: the rungs and relays are
inherited from another input's already-resolved witness, with optional
field-level overlays. See `src/rung/serialize.cpp` `DeserializeLadderWitness`.

#### `MLSCProof`

```
CompactSize(total_rungs)
CompactSize(total_relays)
CompactSize(rung_index)             (which rung is being revealed)
revealed_rung                       (block-by-block fields, conditions context)
CompactSize(n_revealed_relays)
for each revealed relay:
    CompactSize(relay_index)
    relay_blocks                    (conditions context)
CompactSize(n_proof_hashes)
for each: 32-byte sibling hash
CompactSize(n_mutation_targets)     (optional — used by recursive covenants)
for each mutation target:
    CompactSize(target_rung_index)
    target_rung_blocks              (conditions context)
```

The proof hashes are sibling values on the Merkle path from the
revealed leaf (and any revealed relays) up to `conditions_root`.

#### Witness limits

| Constant | Value | Source |
|---|---:|---|
| `MAX_RUNGS` | 16 | `src/rung/serialize.h` |
| `MAX_BLOCKS_PER_RUNG` | 8 | `src/rung/serialize.h` |
| `MAX_FIELDS_PER_BLOCK` | 16 | `src/rung/serialize.h` |
| `MAX_RELAYS` | 8 | `src/rung/serialize.h` |
| `MAX_REQUIRES` | 8 | `src/rung/serialize.h` |
| `MAX_RELAY_DEPTH` | 4 | `src/rung/serialize.h` |
| `MAX_LADDER_WITNESS_SIZE` | 100,000 bytes | `src/rung/serialize.h` |
| `MAX_PREIMAGE_FIELDS_PER_WITNESS` | 2 | `src/rung/serialize.h` |
| `MAX_PREIMAGE_FIELDS_PER_TX` | 2 | `src/rung/serialize.h` (counts across all MLSC-spending inputs and any diff-witness overlays) |
| `MAX_SCRIPT_BODY_FIELDS_PER_TX` | 1 | `src/rung/serialize.h` |
| `MAX_PUBKEYS_PER_MULTISIG` | 16 | `src/rung/serialize.h` |
| `MAX_ACCUMULATOR_BLOCKS_PER_TX` | 2 | `src/rung/serialize.h` |

### Block registry

65 block types are defined at activation, organised in 11 families.
Each block has a canonical 16-bit type code encoded little-endian on
the wire.

#### Witness rules (used by the column below)

The `WitnessRule` column on each row picks one of seven enforcement
rules, defined below. All rules are enforced at the wire-format
deserialiser before any cryptographic operation; the eval-time
checks listed are additional invariants the evaluator rejects on.

| Rule | Wire-format enforcement | Eval-time invariant |
|---|---|---|
| `Fixed N` | Implicit layout with N fields; positional types match the layout. | Eval consumes the fields. |
| `Empty` | Zero witness fields. | Eval reads only conditions-side fields. |
| `Reveal P` | Up to P `PUBKEY` fields (count = `PubkeyCountForBlock`, for `merkle_pub_key` leaf reconstruction) plus up to 2 `PREIMAGE` fields (for hash-binding against a `HASH256` in conditions). All other field types reject. | Eval rebuilds the leaf from PUBKEYs and verifies any PREIMAGE against the conditions HASH256. |
| `Triplets K` | K × `(PUBKEY, MERKLE_PROOF, SIGNATURE)` triplets in strict ascending pubkey-lex order; K is from the conditions `NUMERIC(K)` field. | Eval verifies each pubkey's Merkle proof against `pubkey_root` and each signature against the pubkey. |
| `Accumulator` | Exactly `[NUMERIC(element_id), MERKLE_PROOF]`. | Eval verifies the proof against `set_root`. |
| `Bridging` | Exactly one `PREIMAGE` (the inner script body, hash-bound to the conditions `HASH160`/`HASH256`) followed by stack-push fields whose count must match at least one inner rung's expected witness layout sum. | Eval evaluates the inner conditions tree against the stack-push fields. |
| `PQ-anchor` | Either `[HASH256]` (non-anchor; field merged with the conditions `HASH256` to form a 1-field merged block) or `[HASH256, PUBKEY, SIGNATURE]` (anchor; fields merged to form a 3-field merged block). Any other shape rejects. | Anchor input verifies `SHA256(PUBKEY) == HASH256` and the PQ signature; non-anchor input checks the tx-local cache. |
| `Unspendable` | Witness ignored — eval rejects every spend attempt. | The block is unspendable by design. |

#### Registry table

| Code | Family | Name | Conditions layout | WitnessRule | Witness layout |
|---|---|---|---|---|---|
| 0x0001 | Signature | `SIG` | `[SCHEME]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0002 | Signature | `MULTISIG` | `[NUMERIC(K), SCHEME, HASH256(pubkey_root)]` | `Triplets K` | K × `(PUBKEY, MERKLE_PROOF, SIGNATURE)` |
| 0x0003 | Signature | `ADAPTOR_SIG` | (none) | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0004 | Signature | `MUSIG_THRESHOLD` | `[NUMERIC(M), NUMERIC(N)]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0005 | Signature | `KEY_REF_SIG` | `[NUMERIC(relay_idx), NUMERIC(block_idx)]` | `Fixed 1` | `[SIGNATURE]` |
| 0x0101 | Timelock | `CSV` | `[NUMERIC(blocks)]` | `Empty` | — |
| 0x0102 | Timelock | `CSV_TIME` | `[NUMERIC(seconds)]` | `Empty` | — |
| 0x0103 | Timelock | `CLTV` | `[NUMERIC(height)]` | `Empty` | — |
| 0x0104 | Timelock | `CLTV_TIME` | `[NUMERIC(time)]` | `Empty` | — |
| 0x0203 | Hash | `TAGGED_HASH` | `[HASH256(tag), HASH256(expected)]` | `Fixed 1` | `[PREIMAGE]` |
| 0x0204 | Hash | `HASH_GUARDED` | `[HASH256]` | `Fixed 1` | `[PREIMAGE]` |
| 0x0301 | Covenant | `CTV` | `[HASH256(template)]` | `Empty` | — |
| 0x0302 | Covenant | `VAULT_LOCK` | `[NUMERIC(hot_delay)]` | `Fixed 3` | `[PUBKEY(recovery), PUBKEY(hot), SIGNATURE]` |
| 0x0303 | Covenant | `AMOUNT_LOCK` | `[NUMERIC(min), NUMERIC(max)]` | `Empty` | — |
| 0x0401 | Recursion | `RECURSE_SAME` | `[NUMERIC(max_depth)]` | `Empty` | — |
| 0x0402 | Recursion | `RECURSE_MODIFIED` | variable: NUMERICs encoding mutation specs | `Empty` | — |
| 0x0403 | Recursion | `RECURSE_UNTIL` | `[NUMERIC(until_height)]` | `Empty` | — |
| 0x0404 | Recursion | `RECURSE_COUNT` | `[NUMERIC(max_count)]` | `Empty` | — |
| 0x0405 | Recursion | `RECURSE_SPLIT` | `[NUMERIC(max_splits), NUMERIC(min_sats)]` | `Empty` | — |
| 0x0406 | Recursion | `RECURSE_DECAY` | variable: NUMERICs encoding decay deltas | `Empty` | — |
| 0x0501 | Anchor | `ANCHOR` | `[NUMERIC(anchor_id)]` | `Empty` | — |
| 0x0502 | Anchor | `ANCHOR_CHANNEL` | `[NUMERIC(commitment_number)]` | `Empty` | — |
| 0x0503 | Anchor | `ANCHOR_POOL` | `[HASH256(vtxo_root), NUMERIC(count)]` | `Reveal 0` | up to 1 `PREIMAGE` for hash-binding |
| 0x0504 | Anchor | `ANCHOR_RESERVE` | `[NUMERIC(n), NUMERIC(m), HASH256(guardian)]` | `Reveal 0` | up to 1 `PREIMAGE` for hash-binding |
| 0x0505 | Anchor | `ANCHOR_SEAL` | `[HASH256, HASH256]` | `Reveal 0` | up to 2 `PREIMAGE` for hash-binding |
| 0x0506 | Anchor | `ANCHOR_ORACLE` | `[NUMERIC(outcome_count)]` | `Fixed 1` | `[PUBKEY(oracle)]` |
| 0x0507 | Anchor | `DATA_RETURN` | `[DATA(1..40)]` | `Unspendable` | — |
| 0x0601 | PLC | `HYSTERESIS_FEE` | `[NUMERIC(high), NUMERIC(low)]` | `Empty` | — |
| 0x0602 | PLC | `HYSTERESIS_VALUE` | `[NUMERIC(high), NUMERIC(low)]` | `Empty` | — |
| 0x0611 | PLC | `TIMER_CONTINUOUS` | `[NUMERIC(accumulated), NUMERIC(target)]` | `Empty` | — |
| 0x0612 | PLC | `TIMER_OFF_DELAY` | `[NUMERIC(remaining)]` | `Empty` | — |
| 0x0621 | PLC | `LATCH_SET` | `[NUMERIC(state)]` | `Reveal 1` | 1 `PUBKEY` for leaf reconstruction |
| 0x0622 | PLC | `LATCH_RESET` | `[NUMERIC(state), NUMERIC(delay)]` | `Reveal 1` | 1 `PUBKEY` for leaf reconstruction |
| 0x0631 | PLC | `COUNTER_DOWN` | `[NUMERIC(count)]` | `Reveal 1` | 1 `PUBKEY` for leaf reconstruction |
| 0x0632 | PLC | `COUNTER_PRESET` | `[NUMERIC(current), NUMERIC(preset)]` | `Empty` | — |
| 0x0633 | PLC | `COUNTER_UP` | `[NUMERIC(current), NUMERIC(target)]` | `Reveal 1` | 1 `PUBKEY` for leaf reconstruction |
| 0x0641 | PLC | `COMPARE` | `[NUMERIC(op), NUMERIC(b), NUMERIC(c)]` | `Empty` | — |
| 0x0651 | PLC | `SEQUENCER` | `[NUMERIC(current), NUMERIC(total)]` | `Empty` | — |
| 0x0661 | PLC | `ONE_SHOT` | `[NUMERIC(state), HASH256(commitment)]` | `Empty` | — |
| 0x0671 | PLC | `RATE_LIMIT` | `[NUMERIC(max), NUMERIC(cap), NUMERIC(refill)]` | `Empty` | — |
| 0x0681 | PLC | `COSIGN` | `[HASH256(spk_hash)]` | `Empty` | — |
| 0x0701 | Compound | `TIMELOCKED_SIG` | `[SCHEME, NUMERIC(csv)]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0702 | Compound | `HTLC` | `[HASH256, NUMERIC(csv), SCHEME]` | `Fixed 5` | `[PUBKEY(recv), PUBKEY(send), SIGNATURE, PREIMAGE, NUMERIC(path)]` |
| 0x0703 | Compound | `HASH_SIG` | `[HASH256, SCHEME]` | `Fixed 3` | `[PUBKEY, SIGNATURE, PREIMAGE]` |
| 0x0704 | Compound | `PTLC` | `[NUMERIC(csv)]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0705 | Compound | `CLTV_SIG` | `[SCHEME, NUMERIC(cltv)]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0706 | Compound | `TIMELOCKED_MULTISIG` | `[NUMERIC(K), NUMERIC(csv), SCHEME, HASH256(pubkey_root)]` | `Triplets K` | K × `(PUBKEY, MERKLE_PROOF, SIGNATURE)` |
| 0x0707 | Compound | `ANCHOR_FEE` | `[SCHEME, NUMERIC(min_fee), NUMERIC(max_fee), NUMERIC(max_weight), NUMERIC(commitment)]` | `Fixed 4` | `[PUBKEY, PUBKEY, SIGNATURE, SIGNATURE]` |
| 0x0801 | Governance | `EPOCH_GATE` | `[NUMERIC(period), NUMERIC(offset)]` | `Empty` | — |
| 0x0802 | Governance | `WEIGHT_LIMIT` | `[NUMERIC(max_weight)]` | `Empty` | — |
| 0x0803 | Governance | `INPUT_COUNT` | `[NUMERIC(min), NUMERIC(max)]` | `Empty` | — |
| 0x0804 | Governance | `OUTPUT_COUNT` | `[NUMERIC(min), NUMERIC(max)]` | `Empty` | — |
| 0x0805 | Governance | `RELATIVE_VALUE` | `[NUMERIC(num), NUMERIC(denom)]` | `Empty` | — |
| 0x0806 | Governance | `ACCUMULATOR` | `[HASH256(set_root)]` | `Accumulator` | `[NUMERIC(element_id), MERKLE_PROOF]` |
| 0x0807 | Governance | `OUTPUT_CHECK` | `[NUMERIC(idx), NUMERIC(min), NUMERIC(max), HASH256(script)]` | `Empty` | — |
| 0x0901 | Legacy | `P2PK_LEGACY` | `[SCHEME]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0902 | Legacy | `P2PKH_LEGACY` | `[HASH160]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0903 | Legacy | `P2SH_LEGACY` | `[HASH160(redeem_script_hash)]` | `Bridging` | see Legacy bridging rule below |
| 0x0904 | Legacy | `P2WPKH_LEGACY` | `[HASH160]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0905 | Legacy | `P2WSH_LEGACY` | `[HASH256(witness_script_hash)]` | `Bridging` | see Legacy bridging rule below |
| 0x0906 | Legacy | `P2TR_LEGACY` | `[SCHEME]` | `Fixed 2` | `[PUBKEY, SIGNATURE]` |
| 0x0907 | Legacy | `P2TR_SCRIPT_LEGACY` | `[HASH256(tapscript_hash)]` | `Bridging` | see Legacy bridging rule below |
| 0x0A01 | QABI / PQ | `QABI_PRIME` | (none) | `Fixed 4` | `[HASH256(new_root), NUMERIC(prime_depth), NUMERIC(new_expiry), PREIMAGE(prime_preimage)]` |
| 0x0A02 | QABI / PQ | `QABI_SPEND` | `[HASH256(auth_tip), HASH256(committed_root), NUMERIC(committed_depth), NUMERIC(committed_expiry), PUBKEY_COMMIT(owner_id)]` | `Fixed 1` | `[PREIMAGE(spend_preimage)]` |
| 0x0A03 | QABI / PQ | `PQ_BATCH` | `[HASH256(SHA256(canonical_pq_pubkey))]` | `PQ-anchor` | non-anchor: empty witness; anchor: `[PUBKEY(pubkey_bytes), SIGNATURE]` |

The 11 condition data types referenced above are: `PUBKEY`,
`PUBKEY_COMMIT`, `SCHEME`, `NUMERIC`, `HASH256`, `HASH160`,
`SIGNATURE`, `PREIMAGE`, `SCRIPT_BODY`, `MERKLE_PROOF`, `DATA`. Their
allowed sizes and contexts are defined in `src/rung/types.h`.

#### Legacy bridging rule (`P2SH_LEGACY` / `P2WSH_LEGACY` / `P2TR_SCRIPT_LEGACY`)

The three legacy script-bridging blocks share one witness shape:

```
[ PREIMAGE(inner_script),                         (1 field — bound by HASH160/HASH256 in conditions)
  stack_push_field_0,
  stack_push_field_1,
  ...,
  stack_push_field_K-1 ]
```

`PREIMAGE` carries the inner redeem script / witness script /
tapscript bytes (≤80 bytes by `MAX_SCRIPT_BODY` rule for SCRIPT_BODY
fields, also valid as PREIMAGE here under the same per-tx cap of 1).
The hash binding to the conditions `HASH160` (P2SH) or `HASH256`
(P2WSH / P2TR_SCRIPT) is verified before evaluation.

The stack-push fields are typed: each MUST be one of
`{PUBKEY, SIGNATURE, NUMERIC, SCHEME}`. Their count K is enforced
by the evaluator: K MUST equal the sum of expected witness layout
counts for at least one rung in the inner conditions tree. A spender
that supplies more or fewer stack pushes than any inner rung needs
fails evaluation. The inner-script's evaluation consumes the stack-
push fields positionally as inner block witness fields.

This rule is the legacy bridge: it preserves the on-chain spending
shape of a wrapped P2SH / P2WSH / P2TR script while typing every byte
that appears in the witness. There is no untyped stack push and no
`OP_DROP` analogue.

#### Reserved block-type codes

Type codes outside the 65 entries above are reserved. The deserialiser
rejects unknown type codes — there is no soft-fork-friendly "unknown
block treated as anyone-can-spend" path at the wire layer. Forward
compatibility is provided by allocating new codes through future BIPs;
old nodes either upgrade or are left behind on a chain that does not
include the new block type.

### Evaluator semantics

Per-input verification is `rung::api::VerifyRungTx`. The evaluator
returns one of three states for any block evaluation:

- `SATISFIED` — the block accepts the spending witness.
- `UNSATISFIED` — the block rejects but spend was structurally well-
  formed (the next rung in the ladder may still satisfy).
- `EVAL_ERROR` — the spend is structurally malformed and the entire
  transaction MUST be rejected.

`ladder_lookup_block(type)` returns null for an unknown block type;
the evaluator surfaces this as `UNSATISFIED` for a non-inverted block
and `EVAL_ERROR` for an inverted one. (The asymmetry exists because
inversion of an unknown block can never be sound: see Rationale Q13.)

#### Per-tx checks (`CheckRungTxLevel`)

Run once per v4 transaction by `CheckInputScripts`:

1. `ValidateRungOutputs(tx)`:
   a. Every output is MLSC (1-byte `0xDF` after compression, or 33-
      byte `0xDF || root`, or 34..73-byte `0xDF || root || data`).
   b. At most one DATA_RETURN output.
   c. Non-DATA_RETURN outputs satisfy the dust threshold.
2. PREIMAGE / SCRIPT_BODY count across all MLSC-spending inputs and
   diff-witness overlays does not exceed `MAX_PREIMAGE_FIELDS_PER_TX
   = 2` (PREIMAGE) and `MAX_SCRIPT_BODY_FIELDS_PER_TX = 1`
   (SCRIPT_BODY). Bootstrap inputs (P2WPKH / P2WSH / P2TR / etc) are
   excluded from the count.
3. `tx.qabi_block` is non-empty IFF the transaction contains at least
   one `QABI_SPEND`, `QABI_PRIME`, or `PQ_BATCH` input. `tx.aggregated_sig`
   is non-empty IFF the transaction contains at least one `QABI_SPEND`
   input, in which case it MUST be exactly 666 bytes (FALCON-512).

#### Per-input checks (`VerifyRungTx`)

For each MLSC input, after the per-tx checks pass:

1. Witness stack count is 1, 2, or 3. Other counts reject.
2. Spent output is MLSC. Otherwise reject.
3. Recover the conditions root: directly from the spent output if
   stored full, or via `LadderBlockAccessor::FetchConditionsRoot` if
   the spent output is the compact 1-byte form.
4. Key-path mode (1 element):
   a. Compute `SignatureHashLadderKeyPath` (see "Sighash" below).
   b. Verify Schnorr signature against `conditions_root` interpreted
      as an x-only public key.
5. Script-path modes (2 or 3 elements):
   a. Deserialise `LadderWitness` from `stack[0]`. If diff-witness
      mode (`n_rungs == 0`), resolve the reference.
   b. Deserialise `MLSCProof` from `stack[1]`.
   c. The witness MUST contain exactly 1 rung (the one being
      revealed and spent).
   d. Extract pubkeys via `ExtractBlockPubkeys` over the witness
      blocks (see Rationale Q5).
   e. Compute the revealed leaf via `ComputeTxMLSCLeaf`. Compute any
      revealed relay leaves via `ComputeTxMLSCRelayLeaf`.
   f. Walk `proof_hashes` to reconstruct the Merkle root using the
      byte-sorted interior rule, with `MLSC_EMPTY_LEAF` padding for
      missing slots.
   g. The reconstructed root MUST equal the spent output's
      conditions_root. For 3-element witness mode, the equality is
      against `internal_pubkey` x-only-tweaked by the conditions_root
      via `LadderTweak/v1`.
   h. Read the revealed rung's coil and check `coil.output_index`
      matches the spent input's vout.
   i. Merge conditions and witness fields per block: condition fields
      (`HASH256`, `HASH160`, `NUMERIC`, `SCHEME`, `SPEND_INDEX`)
      come from the proof; witness fields (`PUBKEY`, `SIGNATURE`,
      `PREIMAGE`, `SCRIPT_BODY`, `MERKLE_PROOF`) come from the
      witness. The `inverted` flag comes from the proof.
   j. Evaluate the ladder. The first satisfied rung wins (OR across
      rungs). Within a rung, every block MUST satisfy (AND across
      blocks). Inversion swaps `SATISFIED` ↔ `UNSATISFIED` for
      blocks that are flagged invertible at registration; key-
      consuming blocks are never invertible.
6. If no rung satisfies, the input fails.

### Sighash

This proposal defines two per-input sighash variants and one tx-level
QABI digest. The per-input variants are not selected by a hash-type
byte; the spend mode (key-path vs script-path) is implicit in the
witness stack count, and the variant follows. Hash-type bytes select
which of the BIP-143-style `prevouts` / `sequences` / `outputs`
digests are committed; they do not select between Ladder Script
variants.

#### `SignatureHashLadder` — script-path

Tag: `LadderSighash/v1`. Computed via
`api::SignatureHashLadder(cache, tx, nIn, hash_type, conditions, hash_out)`.
The digest commits to:

1. epoch byte (`0x00`).
2. `hash_type` byte.
3. `tx.version` (4 bytes LE).
4. `tx.lock_time` (4 bytes LE).
5. `cache.hash_prevouts_sha256`, `cache.hash_spent_amounts_sha256`,
   `cache.hash_sequences_sha256` — committed when `hash_type & 0x80
   == 0` (i.e. not `ANYONECANPAY`).
6. `cache.hash_outputs_sha256` — committed when the output type is
   `ALL`.
7. spend_type byte (`0x00` — no annex).
8. For `ANYONECANPAY`: this input's prevout, spent output, and
   sequence directly. Otherwise the input index (4 bytes LE).
9. For `SINGLE`: the SHA256 of the matching output.
10. The 32-byte conditions hash. For an MLSC input this is the spent
    output's `conditions_root` directly; for fixture inputs that
    construct `RungConditions` outside the consensus path the digest
    is `TaggedHash("LadderSighash/v1", serialised_conditions)` (test-
    only fallback; consensus rejects non-MLSC v4 outputs so the path
    is unreachable in production).
11. The 32-byte QABI section hash defined in §Sighash → QABI section
    binding below.

#### `SignatureHashLadderKeyPath` — key-path

Tag: `LadderKeyPathSighash/v1`. Identical to `SignatureHashLadder`
except that **no conditions hash is committed**. The conditions are
already bound to the spent output's scriptPubKey via the
`LadderTweak/v1` x-only tweak applied to the internal pubkey, so
including the conditions a second time would create a cross-protocol
signing-oracle hazard with no offsetting benefit.

#### Hash-type byte set

Both per-input variants accept hash type bytes from the set
`{0x00..0x03, 0x81..0x83}` only:

| Byte | Semantic |
|---|---|
| `0x00` | `DEFAULT` (treated as `ALL`) |
| `0x01` | `ALL` |
| `0x02` | `NONE` |
| `0x03` | `SINGLE` |
| `0x81` | `ALL \| ANYONECANPAY` |
| `0x82` | `NONE \| ANYONECANPAY` |
| `0x83` | `SINGLE \| ANYONECANPAY` |

The BIP-118 ANYPREVOUT family (`0x40..0x43`, `0xC0..0xC3`) is
unconditionally rejected. Both flags allow signature replay against
UTXOs the signer did not intend to spend; this proposal does not
provide the dedicated pubkey-prefix scheme that BIP-118 mitigates the
risk with, and the safe default is to reject the entire family.

#### QABI section binding

Every sighash digest computed by `SignatureHashLadder` and
`SignatureHashLadderKeyPath` includes a 32-byte commitment to the
transaction-level QABI fields:

```
qabi_section_hash = TaggedHash("LadderQABISection/v1",
                               CompactSize(len(tx.qabi_block))
                            || tx.qabi_block
                            || CompactSize(len(tx.aggregated_sig))
                            || tx.aggregated_sig)
```

The `CompactSize`-prefixed length on each field makes the binding
structurally collision-resistant — two distinct
`(qabi_block, aggregated_sig)` pairs cannot produce the same digest
even if their byte concatenations would coincide.

#### `ComputeSighashQABO` — QABI coordinator signature

The coordinator's FALCON-512 signature over a QABI batch transaction
commits to a separate digest:

```
qabo_sighash = TaggedHash("QABOSighash",
                          version (4 LE)
                       || foreach input: prevout || sequence (4 LE)
                       || foreach output: serialised CTxOut
                       || conditions_root (32 bytes)
                       || CompactSize(len(qabi_block)) || qabi_block
                       || foreach input: full witness stack
                                          (CompactSize(count)
                                           + per element CompactSize(len)+bytes)
                       || lock_time (4 LE))
```

The digest excludes `tx.aggregated_sig` itself (otherwise the
signature would be self-referential). Each input of the batch produces
an identical digest, which is why the FALCON verify can be cached
across inputs via the `qabo_sig_cache` (see `LadderEvalContext`).

`ComputeSighashQABO` is a function call, not a hash-type byte. The
QABI coordinator signature is selected by the presence of `tx.aggregated_sig`
on the v4 transaction, not by a sighash flag in any per-input
signature.

### Key-path tweak

Ladder Script defines its own key tweak distinct from BIP 341's
TapTweak. An x-only public key `P` and a 32-byte tweak input `m` (the
conditions root) produce a tweaked key:

```
t = TaggedHash("LadderTweak/v1", P || m)
Q = P + t·G                              (x-only)
```

The construction mirrors BIP 341 byte-for-byte except for the tag
string. A signature valid against a `LadderTweak/v1` tweaked key MUST
NOT validate against a `TapTweak` tweaked key, and vice versa.

Reference: `src/pubkey.cpp` `XOnlyPubKey::ComputeLadderTweakHash`,
`CreateLadderTweak`, `CheckLadderTweak`.

### Worked example: funding transaction

A single-input wallet bootstrap transaction creating one MLSC output
locked by a single SIG rung against an x-only public key.

<!-- TODO: needs canonical bytes from author. The reference
implementation can produce these via createrungtx + signrawtransactionwithwallet
on a regtest fixture. The bytes below are intentionally omitted to
avoid fabrication; replace with a captured signed tx from
test/functional/feature_rung_tx.py once the worked example is
generated. -->

```
version           : 04 00 00 00              (= 4, LE)
dummy             : 00
flags             : 02
n_inputs          : 01
prevout           : <32-byte funding txid LE> <vout LE>
scriptSig_len     : 00
nSequence         : ff ff ff ff
conditions_root   : <32 bytes — TaggedHash("LadderInternal/v1", ...)>
n_outputs         : 01
nValue            : <8 bytes LE — value in satoshis>
                  ; non-zero — no DATA_RETURN block
witness[0]        : <P2WPKH spending witness for the funding input>
qabi_block_len    : 00                       ; non-QABI tx
aggregated_sig_len: 00
nLockTime         : 00 00 00 00
```

Step-by-step deserialisation:

1. Read `version = 4`. The deserialiser branches into the v4 path.
2. Read `dummy = 0x00` and `flags = 0x02`. v4 with witness.
3. Read 1 input with the standard CTxIn form (36-byte prevout +
   scriptSig + sequence).
4. Read the 32-byte tx-level `conditions_root`.
5. Read 1 output: 8 bytes of value. Because value is non-zero, no
   DATA_RETURN payload follows. The deserialiser synthesises
   `vout[0].scriptPubKey = 0xDF || conditions_root`.
6. Read 1 per-input witness stack (the P2WPKH bootstrap signature +
   pubkey).
7. Read `qabi_block_len = 0` and `aggregated_sig_len = 0`.
8. Read `nLockTime`.

Validation: `ValidateRungOutputs` succeeds (one MLSC output, no
DATA_RETURN, non-zero value above dust). The bootstrap input is
P2WPKH and goes through standard SegWit verification. After
`AcceptToMemoryPool` succeeds, `AddCoins` writes:

- `(txid, 0)` — the regular MLSC coin, compressed to 1 byte (`0x06`).
- `(txid, 0xFFFFFFFF)` — the synthetic root coin, scriptPubKey
  `0xDE || conditions_root`.

### Worked example: spending transaction

A single-input v4 transaction spending the MLSC UTXO from the funding
example via the script-path with a single-rung SIG ladder.

<!-- TODO: needs canonical bytes from author. Produce alongside the
funding example so the conditions_root, leaf hash, and proof bytes
are coherent. -->

```
version           : 04 00 00 00
dummy             : 00
flags             : 02
n_inputs          : 01
prevout           : <funding txid LE> 00 00 00 00
scriptSig_len     : 00
nSequence         : ff ff ff ff
conditions_root   : <32 bytes for the spend tx — covers the new MLSC outputs>
n_outputs         : 01
nValue            : <8 bytes — funded amount minus fee>
witness[0]        :
    n_elements        : 02
    elem[0] LadderWitness (variable bytes)
    elem[1] MLSCProof    (variable bytes)
qabi_block_len    : 00
aggregated_sig_len: 00
nLockTime         : 00 00 00 00
```

Walk-through of `LadderWitness` (single rung, single SIG block):

- `n_rungs = 0x01`
- rung[0]:
  - `n_blocks = 0x01`
  - block[0]:
    - micro-header byte for SIG with implicit witness layout
    - `PUBKEY` field (32 bytes x-only)
    - `SIGNATURE` field (64 bytes Schnorr)
  - `n_relay_refs = 0x00`
- coil: `01 01 01 00` (UNLOCK, INLINE, SCHNORR, output_index = 0)
- `n_relays = 0x00`

Walk-through of `MLSCProof`:

- `total_rungs = 0x01`
- `total_relays = 0x00`
- `rung_index = 0x00`
- `revealed_rung`: SIG block with conditions field `[SCHEME = 0x01]`
- `n_revealed_relays = 0x00`
- `n_proof_hashes = 0x00` (single-leaf tree)
- `n_mutation_targets = 0x00`

Verification proceeds as:

1. `ExtractBlockPubkeys` collects 1 PUBKEY from the witness rung's
   SIG block.
2. `ComputeTxMLSCLeaf` over the revealed rung produces a 32-byte
   leaf hash. With `total_rungs = 1` and `total_relays = 0`,
   `BuildMerkleTree` returns the leaf directly.
3. The reconstructed root equals the funding tx's
   `conditions_root` recovered from the synthetic root coin.
4. `coil.output_index == 0` matches the spent input's vout (0).
5. `MergeConditionsAndWitness` produces a SIG block with `[SCHEME,
   PUBKEY, SIGNATURE]`.
6. `EvalSigBlock` computes `SignatureHashLadder` and Schnorr-verifies
   the signature against the pubkey and the sighash.
7. The rung satisfies. The input is spent.

### Activation

Activation uses the BIP 9 versionbits mechanism with a dedicated
deployment bit. Pre-activation, v4 transactions are accepted but their
new fields are unenforced — to legacy nodes, every v4 transaction
appears as anyone-can-spend, matching the existing soft-fork model
used by SegWit (BIP 141) and Taproot (BIP 341).

Post-activation, full Ladder Script consensus rules are enforced. All
65 block types activate together; there is no per-block staged
rollout.

The existing `RUNG_VERIFY_MLSC_ONLY` script flag (bit 28) is set
post-activation. With the flag set, only MLSC outputs are accepted on
v4 transactions; the earlier draft "inline conditions" form
(`0xC1`-prefixed scriptPubKey) is rejected as a defence in depth.

Replace-By-Depth (RBD) is a new mempool policy added alongside
activation. It governs replacement of `QABI_PRIME` transactions only
— a participant may replace their own primed transaction with one
having a strictly deeper `prime_depth`. Standard BIP 125 RBF applies
to all other v4 transactions.

## Rationale

### 1. Why a new transaction version rather than new opcodes?

A new transaction version commits to a complete typed format up
front; an opcode commits to a single new operation inside an existing
untyped format.

The opcode route is the historical path (`OP_CSV`, `OP_CLTV`,
`OP_CHECKSIGADD`). It has two structural costs that compound over
time. First, every new opcode must be analysed against every
combination of every existing opcode — the script's evaluation is
order-dependent and stack-dependent, so adding one opcode increases
the verification surface by roughly the size of the existing opcode
set. Second, the underlying assumption of every Bitcoin Script
extension — that scripts are bytes on a stack — leaves no room to
introduce typed fields, and so each new capability re-litigates the
embedding-and-spam argument from the beginning.

A new transaction version separates the concerns. `RUNG_TX` is a
fresh format whose structural rules are independent of v1/v2/v3
script semantics. Version 4 adds capabilities by registering new
block types, not by adding opcodes — every block has its own typed
field layout, its own evaluator function, and zero interaction with
existing v1/v2/v3 evaluation. The Ladder Script verification path is
called only for v4 transactions and never modifies any byte the
classical script verifier touches.

The cost is one extra `SigVersion` value and one new wire format. The
benefit is that every future Ladder Script extension is additive and
local.

### 2. Why typed blocks rather than extending Script?

Typed blocks make the protocol's commitment to "no embedding" load-
bearing.

A stack-based script with an `OP_DROP` opcode allows arbitrary push-
and-discard. A stack-based script with `OP_IF` and `OP_FALSE` allows
arbitrary dead-code blocks. Both patterns are used on Bitcoin today
to embed kilobytes of arbitrary data — the Ordinals protocol exploits
the `OP_FALSE OP_IF ... OP_ENDIF` form inside Tapscripts; the P2WSH
push-and-`OP_DROP` form predates it. The protocol cannot reject
either pattern at the script layer because the bytes are
syntactically valid script with valid execution; the interpreter
has no way to ask "what is this byte for?"

Typed blocks remove the question. Every byte in an MLSC witness
belongs to a typed field that a specific block evaluator reads. The
deserialiser rejects fields whose type is not listed in the block's
implicit layout. The deserialiser further rejects any field whose
data-type is not legal in its serialisation context (`PUBKEY` cannot
appear on the conditions side; `HASH256` / `HASH160` /
`PUBKEY_COMMIT` / `DATA` cannot appear inside layout-less blocks; and
so on). There is no field type that takes attacker-chosen
unstructured bytes that the evaluator does not consume.

The cost is that programmability is an enumerated list rather than a
universal computation model. Today, a soft fork that wanted to add a
genuinely new computation model (e.g. simplicity-style combinators)
would have to do so as a new block type or a future v5 transaction
format. The trade-off is deliberate: untyped programmability is
paying the cost of permanent embedding, and that cost is too high.

### 3. Why activate sixty-five block types in a single soft fork?

The 65 blocks are not 65 independent features. They share the wire
format, the leaf hashing, the witness merging, and the evaluator
dispatch — every block's correctness depends on the others' field-
type and inversion semantics being fixed. A staged activation that
introduced blocks one at a time would carry one of two costs:

- Maintaining N parallel verification codepaths so that each
  activation point has a self-consistent rule set, OR
- Introducing inter-block invariants that change with each
  activation, requiring every consumer (wallet, indexer, explorer)
  to track which subset is currently active.

Both costs scale linearly with the number of activations. An all-in-
one activation pays the full review cost once.

The block registry is modular at the implementation level (each block
in its own translation unit, registered at process start). A future
soft fork CAN add new blocks at unused type codes; the registry
mechanism does not preclude it. What this BIP rejects is a phased
rollout of the initial 65.

### 4. Why MLSC (transaction-level Merkle commitment) rather than per-output script commitments?

A transaction-level commitment is a strictly tighter constraint than
per-output commitments and produces a smaller wire format and a
smaller chainstate.

Per-output commitments duplicate the 32-byte commitment in every
output. For an N-output transaction, the on-wire cost is 32×N bytes
of script and the chainstate cost is 32×N + N×(SPK overhead). MLSC
puts the commitment once in the transaction body and writes the per-
coin chainstate entry as a 1-byte marker; the 32-byte root is
recovered at spend time from a synthetic UTXO entry written once per
creating transaction (not once per coin).

Concretely:

| N outputs | MLSC chainstate | P2WPKH chainstate | P2TR chainstate |
|---:|---:|---:|---:|
| 10 | 63 B | 240 B | 360 B |
| 100 | 333 B | 2,400 B | 3,600 B |
| 1,000 | 3,033 B | 24,000 B | 36,000 B |

The 8–12× chainstate saving lives in RAM on every full node; this is
the most expensive byte in Bitcoin.

The synthetic root coin is the load-bearing piece. Its prefix byte is
`0xDE` (not `0xDF`) so the existing `0xDF`-aware compressor does not
strip its 32-byte payload. The recovery path is normative —
implementations that get it wrong consensus-split silently. The
stateless-verifier obligation that follows from this design is
specified in §Security Considerations.

### 5. Why fold pubkeys into the leaf hash?

`merkle_pub_key` removes pubkey fields from the on-chain conditions
section. In their place, the spender reveals the pubkey at spend time
and the verifier folds it into the leaf hash during proof
reconstruction. If the spender provides a different pubkey, the
reconstructed leaf does not match the committed root and the proof
fails.

The benefit is twofold. First, it removes a writable byte channel
that would otherwise carry attacker-chosen 32–65-byte content per
key-consuming block in the conditions side; the only `PUBKEY` bytes
that ever land on chain are those revealed at spend time, and they
are bound by leaf reconstruction to the exact value committed at fund
time. Second, it preserves the conditions side's typed-field
invariant — `PUBKEY` is rejected at deserialisation in the conditions
context, leaving only commitment-shaped data types (`HASH256`,
`HASH160`, `NUMERIC`, `SCHEME`, `SPEND_INDEX`, `DATA`) on the
conditions wire.

The cost is that the verifier needs the witness-side pubkey to
recompute the leaf — which means a key-consuming block cannot be
validated from the conditions tree alone. This is fine for
verification (the witness is always present at spend time) but does
require the indexer / wallet to keep witness bytes accessible until
the UTXO is spent.

### 6. Why these specific structural caps (`MAX_RUNGS = 16`, `MAX_BLOCKS_PER_RUNG = 8`, `MAX_FIELDS_PER_BLOCK = 16`)?

The caps bound the worst-case work the deserialiser and evaluator
perform per input, and bound the per-tx attacker-controllable byte
count via the per-block field layouts.

`MAX_RUNGS = 16` limits the number of alternative spending paths per
input. Sixteen is enough to express realistic governance shapes
(primary signer + cold recovery + multiple compound conditions +
emergency paths) without admitting absurd ladders. The Merkle proof
depth at the cap is `log_2(16) = 4`, so a worst-case proof is 4
sibling hashes (128 bytes) above the revealed leaf.

`MAX_BLOCKS_PER_RUNG = 8` limits the AND-conjunction width within a
rung. Eight blocks per rung is enough to express compound shapes
(e.g. 2-of-3 multisig + CSV + amount-lock + governance gate + audit
anchor) without admitting per-rung amplification.

`MAX_FIELDS_PER_BLOCK = 16` is the deserialiser-level cap on
explicit-field encoding. With every block's implicit layout defining
the actual field count, this cap acts as a deserialiser sanity bound
for layout-less blocks (RECURSE_MODIFIED, RECURSE_DECAY) and as a
fast reject for malformed wire bytes.

The numeric values are intentional powers of two for clean
implementation (bit-set state vectors, fixed-size temporary buffers).
Larger values are not foreclosed by the format; they would require a
future soft fork.

### 7. Why `MAX_PREIMAGE_FIELDS_PER_TX = 2`?

Preimage fields are the largest unstructured-byte channel that
remains after typing and key-folding: each is up to 32 bytes, hash-
bound to a `HASH256` in the conditions side. Two preimages per
transaction is enough to express the realistic spend shapes that need
preimages (an HTLC reveal + a hash-locked anchor, say) without
allowing per-input amplification.

The cap is enforced across all MLSC-spending inputs of the
transaction, not per-input — otherwise an attacker could split a
spend across N inputs and embed 64×N preimage bytes. Diff-witness
overlays count too, so an attacker cannot use diff-witness to fan out
fresh preimage bytes past the cap.

`MAX_SCRIPT_BODY_FIELDS_PER_TX = 1` follows the same logic. A single
inner script body suffices for legacy P2SH/P2WSH/P2TR_SCRIPT bridging
spends.

### 8. Why byte-sorted Merkle interior hashing?

A byte-sorted interior rule (`min(a, b) || max(a, b)`) makes the tree
canonical: the same set of leaves produces the same root regardless
of which side of a parent each leaf sits on.

The classic position-sensitive form (left/right concatenation) admits
two distinct Merkle trees over the same leaf set, which the spender
chooses between. The choice is one bit of attacker-controlled
information per interior node — log_2(16) = 4 bits per `MAX_RUNGS =
16` tree. Byte-sorting removes that bit: there is exactly one tree
for each leaf set, and the spender has no encoding freedom at the
interior layer.

The cost is that the proof must reveal the sibling hash but does not
need to reveal direction bits — saving 1 bit per proof level relative
to BIP 341's per-level direction bit. The verifier reconstructs the
parent by sorting reconstructed-leaf and sibling lexicographically
before hashing.

### 9. Why include QABIO in the initial activation rather than defer it?

QABIO depends on the v4 wire format (the tx-level `qabi_block` and
`aggregated_sig` fields), the `SigVersion::LADDER` semantics (so its
per-input checks use the same evaluator dispatch), and the conditions
tree (the QABI_PRIME / QABI_SPEND blocks live in the standard rung
structure). Deferring it would mean a future BIP that re-opens the
v4 wire format to add the two extra fields — equivalent to a partial
re-activation.

The QABIO surface IS modular at the implementation level: the entire
extension is gated by the `LADDER_ENABLE_QABIO` build flag, and a
non-QABIO build is a clean omission of three block types and the two
tx-level fields. But the wire format reserves the slots regardless,
so the activation cost of including QABIO at v4 is zero
incrementally.

### 10. Why FALCON-512 specifically for QABIO?

The QABIO coordinator signature is a fixed per-transaction overhead
amortised across every primed input. Smaller signature size is
strictly better for amortised per-input cost.

| Scheme | Signature size | Pubkey size |
|---|---:|---:|
| FALCON-512 | 666 B | 897 B |
| FALCON-1024 | 1,280 B | 1,793 B |
| Dilithium3 | 3,293 B | 1,952 B |
| SPHINCS+ | ~8 KB+ | varies |

FALCON-512 has the smallest signature among NIST-standardised post-
quantum signature schemes. For the per-tx cost driver of QABIO, that
makes it the dominant choice. FALCON-1024 and Dilithium3 are
available for per-input `SIG` blocks where the larger signature is
acceptable in exchange for FALCON-1024's higher security parameter or
Dilithium3's different lattice assumption, but they are not currently
selectable for the QABIO coordinator slot.

### 11. Why PQ_BATCH as a separate primitive from QABIO?

QABIO is governance-heavy: it requires a coordinator, a priming
round, a covenant on `committed_root`, an output-set commitment in
the qabi_block, and a per-participant escape rung. It is the right
shape for "N independent parties sweep into a coordinated batch
payout".

The simpler shape — "any subset of UTXOs that share a PQ pubkey can
be spent together with one signature" — does not need any of that
machinery. PQ_BATCH commits `SHA256(canonical_pq_pubkey)` per output
at fund time. At spend time, one anchor input in the transaction
reveals the pubkey + a single PQ signature; every other input gated
by the same hash short-circuits via a tx-local cache. There is no
priming, no coordinator election, no governance over composition.

Per-input amortised cost (measured at N=100, see
`doc/ladder-script/SIZING.md` §5):

| Primitive | vB per input @ N=100 |
|---|---:|
| Per-input FALCON-512 `SIG` | ~400 |
| QABIO batch | ~143 |
| PQ_BATCH | ~17.8 |

The two primitives sit in the same `0x0A__` family because they
share the cryptography, but their use cases — coordinator-governed
batch settlement vs simple key-sharing pool — are distinct enough
that one would be a poor fit for the other.

### 12. Why is `liboqs` a hard build dependency rather than optional?

The PQ signature schemes are part of the consensus surface. A node
built without `liboqs` would silently disagree with PQ-enabled nodes
on whether a PQ-signed spend is valid — a consensus split.

`liboqs` is therefore a hard `find_package(... REQUIRED)` build
dependency. The `LADDER_ENABLE_QABIO` build flag CAN disable the
QABIO extension specifically (the three QABI-family blocks), but the
classical PQ signature schemes used by per-input `SIG` blocks are not
optional.

### 13. Why are unknown block types `UNSATISFIED` rather than `ERROR`, except when inverted?

A transaction whose witness uses a block type the verifier does not
recognise is structurally well-formed at the wire level: the type
code, the field count, and the field types are all valid encodings.
The verifier's question is "does this rung satisfy?" — and for an
unknown block type the honest answer is "I cannot tell; I do not
know what this block requires." The conservative response is to fail
THIS rung (treat it as `UNSATISFIED`) and let the OR-across-rungs
logic try the next one. If no rung satisfies, the input fails.

Inversion changes the picture. An inverted block evaluates as the
logical negation of the underlying rule: `[/CSV: 144]` means "spend
BEFORE 144 blocks", which is the inverse of the standard CSV
semantic. If the verifier does not know the underlying block, it
cannot compute the inverse — there is no honest answer to "does the
inverse of an unknown rule hold?" The conservative response is
`ERROR` (rejecting the entire transaction) rather than `UNSATISFIED`,
because `UNSATISFIED` would mean "I evaluated the inverse and it
failed" which is a falsehood.

This produces a clean soft-fork rule for future block types: an old
node rejects a transaction that uses a new block type only if that
block is inverted. Non-inverted uses simply fall through the OR
logic.

### 14. Why a key-path tweak distinct from BIP 341's, instead of reusing BIP 341 directly?

Domain separation. A signature valid under `LadderTweak/v1` MUST
NOT validate under `TapTweak`, and vice versa. Sharing the tag
would mean a signature signed for a Taproot output could in
principle be replayed against a Ladder Script output (or vice
versa) if the same internal key were used in both contexts. The
tag-level separation makes this impossible: the tweak applied to the
internal key is different in the two domains, so the resulting public
key is different and a signature against one cannot match the other.

The implementation reuses BIP 341's tweak construction byte-for-byte
except for the tag string — the only difference is the
`TaggedHash("LadderTweak/v1", ...)` versus
`TaggedHash("TapTweak", ...)`. The "/v1" suffix gives a clean upgrade
path if the construction ever needs to evolve.

### 15. Why two sighash variants and a separate QABO digest, instead of new sighash flag bytes?

A new sighash flag byte is the wrong shape for this proposal's
needs. Spend mode (key-path vs script-path) is implicit in the
witness stack count, so a flag byte that selects between them would
be redundant. The QABI coordinator signature is selected by the
presence of `tx.aggregated_sig` on the v4 transaction, so a flag
byte that selects it would also be redundant. In both cases the
selection is a structural property of the transaction, not a per-
signature choice.

So the proposal defines `SignatureHashLadder` and
`SignatureHashLadderKeyPath` as two distinct functions called by
the verifier based on the witness stack count, and `ComputeSighashQABO`
as a separate function the coordinator calls once per batch. The
hash-type byte on per-input signatures keeps its standard meaning
(`{0x00..0x03, 0x81..0x83}` selecting which BIP-143-style digests
are committed). The BIP-118 ANYPREVOUT family (`0x40..0x43`,
`0xC0..0xC3`) is unconditionally rejected: ANYPREVOUT lets a
signer's signature be replayed against UTXOs the signer did not
intend to spend, and this proposal does not provide the dedicated
pubkey-prefix scheme that BIP-118 mitigates the risk with.

### 16. Why this set of legacy wrapper blocks rather than a generic `LEGACY_SCRIPT` block?

A generic `LEGACY_SCRIPT` block would carry a raw Bitcoin Script in a
SCRIPT_BODY field and execute it via the v1/v2/v3 interpreter. That
would re-import the entire opcode-and-stack model into v4 — every
embedding pattern that exists in legacy script (push-and-`OP_DROP`,
`OP_IF false`) would re-appear in v4 transactions, defeating the
typed-fields property that motivates the format.

The seven wrapper blocks (`P2PK_LEGACY`, `P2PKH_LEGACY`,
`P2SH_LEGACY`, `P2WPKH_LEGACY`, `P2WSH_LEGACY`, `P2TR_LEGACY`,
`P2TR_SCRIPT_LEGACY`) instead model the interface to each existing
output type: the conditions side commits to the same hash that the
legacy SPK would commit to, and the witness side reveals the same
stack data the legacy spend would push. The inner-script payload IS
SCRIPT_BODY, but it is hash-bound and capped at one per transaction
— the same constraint the legacy P2SH / P2WSH script-hash provides,
not a fresh embedding channel.

This gives a 1:1 migration path for every legacy output type without
re-importing the legacy semantics into v4 transactions that don't use
them.

### 17. Why include the Replace-By-Depth mempool policy in the consensus BIP at all?

RBD is a mempool policy, not a consensus rule, and would normally
live in a separate BIP. It is described here because it is the only
sensible replacement rule for QABI_PRIME transactions: standard BIP
125 RBF replaces by fee, but priming cost is not a fee auction — it
is a depth commitment, and a participant who wants to re-aim their
commitment at a deeper depth must be able to evict their own shallower
priming transaction without paying a fee premium.

Including RBD in the same document as QABIO keeps the priming
lifecycle complete in one place. A future BIP could cleanly extract
RBD into its own document; the rule itself is small (a participant
may replace their own primed transaction with one having a strictly
deeper `prime_depth`, evicting the original) and would not change.

## Backwards Compatibility

Pre-activation, v4 transactions are accepted by legacy nodes as
anyone-can-spend transactions — every input's `scriptSig` and witness
stack are unenforced, and the tx is treated as if every output were
spendable by anyone. This matches the BIP 141 (SegWit) and BIP 341
(Taproot) soft-fork patterns. Post-activation, full Ladder Script
rules are enforced. A miner running an unupgraded node may still mine
v4 transactions; a node enforcing the new rules will reject blocks
containing invalid v4 transactions, so the standard soft-fork
incentive structure applies.

No existing v1/v2/v3 transaction validation is altered. The existing
script verifier, signature checker, BIP 141 witness validation, and
BIP 341 Taproot evaluation paths are all left untouched. Two existing
function signatures gain defaulted parameters (the `CScriptCheck`
constructor adds a `block_height` integer and three optional cache-
pointer parameters); every existing call site continues to compile
unchanged.

The synthetic root coin entry at `(txid, MLSC_ROOT_VOUT)` is the one
load-bearing change to chainstate semantics. Any code path that
treats UTXOs as self-describing — `assumeutxo` snapshots, stateless
library verifiers, pruned-node spend validation — must respect the
recovery path documented in `src/compressor.cpp`. A node that fails
to honour this path will silently disagree with conforming nodes on
v4 spend acceptance, producing a consensus split.

Wallet implementations that do not produce v4 transactions are
unaffected. Wallets that wish to produce v4 transactions need to
implement the v4 wire-format serialiser, the conditions root
construction, and the `LadderWitness` + `MLSCProof` witness format.
The reference implementation provides the `createrungtx`,
`signrungtx`, and related RPCs.

## Test Vectors

<!-- TODO: needs canonical bytes from author. The reference
implementation has 619 unit tests under `src/test/rung_tests.cpp` and
multiple functional tests under `test/functional/feature_rung_*.py`.
A test-vector file derived from those tests should ship at
`test/data/rung_tx_vectors.json` containing:
  - One funding transaction (hex + decoded fields + expected txid + expected wtxid)
  - One spending transaction (hex + decoded fields + expected txid + expected wtxid)
  - The conditions tree behind both, with leaf hashes and root
  - The MLSCProof for the spend, with all sibling hashes
  - The sighash bytes for the spend's signature
  - One QABIO priming transaction
  - One QABIO batch-spend transaction
  - One PQ_BATCH spend
The test vectors should be machine-readable so other implementations
can verify byte-identical behaviour. -->

## Reference Implementation

The reference implementation is `libladder`, a self-contained C++
library under `src/rung/` in the `bitcoin-core-ladder-script`
repository. Bitcoin Core integration is provided by `src/rung_shims.h`
and approximately 805 lines of patches across 29 existing Core files.

The library exports a small public API in `src/rung/api.h`:

- `VerifyRungTx(tx, input_index, spent_output, ctx, error_out)` —
  per-input v4 verification.
- `CheckRungTxLevel(tx, spent_outputs, error_out)` — per-tx checks
  (output format, qabi_block / aggregated_sig coherence, per-tx
  preimage / script-body caps).
- `ValidateRungOutputs(tx, error_out)` — output-format check.
- `IsMLSCScript(spk)`, `IsCompactMLSC(spk)`, `IsLadderScript(spk)` —
  script-classification predicates.
- `IsStandardRungTx(tx, reason_out)` — policy-level standardness
  check (mempool acceptance only; not consensus).
- `IsQABIPrimingTx(tx)`, `IsValidRBDReplacement(new_tx, old_tx,
  reason_out)` — RBD policy helpers.
- `SignatureHashLadder`, `SignatureHashLadderKeyPath`, and
  (`ENABLE_QABIO`) `ComputeSighashQABO` — sighash computations.

Following the BIP 340 → libsecp256k1 model, byte-exact behaviour of
the named source files is the consensus contract. Other
implementations are encouraged to produce byte-identical output on
the test vectors but are not required to follow the same internal
structure.

The canonical source is the `ladder-script` branch at
[`https://github.com/defenwycke/bitcoin-core-ladder-script`](https://github.com/defenwycke/bitcoin-core-ladder-script).
The library directory `src/rung/` builds standalone via
`cmake --build build --target bitcoin_rung` and links against
`crypto`, `util`, `secp256k1`, and `liboqs`.

## Security Considerations

**Fail-closed deserialisation.** Every wire-format check in
`src/rung/serialize.cpp` and `src/rung/conditions.cpp` rejects
malformed bytes rather than skipping them. Unknown block types,
unknown data types, oversize fields, non-canonical `CompactSize`
encodings, and field types not legal in their serialisation context
all reject at deserialisation, before any cryptographic operation
runs. This makes the wire format a structural contract: a transaction
that survives deserialisation has already passed every shape check.

**Anti-spam ceiling.** The structural ceiling on attacker-
controllable bytes per transaction is bounded by:

- `MAX_PREIMAGE_FIELDS_PER_TX = 2` × 32 bytes = 64 bytes of preimage.
- One `DATA_RETURN` payload up to 40 bytes (intentional channel).
- 8 bytes of `nLockTime` + per-input `nSequence`.
- 32 bytes per `HASH256` field on the conditions side (up to
  `MAX_BLOCKS_PER_RUNG × MAX_FIELDS_PER_BLOCK` per revealed rung,
  but every `HASH256` is an application-defined commitment, not free
  arbitrary bytes).

There is no equivalent of the Tapscript `OP_FALSE OP_IF ... OP_ENDIF`
dead-code channel and no equivalent of P2WSH push-and-`OP_DROP`. Every
byte in an MLSC witness is consumed by a typed evaluator. The exact
attacker-controllable byte count for a specific spend depends on
which block types are revealed — the maximum within standard relay
limits is bounded by the witness-size cap and the per-tx preimage cap,
not by an unstructured "padding" channel.

**Stateless verifier obligation.** This is the single most subtle
correctness trap in the proposal. The chainstate compressor stores
each MLSC coin as one byte (`0x06`); the 32-byte `conditions_root` is
NOT stored per-coin. Validating a v4 spend requires recovering that
root from the synthetic UTXO entry at `(creating_txid,
MLSC_ROOT_VOUT = 0xFFFFFFFF)`. Implementations MUST honour this path:

- The full-node validation path (`bitcoind`) recovers the root
  through the standard chainstate / undo-data lookup. No additional
  obligation.
- Any validation path that treats UTXOs as self-describing — block
  template validators, libbitcoinkernel-style stateless verifiers,
  `assumeutxo` snapshot loaders, alternative full-node
  implementations — MUST either:
  1. Provide a `LadderBlockAccessor::FetchConditionsRoot` callback
     that resolves the synthetic entry from block storage, OR
  2. Refuse to validate spends of v4 outputs.

A node that silently returns failure (or, worse, success) on the
recovery path without honouring the synthetic-entry lookup will
diverge from conforming nodes on whether a given v4 spend is valid.
This is a hard chain split with no in-protocol detection. The
load-bearing recovery invariant is documented in
`src/compressor.cpp` at the top of file; any change to type-`0x06`
semantics that breaks the recovery path is a silent consensus
divergence.

Snapshot loaders specifically (`assumeutxo` and equivalents) MUST
either carry the synthetic root entries in the snapshot or reject
snapshots that include any v4 MLSC UTXO. A snapshot that drops the
root entries leaves a downstream validator unable to spend the
preserved MLSC outputs.

Pruned-node spend validation works today via the standard undo-data
retention path: the creating block is kept indefinitely while any
spawned MLSC UTXO is unspent. Any future change to pruning behaviour
around MLSC UTXOs MUST replace the access path before removing the
data.

**Soft-fork forward compatibility.** New block types are added by
allocating a fresh 16-bit type code (the registry has 65 used codes
out of 65,536 possible) and registering an evaluator. Old nodes
reject transactions that use an unregistered type code, so each new
block requires its own soft fork — but the BIP for that fork is
small (one block, one evaluator) and the activation cost is local.
Existing nodes that do not run the new soft fork stay on the chain
that does not include the new block.

**Compile-time consensus flags.** `liboqs` is a hard build
dependency (`find_package(liboqs REQUIRED)` in
`src/rung/CMakeLists.txt`) because PQ signature schemes are part of
the consensus surface; a node built without `liboqs` would silently
disagree with PQ-enabled nodes. The `LADDER_ENABLE_QABIO` build flag
can disable the QABIO extension specifically; a non-QABIO build
rejects the three QABI-family block types via the standard "unknown
block type → UNSATISFIED" path. The flag is intended for deployments
that opt out of QABIO-specific semantics; it does not change the
classical PQ surface or any non-QABI block.

**Key-path tweak.** The `LadderTweak/v1` tag is distinct from
`TapTweak`. A signature signed for a Ladder Script tweaked key cannot
validate against a Taproot tweaked key, and vice versa. Internal-
pubkey tweaks are committed via the conditions root passed as the
tweak input.

**Sighash binding.** `SignatureHashLadder` commits to the conditions
hash; `SignatureHashLadderKeyPath` does not (the conditions are
already bound via the x-only tweak applied to the internal key).
Both variants commit to `tx.qabi_block` and `tx.aggregated_sig` via a
domain-separated `LadderQABISection/v1` tagged digest — so a v4
signature locks in the QABIO state alongside everything else.
`ComputeSighashQABO` commits to every input's full witness stack
(closing per-input witness malleability against the coordinator
signature) but excludes `tx.aggregated_sig` itself (otherwise the
signature would be self-referential).

**Merkle proof commutativity and canonical leaf placement.**
Interior nodes hash sorted children: `min(a, b) || max(a, b)`. There
is exactly one tree for any leaf set, so spenders have no encoding
freedom at the interior layer. Leaves are placed in a fixed order
(rung leaves first, then relay leaves), and the coil is folded into
each rung leaf's structural template — there is no separate coil
leaf to permute.

**QABIO Replace-By-Depth and self-flooding mitigations.** RBD
permits a participant to replace their own primed transaction with
one having a strictly deeper `prime_depth`. The deeper-depth rule
prevents a single participant from flooding the mempool with stale
priming transactions at shallow depths. The coordinator cannot
modify a primed UTXO after priming and cannot steal funds: every
primed input commits to `committed_root = SHA256(qabi_block)`, and
the consensus evaluator requires `tx.vout` to bit-exact match
`qabi_block.outputs`, so any deviation rejects.

**Audit status.** The implementation has been internally reviewed
across multiple iterations and runs end-to-end on a private signet
hosted at `ladder-script.org`. No external security audit has been
performed at the time of this draft. A formal audit by an
independent post-quantum cryptography reviewer is scheduled before
any mainnet-activation proposal.

**Out of scope.** Wallet user experience (key management, address
formats, descriptor extensions), mempool fairness for non-QABIO v4
transactions, and block-template construction details are out of
scope for this BIP. They are wallet- and policy-layer concerns whose
choices do not affect consensus.

## Acknowledgements

Ladder Script's typed-block model draws on the programmable logic
controller (PLC) tradition, particularly the IEC 61131-3 Ladder
Diagram language, in which spending paths and rungs translate
directly to PLC programs and their evaluation discipline.

The post-quantum signature schemes used are the work of the original
designers and the broader NIST post-quantum cryptography
standardisation process:

- FALCON: Pierre-Alain Fouque, Jeffrey Hoffstein, Paul Kirchner,
  Vadim Lyubashevsky, Thomas Pornin, Thomas Prest, Thomas Ricosset,
  Gregor Seiler, William Whyte, Zhenfei Zhang. <!-- TODO: confirm
  author list against current NIST submission. -->
- CRYSTALS-Dilithium: Léo Ducas, Eike Kiltz, Tancrède Lepoint,
  Vadim Lyubashevsky, Peter Schwabe, Gregor Seiler, Damien Stehlé.
  <!-- TODO: confirm. -->
- SPHINCS+: the SPHINCS+ team. <!-- TODO: pick a single
  attribution form (full author list or "the SPHINCS+ team") and be
  consistent across the BIP. -->

The Open Quantum Safe project's `liboqs` library provides the
reference implementations of the PQ schemes used at consensus level.

This BIP follows the structural model of BIP 141 (SegWit), the
precision-and-numbered-rationale model of BIP 340 (Schnorr), the
approachable-motivation tone of BIP 173 (Bech32), and the worked-
example discipline of BIP 174 (PSBT).

The activation mechanics build on BIP 9 (versionbits) and BIP 8
(refinements), with the soft-fork compatibility stance the
SegWit and Taproot deployments established. The tagged-hash
construction is from BIP 340. The key-path tweak structure is from
BIP 341.

## References

- BIP 9 — Version bits with timeout and delay:
  <https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki>
- BIP 125 — Replace-By-Fee signalling:
  <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>
- BIP 141 — Segregated Witness (Consensus layer):
  <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>
- BIP 143 — Transaction Signature Verification for Version 0 Witness
  Program:
  <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
- BIP 340 — Schnorr Signatures for secp256k1:
  <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>
- BIP 341 — Taproot:
  <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
- BIP 342 — Validation of Taproot Scripts:
  <https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki>
- `libladder` reference implementation:
  <https://github.com/defenwycke/bitcoin-core-ladder-script>
- In-repository spec files: `doc/ladder-script/INTRODUCTION.md`,
  `doc/ladder-script/TX_MLSC_SPEC.md`,
  `doc/ladder-script/MERKLE-UTXO-SPEC.md`,
  `doc/ladder-script/BLOCK_LIBRARY.md`,
  `doc/ladder-script/QABIO.md`,
  `doc/ladder-script/PQ_BATCH_SPEC.md`,
  `doc/ladder-script/SIZING.md`,
  `doc/ladder-script/SOFT_FORK_GUIDE.md`,
  `doc/ladder-script/ANNOTATED_DIFF.md`.
