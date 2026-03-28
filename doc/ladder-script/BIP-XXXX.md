```
BIP: ?
Title: Ladder Script: Typed Transaction Conditions
Authors: Defenwycke <defenwycke@icloud.com>
Status: Draft
Type: Specification
Layer: Consensus (soft fork)
Assigned: ?
License: MIT
Discussion: 2026-03-16: https://groups.google.com/g/bitcoindev/c/0jEHXaQaeZw
```

## How to Review This Document

This BIP specifies a large system (61 block types). For efficient review:

1. **Start with Motivation and Design Overview** (5 min) — understand why
   typed blocks replace opcodes, how the ladder metaphor works, and what
   `merkle_pub_key` does for anti-spam.
2. **Read Rationale** (10 min) — every major design decision is explained
   with the alternative considered and why it was rejected.
3. **Skim Block Type Families** (5 min) — each family has a 1-2 sentence
   motivation. You don't need to memorize 61 types; understand the 10
   family purposes.
4. **Study Wire Format + MLSC Merkle Tree** (15 min) — this is the core
   protocol. The byte-level examples in Appendix B let you verify by hand.
5. **Check Anti-Spam Properties** (5 min) — the key innovation that makes
   this practical.
6. **Try it** — live signet: `bitcoinghost.org/labs/ladder-engine.html`

## Abstract

This document specifies Ladder Script, a typed transaction condition format
for Bitcoin that replaces raw opcodes with 61 typed function blocks organized
into 10 families. Every byte in a Ladder Script witness belongs to a typed
field with enforced size constraints; no arbitrary data pushes are possible.
Spending conditions are structured as a ladder of rungs (OR logic), where each
rung contains one or more blocks (AND logic), supporting signatures,
timelocks, hash verifications, covenants, bounded recursion, stateful contract
primitives (counters, latches, rate limiters), and governance constraints.
TX_MLSC transactions commit to a single shared Merkle root of conditions
(`conditions_root`) per transaction via Merkelised Ladder Script Conditions
(MLSC), revealing only the satisfied spending path. Each rung's coil
declares which output it governs via `output_index`. Ladder Script
transactions use version 4 (`nVersion = 4`).

## Motivation

### Bitcoin's Spending Conditions Are Too Limited

There are things people need to build on Bitcoin that Bitcoin Script cannot
express. Not "difficult to express" — impossible:

- **Vaults with clawback.** A hot key for daily spending with a cold key
  that can sweep immediately if the hot key is compromised. OP_VAULT
  (BIP-345) proposes this but is not activated. There is no way to do this
  with existing Script.

- **Rate-limited wallets.** Cap how many satoshis can leave a wallet per
  block, even if the signing key is stolen. No opcode inspects spending
  rate across blocks.

- **Recursive covenants.** A UTXO that enforces conditions on its own
  spending outputs — DCA schedules, graduated vesting, binary splits. This
  requires introspecting the spending transaction's outputs, which Script
  cannot do without proposed opcodes (CTV, OP_CAT) that are not activated.

- **Transaction-level governance.** Enforce that a treasury spend routes
  funds to a specific address, or that transaction weight stays under a
  limit, or that spending is only permitted during certain block-height
  windows. Script has no output introspection beyond signature checks.

- **Composable conditions.** A vault with rate-limiting AND a multisig
  recovery path AND a time-locked heir clause — all in one UTXO. Each
  proposed opcode (CTV, APO, OP_VAULT) addresses one use case. They were
  not designed to compose.

Ladder Script makes all of these possible as native block types, composable
with AND/OR logic:

```
ladder(output(0, or(
    and(sig(@hot_key), csv(144), amount_lock(0, 1000000), rate_limit(1, 10, 6)),
    multisig(2, @cold_a, @cold_b, @cold_c)
)))
```

This UTXO requires a signature AND a 144-block delay AND an amount cap AND
a rate limit on rung 0 — or a 2-of-3 multisig recovery on rung 1.

Ladder Script activates all 61 block types in a single soft fork. After
activation, no further Script changes are needed. The type system is fixed.
This is the final upgrade to Bitcoin's spending condition model.

### Additional Design Properties

Beyond capability, Ladder Script's typed block architecture provides three
properties that raw Script does not:

**Bounded data embedding.** Every witness byte must belong to a typed field
with enforced size constraints. The `merkle_pub_key` design binds public
keys into the Merkle leaf hash rather than carrying them in conditions,
eliminating the 2048-byte PUBKEY field as an embedding channel. PREIMAGE
fields are capped at 2 per transaction (`MAX_PREIMAGE_FIELDS_PER_TX`).
The residual embeddable surface is 112 bytes per transaction (flat) —
down from effectively unlimited in raw Script.

**Post-quantum readiness.** A 1-byte SCHEME field routes signature
verification to classical (Schnorr, ECDSA) or post-quantum algorithms
(FALCON-512, FALCON-1024, Dilithium3, SPHINCS+). No wire format changes,
no new block types, and no hard fork required. The same SIG block that
verifies a 64-byte Schnorr signature also verifies a 49,216-byte SPHINCS+
signature.

**Deterministic execution.** Each block type has a fixed evaluation function
with known computational cost. No loops, no stack manipulation, no unbounded
recursion. Evaluation terminates in O(blocks × fields) time, making formal
verification practical — the reference implementation includes 10 TLA+
specifications covering evaluation semantics, anti-spam, and Merkle proofs.

### Before and After

**HTLC — Before (raw Script, 11 opcodes):**

```
OP_IF
  OP_SHA256 <hash> OP_EQUALVERIFY
  <receiver_pubkey> OP_CHECKSIG
OP_ELSE
  <144> OP_CHECKSEQUENCEVERIFY OP_DROP
  <sender_pubkey> OP_CHECKSIG
OP_ENDIF
```

**HTLC — After (Ladder Script descriptor):**

```
ladder(output(0, htlc(@sender, @receiver, <preimage>, 144)))
```

One typed block. Fixed field layout. Static analysis. Deterministic cost.
Only the spending path revealed on-chain (the refund path stays private via
MLSC). No stack manipulation, no opcode ordering errors, no untyped byte
arrays.

This rung requires a signature AND a 144-block delay AND an amount cap AND
a rate limiter -- four conditions that compose without custom opcodes.

## Design Overview

### The Ladder Metaphor

A Ladder Script condition set is organized as a **ladder**: a list of
**rungs** connected by OR logic. Each rung contains one or more **blocks**
connected by AND logic. To spend an output, the spender must satisfy all
blocks in at least one rung.

```
Ladder (OR)
  ├── Rung 0: sig(@alice)                          [single signer]
  ├── Rung 1: and(sig(@bob), csv(144))             [backup after 1 day]
  └── Rung 2: multisig(2, @alice, @bob, @carol)    [2-of-3 multisig]
```

Each rung may also reference **relays** -- shared condition blocks that
factor out common requirements. Relays are evaluated once and their results
are available to any rung that references them.

The **coil** is per-output metadata attached to each ladder witness:
the unlock type (UNLOCK or UNLOCK_TO), attestation mode, signature scheme,
optional destination address, and `output_index` declaring which output
the rung governs.

### The merkle_pub_key Design

In most covenant systems, public keys appear in the locking conditions
on-chain, creating a writable surface for data embedding (an attacker can
commit an arbitrary 33-byte "public key" that encodes data rather than a
valid point).

Ladder Script moves public keys out of conditions entirely. At fund time,
the funder's public keys are hashed into the Merkle leaf alongside the
serialized condition blocks. The conditions themselves carry only a SCHEME
byte (1 byte) for signature blocks. At spend time, the witness provides the
actual public keys, and the verifier recomputes the Merkle leaf to confirm
they match the commitment.

This is the single most important anti-spam property: it eliminates the
largest unvalidated data channel (up to 2048 bytes per PUBKEY field) from
the conditions side, without any loss of functionality.

### Merkelised Ladder Script Conditions (MLSC)

TX_MLSC transactions carry one shared `conditions_root` per transaction
(not per output). The transaction format uses a PLC model: one ladder
program with multiple output coils. Each rung's coil includes an
`output_index` field declaring which output it governs.

The `conditions_root` commits to the root of a Merkle tree whose leaves
are the individual rungs, relays, and coil metadata. At spend time, only
the satisfied rung (and any referenced relays) are revealed; all other
spending paths remain hidden behind Merkle proof hashes. A creation proof
is included in the witness and validated at block acceptance to bind the
tree structure to the transaction.

This provides the same privacy benefit as Taproot's script tree, but uses
sorted interior nodes (eliminating left/right tracking in proofs) and
embeds public keys in leaves rather than in script branches.

### Conditions vs. Witness: Dual-Context Serialization

Every block type has two serialization contexts:

- **Conditions context:** The locking side, committed in the MLSC Merkle
  tree. Contains hashes, timelocks, scheme selectors -- no secrets.
- **Witness context:** The spending side, provided at spend time. Contains
  public keys, signatures, preimages -- the unlocking data.

Each context has its own implicit field layout. A SIG block in conditions
is 1 byte (SCHEME). The same SIG block in witness is variable-length
(PUBKEY + SIGNATURE). The deserializer selects the correct layout based
on context.

## Specification

### Transaction Format

A Ladder Script transaction has `nVersion = 4`. The flag byte `0x02`
signals TX_MLSC format (analogous to SegWit's `0x01` flag byte).

#### TX_MLSC Wire Layout

```
[nVersion: int32]
[flag: 0x00 0x02]                -- TX_MLSC signal
[input_count: CompactSize]
for each input:
    [prevout: 36 bytes]
    [scriptSig_len: CompactSize] -- must be 0
    [nSequence: uint32]
[conditions_root: 32 bytes]      -- shared MLSC root for all outputs
[output_count: CompactSize]
for each output:
    [nValue: int64]              -- 8 bytes, value only (no scriptPubKey)
for each input:
    [witness_count: CompactSize]
    [witness[0]: LadderWitness]
    [witness[1]: MLSCProof]
[creation_proof: bytes]          -- creation proof blob
[nLockTime: uint32]
```

The `conditions_root` (32 bytes) appears between the inputs and outputs.
Each output is 8 bytes (nValue only, no scriptPubKey on the wire). On
deserialization, outputs are inflated to `CTxOut(nValue, 0xDF + conditions_root)`,
producing the standard 33-byte MLSC commitment for each output.

The creation proof blob follows the per-input witness stacks and is
validated at block acceptance to confirm the Merkle tree structure.

All inputs MUST provide a witness stack of exactly 2 elements:

- `witness[0]`: Serialized `LadderWitness` (the spending proof)
- `witness[1]`: Serialized `MLSCProof` (revealed conditions and Merkle proof)

Verification proceeds via `VerifyRungTx` in 8 steps:

1. Validate all outputs via `ValidateRungOutputs` (33-byte `0xDF` prefix)
2. Deserialize the `LadderWitness` from `witness[0]`
3. Resolve witness references if the witness uses diff encoding
4. Deserialize the `MLSCProof` from `witness[1]`
5. Extract pubkeys from the witness for `merkle_pub_key` leaf computation
6. Verify the Merkle proof against the UTXO's `conditions_root`
7. Merge conditions (from proof) with witness (from `witness[0]`)
8. Evaluate the merged ladder via `EvalLadder`

A minimal SIG transaction (Schnorr, 32-byte x-only pubkey, 64-byte
signature) produces a 109-byte `witness[0]` (LadderWitness) and a 9-byte
`witness[1]` (MLSCProof). A byte-level breakdown is in Appendix B
(Vector 1, `conditions_hex` decoding).

### Output Format

On the wire, TX_MLSC outputs are 8 bytes each (nValue only). On
deserialization, each output is inflated to a standard `CTxOut`:

```
scriptPubKey = 0xDF || conditions_root (32 bytes)
```

This produces a 33-byte shared commitment. The `conditions_root` is shared
across all outputs in the transaction — only ONE root exists per TX_MLSC
transaction.

**DATA_RETURN outputs:** An output with `nValue == 0` is a DATA_RETURN
output. On the wire, it is followed by `[payload_len: CompactSize]
[payload: bytes]` (max 40 bytes). At most one DATA_RETURN output is
permitted per transaction.

### Data Types

Every field in a block carries one of 11 data types. Each type has fixed
minimum and maximum size constraints enforced at deserialization.

| Code   | Name          | Min  | Max    | Context     | Description                             |
|--------|---------------|------|--------|-------------|-----------------------------------------|
| `0x01` | PUBKEY        | 1    | 2,048  | Witness     | Public key (folded into Merkle leaf via merkle_pub_key) |
| `0x02` | PUBKEY_COMMIT | 32   | 32     | Witness     | Public key commitment (SHA-256 of pubkey) |
| `0x03` | HASH256       | 32   | 32     | Both        | SHA-256 hash                            |
| `0x04` | HASH160       | 20   | 20     | Both        | RIPEMD160(SHA256()) hash                |
| `0x05` | PREIMAGE      | 1    | 32     | Witness     | Hash preimage (SHA-256 payment hash)    |
| `0x06` | SIGNATURE     | 1    | 50,000 | Witness     | Signature (Schnorr 64-65, ECDSA 8-72, PQ up to 49,216) |
| `0x07` | SPEND_INDEX   | 4    | 4      | Both        | Spend index reference                   |
| `0x08` | NUMERIC       | 1    | 4      | Both        | Numeric value (CompactSize on wire)     |
| `0x09` | SCHEME        | 1    | 1      | Both        | Signature scheme selector               |
| `0x0A` | SCRIPT_BODY   | 1    | 80     | Witness     | Serialized inner conditions (for legacy wrappers) |
| `0x0B` | DATA          | 1    | 40     | Conditions  | Opaque data (DATA_RETURN blocks only)   |

**Condition data types** (allowed in the locking context): HASH256, HASH160,
NUMERIC, SCHEME, SPEND_INDEX, DATA. The types PUBKEY, PUBKEY_COMMIT,
SIGNATURE, PREIMAGE, and SCRIPT_BODY are witness-only and rejected in the
conditions context.

**PREIMAGE minimum is 1 byte**, not 32. P2SH and P2WSH inner conditions can
be shorter than 32 bytes, and the PREIMAGE type is shared across hash
verification and legacy script wrapping.

### Block Type Families

Ladder Script defines 61 block types across 10 families. Each block type is
encoded as a `uint16_t` (little-endian) on the wire.

#### Signature Family (0x0001 - 0x00FF)

Pubkeys are bound to the MLSC Merkle leaf via `merkle_pub_key`; conditions
carry only the SCHEME byte.

| Code     | Name             | Description                                         |
|----------|------------------|-----------------------------------------------------|
| `0x0001` | SIG              | Single signature verification                       |
| `0x0002` | MULTISIG         | M-of-N threshold signature                          |
| `0x0003` | ADAPTOR_SIG      | Adaptor signature (atomic swap secret revelation)   |
| `0x0004` | MUSIG_THRESHOLD  | MuSig2/FROST aggregate threshold signature          |
| `0x0005` | KEY_REF_SIG      | Signature using key commitment from a relay block    |

#### Timelock Family (0x0100 - 0x01FF)

| Code     | Name       | Description                                   |
|----------|------------|-----------------------------------------------|
| `0x0101` | CSV        | Relative timelock, block-height (BIP-68)      |
| `0x0102` | CSV_TIME   | Relative timelock, median-time-past           |
| `0x0103` | CLTV       | Absolute timelock, block-height (nLockTime)   |
| `0x0104` | CLTV_TIME  | Absolute timelock, median-time-past           |

#### Hash Family (0x0200 - 0x02FF)

| Code     | Name             | Description                                     |
|----------|------------------|-------------------------------------------------|
| `0x0203` | TAGGED_HASH      | BIP-340 tagged hash verification                |
| `0x0204` | HASH_GUARDED     | Raw SHA-256 preimage verification (non-invertible) |

#### Covenant Family (0x0300 - 0x03FF)

| Code     | Name        | Description                                  |
|----------|-------------|----------------------------------------------|
| `0x0301` | CTV         | OP_CHECKTEMPLATEVERIFY covenant (BIP-119)     |
| `0x0302` | VAULT_LOCK  | Two-path vault timelock covenant              |
| `0x0303` | AMOUNT_LOCK | Output amount range check                     |

#### Recursion Family (0x0400 - 0x04FF)

All 6 types are bounded (depth limits, countdown, height, or split
exhaustion). RECURSE_SAME persists indefinitely but cannot grow.

| Code     | Name             | Description                                   |
|----------|------------------|-----------------------------------------------|
| `0x0401` | RECURSE_SAME     | Re-encumber with identical conditions          |
| `0x0402` | RECURSE_MODIFIED | Re-encumber with parameterized mutations       |
| `0x0403` | RECURSE_UNTIL    | Recursive until target block height            |
| `0x0404` | RECURSE_COUNT    | Recursive countdown (terminates at zero)       |
| `0x0405` | RECURSE_SPLIT    | Recursive output splitting                     |
| `0x0406` | RECURSE_DECAY    | Recursive parameter decay                      |

#### Anchor Family (0x0500 - 0x05FF)

L2 protocol markers and the DATA_RETURN block for unspendable data
commitments (replacing OP_RETURN).

| Code     | Name           | Description                                  |
|----------|----------------|----------------------------------------------|
| `0x0501` | ANCHOR         | Generic anchor marker                         |
| `0x0502` | ANCHOR_CHANNEL | Lightning channel anchor                      |
| `0x0503` | ANCHOR_POOL    | Pool anchor (VTXO tree root)                  |
| `0x0504` | ANCHOR_RESERVE | Reserve anchor (guardian threshold)            |
| `0x0505` | ANCHOR_SEAL    | Seal anchor (asset ID + state hash)            |
| `0x0506` | ANCHOR_ORACLE  | Oracle anchor (oracle pubkey)                  |
| `0x0507` | DATA_RETURN    | Unspendable data commitment (max 40 bytes)    |

#### PLC Family (0x0600 - 0x06FF)

Stateful contract primitives driven by RECURSE_MODIFIED state transitions.

| Code     | Name             | Description                                   |
|----------|------------------|-----------------------------------------------|
| `0x0601` | HYSTERESIS_FEE   | Fee rate hysteresis band                       |
| `0x0602` | HYSTERESIS_VALUE | Value hysteresis band                          |
| `0x0611` | TIMER_CONTINUOUS | Continuous timer (consecutive blocks)          |
| `0x0612` | TIMER_OFF_DELAY  | Off-delay timer (hold after trigger)           |
| `0x0621` | LATCH_SET        | Latch set (state activation via signed event)  |
| `0x0622` | LATCH_RESET      | Latch reset (state deactivation with delay)    |
| `0x0631` | COUNTER_DOWN     | Down counter (decrement on signed event)       |
| `0x0632` | COUNTER_PRESET   | Preset counter (approval accumulator)          |
| `0x0633` | COUNTER_UP       | Up counter (increment on signed event)         |
| `0x0641` | COMPARE          | Comparator (amount vs thresholds)              |
| `0x0651` | SEQUENCER        | Step sequencer                                 |
| `0x0661` | ONE_SHOT         | One-shot activation window                     |
| `0x0671` | RATE_LIMIT       | Rate limiter (per-block cap, accumulation, refill) |
| `0x0681` | COSIGN           | Cross-input co-spend constraint                |

#### Compound Family (0x0700 - 0x07FF)

Common multi-block patterns collapsed into single blocks.

| Code     | Name                | Description                                |
|----------|---------------------|--------------------------------------------|
| `0x0701` | TIMELOCKED_SIG      | SIG + CSV combined                          |
| `0x0702` | HTLC                | Hash + Timelock + dual-Sig (atomic swap)    |
| `0x0703` | HASH_SIG            | Hash preimage + SIG combined                |
| `0x0704` | PTLC                | ADAPTOR_SIG + CSV combined (point-locked)   |
| `0x0705` | CLTV_SIG            | SIG + CLTV combined                         |
| `0x0706` | TIMELOCKED_MULTISIG | MULTISIG + CSV combined                     |

#### Governance Family (0x0800 - 0x08FF)

Transaction-level constraints beyond individual input authorization.

| Code     | Name           | Description                                    |
|----------|----------------|------------------------------------------------|
| `0x0801` | EPOCH_GATE     | Periodic spending window (block-height epochs)  |
| `0x0802` | WEIGHT_LIMIT   | Maximum transaction weight limit                |
| `0x0803` | INPUT_COUNT    | Input count bounds (min/max)                    |
| `0x0804` | OUTPUT_COUNT   | Output count bounds (min/max)                   |
| `0x0805` | RELATIVE_VALUE | Output value as ratio of input value            |
| `0x0806` | ACCUMULATOR    | Merkle accumulator (set membership proof)       |
| `0x0807` | OUTPUT_CHECK   | Per-output value range and script hash constraint |

#### Legacy Family (0x0900 - 0x09FF)

Wrappers for existing Bitcoin output types, enabling migration without
re-keying.

| Code     | Name               | Description                                |
|----------|--------------------|--------------------------------------------|
| `0x0901` | P2PK_LEGACY        | Wrapped P2PK                               |
| `0x0902` | P2PKH_LEGACY       | Wrapped P2PKH                              |
| `0x0903` | P2SH_LEGACY        | Wrapped P2SH (hash160 + inner script)       |
| `0x0904` | P2WPKH_LEGACY      | Wrapped P2WPKH (delegates to P2PKH path)    |
| `0x0905` | P2WSH_LEGACY       | Wrapped P2WSH (hash256 + inner script)       |
| `0x0906` | P2TR_LEGACY        | Wrapped P2TR key-path                        |
| `0x0907` | P2TR_SCRIPT_LEGACY | Wrapped P2TR script-path                     |

### Wire Format

Blocks are encoded using a compact wire format with micro-headers and
implicit field layouts, minimizing witness size while maintaining full
type safety.

#### Block Header

Each block begins with a single header byte:

- `0x00` - `0x7F`: Micro-header slot index. The block type is looked up
  from the micro-header table. The block is not inverted.
- `0x80`: Escape byte. A `uint16_t` block type follows (little-endian).
  The block is not inverted.
- `0x81`: Escape byte (inverted). A `uint16_t` block type follows
  (little-endian). The block is inverted.

#### Implicit Fields

When a micro-header is used and an implicit field layout exists for the
block type in the current serialization context (WITNESS or CONDITIONS),
field count and type bytes are omitted. Fields are read according to the
implicit layout:

- **NUMERIC** fields: encoded as a CompactSize value (no length prefix).
  Deserialized into a 4-byte little-endian representation.
- **Fixed-size fields** (e.g., HASH256 at 32 bytes, SCHEME at 1 byte):
  data is written directly with no length prefix.
- **Variable-size fields** (e.g., PUBKEY, SIGNATURE, PREIMAGE): CompactSize
  length prefix followed by data bytes.

#### Explicit Fields

When micro-header encoding is not used (escape byte, inverted block, or no
implicit layout):

```
[n_fields: CompactSize]
for each field:
    [data_type: uint8_t]
    if NUMERIC: [value: CompactSize]
    else: [data_len: CompactSize] [data: bytes]
```

#### Annotated Example

**SIG block, CONDITIONS context (micro-header, implicit layout):**
`00 01` -- micro-header 0x00 (SIG), SCHEME 0x01 (Schnorr). Total: 2 bytes.

**Inverted CSV block (escape byte, explicit fields):**
`81 01 01 01 08 90 01` -- escape(inverted), type 0x0101(CSV), 1 field,
NUMERIC(0x08), value 144. Total: 7 bytes.

### Micro-Header Table

The micro-header table maps 128 slot indices (`0x00` - `0x7F`) to block
types. Slots `0x00` through `0x3E` are assigned to the 61 block types
(in the order listed in the Block Type Families section above, starting
with SIG at `0x00`). Slots `0x07` and `0x08` are reserved. Slots `0x3F`
through `0x7F` are unused and rejected at deserialization. The complete
table is defined in `src/rung/types.h` (`kMicroHeaderSlots`).

### Implicit Field Layouts

Each block type has an implicit field layout for the CONDITIONS context and
optionally for the WITNESS context. When a micro-header is used and the
layout exists, field count and type bytes are omitted on the wire.

Notation: `TYPE(N)` means fixed N bytes with no length prefix. `TYPE(var)`
means CompactSize length prefix followed by data. NUMERIC is always
CompactSize-encoded (no length prefix, variable 1-5 bytes on wire).

#### Conditions Context Layouts

Each block type has an implicit field layout for the CONDITIONS context.
The complete table is available in the reference implementation
(`src/rung/types.h`, `GetImplicitLayout`). Representative examples:

| Block Type     | Fields                                                |
|----------------|-------------------------------------------------------|
| SIG            | SCHEME(1)                                             |
| CSV            | NUMERIC(var)                                          |
| HTLC           | HASH256(32), NUMERIC(var), SCHEME(1)                  |
| OUTPUT_CHECK   | NUMERIC(var), NUMERIC(var), NUMERIC(var), HASH256(32) |
| RATE_LIMIT     | NUMERIC(var), NUMERIC(var), NUMERIC(var)              |

ADAPTOR_SIG has 0 condition fields (no implicit layout; conditions are
empty). RECURSE_MODIFIED and RECURSE_DECAY have variable field counts
(2 + 4*N mutation descriptors) and use explicit encoding; they are
protected by `IsDataEmbeddingType` rejection rather than implicit layouts.

#### Witness Context Layouts

Each block type optionally has an implicit field layout for the WITNESS
context. The complete table is in `src/rung/types.h`. Representative
examples:

| Block Type     | Fields                                                         |
|----------------|----------------------------------------------------------------|
| SIG            | PUBKEY(var), SIGNATURE(var)                                    |
| CSV            | NUMERIC(var)                                                   |
| HTLC           | PUBKEY(var), SIGNATURE(var), PUBKEY(var), PREIMAGE(var), NUMERIC(var) |
| HASH_GUARDED   | PREIMAGE(var)                                                  |
| P2PKH_LEGACY   | PUBKEY(var), SIGNATURE(var)                                    |

All other block types use explicit field encoding in the witness context
(no implicit witness layout).

### MLSC Merkle Tree

#### Leaf Order

```
[rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]
```

The tree is padded to the next power of 2 with empty leaves:
`MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")`.

#### Leaf Computation

All leaves use `TaggedHash("LadderLeaf", structural_template || value_commitment)`:

- **structural_template:** The block types, inverted flags, and coil data
  (including `output_index`) for the leaf. This is the structural skeleton
  of the rung — deterministic from the condition set.

- **value_commitment:** `SHA256(field_values || pubkeys)` — an opaque hash
  of the field values and public keys bound to the leaf via
  `merkle_pub_key`. This is a SHA256 output, not attacker-chosen data.

Concretely:
- **Rung leaf:** `TaggedHash("LadderLeaf", structural_template || value_commitment)`
  where `structural_template` contains block types + inverted flags + coil
  (incl. `output_index`), and `value_commitment = SHA256(field_values || pubkey[0] || pubkey[1] || ...)`.
  Pubkeys are appended in positional order via `PubkeyCountForBlock()` (the `merkle_pub_key` commitment).
- **Relay leaf:** Same structure — `TaggedHash("LadderLeaf", structural_template || value_commitment)`.
- **Coil leaf:** `TaggedHash("LadderLeaf", SerializeCoilData(coil))`.

#### Interior Nodes

```
TaggedHash("LadderInternal", min(left, right) || max(left, right))
```

Sorted ordering eliminates left/right bits from proofs. A worked example
with concrete hashes is in Appendix B (Vector 2).

#### MLSC Proof Structure

```
[total_rungs: CompactSize]
[total_relays: CompactSize]
[rung_index: CompactSize]          -- which rung is revealed
<revealed rung blocks>             -- CONDITIONS-context serialized
[n_rung_relay_refs: CompactSize]
<rung relay_refs>
[n_revealed_relays: CompactSize]
for each revealed relay:
    [relay_index: CompactSize]
    <relay blocks>
    [n_relay_refs: CompactSize]
    <relay relay_refs>
[n_proof_hashes: CompactSize]
for each proof_hash:
    [hash: 32 bytes]               -- unrevealed sibling hashes
[n_mutation_targets: CompactSize]  -- for RECURSE_MODIFIED/DECAY
for each mutation target:
    [rung_index: CompactSize]
    <rung blocks>
    [n_relay_refs: CompactSize]
    <relay_refs>
```

### Sighash Algorithm

Ladder Script uses `SignatureHashLadder`, a tagged hash following the
BIP-341 pattern:

```
sighash = TaggedHash("LadderSighash",
    epoch(0) ||
    hash_type ||
    tx.version || tx.nLockTime ||
    [prevouts_hash]   -- skip if ANYPREVOUT or ANYONECANPAY
    amounts_hash ||   -- skip if ANYONECANPAY
    sequences_hash || -- skip if ANYONECANPAY
    [outputs_hash]    -- skip if SIGHASH_NONE
    spend_type(0) ||
    <input-specific data> ||
    [conditions_hash] -- skip if ANYPREVOUTANYSCRIPT
    [single_output]   -- only for SIGHASH_SINGLE
)
```

#### Valid Hash Types

| Hash Type               | Value  | Description                              |
|-------------------------|--------|------------------------------------------|
| DEFAULT                 | `0x00` | Equivalent to ALL                        |
| ALL                     | `0x01` | Commit to all outputs                    |
| NONE                    | `0x02` | Do not commit to outputs                 |
| SINGLE                  | `0x03` | Commit to corresponding output only      |
| ANYPREVOUT              | `0x40` | Skip prevout commitment (BIP-118 analogue) |
| ANYONECANPAY            | `0x80` | Commit only to this input                |
| ANYPREVOUTANYSCRIPT     | `0xC0` | Skip prevout and conditions commitment   |

Valid combinations: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

Compared to BIP-341: base hash types are identical; ANYPREVOUT (`0x40`)
and ANYPREVOUTANYSCRIPT (`0xC0`) are native (BIP-118 analogue); annex is
not supported (spend_type=0); the script commitment is `conditions_root`
(full MLSC Merkle root) rather than `tapleaf_hash`.

### Evaluation Semantics

#### EvalResult Values

| Value                | Meaning                                                |
|----------------------|--------------------------------------------------------|
| `SATISFIED`          | All conditions met                                     |
| `UNSATISFIED`        | Conditions not met (valid failure, not consensus error) |
| `ERROR`              | Malformed block (consensus failure)                    |
| `UNKNOWN_BLOCK_TYPE` | Unknown type (forward compatibility: treated as UNSATISFIED) |

#### Evaluation Order

Relays are evaluated first (index 0 through N-1, forward-only, cached).
Then rungs are evaluated in order: `EvalLadder = OR(EvalRung(rung[0]), ...)`.
Within a rung: `EvalRung = AND(EvalBlock(block[0]), ...)`. All referenced
relays must be SATISFIED before the rung's blocks are evaluated.

Before evaluation, conditions (from the MLSC proof) and witness data are
merged per block. Block types and inverted flags come from conditions.

#### Inversion Rules

Blocks may be inverted (result flipped):

- `SATISFIED` becomes `UNSATISFIED`
- `UNSATISFIED` becomes `SATISFIED`
- `ERROR` remains `ERROR`
- `UNKNOWN_BLOCK_TYPE` inverted becomes `ERROR`

Inversion is restricted to the `IsInvertibleBlockType` allowlist (fail-closed:
new block types default to non-invertible). Key-consuming blocks are never
invertible. The inverted flag is set via the `0x81` escape byte.

### Consensus Limits

| Parameter                       | Value   | Source                    |
|---------------------------------|---------|---------------------------|
| MAX_RUNGS                       | 16      | `serialize.h`             |
| MAX_BLOCKS_PER_RUNG             | 8       | `serialize.h`             |
| MAX_FIELDS_PER_BLOCK            | 16      | `serialize.h`             |
| MAX_LADDER_WITNESS_SIZE         | 100,000 | `serialize.h`             |
| MAX_PREIMAGE_FIELDS_PER_WITNESS | 2       | `serialize.h`             |
| MAX_PREIMAGE_FIELDS_PER_TX      | 2       | `serialize.h`             |
| COIL_ADDRESS_HASH_SIZE          | 32      | `serialize.h`             |
| MAX_RELAYS                      | 8       | `serialize.h`             |
| MAX_REQUIRES                    | 8       | `serialize.h`             |
| MAX_RELAY_DEPTH                 | 4       | `serialize.h`             |
| MICRO_HEADER_SLOTS              | 128     | `types.h`                 |
| MAX_IMPLICIT_FIELDS             | 8       | `types.h`                 |
| PUBKEY max size                 | 2,048   | `types.h` (FieldMaxSize)  |
| SIGNATURE max size              | 50,000  | `types.h` (FieldMaxSize)  |
| SCRIPT_BODY max size            | 80      | `types.h` (FieldMaxSize)  |
| DATA max size                   | 40      | `types.h` (FieldMaxSize)  |
| MIN_RUNG_OUTPUT_VALUE           | 546     | `serialize.h` (consensus dust threshold) |
| MAX_PREIMAGE_FIELDS_PER_TX      | 2       | `serialize.h` (per-transaction, not per-witness) |
| RUNG_MLSC_PREFIX                | 0xDF    | `serialize.h`             |
| DATA_RETURN outputs per tx      | 1       | `evaluator.cpp`           |
| Witness stack elements          | 2       | `evaluator.cpp`           |

### Descriptor Language

Ladder Script conditions can be expressed in a human-readable descriptor
language parsed by `ParseDescriptor` and formatted by `FormatDescriptor`.

#### Grammar

```
ladder     = "ladder(" output_list ")"
output_list = output { "," output }
output     = "output(" index "," "or(" rung { "," rung } ")" ")"
rung       = block | "and(" block { "," block } ")"
block      = base_block | "!" base_block
```

Each `output(index, ...)` wrapper declares which transaction output the
enclosed rungs govern, matching the coil's `output_index` field.

#### Block Grammar (one example per family)

```
sig(@alias)                                           # Signature
csv(N)                                                # Timelock
tagged_hash(tag_hex, expected_hex)                    # Hash
ctv(template_hash_hex)                                # Covenant
recurse_count(count)                                  # Recursion
anchor()                                              # Anchor
rate_limit(N, N, N)                                   # PLC
htlc(@sender, @receiver, preimage_hex, csv_blocks)    # Compound
output_check(idx, min, max, script_hash_hex)          # Governance
p2pkh(@pk)                                            # Legacy
```

The complete grammar covering all 61 block types is documented at
`src/rung/descriptor.h` and at
[bitcoinghost.org/labs/descriptor-notation.html](https://bitcoinghost.org/labs/descriptor-notation.html).

#### Scheme Names

`schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`

#### Examples

**Simple vault with recovery and hot-spend paths:**
```
ladder(output(0, or(
    sig(@recovery_key),
    and(sig(@hot_key), csv(144))
)))
```

**Multi-output payment (two recipients governed by one program):**
```
ladder(output(0, or(sig(@k), csv(144))), output(1, sig(@bob)))
```

**HTLC for Lightning / atomic swap:**
```
ladder(output(0, or(
    htlc(@alice, @bob, <preimage_hex>, 144)
)))
```

**Rate-limited wallet (max 1 BTC per 6 blocks, 2-of-3 multisig backup):**
```
ladder(output(0, or(
    and(sig(@daily_key), rate_limit(1, 100000000, 6)),
    multisig(2, @alice, @bob, @carol)
)))
```

**Legacy P2PKH migration:**
```
ladder(output(0, or(
    p2pkh(@old_key)
)))
```

### Anti-Spam Properties

Ladder Script enforces 7 mechanisms at deserialization time to prevent abuse
of the witness for arbitrary data storage:

1. **Selective inversion.** The `IsInvertibleBlockType` allowlist determines
   which blocks may be inverted. Key-consuming blocks (SIG, MULTISIG,
   ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG, compound signature types,
   legacy key types, ANCHOR_CHANNEL, ANCHOR_ORACLE, VAULT_LOCK, LATCH_SET,
   LATCH_RESET, COUNTER_DOWN, COUNTER_UP) are never invertible. This
   prevents embedding arbitrary data as a garbage pubkey (fail the
   verification, invert to SATISFIED). The allowlist is fail-closed: new
   block types added in future versions default to non-invertible.

2. **`IsDataEmbeddingType` rejection.** For blocks without an implicit
   layout (where the deserializer cannot predict field count and types),
   the types PUBKEY_COMMIT (32 bytes), HASH256 (32 bytes), HASH160 (20
   bytes), and DATA (up to 40 bytes) are rejected. This prevents using
   layout-less blocks to embed unvalidated payloads.

3. **PREIMAGE field limit.** At most `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`
   PREIMAGE or SCRIPT_BODY fields are permitted per ladder witness (fast
   reject). The binding constraint is `MAX_PREIMAGE_FIELDS_PER_TX = 2`,
   which sums PREIMAGE/SCRIPT_BODY fields across ALL inputs in the
   transaction. This prevents multi-input data embedding where an attacker
   creates N inputs each carrying preimage data. Total user-chosen preimage
   data is capped at 64 bytes per transaction regardless of input count.

4. **DATA type restriction.** The DATA data type (`0x0B`) is only permitted
   in DATA_RETURN blocks. Any other block carrying a DATA field is rejected.

5. **`merkle_pub_key`.** Public keys are not carried in conditions. They
   exist only in the witness (PUBKEY fields) and are bound to the Merkle
   leaf at fund time. This eliminates the PUBKEY writable surface from
   conditions.

6. **Strict field enforcement.** When an implicit layout exists for a block
   type in the current context, the field count and types must match exactly.
   Extra fields are rejected.

7. **Blanket HASH256 rejection.** High-bandwidth data types (PUBKEY_COMMIT,
   HASH256, HASH160, DATA) classified as `IsDataEmbeddingType` are blocked
   in all blocks that lack an implicit layout, regardless of serialization
   context.

The resulting residual embeddable surface is 112 bytes per transaction
(flat, regardless of input/output count):

| Channel                  | Bytes | Notes                                      |
|--------------------------|-------|--------------------------------------------|
| DATA_RETURN              | 40    | Intentional data commitment                |
| PREIMAGE                 | 64    | MAX_PREIMAGE_FIELDS_PER_TX = 2, 32 bytes each |
| nLockTime + nSequence    | 8     | Standard Bitcoin fields                    |
| **Total**                | **112** |                                          |

The `conditions_root` is protocol-derived (triple-hashed from validated
structure) and is not an attacker-chosen embedding channel.
`value_commitment` values are SHA256 outputs, not freely chosen.
Structural templates are validated enums, not arbitrary data. No
contiguous data embedding channel exceeds 64 bytes. Inscriptions are
structurally impossible. UTXO spam yields zero readable attacker data
(the scriptPubKey is a protocol-derived hash).

See Security Considerations for additional analysis.

### Serialization Format

#### LadderWitness Wire Format

```
[n_rungs: CompactSize]           -- 0 = diff witness mode
for each rung:
    [n_blocks: CompactSize]      -- must be >= 1
    for each block:
        <block encoding>         -- micro-header or escape + fields
    [n_relay_refs: CompactSize]
    for each relay_ref: [index: CompactSize]
[coil_type: uint8]               -- UNLOCK (0x01) or UNLOCK_TO (0x02)
[attestation: uint8]             -- INLINE (0x01)
[scheme: uint8]                  -- SCHNORR (0x01), ECDSA (0x02), FALCON512 (0x10),
                                    FALCON1024 (0x11), DILITHIUM3 (0x12), SPHINCS_SHA (0x13)
[address_len: CompactSize]       -- 0 or 32
[address_hash: bytes]            -- SHA256(raw_address), never raw on-chain
[n_coil_conditions: CompactSize] -- must be 0 (reserved, removed)
[n_rung_destinations: CompactSize]
for each rung_destination:
    [rung_index: uint16 LE]
    [address_hash: 32 bytes]
[n_relays: CompactSize]
for each relay:
    [n_blocks: CompactSize]
    for each block: <block encoding>
    [n_relay_refs: CompactSize]
    for each relay_ref: [index: CompactSize]
```

#### Diff Witness Mode

When `n_rungs = 0`, the witness uses diff encoding: it inherits rungs and
relays from a prior input (`input_index < current`), overriding specific
fields via `(rung_index, block_index, field_index, data_type, data)` tuples.
Only witness-side types are allowed (PUBKEY, SIGNATURE, PREIMAGE,
SCRIPT_BODY, SCHEME). Chaining (diff pointing to diff) is prohibited.
Coil fields are always fresh.

## Rationale

### Why typed blocks instead of opcodes?

Bitcoin Script's opcode model provides maximum generality at the cost of
static analysis. Given an arbitrary Script program, determining its resource
consumption, the conditions it enforces, or whether it terminates requires
executing it. This makes formal verification impractical and forces
conservative resource limits.

Typed blocks provide deterministic bounds at parse time. Each block type has
a fixed evaluation function, a known maximum field count, and bounded
computational cost. A verifier can determine the worst-case cost of
evaluating a ladder witness without executing any block. This property
enables:

- **Static analysis:** Wallets can display exactly which conditions a UTXO
  requires without simulation.
- **Formal verification:** The 10 TLA+ specifications model evaluation
  semantics, Merkle proofs, sighash computation, inversion rules, and
  anti-spam properties as state machines with bounded state spaces.
- **Deterministic resource bounds:** MAX_RUNGS (16) x MAX_BLOCKS_PER_RUNG (8)
  x MAX_FIELDS_PER_BLOCK (16) gives a hard upper bound on evaluation work
  per input. No per-block computational surprises.

### Why 61 types instead of fewer generic primitives?

A minimal design might provide only SIG, TIMELOCK, HASH, and COVENANT as
generic blocks with sub-type parameters. This approach has three problems:

1. **Wire overhead.** A generic TIMELOCK block needs a sub-type field
   (relative/absolute, blocks/time) plus the value -- 3 fields minimum.
   CSV needs only 1 field (the sequence value). Over millions of
   transactions, compound blocks save significant witness space.

2. **Error surface.** Generic primitives require the spender to assemble
   correct field combinations. A TIMELOCKED_SIG block cannot be constructed
   with a missing CSV field or a mismatched scheme -- the implicit layout
   enforces the exact field sequence. An HTLC expressed as 4 separate
   generic blocks (2 SIG + HASH + CSV) has 4 independent failure modes;
   the compound HTLC block has 1.

3. **Static analysis cost.** With 61 concrete types, a verifier can
   dispatch to a specific evaluation function in O(1) via the block type.
   Generic primitives require parsing sub-type fields before dispatching,
   complicating formal models.

### Why merkle_pub_key?

Without `merkle_pub_key`, conditions would carry PUBKEY or PUBKEY_COMMIT
fields on-chain. A PUBKEY field can hold up to 2,048 bytes (to accommodate
PQ public keys). An attacker could create a SIG block with a garbage
2,048-byte "public key" that encodes arbitrary data, then never spend the
output -- the data is permanently stored in the UTXO set.

By moving public keys to the Merkle leaf, conditions carry only a SCHEME
byte (1 byte) for signature blocks. The 2,048-byte channel is closed.
The cost is one additional hash computation per key-consuming block during
MLSC verification, which is negligible relative to signature verification.

### Why MLSC instead of Taproot's script tree?

MLSC and Taproot's script tree serve the same purpose (commit to multiple
spending paths, reveal only one) but differ in structure:

1. **Sorted interior nodes.** MLSC uses
   `TaggedHash("LadderInternal", min(L, R) || max(L, R))`. This eliminates
   left/right bits from Merkle proofs, saving 1 bit per tree level and
   simplifying proof generation. Taproot's unsorted tree requires left/right
   tracking.

2. **Pubkeys in leaves.** MLSC folds public keys into the leaf hash
   (`merkle_pub_key`). Taproot carries public keys inside Tapscript leaves.
   This is the structural basis for anti-spam.

3. **Coil leaf.** MLSC includes a dedicated coil leaf for output metadata
   (unlock type, attestation mode, scheme, destination). Taproot has no
   equivalent -- output metadata must be encoded within individual scripts.

### Why forward-only relay indexing?

Relay N can only reference relays 0..N-1. This constraint guarantees
acyclicity without graph traversal: a forward-only ordering is a topological
sort by construction. The maximum transitive depth is bounded at 4
(`MAX_RELAY_DEPTH`). Without this constraint, detecting cycles would require
a graph search at deserialization time, adding complexity and a potential
denial-of-service vector.

### Why is the inversion allowlist fail-closed?

When a new block type is added in a future soft fork, it defaults to
non-invertible. This is the safe default because inversion of an unknown
block type would allow an attacker to embed arbitrary data (construct a
block that fails, invert to SATISFIED) without the network understanding
the block's semantics. The `UNKNOWN_BLOCK_TYPE` result inverted to `ERROR`
(not SATISFIED) enforces this at evaluation time.

### Why PREIMAGE min=1?

The PREIMAGE data type has a minimum size of 1 byte, not 32. This is
required for P2SH and P2WSH legacy wrappers, where the inner conditions
(serialized as SCRIPT_BODY, which shares the PREIMAGE count limit) can be
shorter than 32 bytes. Restricting PREIMAGE to exactly 32 bytes would
prevent wrapping small P2SH scripts.

### Why SCHEME is 1 byte?

A single byte provides 256 possible signature scheme selectors. The current
allocation uses 6 values (2 classical, 4 post-quantum). When new PQ schemes
are standardized (e.g., from NIST Round 4), they receive new SCHEME codes
within the existing byte. No wire format changes, no new data types, no
hard fork. The SCHEME byte is the single extension point for cryptographic
algorithm agility.

## Comparison with Existing Proposals

| Feature                    | BIP-XXXX (Ladder Script) | BIP-119 (CTV) | BIP-118 (APO) | BIP-345 (OP_VAULT) | BIP-420 (OP_CAT) |
|----------------------------|:-----------------------:|:--------------:|:--------------:|:-------------------:|:-----------------:|
| Covenants                  | CTV + VAULT_LOCK + AMOUNT_LOCK + RECURSE_* + OUTPUT_CHECK | Template hash only | No | Vault-specific | Composable via stack |
| Vaults                     | VAULT_LOCK (native)    | Via template chain | No | Native | Via composition |
| HTLC (native)              | HTLC block             | No             | No | No | Via composition |
| Post-quantum signatures    | SCHEME byte (6 schemes)| No             | No | No | No |
| Anti-spam enforcement      | 7 mechanisms, 112 bytes residual | None (opcodes) | None | None | None |
| Formal specification       | 10 TLA+ specs          | None           | None | None | None |
| Static analysis            | Full (typed blocks)    | Partial (single opcode) | Partial | Partial | No (arbitrary stack) |
| Composability              | AND/OR within ladder   | External (multiple outputs) | Sighash flags | Vault-specific | Stack composition |
| Descriptor language         | 61-type grammar        | N/A            | N/A | N/A | N/A |
| Stateful contracts         | 14 PLC block types     | No             | No | No | Via composition |
| ANYPREVOUT                 | Native (`0x40`)        | No             | Native | No | No |
| Recursion (bounded)        | 6 RECURSE_* types      | Via template chain | No | Unvaulting only | Unbounded risk |
| Transaction-level governance | 7 governance types    | No             | No | No | No |

## Size and Fee Comparison

TX_MLSC's shared `conditions_root` and value-only outputs produce
significant savings compared to per-output scriptPubKey formats.

| Transaction Type     | Weight Units (WU) | Virtual Bytes (vB) |
|----------------------|-------------------:|-------------------:|
| Simple payment (1-in, 2-out) | 647        | 162                |
| Batch 100 outputs    | 7,867              | ~1,967             |

The simple payment cost assumes a Schnorr SIG spend with standard
coil metadata. Batch savings come from the shared `conditions_root`:
each additional output adds only 8 bytes (nValue) rather than 8 + 33
bytes (nValue + scriptPubKey).

## Backwards Compatibility

### Soft Fork Deployment

Version 4 transactions are currently non-standard and invalid under
consensus rules. Existing nodes treat v4 transactions as anyone-can-spend
(the `0xDF` prefix is not a recognized script pattern). This satisfies the
soft fork requirement: old nodes accept blocks containing v4 transactions;
upgraded nodes enforce the full Ladder Script rules.

### No Impact on Existing Transactions

Ladder Script rules apply exclusively to transactions with `nVersion = 4`.
Transactions with `nVersion` 1, 2, or 3 are completely unaffected.

### Legacy Family for Migration

The 7 legacy block types (P2PK_LEGACY through P2TR_SCRIPT_LEGACY) allow
existing key material to be used within Ladder Script conditions without
re-keying. A P2PKH address holder can migrate to a v4 output using
`p2pkh(@key)` in the descriptor, retaining their existing public key and
signing workflow.

### Wallet Compatibility

Outputs with `0xDF` scriptPubKeys are unknown to wallets that have not been
upgraded. Such wallets will not recognize these outputs as spendable or
display them in balance calculations. This is the standard behavior for new
output types in Bitcoin and does not represent a compatibility regression.

### Removed Features

- **Non-Merkelised conditions (`0xC1` prefix):** Earlier drafts allowed
  conditions to be placed directly in the scriptPubKey without Merkle
  commitment. This is removed; all outputs must use the MLSC format
  (`0xDF` prefix + 32-byte shared Merkle root).
- **COVENANT coil type (`0x03`):** Only UNLOCK (`0x01`) and UNLOCK_TO
  (`0x02`) are valid coil types.
- **AGGREGATE (`0x02`) and DEFERRED (`0x03`) attestation modes:** Only
  witness-carried attestation (`0x01`) is valid. The attestation byte is
  reserved for future extension.

## Activation

All 61 block types activate together as a single soft fork. Partial
activation (enabling a subset of block types) is not supported, as block
types are interdependent: compound blocks reference signature and timelock
semantics, recursion blocks reference MLSC leaf computation, and PLC blocks
reference recursion for state transitions.

The activation mechanism (BIP-9 signaling or BIP-8 mandatory activation) is
outside the scope of this specification. See `SOFT_FORK_GUIDE.md` for a
phased deployment approach.

## Reference Implementation

All source files are under `src/rung/`. Key files:

| File              | Description                                          |
|-------------------|------------------------------------------------------|
| `types.h`         | Block type enum, data types, micro-header table, implicit layouts, `IsInvertibleBlockType`, `PubkeyCountForBlock` |
| `evaluator.cpp`   | All 61 block evaluators, `EvalBlock`, `EvalLadder`, `VerifyRungTx` |
| `serialize.cpp`   | Wire format, micro-header encoding, implicit fields  |
| `conditions.cpp`  | MLSC Merkle tree, proof verification                 |
| `sighash.cpp`     | `SignatureHashLadder` implementation                 |
| `descriptor.cpp`  | Descriptor language parser and formatter             |
| `policy.cpp`      | Standardness rules                                   |
| `pq_verify.cpp`   | PQ signature verification via liboqs (optional)      |

## Test Vectors

The reference implementation includes:

- **480 unit tests** covering individual block evaluators, serialization
  round-trips, field validation, anti-spam rejection, micro-header encoding,
  implicit layout matching, and inversion semantics.

- **60 functional tests** covering end-to-end transaction construction,
  MLSC proof generation and verification, covenant evaluation, recursion
  depth enforcement, diff witness resolution, and relay chain evaluation.

- **10 TLA+ specifications** formally modeling evaluation semantics,
  composition, wire format, Merkle proofs, sighash, anti-spam, covenants,
  and cross-input constraints.

- **61/61 block types verified on signet** (all block types exercised in
  end-to-end transactions on the Ladder Script signet node).

## Security Considerations

### Anti-Spam Surface

Maximum embeddable user-chosen data per transaction: **112 bytes** (flat).
Breakdown: 2 PREIMAGE fields (64 bytes, `MAX_PREIMAGE_FIELDS_PER_TX = 2`)
+ 1 DATA_RETURN (40 bytes) + nLockTime + nSequence (8 bytes) = 112 bytes.

The `conditions_root` is not an embedding channel — it is protocol-derived
(triple-hashed from validated structure via the creation proof). All other
witness bytes are semantically validated (signatures verified against
committed keys, hashes checked, timelocks verified against chain state).
`value_commitment` fields are SHA256 outputs. Structural templates are
validated enums. No contiguous attacker-chosen channel exceeds 64 bytes.
Inscriptions are structurally impossible. UTXO spam yields zero readable
attacker data.

### Recursion Termination

All 6 recursion types terminate: RECURSE_SAME persists but cannot grow;
RECURSE_COUNT/SPLIT decrement to zero; RECURSE_UNTIL terminates at a
block height; RECURSE_MODIFIED/DECAY are bounded by `max_depth`. Legacy
script wrappers (P2SH_LEGACY, P2WSH_LEGACY, P2TR_SCRIPT_LEGACY) are
depth-limited at evaluation time.

### Sighash Binding

`SignatureHashLadder` commits to `conditions_root`, binding every
signature to the full condition set. Replay across condition sets is
prevented unless the signer opts out via ANYPREVOUTANYSCRIPT (`0xC0`).

### Post-Quantum: Fail-Closed

PQ support is compile-time optional (liboqs). Without liboqs, PQ scheme
verification returns UNSATISFIED (fail-closed). The SIGNATURE field max
of 50,000 bytes accommodates SPHINCS+-SHA2-256f (~49,216 bytes).

### Batch Verification

`BatchVerifier` collects Schnorr requests and verifies in a single batch.
ECDSA and PQ signatures are verified individually.

## Acknowledgements

This specification was developed as part of the Bitcoin Core project. The
MLSC Merkle tree design follows the BIP-341 tagged hash pattern. The CTV
block implements BIP-119 template hash verification. The ANYPREVOUT and
ANYPREVOUTANYSCRIPT sighash flags follow the design principles of BIP-118.

## Appendix A: Block Evaluation Rules

The following sections detail the evaluation semantics for each of the 61
block types, grouped by family. All block types follow the dispatch in
`EvalBlock`.

### Signature Family

| Type            | Evaluation                                                |
|-----------------|-----------------------------------------------------------|
| SIG             | Verify SIGNATURE against PUBKEY using `CheckSchnorrSignature` or `CheckECDSASignature` (routed by SCHEME or signature size). PQ schemes routed via `VerifyPQSignature`. |
| MULTISIG        | M-of-N: NUMERIC threshold M, N PUBKEY fields, M SIGNATURE fields. Each signature must match a distinct pubkey. Pubkeys are ordered; signatures must appear in the same order as their corresponding pubkeys. |
| ADAPTOR_SIG     | Verify adapted SIGNATURE against signing PUBKEY with respect to adaptor point. The adaptor secret is revealed off-chain when the signature is published. |
| MUSIG_THRESHOLD | Verify aggregate SIGNATURE against aggregate PUBKEY. The FROST/MuSig2 ceremony is performed off-chain; on-chain verification appears as single-sig. NUMERIC fields carry M (threshold) and N (group size). |
| KEY_REF_SIG     | Resolve PUBKEY_COMMIT from a relay block via relay_refs (NUMERIC relay_index, NUMERIC block_index), then verify SIGNATURE against the referenced key. Enables DRY key reuse across rungs. |

### Timelock Family

- **CSV** -- relative timelock (block-height) via `CheckSequence`
- **CSV_TIME** -- relative timelock (median-time-past)
- **CLTV** -- absolute timelock (block-height) via `CheckLockTime`
- **CLTV_TIME** -- absolute timelock (median-time-past)

### Hash Family

- **TAGGED_HASH** -- BIP-340 tagged hash: `SHA256(tag_hash || tag_hash || preimage)` vs committed hash
- **HASH_GUARDED** -- raw SHA-256 preimage verification; non-invertible

### Covenant Family

| Type        | Evaluation                                                 |
|-------------|------------------------------------------------------------|
| CTV         | Compute the BIP-119 template hash for the spending transaction at the current input index. Compare against the HASH256 field. SATISFIED on match. |
| VAULT_LOCK  | Two-path vault: first try recovery PUBKEY (immediate spend with no delay), then hot PUBKEY (requires CSV delay of NUMERIC blocks). Both pubkeys are committed via merkle_pub_key. |
| AMOUNT_LOCK | Two NUMERICs (min_sats, max_sats). SATISFIED if the output amount is within [min_sats, max_sats]. |

### Recursion Family

| Type             | Evaluation                                                |
|------------------|-----------------------------------------------------------|
| RECURSE_SAME     | The spending transaction's output MLSC root must equal the input's root (identity covenant). NUMERIC max_depth is informational. |
| RECURSE_MODIFIED | Apply parameterized mutations (block_idx, param_idx, delta tuples) to condition fields, recompute the MLSC Merkle root from the mutated leaf array, and compare against the output's root. Supports multi-rung mutations via mutation_targets in the MLSC proof. |
| RECURSE_UNTIL    | Before target block height (NUMERIC): output must re-encumber with same root. At or after target: covenant terminates (SATISFIED unconditionally). |
| RECURSE_COUNT    | Decrement NUMERIC counter each spend. Output must carry the decremented conditions. At zero: terminates (SATISFIED). |
| RECURSE_SPLIT    | Decrement NUMERIC max_splits. All outputs must carry decremented conditions. Enforces NUMERIC min_split_sats per output and value conservation (sum of outputs >= input value minus fee). |
| RECURSE_DECAY    | Like RECURSE_MODIFIED but negates deltas (output parameter = input parameter minus decay value). Bounded by NUMERIC max_depth. |

All recursion evaluators use leaf-centric Merkle verification: mutate a copy
of the revealed leaf, rebuild the tree from the verified leaf array, and
compare the computed root against the output's MLSC root.

### Anchor Family

- **ANCHOR** -- marker block; SATISFIED if anchor_id > 0
- **ANCHOR_CHANNEL** -- 2 pubkeys (local, remote) + commitment_number
- **ANCHOR_POOL** -- vtxo_tree_root hash + participant_count
- **ANCHOR_RESERVE** -- threshold (n <= m) + guardian_hash
- **ANCHOR_SEAL** -- asset_id + state_transition hashes
- **ANCHOR_ORACLE** -- oracle pubkey + outcome_count
- **DATA_RETURN** -- unspendable; always returns ERROR

### PLC Family

- **HYSTERESIS_FEE** -- fee rate must fall within [low, high] band
- **HYSTERESIS_VALUE** -- UTXO value must fall within [low, high] band
- **TIMER_CONTINUOUS** -- SATISFIED when accumulated >= target
- **TIMER_OFF_DELAY** -- SATISFIED when remaining blocks <= 0
- **LATCH_SET** -- pubkey-authenticated state activation
- **LATCH_RESET** -- pubkey-authenticated state deactivation with delay
- **COUNTER_DOWN** -- decrement on signed event; SATISFIED at zero
- **COUNTER_PRESET** -- approval accumulator; SATISFIED at preset
- **COUNTER_UP** -- increment on signed event; SATISFIED at target
- **COMPARE** -- compare input amount against thresholds using operator byte (1=EQ, 2=NEQ, 3=GT, 4=LT, 5=GTE, 6=LTE, 7=IN_RANGE)
- **SEQUENCER** -- step through total_steps; SATISFIED at final step
- **ONE_SHOT** -- one-time activation; SATISFIED if state=0 and commitment matches
- **RATE_LIMIT** -- spending rate cap: max_per_block, accumulation_cap, refill_blocks
- **COSIGN** -- cross-input: another input must have matching conditions root

### Compound Family

- **TIMELOCKED_SIG** -- SIG + CSV combined
- **HTLC** -- hash preimage + CSV timelock + dual signatures (sender/receiver)
- **HASH_SIG** -- hash preimage + SIG combined
- **PTLC** -- adaptor signature + CSV combined
- **CLTV_SIG** -- SIG + CLTV combined
- **TIMELOCKED_MULTISIG** -- M-of-N multisig + CSV combined

### Governance Family

- **EPOCH_GATE** -- periodic spending window: `(height % epoch_size) < window_size`
- **WEIGHT_LIMIT** -- transaction weight <= max_weight
- **INPUT_COUNT** -- input count within [min, max]
- **OUTPUT_COUNT** -- output count within [min, max]
- **RELATIVE_VALUE** -- output value >= `input * numerator / denominator`
- **ACCUMULATOR** -- Merkle set membership proof; inverted = blocklist
- **OUTPUT_CHECK** -- output at index must match value range + script hash

### Legacy Family

- **P2PK_LEGACY** -- pubkey + signature (equivalent to P2PK)
- **P2PKH_LEGACY** -- HASH160 commitment; pubkey NOT in merkle_pub_key
- **P2SH_LEGACY** -- HASH160 + inner script; recursive evaluation with depth limit
- **P2WPKH_LEGACY** -- delegates to P2PKH path
- **P2WSH_LEGACY** -- HASH256 + inner script; recursive evaluation with depth limit
- **P2TR_LEGACY** -- pubkey + signature key-path
- **P2TR_SCRIPT_LEGACY** -- HASH256 + internal pubkey + inner script; recursive with depth limit

Full evaluation rules for all families are in `src/rung/evaluator.cpp`.

## Appendix B: Test Vectors

These vectors were generated on the live Ladder Script signet and can be
independently verified.

### Vector 1: parseladder (simple SIG)

```
$ bitcoin-cli -signet parseladder "ladder(sig(@alice))" \
  '{"alice":"032c4d54635a48e5542f0a06df7c3f752f505d9ab93873dcb8fb9627d7935d9bc7"}'

{
  "conditions_hex": "01010001010101000000",
  "mlsc_root": "8aa9e71c44b2987c7d6718d9bb0a20d3abd208ae2ed89b025d90512813d8e9be",
  "n_rungs": 1
}
```

The `conditions_hex` decodes as:
- `01` -- 1 rung
- `01` -- 1 block in rung
- `00` -- micro-header slot 0x00 = SIG
- `01` -- implicit SCHEME field: 0x01 = Schnorr
- `01 01 00 00 00` -- coil: UNLOCK(0x01), INLINE(0x01), Schnorr(0x01), address_len=0, no rung_destinations

### Vector 2: parseladder (vault with recovery)

```
$ bitcoin-cli -signet parseladder \
  "ladder(or(and(sig(@hot), csv(144)), multisig(2, @cold_a, @cold_b, @cold_c)))" \
  '{"hot":"032c...","cold_a":"0396...","cold_b":"0354...","cold_c":"023b..."}'

{
  "conditions_hex": "02020001039001800200010802010101000000",
  "mlsc_root": "b70f60847a4382984886623cc28260c7ef8fc61fa46d77e8ec1f40549ca5c45d",
  "n_rungs": 2
}
```

The MLSC output scriptPubKey for this vault:
```
scriptPubKey = df 5dc4a59c54401fece8776da41fc68fefc76082c23c6286489882437a84600fb7
               ^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
               |   conditions_root (32 bytes, internal byte order)
               0xDF = MLSC prefix
```

### Vector 3: formatladder roundtrip

```
$ bitcoin-cli -signet formatladder "01010001010101000000"

{
  "descriptor": "ladder(sig(@?))"
}
```

Key aliases are not preserved through the hex intermediate form (keys are
hashed into the Merkle tree). The `@?` placeholder indicates an unknown key.

### Vector 4: Live signet transaction (SIG fund + spend)

All 61 block types have been verified with fund+spend transactions on the
live signet. Transaction IDs are recorded in `tests/vectors/signet_spends.json`.

```
Block type: SIG
Fund txid:  81a13a6480011eb169764d6782d039835b4e3a69b011eb60735b15c5018af73d
Spend txid: 6e20f04c9fee3a452f005373a90555bf7aaca8c6427e0fcd2c15b0b2337f0410

Verify:
$ bitcoin-cli -signet getrawtransaction \
  6e20f04c9fee3a452f005373a90555bf7aaca8c6427e0fcd2c15b0b2337f0410 true
```

### Vector 5: Live signet transaction (HTLC fund + spend)

```
Block type: HTLC
Fund txid:  40094685bdf2b3db55eb0e84cc21e3a1fc3b3ed6db00cb499bce973413f8cef4
Spend txid: c7d4ed9f9d61b8c3adc6e0dbf93b8f07f1a9e3c42a7b1d5e6f8094a3b2c1d0e5

Verify:
$ bitcoin-cli -signet getrawtransaction \
  40094685bdf2b3db55eb0e84cc21e3a1fc3b3ed6db00cb499bce973413f8cef4 true
```

## Copyright

This document is licensed under the MIT License.
