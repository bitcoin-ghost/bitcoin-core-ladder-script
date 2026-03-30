```
BIP: XXXX
Title: Ladder Script: Typed Transaction Conditions for Bitcoin
Author: Defenwycke <defenwycke@icloud.com>
Status: Draft
Type: Standards Track
Layer: Consensus (soft fork)
Created: 2026-03-16
License: MIT
Post-History: https://groups.google.com/g/bitcoindev/c/0jEHXaQaeZw
```

## Abstract

Ladder Script is a typed transaction condition format for Bitcoin. It replaces
raw opcodes with 62 typed function blocks organised into 10 families. Every
witness byte belongs to a typed field with enforced size constraints; no
arbitrary data pushes are possible. Spending conditions are structured as a
ladder of rungs (OR logic), where each rung contains one or more blocks (AND
logic). Transactions commit to a single shared Merkle root of conditions
(`conditions_root`) per transaction via Merkelised Ladder Script Conditions
(MLSC), revealing only the satisfied spending path. Ladder Script transactions
use `nVersion = 4`.

## Copyright

This document is licensed under the MIT License.

## Motivation

### What Bitcoin Cannot Do Today

There are things people need to build on Bitcoin that Bitcoin Script cannot
express -- not "difficult to express," but impossible:

- **Vaults with clawback.** A hot key for daily spending with a cold key
  that can sweep immediately if the hot key is compromised. Requires
  introspection of spending transaction outputs. BIP-345 proposes this but
  is not activated.

- **Rate-limited wallets.** Cap how many satoshis can leave a wallet per
  block, even if the signing key is stolen. No opcode inspects spending
  rate across blocks.

- **Recursive covenants.** A UTXO that enforces conditions on its own
  spending outputs -- DCA schedules, graduated vesting, binary splits.
  Requires output introspection that Script cannot do without CTV or
  OP_CAT, neither of which is activated.

- **Transaction-level governance.** Enforce that a treasury spend routes
  funds to a specific address, or that transaction weight stays under a
  limit, or that spending is only permitted during certain block-height
  windows. Script has no output introspection beyond signature checks.

- **Composable conditions.** A vault with rate-limiting AND multisig
  recovery AND a time-locked heir clause -- all in one UTXO. Each proposed
  opcode (CTV, APO, OP_VAULT) addresses one use case. They were not
  designed to compose.

Ladder Script makes all of these possible as native block types, composable
with AND/OR logic:

```
ladder(output(0, or(
    and(sig(@hot_key), csv(144), amount_lock(0, 1000000), rate_limit(1, 10, 6)),
    multisig(2, @cold_a, @cold_b, @cold_c)
)))
```

### Key Advantages

| Metric | Ladder Script | Taproot (status quo) | Improvement |
|--------|--------------|---------------------|-------------|
| Cheapest transaction | 110 vB (key-path) | 111 vB (key-path) | Tied |
| UTXO set per output | ~8 bytes | ~48 bytes | 6x smaller |
| Max outputs per tx | 252 (8 bytes each) | ~2,300 (43 bytes each) | 5.4x less wire per output |
| Embeddable data per tx | 144 bytes (flat) | ~4 MB (witness) | 27,000x tighter |
| Post-quantum ready | Yes (SCHEME byte) | No | Native PQ slot |
| Covenant support | 62 native block types | None | Full covenant system |
| Formal verification | 21 TLA+ specs | None | Unprecedented |
| Proposals replaced | 8 | N/A | One fork, not eight |

### The Seven Gaps -- One Fork

Ladder Script addresses every major capability gap Bitcoin builders face.
Each gap maps to specific block types that implement the solution.

| # | Gap | Solution | Block Types |
|---|-----|----------|-------------|
| 1 | Introspection | Typed blocks inspect tx structure | OUTPUT_CHECK, AMOUNT_LOCK, RELATIVE_VALUE, INPUT_COUNT, OUTPUT_COUNT, CTV, COSIGN |
| 2 | Native covenants | First-class recursive covenants | 6 RECURSE_* blocks, VAULT_LOCK, CTV, ACCUMULATOR |
| 3 | PQ signatures | 1-byte SCHEME field routes to PQ algorithms | SIG with FALCON-512/1024, Dilithium3, SPHINCS+ |
| 4 | L2 sighash | ANYPREVOUT native flags | Sighash `0x40` (APO), `0xC0` (APOAS) -- enables Eltoo/LN-Symmetry |
| 5 | Structured metadata | Typed, bounded data commitment | DATA_RETURN block, DATA field (1-40 bytes) |
| 6 | Batch validation | Cross-input signature aggregation | `aggregated_sig` field, half-aggregation, BatchVerifier |
| 7 | Fee pinning | Anti-pinning by consensus | ANCHOR_FEE: 2-of-2 sigs + fee band + weight limit |

### Proposals Superseded

| Existing Proposal | Ladder Script Equivalent |
|-------------------|-------------------------|
| BIP-119 (CTV) | CTV block (`0x0301`) |
| BIP-118 (ANYPREVOUT) | Sighash flag `0x40` / `0xC0` |
| BIP-345 (OP_VAULT) | VAULT_LOCK block (`0x0302`) |
| OP_CAT | Unnecessary -- RECURSE_* covenants |
| OP_CHECKSIGFROMSTACK | TAGGED_HASH block (`0x0203`) |
| BIP-443 (MATT/OP_CCV) | ACCUMULATOR block (`0x0806`) |
| OP_TXHASH | OUTPUT_CHECK (`0x0807`) + CTV |
| P2QRH | SCHEME field handles PQ natively |

All eight capabilities activate in a single soft fork. After activation, no
further Script changes are needed.

### Before and After

**HTLC -- Before (raw Script, 11 opcodes):**

```
OP_IF
  OP_SHA256 <hash> OP_EQUALVERIFY
  <receiver_pubkey> OP_CHECKSIG
OP_ELSE
  <144> OP_CHECKSEQUENCEVERIFY OP_DROP
  <sender_pubkey> OP_CHECKSIG
OP_ENDIF
```

**HTLC -- After (Ladder Script descriptor):**

```
ladder(output(0, htlc(@sender, @receiver, <preimage>, 144)))
```

One typed block. Fixed field layout. Static analysis. Deterministic cost.
Only the spending path revealed on-chain; the refund path stays private via
MLSC.

## Design Overview

### The Ladder Metaphor

A Ladder Script condition set is a **ladder**: a list of **rungs** connected
by OR logic. Each rung contains one or more **blocks** connected by AND
logic. To spend an output, the spender must satisfy all blocks in at least
one rung.

```
Ladder (OR)
  +-- Rung 0: sig(@alice)                          [single signer]
  +-- Rung 1: and(sig(@bob), csv(144))             [backup after 1 day]
  +-- Rung 2: multisig(2, @alice, @bob, @carol)    [2-of-3 multisig]
```

Each rung may reference **relays** -- shared condition blocks evaluated once
and cached. The **coil** is per-output metadata: unlock type (UNLOCK or
UNLOCK_TO), attestation mode, signature scheme, optional destination address,
and `output_index` declaring which output the rung governs.

### merkle_pub_key

In most covenant systems, public keys appear in locking conditions on-chain,
creating a writable surface for data embedding. An attacker can commit an
arbitrary 33-byte "public key" that encodes data rather than a valid point.

Ladder Script moves public keys out of conditions entirely. At fund time,
public keys are hashed into the Merkle leaf alongside serialized condition
blocks. Conditions carry only a SCHEME byte (1 byte) for signature blocks.
At spend time, the witness provides actual public keys, and the verifier
recomputes the Merkle leaf to confirm they match the commitment.

This eliminates the largest unvalidated data channel (up to 2,048 bytes per
PUBKEY field) from the conditions side without any loss of functionality.

### TX_MLSC Format

TX_MLSC transactions carry one shared `conditions_root` per transaction (not
per output). The transaction uses a PLC model: one ladder program with
multiple output coils. Each rung's coil includes an `output_index` field
declaring which output it governs.

The `conditions_root` commits to the root of a Merkle tree whose leaves are
individual rungs, relays, and coil metadata. At spend time, only the
satisfied rung (and any referenced relays) are revealed; all other spending
paths remain hidden behind Merkle proof hashes. A creation proof is included
in the witness and validated at block acceptance.

## Specification

### Transaction Format

A Ladder Script transaction has `nVersion = 4`. The flag byte `0x02` signals
RUNG_TX format (analogous to SegWit's `0x01`).

#### Wire Layout

```
[nVersion: int32]                    -- must be 4
[flag: 0x00 0x02]                    -- TX_MLSC signal
[input_count: CompactSize]
for each input:
    [prevout: 36 bytes]
    [scriptSig_len: CompactSize]     -- must be 0
    [nSequence: uint32]
[conditions_root: 32 bytes]          -- shared MLSC root
[output_count: CompactSize]
for each output:
    [nValue: int64]                  -- 8 bytes only (no scriptPubKey)
for each input:
    [witness_count: CompactSize]
    [witness[0]: LadderWitness]
    [witness[1]: MLSCProof]
[creation_proof: bytes]
[nLockTime: uint32]
```

The `conditions_root` appears between inputs and outputs. Each output is
8 bytes (nValue only). On deserialization, outputs are inflated to
`CTxOut(nValue, 0xDF || conditions_root)`, producing the standard 33-byte
MLSC commitment for each output.

All inputs MUST provide exactly 2 witness elements:

- `witness[0]`: Serialized `LadderWitness` (spending proof)
- `witness[1]`: Serialized `MLSCProof` (revealed conditions + Merkle proof)

#### Verification (VerifyRungTx, 8 steps)

1. Validate all outputs via `ValidateRungOutputs` (33-byte `0xDF` prefix)
2. Deserialize `LadderWitness` from `witness[0]`
3. Resolve witness references if diff encoding is used
4. Deserialize `MLSCProof` from `witness[1]`
5. Extract pubkeys from witness for `merkle_pub_key` leaf computation
6. Verify Merkle proof against the UTXO's `conditions_root`
7. Merge conditions (from proof) with witness (from `witness[0]`)
8. Evaluate the merged ladder via `EvalLadder`

### Output Format and UTXO Deduplication

On the wire, TX_MLSC outputs are 8 bytes each. On deserialization:

```
scriptPubKey = 0xDF || conditions_root   (33 bytes)
```

The `conditions_root` is shared across all outputs. This produces ~8 bytes
per UTXO set entry vs ~48 bytes for Taproot (6x reduction).

**DATA_RETURN outputs:** An output with `nValue == 0` is a DATA_RETURN
output. On the wire, it is followed by `[payload_len: CompactSize]
[payload: bytes]` (max 40 bytes). At most one DATA_RETURN output per
transaction.

### Data Types

Every field carries one of 11 data types with enforced size constraints.

| Code | Name | Min | Max | Context | Description |
|------|------|-----|-----|---------|-------------|
| `0x01` | PUBKEY | 1 | 2,048 | Witness | Public key (folded into Merkle leaf via merkle_pub_key) |
| `0x02` | PUBKEY_COMMIT | 32 | 32 | Witness | SHA-256 of pubkey |
| `0x03` | HASH256 | 32 | 32 | Both | SHA-256 hash |
| `0x04` | HASH160 | 20 | 20 | Both | RIPEMD160(SHA256()) |
| `0x05` | PREIMAGE | 1 | 32 | Witness | Hash preimage |
| `0x06` | SIGNATURE | 1 | 50,000 | Witness | Signature (Schnorr 64-65, ECDSA 8-72, PQ up to 49,216) |
| `0x07` | SPEND_INDEX | 4 | 4 | Both | Spend index reference |
| `0x08` | NUMERIC | 1 | 4 | Both | Numeric value (CompactSize on wire) |
| `0x09` | SCHEME | 1 | 1 | Both | Signature scheme selector |
| `0x0A` | SCRIPT_BODY | 1 | 80 | Witness | Inner conditions (legacy wrappers) |
| `0x0B` | DATA | 1 | 40 | Conditions | Opaque data (DATA_RETURN only; hash + protocol ref) |

**Condition-side types:** HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX,
DATA. The types PUBKEY, PUBKEY_COMMIT, SIGNATURE, PREIMAGE, and SCRIPT_BODY
are witness-only and rejected in conditions context.

PREIMAGE minimum is 1 byte (not 32) to accommodate P2SH/P2WSH inner
conditions shorter than 32 bytes. See Rationale.

### Block Type Families

Ladder Script defines 62 block types across 10 families. Each block type is
encoded as `uint16_t` (little-endian) on the wire.

#### 1. Signature Family (0x0001-0x0005)

Pubkeys are bound to the MLSC Merkle leaf via `merkle_pub_key`; conditions
carry only the SCHEME byte.

| Code | Name | Description |
|------|------|-------------|
| `0x0001` | SIG | Single signature verification |
| `0x0002` | MULTISIG | M-of-N threshold signature |
| `0x0003` | ADAPTOR_SIG | Adaptor signature (atomic swap secret revelation) |
| `0x0004` | MUSIG_THRESHOLD | MuSig2/FROST aggregate threshold |
| `0x0005` | KEY_REF_SIG | Signature using key commitment from a relay block |

#### 2. Timelock Family (0x0101-0x0104)

| Code | Name | Description |
|------|------|-------------|
| `0x0101` | CSV | Relative timelock, block-height (BIP-68) |
| `0x0102` | CSV_TIME | Relative timelock, median-time-past |
| `0x0103` | CLTV | Absolute timelock, block-height (nLockTime) |
| `0x0104` | CLTV_TIME | Absolute timelock, median-time-past |

#### 3. Hash Family (0x0203-0x0204)

| Code | Name | Description |
|------|------|-------------|
| `0x0203` | TAGGED_HASH | BIP-340 tagged hash verification |
| `0x0204` | HASH_GUARDED | Raw SHA-256 preimage verification (non-invertible) |

#### 4. Covenant Family (0x0301-0x0303)

| Code | Name | Description |
|------|------|-------------|
| `0x0301` | CTV | OP_CHECKTEMPLATEVERIFY (BIP-119) |
| `0x0302` | VAULT_LOCK | Two-path vault: recovery key (immediate) or hot key (delayed) |
| `0x0303` | AMOUNT_LOCK | Output amount range check [min_sats, max_sats] |

#### 5. Recursion Family (0x0401-0x0406)

All 6 types are bounded. RECURSE_SAME persists indefinitely but cannot grow.

| Code | Name | Description |
|------|------|-------------|
| `0x0401` | RECURSE_SAME | Re-encumber with identical conditions |
| `0x0402` | RECURSE_MODIFIED | Re-encumber with parameterized mutations |
| `0x0403` | RECURSE_UNTIL | Recursive until target block height |
| `0x0404` | RECURSE_COUNT | Countdown (terminates at zero) |
| `0x0405` | RECURSE_SPLIT | Output splitting with value conservation |
| `0x0406` | RECURSE_DECAY | Parameter decay (negated deltas) |

#### 6. Anchor Family (0x0501-0x0507)

L2 protocol markers and the DATA_RETURN block.

| Code | Name | Description |
|------|------|-------------|
| `0x0501` | ANCHOR | Generic anchor marker |
| `0x0502` | ANCHOR_CHANNEL | Lightning channel anchor (2 pubkeys + commitment_number) |
| `0x0503` | ANCHOR_POOL | Pool anchor (VTXO tree root + participant_count) |
| `0x0504` | ANCHOR_RESERVE | Reserve anchor (guardian threshold) |
| `0x0505` | ANCHOR_SEAL | Seal anchor (asset_id + state_hash) |
| `0x0506` | ANCHOR_ORACLE | Oracle anchor (oracle pubkey + outcome_count) |
| `0x0507` | DATA_RETURN | Unspendable data commitment (max 40 bytes, replaces OP_RETURN) |

#### 7. PLC Family (0x0601-0x0681)

Stateful contract primitives driven by RECURSE_MODIFIED state transitions.

| Code | Name | Description |
|------|------|-------------|
| `0x0601` | HYSTERESIS_FEE | Fee rate hysteresis band |
| `0x0602` | HYSTERESIS_VALUE | Value hysteresis band |
| `0x0611` | TIMER_CONTINUOUS | Consecutive-block timer |
| `0x0612` | TIMER_OFF_DELAY | Hold-after-trigger timer |
| `0x0621` | LATCH_SET | State activation via signed event |
| `0x0622` | LATCH_RESET | State deactivation with delay |
| `0x0631` | COUNTER_DOWN | Decrement on signed event |
| `0x0632` | COUNTER_PRESET | Approval accumulator |
| `0x0633` | COUNTER_UP | Increment on signed event |
| `0x0641` | COMPARE | Amount vs thresholds (EQ/NEQ/GT/LT/GTE/LTE/IN_RANGE) |
| `0x0651` | SEQUENCER | Step sequencer (SATISFIED at final step) |
| `0x0661` | ONE_SHOT | One-time activation window |
| `0x0671` | RATE_LIMIT | Per-block spending cap with accumulation and refill |
| `0x0681` | COSIGN | Cross-input co-spend constraint |

#### 8. Compound Family (0x0701-0x0707)

Common multi-block patterns collapsed into single blocks.

| Code | Name | Composition |
|------|------|-------------|
| `0x0701` | TIMELOCKED_SIG | SIG + CSV |
| `0x0702` | HTLC | Hash + CSV + dual-SIG (atomic swap) |
| `0x0703` | HASH_SIG | Hash preimage + SIG |
| `0x0704` | PTLC | ADAPTOR_SIG + CSV (point-locked) |
| `0x0705` | CLTV_SIG | SIG + CLTV |
| `0x0706` | TIMELOCKED_MULTISIG | MULTISIG + CSV |
| `0x0707` | ANCHOR_FEE | 2-of-2 sigs + fee band + weight limit |

#### 9. Governance Family (0x0801-0x0807)

Transaction-level constraints beyond individual input authorisation.

| Code | Name | Description |
|------|------|-------------|
| `0x0801` | EPOCH_GATE | Periodic spending window (block-height epochs) |
| `0x0802` | WEIGHT_LIMIT | Maximum transaction weight |
| `0x0803` | INPUT_COUNT | Input count bounds [min, max] |
| `0x0804` | OUTPUT_COUNT | Output count bounds [min, max] |
| `0x0805` | RELATIVE_VALUE | Output value as ratio of input value |
| `0x0806` | ACCUMULATOR | Merkle set membership proof |
| `0x0807` | OUTPUT_CHECK | Per-output value range + script hash constraint |

#### 10. Legacy Family (0x0901-0x0907)

Wrappers for existing Bitcoin output types. Migration without re-keying.

| Code | Name | Wraps |
|------|------|-------|
| `0x0901` | P2PK_LEGACY | P2PK |
| `0x0902` | P2PKH_LEGACY | P2PKH |
| `0x0903` | P2SH_LEGACY | P2SH (hash160 + inner script) |
| `0x0904` | P2WPKH_LEGACY | P2WPKH (delegates to P2PKH path) |
| `0x0905` | P2WSH_LEGACY | P2WSH (hash256 + inner script) |
| `0x0906` | P2TR_LEGACY | P2TR key-path |
| `0x0907` | P2TR_SCRIPT_LEGACY | P2TR script-path |

### Wire Format

Blocks are encoded with micro-headers and implicit field layouts, minimizing
witness size while maintaining full type safety.

#### Block Header

Each block begins with a single header byte:

| Byte | Meaning |
|------|---------|
| `0x00`-`0x3E` | Micro-header slot index (block type from table, not inverted) |
| `0x3F`-`0x7F` | Reserved (rejected at deserialization) |
| `0x80` | Escape: `uint16_t` block type follows (LE), not inverted |
| `0x81` | Escape: `uint16_t` block type follows (LE), inverted |

#### Implicit Fields

When a micro-header is used and an implicit field layout exists for the block
type in the current context (WITNESS or CONDITIONS), field count and type
bytes are omitted. Fields are read by layout:

- **NUMERIC:** CompactSize value, no length prefix. Deserialized to 4-byte LE.
- **Fixed-size** (HASH256=32, SCHEME=1): data directly, no length prefix.
- **Variable-size** (PUBKEY, SIGNATURE, PREIMAGE): CompactSize length prefix + data.

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

SIG block, CONDITIONS context (micro-header, implicit layout):
`00 01` -- slot 0x00 (SIG), SCHEME 0x01 (Schnorr). Total: 2 bytes.

Inverted CSV block (escape byte, explicit fields):
`81 01 01 01 08 90 01` -- escape(inverted), type 0x0101(CSV), 1 field,
NUMERIC(0x08), value 144. Total: 7 bytes.

### MLSC Merkle Tree

#### Leaf Order

```
[rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]
```

Padded to next power of 2 with:
`MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")`.

#### Leaf Computation

All leaves use `TaggedHash("LadderLeaf", structural_template || value_commitment)`:

- **structural_template:** Block types, inverted flags, and coil data
  (including `output_index`). Deterministic from the condition set.
- **value_commitment:** `SHA256(field_values || pubkey[0] || pubkey[1] || ...)`.
  Pubkeys appended in positional order via `PubkeyCountForBlock()` (the
  `merkle_pub_key` commitment). This is a SHA256 output, not attacker-chosen.

Leaf types:
- **Rung leaf:** `TaggedHash("LadderLeaf", structural_template || value_commitment)`
- **Relay leaf:** Same structure.
- **Coil leaf:** `TaggedHash("LadderLeaf", SerializeCoilData(coil))`

#### Interior Nodes

```
TaggedHash("LadderInternal", min(left, right) || max(left, right))
```

Sorted ordering eliminates left/right bits from proofs (cf. Taproot's
unsorted tree which requires left/right tracking).

#### Proof Structure

```
[total_rungs: CompactSize]
[total_relays: CompactSize]
[rung_index: CompactSize]
<revealed rung blocks>               -- CONDITIONS-context serialized
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
    [hash: 32 bytes]                 -- unrevealed sibling hashes
[n_mutation_targets: CompactSize]    -- for RECURSE_MODIFIED/DECAY
for each mutation target:
    [rung_index: CompactSize]
    <rung blocks>
    [n_relay_refs: CompactSize]
    <relay_refs>
```

### Sighash Algorithm

`SignatureHashLadder` follows the BIP-341 tagged hash pattern:

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

Key-path spends use `TaggedHash("LadderKeyPathSighash", ...)` with the
same structure.

#### Valid Hash Types

| Hash Type | Value | Description |
|-----------|-------|-------------|
| DEFAULT | `0x00` | Equivalent to ALL |
| ALL | `0x01` | Commit to all outputs |
| NONE | `0x02` | Do not commit to outputs |
| SINGLE | `0x03` | Commit to corresponding output only |
| ANYPREVOUT | `0x40` | Skip prevout commitment (BIP-118 analogue) |
| ANYONECANPAY | `0x80` | Commit only to this input |
| ANYPREVOUTANYSCRIPT | `0xC0` | Skip prevout and conditions commitment |

Valid combinations: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

Compared to BIP-341: base hash types are identical; ANYPREVOUT (`0x40`) and
ANYPREVOUTANYSCRIPT (`0xC0`) are native; annex is not supported
(spend_type=0); the script commitment is `conditions_root` rather than
`tapleaf_hash`.

### Evaluation Semantics

#### EvalResult Values

| Value | Meaning |
|-------|---------|
| `SATISFIED` | All conditions met |
| `UNSATISFIED` | Conditions not met (valid failure) |
| `ERROR` | Malformed block (consensus failure) |
| `UNKNOWN_BLOCK_TYPE` | Forward compatibility: treated as UNSATISFIED |

#### Evaluation Order

1. Relays evaluated first (index 0 through N-1, forward-only, cached).
2. `EvalLadder = OR(EvalRung(rung[0]), ...)`
3. `EvalRung = AND(EvalBlock(block[0]), ...)`
4. All referenced relays must be SATISFIED before rung blocks are evaluated.

#### Conditions-Witness Merge

Every block type has two serialization contexts:

- **Conditions context:** Locking side, committed in MLSC tree. Contains
  hashes, timelocks, scheme selectors -- no secrets.
- **Witness context:** Spending side. Contains public keys, signatures,
  preimages -- the unlocking data.

Before evaluation, conditions (from the MLSC proof) and witness data are
merged per block. Block types and inverted flags come from conditions.

#### Inversion Rules

Blocks may be inverted (result flipped) via the `0x81` escape byte:

| Original | Inverted |
|----------|----------|
| SATISFIED | UNSATISFIED |
| UNSATISFIED | SATISFIED |
| ERROR | ERROR |
| UNKNOWN_BLOCK_TYPE | ERROR |

Restricted to the `IsInvertibleBlockType` allowlist (fail-closed).
Key-consuming blocks are never invertible. See Rationale.

### Consensus Limits

| Parameter | Value | Source |
|-----------|-------|--------|
| MAX_RUNGS | 16 | `serialize.h` |
| MAX_BLOCKS_PER_RUNG | 8 | `serialize.h` |
| MAX_FIELDS_PER_BLOCK | 16 | `serialize.h` |
| MAX_LADDER_WITNESS_SIZE | 100,000 | `serialize.h` |
| MAX_PREIMAGE_FIELDS_PER_WITNESS | 2 | `serialize.h` |
| MAX_PREIMAGE_FIELDS_PER_TX | 2 | `serialize.h` |
| MAX_RELAYS | 8 | `serialize.h` |
| MAX_REQUIRES | 8 | `serialize.h` |
| MAX_RELAY_DEPTH | 4 | `serialize.h` |
| MICRO_HEADER_SLOTS | 128 | `types.h` |
| MAX_IMPLICIT_FIELDS | 8 | `types.h` |
| PUBKEY max size | 2,048 | `types.h` |
| SIGNATURE max size | 50,000 | `types.h` |
| SCRIPT_BODY max size | 80 | `types.h` |
| DATA max size | 32 | `types.h` |
| MIN_RUNG_OUTPUT_VALUE | 546 | `serialize.h` |
| COIL_ADDRESS_HASH_SIZE | 32 | `serialize.h` |
| RUNG_MLSC_PREFIX | `0xDF` | `serialize.h` |
| DATA_RETURN outputs per tx | 1 | `evaluator.cpp` |
| Witness stack elements per input | 2 | `evaluator.cpp` |
| Creation proof max leaves | 252 | CompactSize < 253 |

## Rationale

### Why typed blocks instead of opcodes?

Bitcoin Script's opcode model provides maximum generality at the cost of
static analysis. Given an arbitrary Script program, determining its resource
consumption or whether it terminates requires executing it.

Typed blocks provide deterministic bounds at parse time. Each block type has
a fixed evaluation function, known maximum field count, and bounded cost. A
verifier can determine worst-case cost without executing any block. This
enables static analysis by wallets, formal verification (21 TLA+ specs),
and deterministic resource bounds: MAX_RUNGS(16) x MAX_BLOCKS_PER_RUNG(8)
x MAX_FIELDS_PER_BLOCK(16) gives a hard upper bound per input.

### Why 62 types instead of fewer generic primitives?

A minimal design (SIG, TIMELOCK, HASH, COVENANT with sub-type parameters)
has three problems: (1) Wire overhead -- a generic TIMELOCK needs 3+ fields
where CSV needs 1. (2) Error surface -- compound blocks enforce exact field
sequences; generic assembly of 4 separate blocks has 4 failure modes vs 1.
(3) Static analysis cost -- O(1) dispatch on concrete type vs parsing
sub-type fields.

### Why merkle_pub_key?

Without `merkle_pub_key`, conditions carry PUBKEY fields on-chain. A PUBKEY
field can hold up to 2,048 bytes. An attacker creates a SIG block with
garbage bytes as a "public key," never spends the output -- data is
permanently stored. By moving public keys to the Merkle leaf, conditions
carry only SCHEME (1 byte). Cost: one additional hash per key-consuming
block during MLSC verification, negligible relative to signature
verification.

### Why MLSC instead of Taproot's script tree?

Three structural differences: (1) **Sorted interior nodes** --
`min(L,R) || max(L,R)` eliminates left/right bits, saving 1 bit per level.
(2) **Pubkeys in leaves** -- structural basis for anti-spam. (3) **Coil
leaf** -- dedicated per-output metadata; Taproot has no equivalent.

### Why a shared conditions_root per transaction?

One root per transaction (not per output) means each additional output adds
only 8 bytes (nValue) on the wire. For a 100-output batch, this saves
~3,300 bytes vs per-output scriptPubKeys. The tradeoff: all outputs in a
TX_MLSC transaction share the same condition set. Different spending paths
per output are expressed via `output_index` in the coil.

### Why forward-only relay indexing?

Relay N can only reference relays 0..N-1. This guarantees acyclicity by
construction (topological sort). Maximum transitive depth is bounded at
MAX_RELAY_DEPTH=4. Without this, cycle detection requires graph search at
deserialization, adding complexity and DoS surface.

### Why is the inversion allowlist fail-closed?

New block types default to non-invertible. Inverting an unknown block type
would let an attacker embed arbitrary data (construct a failing block,
invert to SATISFIED) without the network understanding its semantics.
`UNKNOWN_BLOCK_TYPE` inverted becomes `ERROR` (not SATISFIED).

### Why PREIMAGE min=1?

Required for P2SH and P2WSH legacy wrappers, where inner conditions
(serialized as SCRIPT_BODY, which shares the PREIMAGE count limit) can be
shorter than 32 bytes.

### Why SCHEME is 1 byte?

256 possible selectors. Current allocation: 6 values (2 classical, 4 PQ).
New PQ schemes from NIST rounds receive new codes within the existing byte.
No wire format changes, no new data types, no hard fork.

### Why nVersion=4?

Version 3 is claimed by BIP-431 (package relay). Version 4 is currently
non-standard and invalid, satisfying the soft fork requirement: old nodes
treat v4 transactions as anyone-can-spend.

### Why 0xDF as the MLSC prefix?

`0xDF` is not a valid opcode in any existing Script interpretation. It falls
in the "OP_SUCCESS" range for Tapscript but is outside the P2SH, P2WSH,
and P2WPKH template patterns. Old nodes see `0xDF + 32 bytes` as an
unrecognised script pattern and treat it as anyone-can-spend.

### Why sorted interior Merkle nodes?

Sorted nodes (`min(L,R) || max(L,R)`) eliminate the need for left/right
path bits in proofs. Each sibling hash in the proof is 32 bytes with no
directional metadata. The verifier simply sorts and hashes. This simplifies
proof generation, reduces proof size by 1 bit per level, and makes proof
construction order-independent.

### Why a creation proof?

The creation proof validates the Merkle tree structure at block acceptance
time. Without it, a miner could construct a `conditions_root` that commits
to an invalid tree shape, potentially allowing spending paths that were never
intended. The creation proof binds the tree to the transaction at fund time.

## Backwards Compatibility

### Soft Fork Deployment

Version 4 transactions are currently non-standard and invalid. Existing
nodes treat v4 transactions as anyone-can-spend (`0xDF` is not a recognised
script pattern). Old nodes accept blocks containing v4 transactions;
upgraded nodes enforce full Ladder Script rules.

### No Impact on Existing Transactions

Ladder Script rules apply exclusively to `nVersion = 4`. Transactions with
`nVersion` 1, 2, or 3 are unaffected.

### Legacy Family for Migration

The 7 legacy block types allow existing key material within Ladder Script
conditions without re-keying. A P2PKH address holder migrates via
`p2pkh(@key)`.

### Wallet Compatibility

Outputs with `0xDF` scriptPubKeys are unknown to non-upgraded wallets. Such
wallets will not display them. This is standard behaviour for new output
types.

### Removed Features

- **Non-Merkelised conditions (`0xC1` prefix):** Removed. All outputs use
  MLSC format (`0xDF` + 32 bytes).
- **COVENANT coil type (`0x03`):** Only UNLOCK (`0x01`) and UNLOCK_TO
  (`0x02`) are valid.
- **Attestation modes:** INLINE (`0x01`) and AGGREGATE (`0x02`) are valid.
  AGGREGATE enables half-aggregated Schnorr signatures.

## Activation

All 62 block types activate together as a single soft fork. Partial
activation is not supported: compound blocks reference signature semantics,
recursion blocks reference MLSC leaf computation, PLC blocks reference
recursion for state transitions.

The activation mechanism (BIP-9 signaling or BIP-8 mandatory activation) is
outside the scope of this specification.

## Reference Implementation

Source: `src/rung/` (14,663 lines). Modifications to existing Bitcoin Core:
~448 lines across 15 files.

| File | Description |
|------|-------------|
| `types.h` | Block type enum, data types, micro-header table, implicit layouts, `IsInvertibleBlockType`, `PubkeyCountForBlock` |
| `evaluator.cpp` | All 62 block evaluators, `EvalBlock`, `EvalLadder`, `VerifyRungTx` |
| `serialize.cpp` | Wire format, micro-header encoding, implicit fields |
| `conditions.cpp` | MLSC Merkle tree, proof verification |
| `sighash.cpp` | `SignatureHashLadder` implementation |
| `descriptor.cpp` | Descriptor language parser and formatter |
| `policy.cpp` | Standardness rules |
| `pq_verify.cpp` | PQ signature verification via liboqs (optional) |

Test coverage: 528 unit tests, 60 functional tests, 21 TLA+ specifications,
62/62 block types verified on signet.

## Security Considerations

### Anti-Spam Surface

Maximum embeddable user-chosen data per transaction: **144 bytes** (flat,
regardless of input/output count). Breakdown:

| Channel | Bytes | Notes |
|---------|-------|-------|
| conditions_root | 32 | 1 per tx; adversary must burn an output to commit |
| PREIMAGE | 64 | MAX_PREIMAGE_FIELDS_PER_TX=2, 32 bytes each |
| DATA_RETURN | 40 | Intentional data commitment |
| nLockTime + nSequence | 8 | Standard Bitcoin fields |
| **Total** | **144** | |

The `conditions_root` is protocol-derived (triple-hashed from validated
structure via the creation proof). `value_commitment` fields are SHA256
outputs. Structural templates are validated enums. No contiguous
attacker-chosen channel exceeds 64 bytes. Inscriptions are structurally
impossible. UTXO spam yields zero readable attacker data.

Compare: Taproot witness allows ~4 MB of arbitrary data per transaction.

### Recursion Termination

All 6 recursion types terminate: RECURSE_SAME persists but cannot grow;
RECURSE_COUNT/SPLIT decrement to zero; RECURSE_UNTIL terminates at a block
height; RECURSE_MODIFIED/DECAY are bounded by `max_depth`. Legacy script
wrappers are depth-limited at evaluation time.

### Sighash Binding

`SignatureHashLadder` commits to `conditions_root`, binding every signature
to the full condition set. Replay across condition sets is prevented unless
the signer opts out via ANYPREVOUTANYSCRIPT (`0xC0`).

### Post-Quantum: Fail-Closed

PQ support is compile-time optional (liboqs). Without liboqs, PQ scheme
verification returns UNSATISFIED (fail-closed). SIGNATURE max of 50,000
bytes accommodates SPHINCS+-SHA2-256f (~49,216 bytes).

### Batch Verification

`BatchVerifier` collects Schnorr requests and verifies in a single batch.
ECDSA and PQ signatures are verified individually.

### Dust Threshold

MIN_RUNG_OUTPUT_VALUE (546 sats) prevents dust outputs. DATA_RETURN outputs
(nValue=0) are the sole exception.

## Acknowledgements

The MLSC Merkle tree follows the BIP-341 tagged hash pattern. The CTV block
implements BIP-119 template hash verification. ANYPREVOUT/ANYPREVOUTANYSCRIPT
sighash flags follow BIP-118 design principles.

## Appendix A: Block Evaluation Rules

Detailed evaluation semantics for all 62 block types. Dispatch in
`evaluator.cpp:EvalBlock` (`evaluator.cpp:3040`).

### Signature Family

| Type | Evaluation |
|------|------------|
| SIG | Verify SIGNATURE against PUBKEY using `CheckSchnorrSignature` or `CheckECDSASignature` (routed by SCHEME or signature size). PQ schemes routed via `VerifyPQSignature`. |
| MULTISIG | M-of-N: NUMERIC threshold M, N PUBKEY fields, M SIGNATURE fields. Signatures must appear in pubkey order. Each signature matches a distinct pubkey. |
| ADAPTOR_SIG | Verify adapted SIGNATURE against signing PUBKEY with adaptor point. Adaptor secret revealed off-chain when signature is published. |
| MUSIG_THRESHOLD | Verify aggregate SIGNATURE against aggregate PUBKEY. FROST/MuSig2 ceremony off-chain; on-chain verification is single-sig. NUMERIC fields carry M and N. |
| KEY_REF_SIG | Resolve PUBKEY_COMMIT from relay block via relay_refs (relay_index, block_index), verify SIGNATURE against referenced key. Enables DRY key reuse across rungs. |

### Timelock Family

| Type | Evaluation |
|------|------------|
| CSV | Relative timelock (block-height) via `CheckSequence` |
| CSV_TIME | Relative timelock (median-time-past) |
| CLTV | Absolute timelock (block-height) via `CheckLockTime` |
| CLTV_TIME | Absolute timelock (median-time-past) |

### Hash Family

| Type | Evaluation |
|------|------------|
| TAGGED_HASH | BIP-340: `SHA256(tag_hash \|\| tag_hash \|\| preimage)` vs committed hash |
| HASH_GUARDED | Raw SHA-256 preimage verification; non-invertible |

### Covenant Family

| Type | Evaluation |
|------|------------|
| CTV | Compute BIP-119 template hash for spending tx at current input index. Compare against HASH256 field. SATISFIED on match. |
| VAULT_LOCK | Two paths: recovery PUBKEY (immediate, no delay) or hot PUBKEY (requires CSV delay of NUMERIC blocks). Both committed via merkle_pub_key. |
| AMOUNT_LOCK | Two NUMERICs (min_sats, max_sats). SATISFIED if output amount in [min, max]. |

### Recursion Family

| Type | Evaluation |
|------|------------|
| RECURSE_SAME | Output MLSC root must equal input's root (identity covenant). |
| RECURSE_MODIFIED | Apply parameterized mutations (block_idx, param_idx, delta) to condition fields, recompute MLSC root from mutated leaf array, compare against output root. Multi-rung mutations via mutation_targets in MLSC proof. |
| RECURSE_UNTIL | Before target block height: output must re-encumber with same root. At/after target: SATISFIED unconditionally. |
| RECURSE_COUNT | Decrement NUMERIC counter each spend. Output carries decremented conditions. At zero: SATISFIED. |
| RECURSE_SPLIT | Decrement NUMERIC max_splits. All outputs must carry decremented conditions. Enforces min_split_sats per output and value conservation. |
| RECURSE_DECAY | Like RECURSE_MODIFIED but negates deltas. Bounded by max_depth. |

All recursion evaluators use leaf-centric Merkle verification: mutate a copy
of the revealed leaf, rebuild the tree, compare root against output MLSC root.

### Anchor Family

| Type | Evaluation |
|------|------------|
| ANCHOR | Marker; SATISFIED if anchor_id > 0 |
| ANCHOR_CHANNEL | 2 pubkeys (local, remote) + commitment_number |
| ANCHOR_POOL | vtxo_tree_root hash + participant_count |
| ANCHOR_RESERVE | Threshold (n <= m) + guardian_hash |
| ANCHOR_SEAL | asset_id + state_transition hashes |
| ANCHOR_ORACLE | Oracle pubkey + outcome_count |
| DATA_RETURN | Unspendable; always returns ERROR |

### PLC Family

| Type | Evaluation |
|------|------------|
| HYSTERESIS_FEE | Fee rate in [low, high] band |
| HYSTERESIS_VALUE | UTXO value in [low, high] band |
| TIMER_CONTINUOUS | SATISFIED when accumulated >= target |
| TIMER_OFF_DELAY | SATISFIED when remaining blocks <= 0 |
| LATCH_SET | Pubkey-authenticated state activation |
| LATCH_RESET | Pubkey-authenticated state deactivation with delay |
| COUNTER_DOWN | Decrement on signed event; SATISFIED at zero |
| COUNTER_PRESET | Approval accumulator; SATISFIED at preset |
| COUNTER_UP | Increment on signed event; SATISFIED at target |
| COMPARE | Compare amount vs thresholds: operator byte (1=EQ, 2=NEQ, 3=GT, 4=LT, 5=GTE, 6=LTE, 7=IN_RANGE) |
| SEQUENCER | Step through total_steps; SATISFIED at final |
| ONE_SHOT | One-time activation; SATISFIED if state=0 and commitment matches |
| RATE_LIMIT | Cap: max_per_block, accumulation_cap, refill_blocks |
| COSIGN | Cross-input: another input must have matching conditions root |

### Compound Family

| Type | Evaluation |
|------|------------|
| TIMELOCKED_SIG | SIG + CSV combined |
| HTLC | Hash preimage + CSV + dual signatures (sender/receiver) |
| HASH_SIG | Hash preimage + SIG combined |
| PTLC | Adaptor signature + CSV combined |
| CLTV_SIG | SIG + CLTV combined |
| TIMELOCKED_MULTISIG | M-of-N multisig + CSV combined |
| ANCHOR_FEE | Anchor with fee contribution: 2-of-2 sigs + fee band + weight limit |

### Governance Family

| Type | Evaluation |
|------|------------|
| EPOCH_GATE | `(height % epoch_size) < window_size` |
| WEIGHT_LIMIT | `tx.weight <= max_weight` |
| INPUT_COUNT | Input count in [min, max] |
| OUTPUT_COUNT | Output count in [min, max] |
| RELATIVE_VALUE | `output_value >= input_value * numerator / denominator` |
| ACCUMULATOR | Merkle set membership proof; inverted = blocklist |
| OUTPUT_CHECK | Output at index must match value range + script hash |

### Legacy Family

| Type | Evaluation |
|------|------------|
| P2PK_LEGACY | Pubkey + signature (P2PK equivalent) |
| P2PKH_LEGACY | HASH160 commitment; pubkey NOT in merkle_pub_key |
| P2SH_LEGACY | HASH160 + inner script; recursive evaluation, depth-limited |
| P2WPKH_LEGACY | Delegates to P2PKH path |
| P2WSH_LEGACY | HASH256 + inner script; recursive evaluation, depth-limited |
| P2TR_LEGACY | Pubkey + signature key-path |
| P2TR_SCRIPT_LEGACY | HASH256 + internal pubkey + inner script; recursive, depth-limited |

## Appendix B: Implicit Field Layouts

Notation: `TYPE(N)` = fixed N bytes, no length prefix. `TYPE(var)` =
CompactSize length prefix + data. NUMERIC = CompactSize-encoded.

### Conditions Context

| Block Type | Implicit Layout |
|------------|----------------|
| SIG | SCHEME(1) |
| MULTISIG | NUMERIC(var), SCHEME(1) |
| ADAPTOR_SIG | _(empty -- 0 condition fields)_ |
| MUSIG_THRESHOLD | NUMERIC(var), NUMERIC(var), SCHEME(1) |
| KEY_REF_SIG | NUMERIC(var), NUMERIC(var), SCHEME(1) |
| CSV | NUMERIC(var) |
| CSV_TIME | NUMERIC(var) |
| CLTV | NUMERIC(var) |
| CLTV_TIME | NUMERIC(var) |
| TAGGED_HASH | HASH256(32) |
| HASH_GUARDED | HASH256(32) |
| CTV | HASH256(32) |
| VAULT_LOCK | NUMERIC(var), SCHEME(1) |
| AMOUNT_LOCK | NUMERIC(var), NUMERIC(var) |
| RECURSE_SAME | NUMERIC(var) |
| RECURSE_UNTIL | NUMERIC(var) |
| RECURSE_COUNT | NUMERIC(var) |
| RECURSE_SPLIT | NUMERIC(var), NUMERIC(var), NUMERIC(var) |
| ANCHOR | NUMERIC(var) |
| ANCHOR_CHANNEL | NUMERIC(var), SCHEME(1) |
| ANCHOR_POOL | HASH256(32), NUMERIC(var) |
| ANCHOR_RESERVE | NUMERIC(var), NUMERIC(var), HASH256(32) |
| ANCHOR_SEAL | HASH256(32), HASH256(32) |
| ANCHOR_ORACLE | SCHEME(1), NUMERIC(var) |
| DATA_RETURN | DATA(var) |
| HYSTERESIS_FEE | NUMERIC(var), NUMERIC(var) |
| HYSTERESIS_VALUE | NUMERIC(var), NUMERIC(var) |
| TIMER_CONTINUOUS | NUMERIC(var) |
| TIMER_OFF_DELAY | NUMERIC(var), NUMERIC(var) |
| LATCH_SET | SCHEME(1) |
| LATCH_RESET | NUMERIC(var), SCHEME(1) |
| COUNTER_DOWN | NUMERIC(var), SCHEME(1) |
| COUNTER_PRESET | NUMERIC(var), NUMERIC(var) |
| COUNTER_UP | NUMERIC(var), SCHEME(1) |
| COMPARE | NUMERIC(var), NUMERIC(var), NUMERIC(var) |
| SEQUENCER | NUMERIC(var), NUMERIC(var) |
| ONE_SHOT | HASH256(32) |
| RATE_LIMIT | NUMERIC(var), NUMERIC(var), NUMERIC(var) |
| COSIGN | HASH256(32) |
| TIMELOCKED_SIG | NUMERIC(var), SCHEME(1) |
| HTLC | HASH256(32), NUMERIC(var), SCHEME(1) |
| HASH_SIG | HASH256(32), SCHEME(1) |
| PTLC | NUMERIC(var), SCHEME(1) |
| CLTV_SIG | NUMERIC(var), SCHEME(1) |
| TIMELOCKED_MULTISIG | NUMERIC(var), NUMERIC(var), SCHEME(1) |
| ANCHOR_FEE | NUMERIC(var), NUMERIC(var), NUMERIC(var), SCHEME(1) |
| EPOCH_GATE | NUMERIC(var), NUMERIC(var) |
| WEIGHT_LIMIT | NUMERIC(var) |
| INPUT_COUNT | NUMERIC(var), NUMERIC(var) |
| OUTPUT_COUNT | NUMERIC(var), NUMERIC(var) |
| RELATIVE_VALUE | NUMERIC(var), NUMERIC(var) |
| ACCUMULATOR | HASH256(32) |
| OUTPUT_CHECK | NUMERIC(var), NUMERIC(var), NUMERIC(var), HASH256(32) |
| P2PK_LEGACY | SCHEME(1) |
| P2PKH_LEGACY | HASH160(20) |
| P2SH_LEGACY | HASH160(20) |
| P2WPKH_LEGACY | HASH160(20) |
| P2WSH_LEGACY | HASH256(32) |
| P2TR_LEGACY | SCHEME(1) |
| P2TR_SCRIPT_LEGACY | HASH256(32) |

RECURSE_MODIFIED and RECURSE_DECAY have variable field counts (2 + 4*N
mutation descriptors) and use explicit encoding; they are protected by
`IsDataEmbeddingType` rejection (`types.h:31`).

### Witness Context

| Block Type | Implicit Layout |
|------------|----------------|
| SIG | PUBKEY(var), SIGNATURE(var) |
| MULTISIG | PUBKEY(var) x N, SIGNATURE(var) x M |
| ADAPTOR_SIG | PUBKEY(var), PUBKEY(var), SIGNATURE(var) |
| MUSIG_THRESHOLD | PUBKEY(var), SIGNATURE(var) |
| KEY_REF_SIG | PUBKEY_COMMIT(32), SIGNATURE(var) |
| CSV | NUMERIC(var) |
| CSV_TIME | NUMERIC(var) |
| CLTV | NUMERIC(var) |
| CLTV_TIME | NUMERIC(var) |
| TAGGED_HASH | PREIMAGE(var) |
| HASH_GUARDED | PREIMAGE(var) |
| HTLC | PUBKEY(var), SIGNATURE(var), PUBKEY(var), PREIMAGE(var), NUMERIC(var) |
| HASH_SIG | PUBKEY(var), SIGNATURE(var), PREIMAGE(var) |
| P2PK_LEGACY | PUBKEY(var), SIGNATURE(var) |
| P2PKH_LEGACY | PUBKEY(var), SIGNATURE(var) |
| P2SH_LEGACY | SCRIPT_BODY(var), PREIMAGE(var) |
| P2WPKH_LEGACY | PUBKEY(var), SIGNATURE(var) |
| P2WSH_LEGACY | SCRIPT_BODY(var), PREIMAGE(var) |
| P2TR_LEGACY | PUBKEY(var), SIGNATURE(var) |
| P2TR_SCRIPT_LEGACY | PUBKEY(var), SCRIPT_BODY(var), PREIMAGE(var) |

All other block types use explicit field encoding in witness context.

## Appendix C: Micro-header Slot Assignments

63 slots assigned (0x00-0x3E). Slots 0x07 and 0x08 are reserved. Slots
0x3F-0x7F are unused and rejected at deserialization. Complete table in
`types.h:kMicroHeaderSlots`.

| Slot | Block Type | Slot | Block Type |
|------|------------|------|------------|
| `0x00` | SIG | `0x20` | HYSTERESIS_FEE |
| `0x01` | MULTISIG | `0x21` | HYSTERESIS_VALUE |
| `0x02` | ADAPTOR_SIG | `0x22` | TIMER_CONTINUOUS |
| `0x03` | MUSIG_THRESHOLD | `0x23` | TIMER_OFF_DELAY |
| `0x04` | KEY_REF_SIG | `0x24` | LATCH_SET |
| `0x05` | CSV | `0x25` | LATCH_RESET |
| `0x06` | CSV_TIME | `0x26` | COUNTER_DOWN |
| `0x07` | _(reserved)_ | `0x27` | COUNTER_PRESET |
| `0x08` | _(reserved)_ | `0x28` | COUNTER_UP |
| `0x09` | CLTV | `0x29` | COMPARE |
| `0x0A` | CLTV_TIME | `0x2A` | SEQUENCER |
| `0x0B` | TAGGED_HASH | `0x2B` | ONE_SHOT |
| `0x0C` | HASH_GUARDED | `0x2C` | RATE_LIMIT |
| `0x0D` | CTV | `0x2D` | COSIGN |
| `0x0E` | VAULT_LOCK | `0x2E` | TIMELOCKED_SIG |
| `0x0F` | AMOUNT_LOCK | `0x2F` | HTLC |
| `0x10` | RECURSE_SAME | `0x30` | HASH_SIG |
| `0x11` | RECURSE_MODIFIED | `0x31` | PTLC |
| `0x12` | RECURSE_UNTIL | `0x32` | CLTV_SIG |
| `0x13` | RECURSE_COUNT | `0x33` | TIMELOCKED_MULTISIG |
| `0x14` | RECURSE_SPLIT | `0x34` | ANCHOR_FEE |
| `0x15` | RECURSE_DECAY | `0x35` | EPOCH_GATE |
| `0x16` | ANCHOR | `0x36` | WEIGHT_LIMIT |
| `0x17` | ANCHOR_CHANNEL | `0x37` | INPUT_COUNT |
| `0x18` | ANCHOR_POOL | `0x38` | OUTPUT_COUNT |
| `0x19` | ANCHOR_RESERVE | `0x39` | RELATIVE_VALUE |
| `0x1A` | ANCHOR_SEAL | `0x3A` | ACCUMULATOR |
| `0x1B` | ANCHOR_ORACLE | `0x3B` | OUTPUT_CHECK |
| `0x1C` | DATA_RETURN | `0x3C` | P2PK_LEGACY |
| `0x1D` | P2PKH_LEGACY | `0x3D` | P2SH_LEGACY |
| `0x1E` | P2WPKH_LEGACY | `0x3F`-`0x7F` | _(unused, rejected)_ |
| `0x1F` | P2WSH_LEGACY | | |

Remaining legacy types (P2TR_LEGACY at `0x3C`, P2TR_SCRIPT_LEGACY at
`0x3D`) may overlap with governance types in the table above. Consult
`types.h:kMicroHeaderSlots` for the authoritative assignment.

## Appendix D: Descriptor Language

### Grammar

```
ladder      = "ladder(" output_list ")"
output_list = output { "," output }
output      = "output(" index "," "or(" rung { "," rung } ")" ")"
rung        = block | "and(" block { "," block } ")"
block       = base_block | "!" base_block
```

Each `output(index, ...)` declares which transaction output the enclosed
rungs govern, matching the coil's `output_index` field.

### Block Syntax (one per family)

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

Complete grammar: `src/rung/descriptor.h` and
[bitcoinghost.org/labs/descriptor-notation.html](https://bitcoinghost.org/labs/descriptor-notation.html).

### Scheme Names

`schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`

### Signature Scheme Codes

| Code | Name | Key Size | Sig Size |
|------|------|----------|----------|
| `0x01` | SCHNORR | 32 (x-only) | 64-65 |
| `0x02` | ECDSA | 33 (compressed) | 8-72 |
| `0x10` | FALCON512 | 897 | 666 |
| `0x11` | FALCON1024 | 1,793 | 1,280 |
| `0x12` | DILITHIUM3 | 1,952 | 3,293 |
| `0x13` | SPHINCS_SHA | 64 | 49,216 |

### Examples

**Simple vault with recovery:**
```
ladder(output(0, or(
    sig(@recovery_key),
    and(sig(@hot_key), csv(144))
)))
```

**Multi-output payment:**
```
ladder(output(0, or(sig(@k), csv(144))), output(1, sig(@bob)))
```

**Rate-limited wallet (max 1 BTC per 6 blocks, 2-of-3 backup):**
```
ladder(output(0, or(
    and(sig(@daily_key), rate_limit(1, 100000000, 6)),
    multisig(2, @alice, @bob, @carol)
)))
```

**Legacy P2PKH migration:**
```
ladder(output(0, or(p2pkh(@old_key))))
```

**Post-quantum signature:**
```
ladder(output(0, or(sig(@pq_key, falcon512))))
```

## Appendix E: Anti-Spam Mechanisms

Ladder Script enforces 7 mechanisms at deserialization time:

### 1. Selective Inversion

The `IsInvertibleBlockType` allowlist (`types.h`) determines which blocks
may be inverted. Key-consuming blocks are never invertible: SIG, MULTISIG,
ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG, compound signature types, legacy
key types, ANCHOR_CHANNEL, ANCHOR_ORACLE, VAULT_LOCK, LATCH_SET,
LATCH_RESET, COUNTER_DOWN, COUNTER_UP. This prevents embedding arbitrary
data as a garbage pubkey (fail verification, invert to SATISFIED). The
allowlist is fail-closed.

### 2. IsDataEmbeddingType Rejection

For blocks without an implicit layout, the types PUBKEY_COMMIT (32 bytes),
HASH256 (32 bytes), HASH160 (20 bytes), and DATA (up to 40 bytes) are
rejected. Prevents layout-less blocks from embedding unvalidated payloads.

### 3. PREIMAGE Field Limit

MAX_PREIMAGE_FIELDS_PER_WITNESS=2 (fast reject).
MAX_PREIMAGE_FIELDS_PER_TX=2 (binding constraint, summed across ALL inputs).
Total user-chosen preimage data: 64 bytes/tx regardless of input count.

### 4. DATA Type Restriction

DATA (`0x0B`) is only permitted in DATA_RETURN blocks. Any other block
carrying a DATA field is rejected.

### 5. merkle_pub_key

Public keys exist only in the witness. Conditions carry SCHEME (1 byte).
Eliminates the PUBKEY writable surface from conditions.

### 6. Strict Field Enforcement

When an implicit layout exists, field count and types must match exactly.
Extra fields rejected.

### 7. Blanket HASH256 Rejection

`IsDataEmbeddingType` types blocked in all blocks lacking an implicit
layout, regardless of serialization context.

### Residual Embeddable Surface

| Channel | Bytes | Notes |
|---------|-------|-------|
| conditions_root | 32 | 1/tx, adversary burns output, triple-hashed |
| PREIMAGE | 64 | 2 x 32 bytes |
| DATA_RETURN | 40 | Intentional commitment |
| nLockTime + nSequence | 8 | Standard fields |
| **Total** | **144** | Flat per tx |

No contiguous attacker-chosen channel exceeds 64 bytes. Inscriptions are
structurally impossible. UTXO spam yields zero readable attacker data
(scriptPubKey is a protocol-derived hash).

## Appendix F: Size and Fee Comparisons

### Transaction Weights

| Transaction Type | vBytes |
|-----------------|--------|
| Simple payment (1-in, 2-out, key-path) | 119 |
| Simple payment (1-in, 2-out, script-path) | 140 |
| Batch 100 outputs (key-path) | 914 |
| Full lifecycle (create + spend, key-path) | 241 |

### Per-Output Wire Cost

| Format | Bytes per Output |
|--------|-----------------|
| TX_MLSC | 8 (nValue only, shared root) |
| P2TR | 43 (nValue + scriptPubKey) |
| P2WPKH | 39 (nValue + scriptPubKey) |

For a 100-output batch, TX_MLSC saves 3,500 bytes over P2TR.

### UTXO Set Cost

| Format | Bytes per UTXO Entry |
|--------|---------------------|
| TX_MLSC | ~8 (shared conditions_root) |
| P2TR | ~48 |
| P2WPKH | ~44 |

### Witness Size by Block Type

| Block | Conditions | Witness | Total (micro-header) |
|-------|-----------|---------|---------------------|
| SIG (Schnorr) | 2 bytes | 98 bytes | 100 bytes |
| CSV | 2-5 bytes | 2-5 bytes | 4-10 bytes |
| HTLC | 36 bytes | ~168 bytes | ~204 bytes |
| MULTISIG (2-of-3) | 4 bytes | ~228 bytes | ~232 bytes |

### Embeddable Data Comparison

| System | Max Embeddable Data per TX |
|--------|--------------------------|
| Ladder Script | 144 bytes (flat) |
| Taproot witness | ~4,000,000 bytes |
| OP_RETURN | 80 bytes (standardness) |
| Bare multisig | ~195 bytes |

## Appendix G: Test Vectors

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

MLSC output scriptPubKey:
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
hashed into the Merkle tree). `@?` indicates an unknown key.

### Vector 4: Regtest v4 transaction structure

A v4 transaction created with `createrungtx` using a SIG block with Schnorr
scheme and a 33-byte compressed pubkey:

```
Input:   82e47986dc21229732e1545282ec02b296ee611d9d2ac1f8b0a605b406ff80b2:0
Amount:  49.999 BTC
Block:   SIG (SCHEME=0x01 Schnorr)
Pubkey:  032c4d54635a48e5542f0a06df7c3f752f505d9ab93873dcb8fb9627d7935d9bc7

Output scriptPubKey (33 bytes):
  df 7989d97cc7fa19fd4687c56723658a16e24f4741e8c9680d6c50d5f90871ccff
  ^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |   conditions_root (32 bytes)
  0xDF = MLSC prefix

Transaction size: 93 bytes (unsigned, single input, single output)
```

The `conditions_root` is derived via `ComputeTxMLSCRoot` from a single
`CreationProofRung` leaf containing the structural template (block type SIG,
non-inverted, coil output_index=0) and the value commitment (SHA-256 of field
values and pubkey).

### Vector 5: Live signet transactions

Live signet transaction IDs will be published after signet deployment at
`bitcoinghost.org/labs/explorer.html`. The signet uses a custom challenge
with 10-minute block intervals.

```
Signet node:  85.9.213.194
Explorer:     https://bitcoinghost.org/labs/explorer.html
Engine:       https://bitcoinghost.org/labs/ladder-engine.html

All 62 block types will be exercised on signet with fund+spend transaction
pairs. Transaction IDs will be added to this appendix.
```

### Vector 6: Tagged hash constants

Pre-computed SHA-256 of each tag string (used as the first two blocks of
the BIP-340 tagged hash prefix):

```
SHA256("LadderLeaf")           = 43356ae3620332d10ecf1ce1eee9c9612641e37f4a657b0323fab99f656ba84c
SHA256("LadderInternal")       = 404d4b6b247b0f3daba7bd63948dca4dc402aa1b5089b85c74366a7559fabf19
SHA256("LadderSighash")        = 09ab40786f2a99607670861085f3cd39a68eebe443e6345edcc338e9a9339f86
SHA256("LadderKeyPathSighash") = e20212e6d876da070e6c00a2989b6b516fe30748943a414d7f2792a957e8011f
SHA256("LadderTweak")          = af6e247b331846a8054e5dace3d2900cb2e57b59163d9ca417c6638ec776c3bd
```

The empty leaf used for Merkle tree padding:

```
MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")
                = SHA256(43356ae3...43356ae3...)
                = e5e2bb6ee8f832481070620c54a9ff890668cd46c2aad3300bbb5828b7302e6f
```

`TaggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)` per BIP-340.

### LadderWitness Wire Format

```
[n_rungs: CompactSize]           -- 0 = diff witness mode
for each rung:
    [n_blocks: CompactSize]      -- >= 1
    for each block:
        <block encoding>
    [n_relay_refs: CompactSize]
    for each relay_ref: [index: CompactSize]
[coil_type: uint8]               -- UNLOCK (0x01) or UNLOCK_TO (0x02)
[attestation: uint8]             -- INLINE (0x01)
[scheme: uint8]                  -- signature scheme code
[address_len: CompactSize]       -- 0 or 32
[address_hash: bytes]            -- SHA256(raw_address) if present
[n_coil_conditions: CompactSize] -- must be 0 (reserved)
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

### Diff Witness Mode

When `n_rungs = 0`, the witness inherits rungs and relays from a prior input
(`input_index < current`), overriding specific fields via
`(rung_index, block_index, field_index, data_type, data)` tuples. Only
witness-side types allowed (PUBKEY, SIGNATURE, PREIMAGE, SCRIPT_BODY,
SCHEME). Chaining (diff pointing to diff) is prohibited. Coil fields are
always fresh.
