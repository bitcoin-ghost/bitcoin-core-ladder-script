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

Ladder Script replaces Bitcoin Script with a typed transaction condition
format. Sixty-four typed function blocks grouped into eleven families
cover introspection, covenants, post-quantum signatures, Layer 2 sighash
modes, structured metadata, fee pinning, and multi-party atomic batching.
Every witness byte carries a declared data type with an enforced size
bound; no free-form pushes are possible. Spending paths are arranged as a
ladder of rungs evaluated with OR logic; each rung is a conjunction of
blocks. Transactions commit to a single shared Merkle root of all
conditions (Merkelised Ladder Script Conditions, MLSC) and reveal only
the satisfied rung at spend time. This proposal activates as a soft fork
on `nVersion = 4` and supersedes eight outstanding proposals that would
otherwise address one capability gap each.

## Copyright

This document is licensed under the MIT License.

## Motivation

There are things people need to build on Bitcoin that Bitcoin Script
cannot express — not "difficult to express," but impossible — and the
individual fixes proposed for each gap over the past five years do not
compose. This section enumerates the gaps, shows how Ladder Script
closes all of them in a single fork, and lists the proposals that
become redundant.

### Capability gaps

**Vaults with clawback.** A hot key for daily spending alongside a cold
key that can sweep immediately if the hot key is compromised. Requires
introspection of the spending transaction's outputs. BIP-345 proposes
this but is not activated.

**Rate-limited wallets.** A cap on how many satoshis may leave a wallet
per block, independent of whether the signing key is compromised. No
Bitcoin Script opcode inspects spending rate across blocks.

**Recursive covenants.** A UTXO whose spending condition enforces
conditions on its own outputs: DCA schedules, vesting graphs, binary
splits. Requires output introspection Script cannot provide without
CTV or OP_CAT, neither of which is activated.

**Transaction-level governance.** Constraints that route treasury
spends to specific addresses, cap transaction weight, gate spending to
block-height windows, or verify Merkle set membership against an
on-chain accumulator. Script has no structured introspection beyond
signature checks.

**Composable conditions.** A vault that combines rate-limiting AND
multisig recovery AND a time-locked heir clause in a single UTXO.
Every currently proposed opcode (CTV, APO, OP_VAULT) addresses one use
case and was not designed to compose with the others.

**Post-quantum signatures.** A migration path to FALCON / Dilithium /
SPHINCS+ before quantum attack becomes practical. Script has no slot
for a signature scheme selector; any PQ deployment would need a new
output type on every migration path. P2QRH proposes a single family
but not the general mechanism.

**Layer 2 sighash modes.** `SIGHASH_ANYPREVOUT` (BIP-118) enables
Eltoo and LN-Symmetry. Activation is stalled and the mechanism — a
taproot leaf version upgrade — is not available outside taproot.

**Structured metadata.** A typed, bounded data commitment that
replaces OP_RETURN, DATA_DROP padding, and the inscription pattern.
No existing proposal offers a 40-byte committed metadata slot at
consensus-level granularity.

**Multi-party atomic batching.** N independent parties collapsing
their UTXOs into a single settlement transaction authorised by one
signature, without escrow, pre-registration, or separate commitment
transactions. CoinJoin and FROST each solve half the problem;
neither is post-quantum safe; neither is enforced at consensus.

**Fee pinning resistance.** A block type that caps the fee range and
transaction weight of the spending transaction, usable as a Lightning
anchor output without the current pinning vectors.

### A single fork

Each gap maps to specific block types in the typed catalogue. Ladder
Script closes all of them in one soft fork activation:

| Gap | Solution | Primary block types |
|-----|----------|---------------------|
| Vaults with clawback | Native two-path vault | VAULT_LOCK |
| Rate-limited wallets | Per-block spend cap with accumulator | RATE_LIMIT |
| Recursive covenants | Six bounded recursion types | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| Transaction-level governance | Introspection primitives | WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK, COSIGN |
| Composable conditions | AND/OR ladder at evaluator level | all of the above, combined per rung |
| Post-quantum signatures | 1-byte SCHEME selector routes to PQ | SIG with FALCON-512/1024, Dilithium3, SPHINCS+ |
| Layer 2 sighash | Native ANYPREVOUT flag | sighash flag `0x40` (APO), `0xC0` (APOAS) |
| Structured metadata | Typed 40-byte commitment | DATA_RETURN |
| Multi-party atomic batching | Auth-chain priming + single PQ batch sig | QABI_PRIME, QABI_SPEND |
| Fee pinning resistance | 2-of-2 sig + fee band + weight limit | ANCHOR_FEE |

### Proposals superseded

Activating Ladder Script makes the following proposals redundant:

| Proposal | Ladder Script equivalent |
|----------|-------------------------|
| BIP-119 (CTV) | `CTV` block (`0x0301`) |
| BIP-118 (ANYPREVOUT) | sighash flag `0x40` / `0xC0` |
| BIP-345 (OP_VAULT) | `VAULT_LOCK` block (`0x0302`) |
| OP_CAT | unnecessary — recursion family |
| OP_CHECKSIGFROMSTACK | `TAGGED_HASH` block (`0x0203`) |
| BIP-443 (MATT / OP_CCV) | `ACCUMULATOR` block (`0x0806`) |
| OP_TXHASH | `OUTPUT_CHECK` (`0x0807`) + `CTV` |
| P2QRH | SCHEME byte on every signature block |

No further Script changes are needed after activation.

### The cost profile, summarised

| Metric | Ladder Script | Taproot | Ratio |
|--------|--------------|---------|-------|
| Cheapest spend (1-in 1-out key-path) | 110 vB | 111 vB | tied |
| UTXO set entry per output | ~8 B | ~48 B | 6× smaller |
| Wire cost per additional output | 8 B | ~43 B | 5.4× smaller |
| Maximum embeddable user-chosen data per tx | 144 B | ~4 MB | 27,000× tighter |
| Post-quantum signature support | native (SCHEME byte) | none | — |
| Covenant support | 64 native block types | none | — |

The UTXO savings come from a single shared `conditions_root` per
transaction. The data-embedding ratio comes from typed fields with
enforced size bounds. The post-quantum support comes from the SCHEME
byte routing to a signature verification dispatcher.

### Example: HTLC

Bitcoin Script today:

```
OP_IF
  OP_SHA256 <hash> OP_EQUALVERIFY
  <receiver_pubkey> OP_CHECKSIG
OP_ELSE
  <144> OP_CHECKSEQUENCEVERIFY OP_DROP
  <sender_pubkey> OP_CHECKSIG
OP_ENDIF
```

Ladder Script:

```
ladder(output(0, htlc(@sender, @receiver, <preimage>, 144)))
```

One typed block, fixed layout, deterministic cost, and the refund path
never appears on-chain — the MLSC proof reveals only the satisfied
rung.

## Design Overview

### The ladder metaphor

A spending-condition set is a **ladder** — an ordered list of **rungs**
combined with OR logic. Each rung is an AND-conjunction of one or more
**blocks**. To spend an output, the spender must satisfy every block in
at least one rung.

```
ladder (OR)
 ├─ rung 0: sig(@alice)                          single signer
 ├─ rung 1: and(sig(@bob), csv(144))             backup after 1 day
 └─ rung 2: multisig(2, @alice, @bob, @carol)    2-of-3 fallback
```

Rungs may reference **relays** — shared blocks evaluated once and
cached, used to deduplicate conditions across rungs. A **coil** is
per-output metadata attached to a rung: unlock type (UNLOCK or
UNLOCK_TO), attestation mode, signature scheme, optional destination
address, and `output_index` declaring which transaction output the
rung governs.

### TX_MLSC: one Merkle root per transaction

Every transaction commits to a single `conditions_root` whose Merkle
tree covers all rungs, relays, and coils of all outputs. Outputs on
the wire carry only their value (8 bytes); the scriptPubKey is
reconstructed at deserialisation as `0xDF || conditions_root` and
stored as 33 bytes per UTXO.

This is the PLC model — one program, multiple output coils. Each
rung's coil carries an `output_index` field declaring which output it
governs. At spend time, only the satisfied rung (and any relays it
references) is revealed in the witness; every other rung stays hidden
behind proof hashes. A creation proof — the full leaf list — is
included in the witness and validated at block acceptance, guaranteeing
that `conditions_root` commits to a real tree shape and not an
attacker-crafted root.

One root per transaction means each additional output costs 8 bytes,
not 43. For a 100-output batch, this saves ~3,500 bytes against P2TR.

### merkle_pub_key

Most covenant systems store public keys in locking conditions
on-chain, creating a writable channel for data embedding: an attacker
can place arbitrary bytes into a 33-byte "public key" field and never
spend the output. Ladder Script moves every public key out of the
conditions. At fund time, pubkeys are hashed into the Merkle leaf
alongside the serialised structural template; at spend time, the
witness provides the actual pubkey bytes and the verifier recomputes
the leaf to check they match the commitment.

Conditions carry only a 1-byte SCHEME field for signature blocks. The
cost is one additional SHA-256 per key-consuming block during MLSC
verification, negligible next to signature verification itself. The
benefit is the elimination of the largest unvalidated data channel
(up to 2,048 bytes per PUBKEY field) from the conditions side.

### Two-phase commitment: QABIO

Ladder Script also provides a native facility for N independent
parties to collapse their UTXOs into a single transaction authorised
by one post-quantum FALCON-512 signature from a designated
coordinator. This is QABIO — Quantum Atomic Batch Input / Output — and
it falls out of three existing capabilities: the typed block catalogue
(for the priming and spending blocks), the MLSC covenant model (for
committing a UTXO to a specific batch without broadcasting anything),
and the SCHEME-based PQ signature dispatch (for the batch
authorisation).

The two-phase commitment pattern is simple: each participant
unilaterally **primes** their UTXO for a specific batch by revealing
an auth-chain preimage (participant-authorised only, no coordinator
signature required), and then the coordinator **batch-spends** every
primed UTXO in a single transaction carrying one FALCON-512
signature. Partial settlement is structurally impossible — any
deviation from the committed batch forces every participant to
re-prime.

QABIO is specified as `QABI_PRIME` and `QABI_SPEND` blocks
(family `0x0A`), a new `qabi_block` transaction field, a new
`SIGHASH_QABO` mode, and a Replace-By-Depth mempool policy. Full
details are in the **QABIO** subsection of the Specification. From a
design-overview perspective it is one of the eleven capabilities this
fork activates, not a separate proposal bolted on top.

## Specification

### Transaction format

A Ladder Script transaction has `nVersion = 4` and is serialised with
flag byte `0x02` (analogous to SegWit's `0x01`). The `nVersion` value
is currently non-standard and invalid on unupgraded nodes, which is
the standard soft-fork escape hatch.

#### Wire layout

```
[nVersion: int32]                    must be 4
[flag: 0x00 0x02]                    TX_MLSC signal
[input_count: CompactSize]
for each input:
    [prevout: 36 bytes]
    [scriptSig_len: CompactSize]     must be 0
    [nSequence: uint32]
[conditions_root: 32 bytes]          shared MLSC root
[output_count: CompactSize]
for each output:
    [nValue: int64]                  8 bytes only, no scriptPubKey
for each input:
    [witness_count: CompactSize]
    [witness[0]: LadderWitness]      serialised spending proof
    [witness[1]: MLSCProof]           revealed conditions + Merkle proof
[creation_proof_len: CompactSize]    max 8,065
[creation_proof: bytes]              leaf hashes, required for 3+ outputs
[qabi_block_len: CompactSize]        max 262,144; zero for non-QABIO txs
[qabi_block: bytes]                  serialised QABIBlock (see QABIO §)
[aggregated_sig_len: CompactSize]    max 666; zero for non-QABIO txs
[aggregated_sig: bytes]              FALCON-512 SIGHASH_QABO signature
[nLockTime: uint32]
```

The `conditions_root` appears between inputs and outputs, not inside
either. Each output serialises as 8 bytes (value only); on
deserialisation outputs are inflated to
`CTxOut(nValue, 0xDF || conditions_root)`, producing the standard
33-byte MLSC scriptPubKey for each output in-memory.

All inputs must provide exactly two witness stack elements:

- `witness[0]` — serialised `LadderWitness` (the spending proof)
- `witness[1]` — serialised `MLSCProof` (the revealed conditions plus
  the Merkle path)

The four trailing fields (`creation_proof`, `qabi_block`,
`aggregated_sig`, `nLockTime`) are all tx-level. Non-QABIO
transactions carry `qabi_block_len = 0` and `aggregated_sig_len = 0`;
the serialiser still emits the length prefixes.

#### Verification (`VerifyRungTx`, eight steps)

1. Validate every output via `ValidateRungOutputs` (each must carry
   the 33-byte `0xDF` prefix; at most one DATA_RETURN output; dust
   threshold honoured).
2. Deserialise `LadderWitness` from `witness[0]`.
3. Resolve witness references if diff encoding is used.
4. Deserialise `MLSCProof` from `witness[1]`.
5. Extract pubkeys from the witness for `merkle_pub_key` leaf
   computation.
6. Verify the Merkle proof against the UTXO's `conditions_root`.
7. Merge the conditions (from the proof) with the witness (from
   `witness[0]`) into a single evaluation tree.
8. Evaluate the merged ladder via `EvalLadder`.

If the spending input is a QABIO input (see the QABIO subsection
below), one additional per-transaction pass validates the shared
`qabi_block` and verifies the `aggregated_sig`; the result is cached
and shared across every primed input of the same transaction.

### Output format and UTXO deduplication

On the wire, each output is 8 bytes. On deserialisation:

```
scriptPubKey = 0xDF || conditions_root     (33 bytes in-memory)
```

The `conditions_root` is shared across every output of the
transaction. Consequences:

- A UTXO set entry costs roughly 8 bytes of delta storage per output.
- Different spending paths per output are expressed via `output_index`
  in each rung's coil, not via different scriptPubKey bytes.
- A 100-output batch costs ~800 wire bytes for outputs vs. ~4,300 for
  P2TR, a saving that scales linearly with output count.

A **DATA_RETURN output** is an output with `nValue == 0`. On the wire,
a DATA_RETURN output is followed by `[payload_len: CompactSize][payload: bytes]`
where `payload_len ≤ 40`. At most one DATA_RETURN output per transaction.
DATA_RETURN is the structured replacement for OP_RETURN; it is always
unspendable (the evaluator returns ERROR).

### Data types

Every field in a Ladder Script witness or conditions block carries
exactly one of eleven data types:

| Code | Name | Min | Max | Context | Description |
|------|------|-----|-----|---------|-------------|
| `0x01` | PUBKEY | 1 | 2,048 | Witness | Public key (folded into Merkle leaf via merkle_pub_key) |
| `0x02` | PUBKEY_COMMIT | 32 | 32 | Witness | SHA-256 of pubkey (QABI_SPEND owner_id; conditions-only exception) |
| `0x03` | HASH256 | 32 | 32 | Both | SHA-256 digest |
| `0x04` | HASH160 | 20 | 20 | Both | RIPEMD160(SHA256()) digest |
| `0x05` | PREIMAGE | 1 | 32 | Witness | Hash preimage |
| `0x06` | SIGNATURE | 1 | 50,000 | Witness | Schnorr 64–65 B, ECDSA 8–72 B, PQ up to 49,216 B |
| `0x07` | SPEND_INDEX | 4 | 4 | Both | Spend index reference |
| `0x08` | NUMERIC | 1 | 8 | Both | Numeric value (CompactSize on wire) |
| `0x09` | SCHEME | 1 | 1 | Both | Signature scheme selector |
| `0x0A` | SCRIPT_BODY | 1 | 80 | Witness | Inner conditions for P2SH/P2WSH/P2TR_SCRIPT wrappers |
| `0x0B` | DATA | 1 | 40 | Conditions | Opaque data (DATA_RETURN blocks only) |

Condition-side types are HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX,
and DATA. The types PUBKEY, PUBKEY_COMMIT, SIGNATURE, PREIMAGE, and
SCRIPT_BODY are witness-only and rejected in conditions context, with
a single documented exception: `QABI_SPEND` conditions carry
`PUBKEY_COMMIT(32)` as the `owner_id` commitment. See the QABIO
subsection.

`PREIMAGE` min is 1 byte (not 32) because legacy P2SH and P2WSH
wrappers encode their inner conditions via `SCRIPT_BODY`, which
shares the PREIMAGE count limit and can be shorter than 32 bytes.

### Block types

Ladder Script defines **64 block types across 11 families**. Each
block type is a 16-bit value encoded little-endian on the wire.

#### 1. Signature family (0x0001–0x0005)

Pubkeys are bound to the MLSC Merkle leaf via `merkle_pub_key`;
conditions carry only the SCHEME byte.

| Code | Name | Description |
|------|------|-------------|
| `0x0001` | SIG | Single-signature verification, scheme-selected |
| `0x0002` | MULTISIG | M-of-N threshold signature |
| `0x0003` | ADAPTOR_SIG | Adaptor signature (atomic-swap secret revelation) |
| `0x0004` | MUSIG_THRESHOLD | MuSig2 / FROST aggregate threshold |
| `0x0005` | KEY_REF_SIG | Signature using a pubkey commitment from a relay block |

#### 2. Timelock family (0x0101–0x0104)

| Code | Name | Description |
|------|------|-------------|
| `0x0101` | CSV | Relative timelock, block-height (BIP-68) |
| `0x0102` | CSV_TIME | Relative timelock, median-time-past |
| `0x0103` | CLTV | Absolute timelock, block-height (BIP-65) |
| `0x0104` | CLTV_TIME | Absolute timelock, median-time-past |

#### 3. Hash family (0x0203–0x0204)

| Code | Name | Description |
|------|------|-------------|
| `0x0203` | TAGGED_HASH | BIP-340 tagged hash preimage verification |
| `0x0204` | HASH_GUARDED | Raw SHA-256 preimage verification (non-invertible) |

#### 4. Covenant family (0x0301–0x0303)

| Code | Name | Description |
|------|------|-------------|
| `0x0301` | CTV | BIP-119 CheckTemplateVerify |
| `0x0302` | VAULT_LOCK | Two-path vault: recovery key (immediate) or hot key (delayed) |
| `0x0303` | AMOUNT_LOCK | Output amount within `[min_sats, max_sats]` |

#### 5. Recursion family (0x0401–0x0406)

All six types terminate: `RECURSE_SAME` persists indefinitely but
cannot grow; the others decrement or time out. Evaluation is
leaf-centric — mutate a copy of the revealed leaf, rebuild the
Merkle tree, compare against the output's `conditions_root`.

| Code | Name | Description |
|------|------|-------------|
| `0x0401` | RECURSE_SAME | Re-encumber with identical conditions |
| `0x0402` | RECURSE_MODIFIED | Re-encumber with parameterised mutations |
| `0x0403` | RECURSE_UNTIL | Recursive until a target block height |
| `0x0404` | RECURSE_COUNT | Countdown, terminates at zero |
| `0x0405` | RECURSE_SPLIT | Output splitting with value conservation and min-sats enforcement |
| `0x0406` | RECURSE_DECAY | Parameter decay (negated deltas) |

#### 6. Anchor family (0x0501–0x0507)

L2 protocol markers and the structured-data commitment.

| Code | Name | Description |
|------|------|-------------|
| `0x0501` | ANCHOR | Generic anchor marker |
| `0x0502` | ANCHOR_CHANNEL | Lightning channel anchor: two pubkeys + commitment number |
| `0x0503` | ANCHOR_POOL | Pool anchor: VTXO tree root + participant count |
| `0x0504` | ANCHOR_RESERVE | Reserve anchor: N-of-M guardian threshold |
| `0x0505` | ANCHOR_SEAL | Seal anchor: asset_id + state_hash |
| `0x0506` | ANCHOR_ORACLE | Oracle anchor: oracle pubkey + outcome count |
| `0x0507` | DATA_RETURN | Unspendable data commitment (max 40 bytes; replaces OP_RETURN) |

#### 7. PLC family (0x0601–0x0681)

Stateful contract primitives driven by `RECURSE_MODIFIED` state
transitions. Named after their PLC (Programmable Logic Controller)
analogues.

| Code | Name | Description |
|------|------|-------------|
| `0x0601` | HYSTERESIS_FEE | Fee rate hysteresis band |
| `0x0602` | HYSTERESIS_VALUE | Value hysteresis band |
| `0x0611` | TIMER_CONTINUOUS | Consecutive-block timer |
| `0x0612` | TIMER_OFF_DELAY | Hold-after-trigger timer |
| `0x0621` | LATCH_SET | Pubkey-authenticated state activation |
| `0x0622` | LATCH_RESET | Pubkey-authenticated state deactivation with delay |
| `0x0631` | COUNTER_DOWN | Decrement on signed event |
| `0x0632` | COUNTER_PRESET | Approval accumulator |
| `0x0633` | COUNTER_UP | Increment on signed event |
| `0x0641` | COMPARE | Amount vs. thresholds: EQ / NEQ / GT / LT / GTE / LTE / IN_RANGE |
| `0x0651` | SEQUENCER | Step sequencer |
| `0x0661` | ONE_SHOT | One-time activation window |
| `0x0671` | RATE_LIMIT | Per-block spending cap with accumulator and refill |
| `0x0681` | COSIGN | Cross-input co-spend constraint |

#### 8. Compound family (0x0701–0x0707)

Common multi-block patterns collapsed into a single typed block, for
both wire compression and reduced error surface.

| Code | Name | Composition |
|------|------|-------------|
| `0x0701` | TIMELOCKED_SIG | SIG + CSV |
| `0x0702` | HTLC | Hash + CSV + dual SIG (atomic swap) |
| `0x0703` | HASH_SIG | Hash preimage + SIG |
| `0x0704` | PTLC | ADAPTOR_SIG + CSV (point-locked) |
| `0x0705` | CLTV_SIG | SIG + CLTV |
| `0x0706` | TIMELOCKED_MULTISIG | MULTISIG + CSV |
| `0x0707` | ANCHOR_FEE | 2-of-2 sigs + fee band + weight limit |

#### 9. Governance family (0x0801–0x0807)

Transaction-level constraints that inspect the spending transaction
as a whole, not just the input being evaluated.

| Code | Name | Description |
|------|------|-------------|
| `0x0801` | EPOCH_GATE | Periodic spending window (block-height epochs) |
| `0x0802` | WEIGHT_LIMIT | Maximum transaction weight |
| `0x0803` | INPUT_COUNT | Input count bounds `[min, max]` |
| `0x0804` | OUTPUT_COUNT | Output count bounds `[min, max]` |
| `0x0805` | RELATIVE_VALUE | Output value as ratio of input value |
| `0x0806` | ACCUMULATOR | Merkle set membership proof |
| `0x0807` | OUTPUT_CHECK | Per-output value range + script hash constraint |

#### 10. Legacy family (0x0901–0x0907)

Wrappers that allow existing Bitcoin output types to migrate into
Ladder Script without re-keying. Evaluation delegates to the original
semantics.

| Code | Name | Wraps |
|------|------|-------|
| `0x0901` | P2PK_LEGACY | P2PK |
| `0x0902` | P2PKH_LEGACY | P2PKH |
| `0x0903` | P2SH_LEGACY | P2SH (hash160 + inner script) |
| `0x0904` | P2WPKH_LEGACY | P2WPKH (delegates to the P2PKH path) |
| `0x0905` | P2WSH_LEGACY | P2WSH (hash256 + inner script) |
| `0x0906` | P2TR_LEGACY | P2TR key-path |
| `0x0907` | P2TR_SCRIPT_LEGACY | P2TR script-path |

#### 11. QABIO family (0x0A01–0x0A02)

Multi-party atomic batching.

| Code | Name | Description |
|------|------|-------------|
| `0x0A01` | QABI_PRIME | Priming state transition: reveal auth chain preimage, covenant-mutate committed state |
| `0x0A02` | QABI_SPEND | Batch spend: primed state check + FALCON-512 coordinator signature over `SIGHASH_QABO` |

Full semantics are in the **QABIO** subsection of this Specification.

### Block wire encoding

Blocks are serialised with a one-byte header followed by a field list.
Two encodings are supported:

#### Micro-header

When the block type has a slot in the micro-header table and an
implicit field layout exists for the current serialisation context,
the header occupies one byte:

| Byte | Meaning |
|------|---------|
| `0x00`–`0x3E` | micro-header slot index (block type, not inverted) |
| `0x3F`–`0x7F` | reserved; rejected at deserialisation |
| `0x80` | escape: `uint16_t` block type follows (LE), not inverted |
| `0x81` | escape: `uint16_t` block type follows (LE), inverted |

Under an implicit layout, field count and per-field type bytes are
omitted; fields are read by position. NUMERIC fields are CompactSize-
encoded; fixed-size fields (HASH256=32, SCHEME=1) have no length
prefix; variable-size fields (PUBKEY, SIGNATURE, PREIMAGE,
SCRIPT_BODY) carry a CompactSize length prefix followed by their
bytes.

#### Explicit fields

When the micro-header is not used — the escape byte is emitted, the
block is inverted, or no implicit layout exists — the encoding is:

```
[n_fields: CompactSize]
for each field:
    [data_type: uint8_t]
    if NUMERIC: [value: CompactSize]
    else: [data_len: CompactSize] [data: bytes]
```

#### Examples

SIG block, conditions context, micro-header encoding:

```
00 01
```

Slot `0x00` (SIG), implicit SCHEME field `0x01` (Schnorr). Two bytes
total.

Inverted CSV block, explicit encoding:

```
81 01 01 01 08 90 01
```

Escape-invert byte `0x81`, type `0x0101` (CSV), 1 field, NUMERIC
(`0x08`), value 144. Seven bytes total.

### MLSC Merkle tree

#### Leaf order

```
[rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]
```

The leaf list is padded to the next power of two using
`MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")`.

#### Leaf computation

Every leaf uses the BIP-340 tagged-hash pattern:

```
leaf = TaggedHash("LadderLeaf", structural_template || value_commitment)
```

where:

- **structural_template** — block types, inverted flags, and coil
  metadata (including `output_index`). Deterministic from the
  condition set.
- **value_commitment** — `SHA256(field_values || pubkey[0] || ...)`.
  Pubkeys are appended in positional order via `PubkeyCountForBlock`;
  this is the `merkle_pub_key` commitment. The result is a SHA-256
  output, never attacker-chosen data.

Coil leaves use `TaggedHash("LadderLeaf", SerializeCoilData(coil))`.

#### Interior nodes

```
TaggedHash("LadderInternal", min(left, right) || max(left, right))
```

Sorted ordering eliminates the left/right bit per level that Taproot
proofs must carry.

#### Proof structure

```
[total_rungs: CompactSize]
[total_relays: CompactSize]
[rung_index: CompactSize]
<revealed rung blocks>                conditions-context serialised
[n_rung_relay_refs: CompactSize]
<rung relay_refs>
[n_revealed_relays: CompactSize]
for each revealed relay:
    [relay_index: CompactSize]
    <relay blocks>
    [n_relay_refs: CompactSize]
    <relay relay_refs>
[n_proof_hashes: CompactSize]
for each proof_hash: [hash: 32 bytes]
[n_mutation_targets: CompactSize]     for cross-rung RECURSE_MODIFIED / QABI_PRIME
for each mutation target:
    [rung_index: CompactSize]
    <rung blocks>
    [n_relay_refs: CompactSize]
    <relay_refs>
```

Mutation targets carry the full content of non-revealed rungs that
covenant checks depend on. Cross-rung `RECURSE_MODIFIED` uses this
channel to reveal the target rung; `QABI_PRIME` uses it to reveal the
`QABI_SPEND` rung so the covenant check has access to the full input
conditions tree.

### Sighash algorithms

Ladder Script defines two sighash algorithms: `SignatureHashLadder`
for per-input classical and PQ signatures, and `SIGHASH_QABO` for the
tx-level FALCON-512 batch signature used by QABIO. Both follow the
BIP-341 tagged-hash pattern and commit to the information they
authorise — never more, never less.

#### `SignatureHashLadder`

```
sighash = TaggedHash("LadderSighash",
    epoch(0) ||
    hash_type ||
    tx.version || tx.nLockTime ||
    [prevouts_hash]     skip if ANYPREVOUT or ANYONECANPAY
    [amounts_hash]      skip if ANYONECANPAY
    [sequences_hash]    skip if ANYONECANPAY
    [outputs_hash]      skip if SIGHASH_NONE
    spend_type(0) ||
    <input-specific data> ||
    [conditions_hash]   skip if ANYPREVOUTANYSCRIPT
    [single_output]     only if SIGHASH_SINGLE
)
```

Key-path spends use `TaggedHash("LadderKeyPathSighash", ...)` with the
same structure.

Valid hash types:

| Hash type | Value | Description |
|-----------|-------|-------------|
| DEFAULT | `0x00` | equivalent to ALL |
| ALL | `0x01` | commit to all outputs |
| NONE | `0x02` | do not commit to outputs |
| SINGLE | `0x03` | commit to the corresponding output only |
| ANYPREVOUT | `0x40` | skip prevout commitment (BIP-118 analogue) |
| ANYONECANPAY | `0x80` | commit only to this input |
| ANYPREVOUTANYSCRIPT | `0xC0` | skip prevout AND conditions commitment |

Valid combinations: `{0x00–0x03, 0x40–0x43, 0x81–0x83, 0xC0–0xC3}`.
Base hash types are identical to BIP-341; ANYPREVOUT (`0x40`) and
ANYPREVOUTANYSCRIPT (`0xC0`) are native; annex is not supported
(`spend_type = 0`); the script commitment is `conditions_root`, not
`tapleaf_hash`.

#### `SIGHASH_QABO`

Used exclusively for the coordinator's FALCON-512 signature over a
QABIO batch transaction. The hash order is:

1. `tx.nVersion` (u32 LE)
2. for each `tx.vin[i]`: `prevout.hash` (32 B), `prevout.n` (u32 LE),
   `nSequence` (u32 LE)
3. for each `tx.vout[i]`: `nValue` (i64 LE), `scriptPubKey` length
   (u64 LE), `scriptPubKey` bytes
4. `tx.conditions_root` (32 B)
5. `tx.qabi_block` length (u64 LE), `tx.qabi_block` bytes
6. `tx.nLockTime` (u32 LE)

Excluded:

- `tx.aggregated_sig` itself (the sig signs over the hash —
  chicken-and-egg)
- `tx.creation_proof` (not relevant to batch authorisation)
- Per-input witness stacks (each input's `spend_preimage` is
  independently validated against the UTXO's committed `auth_tip`, so
  witness malleation is prevented at the evaluator layer rather than
  the sighash layer)

`SIGHASH_QABO` is identical for every input of the same transaction.
The coordinator signs once; every primed input's `QABI_SPEND`
evaluator verifies against the same hash; the FALCON-512 verification
is cached and shared across inputs. This is what makes multi-party
batching economically viable under a 666-byte PQ signature.

### Evaluation semantics

#### Return values

| Value | Meaning |
|-------|---------|
| `SATISFIED` | all conditions met |
| `UNSATISFIED` | conditions not met (valid failure) |
| `ERROR` | malformed block (consensus failure) |
| `UNKNOWN_BLOCK_TYPE` | forward compatibility: treated as UNSATISFIED |

#### Order

1. Relays are evaluated first, in index order (forward-only, cached).
2. `EvalLadder = OR(EvalRung(rung[0]), ...)`.
3. `EvalRung = AND(EvalBlock(block[0]), ...)`.
4. All relays referenced by a rung must be SATISFIED before the
   rung's blocks are evaluated.

#### Conditions–witness merge

Every block type has two serialisation contexts:

- **Conditions context** — the locking side, committed in the MLSC
  tree. Contains hashes, timelocks, scheme selectors, structured
  integers — no secrets and (with the QABI_SPEND `owner_id` exception)
  no commitments to keys.
- **Witness context** — the spending side. Contains public keys,
  signatures, preimages — the unlocking data.

Before evaluation, conditions (from the MLSC proof) and witness data
are merged per block. Block types and inverted flags come from
conditions; fields are concatenated in each block.

#### Inversion

Blocks may be inverted (result flipped) via the `0x81` escape byte:

| Original | Inverted |
|----------|----------|
| SATISFIED | UNSATISFIED |
| UNSATISFIED | SATISFIED |
| ERROR | ERROR |
| UNKNOWN_BLOCK_TYPE | ERROR |

Inversion is restricted to the `IsInvertibleBlockType` allowlist,
which is fail-closed: new block types default to non-invertible.
Key-consuming blocks are never invertible. Inverting an
`UNKNOWN_BLOCK_TYPE` yields `ERROR`, not `SATISFIED`, so an attacker
cannot embed arbitrary data by constructing a failing block and
inverting it.

#### Block-specific rules

The evaluator for each block family enforces the following:

**Signature family.** SIG routes Schnorr / ECDSA / PQ based on the
SCHEME byte (or signature size if SCHEME is absent); pubkeys are
checked against the `merkle_pub_key` commitment. MULTISIG enforces
signatures in pubkey order, each matching a distinct pubkey.
ADAPTOR_SIG verifies against a combined challenge including the
adaptor point. MUSIG_THRESHOLD is on-chain single-sig (the
aggregation ceremony is off-chain). KEY_REF_SIG resolves a
`PUBKEY_COMMIT` from a relay block via `relay_refs` and verifies the
signature against the referenced key.

**Timelock family.** CSV / CSV_TIME via `CheckSequence`; CLTV /
CLTV_TIME via `CheckLockTime`.

**Hash family.** TAGGED_HASH computes
`SHA256(tag_hash || tag_hash || preimage)` and compares against the
committed hash (BIP-340). HASH_GUARDED computes raw
`SHA256(preimage)`; non-invertible.

**Covenant family.** CTV computes the BIP-119 template hash for the
spending tx at the current input index and compares. VAULT_LOCK
provides two paths — a recovery key (immediate) and a hot key
(requires CSV delay). AMOUNT_LOCK checks the output amount is in
`[min_sats, max_sats]`.

**Recursion family.** Evaluation is leaf-centric: mutate a copy of
the revealed rung, recompute its leaf hash via `BuildCPRung`, rebuild
the Merkle tree, and compare against the output's `conditions_root`.
RECURSE_SAME is an identity covenant. RECURSE_MODIFIED applies
parameterised mutations (block_idx, param_idx, delta) to condition
fields; multi-rung mutations use `mutation_targets` in the MLSC
proof. RECURSE_UNTIL releases the covenant at a target block height.
RECURSE_COUNT and RECURSE_SPLIT decrement an explicit counter and
terminate at zero. RECURSE_DECAY is RECURSE_MODIFIED with negated
deltas, bounded by `max_depth`.

**Anchor family.** ANCHOR is a marker (SATISFIED if `anchor_id > 0`).
ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, and
ANCHOR_ORACLE carry structured metadata for L2 protocols.
DATA_RETURN always returns ERROR (unspendable by construction).

**PLC family.** HYSTERESIS_FEE / HYSTERESIS_VALUE check in-band;
TIMER_* check accumulated vs. target blocks; LATCH_SET / LATCH_RESET
use pubkey-authenticated state transitions; COUNTER_DOWN /
COUNTER_PRESET / COUNTER_UP accumulate on signed events; COMPARE
routes to seven comparison operators; SEQUENCER steps through a
fixed program; ONE_SHOT allows a single activation; RATE_LIMIT caps
spending with an accumulator that refills over a window; COSIGN
requires another input in the same transaction to have matching
conditions.

**Compound family.** Each type is equivalent to the AND of its
components, collapsed into one block for wire compression. The
evaluator applies each sub-check in turn.

**Governance family.** EPOCH_GATE checks
`(height % epoch_size) < window_size`. WEIGHT_LIMIT bounds
`tx.weight`. INPUT_COUNT and OUTPUT_COUNT bound `[min, max]` on the
respective counts. RELATIVE_VALUE enforces
`output_value >= input_value * numerator / denominator`. ACCUMULATOR
verifies a Merkle set-membership proof against a committed root
(inverted form = blocklist). OUTPUT_CHECK enforces a per-output value
range and script-hash constraint at a given index.

**Legacy family.** Evaluation delegates to the equivalent legacy
semantics via a shared path, depth-limited at evaluation time for
P2SH / P2WSH / P2TR_SCRIPT to prevent unbounded nested scripts.

**QABIO family.** See the QABIO subsection.

### QABIO

QABIO — Quantum Atomic Batch Input / Output — is the facility that
lets N independent parties collapse their UTXOs into one transaction
authorised by one FALCON-512 signature from a designated coordinator.
It is specified as two block types, one transaction-level block
structure, one sighash mode, and one mempool policy. Everything
compositional in this subsection (the auth chain, the covenant, the
output-set match) builds on the mechanisms already defined above.

#### Context and actors

A QABIO transaction has a **coordinator** — one party with a
FALCON-512 keypair who signs the batch — and **N participants**, each
of whom holds an `auth_seed` (a 32-byte secret) and a separate
signing key for an escape path. No key material is shared. The
coordinator never holds participants' funds and cannot produce a
valid batch signature without seeing the assembled transaction
first.

#### UTXO shape (wallet convention)

Every QABIO-enabled `rung_tx` output should include the following
rungs in its MLSC conditions tree. This is a wallet convention, not
consensus-mandated; consensus enforces the individual blocks, and
wallets are free to add or omit other rungs alongside them.

```
rung 0: sig(@owner)                         escape hatch: unilateral recovery
rung 1: qabi_prime()                        priming entry point
rung 2: qabi_spend(auth_tip, 0, 0, 0, owner_id)   batch-spend entry
```

Fields in the `qabi_spend` rung are zeroed before priming (the UTXO
has not yet been committed to any batch). The `auth_tip` is set at
UTXO creation to `SHA256^N(auth_seed)`. Default `N = 20,000`, giving
roughly 10,000 clean priming attempts before the chain is exhausted.

#### `qabi_block` transaction field

When a QABIO transaction is broadcast, it carries a structured data
blob in `tx.qabi_block`:

```
QABIBlock {
    version              : uint8     currently 0x01
    batch_id             : uint256   32 bytes, unique batch identifier
    coordinator_pubkey   : bytes     exactly 897 bytes (FALCON-512)
    prime_expiry_height  : uint32    max block height for the batch
    entries              : QABIEntry[]
    outputs              : CTxOut[]
}

QABIEntry {
    participant_id       : uint256   SHA256(participant FALCON pubkey)
    contribution         : int64     sats
    destination_index    : varint    index into outputs[]
}

QABI_ROOT = SHA256(canonical_serialise(QABIBlock))
```

Canonical serialisation uses little-endian integers, Bitcoin
`CompactSize` varints, and length-prefixed vectors. A single-bit
difference in the serialised bytes produces a different `QABI_ROOT`.

`qabi_block` size caps:

| Cap | Value | Where enforced |
|-----|-------|----------------|
| Hard cap | 262,144 bytes (256 KB) | `UnserializeTransaction` — rejected at block acceptance |
| Soft cap | 65,536 bytes (64 KB) | Standard relay policy |

The fixed header (version, batch_id, coordinator_pubkey,
prime_expiry_height, framing) is ~937 bytes. Each additional
participant adds ~74 bytes (entry + destination output). The hard cap
allows batches of up to ~3,500 participants; the soft cap ~870. See
the Scaling and Fees appendix for measured numbers at multiple sizes.

#### `QABI_PRIME` — priming state transition

Spent via rung 1 of the wallet-convention tree. Witness layout:

| Index | Type | Name |
|-------|------|------|
| 0 | `HASH256` | `new_committed_root` |
| 1 | `NUMERIC` | `prime_depth` |
| 2 | `NUMERIC` | `new_committed_expiry` |
| 3 | `PREIMAGE` | `prime_preimage` |

QABI_PRIME has no conditions-context fields. The state it mutates
(the QABI_SPEND rung's `committed_root`, `committed_depth`, and
`committed_expiry`) is read from the input UTXO's conditions tree via
the MLSC proof; QABI_PRIME does not duplicate state in its own fields.

Consensus checks, in order:

1. Witness field count and types match the implicit
   `QABI_PRIME_WITNESS` layout.
2. Exactly one `QABI_SPEND` block is discoverable across the revealed
   rungs of the input conditions tree. Because QABI_PRIME is
   cross-rung (it reads state from the QABI_SPEND rung, not its own),
   signrungtx must reveal the `QABI_SPEND` rung as a mutation target
   in the MLSC proof.
3. `prime_depth > committed_depth` — monotonic progression.
4. `SHA256^prime_depth(prime_preimage) == auth_tip` — preimage valid
   against the committed chain tip.
5. **Covenant**: the output UTXO's `conditions_root` must equal the
   MLSC root of the input conditions tree with the following
   mutations applied inside the QABI_SPEND rung:
   - `committed_root ← new_committed_root`
   - `committed_depth ← prime_depth`
   - `committed_expiry ← new_committed_expiry`

   Every other leaf (including `auth_tip`, `owner_id`, Rung 0, other
   rungs, relays, coil metadata) must be preserved bit-exact.

The covenant check is what binds the priming transaction to a
specific batch commitment. The participant chooses `new_committed_root`
(which will be `SHA256(qabi_block)` for the batch they intend to
participate in) and covenant-forces it into the output UTXO. No
coordinator signature is required at priming time; only the `auth_seed`
holder can produce a valid preimage.

#### `QABI_SPEND` — batch spend

Spent via rung 2 of the wallet-convention tree. Conditions layout
(5 fields, committed at UTXO creation):

| Index | Type | Name |
|-------|------|------|
| 0 | `HASH256` | `auth_tip` |
| 1 | `HASH256` | `committed_root` |
| 2 | `NUMERIC` | `committed_depth` |
| 3 | `NUMERIC` | `committed_expiry` |
| 4 | `PUBKEY_COMMIT` | `owner_id` |

Witness layout (6 fields — the conditions plus the spend preimage):

| Index | Type | Name |
|-------|------|------|
| 0–4 | *(same as conditions)* | |
| 5 | `PREIMAGE` | `spend_preimage` |

Consensus checks, per primed input:

1. `committed_root != 0` — UTXO is primed.
2. `current_block_height <= committed_expiry` — batch not expired.
3. `SHA256^(committed_depth + 1)(spend_preimage) == auth_tip` — spend
   preimage valid, one depth deeper than the priming depth.
4. `SHA256(tx.qabi_block) == committed_root` — qabi_block matches the
   batch this UTXO was primed for.
5. `tx.qabi_block` parses as a well-formed QABIBlock with
   `version == 0x01`, `coordinator_pubkey.size() == 897`, non-negative
   contributions, destination indices in range, and no trailing data.
6. `parsed.prime_expiry_height == committed_expiry` — expiry
   binding.
7. `owner_id` appears in `parsed.entries[*].participant_id` — identity
   match against the batch manifest. Performed as an `O(1)`
   hash-indexed lookup against a pre-built `std::unordered_set`; the
   total identity-check work across all inputs of a batch is `O(N)`,
   not `O(N²)`.
8. **Full output-set match**: `tx.vout` is bit-exact equal to
   `parsed.outputs` — same count, same order, same values, same
   scriptPubKeys. This closes the coordinator-skim attack.
9. `FalconVerify(parsed.coordinator_pubkey, SIGHASH_QABO(tx), tx.aggregated_sig) == VALID`.
   Cached per transaction via the QABO sig cache — one verify per
   transaction, not per input.

All nine checks must pass for every primed input, or the whole
transaction is rejected. There is no partial-acceptance path.

#### Compositional atomicity

A consequence of check 4 (not a separate rule): every primed input's
`committed_root` equals `SHA256(tx.qabi_block)`. If the coordinator
alters the batch — adds, removes, or reorders an entry, changes an
output, shifts the expiry — the recomputed root diverges and every
primed input fails check 4. No strict subset of a primed batch can
execute. To reduce the participant set, the coordinator must issue a
new QABIBlock and every remaining participant must re-prime to the
new root, burning one auth-chain depth each.

This eliminates the "silently reduced batch" attack class: a
participant is guaranteed that the transaction they primed for is
either the exact transaction that lands on-chain or nothing at all.

#### Replace-By-Depth (RBD)

Mempool policy for QABI_PRIME transactions. A priming transaction
`T2` replaces an existing priming transaction `T1` if:

- `T1` and `T2` spend the same prevout.
- Both carry a `QABI_PRIME` block for that input.
- `T2.prime_depth > T1.prime_depth` on every shared prevout.

Integrated into `MemPoolAccept::ReplacementChecks`: when the new
transaction and every conflicting transaction are priming txs, RBD
replaces the fee-based `PaysMoreThanConflicts` (BIP-125 Rule #6) and
`PaysForRBF` (Rules #3 and #4). Mempool hygiene rules (Rule #2 no new
unconfirmed, Rule #5 max replacements) are still enforced.

RBD gives the legitimate UTXO owner a cryptographic "last word" over
any sniper who scrapes a shallower preimage from the mempool. Only the
`auth_seed` holder can produce a deeper preimage (one-way hash
property); fee-based RBF cannot capture this asymmetry. When the
conflicting set is mixed (some priming, some standard transactions),
RBD is not applied and fee-based RBF runs normally — combining the
two policies is semantically ambiguous and the safer fallback is the
existing policy.

### Consensus limits

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
| DATA max size | 40 | `types.h` |
| MIN_RUNG_OUTPUT_VALUE | 546 | `serialize.h` |
| COIL_ADDRESS_HASH_SIZE | 32 | `serialize.h` |
| RUNG_MLSC_PREFIX | `0xDF` | `serialize.h` |
| DATA_RETURN outputs per tx | 1 | `evaluator.cpp` |
| Witness stack elements per input | 2 | `evaluator.cpp` |
| Creation proof max leaves | 252 | CompactSize < 253 |
| QABI_COORDINATOR_PUBKEY_SIZE | 897 | `qabi.h` |
| QABI_AGGREGATED_SIG_MAX | 666 | `qabi.h` |
| QABI_BLOCK_MAX_HARD | 262,144 | `qabi.h` |
| QABI_BLOCK_MAX_SOFT | 65,536 | `qabi.h` |
| QABI_AUTH_CHAIN_DEFAULT_LENGTH | 20,000 | `qabi.h` |

## Rationale

### Why typed blocks instead of opcodes

Bitcoin Script's opcode model provides maximum generality at the cost
of static analysis. Given an arbitrary Script program, determining
its resource consumption, whether it terminates, or what shape of
transaction can satisfy it requires executing it. Ladder Script's
typed blocks provide deterministic bounds at parse time. Each block
has a fixed evaluation function, a known maximum field count, and
bounded cost. A verifier can determine worst-case cost without
executing any block, and static analysis tools (wallets, indexers,
formal verifiers) can reason about a condition set before any signing
takes place. The deterministic resource bound per input is
`MAX_RUNGS(16) × MAX_BLOCKS_PER_RUNG(8) × MAX_FIELDS_PER_BLOCK(16)`.

### Why 64 types instead of a handful of generic primitives

A minimal design — SIG, TIMELOCK, HASH, COVENANT with sub-type
parameters — has three problems. (1) Wire overhead: a generic
TIMELOCK needs three or more fields where CSV needs one. (2) Error
surface: compound blocks enforce exact field sequences at parse
time; assembling the same semantics from four generic blocks
multiplies the failure modes. (3) Static analysis cost: O(1)
dispatch on concrete type is cheaper than parsing sub-type fields.
The catalogue is large because each common pattern — HTLC, PTLC,
TIMELOCKED_SIG, RATE_LIMIT — has a single type with an enforced
layout, not an ad-hoc composition.

### Why merkle_pub_key

Without it, conditions carry PUBKEY fields on-chain, and a PUBKEY
field can hold up to 2,048 bytes. An attacker creates a SIG block
with a 2,048-byte "public key" encoding arbitrary data, never spends
the output, and the data is permanently stored in the chain's
scriptPubKey set. Moving public keys to the Merkle leaf reduces
conditions to 1 byte (SCHEME) per signature block. The cost is one
additional hash per key-consuming block during MLSC verification,
negligible relative to the signature verification itself. The
benefit is the elimination of the largest writable on-chain data
surface.

### Why MLSC instead of Taproot's script tree

Three structural changes. (1) Sorted interior nodes —
`min(L, R) || max(L, R)` eliminates the left/right bit per level and
makes proofs order-independent. (2) Pubkeys in leaves — enables
merkle_pub_key as a structural anti-spam measure. (3) A dedicated
coil leaf per output — gives Ladder Script the notion of per-output
unlock metadata (UNLOCK / UNLOCK_TO, attestation mode, scheme,
destination), which Taproot has no equivalent for.

### Why a shared conditions_root per transaction

One root per transaction (not per output) means each additional
output adds only 8 bytes (nValue) on the wire. For a 100-output
batch this saves ~3,500 bytes against per-output P2TR scriptPubKeys.
The tradeoff: all outputs in a TX_MLSC transaction share the same
condition set. Different spending paths per output are expressed
via `output_index` inside the coil, and the rung governing each
output is identified by that field.

### Why forward-only relay indexing

Relay `N` can only reference relays `0..N-1`, guaranteeing
acyclicity by construction (topological sort). The maximum transitive
depth is bounded at `MAX_RELAY_DEPTH = 4`. Without this, cycle
detection would require graph search at deserialisation, adding
complexity and DoS surface for no functional gain.

### Why the inversion allowlist is fail-closed

New block types default to non-invertible. If inversion were the
default, an attacker could embed arbitrary data in an unknown block
type by constructing a failing block and inverting it to SATISFIED
without the network understanding the block's semantics.
`UNKNOWN_BLOCK_TYPE` inverted becomes `ERROR`, not `SATISFIED`.

### Why PREIMAGE min = 1

Required for P2SH and P2WSH legacy wrappers, where the inner
conditions serialised as `SCRIPT_BODY` can be shorter than 32 bytes
(for instance, a single CSV(144) block is 4 bytes). `SCRIPT_BODY` and
`PREIMAGE` share the preimage count limit.

### Why SCHEME is 1 byte

Each SCHEME byte has 256 possible selectors. Current allocation is
6 values (2 classical, 4 PQ). New post-quantum schemes from later
NIST rounds receive new codes within the existing byte. No wire
format changes, no new data types, no hard fork for future PQ
additions.

### Why `nVersion = 4`

Version 3 is claimed by BIP-431 (package relay). Version 4 is
currently non-standard and invalid on pre-Ladder nodes, satisfying
the soft-fork escape hatch: old nodes treat v4 transactions as
anyone-can-spend and do not enforce Ladder Script rules.

### Why `0xDF` as the MLSC prefix

`0xDF` is not a valid opcode in any existing Script interpretation.
It lies in the OP_SUCCESS range for Tapscript but outside every
P2SH / P2WSH / P2WPKH template pattern. Old nodes see
`0xDF || conditions_root` as an unrecognised scriptPubKey pattern
and treat it as anyone-can-spend, the standard soft-fork behaviour.

### Why sorted interior Merkle nodes

Sorted nodes remove the need for left/right path bits in proofs.
Each sibling hash in the proof is 32 bytes with no directional
metadata; the verifier sorts and hashes. This simplifies proof
generation, reduces proof size by 1 bit per level, and makes the
verifier's job order-independent.

### Why a creation proof

The creation proof validates the Merkle tree structure at block
acceptance time. Without it, a miner could publish a `conditions_root`
that commits to an impossible tree shape, potentially opening
spending paths that were never intended. The creation proof binds
the tree structure to the transaction at fund time, preventing this
entire attack class.

### Why QABIO uses structural aggregation instead of a cryptographic one

No post-quantum signature aggregation scheme is currently
standardised, constant-size, and trusted-setup-free. QABIO achieves
"one signature authorises N UTXOs" by requiring every input to
commit to the same block and signing the block once. The per-input
`spend_preimage` supplies the missing "each owner consented"
property without requiring per-input PQ signatures. The tradeoff is
that participants must prime before the batch fires; the benefit is
no per-input 666-byte PQ signature.

### Why a single hash chain per UTXO instead of two

Earlier iterations used two chains per UTXO — Chain A for priming
and Chain B for spend consent. Consolidating to one chain (prime at
depth `d`, spend at depth `d+1`) preserves security (a sniper with
the priming preimage cannot compute the spend preimage by the
one-way hash property) while halving the state and simplifying the
wallet.

### Why `qabi_block` is carried natively in the batch transaction

Earlier iterations used a separate commitment transaction that
created an anchor UTXO committing to the QABIBlock. This cost ~$0.65
per batch attempt plus a $1–3 sweep on failure. Carrying `qabi_block`
natively in the batch transaction costs zero on failure — the
coordinator simply does not broadcast anything until all participants
have primed — and loses only pre-priming inconsistency detection,
which is a UX concern rather than a security one, because
compositional atomicity still prevents actual theft.

### Why `prime_expiry_height` lives inside the qabi_block

Each batch carries a hard deadline committed to its root. This
prevents the coordinator from holding a primed UTXO hostage
indefinitely, and it creates a natural retry cadence: if the batch
does not land by `committed_expiry`, every primed UTXO auto-falls
out of the QABI_SPEND path and the participant can recover via
rung 0. Because expiry is committed to the root, participants agree
to the expiry before they prime.

### Why full output-set match in QABI_SPEND

An earlier iteration of the QABI_SPEND evaluator verified only each
participant's own destination output. This allowed the coordinator
to add an extra output (e.g. to themselves) for value participants
thought was going to miner fees. Requiring `tx.vout` to be
bit-exact equal to `qabi_block.outputs` closes the skim: a
coordinator who wants a fee must include themselves as an explicit
entry in the block, visible to every participant at block-review
time.

### Why Replace-By-Depth instead of Replace-By-Fee for priming

A sniper who scrapes a mempool priming preimage can attach a higher
fee and steal the priming under standard RBF. RBD uses the one-way
hash property — only the legitimate owner can produce a deeper
preimage — to give the owner a cryptographic last word. Fee-based
RBF cannot capture this asymmetry because fee is not a function of
key material.

### Why FALCON-512 specifically for QABIO

FALCON-512 has the smallest signature of any NIST-standardised PQ
signature scheme — 666 bytes, vs. 1,280 for FALCON-1024, 3,293 for
Dilithium3, and ~8 KB and up for SPHINCS+. Since the signature is
a fixed per-transaction overhead amortised across every primed
input, the smaller the signature, the lower the per-input cost.
Other schemes can be unlocked by a future `QABI_BLOCK_VERSION = 0x02`
that carries a scheme selector; the mechanism exists, only the
dispatch is not wired yet.

## Backwards Compatibility

### Soft-fork deployment

Version 4 transactions are currently non-standard and invalid on
pre-activation nodes. Existing nodes treat v4 transactions as
anyone-can-spend because `0xDF` is not a recognised scriptPubKey
pattern. Old nodes accept blocks containing v4 transactions (they
cannot reject a block for containing a tx whose scriptPubKey is
anyone-can-spend); upgraded nodes enforce the full Ladder Script
rules. This is a standard soft fork.

### No impact on existing transactions

Ladder Script rules apply exclusively to `nVersion = 4`. Transactions
with `nVersion` 1, 2, or 3 are unaffected. Existing UTXOs, existing
wallets, existing transaction formats continue to behave identically.

### Legacy family for migration

The seven legacy block types allow existing key material within
Ladder Script conditions without re-keying. A P2PKH address holder
migrates via `p2pkh(@key)`; a P2TR address holder via
`p2tr(@key)`. Every existing script pattern has a wrapper.

### Wallet compatibility

Outputs with `0xDF` scriptPubKeys are unknown to non-upgraded
wallets. Such wallets will not display them. This is the same
behaviour observed for every new output type historically
(native SegWit, Taproot).

### Removed features

Non-Merkelised conditions (`0xC1` prefix) are removed; all outputs
use MLSC format. The COVENANT coil type (`0x03`) is removed; only
UNLOCK (`0x01`) and UNLOCK_TO (`0x02`) are valid unlock types. The
AGGREGATE attestation mode (`0x02`) is removed along with Schnorr
half-aggregation; the `aggregated_sig` transaction field is now used
by QABIO as the FALCON-512 coordinator signature.

### QABIO-specific compatibility

QABIO activates as part of the same soft fork. Pre-activation nodes
reject `qabi_block` serialisation (unknown tx-level field) and the
new block types (`QABI_PRIME`, `QABI_SPEND`) via the existing
`IsKnownBlockType` machinery. UTXOs created before activation do not
include the QABI rungs; to participate in batches, they must be
re-created via a self-spend to a new QABI-enabled UTXO.

## Activation

All 64 block types and the QABIO machinery activate together as a
single soft fork. Partial activation is not supported: compound
blocks reference signature semantics, recursion blocks reference
MLSC leaf computation, PLC blocks reference recursion for state
transitions, and QABIO references both the covenant pattern and the
PQ signature dispatch. The activation mechanism (BIP-9 signalling or
BIP-8 mandatory activation) is outside the scope of this
specification.

## Reference Implementation

Source: `src/rung/` (~15,000 lines). Modifications to existing
Bitcoin Core outside of `src/rung/`: ~420 lines across 24 files.

| File | Description |
|------|-------------|
| `types.h` | Block type enum, data types, micro-header table, implicit layouts, `IsInvertibleBlockType`, `PubkeyCountForBlock` |
| `evaluator.cpp` | All 64 block evaluators, `EvalBlock`, `EvalLadder`, `VerifyRungTx`, QABIO per-tx validation |
| `serialize.cpp` | Wire format, micro-header encoding, implicit fields |
| `conditions.cpp` | MLSC Merkle tree, proof verification, mutation-target handling |
| `sighash.cpp` | `SignatureHashLadder` implementation |
| `qabi.{h,cpp}` | QABIBlock struct, canonical serialisation, auth chain helpers, `ComputeSighashQABO` |
| `policy.cpp` | Standardness rules, RBD mempool replacement |
| `descriptor.cpp` | Descriptor language parser and formatter |
| `pq_verify.cpp` | PQ signature verification via liboqs (optional) |

Test coverage:

- **Unit tests.** 590 test cases in `src/test/rung_tests.cpp`
  (suite `rung_tests`, includes the 77-case `qabi_tests` subsuite).
- **Functional tests.** 60 regtest functional tests via
  `test/functional/feature_*.py`, covering the full happy-path
  lifecycle for every block family and the QABIO priming + escape
  + reorg survival flows.
- **Formal verification.** 21 TLA+ specifications covering core
  evaluator semantics, MLSC tree construction, sighash binding, and
  QABIO compositional atomicity.
- **Live signet.** Every block type exercised on the ladder-signet
  chain. QABIO real mined priming and escape transactions available
  in the public test vectors appendix.

## Security Considerations

### Anti-spam surface

Ladder Script caps the user-chosen embeddable data per transaction
at **144 bytes**, flat, regardless of input or output count. The
breakdown:

| Channel | Bytes | Notes |
|---------|-------|-------|
| `conditions_root` | 32 | one per tx; adversary must burn an output to commit; triple-hashed from validated structure via creation proof |
| PREIMAGE fields | 64 | `MAX_PREIMAGE_FIELDS_PER_TX = 2`, 32 bytes each |
| DATA_RETURN | 40 | intentional, typed commitment |
| `nLockTime` + `nSequence` | 8 | standard Bitcoin fields |
| **Total** | **144** | flat per tx |

No contiguous attacker-chosen channel exceeds 64 bytes.
`value_commitment` fields are SHA-256 outputs; structural templates
are validated enums; UTXO set entries are protocol-derived hashes.
Inscriptions are structurally impossible. Taproot, for comparison,
permits roughly 4 MB of arbitrary data per transaction via the
witness — a factor-of-27,000 difference.

Seven mechanisms enforce this at deserialisation time:

1. **Selective inversion.** The `IsInvertibleBlockType` allowlist
   denies inversion for every key-consuming block. An attacker cannot
   embed data by constructing a failing block with a garbage pubkey
   and inverting the result.
2. **`IsDataEmbeddingType` rejection.** For blocks without an
   implicit layout, the types PUBKEY_COMMIT, HASH256, HASH160, and
   DATA are rejected unconditionally. This closes the
   layout-less-block data channel.
3. **PREIMAGE field limit.** `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`
   (fast reject) and `MAX_PREIMAGE_FIELDS_PER_TX = 2` (binding,
   summed across all inputs of the transaction).
4. **DATA type restriction.** Permitted only inside DATA_RETURN
   blocks. Any other block carrying a DATA field is rejected.
5. **merkle_pub_key.** Public keys exist only in the witness. The
   conditions side carries a 1-byte SCHEME field. The largest
   writable on-chain surface is eliminated.
6. **Strict field enforcement.** When an implicit layout exists,
   field count and types must match exactly. Extra fields rejected.
7. **Blanket HASH256 rejection.** Layout-less blocks cannot carry
   HASH256 fields regardless of serialisation context.

### Recursion termination

All six recursion types terminate. RECURSE_SAME persists indefinitely
but cannot grow. RECURSE_COUNT and RECURSE_SPLIT decrement counters
to zero. RECURSE_UNTIL terminates at a target block height.
RECURSE_MODIFIED and RECURSE_DECAY are bounded by `max_depth`.
Legacy script wrappers are depth-limited at evaluation time.

### Sighash binding

`SignatureHashLadder` commits to `conditions_root` by default, binding
every signature to the full condition set. Replay across condition
sets is prevented unless the signer opts out via
`ANYPREVOUTANYSCRIPT (0xC0)`.

### Post-quantum fail-closed

PQ support is compile-time optional (liboqs). Without liboqs, PQ
scheme verification returns UNSATISFIED (fail-closed). The
`SIGNATURE` max of 50,000 bytes accommodates SPHINCS+-SHA2-256f at
~49,216 bytes.

### QABIO-specific attacks

- **Coordinator skim** (closed by check 8): `tx.vout` must bit-exact
  equal `qabi_block.outputs`. A coordinator who wants a fee must
  include themselves as an explicit entry in the block, visible at
  block-review time.
- **Silently reduced batch** (closed by compositional atomicity): any
  change to the participant set or output list changes
  `SHA256(qabi_block)`, which invalidates every primed input's
  check 4. No subset of a primed batch can execute.
- **Priming theft via mempool sniping** (closed by RBD): only the
  `auth_seed` holder can produce a deeper preimage, and deeper
  preimages win replacement regardless of fee.
- **Expiry mismatch** (closed by check 9): `prime_expiry_height`
  inside the qabi_block must equal the committed expiry. A
  coordinator cannot sign over a block with a different expiry than
  the one participants primed against.
- **Cross-batch replay** (closed by monotonic depth): every priming
  and spending event consumes a strictly deeper chain depth. A
  preimage consumed in one batch cannot be reused in another.
- **Coordinator disappearance**: the participant's escape rung (the
  wallet-convention rung 0) remains valid in both unprimed and
  primed states. If the coordinator never produces a valid
  QABI_SPEND, the participant can sweep unilaterally at any time
  using their own signing key. The primed UTXO's rung 0 leaf is
  byte-identical to the unprimed UTXO's rung 0 leaf — the covenant
  check only affects the QABI_SPEND rung.

### Dust threshold

`MIN_RUNG_OUTPUT_VALUE` (546 sats) prevents dust outputs. DATA_RETURN
outputs (`nValue == 0`) are the sole exception.

## Acknowledgements

The MLSC Merkle tree follows the BIP-340 tagged hash pattern. The
CTV block implements BIP-119 template hash verification.
ANYPREVOUT / ANYPREVOUTANYSCRIPT sighash flags follow BIP-118 design
principles. The auth chain priming pattern is inspired by
time-lock puzzles and Lamport-style one-time signatures, adapted for
covenant-backed multi-party batching.

## Appendix A: Implicit Field Layouts

Notation: `TYPE(N)` = fixed `N` bytes, no length prefix.
`TYPE(var)` = CompactSize length prefix + data.
NUMERIC = CompactSize-encoded.

### Conditions context

| Block type | Implicit layout |
|------------|-----------------|
| SIG | SCHEME(1) |
| MULTISIG | NUMERIC(var), SCHEME(1) |
| ADAPTOR_SIG | *(empty)* |
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
| QABI_PRIME | *(empty)* |
| QABI_SPEND | HASH256(32), HASH256(32), NUMERIC(var), NUMERIC(var), PUBKEY_COMMIT(32) |

`RECURSE_MODIFIED` and `RECURSE_DECAY` carry variable field counts
(`2 + 4·N` mutation descriptors) and use explicit encoding; they
are protected by `IsDataEmbeddingType` rejection.

### Witness context

| Block type | Implicit layout |
|------------|-----------------|
| SIG | PUBKEY(var), SIGNATURE(var) |
| MULTISIG | PUBKEY(var) × N, SIGNATURE(var) × M |
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
| QABI_PRIME | HASH256(32), NUMERIC(var), NUMERIC(var), PREIMAGE(var) |
| QABI_SPEND | HASH256(32), HASH256(32), NUMERIC(var), NUMERIC(var), PUBKEY_COMMIT(32), PREIMAGE(var) |

All other block types use explicit field encoding in the witness
context.

## Appendix B: Micro-header Slot Assignments

63 slots are currently assigned (`0x00`–`0x3E`). Slots `0x07` and
`0x08` are reserved. Slots `0x3F`–`0x7F` are unused and rejected at
deserialisation. The authoritative table is
`src/rung/types.h:MICRO_HEADER_TABLE`. ANCHOR_FEE (`0x0707`) has no
micro-header slot and is encoded via the full header. QABI_PRIME
and QABI_SPEND have micro-header slots at the tail of the table.

| Slot | Block type | Slot | Block type |
|------|------------|------|------------|
| `0x00` | SIG | `0x20` | COUNTER_PRESET |
| `0x01` | MULTISIG | `0x21` | COUNTER_UP |
| `0x02` | ADAPTOR_SIG | `0x22` | COMPARE |
| `0x03` | CSV | `0x23` | SEQUENCER |
| `0x04` | CSV_TIME | `0x24` | ONE_SHOT |
| `0x05` | CLTV | `0x25` | RATE_LIMIT |
| `0x06` | CLTV_TIME | `0x26` | COSIGN |
| `0x07` | *(reserved)* | `0x27` | TIMELOCKED_SIG |
| `0x08` | *(reserved)* | `0x28` | HTLC |
| `0x09` | TAGGED_HASH | `0x29` | HASH_SIG |
| `0x0A` | CTV | `0x2A` | PTLC |
| `0x0B` | VAULT_LOCK | `0x2B` | CLTV_SIG |
| `0x0C` | AMOUNT_LOCK | `0x2C` | TIMELOCKED_MULTISIG |
| `0x0D` | RECURSE_SAME | `0x2D` | EPOCH_GATE |
| `0x0E` | RECURSE_MODIFIED | `0x2E` | WEIGHT_LIMIT |
| `0x0F` | RECURSE_UNTIL | `0x2F` | INPUT_COUNT |
| `0x10` | RECURSE_COUNT | `0x30` | OUTPUT_COUNT |
| `0x11` | RECURSE_SPLIT | `0x31` | RELATIVE_VALUE |
| `0x12` | RECURSE_DECAY | `0x32` | ACCUMULATOR |
| `0x13` | ANCHOR | `0x33` | MUSIG_THRESHOLD |
| `0x14` | ANCHOR_CHANNEL | `0x34` | KEY_REF_SIG |
| `0x15` | ANCHOR_POOL | `0x35` | P2PK_LEGACY |
| `0x16` | ANCHOR_RESERVE | `0x36` | P2PKH_LEGACY |
| `0x17` | ANCHOR_SEAL | `0x37` | P2SH_LEGACY |
| `0x18` | ANCHOR_ORACLE | `0x38` | P2WPKH_LEGACY |
| `0x19` | HYSTERESIS_FEE | `0x39` | P2WSH_LEGACY |
| `0x1A` | HYSTERESIS_VALUE | `0x3A` | P2TR_LEGACY |
| `0x1B` | TIMER_CONTINUOUS | `0x3B` | P2TR_SCRIPT_LEGACY |
| `0x1C` | TIMER_OFF_DELAY | `0x3C` | DATA_RETURN |
| `0x1D` | LATCH_SET | `0x3D` | HASH_GUARDED |
| `0x1E` | LATCH_RESET | `0x3E` | OUTPUT_CHECK |
| `0x1F` | COUNTER_DOWN | `0x3F`–`0x7F` | *(unused, rejected)* |

## Appendix C: Descriptor Language

### Grammar

```
ladder      = "ladder(" output_list ")"
output_list = output { "," output }
output      = "output(" index "," "or(" rung { "," rung } ")" ")"
rung        = block | "and(" block { "," block } ")"
block       = base_block | "!" base_block
```

Each `output(index, ...)` declares which transaction output the
enclosed rungs govern, matching the coil's `output_index` field.

### Block syntax (one per family)

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
qabi_prime()                                          # QABIO
qabi_spend(auth_tip, committed_root, depth, expiry, owner_id)  # QABIO
```

Complete grammar: `src/rung/descriptor.h` and
[bitcoinghost.org/labs/descriptor-notation.html](https://bitcoinghost.org/labs/descriptor-notation.html).

### Signature scheme codes

| Code | Name | Key size | Sig size |
|------|------|----------|----------|
| `0x01` | SCHNORR | 32 (x-only) | 64–65 |
| `0x02` | ECDSA | 33 (compressed) | 8–72 |
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

**Rate-limited wallet (1 BTC per 6 blocks, 2-of-3 backup):**
```
ladder(output(0, or(
    and(sig(@daily_key), rate_limit(1, 100000000, 6)),
    multisig(2, @alice, @bob, @carol)
)))
```

**Post-quantum signature:**
```
ladder(output(0, or(sig(@pq_key, falcon512))))
```

**QABIO-enabled UTXO (3-rung wallet convention):**
```
ladder(output(0, or(
    sig(@owner),
    qabi_prime(),
    qabi_spend(@auth_tip, 0, 0, 0, @owner_id)
)))
```

## Appendix D: Test Vectors

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

Decoded:

- `01` — 1 rung
- `01` — 1 block in rung
- `00` — micro-header slot `0x00` = SIG
- `01` — implicit SCHEME field, `0x01` = Schnorr
- `01 01 00 00 00` — coil: UNLOCK(`0x01`), INLINE(`0x01`), Schnorr(`0x01`), address_len=0, no rung_destinations

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

### Vector 3: formatladder roundtrip

```
$ bitcoin-cli -signet formatladder "01010001010101000000"

{
  "descriptor": "ladder(sig(@?))"
}
```

Key aliases are not preserved through the hex intermediate form;
`@?` indicates an unknown key.

### Vector 4: Minimal QABIBlock serialisation

Canonical bytes for a minimal single-participant block:

```
Version:                          0x01
batch_id:                         32 × 0xA1
coordinator_pubkey length:        0xFD 0x81 0x03   (CompactSize 897)
coordinator_pubkey:               897 × 0xB2
prime_expiry_height:              0x39 0x30 0x00 0x00   (12345 LE)
entries length:                   0x01
  entry[0] participant_id:        32 × 0xC3
  entry[0] contribution:          0xA0 0x86 0x01 0x00 0x00 0x00 0x00 0x00   (100000 LE)
  entry[0] destination_index:     0x00
outputs length:                   0x01
  outputs[0] nValue:              0x58 0x82 0x01 0x00 0x00 0x00 0x00 0x00   (99000 LE)
  outputs[0] scriptPubKey:        0x17 OP_0 0x14 (20 × 0xD4)
```

`QABI_ROOT` of this block is deterministic and can be reproduced via
`ComputeQABIRoot(SerializeQABIBlock(block))` from the reference
implementation.

### Vector 5: Regtest v4 transaction structure

A v4 transaction created with `createrungtx` using a SIG block with
Schnorr scheme:

```
Input:   82e47986dc21229732e1545282ec02b296ee611d9d2ac1f8b0a605b406ff80b2:0
Amount:  49.999 BTC
Block:   SIG (SCHEME = 0x01, Schnorr)
Pubkey:  032c4d54635a48e5542f0a06df7c3f752f505d9ab93873dcb8fb9627d7935d9bc7

Output scriptPubKey (33 bytes, in-memory):
  df 7989d97cc7fa19fd4687c56723658a16e24f4741e8c9680d6c50d5f90871ccff
  ^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |   conditions_root (32 bytes)
  0xDF = MLSC prefix

Transaction size: 93 bytes unsigned (single input, single output)
```

`conditions_root` is derived via `ComputeTxMLSCRoot` from a single
`CreationProofRung` leaf containing the structural template (block
type SIG, non-inverted, coil `output_index` = 0) and the value
commitment (SHA-256 of field values and pubkey).

### Vector 6: Live signet QABIO transactions

First real QABIO priming and escape-after-prime transactions on the
ladder-signet chain:

```
Signet node: 85.9.213.194

Priming tx: 8f379e0c8c0a6acaa48d260be6b869efe8e159c1be85aed9b221d77496ac4ea5
Escape tx:  7bd0d5e4ced77cb2b5d1f12a0494273e1f61c9e988ede6f38b3e4ad126e4c66a
```

The priming tx commits a QABIO-enabled UTXO to a specific batch root.
The escape tx demonstrates the participant unilaterally sweeping the
primed UTXO via the SIG escape rung after the coordinator has
disappeared, producing a fresh MLSC UTXO under the participant's sole
control.

Additional live-chain vectors:

```
Explorer:    https://bitcoinghost.org/labs/explorer.html
Engine:      https://bitcoinghost.org/labs/engine/
QABIO guide: https://bitcoinghost.org/labs/docs/QABIO.md
```

### Vector 7: Tagged hash constants

Pre-computed SHA-256 of each tag string (the first two blocks of the
BIP-340 tagged-hash prefix):

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

`TaggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)`,
per BIP-340.

### LadderWitness wire format

```
[n_rungs: CompactSize]           0 = diff witness mode
for each rung:
    [n_blocks: CompactSize]      >= 1
    for each block: <block encoding>
    [n_relay_refs: CompactSize]
    for each relay_ref: [index: CompactSize]
[coil_type: uint8]               UNLOCK (0x01) or UNLOCK_TO (0x02)
[attestation: uint8]             INLINE (0x01)
[scheme: uint8]                  signature scheme code
[address_len: CompactSize]       0 or 32
[address_hash: bytes]            SHA256(raw_address) if present
[n_coil_conditions: CompactSize] must be 0 (reserved)
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

### Diff witness mode

When `n_rungs == 0`, the witness inherits rungs and relays from a
prior input (`input_index < current`), overriding specific fields
via `(rung_index, block_index, field_index, data_type, data)`
tuples. Only witness-side types are allowed (PUBKEY, SIGNATURE,
PREIMAGE, SCRIPT_BODY, SCHEME). Chaining (a diff pointing to another
diff) is prohibited. Coil fields are always fresh.

## Appendix E: Size and Fee Comparisons

### Transaction weights

| Transaction type | vBytes |
|------------------|--------|
| Minimal spend (1-in, 1-out, key-path) | 110 |
| Simple payment (1-in, 2-out, key-path) | 118 |
| Simple payment (1-in, 2-out, script-path SIG+CSV) | 124 |
| Batch 100 outputs (key-path) | 914 |
| Full lifecycle (create + spend, key-path) | 241 |

### Per-output wire cost

| Format | Bytes per output |
|--------|------------------|
| TX_MLSC | 8 (nValue only, shared root) |
| P2TR | 43 (nValue + scriptPubKey) |
| P2WPKH | 39 (nValue + scriptPubKey) |

For a 100-output batch, TX_MLSC saves ~3,500 bytes over P2TR.

### UTXO set cost

| Format | Bytes per UTXO entry |
|--------|----------------------|
| TX_MLSC | ~8 (shared conditions_root) |
| P2TR | ~48 |
| P2WPKH | ~44 |

### Witness size by block type

| Block | Conditions | Witness | Total (micro-header) |
|-------|------------|---------|---------------------|
| SIG (Schnorr) | 2 B | 98 B | 100 B |
| CSV | 2–5 B | 2–5 B | 4–10 B |
| HTLC | 36 B | ~168 B | ~204 B |
| MULTISIG (2-of-3) | 4 B | ~228 B | ~232 B |

### QABIO batch scaling

Measured on v1 QABIBlock format with FALCON-512 coordinator
signature, 1-rung MLSC proof per input, per-input LadderWitness
carrying the full `QABI_SPEND` block:

| Participants | qabi_block | tx bytes | vsize | Block % (of 4M WU) |
|-------------|------------|----------|-------|--------------------|
| 1 | 1,011 | 2,085 | 583 | 0.06 % |
| 10 | 1,659 | 5,946 | 2,034 | 0.20 % |
| 100 | 8,139 | 44,556 | 16,547 | 1.65 % |
| 500 | 37,437 | 216,658 | 81,175 | 8.12 % |
| 1,000 | 74,437 | 432,160 | 162,051 | 16.21 % |
| 2,000 | 148,437 | 863,160 | 323,801 | 32.38 % |
| 3,000 | 222,437 | 1,294,160 | 485,551 | 48.56 % |

Asymptotic per-participant cost: ~432 bytes serialised, ~162 vbytes
after witness discount. Three binding ceilings:

- **Standard-relay policy** (`MAX_STANDARD_TX_WEIGHT = 400,000 WU`)
  binds at ~618 participants; larger batches require direct-to-miner
  submission.
- **QABI block hard cap** (`QABI_BLOCK_MAX_HARD = 262,144 B`) binds
  at ~3,500 participants; above this, a future `QABI_BLOCK_VERSION = 0x02`
  would be required.
- **Block weight** (`MAX_BLOCK_WEIGHT = 4,000,000 WU`) is an absolute
  ceiling at ~6,100 participants. In practice, the qabi_block cap
  binds first.

### Embeddable data comparison

| System | Maximum embeddable data per tx |
|--------|--------------------------------|
| Ladder Script | 144 bytes (flat) |
| Taproot witness | ~4,000,000 bytes |
| OP_RETURN | 80 bytes (standardness) |
| Bare multisig | ~195 bytes |
