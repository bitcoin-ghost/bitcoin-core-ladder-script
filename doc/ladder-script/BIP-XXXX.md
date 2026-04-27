```
BIP: XXXX
Layer: Consensus (soft fork)
Title: Ladder Script — Typed Spending Conditions and Merkelised Ladder Script Conditions (MLSC)
Author: Defenwycke <defenwycke@icloud.com>
Comments-Summary: No comments yet.
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXXX
Status: Draft
Type: Standards Track
Created: 2026-04-27
License: BSD-2-Clause
Requires: 141, 340, 341
```

## Abstract

This BIP defines a new transaction version (`nVersion = 4`, `RUNG_TX`) that replaces
Bitcoin Script with **typed spending conditions** organised into ladder-logic
*rungs*. Output spending conditions are committed in a single 32-byte
*conditions root* shared across every output of a transaction, in a wire
format called **Merkelised Ladder Script Conditions (MLSC)**. Conditions are
revealed at spend time as a `LadderWitness` plus an `MLSCProof`. Evaluation
is fully typed: every byte in a transaction belongs to a declared field, and
unknown types are a parse error.

The change is a single soft fork. Activated nodes enforce the full Ladder
Script validation rules on `nVersion = 4` transactions; non-upgraded nodes
treat them as anyone-can-spend, in the same fashion as SegWit and Taproot.
Existing transactions and existing wallets continue to function unchanged.
Legacy Bitcoin Script output types are wrappable as Ladder Script blocks,
so migration is incremental and wallet-paced.

The specification is intentionally compact: this BIP defines the consensus
contract — the wire format, the evaluator semantics, the activation rule —
and normatively references a separately versioned `libladder` library for
the byte-exact reference implementation, in the same spirit as BIP-340
references `libsecp256k1`.

## Copyright

This document is licensed under the BSD 2-Clause License.

## Motivation

Bitcoin Script is a stack machine from 2009. Every element on the stack is
an opaque byte array; type information lives nowhere in the protocol. A
public key, a hash digest, a timelock value, and a JPEG image are
indistinguishable at the language level. The script authoriser learns what
a byte string means only by attempting to use it in a typed operation
(`OP_CHECKSIG`, `OP_SHA256`, `OP_CHECKLOCKTIMEVERIFY`) — and only at runtime,
on the spending path actually exercised.

This design decision has had three concrete consequences:

1. **Each new capability requires a new opcode.** Every soft fork that adds
   semantic richness — `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`,
   `OP_CHECKSIGADD`, the proposed `OP_CHECKTEMPLATEVERIFY`, the proposed
   `OP_VAULT` — must thread a new opcode into the existing untyped stack
   machine, with all the interaction-with-prior-opcodes analysis that
   entails. The result is a slowly accumulating pile of narrow soft forks
   with no shared model.

2. **There is no protocol-level distinction between data and instruction.**
   `OP_RETURN` and the witness section permit arbitrary data; inscriptions
   and ordinals exploited this surface to embed arbitrary content at the
   witness discount. Defending against these vectors at the script layer is
   topologically difficult because the script machine has no concept of
   "this byte must be a public key" — only "this byte may be pushed onto the
   stack and later interpreted by some opcode if the spender chooses".

3. **Post-quantum signatures cannot be added by introducing new schemes
   alone.** A new signature opcode must be defined for each new scheme, and
   the script writer must commit at output-creation time to which
   signature scheme will sign the spend. Migrating an existing Bitcoin
   wallet to a post-quantum scheme requires moving funds — there is no
   in-place upgrade.

Ladder Script addresses these by recasting spending conditions as a list
of typed function blocks. A spending policy is a **ladder**. Each rung
is a possible spending path containing one or more **typed condition
blocks**. Within a rung, blocks are conjunctive (all must be satisfied);
across rungs they are disjunctive (the first satisfied rung authorises
the spend). Each block has a fixed type (`SIG`, `CSV`, `HTLC`, `VAULT_LOCK`,
`MULTISIG`, `RECURSE_SAME`, …) with declared fields of declared types
(`PUBKEY`, `NUMERIC`, `HASH256`, `PREIMAGE`, `SIGNATURE`, `SCHEME`,
`SPEND_INDEX`, `DATA`, `PUBKEY_COMMIT`, `SCRIPT_BODY`, `HASH160`).

Three properties follow from this design choice that Bitcoin Script
cannot achieve incrementally:

* **Untyped data is a parse error.** There is no contiguous attacker-chosen
  data block in a v4 transaction. The total user-chosen arbitrary data
  surface is structurally bounded at **112 bytes per transaction** (64 B
  from two `PREIMAGE` fields × 32 B + 40 B from one `DATA_RETURN` payload
  + 8 B from `nLockTime` and per-input `nSequence`). The bound is
  consensus-enforced, not policy.

* **Capability extensions are typed blocks, not new opcodes.** Adding a
  new spending primitive means defining a new block type (a name, a fixed
  field schema, an evaluator function); there is no opcode-interaction
  combinatorial space. Sixty-five blocks across eleven families ship in
  the initial activation. (The initial set is large by precedent because
  the underlying mechanism is uniform: each block type is independently
  evaluated.)

* **Post-quantum migration is a 1-byte field change.** Every
  signature-bearing block carries a `SCHEME` field. SCHEME = 0x01
  authorises Schnorr; 0x02 authorises FALCON-512; 0x03 authorises
  FALCON-1024; 0x04 authorises Dilithium3; 0x05 authorises SPHINCS+. New
  schemes are added by extending the SCHEME registry. Wallets can migrate
  in place by re-issuing the same conditions tree with a different SCHEME
  byte; the on-chain output format is unchanged.

A fourth property follows from the wire encoding rather than the type
system. Outputs in a v4 transaction share **one 32-byte conditions root**
across all `vout` entries; per-output cost on the wire is 8 bytes of value
plus an implicit reference to the shared root. This produces measurable
consequences:

| Transaction type            | Witness-discounted vsize  | vs P2WPKH  | vs P2TR   |
|----------------------------:|-------------------------:|----------:|----------:|
| 1-in 1-out (key-path)       | 109 vB                    | −1 vB     | −2 vB     |
| 100-output batch payment    | 911 vB                    | 3.49×     | 4.79×     |
| Per-coin chainstate footprint | 3 B                     | 8.0×      | 12.0×     |

A 100-output payout fits in one quarter of the bytes a P2WPKH
equivalent would take. Per-coin chainstate footprint, which lives in
RAM on every full node and is the dominant scaling concern over multi-year
horizons, drops by roughly an order of magnitude relative to Taproot.
These savings come from the shared conditions root and the typed
1-byte SPK marker (`0x06` in the standard UTXO compressor), not from any
weaker validation.

This BIP defines the format and evaluation rules that produce these
properties. The full block reference and evaluator are in `libladder`,
which this BIP normatively references.

## Specification

### Notation

Throughout this document:

* `||` denotes byte-string concatenation.
* `H(x)` is `SHA256(x)`.
* `TaggedHash(tag, x)` is `H(H(tag) || H(tag) || x)` per BIP-340 §3.1.
* `len(x)` is the length of `x` in bytes.
* `LE(x, n)` is the little-endian encoding of integer `x` in `n` bytes.
* `CompactSize(x)` is the Bitcoin Core variable-length integer encoding.
* `[]byte` denotes a byte vector.

### Transaction format

A `RUNG_TX` is a transaction with `nVersion = 4`. Two serialisation
forms exist: a *stripped* form used to compute the transaction id
(`txid`) and a *full* form used to compute the witness id (`wtxid`)
and broadcast on the wire.

#### Stripped form (txid input)

```
nVersion        : LE(version, 4) = 0x04 0x00 0x00 0x00
vin             : CompactSize n_in || n_in × CTxIn
conditions_root : 32-byte HASH256
n_outputs       : CompactSize
per output:
    nValue          : LE(value, 8)
    if nValue == 0:
        data_len    : CompactSize ∈ [1, 40]
        data        : data_len bytes
nLockTime       : LE(locktime, 4)
```

The empty `vin` rule of BIP-141 (an empty `vin` followed by a non-zero
flag byte signals SegWit) does not apply to the stripped form: a v4
stripped serialisation has no flag byte and never contains witness
data.

#### Full form (wire / wtxid)

```
nVersion        : LE(version, 4) = 0x04 0x00 0x00 0x00
0x00 0x02       : two flag bytes (dummy, then flags = 0x02)
vin             : CompactSize n_in || n_in × CTxIn
conditions_root : 32-byte HASH256
n_outputs       : CompactSize
per output:
    nValue          : LE(value, 8)
    if nValue == 0:
        data_len    : CompactSize ∈ [1, 40]
        data        : data_len bytes
per input:
    witness         : CompactSize n_stack || n_stack × (CompactSize size || size bytes)
qabi_block_len  : CompactSize ∈ [0, 262 144]
qabi_block      : qabi_block_len bytes
agg_sig_len     : CompactSize ∈ {0, 666}
agg_sig         : agg_sig_len bytes
nLockTime       : LE(locktime, 4)
```

The flag byte `0x02` selects the MLSC body layout; flag `0x01` (BIP-141
SegWit) is invalid in combination with `nVersion = 4`. Combined flag
`0x03` is rejected at deserialisation. Flag bytes other than `0x02` are
rejected for v4 transactions.

The `qabi_block` and `agg_sig` fields are the QABIO extension's per-tx
data and coordinator signature; both are empty (`CompactSize = 0`) for
non-QABIO transactions. See *QABIO* under Rationale.

#### Output reconstruction

For each output `i`, the consensus-visible `scriptPubKey` is reconstructed
as:

```
if nValue == 0:        scriptPubKey = 0xDF || conditions_root || data
otherwise:             scriptPubKey = 0xDF || conditions_root
```

This produces the *MLSC marker* `0xDF` followed by the shared root. All
33-byte MLSC scriptPubKeys in a transaction share the same root. The 8-byte
output (value-only) on the wire expands to a standard 33-byte
`scriptPubKey` for purposes of all existing consensus and policy code that
inspects `tx.vout[i].scriptPubKey`. The expansion is local to
deserialisation and does not change the txid or wtxid.

#### Per-coin compressor

When written to the chainstate UTXO database, a v4 output is stored using
script type `0x06`: a single byte indicating "MLSC, root recoverable from
the synthetic root entry at this txid". The full root is stored once per
transaction in a synthetic coin entry at `(txid, 0xFFFFFFFF)` — the
out-of-range vout index `MLSC_ROOT_VOUT`. This produces the per-coin
footprint of 3 bytes (1-byte SPK + 8-byte value, plus minimal metadata),
versus 24 B for compressed P2WPKH and 36 B for compressed P2TR.

### Conditions and the conditions root

A transaction's *conditions* is a list of `n_outputs` `RungConditions`
objects. A `RungConditions` object describes how the corresponding output
is spent:

```
RungConditions := {
    rungs       : [Rung],         -- ordered list, max MAX_RUNGS = 16
    coil        : Coil,           -- post-spend mutation directive
    relays      : [Relay],        -- shared block sequences referenced from rungs
    template_ref: TemplateReference?  -- optional: copy from another input's resolved conditions
}
Rung := {
    blocks      : [Block],        -- max MAX_BLOCKS_PER_RUNG = 8
    relay_refs  : [u16],          -- indices into `relays`
}
Block := {
    type        : u16,            -- block type code (see Block Registry below)
    inverted    : bool,           -- iff type ∈ InvertibleBlockTypes
    fields      : [Field],        -- max MAX_FIELDS_PER_BLOCK = 16
}
Field := {
    type        : u8,             -- one of the 11 typed field codes
    bytes       : []byte          -- length constraints depend on type
}
```

The conditions object for output `i` contributes to the conditions root via
a leaf hash:

```
leaf_i = TaggedHash("LadderLeaf/v1",
                    structural_template_i || value_commitment_i)

structural_template_i = SerialiseRungs(conditions_i.rungs)
                          where each Field's `bytes` are stripped from
                          types in {PUBKEY, PUBKEY_COMMIT, NUMERIC,
                          PREIMAGE, SIGNATURE, SCRIPT_BODY}
                       || SerialiseCoil(conditions_i.coil)
                       || SerialiseRelayStructure(conditions_i.relays)

value_commitment_i = SHA256(
    serialised condition fields of every Block in every Rung, in order
    || every PUBKEY field bytestring, in block-then-field positional order
)
```

The exact serialisation of `structural_template` and `value_commitment` is
defined in `libladder/src/conditions.cpp` and is consensus-critical.

`PUBKEY` field bytes are *folded into* the leaf hash via
`value_commitment` rather than appearing in the structural template. This
is the *no-pubkeys-in-clear* property: there is no writable `PUBKEY`
surface in the conditions wire format. At spend time the witness reveals
the public key; the verifier reconstructs the leaf and checks the Merkle
proof. (The same folding rule applies to `PUBKEY_COMMIT`, `NUMERIC`,
`PREIMAGE`, `SIGNATURE`, and `SCRIPT_BODY` fields: only their *positional
contribution* shapes the structural template; their *byte content*
appears in `value_commitment` only when the type is determined by the
key-folding rules in `libladder`.)

The `conditions_root` is the Merkle root of `[leaf_0, leaf_1, …]`
padded with `MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf/v1",
0x00...0x00)` (32 zero bytes) to the next power of two:

```
internal(L, R) = TaggedHash("LadderInternal/v1",
                            min(L, R) || max(L, R))
```

Interior pairs are *byte-sorted* before hashing. This eliminates the
need for direction bits in proofs at the cost of any per-input
left/right asymmetry. Construction-time leaf placement is canonical
(left-to-right in `output_index` order) and not chosen by the
spender.

### Witness format

A spend of an MLSC output presents two stack elements:

```
witness[0] = LadderWitness    -- the conditions and per-block witness data
witness[1] = MLSCProof        -- merkle path from leaf to conditions_root
```

The `LadderWitness` is the complete `RungConditions` for the spent
output, serialised per `libladder/src/serialize.cpp`. The `MLSCProof`
is a path of sibling hashes plus mode flags supporting the four proof
modes: `MERKLE_PATH` (one input, full path), `FULL_LEAVES` (compact
multi-input proof), `SHARED` (cross-input proof reference for inputs
spending the same source UTXO), and the structural-only modes used
internally for cross-rung mutation targeting.

The witness limits are:

| Limit                              | Value                |
|:-----------------------------------|---------------------:|
| MAX_RUNGS                          | 16                   |
| MAX_BLOCKS_PER_RUNG                | 8                    |
| MAX_FIELDS_PER_BLOCK               | 16                   |
| MAX_LADDER_WITNESS_SIZE            | 100 000 bytes        |
| MAX_PREIMAGE_FIELDS_PER_WITNESS    | 2                    |
| MAX_PREIMAGE_FIELDS_PER_TX         | 2                    |
| MAX_RELAYS                         | 16                   |
| MAX_RELAY_DEPTH                    | 4                    |

These are consensus rules. A v4 transaction violating any of them is
invalid at all flag levels.

### Block registry (initial activation)

Sixty-five block types in eleven families activate together. The
complete block registry, including each block's field schema, evaluator
function, and post-spend coil semantics, is defined in
[`libladder/src/blocks/`](../../src/rung/blocks/) and reproduced
human-readably in
[`BLOCK_LIBRARY.md`](BLOCK_LIBRARY.md).

| Family         | Block types                                                                                                                          |
|:---------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| Signature      | `SIG`, `MULTISIG`, `ADAPTOR_SIG`, `MUSIG_THRESHOLD`, `KEY_REF_SIG`                                                                    |
| Timelock       | `CSV`, `CSV_TIME`, `CLTV`, `CLTV_TIME`                                                                                                |
| Hash           | `TAGGED_HASH`, `HASH_GUARDED`                                                                                                         |
| Covenant       | `CTV`, `VAULT_LOCK`, `AMOUNT_LOCK`                                                                                                    |
| Recursion      | `RECURSE_SAME`, `RECURSE_MODIFIED`, `RECURSE_UNTIL`, `RECURSE_COUNT`, `RECURSE_SPLIT`, `RECURSE_DECAY`                                |
| Anchor         | `ANCHOR`, `ANCHOR_CHANNEL`, `ANCHOR_FEE`, `ANCHOR_POOL`, `ANCHOR_RESERVE`, `ANCHOR_SEAL`, `ANCHOR_ORACLE`, `DATA_RETURN`              |
| PLC            | `HYSTERESIS_FEE`, `HYSTERESIS_VALUE`, `TIMER_CONTINUOUS`, `TIMER_OFF_DELAY`, `LATCH_SET`, `LATCH_RESET`, `COUNTER_DOWN`, `COUNTER_PRESET`, `COUNTER_UP`, `COMPARE`, `SEQUENCER`, `ONE_SHOT`, `RATE_LIMIT`, `COSIGN` |
| Compound       | `TIMELOCKED_SIG`, `HTLC`, `HASH_SIG`, `PTLC`, `CLTV_SIG`, `TIMELOCKED_MULTISIG`                                                       |
| Governance     | `EPOCH_GATE`, `WEIGHT_LIMIT`, `INPUT_COUNT`, `OUTPUT_COUNT`, `RELATIVE_VALUE`, `ACCUMULATOR`, `OUTPUT_CHECK`                          |
| Legacy         | `P2PK_LEGACY`, `P2PKH_LEGACY`, `P2SH_LEGACY`, `P2WPKH_LEGACY`, `P2WSH_LEGACY`, `P2TR_LEGACY`, `P2TR_SCRIPT_LEGACY`                    |
| QABIO / PQ     | `PQ_BATCH`, `QABI_PRIME`, `QABI_SPEND`                                                                                                |

Block types not present in the registry above are reserved. A v4
transaction whose conditions reveal an unknown block type evaluates
that block as `UNSATISFIED` (not `ERROR`); this preserves the
soft-fork-friendly semantics that future BIPs may extend the registry
without invalidating prior deployments. (The exception is *inverted*
unknown blocks, which evaluate as `ERROR` — the inversion of an
unsatisfied unknown is well-defined as `SATISFIED`, but accepting
that would let a future block extension change semantics for already-
mined coins; failing closed is the safe default.)

The set is finite and consensus-enforced. New block types require a
follow-up BIP.

### Evaluator semantics

Spending an MLSC output evaluates as follows:

1. **Deserialise** the witness as `LadderWitness` and the second
   stack element as `MLSCProof`. Reject on any structural error
   (size, count, type, trailing bytes).
2. **Reconstruct** each `leaf_i` from the revealed conditions and
   verify the Merkle path against the `conditions_root` from the
   spent output's scriptPubKey. (For SHARED proof mode, verify
   against the cached root from the source input.)
3. **Apply per-tx checks** on the first input: every output is MLSC
   (`0xDF`) or MLSC + DATA_RETURN; at most one DATA_RETURN per tx;
   total preimage fields across all witnesses ≤
   `MAX_PREIMAGE_FIELDS_PER_TX`; legacy multi-witness checks for
   `LEGACY_*` blocks.
4. **Evaluate** the rungs in order. For each rung, evaluate its blocks
   left-to-right (conjunctive). If any block returns `UNSATISFIED` or
   `ERROR`, that rung fails; try the next rung. If a block returns
   `SATISFIED`, continue; if all blocks satisfy, the rung satisfies
   and the spend authorises.
5. **Apply the coil** if present: post-spend mutation directives that
   constrain output structure (e.g. `unlock_to(address_hash)` requires
   `tx.vout[coil.output_index].scriptPubKey` to hash to the committed
   address).

Each block's evaluator is a function `(Block, RungEvalContext) →
{SATISFIED, UNSATISFIED, ERROR, UNKNOWN_BLOCK_TYPE}`. The
`RungEvalContext` carries: the spending transaction, input index, the
spent output, the consensus block height, the precomputed transaction
data (sighash caches), the MLSC proof (for cross-rung covenant
targeting), and optional per-tx caches (`SharedTreeCache`,
`PQBatchCache`, `QABOSigCache`) keyed by source UTXO or by signature
input.

`ERROR` is fatal: the spend is invalid. `UNSATISFIED` allows the
evaluator to try the next rung. `UNKNOWN_BLOCK_TYPE` becomes
`UNSATISFIED` (or `ERROR` if inverted) per the soft-fork-friendly
forward-compat rule.

### Sighash

Two new sighash types are defined for Ladder Script:

* `SIGHASH_LADDER` (value `0x84`) — used by signature blocks in the
  conditions tree. Commits to: nVersion, nLockTime, the `prevouts`
  hash (BIP-143 style), the `sequences` hash, the `outputs` hash,
  the input index, the spent output amount and scriptPubKey, the
  spending input's `nSequence`, the `conditions_root`, the spent
  rung index, and the spent block index within the rung.

* `SIGHASH_KEYPATH_LADDER` (value `0x85`) — used by the key-path
  spend (a single signature spending the tweaked output pubkey
  directly without revealing any conditions). Commits to: nVersion,
  nLockTime, prevouts, sequences, outputs, input index, spent
  output amount and scriptPubKey, spending input's nSequence, and
  the *internal* x-only pubkey before tweaking.

The exact byte sequences are computed by
`libladder/src/sighash.cpp::SignatureHashLadder` and
`SignatureHashKeyPathLadder`, both as `TaggedHash("LadderSighash/v1", …)`
and `TaggedHash("LadderKeyPathSighash/v1", …)` respectively.

The third sighash type, `SIGHASH_QABO` (value `0x86`), is defined
under *QABIO* in Rationale.

### Key-path tweak

Output key-path spends use a BIP-341-style tweak:

```
output_pk = internal_pk + TaggedHash("LadderTweak/v1",
                                      internal_pk || conditions_root) * G
```

with the standard parity convention. A v4 output may set the
`internal_pubkey` field of its scriptPubKey to enable key-path
spending; if absent, only script-path spending is permitted.
Verification is performed via `secp256k1_xonly_pubkey_tweak_add_check`.

### Activation

Activation uses BIP 9 with the deployment name `ladder-script` and a
single bit assignment to be specified in the deployment table. The
start time, timeout, and minimum_activation_height are configured
per the standard process and not pinned by this document.

Pre-activation: nodes treat `nVersion = 4` transactions as
anyone-can-spend at the script layer, identical to the SegWit and
Taproot soft-fork pattern. A miner mining a v4 transaction
pre-activation produces a chain that activated nodes accept (they
will not enforce the v4 rules until activation). Post-activation:
all v4 transactions are validated under the rules of this BIP.

Standardness rules track activation: pre-activation, v4 is
non-standard for relay; at activation, the standardness rules in
`libladder/src/policy.cpp::IsStandardRungTx` apply.

## Rationale

### Why a single soft fork for sixty-five block types

The block-type evaluator is uniform: every block is a function of
its fields and an evaluation context, returning one of four results.
The wire format and anti-spam rules are designed as a single
coherent system. Activating subsets of blocks would require
maintaining multiple validation codepaths for transactions that mix
activated and non-activated blocks, with combinatorial implications
for testing.

The precedent here is Taproot (BIP-341), which activated a single
larger surface (key-path, script-path, leaf-version semantics,
sighash extensions) as one deployment. The audit and review effort
scales with the *uniformity* of the surface, not its line count.

### Why typed blocks instead of new opcodes

Bitcoin Script's untyped stack creates an interaction surface that
grows with each new opcode. CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY,
CHECKSIGADD, OP_CSFS, CTV, OP_VAULT, and APO each had to be
analysed against every prior opcode for unintended interactions. The
block model collapses that surface: each block has a fixed schema
and a single evaluator; there is no opcode-to-opcode interaction
because there are no opcodes.

### Why MLSC instead of inline conditions

An earlier design had an inline-conditions wire format (`0xC1`
prefix). The Merkle-committed form was chosen for two reasons:

1. *Per-coin chainstate footprint* — the dominant scaling concern
   over multi-year horizons — is bounded by the marker byte plus the
   value, with the conditions tree paid only at spend time.
2. *Privacy* — only the spending rung is revealed. Unused rungs stay
   permanently hidden behind their leaf hash. The total information
   leakage is the path length (revealing the rung count rounded up
   to a power of two), which is shorter than revealing the
   conditions themselves.

The cost is one Merkle proof per spend. For typical multi-rung
conditions trees (≤ 4 rungs) this is 2 sibling hashes (64 bytes).

### Why `MAX_RUNGS = 16`, `MAX_BLOCKS_PER_RUNG = 8`

The limits were chosen to be:

* **Generous enough** that real-world spending policies fit. The
  most complex policies the authors are aware of — multi-party
  vaults with timelock escalation, Lightning revocation paths
  combining HTLC + PTLC + CSV, recursive split trees with bounded
  depth — fit in 4 rungs of ≤ 6 blocks each.

* **Small enough** that the evaluator's worst-case work is bounded.
  16 × 8 = 128 evaluator invocations per spend. Each invocation is
  bounded in CPU; the worst single block (`MUSIG_THRESHOLD` with N
  signers) is bounded by N (capped at MAX_FIELDS_PER_BLOCK = 16).
  Total worst case is well under a millisecond on commodity
  hardware.

* **Aligned with witness-size cap**. A maximally-deep conditions
  tree fits in `MAX_LADDER_WITNESS_SIZE = 100 000` bytes. This
  matches `MAX_STANDARD_TX_WEIGHT / 4` and avoids any need for a
  separate witness-count limit.

### Why `MAX_PREIMAGE_FIELDS_PER_TX = 2`

Two PREIMAGE fields per transaction is the minimum required to
support the canonical HTLC use case (one preimage on the claim path,
one on the refund path's signature). Allowing more would expand the
arbitrary-data surface beyond the 64-byte ceiling claimed in the
*Anti-spam* section. Two is the smallest number that supports the
real use cases without expanding the data-embedding surface.

### Why folded pubkeys

`PUBKEY` field bytes are folded into the leaf hash via
`value_commitment` rather than appearing in the conditions wire
format. This eliminates the largest data-embedding surface a typed
condition system could otherwise expose. Without folding, the
33-byte (or 32-byte x-only) `PUBKEY` field would be a
spender-controlled arbitrary blob; an attacker could publish
arbitrary data by funding a SIG-locked output with a chosen
"public key" (which would be verified as a valid curve point at
spend time, but the *data* is freely chosen at output-creation
time).

Folding closes this. The PUBKEY is revealed at spend time in the
witness; the conditions tree itself contains no PUBKEY bytes.

### QABIO

The QABIO extension defines `QABI_PRIME` and `QABI_SPEND` block
types plus the per-transaction `qabi_block` and `aggregated_sig`
wire fields, supporting N-party batch-spend transactions
authorised by a single FALCON-512 coordinator signature over a new
sighash type `SIGHASH_QABO` (`0x86`).

The detailed QABIO consensus rules — the priming covenant, the nine
per-input checks, the auth-chain hash mechanism, the
`Replace-By-Depth` mempool policy that lets a participant re-aim
their commitment without paying fees for what is structurally a
free re-targeting — are specified in
[`QABIO.md`](QABIO.md) and implemented in
`libladder/src/qabi.cpp` and `libladder/src/blocks/qabi.cpp`.

The reason QABIO is included in the initial activation rather than
deferred to a follow-up BIP is that the wire format must reserve
the `qabi_block` and `agg_sig` slots in the v4 transaction body
from the start. Reserving the slots without specifying their
semantics would prevent meaningful policy enforcement, and there
is no in-format way to add them later without bumping nVersion
again.

### PQ_BATCH

The `PQ_BATCH` block type permits N inputs in a single transaction
to share one FALCON-512 verification: an *anchor input* reveals the
public key and signature; subsequent inputs that commit to
`SHA256(falcon_pubkey)` short-circuit via a per-tx cache. This
amortises the 4 ms FALCON verify cost across the batch, dropping
per-input cost to ≈ 55 vB asymptotically — about 12× cheaper than
per-input PQ signatures would be otherwise.

`PQ_BATCH` is *not* a coordinator-driven scheme and does not
require off-chain protocol state, distinguishing it from QABIO.
The two are complementary: PQ_BATCH amortises PQ signatures within
a single transaction; QABIO atomically batches multiple parties'
funds under one PQ signature.

### Why FALCON-512 for QABIO

FALCON-512 has the smallest signature of any NIST-standardised
post-quantum scheme — 666 bytes, vs 1 280 (FALCON-1024), 3 293
(Dilithium3), or ≥ 8 000 (SPHINCS+). Since the coordinator
signature is a fixed per-transaction overhead amortised across
every primed input, smaller is strictly better. FALCON-1024 may
become the appropriate choice if FALCON-512 security degrades; the
QABIO block carries a `version` byte, enabling a future
soft-fork-compatible upgrade.

### Why `liboqs` is a hard requirement

Post-quantum verification is consensus-critical. A node compiled
without `liboqs` would silently disagree with `liboqs`-enabled
nodes about the validity of any FALCON, Dilithium3, or SPHINCS+
signature, producing a hard chain split. The reference
implementation enforces `find_package(liboqs REQUIRED)` at build
time and refuses to start without it.

### Why Cap'n Proto IPC is not part of this BIP

The reference implementation uses Bitcoin Core's optional Cap'n
Proto IPC layer for the multiprocess (`bitcoin-node`) mode. This
BIP does not require it. Implementations may build with
`-DENABLE_IPC=OFF` and still be conformant.

## Backwards Compatibility

`nVersion = 4` transactions are anyone-can-spend on non-upgraded
nodes, the same SegWit / Taproot soft-fork pattern. A miner who
includes a v4 transaction in a block before activation produces a
chain that activated and non-activated nodes both accept (the
non-activated node sees the v4 inputs as anyone-can-spend; the
activated node enforces the full Ladder Script rules). After
activation, mining a block containing an invalid v4 transaction
produces a chain that non-upgraded miners would mine on but
upgraded miners would reject — the standard soft-fork worry. This
risk is bounded by the activation procedure (BIP 9 supermajority
signaling) and is no different in shape from any prior consensus
soft fork.

Existing transactions (`nVersion ∈ {1, 2}`) continue to function
unchanged. Existing wallets that do not produce v4 transactions
are unaffected.

The `Legacy` block family wraps every existing Bitcoin output type
(P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR key-path, P2TR script-path)
as Ladder Script blocks. Wallets that wish to migrate from a legacy
output type to v4 may do so output-by-output, with no functional
loss. The wrapper blocks have identical spending semantics to the
underlying script types (witness format, sighash, signature
algorithm).

This BIP does not propose deprecating legacy transaction versions.

## Test Vectors

The reference implementation includes:

* **Unit tests:** 619 boost test cases under
  `src/test/rung_tests.cpp` covering wire format, evaluator
  semantics, anti-spam, sighash, MLSC proof verification, key-path
  tweaks, and per-block-type behaviour. Run via
  `build/bin/test_bitcoin --run_test=rung_tests`.

* **Functional tests:** 52 Python tests under
  `test/functional/feature_rung_*.py` covering transaction
  lifecycle on a regtest node, including funding, signing,
  broadcasting, mining, reorg, and cross-input replay scenarios.

* **TLA+ specifications:** 27 specifications under `spec/`
  modelling: evaluation semantics, anti-spam invariants, wire
  format, Merkle proof security, sighash binding, covenant
  termination, cross-input rules, QABIO, PQ_BATCH.

* **Live-signet vectors:** the Ladder Script signet at
  `ladder-script.org` carries every block type's fund + spend
  cycle. Per-block-type transaction ids are recorded in
  [`MEASUREMENTS.md`](MEASUREMENTS.md) and updated on chain
  resets.

* **End-to-end presets:** 56 example conditions trees in
  `tools/ladder-engine/presets.json`, each fundable and spendable
  through the Ladder Engine's BUILD / SIMULATE / CONVERT tabs.

A focused vector pack for BIP review (one canonical transaction
per consensus rule, including malformed cases that must reject) is
maintained at `doc/ladder-script/test-vectors/` and is the
authoritative source for cross-implementation testing.

## Reference Implementation

The reference implementation is published at
[github.com/defenwycke/bitcoin-core-ladder-script](https://github.com/defenwycke/bitcoin-core-ladder-script),
branch `ladder-script`. It is a Bitcoin Core v30.0 fork carrying:

* a small integration shim under `src/` (≈ 805 lines patched
  across 29 files),
* the `libladder` library under `src/rung/` (≈ 19 345 lines
  across 39 files), with a single header (`src/rung_shims.h`) as
  the boundary against Core types.

This BIP normatively references `libladder` — the byte-exact
behaviour of `libladder/src/conditions.cpp`,
`libladder/src/evaluator.cpp`, `libladder/src/sighash.cpp`,
`libladder/src/serialize.cpp`, `libladder/src/qabi.cpp`,
`libladder/src/pq_verify.cpp`, and `libladder/src/blocks/*.cpp` is
the consensus contract. Other implementations are encouraged but
must produce byte-identical results on all test vectors.

The library is structured to be vendorable: the boundary header
`rung_shims.h` is the only place Bitcoin Core types meet library
types. A new implementation can re-stub the boundary against its
own types without modifying any library file.

A live signet at `ladder-script.org` runs every block type
end-to-end with all sixty-five evaluators active. Pre-built
binaries for Linux x86_64, macOS arm64, and Windows x86_64 are
published per release at
[releases](https://github.com/defenwycke/bitcoin-core-ladder-script/releases),
each with PGP-signed `SHA256SUMS` (key fingerprint
`777FE81F8CC077FD3D08055E852C2B3190F5B928`).

## Security Considerations

### Fail-closed design

Unknown block types evaluate as `UNSATISFIED` (forward-compat for
future BIPs), but inverted unknown blocks evaluate as `ERROR`. New
block types MUST NOT change semantics for already-mined coins.

The deserialiser is fail-closed at every level: unknown field
types, oversize fields, undersize fields, trailing bytes, exceeded
counts, and proof-format mismatches all reject. The CompactSize
caps (256 KB hard / 64 KB soft for `qabi_block`, 666 B for
`agg_sig`, 100 000 B for `LadderWitness`, 40 B for `DATA_RETURN`
data) are all hard consensus, not policy.

### Anti-spam surface

The total user-chosen arbitrary data per v4 transaction is
**112 bytes**, structurally bounded:

* 64 B from two `PREIMAGE` fields (each 32 B; `MAX_PREIMAGE_FIELDS_PER_TX = 2`).
* 40 B from the optional `DATA_RETURN` payload.
* 8 B from `nLockTime` + per-input `nSequence`.

`PUBKEY` and `SIGNATURE` fields are *cryptographically constrained*
(the bytes must be valid curve points and valid signatures
respectively at evaluation time), eliminating the
"plant-arbitrary-data-as-a-fake-pubkey" vector.

Per-output cost in chainstate is 3 bytes; spamming the UTXO set
with v4 outputs costs at least 8× more per coin than P2WPKH
spamming would.

### Soft-fork forward compatibility

Adding new block types in future BIPs follows the same pattern as
Taproot's leaf-version registry: a new block type code is reserved,
its evaluator function is added, and pre-existing nodes treat the
unknown block type as `UNSATISFIED` until they upgrade. Existing
spending policies cannot be invalidated by future block-type
additions.

### Compile-time consensus flags

Both `ENABLE_QABIO` and `HAVE_LIBOQS` are consensus-relevant
compile-time flags. A node built with either disabled would
silently disagree with the activated network on any QABIO or PQ
transaction, producing a hard chain split. The reference
implementation makes both required at build time. Implementations
of this BIP MUST NOT permit either to be optional in deployable
binaries.

(The recommendation is to delete the `#else` branches in the
reference implementation entirely so a no-liboqs / no-QABIO build
fails to compile rather than silently produces a network-divergent
binary.)

### Key-path tweak

The key-path tweak follows BIP-341 closely with a domain-separated
tag. The internal pubkey is committed in the spending transaction's
sighash (`SIGHASH_KEYPATH_LADDER`), preventing tweak substitution
attacks. The tagged hash domain string `LadderTweak/v1` is
explicitly versioned to allow a future soft fork to revise the
tweak rule without ambiguity.

### Sighash binding

`SIGHASH_LADDER` commits to the conditions root, the spent rung
index, and the spent block index within the rung. Combined with the
prevouts/sequences/outputs hashes, this binds the signature to:

* the specific input being spent,
* the specific rung being authorised,
* the specific block within that rung,
* the entire transaction's structure.

A signature cannot be moved across inputs, across rungs, or across
transactions. Two SIG blocks in different rungs of the same output
require two distinct signatures.

### Merkle proof commutativity

Interior pairs are byte-sorted before hashing
(`min(L, R) || max(L, R)`). This eliminates the need for direction
bits in proofs at the cost of leaf-placement canonicality:
construction-time leaf order is fixed (left-to-right in
`output_index`), and witness-time proofs cannot reorder leaves to
fabricate alternative paths to the same root. Implementers MUST
preserve the canonical leaf ordering at construction time.

### QABIO replacement policy

QABIO's `Replace-By-Depth` (RBD) mempool policy bypasses the
fee-rate-based RBF rule for QABI_PRIME transaction replacement.
This is intentional: the depth-monotonicity rule is a stronger
cryptographic ordering than fee competition (only the seed holder
can produce deeper preimages). However, RBD as currently
implemented imposes no minimum depth gap and no per-prevout rate
limit, allowing the legitimate UTXO owner to free-flood the
mempool with their own replacements. Implementations SHOULD
enforce a minimum depth gap (recommend ≥ 5) and a per-prevout
rate limit (recommend ≥ 30 s wall-clock) to prevent self-flooding.

### Audit status

The reference implementation has not yet undergone an external
audit. A first-pass adversarial review was conducted by the author
in April 2026 and the surfaced issues are tracked in private
remediation notes; activation should follow an external audit by
an independent party and the standard BIP 9 deployment process.

### Out of scope

* **Wallet UX.** This BIP defines the consensus contract. Wallet-
  level interfaces (descriptor notation, RPC schemata, signing
  workflows) are reference implementation choices, not part of
  the consensus surface.

* **Mempool fairness.** RBF rules for non-QABIO v4 transactions
  follow BIP-125 unchanged. The new RBD path is QABIO-specific
  and only triggers when both incoming and conflicting transactions
  are QABI_PRIME priming transactions.

* **Block-template construction.** Miners may use any algorithm to
  select v4 transactions for inclusion. The consensus rules
  validate inclusion; they do not prescribe selection.

## Acknowledgements

This BIP builds on the work of every Bitcoin Core developer who has
shaped the script language and its surrounding consensus code over
the past sixteen years. The shape of the soft-fork process is owed
to BIP 9 / BIP 8 and the activation experience of SegWit and
Taproot.

The MLSC structure draws from BIP-341's TapLeaves; the tagged-hash
domain separation pattern is borrowed from BIP-340. The
`Replace-By-Depth` mempool policy is novel to QABIO but the
fee-bypass-with-cryptographic-progress argument was prefigured by
the design discussions around BIP-125 and BIP-326.

The post-quantum signature schemes are implemented via
`liboqs` (Open Quantum Safe), maintained by the OQS project at
[openquantumsafe.org](https://openquantumsafe.org/). The FALCON
specification is the work of Pierre-Alain Fouque, Jeffrey Hoffstein,
Paul Kirchner, Vadim Lyubashevsky, Thomas Pornin, Thomas Prest,
Thomas Ricosset, Gregor Seiler, William Whyte, and Zhenfei Zhang.
Dilithium is the work of Léo Ducas, Eike Kiltz, Tancrède Lepoint,
Vadim Lyubashevsky, Peter Schwabe, Gregor Seiler, and Damien Stehlé.
SPHINCS+ is the work of Daniel J. Bernstein and the SPHINCS+ team.

This document was first published as a wireframe on 2026-03-16; the
full draft (this version) was published on 2026-04-27.

## References

* [BIP 9](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) — Version bits with timeout and delay
* [BIP 125](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki) — Replace-By-Fee
* [BIP 141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki) — Segregated Witness (Consensus layer)
* [BIP 143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) — Transaction Signature Verification for v0 Witness Program
* [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) — Schnorr Signatures for secp256k1
* [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) — Taproot: SegWit version 1 spending rules
* `libladder` reference implementation: `src/rung/` in this repository
* MLSC wire format: `doc/ladder-script/TX_MLSC_SPEC.md`
* Block library: `doc/ladder-script/BLOCK_LIBRARY.md`
* QABIO specification: `doc/ladder-script/QABIO.md`
* PQ_BATCH specification: `doc/ladder-script/PQ_BATCH_SPEC.md`
* Sizing analysis: `doc/ladder-script/SIZING.md`
