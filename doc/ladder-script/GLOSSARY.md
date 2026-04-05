# Ladder Script Glossary

Alphabetical glossary of Ladder Script terminology. Every definition is derived from the
source code in `src/rung/`.

---

### ACCUMULATOR
Block type 0x0806 (Governance family). Merkle accumulator for set membership proofs.
Conditions carry a HASH256 Merkle root; witness provides proof nodes. Invertible (inverted
ACCUMULATOR = blocklist, "NOT in set"). Capped at 10 HASH256 fields (root + 8 proof + leaf).

### ADAPTOR_SIG
Block type 0x0003 (Signature family). Adaptor signature verification. Key-consuming with
2 pubkeys. Has no implicit conditions layout (no condition fields at all in conditions
context). Used for atomic swap and PTLC protocols.

### AMOUNT_LOCK
Block type 0x0303 (Covenant family). Constrains the output amount to a range defined by
two NUMERIC fields (min, max). Invertible. Conditions-only implicit layout.

### ANCHOR
Block type 0x0501 (Anchor family). Generic anchor marker with a single NUMERIC(anchor_id).
Invertible. Conditions-only implicit layout.

### ANCHOR_FEE
Block type 0x0707 (Compound family). Anti-pinning fee anchor combining 2-of-2 signatures
with fee rate band enforcement and weight limit. Key-consuming with 2 pubkeys. Conditions:
SCHEME(1), NUMERIC(min_fee_rate), NUMERIC(max_fee_rate), NUMERIC(max_weight),
NUMERIC(commitment). Not invertible.

### ANCHOR_CHANNEL
Block type 0x0502 (Anchor family). Lightning channel anchor. Key-consuming with 2 pubkeys
(local and remote). Conditions: NUMERIC(commitment_number). Not invertible (key-consuming).

### ANCHOR_ORACLE
Block type 0x0506 (Anchor family). Oracle anchor. Key-consuming with 1 pubkey (oracle key).
Conditions: NUMERIC(outcome_count). Not invertible (key-consuming).

### ANCHOR_POOL
Block type 0x0503 (Anchor family). Pool anchor. Conditions: HASH256(vtxo_tree_root),
NUMERIC(participant_count). Invertible. Not key-consuming.

### ANCHOR_RESERVE
Block type 0x0504 (Anchor family). Reserve anchor for guardian sets. Conditions:
NUMERIC(threshold_n), NUMERIC(threshold_m), HASH256(guardian_hash). Invertible.

### ANCHOR_SEAL
Block type 0x0505 (Anchor family). Seal anchor. Conditions: HASH256(32), HASH256(32).
Invertible. Not key-consuming.

### ANYPREVOUT
Sighash flag `LADDER_SIGHASH_ANYPREVOUT = 0x40`. When set, the sighash computation skips
the prevout commitment (outpoint hash) while still committing to amounts, sequences, and
conditions. Enables LN-Symmetry/eltoo-style protocols. Defined in `sighash.h`.

### ANYPREVOUTANYSCRIPT
Sighash flag `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT = 0xC0`. When set, the sighash skips
both prevout and conditions commitments. Enables rebindable signatures across different
scripts. Defined in `sighash.h`.

### BatchVerifier
Struct in `evaluator.h`. Collects (sighash, pubkey, signature) tuples during evaluation.
After all inputs pass, `Verify()` checks them all in a single batch. On batch failure,
`FindFailure()` identifies the first invalid entry by individual verification.

### BlockDescriptor
Compile-time descriptor struct in `types.h`. Contains block type metadata: type code, name,
known/invertible/key-consuming flags, pubkey count, pointers to conditions and witness
implicit layouts, and a `conditions_only` flag. The `LookupBlockDescriptor()` function
provides a runtime lookup table of all 62 block types.

### CLTV
Block type 0x0103 (Timelock family). Absolute timelock checking nLockTime against a
block-height threshold. Invertible. Conditions: NUMERIC(height).

### CLTV_SIG
Block type 0x0705 (Compound family). SIG + CLTV combined in one block. Key-consuming
with 1 pubkey. Conditions: SCHEME(1), NUMERIC(cltv). Not invertible.

### CLTV_TIME
Block type 0x0104 (Timelock family). Absolute timelock checking nLockTime against a
median-time-past threshold. Invertible. Conditions: NUMERIC(time).

### COIL_MAP
See RungCoil. The coil metadata attached to each output/witness, defining unlock semantics
(coil_type), attestation mode, signature scheme, address hash, and per-rung destination
overrides (rung_destinations).

### COMPARE
Block type 0x0641 (PLC family). Comparator for amount vs thresholds. Conditions:
NUMERIC(operator), NUMERIC(value_b), NUMERIC(value_c). Invertible.

### Conditions
See RungConditions. The locking side of a v4 output. In a RUNG_TX, conditions are committed
via a shared conditions_root per transaction (MLSC `0xDF` prefix); each output is 8 bytes
(value only). Contains rungs (with blocks), a coil, and optionally relays. Only condition
data types are allowed: HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX, DATA. Never
PUBKEY, SIGNATURE, PREIMAGE, or SCRIPT_BODY.

### ComputeTxMLSCLeaf
Function in `conditions.cpp`. Computes a TX_MLSC Merkle leaf from a `CreationProofRung`:
`TaggedHash("LadderLeaf", structural_template || value_commitment)`. The structural
template is the block types and inversion flags. The value commitment binds the output
value and pubkeys to the leaf.

### ComputeValueCommitment
Function in `conditions.cpp`. Computes the value commitment component of a TX_MLSC leaf.
Hashes the rung's block fields (conditions-only) concatenated with the pubkeys from
key-consuming blocks (merkle_pub_key). Returns a 32-byte hash.

### Creation Proof
A witness section validated at block acceptance in a RUNG_TX. The creation proof
binds the shared conditions_root to the transaction's outputs, proving that the structural
template and value commitments are correctly constructed.

### COSIGN
Block type 0x0681 (PLC family). Cross-input co-spend constraint. Requires another input
in the same transaction to have matching conditions identified by a HASH256. Not
key-consuming (pubkey_count=0). Not invertible. Uses the `spent_outputs` field of
RungEvalContext.

### COUNTER_DOWN
Block type 0x0631 (PLC family). Down counter decremented on event. Key-consuming with
1 pubkey (event signer). Conditions: NUMERIC(count). Not invertible (key-consuming).

### COUNTER_PRESET
Block type 0x0632 (PLC family). Preset counter (approval accumulator). Conditions:
NUMERIC(current), NUMERIC(preset). Invertible. Not key-consuming.

### COUNTER_UP
Block type 0x0633 (PLC family). Up counter incremented on event. Key-consuming with
1 pubkey (event signer). Conditions: NUMERIC(current), NUMERIC(target). Not invertible (key-consuming).

### CSV
Block type 0x0101 (Timelock family). Relative timelock checking BIP 68 sequence against
a block-height threshold. Invertible. Conditions: NUMERIC(blocks).

### CSV_TIME
Block type 0x0102 (Timelock family). Relative timelock checking BIP 68 sequence against
a time-based threshold. Invertible. Conditions: NUMERIC(seconds).

### CTV
Block type 0x0301 (Covenant family). OP_CHECKTEMPLATEVERIFY covenant. Conditions:
HASH256(template_hash). Invertible. The template hash is computed by `ComputeCTVHash()`
in `evaluator.h`, following BIP-119.

### DATA
Data type 0x0B. Opaque data, 1 to 40 bytes. Restricted to DATA_RETURN blocks only.
Rejected in all other block types at deserialization.

### DATA_RETURN
Block type 0x0507 (Anchor family). Unspendable data commitment, replacing OP_RETURN.
Maximum 40 bytes of DATA. Exactly one DATA_RETURN per transaction. Conditions:
DATA(var). Invertible.

### Descriptor
A human-readable text format for Ladder Script conditions. Grammar:
`ladder(or(rung1, rung2, ...))` where each rung is a block or `and(block, block, ...)`.
Blocks use lowercase names: `sig(@alias)`, `csv(N)`, `multisig(M, @pk1, ...)`, etc.
Parsed by `ParseDescriptor()`, formatted by `FormatDescriptor()` in `descriptor.h/cpp`.

### EPOCH_GATE
Block type 0x0801 (Governance family). Periodic spending window: spendable only when
`block_height mod period == offset`. Not invertible. Conditions: NUMERIC(period),
NUMERIC(offset).

### EvalResult
Enum in `evaluator.h`. Four values: SATISFIED (conditions met), UNSATISFIED (valid but
fails), ERROR (malformed block, consensus failure), UNKNOWN_BLOCK_TYPE (forward-compat,
treated as unsatisfied). `ApplyInversion()` flips SATISFIED/UNSATISFIED; ERROR is unchanged;
UNKNOWN_BLOCK_TYPE inverted becomes ERROR (prevents attackers exploiting unknown types).

### HASH_GUARDED
Block type 0x0204 (Hash family). Raw SHA256 preimage verification. Conditions:
HASH256(hash). Witness: PREIMAGE(preimage). Not invertible, not key-consuming.

### HASH_SIG
Block type 0x0703 (Compound family). Hash preimage + signature combined. Key-consuming
with 1 pubkey. Conditions: HASH256(hash), SCHEME(1). Witness: PUBKEY, SIGNATURE, PREIMAGE.

### HASH160
Data type 0x04. RIPEMD160(SHA256()) hash, exactly 20 bytes.

### HASH256
Data type 0x03. SHA-256 hash, exactly 32 bytes.

### HTLC
Block type 0x0702 (Compound family). Hash + timelock + sig: standard Lightning HTLC.
Key-consuming with 2 pubkeys. Conditions: HASH256(payment_hash), NUMERIC(csv_timeout).
Witness: PUBKEY, SIGNATURE, PUBKEY, PREIMAGE, NUMERIC.

### HYSTERESIS_FEE
Block type 0x0601 (PLC family). Fee hysteresis band. Conditions: NUMERIC(high_sat_vb),
NUMERIC(low_sat_vb). Invertible.

### HYSTERESIS_VALUE
Block type 0x0602 (PLC family). Value hysteresis band. Conditions: NUMERIC(high_sats),
NUMERIC(low_sats). Invertible.

### Implicit Layout
A per-block-type, per-context fixed field table defined in `types.h`. When a block uses
a micro-header and its fields match the implicit layout, the field count and type bytes
are omitted from the wire format. The deserializer uses the micro-header + layout presence
as the signal for implicit encoding. Defined by `ImplicitFieldLayout` struct and queried
via `GetImplicitLayout()`.

### Inline Conditions
The 0xC1 prefix format for embedding conditions directly in scriptPubKey. **Removed.**
`IsRungConditionsScript()` always returns false. All outputs must use MLSC (`0xDF`).

### INPUT_COUNT
Block type 0x0803 (Governance family). Input count bounds on the spending transaction.
Conditions: NUMERIC(min_inputs), NUMERIC(max_inputs). Invertible.

### Inversion
The ability to flip a block's evaluation result. When a block's `inverted` flag is true,
SATISFIED becomes UNSATISFIED and vice versa. Only blocks on the `IsInvertibleBlockType()`
allowlist may be inverted. Key-consuming blocks are never invertible. Encoded on the wire
as header byte 0x81 (escape + inverted). See `ApplyInversion()` in `evaluator.h`.

### Key-path Spend
A 1-element witness spend where the `conditions_root` is treated as an x-only public key.
A Schnorr signature against the tweaked key spends the output with no conditions revealed.
This is the cheapest transaction type in Bitcoin at 119 vB. Only works if the output was
tweaked at creation time (see LadderTweak). Verified by `SignatureHashLadderKeyPath` in
`sighash.cpp`.

### KEY_REF_SIG
Block type 0x0005 (Signature family). Signature verification using a pubkey
resolved from a relay block. Key-consuming. Conditions: NUMERIC(relay_index),
NUMERIC(block_index). The actual pubkey is looked up from the referenced relay's
PUBKEY field (bound to the relay's Merkle leaf via merkle_pub_key) at evaluation time.

### Ladder
The complete set of spending paths for one output. Represented by `LadderWitness` in
`types.h`. Contains rungs (OR paths), a coil (output metadata), relays (shared conditions),
and optionally a witness reference (diff witness). `EvalLadder()` evaluates relays first,
then tries each rung in order; the first satisfied rung wins.

### LadderTweak
The mechanism that enables key-path spending on outputs that also have script-path
conditions. `conditions_root = internal_pubkey + H("LadderTweak", internal_pubkey || merkle_root) × G`.
Same approach as Taproot's output tweaking but with a distinct tag. `createtxmlsc`
auto-detects single-SIG ladders and tweaks automatically. Functions:
`ComputeLadderTweakHash()`, `CheckLadderTweak()`, `CreateLadderTweak()` in `pubkey.cpp`.
`SignSchnorrLadder()` in `key.cpp` signs with the tweaked keypair.

### LadderSignatureChecker
Class in `evaluator.h`. Wraps an existing `BaseSignatureChecker` and adds rung conditions
context. When `CheckSchnorrSignature()` is called with `SigVersion::LADDER`, it computes
`SignatureHashLadder` instead of `SignatureHashSchnorr`. Supports batch verification via
an optional `m_batch` pointer to `BatchVerifier`.

### LATCH_RESET
Block type 0x0622 (PLC family). Latch reset (state deactivation). Key-consuming with
1 pubkey (resetter key). Conditions: NUMERIC(state), NUMERIC(delay). Not invertible (key-consuming).

### LATCH_SET
Block type 0x0621 (PLC family). Latch set (state activation). Key-consuming with 1
pubkey (setter key). Conditions: NUMERIC(state). Not invertible (key-consuming).

### MergeConditionsAndWitness
Function in `evaluator.cpp`. Combines the conditions (from the MLSC proof — block types,
condition fields, coil) with the witness (signatures, pubkeys, preimages) into a single
`LadderWitness` structure that can be evaluated by `EvalLadder()`. Each block's condition
fields and witness fields are interleaved according to the implicit field layout.

### Merkle
See MLSC. Ladder Script uses binary Merkle trees with sorted interior hashing:
`SHA256(0x01 || min(left, right) || max(left, right))`. Leaves are padded to the next
power of 2 using `MLSC_EMPTY_LEAF = SHA256("LADDER_EMPTY_LEAF")`. Functions:
`BuildMerkleTree()`, `ComputeRungLeaf()`, `ComputeCoilLeaf()`, `ComputeRelayLeaf()`,
`ComputeConditionsRoot()`. All in `conditions.h/cpp`.

### merkle_pub_key
The mechanism by which public keys are folded into MLSC Merkle leaf hashes rather than
stored as condition fields. `PubkeyCountForBlock()` in `types.h` determines how many
pubkeys each key-consuming block contributes. `ComputeRungLeaf()` appends pubkeys to the
serialized rung data before hashing. This prevents arbitrary data embedding through the
PUBKEY_COMMIT writable surface.

### Micro-header
A 1-byte encoding for common block types, replacing the 2-byte type code + inversion flag.
Values 0x00 through 0x7F index into `MICRO_HEADER_TABLE[]` (128 slots, 63 active, 2
deprecated slots 0x07/0x08 set to 0xFFFF). Escape bytes: 0x80 = full header (not inverted),
0x81 = full header (inverted). Defined in `types.h`.

### MLSC
Merkelised Ladder Script Conditions. The per-output format prior to TX_MLSC. Originally
`0xDF + 32-byte conditions_root` (33 bytes, shared per transaction). Superseded by TX_MLSC which
uses a shared conditions_root per transaction with 0xDF prefix and 8 bytes per output.
See TX_MLSC.

### output_index
A field on each rung's coil in a RUNG_TX declaring which transaction output
that rung governs. Enables the shared-tree model where one Merkle tree covers multiple
outputs.

### MLSCProof
Struct in `conditions.h`. Carried in witness `stack[1]` when spending an MLSC output.
Contains: total_rungs, total_relays, rung_index, revealed_rung, revealed_relays,
proof_hashes (leaf hashes for unrevealed leaves), and optional revealed_mutation_targets
for cross-rung mutation access.

### MLSCVerifiedLeaves
Struct in `conditions.h`. Output of `VerifyMLSCProof()`. Contains the full leaf array,
verified root, rung index, and counts. Used by covenant evaluators to mutate a leaf,
rebuild the Merkle tree, and compare against the output root.

### MULTISIG
Block type 0x0002 (Signature family). M-of-N threshold signature. Key-consuming with
variable pubkey count (counted from PUBKEY fields). Conditions: NUMERIC(threshold_M).
Not invertible.

### MUSIG_THRESHOLD
Block type 0x0004 (Signature family). MuSig2/FROST aggregate threshold signature.
Key-consuming with 1 pubkey. Conditions: NUMERIC(M), NUMERIC(N). Not invertible.

### NUMERIC
Data type 0x08. Numeric value (threshold, locktime, etc.), 1 to 8 bytes little-endian.
Encoded as CompactSize (varint) in the wire format when using implicit layouts. Always
stored internally as 4-byte LE.

### ONE_SHOT
Block type 0x0661 (PLC family). One-shot activation window. Conditions: NUMERIC(state),
HASH256(commitment). Invertible. Not key-consuming.

### OUTPUT_CHECK
Block type 0x0807 (Governance family). Per-output value and script constraint. Conditions:
NUMERIC(output_index), NUMERIC(min_sats), NUMERIC(max_sats), HASH256(script_hash). Not
invertible. Verifies that a specific output has a value within bounds and a script matching
the committed hash.

### OUTPUT_COUNT
Block type 0x0804 (Governance family). Output count bounds on the spending transaction.
Conditions: NUMERIC(min_outputs), NUMERIC(max_outputs). Invertible.

### P2PK_LEGACY
Block type 0x0901 (Legacy family). Wrapped P2PK. Key-consuming with 1 pubkey. Conditions:
SCHEME(1). Not invertible.

### P2PKH_LEGACY
Block type 0x0902 (Legacy family). Wrapped P2PKH. Key-consuming (pubkey in witness, hash
in conditions). Conditions: HASH160(20). Not invertible. Pubkey count 0 in PubkeyCountForBlock
because pubkey is hashed, not folded into Merkle leaf.

### P2SH_LEGACY
Block type 0x0903 (Legacy family). Wrapped P2SH. Conditions: HASH160(20). Invertible.
Not key-consuming. Inner conditions are provided via SCRIPT_BODY in the witness.

### P2TR_LEGACY
Block type 0x0906 (Legacy family). Wrapped P2TR key-path. Key-consuming with 1 pubkey.
Conditions: SCHEME(1). Not invertible.

### P2TR_SCRIPT_LEGACY
Block type 0x0907 (Legacy family). Wrapped P2TR script-path. Key-consuming with 1 pubkey
(internal key). Conditions: HASH256(32). Not invertible. Inner conditions via SCRIPT_BODY.

### P2WPKH_LEGACY
Block type 0x0904 (Legacy family). Wrapped P2WPKH. Key-consuming (pubkey in witness,
hash in conditions). Conditions: HASH160(20). Not invertible.

### P2WSH_LEGACY
Block type 0x0905 (Legacy family). Wrapped P2WSH. Conditions: HASH256(32). Invertible.
Not key-consuming. Inner conditions via SCRIPT_BODY.

### PLC
Programmable Logic Controller. A family of 14 block types (0x0600-0x06FF) inspired by
industrial PLC ladder logic: HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS,
TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP,
COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, and COSIGN. These enable stateful spending
logic via recursive covenants.

### PREIMAGE
Data type 0x05. Hash preimage, exactly 32 bytes. Witness-only (never in conditions).
Limited to 2 PREIMAGE + SCRIPT_BODY fields per witness (`MAX_PREIMAGE_FIELDS_PER_WITNESS`).

### PTLC
Block type 0x0704 (Compound family). Adaptor signature + CSV combined: point-locked
payment channel. Key-consuming with 2 pubkeys. Conditions: NUMERIC(csv_sequence).
Not invertible.

### PUBKEY
Data type 0x01. Public key, 1 to 2048 bytes (supports PQ keys). Witness-only. In
conditions context, pubkeys are folded into the Merkle leaf via `merkle_pub_key`.

### PUBKEY_COMMIT
Data type 0x02. Public key commitment, exactly 32 bytes. Removed from conditions context
(pubkeys now folded into Merkle leaf). Still a valid wire-format data type for backward
compatibility.

### RATE_LIMIT
Block type 0x0671 (PLC family). Rate limiter. Conditions: NUMERIC(max_per_block),
NUMERIC(accumulation_cap), NUMERIC(refill_blocks). Invertible. Not key-consuming.

### RECURSE_COUNT
Block type 0x0404 (Recursion family). Recursive countdown. Conditions:
NUMERIC(max_count). Invertible.

### RECURSE_DECAY
Block type 0x0406 (Recursion family). Recursive parameter decay. No implicit layout
(variable field count). Invertible.

### RECURSE_MODIFIED
Block type 0x0402 (Recursion family). Recursive re-encumber with a single mutation.
No implicit layout (variable field count: 2 + 4*N mutations). Invertible.

### RECURSE_SAME
Block type 0x0401 (Recursion family). Recursive re-encumber with identical conditions.
Conditions: NUMERIC(max_depth). Invertible.

### RECURSE_SPLIT
Block type 0x0405 (Recursion family). Recursive output splitting. Conditions:
NUMERIC(max_splits), NUMERIC(min_split_sats). Invertible.

### RECURSE_UNTIL
Block type 0x0403 (Recursion family). Recursive re-encumber until a specified block
height. Conditions: NUMERIC(until_height). Invertible.

### Relay
Struct in `types.h`. A shared condition set that can be required by multiple rungs or
other relays. Contains blocks and relay_refs (indices of prerequisite relays). Forward-only
indexing: relay N can only reference relays 0..N-1 (no cycles). Maximum 8 relays per
witness (`MAX_RELAYS`), maximum chain depth 4 (`MAX_RELAY_DEPTH`). Evaluated by
`EvalRelays()` in `evaluator.h`.

### RELATIVE_VALUE
Block type 0x0805 (Governance family). Output value as a ratio of input value. Conditions:
NUMERIC(numerator), NUMERIC(denominator). Not invertible.

### Rung
Struct in `types.h`. A single spending path containing blocks (AND-combined) and optional
relay_refs. All blocks must return SATISFIED for the rung to pass. Evaluated by
`EvalRung()` in `evaluator.h`. Maximum 8 blocks per rung (`MAX_BLOCKS_PER_RUNG`).

### RungAttestationMode
Enum in `types.h`. INLINE (0x01, signatures inline in witness) and AGGREGATE (0x02,
half-aggregated: R per input in witness, aggregated s-value at transaction level).

### RungBlock
Struct in `types.h`. A function block within a rung. Contains a `RungBlockType`, a vector
of `RungField` typed fields, and an `inverted` flag.

### RungCoil
Struct in `types.h`. Coil metadata attached to each output. Fields: `coil_type` (UNLOCK,
UNLOCK_TO), `attestation` (INLINE or AGGREGATE), `scheme` (SCHNORR,
ECDSA, FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA), `address_hash` (SHA256 of raw
address, 0 or 32 bytes), `conditions` (reserved, must be empty), `rung_destinations`
(per-rung destination overrides as pairs of rung_index + address_hash).

### RungConditions
Struct in `conditions.h`. The locking side of a v4 output. Fields: rungs, coil, relays,
optional template_ref, optional conditions_root (MLSC root from UTXO). Key methods:
`IsMLSC()`, `IsTemplateRef()`, `IsEmpty()`.

### RungCoilType
Enum in `types.h`. Two values: UNLOCK (0x01, standard spend), UNLOCK_TO (0x02, send to
specific destination).

### RungDataType
Enum in `types.h`. 11 data types: PUBKEY (0x01), PUBKEY_COMMIT (0x02), HASH256 (0x03),
HASH160 (0x04), PREIMAGE (0x05), SIGNATURE (0x06), SPEND_INDEX (0x07), NUMERIC (0x08),
SCHEME (0x09), SCRIPT_BODY (0x0A), DATA (0x0B). Each has minimum and maximum size
constraints enforced at deserialization.

### RungEvalContext
Struct in `evaluator.h`. Extended evaluation context for blocks needing transaction data.
Fields: tx, input_index, input_amount, output_amount, block_height, spending_output,
input_conditions, spent_outputs (for COSIGN), relays (for KEY_REF_SIG), rung_relay_refs,
rung_pubkeys, verified_leaves (for covenant checks), mlsc_proof, aggregate_ctx.

### RungScheme
Enum in `types.h`. Signature schemes: SCHNORR (0x01), ECDSA (0x02), FALCON512 (0x10),
FALCON1024 (0x11), DILITHIUM3 (0x12), SPHINCS_SHA (0x13). Schemes 0x10+ are post-quantum
(`IsPQScheme()` returns true).

### RUNG_TX
A version 4 Bitcoin transaction carrying Ladder Script conditions. The wire format uses
flag byte `0x02` (distinct from SegWit's `0x01`). Layout: nVersion(4) + dummy(0x00) +
flag(0x02) + vin[] + conditions_root(32) + vout[](8 bytes each) + witness[] +
aggregated_sig + nLockTime(4). On deserialisation, outputs are inflated to
`CTxOut(value, 0xDF + root)` for compatibility with existing Bitcoin Core code.

### RUNG_TX_VERSION
Transaction version 4. All Ladder Script transactions use this version. Defined as a
consensus constant. Outputs use MLSC format (`0xDF` prefix, 8 bytes per output, shared
conditions_root per transaction). Flag byte 0x02 signals RUNG_TX serialisation. Witnesses
are deserialised via `DeserializeLadderWitness()`. Verification entry point: `VerifyRungTx()`.

### TX_MLSC
Transaction-level Merkelised Ladder Script Conditions. The conditions commitment scheme
replacing per-output MLSC. One shared Merkle tree per transaction (PLC model: one program,
multiple output coils). Each output is 8 bytes (value only); the transaction carries a
single shared `conditions_root` with MLSC prefix byte `0xDF`. A creation proof witness section is validated at
block acceptance. Leaf computation uses `TaggedHash("LadderLeaf", structural_template ||
value_commitment)`. Each rung's coil has an `output_index` field declaring which output it
governs. Anti-spam surface: 112 bytes per transaction (flat). Simple payment: 119 vB
(key-path) / 140 vB (script-path). Batch 100: 914 vB (71% cheaper than P2WPKH). Key functions: `IsMLSCScript()`, `GetMLSCRoot()`,
`CreateMLSCScript()`, `VerifyMLSCProof()`. Leaf order: `[rung_leaf[0], ..., rung_leaf[N-1],
relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]`.

### SCHEME
Data type 0x09. Signature scheme selector, exactly 1 byte. Values defined by RungScheme.

### Script-path Spend
A 2 or 3 element witness spend. The witness carries a `LadderWitness` (stack[0]) and an
`MLSCProof` (stack[1]). The node deserialises the proof, verifies the Merkle proof against
the conditions root, merges conditions with the witness, and evaluates the ladder. If the
output was tweaked (see LadderTweak), a third element (the internal pubkey) proves the
tweak relationship. This is the 140 vB path.

### Synthetic Root Entry
A UTXO entry at `(txid, 0xFFFFFFFF)` storing the conditions root once per RUNG_TX.
Individual outputs store a 1-byte compressed scriptPubKey (`0x06`); the root is recovered
from this synthetic entry at spend time. Defined by `MLSC_ROOT_VOUT = 0xFFFFFFFF` in
`coins.h`. This deduplication reduces per-output UTXO cost from ~41 bytes (P2TR) to ~8
bytes. Written in `AddCoins()` in `coins.cpp`.

### SCRIPT_BODY
Data type 0x0A. Serialized inner conditions, 1 to 80 bytes. Witness-only. Used by
P2SH_LEGACY, P2WSH_LEGACY, and P2TR_SCRIPT_LEGACY for inner condition delivery. Shares
the MAX_PREIMAGE_FIELDS_PER_WITNESS limit with PREIMAGE (combined cap of 2).

### SEQUENCER
Block type 0x0651 (PLC family). Step sequencer. Conditions: NUMERIC(current_step),
NUMERIC(total_steps). Invertible.

### SerializationContext
Enum in `serialize.h`. Two values: WITNESS (spending side, SIGNATURE and PREIMAGE allowed)
and CONDITIONS (locking side, only condition data types). Controls which implicit field
table is used and which data types are accepted.

### SIG
Block type 0x0001 (Signature family). Single signature verification. Key-consuming with
1 pubkey. Conditions: SCHEME(1). Not invertible. Witness: PUBKEY, SIGNATURE.

### Sighash
The signature hash for Ladder Script script-path transactions, computed by
`SignatureHashLadder()` in `sighash.cpp`. Uses tagged hash `TaggedHash("LadderSighash")`.
Commits to: epoch (0),
hash_type, tx version/locktime, prevouts/amounts/sequences (unless ANYONECANPAY/APO),
outputs (unless NONE), spend_type (always 0), input-specific data, conditions hash (unless
ANYPREVOUTANYSCRIPT), and output for SIGHASH_SINGLE.

### SignatureHashLadderKeyPath
Function in `sighash.cpp`. Computes the sighash for key-path spends. Uses tagged hash
`TaggedHash("LadderKeyPathSighash")`. Does NOT commit to the conditions hash (since no
conditions are revealed in key-path). Domain-separated from `SignatureHashLadder` to
prevent cross-path signature replay.

### SIGNATURE
Data type 0x06. Signature, 1 to 50000 bytes (accommodates PQ signatures up to 49216 bytes
for SPHINCS+). Witness-only.

### SPEND_INDEX
Data type 0x07. Spend index reference, exactly 4 bytes.

### TAGGED_HASH
Block type 0x0203 (Hash family). BIP-340 tagged hash verification. Conditions:
HASH256(tag_hash), HASH256(content_hash). Witness adds PREIMAGE. Invertible.

### TIMELOCKED_MULTISIG
Block type 0x0706 (Compound family). MULTISIG + CSV combined. Key-consuming with variable
pubkey count. Conditions: NUMERIC(threshold_M), NUMERIC(csv). Not invertible.

### TIMELOCKED_SIG
Block type 0x0701 (Compound family). SIG + CSV combined. Key-consuming with 1 pubkey.
Conditions: SCHEME(1), NUMERIC(csv_value). Not invertible. Witness: PUBKEY, SIGNATURE,
NUMERIC.

### TIMER_CONTINUOUS
Block type 0x0611 (PLC family). Continuous timer counting consecutive blocks. Conditions:
NUMERIC(accumulated), NUMERIC(target). Invertible.

### TIMER_OFF_DELAY
Block type 0x0612 (PLC family). Off-delay timer (hold after trigger). Conditions:
NUMERIC(remaining). Invertible.

### TxAggregateContext
Reserved. AGGREGATE attestation is not implemented in the current release. The attestation
byte is reserved for future extension via soft fork.

### value_commitment
A component of the TX_MLSC leaf hash. In the new leaf computation, each leaf is
`TaggedHash("LadderLeaf", structural_template || value_commitment)`, replacing the
previous `TaggedHash("LadderLeaf", serialized_blocks || pubkeys)`. The value commitment
binds the output value to the Merkle tree.

### ValidateRungOutputs
Function in `evaluator.cpp`. Per-transaction consensus check run on the first input.
Ensures every output uses MLSC format (`0xDF` prefix), enforces dust threshold
(`MIN_RUNG_OUTPUT_VALUE = 546 sats`), and allows at most 1 DATA_RETURN output per
transaction.

### VAULT_LOCK
Block type 0x0302 (Covenant family). Vault timelock covenant with hot/cold key pairs.
Key-consuming with 2 pubkeys. Conditions: NUMERIC(hot_delay). Not invertible.

### WEIGHT_LIMIT
Block type 0x0802 (Governance family). Maximum transaction weight constraint. Conditions:
NUMERIC(max_weight). Invertible.

### Wire Format
The binary serialization of `LadderWitness`, defined in `serialize.h/cpp`. Structure:
`[n_rungs]` then per-rung `[n_blocks]` with blocks encoded as micro-header or escape +
type, followed by implicit or explicit fields. After rungs: coil (type + attestation +
scheme + address + conditions + rung_destinations), then relays and per-rung relay_refs.
Key constants: `MAX_RUNGS = 16`, `MAX_BLOCKS_PER_RUNG = 8`, `MAX_FIELDS_PER_BLOCK = 16`,
`MAX_LADDER_WITNESS_SIZE = 100000`, `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2` (per-input),
`MAX_PREIMAGE_FIELDS_PER_TX = 2` (per-transaction), `MAX_RELAYS = 8`, `MAX_RELAY_DEPTH = 4`.

### Witness Reference
Struct `WitnessReference` in `types.h`. When `n_rungs == 0` on the wire, rungs and relays
are inherited from another input's witness. Only field-level diffs (via `WitnessDiff`) and
a fresh coil are provided. Coil is never inherited. Resolution happens in `VerifyRungTx()`.
