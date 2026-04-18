# Ladder Script: Frequently Asked Questions

---

## Q1: What is Ladder Script?

Ladder Script is the spending-condition language for Bitcoin v4 transaction format (`RUNG_TX`)
transactions. It replaces Bitcoin Script with a structured, typed system of
**function blocks** organized into **rungs**. Each block evaluates exactly one
spending condition (signature check, timelock, hash preimage, covenant, etc.),
and each rung is a conjunction (AND) of blocks. The complete ladder is a
disjunction (OR) across rungs: the first rung in which every block returns
SATISFIED wins.

Ladder Script is carried in two places:

1. **Conditions** (locking side): stored on-chain as a TX_MLSC output.
   Each output is 8 bytes (value only); the transaction carries one shared
   `conditions_root` with prefix byte `0xDF`. A creation proof in the witness
   is validated at block acceptance. The full conditions are never on-chain;
   only the root hash is published. Inline conditions (`0xC1`) are removed.
2. **Witness** (spending side): carried in the transaction witness. Contains
   signatures, preimages, and other secrets required to satisfy the conditions.

The transaction version for Ladder Script transactions is **4** (`RUNG_TX_VERSION = 4`).

---

## Q2: How does Ladder Script differ from Bitcoin Script?

| Property | Bitcoin Script | Ladder Script |
|---|---|---|
| Encoding | Stack-based opcodes | Typed function blocks with fixed field layouts |
| Evaluation | Sequential opcode execution | Block dispatch: AND within rung, OR across rungs |
| Data model | Untyped stack items | 11 typed data types (PUBKEY, HASH256, NUMERIC, etc.) |
| Locking script | On-chain (scriptPubKey) | Off-chain Merkle root only (TX_MLSC, 8 bytes per output + shared root) |
| Extensibility | Soft-fork new opcodes | New block types added to micro-header table |
| Post-quantum | Not supported | FALCON-512, FALCON-1024, Dilithium3, SPHINCS+ |
| Wire efficiency | Variable opcode sizes | Micro-headers (1 byte) + implicit field layouts |
| Covenants | Limited (OP_CTV proposal) | Native CTV, recursion, VAULT_LOCK, AMOUNT_LOCK, OUTPUT_CHECK |
| Batch verification | Not supported | BatchVerifier collects Schnorr sigs for batch verify |
| Anti-spam | Script size limits only | Typed fields, max sizes, PREIMAGE cap, data-embedding rejection |
| Inversion | No equivalent | Selective inversion (per-block negation, restricted to safe types) |
| State machines | Not possible | PLC family: latches, counters, timers, sequencers, rate limiters |

---

## Q3: What are the block type families?

There are **10 families** containing **61 block types**.

| # | Family | Range | Block types | Count |
|---|--------|-------|-------------|-------|
| 1 | **Signature** | `0x0001`-`0x00FF` | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG | 5 |
| 2 | **Timelock** | `0x0100`-`0x01FF` | CSV, CSV_TIME, CLTV, CLTV_TIME | 4 |
| 3 | **Hash** | `0x0200`-`0x02FF` | TAGGED_HASH, HASH_GUARDED | 2 |
| 4 | **Covenant** | `0x0300`-`0x03FF` | CTV, VAULT_LOCK, AMOUNT_LOCK | 3 |
| 5 | **Recursion** | `0x0400`-`0x04FF` | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY | 6 |
| 6 | **Anchor/L2** | `0x0500`-`0x05FF` | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN | 7 |
| 7 | **PLC** | `0x0600`-`0x06FF` | HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN | 14 |
| 8 | **Compound** | `0x0700`-`0x07FF` | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG | 6 |
| 9 | **Governance** | `0x0800`-`0x08FF` | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK | 7 |
| 10 | **Legacy** | `0x0900`-`0x09FF` | P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY, P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY | 7 |

---

## Q4: How does evaluation work?

Evaluation follows a strict two-level boolean structure:

1. **Within a rung**: AND logic. Every block must return `SATISFIED`. If any
   block returns `UNSATISFIED` or `ERROR`, the rung fails.
2. **Across rungs**: OR logic. The evaluator tries rungs in order (index 0, 1,
   2, ...). The first rung where all blocks are SATISFIED wins.
3. **Relays**: Evaluated before rungs. Each relay is a set of blocks with AND
   logic. Rungs and relays can declare `relay_refs`; all referenced relays must
   be SATISFIED before the rung/relay is evaluated.

```
EvalLadder:
  1. EvalRelays (index 0 first, caching results)
  2. For each rung r in order:
     a. Check relay_refs (all must be SATISFIED)
     b. For each block in rung r:
        - result = EvalBlock(block)
        - result = ApplyInversion(result, block.inverted)
        - If result != SATISFIED, skip to next rung
     c. If all blocks SATISFIED, return true (rung r wins)
  3. No rung satisfied: return false
```

**EvalResult values**:
- `SATISFIED`: condition met
- `UNSATISFIED`: condition not met (valid but fails)
- `ERROR`: malformed block (consensus failure)
- `UNKNOWN_BLOCK_TYPE`: forward compatibility (treated as UNSATISFIED)

---

## Q5: What is selective inversion?

Any block can be marked as **inverted** (`block.inverted = true`). When inverted,
the `ApplyInversion` function flips the evaluation result:

- `SATISFIED` becomes `UNSATISFIED`
- `UNSATISFIED` becomes `SATISFIED`
- `ERROR` remains `ERROR` (errors never flip)
- `UNKNOWN_BLOCK_TYPE` when inverted becomes `ERROR` (unknown types must not satisfy)

**Not all block types can be inverted.** The `IsInvertibleBlockType()` function
defines a fail-closed allowlist. Key-consuming blocks (SIG, MULTISIG, all
compound blocks with signatures, COSIGN, etc.) are **never invertible** because
inverting them would allow garbage pubkey data embedding: provide an invalid
pubkey (arbitrary data), signature check fails, inversion flips to SATISFIED.

Invertible families include: timelocks, hashes (TAGGED_HASH), covenants,
recursion, PLC, anchors, governance (WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT,
ACCUMULATOR), and hash-locked legacy (P2SH_LEGACY, P2WSH_LEGACY).

In the wire format, inverted blocks use escape byte `0x81` (vs `0x80` for
non-inverted escapes). Micro-header encoding (`0x00`-`0x7F`) is always
non-inverted.

In descriptor notation, inversion is written with `!` prefix: `!csv(144)`.

---

## Q6: What is merkle_pub_key?

`merkle_pub_key` is the design pattern where public keys are **not stored in the
conditions** (locking side). Instead, pubkeys are carried in the witness and
bound to the MLSC Merkle leaf at fund time.

When computing a rung's Merkle leaf hash (`ComputeRungLeaf`), the function:

1. Serializes the rung's blocks in CONDITIONS context (no pubkeys, no signatures)
2. Appends each pubkey in positional order (walked left-to-right across
   key-consuming blocks using `PubkeyCountForBlock()`)
3. Hashes the result with the `LadderLeaf` tagged hasher

This means:
- **Conditions on-chain** contain only `SCHEME`, `HASH256`, `HASH160`, `NUMERIC`,
  `SPEND_INDEX`, and `DATA` fields. No `PUBKEY` or `PUBKEY_COMMIT`.
- **Pubkeys appear only in the witness**, where they are verified against the
  Merkle proof binding them to the commitment root.
- The writable surface for arbitrary data in conditions is eliminated because
  `PUBKEY_COMMIT` (32 bytes of attacker-chosen data) no longer exists there.

Key-consuming block types (those returning `true` from `IsKeyConsumingBlockType()`)
include: SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG, COSIGN,
TIMELOCKED_SIG, HTLC, HASH_SIG, CLTV_SIG, PTLC, TIMELOCKED_MULTISIG,
P2PK_LEGACY, P2PKH_LEGACY, P2WPKH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY,
ANCHOR_CHANNEL, ANCHOR_ORACLE, VAULT_LOCK, LATCH_SET, LATCH_RESET,
COUNTER_DOWN, COUNTER_UP.

---

## Q7: What is TX_MLSC?

**TX_MLSC** (Transaction-level Merkelized Ladder Script Conditions) is the output
format for Ladder Script. In the TX_MLSC model, there is one shared Merkle tree
per transaction (PLC model: one program, multiple output coils). Each output is
8 bytes (value only); the transaction carries a single shared `conditions_root`
with prefix byte `0xDF`. A creation proof in the witness section is validated at
block acceptance.

Each rung's coil has an `output_index` field declaring which output it governs.

The `conditions_root` is a Merkle tree root computed from leaves:

```
Leaf order: [rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]
```

Leaf hashing uses `TaggedHash("LadderLeaf", structural_template || value_commitment)`.
Interior nodes use `TaggedHash("LadderInternal", min(a,b) || max(a,b))` with
sorted children (lexicographic order). The tree is padded to the next power of 2
with `MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")`.

The transaction serialization uses flag byte `0x02` to signal the TX_MLSC format.

At spend time, the witness carries an `MLSCProof` containing:
- `total_rungs`, `total_relays`, `rung_index`
- The revealed rung's condition blocks
- Revealed relay conditions (for relays referenced by the rung)
- Proof hashes for unrevealed leaves
- Optional: revealed mutation targets (for cross-rung recursion)

The verifier (`VerifyMLSCProof`) reconstructs the full leaf array from revealed
data plus proof hashes, builds the Merkle tree, and checks the computed root
against the transaction's `conditions_root`.

**Privacy benefit**: only the spending rung is revealed. All other rungs remain
hidden behind their leaf hashes.

**Anti-spam surface**: 112 bytes per transaction (flat, no contiguous block).
Zero readable attacker data in UTXOs (root is protocol-derived).

---

## Q8: What sighash types are supported?

Ladder Script sighash computation uses `TaggedHash("LadderSighash")` and
supports these hash types:

| Hash type | Value | Behavior |
|-----------|-------|----------|
| `SIGHASH_DEFAULT` | `0x00` | Commits to all inputs and outputs (same as ALL) |
| `SIGHASH_ALL` | `0x01` | Commits to all inputs and outputs |
| `SIGHASH_NONE` | `0x02` | Commits to all inputs, no outputs |
| `SIGHASH_SINGLE` | `0x03` | Commits to all inputs, only the matching output |
| `SIGHASH_ANYONECANPAY` | `0x81`-`0x83` | Commits to only the signing input |
| `SIGHASH_ANYPREVOUT` | `0x40`-`0x43` | Skips prevout commitment (BIP-118 analogue) |
| `SIGHASH_ANYPREVOUTANYSCRIPT` | `0xC0`-`0xC3` | Skips prevout + conditions commitment |

The valid hash type ranges are: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

The sighash commits to:
- Epoch (always 0)
- Hash type byte
- Transaction version and locktime
- Prevouts hash, amounts hash, sequences hash (unless ANYONECANPAY; prevouts
  skipped for ANYPREVOUT)
- Outputs hash (unless NONE)
- Spend type (always 0 for ladder; no annex or extensions)
- Input-specific data (prevout or index)
- Conditions hash: SHA256 of serialized conditions, or the MLSC `conditions_root`
  directly (skipped for ANYPREVOUTANYSCRIPT)
- Output hash for SIGHASH_SINGLE

**ANYPREVOUT** enables LN-Symmetry/eltoo: the signature still commits to amounts,
sequences, and conditions, but not to the specific prevout being spent.

**ANYPREVOUTANYSCRIPT** enables rebindable signatures across different scripts
by additionally skipping the conditions commitment.

---

## Q9: How does the wire format work?

### Micro-headers

Each block begins with a single-byte **micro-header** that maps to a block type
via a 128-entry lookup table (`MICRO_HEADER_TABLE`):

- `0x00`-`0x7F`: Lookup table index (1 byte total for block header)
- `0x80`: Escape byte, followed by `uint16_t LE` block type (3 bytes total, not inverted)
- `0x81`: Escape byte, followed by `uint16_t LE` block type (3 bytes total, inverted)

All 61 block types have assigned micro-header slots (slots 0x00 through
0x3E). Slots 0x07 and 0x08 are reserved.

### Implicit field layouts

When a block uses a micro-header and has a known implicit field layout for the
current serialization context (WITNESS or CONDITIONS), field count bytes and
data type bytes are omitted. The deserializer knows the exact number, types,
and sizes of fields from the block type alone.

For example, SIG in CONDITIONS context has the implicit layout `[SCHEME(1)]`,
meaning exactly 1 byte follows (the scheme byte, no length prefix). SIG in
WITNESS context has `[SCHEME(1), PUBKEY(var), SIGNATURE(var)]`.

**Varint NUMERIC optimization**: NUMERIC fields are encoded as CompactSize
values directly (no length prefix), saving 1-4 bytes per numeric field. They
are always deserialized into 4-byte little-endian storage.

**Fixed-size fields**: Fields like SCHEME (always 1 byte), HASH256 (always 32
bytes), and HASH160 (always 20 bytes) skip the length prefix entirely in
implicit layouts.

### Full wire format

```
[n_rungs: varint]
for each rung:
  [n_blocks: varint]
  for each block:
    [micro_header or escape + type]
    [implicit fields] or [n_fields: varint, explicit fields]
[coil: coil_type(1) + attestation(1) + scheme(1) + addr_len(varint) + addr + n_coil_conditions(varint)]
[rung_destinations: n(varint) + entries]
[relays section (optional)]
[per-rung relay_refs (optional)]
```

**Diff witness mode**: When `n_rungs == 0`, the witness is a reference to
another input's witness with field-level diffs (see Q19).

---

## Q10: What anti-spam properties exist?

Ladder Script enforces multiple layers of anti-spam protection:

1. **Typed fields with size bounds**: Every data type has a minimum and maximum
   size. PUBKEY: 1-2048 bytes. SIGNATURE: 1-50000 bytes. HASH256: exactly 32
   bytes. HASH160: exactly 20 bytes. PREIMAGE: exactly 32 bytes. NUMERIC:
   1-4 bytes. SCHEME: 1 byte. SCRIPT_BODY: 1-80 bytes. DATA: 1-40 bytes.

2. **PREIMAGE/SCRIPT_BODY field cap**: Maximum 2 PREIMAGE or SCRIPT_BODY
   fields per witness (`MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`, fast reject).
   The binding constraint is per-transaction: `MAX_PREIMAGE_FIELDS_PER_TX = 2`
   sums across ALL inputs, preventing multi-input data embedding. Total
   user-chosen preimage data: 64 bytes per transaction regardless of input count.

3. **Data-embedding type rejection**: For blocks without an implicit layout,
   high-bandwidth data types (PUBKEY_COMMIT, HASH256, HASH160, DATA) are
   rejected. This prevents layout-less blocks from carrying
   16 x 80 = 1280 bytes of unvalidated payload. ACCUMULATOR is whitelisted
   (needs variable HASH256 fields for Merkle proofs, capped at 10).

4. **DATA type restriction**: The DATA type is only allowed in DATA_RETURN
   blocks. Using it in any other block type causes a deserialization error.

5. **merkle_pub_key**: Public keys removed from conditions eliminates the
   PUBKEY_COMMIT writable surface.

6. **Inverted key-consuming block rejection**: Blocks that consume pubkeys
   cannot be inverted, preventing garbage-pubkey data embedding.

7. **Strict field enforcement**: When a block type has an implicit layout, the
   explicit field count and types must match exactly.

8. **Hash-preimage binding**: Anchor blocks (ANCHOR_POOL, ANCHOR_RESERVE,
   ANCHOR_SEAL) and ONE_SHOT verify that every HASH256 field equals
   SHA256(corresponding PREIMAGE), preventing unverified hash data embedding.

9. **Consensus limits**:
   - `MAX_RUNGS = 16`
   - `MAX_BLOCKS_PER_RUNG = 8`
   - `MAX_FIELDS_PER_BLOCK = 16`
   - `MAX_LADDER_WITNESS_SIZE = 100000` bytes
   - `MAX_RELAYS = 8`
   - `MAX_REQUIRES = 8` (relay_refs per rung or relay)
   - `MAX_RELAY_DEPTH = 4` (transitive chain depth)
   - `MAX_COIL_CONDITION_RUNGS = 0` (coil conditions reserved)
   - `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2` (per-input fast reject)
   - `MAX_PREIMAGE_FIELDS_PER_TX = 2` (per-transaction binding constraint)
   - `COIL_ADDRESS_HASH_SIZE = 32` (SHA256 of raw address)

10. **Blanket HASH256 rejection**: In blocks without implicit layouts, HASH256
    fields are rejected by the `IsDataEmbeddingType` check, closing the gap
    where arbitrary 32-byte data could be injected.

---

## Q11: What coil types exist? What are rung_destinations?

### Coil types

Every Ladder Script output carries a **coil** with three metadata bytes:

| Field | Type | Values |
|-------|------|--------|
| `attestation` | `RungAttestationMode` | `INLINE (0x01)`: signatures inline in witness. `AGGREGATE (0x02)` and `DEFERRED (0x03)` are reserved for future extension (rejected at deserialization). |
| `scheme` | `RungScheme` | `SCHNORR (0x01)`, `ECDSA (0x02)`, `FALCON512 (0x10)`, `FALCON1024 (0x11)`, `DILITHIUM3 (0x12)`, `SPHINCS_SHA (0x13)` |

The coil also carries:
- **address_hash**: 0 or 32 bytes. When present, it is `SHA256(raw_address)`.
  The raw address never goes on-chain.
- **conditions**: Reserved (must be 0 rungs; `MAX_COIL_CONDITION_RUNGS = 0`).

### Rung destinations

`rung_destinations` is a per-rung extension of the coil. Each entry is a pair
of `(rung_index: uint16_t, address_hash: 32 bytes)`. This allows different
rungs to route funds to different destinations.

Constraints:
- Maximum entries: `MAX_RUNGS` (16)
- Rung indices must be unique (duplicate indices rejected at deserialization)
- Coil leaf computation includes rung_destinations (Merkle-committed)

---

## Q12: What is a relay?

A **relay** is a reusable set of condition blocks that can be shared across
multiple rungs. Relays are evaluated independently before rungs, and their
results are cached. Rungs and other relays can declare **relay_refs** (indices
into the relay array), requiring all referenced relays to be SATISFIED before
the rung/relay is evaluated.

Example use case: a shared signature check. If 4 rungs all require Alice's
signature, Alice's SIG block can be placed in a relay. Each rung declares a
relay_ref to that relay. Alice signs once; the relay is evaluated once and
cached.

Constraints from the serialization layer:
- Maximum 8 relays per ladder (`MAX_RELAYS = 8`)
- Maximum 8 blocks per relay (`MAX_BLOCKS_PER_RUNG`)
- Maximum 8 relay_refs per rung or relay (`MAX_REQUIRES = 8`)
- Maximum transitive relay chain depth: 4 (`MAX_RELAY_DEPTH = 4`)
- Relay relay_refs must point backward (no forward or self references)
- Relays participate in the MLSC Merkle tree as `relay_leaf` entries

Relay evaluation uses AND logic (same as rung evaluation): every block in the
relay must return SATISFIED. If a relay's relay_refs are not all SATISFIED, the
relay itself evaluates to UNSATISFIED.

`KEY_REF_SIG` blocks can reference a relay's pubkey: the block carries
`NUMERIC(relay_index)` and `NUMERIC(block_index)` in conditions, plus a
SIGNATURE in the witness. At evaluation, the pubkey (and optionally SCHEME) is
resolved from the referenced relay block.

---

## Q13: How do covenant/recursion blocks work?

### Covenant blocks

**CTV** (`0x0301`): Implements BIP-119 `OP_CHECKTEMPLATEVERIFY`. Conditions
carry a 32-byte HASH256 template hash. At evaluation, `ComputeCTVHash` computes
the BIP-119 template hash from the spending transaction and compares it to the
committed hash. SATISFIED when they match.

**VAULT_LOCK** (`0x0302`): Two-path vault with recovery key and hot key. The
block carries two PUBKEYs (recovery and hot) and a NUMERIC delay. If the
recovery key's signature verifies, SATISFIED immediately (cold sweep). If the
hot key's signature verifies, the CSV delay must also be met.

**AMOUNT_LOCK** (`0x0303`): Checks that the output amount is within a range.
Carries two NUMERICs (min_sats, max_sats). SATISFIED when
`min_sats <= output_amount <= max_sats`.

### Recursion blocks

All recursion blocks enforce that the spending transaction's output carries
specific MLSC conditions, creating covenant chains.

**RECURSE_SAME** (`0x0401`): Output must carry identical conditions (same MLSC
root). Carries a NUMERIC max_depth. SATISFIED when depth > 0 and the output
MLSC root matches the input MLSC root.

**RECURSE_MODIFIED** (`0x0402`): Output must carry conditions with specific
NUMERIC field mutations. Carries max_depth + mutation specs (rung_idx,
block_idx, param_idx, delta). Verifies the output root matches the expected
root after applying mutations.

**RECURSE_UNTIL** (`0x0403`): Recursive until a block height. Carries a NUMERIC
until_height. If the effective height >= until_height, the covenant terminates
(SATISFIED without recursion). Otherwise, the output must re-encumber with
identical conditions.

**RECURSE_COUNT** (`0x0404`): Countdown covenant. Carries a NUMERIC count. If
count == 0, the covenant terminates. Otherwise, the output must re-encumber
with count-1. The evaluator recomputes the MLSC leaf with the decremented count
and verifies the output root.

**RECURSE_SPLIT** (`0x0405`): Recursive output splitting. Carries max_splits
and min_split_sats. Decrements max_splits, ensures every output has the new
MLSC root and meets min_split_sats, and verifies total outputs do not exceed
total inputs (value conservation).

**RECURSE_DECAY** (`0x0406`): Like RECURSE_MODIFIED but with negated deltas
(parameters decrease over time). Uses the same mutation spec format.

Leaf-centric verification: when `MLSCVerifiedLeaves` is available, recursion
evaluators replace only the mutated leaf in the verified leaf array and rebuild
the Merkle tree, avoiding the need to know all other rungs' pubkeys.

---

## Q14: What post-quantum schemes are supported?

Ladder Script supports four post-quantum signature schemes via liboqs:

| Scheme | Enum | Value | Pubkey size | Sig size |
|--------|------|-------|-------------|----------|
| FALCON-512 | `FALCON512` | `0x10` | 897 bytes | ~690 bytes |
| FALCON-1024 | `FALCON1024` | `0x11` | 1793 bytes | ~1330 bytes |
| Dilithium3 | `DILITHIUM3` | `0x12` | 1952 bytes | 3293 bytes |
| SPHINCS+-SHA2-256f | `SPHINCS_SHA` | `0x13` | 64 bytes | 49216 bytes |

PQ schemes are identified by `IsPQScheme()`: any scheme with value >= `0x10`.

PQ signature verification is handled by `VerifyPQSignature()` in `pq_verify.h`.
The ladder sighash is computed first via `LadderSignatureChecker::ComputeSighash`,
then passed as the message to the PQ verifier. If PQ support is not compiled in
(`HasPQSupport()` returns false), verification returns ERROR.

PQ schemes work with: SIG, MULTISIG, TIMELOCKED_SIG, CLTV_SIG,
TIMELOCKED_MULTISIG, and KEY_REF_SIG blocks. The SCHEME field in conditions
routes the evaluator to the PQ verification path.

The PUBKEY data type allows up to 2048 bytes, and SIGNATURE allows up to 50000
bytes, accommodating even SPHINCS+ signatures.

The `MAX_LADDER_WITNESS_SIZE = 100000` bytes accommodates PQ signatures.

---

## Q15: How does OUTPUT_CHECK work?

`OUTPUT_CHECK` (`0x0807`) is a per-output value and script constraint. It
verifies that a specific output in the spending transaction meets value and
script requirements.

**Conditions fields**: 4 fields
1. `NUMERIC` (output_index): which output to check
2. `NUMERIC` (min_sats): minimum output value
3. `NUMERIC` (max_sats): maximum output value
4. `HASH256` (script_hash): SHA256 of the expected scriptPubKey

**Evaluation logic** (`EvalOutputCheckBlock`):
1. Validate all fields are present and non-negative, min_sats <= max_sats
2. Bounds check: output_index must be within `tx.vout.size()`
3. Value check: `vout[output_index].nValue` must be in `[min_sats, max_sats]`
4. Script check: `SHA256(vout[output_index].scriptPubKey)` must equal
   script_hash. If script_hash is all zeros (32 zero bytes), the script check
   is skipped (value-only constraint).

**Descriptor notation**: `output_check(idx, min, max, hex_hash)`

OUTPUT_CHECK is in the Governance family. It is not invertible (not in the
`IsInvertibleBlockType` allowlist). It has micro-header slot `0x3E`.

---

## Q16: How does the descriptor language work?

The descriptor language provides human-readable notation for Ladder Script
conditions. The parser (`ParseDescriptor`) converts descriptor strings into
`RungConditions` + per-rung pubkey lists for MLSC commitment.

**Grammar**:

```
ladder(or(rung1, rung2, ...))         -- multiple rungs (OR)
ladder(rung)                          -- single rung

rung = block                          -- single block rung
     | and(block, block, ...)         -- multi-block rung (AND)

block = sig(@alias)                   -- Schnorr signature (default)
      | sig(@alias, scheme)           -- signature with explicit scheme
      | csv(N) | csv_time(N)          -- relative timelocks
      | cltv(N) | cltv_time(N)        -- absolute timelocks
      | multisig(M, @pk1, @pk2, ...)  -- M-of-N threshold
      | hash_guarded(hex)             -- SHA256 preimage check
      | tagged_hash(hex1, hex2)       -- tagged hash verification
      | ctv(hex)                      -- CTV template hash
      | amount_lock(min, max)         -- output amount range
      | timelocked_sig(@alias, N)     -- SIG + CSV compound
      | output_check(idx, min, max, hex) -- per-output constraint
      | !block                        -- inverted block
```

**Scheme names**: `schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`,
`sphincs_sha`

**Key aliases**: `@alice`, `@bob`, etc. Mapped to pubkey bytes via the keys
parameter. The formatter (`FormatDescriptor`) reverses the process, using an
alias map to produce readable output.

---

## Q17: What is batch Schnorr verification?

`BatchVerifier` is a structure that collects `(sighash, pubkey, signature)`
tuples during evaluation and verifies them all in a single batch after all
inputs pass.

```cpp
struct BatchVerifier {
    struct Entry {
        uint256 sighash;
        XOnlyPubKey pubkey;
        std::vector<unsigned char> sig;
    };
    std::vector<Entry> entries;
    bool active{false};
};
```

When `batch->active` is true in `LadderSignatureChecker::CheckSchnorrSignature`,
the signature is not verified immediately. Instead, it is added to the batch via
`batch->Add()` and the function returns true (deferred).

After all inputs are evaluated, `batch->Verify()` verifies all entries. The
current implementation falls back to individual verification (the secp256k1
batch API is not yet available), but the interface is ready for true batch
verification.

On batch failure, `batch->FindFailure()` identifies the first invalid entry by
testing each individually, enabling precise error reporting.

Batch verification applies only to BIP-340 Schnorr signatures. ECDSA and PQ
signatures are always verified immediately.

---

## Q18: How does COSIGN work?

`COSIGN` (`0x0681`) is a cross-input spending constraint in the PLC family. It
requires that another input in the same transaction is spending a UTXO whose
scriptPubKey matches a committed hash.

**Conditions fields**: `HASH256` containing `SHA256(anchor_scriptPubKey)`

**Evaluation logic** (`EvalCosignBlock`):
1. Extract the 32-byte HASH256 field
2. Iterate over all other inputs in the transaction (skip self)
3. For each other input, compute `SHA256(spent_output.scriptPubKey)`
4. If any match the committed hash, return SATISFIED

This creates a "paired UTXO" pattern: two UTXOs that can only be spent
together. UTXO A carries `COSIGN(SHA256(scriptPubKey_B))` and UTXO B carries
`COSIGN(SHA256(scriptPubKey_A))`. Neither can be spent without the other being
present in the same transaction.

COSIGN is a key-consuming block type and cannot be inverted. It has an implicit
conditions layout of `[HASH256(32)]` and micro-header slot `0x26`.

---

## Q19: What is a witness reference (diff witness)?

A **witness reference** (also called a **diff witness**) allows an input to
inherit its witness structure from another input in the same transaction,
providing only field-level diffs.

**Wire format**: When `n_rungs == 0` at the start of the witness, the
deserializer enters diff witness mode:

```
[0: varint]                    -- sentinel: n_rungs == 0
[input_index: varint]          -- which input's witness to inherit
[n_diffs: varint]              -- number of field replacements
for each diff:
  [rung_index: varint]
  [block_index: varint]
  [field_index: varint]
  [type_byte: uint8]
  [field_data]
[coil section]                 -- fresh coil (always present)
```

**Allowed diff field types**: PUBKEY, SIGNATURE, PREIMAGE, SCRIPT_BODY, SCHEME.
Only witness-side types can be diffed.

**Constraints**:
- Maximum diffs: `MAX_FIELDS_PER_BLOCK * MAX_BLOCKS_PER_RUNG * MAX_RUNGS`
  (2048)
- PREIMAGE/SCRIPT_BODY fields in diffs are capped at
  `MAX_PREIMAGE_FIELDS_PER_WITNESS` (2)
- Source input must not itself be a diff witness (no chaining, same as template
  references)
- Relays are inherited from the source (no relay section in diff witness)

This is useful when multiple inputs spend UTXOs with identical conditions but
different signatures.

---

## Q20: How does CTV work in Ladder Script?

CTV (CheckTemplateVerify, `0x0301`) implements BIP-119 template verification as
a native block type.

**Conditions**: A single HASH256 field containing the pre-computed BIP-119
template hash.

**Template hash computation** (`ComputeCTVHash`):

```
SHA256(
  version         (4 bytes LE)
  locktime        (4 bytes LE)
  scriptsigs_hash (SHA256 of concatenated scriptSigs)
  num_inputs      (4 bytes LE)
  sequences_hash  (SHA256 of concatenated sequences)
  num_outputs     (4 bytes LE)
  outputs_hash    (SHA256 of concatenated outputs: amount + spk_len + scriptPubKey)
  input_index     (4 bytes LE)
)
```

**Evaluation**: `EvalCTVBlock` computes the template hash from the spending
transaction at the current input index and compares it byte-for-byte to the
committed hash. SATISFIED on match.

CTV has an implicit conditions layout of `[HASH256(32)]` (1 byte micro-header +
32 bytes hash = 33 bytes total in conditions). It is invertible.

---

## Q21: What legacy Bitcoin types are supported?

The Legacy family (`0x0900`-`0x09FF`) wraps 7 traditional Bitcoin transaction
types as Ladder Script block types:

| Block | Code | Evaluation |
|-------|------|------------|
| `P2PK_LEGACY` | `0x0901` | Identical to SIG (delegates to `EvalSigBlock`) |
| `P2PKH_LEGACY` | `0x0902` | HASH160(pubkey) == committed hash, then verify signature |
| `P2SH_LEGACY` | `0x0903` | HASH160(preimage) == committed hash, then deserialize and evaluate inner conditions |
| `P2WPKH_LEGACY` | `0x0904` | Identical to P2PKH (delegates to `EvalP2PKHLegacyBlock`) |
| `P2WSH_LEGACY` | `0x0905` | SHA256(preimage) == committed hash, then deserialize and evaluate inner conditions |
| `P2TR_LEGACY` | `0x0906` | Identical to SIG (key-path, delegates to `EvalSigBlock`) |
| `P2TR_SCRIPT_LEGACY` | `0x0907` | SHA256(leaf) == Merkle root, then deserialize and evaluate inner conditions |

P2SH, P2WSH, and P2TR_SCRIPT support recursive inner conditions: the PREIMAGE
(or SCRIPT_BODY) field is deserialized as a LadderWitness in CONDITIONS context,
then evaluated with remaining outer witness fields. Maximum recursion depth is 2
(`MAX_LEGACY_INNER_DEPTH = 2`).

---

## Q22: How is DATA_RETURN handled?

`DATA_RETURN` (`0x0507`) replaces `OP_RETURN` for data commitments. It is an
**unspendable** block type: if evaluation reaches a DATA_RETURN block, it
returns ERROR (the output should never have been spent).

**DATA type**: The DATA data type (`0x0B`) is restricted to DATA_RETURN blocks
only. Using DATA in any other block type causes a deserialization error.

**Size limits**: DATA fields are 1-40 bytes (hash 32 bytes + 8 bytes protocol
metadata).

**TX_MLSC integration**: DATA_RETURN payload can be appended to the shared
conditions root, producing output data of 34-73 bytes:
`0xDF + conditions_root(32) + data(1-40)`.

**Consensus**: `ValidateRungOutputs` allows exactly one DATA_RETURN per
transaction. The maximum data payload is 80 bytes.

---

## Q23: What are the consensus limits?

| Limit | Value | Source |
|-------|-------|--------|
| Max rungs per ladder | 16 | `MAX_RUNGS` |
| Max blocks per rung | 8 | `MAX_BLOCKS_PER_RUNG` |
| Max fields per block | 16 | `MAX_FIELDS_PER_BLOCK` |
| Max witness size | 100,000 bytes | `MAX_LADDER_WITNESS_SIZE` |
| Max relays per ladder | 8 | `MAX_RELAYS` |
| Max relay_refs per rung/relay | 8 | `MAX_REQUIRES` |
| Max relay chain depth | 4 | `MAX_RELAY_DEPTH` |
| Max PREIMAGE/SCRIPT_BODY per witness | 2 | `MAX_PREIMAGE_FIELDS_PER_WITNESS` |
| Max PREIMAGE/SCRIPT_BODY per tx | 2 | `MAX_PREIMAGE_FIELDS_PER_TX` |
| Coil condition rungs | 0 (reserved) | `MAX_COIL_CONDITION_RUNGS` |
| Coil address hash size | 32 bytes | `COIL_ADDRESS_HASH_SIZE` |
| Max PUBKEY size | 2,048 bytes | `FieldMaxSize(PUBKEY)` |
| Max SIGNATURE size | 50,000 bytes | `FieldMaxSize(SIGNATURE)` |
| Max SCRIPT_BODY size | 80 bytes | `FieldMaxSize(SCRIPT_BODY)` |
| Max DATA size | 40 bytes | `FieldMaxSize(DATA)` |
| HASH256 size | exactly 32 bytes | `FieldMinSize == FieldMaxSize` |
| HASH160 size | exactly 20 bytes | `FieldMinSize == FieldMaxSize` |
| PREIMAGE size | exactly 32 bytes | `FieldMinSize == FieldMaxSize` |
| NUMERIC size | 1-4 bytes | `FieldMinSize(NUMERIC)` / `FieldMaxSize(NUMERIC)` |
| SCHEME size | 1 byte | Fixed |
| SPEND_INDEX size | 4 bytes | Fixed |
| PUBKEY_COMMIT size | exactly 32 bytes | Fixed |
| Max ACCUMULATOR fields | 10 | root + 8 proof nodes + leaf |
| Legacy inner depth | 2 | `MAX_LEGACY_INNER_DEPTH` |
| Max implicit fields per layout | 8 | `MAX_IMPLICIT_FIELDS` |
| Micro-header slots | 128 | `MICRO_HEADER_SLOTS` |
| Transaction version | 4 | `RUNG_TX_VERSION` |

---

## Q24: How does the block descriptor table work?

The **block descriptor table** is the combination of the micro-header lookup
table and the implicit field layouts that together define the complete wire
encoding for every block type.

### Micro-header table

The `MICRO_HEADER_TABLE` is a 128-entry array mapping slot index to block type
(`uint16_t`). Unused slots contain `0xFFFF`. Every active block type has a
slot assignment:

- Slots 0x00-0x02: Signature (SIG, MULTISIG, ADAPTOR_SIG)
- Slots 0x03-0x06: Timelock (CSV, CSV_TIME, CLTV, CLTV_TIME)
- Slots 0x07-0x08: Reserved
- Slot 0x09: TAGGED_HASH
- Slots 0x0A-0x0C: Covenant (CTV, VAULT_LOCK, AMOUNT_LOCK)
- Slots 0x0D-0x12: Recursion (6 types)
- Slots 0x13-0x18: Anchor (6 types, excluding DATA_RETURN)
- Slots 0x19-0x26: PLC (14 types)
- Slots 0x27-0x2C: Compound (6 types)
- Slots 0x2D-0x32: Governance (6 types, excluding OUTPUT_CHECK)
- Slots 0x33-0x34: Late-added Signature (MUSIG_THRESHOLD, KEY_REF_SIG)
- Slots 0x35-0x3B: Legacy (7 types)
- Slot 0x3C: DATA_RETURN
- Slot 0x3D: HASH_GUARDED
- Slot 0x3E: OUTPUT_CHECK
- Slots 0x3F-0x7F: Unused (65 slots reserved for future block types)

### Implicit field layouts

`GetImplicitLayout(block_type, ctx)` returns the fixed field layout for a block
type in a given serialization context (0 = WITNESS, 1 = CONDITIONS). When a
micro-header is used and a layout exists, field count bytes and type bytes are
omitted, producing minimal wire encoding.

Example layouts (CONDITIONS context):

| Block type | Layout |
|------------|--------|
| SIG | `[SCHEME(1)]` |
| CSV, CSV_TIME, CLTV, CLTV_TIME | `[NUMERIC(varint)]` |
| CTV | `[HASH256(32)]` |
| TAGGED_HASH | `[HASH256(32), HASH256(32)]` |
| AMOUNT_LOCK | `[NUMERIC(varint), NUMERIC(varint)]` |
| COSIGN | `[HASH256(32)]` |
| TIMELOCKED_SIG | `[SCHEME(1), NUMERIC(varint)]` |
| HTLC | `[HASH256(32), NUMERIC(varint)]` |
| OUTPUT_CHECK | `[NUMERIC(varint), NUMERIC(varint), NUMERIC(varint), HASH256(32)]` |

The `MatchesImplicitLayout` function checks whether a block's actual fields
match the expected implicit layout (correct count and types). If they do not
match, the serializer falls back to explicit encoding with escape headers.

The `VerifyImplicitLayoutPairing` function validates that all block types have
consistent implicit layouts between CONDITIONS and WITNESS contexts.
