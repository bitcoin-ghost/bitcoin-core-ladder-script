# Frequently Asked Questions

---

## What is Ladder Script?

Ladder Script replaces Bitcoin Script with typed function blocks. Instead of writing
opcode sequences, you declare what conditions must be met to spend an output: a signature
check, a timelock, a hash preimage, a covenant — each is a named block with typed fields.

Blocks are grouped into **rungs** (AND — every block must pass) and **ladders** (OR —
first satisfied rung wins). A 2-of-3 multisig vault with a timelocked recovery key is
two rungs: `or(multisig(2, @alice, @bob, @carol), and(csv(26280), sig(@recovery)))`.

The transaction version is 4 (`RUNG_TX`). Each output is 8 bytes on the wire (value
only). A single Merkle root covers all outputs. Full conditions are only revealed at
spend time — the paths you don't use stay private.

---

## How is it different from Bitcoin Script?

| | Bitcoin Script | Ladder Script |
|---|---|---|
| **Model** | Untyped stack machine | Typed function blocks |
| **Evaluation** | Sequential opcode execution | AND within rung, OR across rungs |
| **Data** | Arbitrary byte pushes | 11 typed fields with size constraints |
| **On-chain footprint** | Full script in every output | Merkle root only (8 bytes per output) |
| **Covenants** | OP_CTV proposal only | Native CTV, recursive covenants, vaults, output constraints |
| **State machines** | Not possible | Latches, counters, timers, sequencers, rate limiters |
| **Post-quantum** | Not supported | FALCON-512/1024, Dilithium3, SPHINCS+ |
| **Inscriptions** | Unlimited witness data | 112 bytes per transaction (structurally impossible) |
| **Privacy** | Full script visible | Only the used spending path is revealed |

---

## What are the 62 block types?

10 families covering every spending condition you'd want:

| Family | Blocks | What they do |
|--------|--------|-------------|
| **Signature** | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG | Verify signatures — Schnorr, ECDSA, or post-quantum |
| **Timelock** | CSV, CSV_TIME, CLTV, CLTV_TIME | Relative and absolute time/height locks |
| **Hash** | TAGGED_HASH, HASH_GUARDED | Hash preimage verification |
| **Covenant** | CTV, VAULT_LOCK, AMOUNT_LOCK | Constrain the spending transaction |
| **Recursion** | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY | Self-referencing covenant chains |
| **Anchor** | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN | L2 state commitments and data |
| **PLC** | HYSTERESIS_FEE/VALUE, TIMER_CONTINUOUS/OFF_DELAY, LATCH_SET/RESET, COUNTER_DOWN/PRESET/UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN | Programmable logic — industrial automation primitives for Bitcoin |
| **Compound** | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG, ANCHOR_FEE | Common multi-block patterns collapsed into one block |
| **Governance** | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK | Transaction structure constraints |
| **Legacy** | P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT | Wrapped Bitcoin transaction types with typed fields |

---

## How does evaluation work?

```
For each rung (in order):
  Check relay dependencies (shared condition sets, cached)
  For each block in the rung:
    Evaluate the block
    Apply inversion if flagged
    If not SATISFIED → skip to next rung
  All blocks SATISFIED → this rung wins, input is valid

No rung satisfied → input is invalid
```

Four possible results per block: **SATISFIED** (passed), **UNSATISFIED** (valid but
failed), **ERROR** (malformed — consensus failure), **UNKNOWN_BLOCK_TYPE** (forward
compatibility — treated as unsatisfied, inverted becomes error).

---

## How do the Merkle conditions work?

Each RUNG_TX carries a 32-byte `conditions_root` shared across all outputs. On the wire,
this sits between the inputs and outputs (flag byte `0x02`). Each output is just 8 bytes
(value). On deserialisation, the node inflates each output's scriptPubKey to `0xDF + root`
for compatibility with existing Bitcoin Core code.

When spending, the witness reveals one rung's conditions plus a Merkle proof. The node
verifies the proof against the root, merges conditions with the witness, and evaluates the
ladder. Unrevealed rungs stay hidden behind their leaf hashes.

**Key-path spend** (1-element witness): the conditions root is treated as an x-only public
key. A Schnorr signature against it spends the output with no conditions revealed at all.

**Script-path spend** (2 or 3 element witness): ladder witness + Merkle proof. The
revealed rung is evaluated. If a third element is provided (the internal pubkey), the
node verifies that the conditions root is a tweak of that key — this is the same
relationship as Taproot's output_key = internal_key + H(internal_key || merkle_root) × G,
enabling both key-path and script-path spending from the same output.

Three proof modes: **FULL_LEAVES** (all leaf hashes provided), **MERKLE_PATH** (O(log N)
sibling path — the default), **SHARED** (references a previously verified input from the
same source transaction).

---

## How are inscriptions prevented?

Every byte in a RUNG_TX must belong to a typed field. There is no free-form data
area. The total user-chosen arbitrary data per transaction is 112 bytes:

- 64 bytes from PREIMAGE fields (max 2 per transaction, 32 bytes each)
- 40 bytes from DATA_RETURN (max 1 per transaction)
- 8 bytes from nLockTime + nSequence

The conditions root is protocol-derived (not attacker-chosen). Public keys are folded
into Merkle leaf hashes (`merkle_pub_key`) rather than stored in conditions, eliminating
the PUBKEY_COMMIT writable surface that inscriptions exploit in Taproot.

Blocks without an implicit field layout are rejected if they contain high-bandwidth
data types (HASH256, HASH160, DATA, PUBKEY_COMMIT). Key-consuming blocks cannot be
inverted — so you cannot embed arbitrary data by providing a garbage pubkey and flipping
the result.

---

## What is selective inversion?

Any block on the invertible allowlist can have its result flipped: SATISFIED becomes
UNSATISFIED and vice versa. This enables patterns like "spendable BEFORE a timeout"
(`!csv(144)`) or "NOT in this Merkle set" (`!accumulator(root)`).

Key-consuming blocks (SIG, MULTISIG, all compound signature blocks) are never invertible.
ERROR stays ERROR. UNKNOWN_BLOCK_TYPE inverted becomes ERROR (prevents exploiting
unknown types).

---

## What post-quantum schemes are supported?

| Scheme | Pubkey | Signature | Security |
|--------|--------|-----------|----------|
| FALCON-512 | 897 B | ~690 B | 128-bit PQ |
| FALCON-1024 | 1,793 B | ~1,330 B | 256-bit PQ |
| Dilithium3 | 1,952 B | 3,293 B | 192-bit PQ |
| SPHINCS+-SHA2-256f | 64 B | 49,216 B | 256-bit PQ |

Set the SCHEME field to `0x10`–`0x13` and the same SIG block verifies a post-quantum
signature. Works with SIG, MULTISIG, TIMELOCKED_SIG, CLTV_SIG, TIMELOCKED_MULTISIG,
and KEY_REF_SIG. Requires liboqs at compile time (`HasPQSupport()`).

---

## How do covenants work?

**CTV** (`0x0301`): BIP-119 CheckTemplateVerify. A 32-byte hash commits to the exact
structure of the spending transaction. If the hash matches, SATISFIED. No signatures
needed — the most compact covenant.

**VAULT_LOCK** (`0x0302`): Two-path vault. Recovery key spends immediately (cold sweep).
Hot key requires a CSV delay before funds move. One block replaces what would be a
complex multi-script setup in Bitcoin Script.

**AMOUNT_LOCK** (`0x0303`): Output value must be within a committed range. Prevents
draining more than allowed per transaction.

**Recursive covenants** (RECURSE_SAME, RECURSE_MODIFIED, RECURSE_COUNT, RECURSE_SPLIT,
RECURSE_UNTIL, RECURSE_DECAY): The spending transaction's output must carry specific MLSC
conditions, creating covenant chains. RECURSE_COUNT decrements a counter each spend.
RECURSE_MODIFIED allows specific field mutations. RECURSE_SPLIT fans one input into
multiple covenant outputs. All have termination conditions — no infinite loops.

---

## What sighash types are supported?

| Hash type | Value | Effect |
|-----------|-------|--------|
| SIGHASH_DEFAULT / ALL | 0x00 / 0x01 | Commits to all inputs and outputs |
| SIGHASH_NONE | 0x02 | Commits to inputs only |
| SIGHASH_SINGLE | 0x03 | Commits to inputs + matching output |
| ANYONECANPAY | 0x81–0x83 | Commits to signing input only |
| ANYPREVOUT | 0x40–0x43 | Skips prevout — enables LN-Symmetry/eltoo |
| ANYPREVOUTANYSCRIPT | 0xC0–0xC3 | Skips prevout + conditions — rebindable signatures |

The sighash uses `TaggedHash("LadderSighash")` and commits to epoch, version, locktime,
prevouts, amounts, sequences, outputs, spend type, input data, and conditions hash
(selectively skipped by the flags above).

---

## What is a relay?

A **relay** is a reusable set of blocks that multiple rungs can reference. If 4 rungs
all require Alice's signature, put the SIG block in a relay and reference it from each
rung. Alice signs once; the relay evaluates once and the result is cached.

Relays can reference other relays (forward-only, max chain depth 4). They participate in
the Merkle tree as relay leaves. `KEY_REF_SIG` lets a rung verify a signature against a
pubkey stored in a relay, separating key storage from key usage.

---

## What is the descriptor notation?

Human-readable text for Ladder Script conditions:

```
ladder(sig(@alice))
ladder(or(multisig(2, @alice, @bob, @carol), timelocked_sig(@recovery, 26280)))
ladder(and(sig(@owner), !csv(144), amount_lock(0, 100000)))
```

`@aliases` map to pubkey hex via a key dictionary. `!` prefix inverts a block.
`parseladder` converts a descriptor to conditions hex + MLSC root.
`formatladder` converts conditions hex back to a descriptor string.

---

## How does COSIGN work?

COSIGN (`0x0681`) is a cross-input constraint — it requires that another input in the
same transaction is spending a UTXO whose scriptPubKey hash matches a committed value.
This creates "paired UTXOs" that can only be spent together: UTXO A carries
`COSIGN(SHA256(scriptPubKey_B))` and UTXO B carries `COSIGN(SHA256(scriptPubKey_A))`.

---

## How does the soft fork activate?

Ladder Script uses the `0xDF` scriptPubKey prefix, which falls in Bitcoin's "OP_UNKNOWN"
range. Pre-activation nodes treat these outputs as anyone-can-spend (standard SegWit-style
upgrade mechanism). Post-activation, the ladder evaluator enforces the conditions.

The integration patch is ~412 lines across 24 existing Bitcoin Core files. The full
Ladder Script library is 14,771 lines in 22 new files under `src/rung/` — completely
self-contained with no modifications to existing evaluation, signing, or consensus logic.
