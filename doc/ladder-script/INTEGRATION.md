# Ladder Script Integration Guide

How to integrate Ladder Script into a wallet or application. Covers creating outputs,
building witnesses, signing, broadcasting, the descriptor language, coil types, attestation
modes, PQ schemes, and per-rung destinations.

## Overview

Ladder Script uses version 4 transactions (`RUNG_TX`). Each output is 8 bytes on the wire
(value only). A single 32-byte `conditions_root` is shared across all outputs, carrying the
Merkelised Ladder Script Conditions. Flag byte `0x02` signals the RUNG_TX wire format. A
creation proof in the witness is required for 3 or more spendable outputs. At spend time,
the witness reveals one rung's conditions plus a Merkle proof. The node verifies the proof,
merges conditions with the witness, and evaluates the ladder.

## Creating Outputs (MLSC)

### Step 1: Define Conditions

Use the `createrung` RPC or the descriptor language to define your spending conditions.
Conditions are organised as rungs (OR paths), each containing blocks (AND conditions).

**RPC approach** (`createrung`):

```json
{
  "rungs": [
    {
      "blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": "<pubkey_hex>"}]}
      ]
    },
    {
      "blocks": [
        {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": "e8030000"}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": "<recovery_key_hex>"}]}
      ]
    }
  ],
  "coil": {"type": "UNLOCK", "attestation": "INLINE", "scheme": "SCHNORR"}
}
```

The RPC auto-converts PUBKEY fields in conditions to Merkle leaf entries and PREIMAGE fields
to hash commitments. You do not provide HASH256 or PUBKEY_COMMIT directly (the node computes
them).

**Descriptor approach** (`parseladder`):

```
ladder(or(sig(@alice), and(csv(1000), sig(@bob))))
```

Key aliases are passed as a separate map: `{"alice": "<hex>", "bob": "<hex>"}`.

### Step 2: Compute the MLSC Root

The `createrung` RPC returns the conditions root. Programmatically, use `ComputeConditionsRoot()`
from `conditions.h`:

1. For each rung, compute `ComputeRungLeaf(rung, rung_pubkeys)` — serializes the rung blocks
   and appends pubkeys for key-consuming blocks.
2. For each relay, compute `ComputeRelayLeaf(relay, relay_pubkeys)`.
3. Compute `ComputeCoilLeaf(coil)`.
4. Leaf order: `[rung_leaves..., relay_leaves..., coil_leaf]`.
5. `BuildMerkleTree(leaves)` pads to next power of 2 with `MLSC_EMPTY_LEAF` and returns the root.

### Step 3: Create the Output

In a RUNG_TX, each output is 8 bytes (value only). The shared `conditions_root` is
stored once per transaction with MLSC prefix byte `0xDF`. Use `CreateMLSCScript(root)` from
`conditions.h`. To attach a DATA_RETURN payload: `CreateMLSCScript(root, data)` where data
is 1 to 40 bytes.

## Building Witnesses

### Standard Witness

The witness stack has 1, 2, or 3 elements depending on the spending path:

- **Key-path** (1 element): `[signature(64)]` — sign against the tweaked conditions root
  as an x-only pubkey. No conditions revealed. 110 vB (1-in, 1-out).
- **Script-path** (2 elements): `[LadderWitness, MLSCProof]` — reveal one rung's
  conditions with a Merkle proof.
- **Tweaked script-path** (3 elements): `[LadderWitness, MLSCProof, internal_pubkey]` —
  same as script-path but proves the tweak relationship for outputs that also support
  key-path spending.

The `LadderWitness` contains:
- Rungs with blocks and typed fields (PUBKEY, SIGNATURE, NUMERIC, etc.)
- Coil metadata (coil_type, attestation, scheme, address_hash, rung_destinations)
- Relays (shared condition blocks) and per-rung relay_refs

The `MLSCProof` contains:
- `total_rungs`, `total_relays`, `rung_index` (which rung to reveal)
- `revealed_rung` (condition blocks for the revealed rung)
- `revealed_relays` (condition blocks for any relays referenced by relay_refs)
- `proof_hashes` (leaf hashes for unrevealed leaves, in leaf order)
- Optional `revealed_mutation_targets` for cross-rung covenant access

### Diff Witness

When multiple inputs share the same conditions (e.g., batch spends), the second input can
use a diff witness to save space. Set `n_rungs = 0` on the wire, followed by:
- `input_index`: which input's witness to inherit
- `diffs`: field-level patches (rung_index, block_index, field_index, new_field)
- Fresh coil (coil is never inherited)

Diff field types are restricted to PUBKEY, SIGNATURE, PREIMAGE, SCRIPT_BODY, and SCHEME.

## Signing (signladder)

Use the `signladder` RPC to sign a Ladder Script transaction. The RPC automatically
looks up the funding transaction. The RPC:

1. Computes `SignatureHashLadder()` using tagged hash `"LadderSighash"`.
2. Signs with the specified scheme (Schnorr by default).
3. Inserts the signature into the correct field position.

The sighash commits to: epoch (0), hash_type, tx version/locktime, prevouts hash, amounts
hash, sequences hash, outputs hash, spend_type (0), input-specific data, and conditions hash.

### Sighash Types

| Value | Name | Behaviour |
|-------|------|----------|
| 0x00 | SIGHASH_DEFAULT | Same as ALL |
| 0x01 | SIGHASH_ALL | Commit to all outputs |
| 0x02 | SIGHASH_NONE | Do not commit to outputs |
| 0x03 | SIGHASH_SINGLE | Commit to matching output only |
| 0x40 | ANYPREVOUT | Skip prevout commitment (BIP-118 analogue) |
| 0xC0 | ANYPREVOUTANYSCRIPT | Skip prevout and conditions commitment |
| 0x80 | ANYONECANPAY | Combine with above; commit to this input only |

ANYPREVOUT enables LN-Symmetry/eltoo. ANYPREVOUTANYSCRIPT enables rebindable signatures.

### Post-Quantum Signing

Set the coil's `scheme` field to a PQ scheme. Use `generatepqkeypair` to create a keypair
and `pqpubkeycommit` to compute the commitment. Supported schemes:

| Code | Scheme | Signature Size |
|------|--------|---------------|
| 0x01 | SCHNORR | 64-65 bytes |
| 0x02 | ECDSA | 8-72 bytes |
| 0x10 | FALCON512 | ~666 bytes |
| 0x11 | FALCON1024 | ~1280 bytes |
| 0x12 | DILITHIUM3 | ~3293 bytes |
| 0x13 | SPHINCS_SHA | ~49216 bytes |

The `MAX_LADDER_WITNESS_SIZE` of 100,000 bytes accommodates PQ signatures.

## Broadcasting

Use `createtxmlsc` to build a raw v4 transaction (replaces `createrungtx`), `signladder`
to sign it (with funding tx auto-lookup), then `sendrawtransaction` to broadcast. The
mempool policy check (`IsStandardRungTx`) verifies:
- Every input has a witness that deserializes successfully
- The transaction uses valid MLSC format (`0xDF` prefix)

## Descriptor Language

The descriptor language provides a human-readable format for Ladder Script conditions.

### Grammar

```
ladder(or(rung1, rung2, ...))       multiple rungs (OR)
ladder(rung)                        single rung
rung = block | and(block, ...)      single block or AND composition
```

### Block Syntax

All 62 block types are supported in descriptors. Common examples:

| Block | Syntax |
|-------|--------|
| sig | `sig(@alias)` or `sig(@alias, scheme)` |
| multisig | `multisig(M, @pk1, @pk2, ...)` |
| csv / csv_time | `csv(N)` / `csv_time(N)` |
| cltv / cltv_time | `cltv(N)` / `cltv_time(N)` |
| timelocked_sig | `timelocked_sig(@alias, N)` |
| htlc | `htlc(@claim, @refund, hash_hex, csv_N)` |
| ctv | `ctv(hex32)` |
| amount_lock | `amount_lock(min, max)` |
| vault_lock | `vault_lock(@recovery, @hot, delay)` |
| output_check | `output_check(idx, min, max, hex32)` |
| recurse_same | `recurse_same(max_depth)` |
| recurse_count | `recurse_count(N)` |
| cosign | `cosign(hex32)` |
| hash_guarded | `hash_guarded(hex32)` |
| (inverted) | `!block` prefix |

All other blocks follow the pattern `block_name(args...)`. The full list of 44
parseable names matches the block type names in lowercase with underscores.

Scheme names: `schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`.

### RPC Commands

- `parseladder "descriptor" '{"alias": "pubkey_hex", ...}'` — parse descriptor to conditions
- `formatladder <conditions_hex>` — format conditions hex as descriptor string

## Coil Types

The coil determines what happens when a rung is satisfied:

| Type | Code | Behaviour |
|------|------|----------|
| UNLOCK | 0x01 | Standard spend. No destination constraint. |
| UNLOCK_TO | 0x02 | Spend to the address in `address_hash`. The hash is `SHA256(raw_address)`; raw address never goes on-chain. |

Coil conditions (the `conditions` field in RungCoil) are reserved and must be empty
(`MAX_COIL_CONDITION_RUNGS = 0`). Covenant semantics are handled by rung-level block types.

## Attestation Modes

| Mode | Code | Behaviour |
|------|------|----------|
| INLINE | 0x01 | Signatures are inline in the witness. Standard mode. |
| AGGREGATE | 0x02 | Half-aggregated Schnorr: R per input in witness, aggregated s-value at tx level. |

## Per-Rung Destinations (rung_destinations)

The coil's `rung_destinations` field allows different rungs to specify different destination
addresses. Each entry is a `(rung_index, address_hash)` pair. This enables patterns like:

- Rung 0 (hot key): sends to the user's address
- Rung 1 (cold key + timelock): sends to a recovery address

Entries are bounded by `MAX_RUNGS` and must have unique rung indices (duplicates rejected
at deserialization).

## Relays

Relays are shared condition blocks that can be required by multiple rungs. They enable:

- **DRY composition.** Define a condition once, reference it from multiple rungs.
- **Cross-rung AND.** A relay that must be satisfied is effectively an AND across rungs.
- **KEY_REF_SIG.** A relay can hold a pubkey commitment that KEY_REF_SIG blocks reference.

Relays are defined in the `LadderWitness` and committed to the MLSC Merkle tree as relay
leaves. Forward-only indexing prevents cycles (relay N can only reference relays 0..N-1).
Maximum 8 relays (`MAX_RELAYS`), maximum chain depth 4 (`MAX_RELAY_DEPTH`).

Rungs reference relays via `relay_refs` (indices into the relay array). `EvalRelays()`
evaluates relays in index order, caching results. `EvalRung()` checks relay_refs against
cached results before evaluating the rung's own blocks.

## Validation Pipeline

The full validation pipeline for a v4 RUNG_TX:

**Per-transaction (first input only):**

1. `ValidateRungOutputs()`: every output must be MLSC (`0xDF`), max 1 DATA_RETURN, dust threshold.
2. Creation proof validated (required for 3+ spendable outputs).
3. PREIMAGE/SCRIPT_BODY count across all inputs checked against `MAX_PREIMAGE_FIELDS_PER_TX`.

**Per-input:**

4. `VerifyRungTx()` is called. Witness stack size determines spending path (1/2/3 elements).
5. Key-path (1 element): verify Schnorr signature against conditions root as pubkey. Done.
6. Script-path (2-3 elements): deserialise `LadderWitness` (stack[0]) and `MLSCProof` (stack[1]).
7. Extract pubkeys via `ExtractBlockPubkeys()` (merkle_pub_key).
8. Verify Merkle proof against conditions root (or tweak for 3-element witness).
9. `MergeConditionsAndWitness()`: combine conditions from proof with witness fields.
10. `EvalLadder()`: evaluate relays (cached), then the revealed rung (AND/OR logic).

## RPC Command Reference

| Command | Purpose |
|---------|---------|
| `decoderung` | Decode a ladder witness from hex |
| `createrung` | Build conditions and compute MLSC root |
| `validateladder` | Validate a ladder witness structure |
| `createtxmlsc` | Build a raw v4 RUNG_TX transaction (replaces `createrungtx`) |
| `signladder` | Sign a v4 transaction input with funding tx auto-lookup (replaces `signrungtx`) |
| `computectvhash` | Compute BIP-119 CTV template hash |
| `generatepqkeypair` | Generate a PQ keypair |
| `pqpubkeycommit` | Compute PQ pubkey commitment |
| `extractadaptorsecret` | Extract adaptor secret from completed signature |
| `verifyadaptorpresig` | Verify an adaptor pre-signature |
| `parseladder` | Parse descriptor string to conditions |
| `formatladder` | Format conditions as descriptor string |
| `createrungtx` | Build a raw v4 transaction (legacy, superseded by `createtxmlsc`) |
| `signrungtx` | Sign a v4 transaction input (legacy, superseded by `signladder`) |
| `computemutation` | Compute mutated conditions root for recursive covenants |
