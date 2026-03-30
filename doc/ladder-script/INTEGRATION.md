# Ladder Script Integration Guide

How to integrate Ladder Script into a wallet or application. Covers creating outputs,
building witnesses, signing, broadcasting, the descriptor language, coil types, attestation
modes, PQ schemes, and per-rung destinations.

## Overview

Ladder Script transactions use `RUNG_TX_VERSION = 4`. Each output is 8 bytes (value only)
and the transaction carries one shared `conditions_root` with MLSC prefix byte `0xDF`. A
creation proof in the witness is validated at block acceptance. The RUNG_TX wire format
uses flag byte `0x02`; TX_MLSC defines the conditions commitment (one shared root per
transaction). The spending
witness carries the full conditions for one rung plus a Merkle proof for the unrevealed
rungs. The node verifies the Merkle proof, evaluates the revealed rung, and (if signatures
are batched) verifies all Schnorr signatures in a single batch.

## Creating Outputs (MLSC)

### Step 1: Define Conditions

Use the `createrung` RPC or the descriptor language to define your spending conditions.
Conditions are organized as rungs (OR paths), each containing blocks (AND conditions).

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

The witness stack has two elements:

- `stack[0]`: Serialized `LadderWitness` (the spending witness with rungs, blocks, fields,
  and coil).
- `stack[1]`: Serialized `MLSCProof` (Merkle proof revealing one rung).

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

| Value | Name | Behavior |
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

| Block | Syntax |
|-------|--------|
| sig | `sig(@alias)` or `sig(@alias, scheme)` |
| csv | `csv(N)` |
| csv_time | `csv_time(N)` |
| cltv | `cltv(N)` |
| cltv_time | `cltv_time(N)` |
| multisig | `multisig(M, @pk1, @pk2, ...)` |
| hash_guarded | `hash_guarded(hex32)` |
| ctv | `ctv(hex32)` |
| amount_lock | `amount_lock(min, max)` |
| timelocked_sig | `timelocked_sig(@alias, N)` |
| output_check | `output_check(idx, min, max, hex32)` |
| (inverted) | `!block` prefix |

Scheme names: `schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`.

### RPC Commands

- `parseladder "descriptor" '{"alias": "pubkey_hex", ...}'` — parse descriptor to conditions
- `formatladder <conditions_json>` — format conditions as descriptor string

## Coil Types

The coil determines what happens when a rung is satisfied:

| Type | Code | Behavior |
|------|------|----------|
| UNLOCK | 0x01 | Standard spend. No destination constraint. |
| UNLOCK_TO | 0x02 | Spend to the address in `address_hash`. The hash is `SHA256(raw_address)`; raw address never goes on-chain. |

Coil conditions (the `conditions` field in RungCoil) are reserved and must be empty
(`MAX_COIL_CONDITION_RUNGS = 0`). Covenant semantics are handled by rung-level block types.

## Attestation Modes

| Mode | Code | Behavior |
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

1. `VerifyRungTx()` is called for each input.
2. Witness `stack[0]` is deserialized via `DeserializeLadderWitness()`.
3. Witness `stack[1]` is deserialized via `DeserializeMLSCProof()`.
4. `VerifyMLSCProof()` reconstructs the Merkle tree and verifies the root matches the UTXO.
5. Conditions are assembled from the proof's revealed rung.
6. `EvalLadder()` evaluates relays, then the revealed rung.
7. If batch verification is active, `BatchVerifier::Verify()` checks all Schnorr signatures.
8. `ValidateRungOutputs()` verifies every output is valid MLSC.

## RPC Command Reference

| Command | Purpose |
|---------|---------|
| `decoderung` | Decode a ladder witness from hex |
| `createrung` | Build conditions and compute MLSC root |
| `validateladder` | Validate a ladder witness structure |
| `createtxmlsc` | Build a raw v4 TX_MLSC transaction (replaces `createrungtx`) |
| `signladder` | Sign a v4 transaction input with funding tx auto-lookup (replaces `signrungtx`) |
| `computectvhash` | Compute BIP-119 CTV template hash |
| `generatepqkeypair` | Generate a PQ keypair |
| `pqpubkeycommit` | Compute PQ pubkey commitment |
| `extractadaptorsecret` | Extract adaptor secret from completed signature |
| `verifyadaptorpresig` | Verify an adaptor pre-signature |
| `parseladder` | Parse descriptor string to conditions |
| `formatladder` | Format conditions as descriptor string |
| `decodetxmlsc` | Decode a TX_MLSC transaction |
| `validaterungtx` | Validate a rung transaction |
| `getladdertxinfo` | Get ladder transaction info |
