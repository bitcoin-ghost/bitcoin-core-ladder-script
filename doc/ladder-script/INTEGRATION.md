# Ladder Script Integration Guide

How to integrate Ladder Script into a wallet or application. Covers creating outputs,
building witnesses, signing, broadcasting, the descriptor language, coil types, attestation
modes, PQ schemes, and per-rung destinations.

## Overview

Ladder Script uses version 4 transactions (`RUNG_TX`). Each output is 8 bytes on the wire
(value only) — TX_MLSC encoding. A single 32-byte `conditions_root` is shared across all
outputs of the transaction, carrying the Merkelised Ladder Script Conditions. Flag byte
`0x02` signals the RUNG_TX wire format. The 32-byte root is recovered at spend time from
a synthetic UTXO entry at `(txid, MLSC_ROOT_VOUT = 0xFFFFFFFF)` — see
[`MERKLE-UTXO-SPEC.md`](MERKLE-UTXO-SPEC.md) for the full mechanism. At spend time the
witness reveals one rung's conditions plus a Merkle proof; the node verifies the proof,
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

The `createrung` RPC returns the conditions root. **Programmatically,
call `ComputeTxMLSCRoot()` from `conditions.cpp` &mdash; this is the
live consensus path.** Do *not* call the legacy `ComputeRungLeaf` /
`ComputeCoilLeaf` / `ComputeRelayLeaf` helpers in the same file:
they are test-only and produce different leaf hashes than consensus.

`ComputeTxMLSCRoot` does the following internally:

1. For each rung: build a `CreationProofRung` via `BuildCPRung(rung,
   rung_pubkeys, coil)` and compute `leaves[i] =
   ComputeTxMLSCLeaf(cp_rung)`. The leaf hash is
   `TaggedHash("LadderLeaf/v1", structural_template ||
   value_commitment)` &mdash; the structural template encodes block
   types, inversion flags, **and the four coil bytes** (`coil_type`,
   `attestation`, `scheme`, `output_index`); the value commitment
   binds output value plus key-consuming pubkeys folded via
   `merkle_pub_key`.
2. For each relay: append `ComputeRelayLeaf(relay, relay_pubkeys)`
   to the same leaf array.
3. Leaf order: `[rung_leaves..., relay_leaves...]`. There is **no
   separate coil leaf** in the consensus path &mdash; coil bytes live
   inside each rung leaf's structural template (this matters for
   Merkle proof construction).
4. `BuildMerkleTree(leaves)` pads to the next power of 2 with
   `MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf/v1", "")`, hashes
   pairs with `TaggedHash("LadderInternal/v1", min(a,b) || max(a,b))`,
   and returns the root.

### Step 3: Create the Output

In a RUNG_TX, each output is 8 bytes (value only). The shared `conditions_root` is
stored once per transaction with MLSC prefix byte `0xDF`. Use `CreateMLSCScript(root)` from
`conditions.h`. To attach a DATA_RETURN payload: `CreateMLSCScript(root, data)` where data
is 1 to 40 bytes.

## Building Witnesses

### Standard Witness

The witness stack has 1, 2, or 3 elements depending on the spending path:

- **Key-path** (1 element): `[signature(64)]` — sign against the tweaked conditions root
  as an x-only pubkey. No conditions revealed. **109 vB** (1-in, 1-out — 1 vB smaller
  than P2WPKH, 2 vB smaller than P2TR key-path).
- **Script-path** (2 elements): `[LadderWitness, MLSCProof]` — reveal one rung's
  conditions with a Merkle proof.
- **Tweaked script-path** (3 elements): `[LadderWitness, MLSCProof, internal_pubkey]` —
  same as script-path but proves the tweak relationship for outputs that also support
  key-path spending.

The `LadderWitness` contains:
- Rungs with blocks and typed fields (PUBKEY, SIGNATURE, NUMERIC, etc.)
- Relays (shared condition blocks) and per-rung relay_refs
- Coil metadata — fixed 4 bytes: `coil_type + attestation + scheme + output_index`
  (v0.8 dropped the unbound `address_hash` and `rung_destinations` fields,
  E-009/E-010)

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

1. Computes `SignatureHashLadder()` using tagged hash `"LadderSighash/v1"` (script-path)
   or `"LadderKeyPathSighash/v1"` (key-path).
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
| 0x80 | ANYONECANPAY | Combine with above; commit to this input only |

Valid hash-type bytes: `{0x00-0x03, 0x81-0x83}`. The BIP-118
ANYPREVOUT family (`0x40-0x43`) and ANYPREVOUTANYSCRIPT family
(`0xC0-0xC3`) are unconditionally rejected by `SignatureHashLadder`.
LN-Symmetry / eltoo workflows that require these flags need a future
opt-in mechanism (a dedicated block type or pubkey-prefix scheme)
before these flags become available.

### Post-Quantum Signing

Set the coil's `scheme` field to a PQ scheme. Use `generatepqkeypair` to create a keypair
and `pqpubkeycommit` to compute the commitment. Supported schemes:

| Code | Scheme | Pubkey Size | Signature Size |
|------|--------|-------------|---------------|
| 0x01 | SCHNORR | 32 bytes | 64-65 bytes |
| 0x02 | ECDSA | 33 bytes | 8-72 bytes |
| 0x10 | FALCON512 | 897 bytes | up to 666 bytes (variable; OQS validates encoded length) |
| 0x11 | FALCON1024 | 1,793 bytes | up to ~1,330 bytes (variable) |
| 0x12 | DILITHIUM3 | 1,952 bytes | 3,293 bytes |
| 0x13 | SPHINCS_SHA | 64 bytes | 49,216 bytes |

Pubkey sizes are canonical per scheme; FALCON sigs are variable
(post-v0.14 &mdash; pre-v0.14 wire-required variable up to 666 B
which opened a 0-66 B/tx silent-padding embedding channel).
`MAX_LADDER_WITNESS_SIZE = 100,000` bytes accommodates the largest
PQ signature (SPHINCS+).

For batched PQ spends, see the **PQ_BATCH** primitive (one anchor
input reveals pubkey + sig once; other inputs gated by the same
`SHA256(falcon_pubkey)` short-circuit via a tx-local cache).
**~17.8 vB per input at N=100** (anchor ~392 vB, non-anchors ~14 vB
each), about 22&times; cheaper than per-input FALCON-512. See
[`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md) and [`SIZING.md`](SIZING.md).

## Broadcasting

Use `createrungtx` to build a raw v4 transaction, `signladder`
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

All 65 block types are supported in descriptors. Common examples:

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

All other blocks follow the pattern `block_name(args...)` — block names are the
type names in lowercase with underscores (e.g. `RECURSE_MODIFIED` →
`recurse_modified(...)`, `PQ_BATCH` → `pq_batch(hex32)`).

Scheme names: `schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`.

### RPC Commands

- `parseladder "descriptor" '{"alias": "pubkey_hex", ...}'` — parse descriptor to conditions
- `formatladder <conditions_hex>` — format conditions hex as descriptor string

## Coil Types (v0.8)

The coil determines what happens when a rung is satisfied:

| Type | Code | Behaviour |
|------|------|----------|
| UNLOCK | 0x01 | Standard spend. The spender must satisfy at least one rung. |
| UNLOCK_TO | 0x02 | Reserved for a future wire format that binds output structure on-chain (e.g. via a CTV-style template hash). |

The 4-byte coil tail (`coil_type + attestation + scheme + output_index`) is
the entire on-chain coil — covenant semantics are handled by rung-level block
types (CTV, RECURSE_*, VAULT_LOCK, AMOUNT_LOCK, OUTPUT_CHECK).

## Attestation Modes

| Mode | Code | Behaviour |
|------|------|----------|
| INLINE | 0x01 | Signatures sit inline in the witness. The only defined mode. |

Earlier draft modes (`AGGREGATE`, `DEFERRED`) were removed from the enum entirely; values
other than `0x01` reject at deserialisation. For tx-level FALCON-512 aggregation see
QABIO ([`QABIO.md`](QABIO.md)) — the coordinator's signature is carried in the tx-level
`aggregated_sig` field, not via this attestation byte.

## Per-Rung Destinations (off-chain in v0.8)

`coil.rung_destinations` was removed in v0.8 (E-010 — it was an unbound spender
data channel). Wallets that need per-rung destination tracking must keep that
metadata locally. If on-chain enforcement is required, use rung-level
`OUTPUT_CHECK` blocks (which bind specific outputs by index, value range, and
script hash) or `CTV` covenants.

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

**Per-transaction (`CheckRungTxLevel`, runs once per tx):**

1. `ValidateRungOutputs()`: every output must be MLSC (`0xDF`), max 1 DATA_RETURN,
   non-DATA_RETURN outputs ≥ `MIN_RUNG_OUTPUT_VALUE` (546 sats).
2. PREIMAGE/SCRIPT_BODY count across all MLSC-spending inputs ≤ `MAX_PREIMAGE_FIELDS_PER_TX` (2). v0.10 excluded bootstrap inputs from the cap — only MLSC-bearing witnesses count.
3. Cross-input invariants when applicable: PQ_BATCH cache consistency, QABIO output-set
   binding.

**Per-input:**

4. `VerifyRungTx()` is called. Witness stack size determines spending path (1/2/3 elements).
5. Key-path (1 element): verify Schnorr signature against conditions root as pubkey. Done.
6. Script-path (2-3 elements): deserialise `LadderWitness` (stack[0]) and `MLSCProof` (stack[1]).
7. Extract pubkeys via `ExtractBlockPubkeys()` (merkle_pub_key).
8. Verify Merkle proof against conditions root (or tweak for 3-element witness).
9. `MergeConditionsAndWitness()`: combine conditions from proof with witness fields.
10. `EvalLadder()`: evaluate relays (cached), then the revealed rung (AND/OR logic).

## RPC Command Reference

The library adds **21 RPCs** across six groups (descriptor authoring, raw construction,
inspection/validation, templates/commitments, PQ helpers, QABIO). Headline commands:

| Command | Purpose |
|---------|---------|
| `parseladder` / `formatladder` | Descriptor ↔ conditions hex |
| `signladder` | One-call sign of a v4 RUNG_TX using descriptor notation |
| `createrungtx` | Build an unsigned v4 RUNG_TX with shared conditions tree |
| `signrungtx` | Sign a v4 RUNG_TX (raw path, used internally by `signladder`) |
| `createrung` / `decoderung` / `validateladder` / `serialiseconditions` | Witness/conditions construction and inspection |
| `computectvhash` / `computemutation` / `computesighash` | Templates, recursive-covenant target hashes, and sighash preview |
| `generatepqkeypair` / `pqpubkeycommit` | PQ key helpers |
| `extractadaptorsecret` / `verifyadaptorpresig` | Adaptor signature primitives (PTLC) |
| `qabi_buildblock` / `qabi_blockinfo` / `qabi_authchain` / `qabi_signqabo` / `qabi_sighash` | QABIO ceremony |

Full per-RPC signature, args, returns, and examples in
[`RPC_REFERENCE.md`](RPC_REFERENCE.md).
