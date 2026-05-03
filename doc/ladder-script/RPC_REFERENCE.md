# RPC reference

The Ladder Script library adds **20 RPCs** to Bitcoin Core. They cluster
into six groups: descriptor-based authoring (the recommended modern path),
raw conditions construction, inspection, templates and commitments,
post-quantum helpers, and the QABIO suite.

Every RPC lives in `src/rung/rpc.cpp` and is registered in Core via
`RegisterRungRPCCommands(CRPCTable&)` (declared in `src/rpc/register.h`,
implemented at the bottom of `rpc.cpp`).

`bitcoin-cli` argument-type entries for the non-string positional args are
registered in `src/rpc/client.cpp` — without them the CLI forwards numeric/
array/object args as JSON strings and the server rejects them.

---

## Quick reference

| RPC                       | Purpose                                                                       |
|---------------------------|-------------------------------------------------------------------------------|
| `parseladder`             | Descriptor string → conditions hex + MLSC root                                |
| `formatladder`            | Serialised conditions → descriptor string                                     |
| `signladder`              | One-call sign of a v4 RUNG_TX using descriptor notation                       |
| `createrungtx`            | Build an unsigned v4 RUNG_TX with a shared condition tree                     |
| `signrungtx`              | Sign a v4 RUNG_TX's inputs (raw path)                                         |
| `createrung`              | Build a single rung from JSON spec                                            |
| `serialiseconditions`     | Serialise a LadderWitness in CONDITIONS context (P2SH/P2WSH/P2TR_SCRIPT inner)|
| `decoderung`              | Decode a hex witness into a typed structure                                   |
| `validateladder`          | Validate every witness on a raw v4 RUNG_TX                                    |
| `computemutation`         | Compute mutated conditions for `RECURSE_MODIFIED` / `RECURSE_DECAY`           |
| `computectvhash`          | BIP-119 CTV template hash for a v4 RUNG_TX                                    |
| `pqpubkeycommit`          | SHA256(pubkey) commitment for `PQ_BATCH`                                      |
| `generatepqkeypair`       | Generate a FALCON-512 / FALCON-1024 / Dilithium3 / SPHINCS+ keypair           |
| `extractadaptorsecret`    | Extract `t = s_adapted - s_pre` from an adapted signature pair                |
| `verifyadaptorpresig`     | Verify an adaptor pre-signature                                               |
| `qabi_buildblock`         | Build a `qabi_block` from participants and outputs                            |
| `qabi_blockinfo`          | Decode `qabi_block` bytes into JSON                                           |
| `qabi_authchain`          | Generate the auth hash chain for one QABIO participant                        |
| `qabi_signqabo`           | Coordinator-side FALCON-512 sign over `SIGHASH_QABO`                          |
| `qabi_sighash`            | Compute `SIGHASH_QABO` for a QABIO tx                                         |

---

## 1. Descriptor-based authoring

These are the recommended modern path. The descriptor language abstracts
away wire formats, witness construction, and Merkle proof building.

### `parseladder`

Parse a Ladder Script descriptor into wire-format conditions hex and the
MLSC root.

```
parseladder "descriptor" '{"key_alias":"hex_pubkey", ...}'
```

| Arg          | Type   | Description                                              |
|--------------|--------|----------------------------------------------------------|
| `descriptor` | string | The Ladder Script descriptor string                      |
| `keys`       | object | Optional alias→pubkey map (for `@alice` style references)|

**Returns:** `{ "conditions_hex": "...", "mlsc_root": "...", "n_rungs": <int> }`.

**Example:**

```bash
bitcoin-cli parseladder "ladder(or(sig(@alice), csv(144)))" \
  '{"alice":"02aabb...cc"}'
```

### `formatladder`

Inverse of `parseladder` — turn serialised conditions back into a
descriptor string. Useful for debugging and for round-tripping conditions
extracted from a witness.

```
formatladder "conditions_hex"
```

### `signladder`

Sign an unsigned v4 RUNG_TX using descriptor notation. This is the
one-shot RPC: descriptor in, signed tx out. Internally it computes the
sighash, builds the Merkle proof, runs the per-block signer, and packs
the witness stack. Use this unless you need to control the witness
construction yourself.

```
signladder "hex" "descriptor" '{"alias":"wif", ...}' spent_outputs
           [input_index] [rung_index] [keypath_key] [keypath_merkle_root] [shared_source]
```

| Arg                    | Type    | Description                                                                                                              |
|------------------------|---------|--------------------------------------------------------------------------------------------------------------------------|
| `hex`                  | string  | Unsigned v4 RUNG_TX hex (from `createrungtx`)                                                                            |
| `descriptor`           | string  | The spending-side descriptor                                                                                             |
| `keys`                 | object  | Alias→WIF map (private keys)                                                                                             |
| `spent_outputs`        | array   | Outputs being spent (`[{"amount":..., "scriptPubKey":...}, ...]`) — required for sighash computation                     |
| `input_index`          | integer | Optional, default 0                                                                                                      |
| `rung_index`           | integer | Optional, default 0 — target rung for multi-rung conditions                                                              |
| `keypath_key`          | string  | Optional WIF for key-path spending. When provided, produces a 1-element witness                                          |
| `keypath_merkle_root`  | string  | Optional 32-byte Merkle root hex for key-path with a script tree. Omit for key-path-only                                 |
| `shared_source`        | integer | Optional input index of an already-signed input from the same source tx (SHARED proof mode)                              |

**Returns:** `{ "hex": "...", "complete": <bool> }`.

### `createrungtx`

Build an unsigned v4 RUNG_TX with a single shared `conditions_root` for
every output. The headline construction RPC: every output shares one
Merkelised condition tree, and each rung's coil specifies which output
it governs (`output_index`). The wire format used is TX_MLSC (8-byte
value-only outputs, conditions_root once per tx).

```
createrungtx inputs outputs rungs [locktime] [internal_pubkey] [qabi_block] [relays]
```

| Arg               | Type    | Description                                                                                                                  |
|-------------------|---------|------------------------------------------------------------------------------------------------------------------------------|
| `inputs`          | array   | UTXOs to spend (`[{"txid":..., "vout":..., "sequence":...}, ...]`)                                                           |
| `outputs`         | array   | Output amounts (BTC) — value-only on the wire (TX_MLSC format)                                                               |
| `rungs`           | array   | Per-rung spec (each rung carries `output_index`, `blocks`, optional `coil`)                                                  |
| `locktime`        | integer | Optional, default 0                                                                                                          |
| `internal_pubkey` | string  | Optional 32-byte x-only internal pubkey for key-path spending. When provided, the conditions_root is tweaked                 |
| `qabi_block`      | string  | Optional serialised QABIBlock bytes (hex). Present iff this is a QABIO batch tx — use `qabi_buildblock` to construct         |
| `relays`          | array   | Optional shared relay blocks (v0.7) folded into the conditions_root tree at positions `[N..N+M-1]`                           |

**Returns:** the unsigned transaction hex.

### `signrungtx`

Sign a v4 RUNG_TX's inputs using a per-input signer spec. This is the
raw path used internally by `signladder` and exposed for callers that
need to drive witness construction directly (e.g. mixed-input txs where
one input uses the wallet and another uses a custom keystore).

```
signrungtx "hex" signers spent_outputs
```

| Arg              | Type   | Description                                                                                                                                                         |
|------------------|--------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hex`            | string | Unsigned v4 RUNG_TX hex                                                                                                                                             |
| `signers`        | array  | Per-input objects. Legacy SIG-only: `{"input":N, "privkey":"WIF"}`. Full: `{"input":N, "rung":N, "blocks":[{type,privkey,...}], "conditions":..., "relay_blocks":..., "diff_witness":...}` |
| `spent_outputs`  | array  | Spent outputs (`[{"amount":..., "scriptPubKey":...}, ...]`) — required for sighash computation                                                                      |

**Returns:** `{ "hex": "...", "complete": <bool> }`.

---

## 2. Raw conditions construction

Lower-level RPCs for callers that want to assemble conditions or
transactions by hand. Most users should prefer the descriptor-based path.

### `createrung`

Build a single rung from a JSON specification (block types + fields +
coil). Returns the serialised LadderWitness hex.

### `serialiseconditions`

Serialise a LadderWitness in CONDITIONS context (PUBKEYs fold into
`merkle_pub_key`, no per-rung output_index baggage). Returns bytes
suitable as a P2SH / P2WSH / P2TR_SCRIPT inner-script preimage when
embedding ladder conditions inside a non-MLSC scriptPubKey.

---

## 3. Inspection and validation

### `decoderung`

Decode a hex witness into a typed JSON structure: rungs, blocks,
fields, coil. The inverse of `createrung` for inspection.

### `validateladder`

Take a raw v4 RUNG_TX and run every input's witness through the
ladder evaluator. Returns per-input `{ ok: bool, error: string }`.
Useful for CI testing and offline tx review without needing to broadcast.

### `computemutation`

Compute the expected output conditions after applying a
`RECURSE_MODIFIED` or `RECURSE_DECAY` mutation. Use this to predict
the shape of a recursive covenant's child UTXO so you can build the
spending tx with the correct output `conditions_root`.

```
computemutation "input_descriptor" '{"alias":"hex"}' block_idx param_idx delta
```

---

## 4. Templates and commitments

### `computectvhash`

Compute the BIP-119 `OP_CHECKTEMPLATEVERIFY` template hash for a v4
RUNG_TX. The hash commits to version, locktime, inputs, outputs, and
input index. Use this when constructing a CTV block that constrains
how a created output can later be spent.

### `pqpubkeycommit`

Compute `SHA256(canonical_pq_pubkey_bytes)` — the commitment used by
`PQ_BATCH` blocks. Informational; `createrungtx` and `createrungtx`
compute commitments automatically when the PQ_BATCH block carries a
PUBKEY field. Use this RPC when you want to inspect or precompute the
commitment for a given key.

---

## 5. Post-quantum helpers

### `generatepqkeypair`

Generate a post-quantum keypair. Requires `liboqs` support compiled
into the build.

```
generatepqkeypair "scheme"
```

Schemes (case-sensitive, uppercase): `FALCON512`, `FALCON1024`, `DILITHIUM3`, `SPHINCS_SHA`.

**Returns:** `{ "scheme": "...", "pubkey": "...", "privkey": "..." }`.

### `extractadaptorsecret`

Given a Schnorr pre-signature `s_pre` and the adapted signature
`s_adapted`, recover the adaptor secret `t = s_adapted - s_pre`
(scalar subtraction mod n). Used in PTLC settlement.

### `verifyadaptorpresig`

Verify a Schnorr adaptor pre-signature: checks that
`s'·G == R + e·P` where `e = H(R + T || P || m)`. Returns true / false.

---

## 6. QABIO suite

QABIO is the multi-party batch ceremony — a coordinator and N
participants pool inputs into a single transaction with one FALCON-512
aggregate signature. The five RPCs cover the full ceremony.

See [`QABIO.md`](QABIO.md) for the protocol overview.

### `qabi_buildblock`

Build a `qabi_block` from a list of participants and outputs. The
coordinator runs this once per ceremony round. Produces the bytes that
the ceremony commits to via `committed_root` in every participant's
`QABI_SPEND` block.

```
qabi_buildblock coordinator_pubkey prime_expiry_height [batch_id]
                entries outputs_conditions_root output_values
```

| Arg                       | Type    | Description                                                                                                                       |
|---------------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------|
| `coordinator_pubkey`      | string  | Coordinator's FALCON-512 pubkey (897 bytes hex)                                                                                   |
| `prime_expiry_height`     | integer | Block height after which the priming expires                                                                                      |
| `batch_id`                | string  | Optional placeholder — ignored by the parser (v0.13 enforces canonical SHA256 derivation). Returned in the result     |
| `entries`                 | array   | Per-participant entries `[{participant_id, contribution, destination_index}, ...]`                                                |
| `outputs_conditions_root` | string  | 32-byte conditions root that the spend tx must use as `tx.conditions_root`. Pins every destination scriptPubKey structurally     |
| `output_values`           | array   | Per-output amounts (BTC). The destination scriptPubKey is implicit (`0xDF + outputs_conditions_root` for every v4 MLSC output)    |

**Returns:** `{ "qabi_block": "<hex>", "qabi_root": "<hex>", "batch_id": "<hex>", "size": <bytes> }`.

### `qabi_blockinfo`

Decode serialised `qabi_block` bytes into JSON for inspection. Useful
for debugging coordination rounds and verifying that a participant
received the same block bytes as everyone else.

### `qabi_authchain`

Generate the auth hash chain for one participant: returns the
`auth_tip = H^N(seed)` and the preimage at any specified depth. Used
to construct a QABI-enabled UTXO and to reveal preimages at priming
and spend time.

```
qabi_authchain "auth_seed" chain_length [depth]
```

`depth` is optional. When omitted, only `auth_tip` is returned. When provided (`0 = tip`, `N = seed`), the matching preimage is also returned: `{ "auth_tip": "<hex>", "preimage": "<hex>" }`.

### `qabi_signqabo`

Coordinator-side signing operation. Takes the unsigned QABIO tx
(`hex_tx`) and the coordinator's FALCON-512 private key (`privkey`),
computes `SIGHASH_QABO`, and produces the FALCON-512 signature that
goes into the tx-level `aggregated_sig` field.

**Returns:** `{ "hex": "<signed tx>", "sighash": "<hex>", "sig_size": <1..666> }`.

Since v0.14 the signature is written without padding —
`sig_size` is the actual FALCON sig length (consensus accepts
`1..QABI_AGGREGATED_SIG_MAX = 666`). Pre-v0.14 behaviour padded to a
variable-length up to 666 B and was changed to close a coordinator-side embedding
channel.

### `qabi_sighash`

Compute `SIGHASH_QABO` for a QABIO tx without signing. Useful for
participants who want to verify what the coordinator will sign before
the ceremony commits. The sighash covers `tx.version`, `vin`, `vout`,
`conditions_root`, `qabi_block`, and the standard BIP 341-style
midstate hashes.

---

## How RPCs are wired into Core

`src/rung/rpc.cpp` declares each RPC as `static RPCHelpMan name()` and
appends it to a `static const CRPCCommand commands[]` array at the end
of the file. `RegisterRungRPCCommands(CRPCTable& t)` walks the array
and registers each command.

The Core side adds one line in `src/rpc/register.h`:

```cpp
RegisterRungRPCCommands(t);   // alongside RegisterBlockchainRPCCommands etc.
```

…plus the `bitcoin-cli` arg-type entries in `src/rpc/client.cpp` that
tell the CLI which positional args are non-string. See
[`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md#9-srcrpcclientcpp-16) for the
full list.
