# QABIO Integrator Guide

**Audience:** wallet developers, coordinator services, engine integrators building on Ladder Script.

**Scope:** the full RPC-driven flow for creating QABI-enabled UTXOs, priming them, assembling a batch, and signing it with a single FALCON-512 coordinator signature.

**Related docs:**
- `project_qabi.md` — design spec (693 lines)
- `bip-qabio.md` — BIP-format adaptation for integration into the main Ladder Script BIP

---

## 1. What QABIO gives you

N independent parties batch their UTXOs into ONE transaction authorised by ONE post-quantum FALCON-512 signature from a designated coordinator. No per-input PQ signatures, no commitment anchors, no pre-registration.

### Scale characteristics

Measured on the QABIO branch's scale tests:

| Participants | QABIBlock size | Total tx-level overhead |
|---|---|---|
| 10 | 1.7 KB | ~2.3 KB |
| 100 | 8.1 KB | ~8.8 KB |
| 500 | 37 KB | ~38 KB |
| 1000 | 74 KB | ~75 KB |
| 3238 | 240 KB | at hard cap |

All batches use **one** 666-byte FALCON-512 signature regardless of participant count. For comparison, 1000 participants with per-input FALCON sigs would require 666 KB of signature bytes — QABIO reduces that to 666 B (~1000× compression).

### Security properties

- **Compositional atomicity**: no strict subset of a primed batch can execute. Any change to participants/outputs/expiry/coordinator forces a full re-prime cycle.
- **Cryptographic ownership**: each participant reveals a hash-chain preimage at spend time, proving they authorised this specific batch. An attacker cannot forge a preimage without the participant's `auth_seed`.
- **Compact signature**: the coordinator's FALCON signature covers a sighash that includes `tx.qabi_block` — the block is bound to this exact signature.
- **Replace-By-Depth mempool policy**: deeper preimages can only be produced by the UTXO owner (one-way hash), so the owner has cryptographic last word over mempool snipers.
- **Full output-set match**: `tx.vout` must bit-exactly equal `block.outputs`. Coordinators cannot siphon extra outputs — any fee they want to charge must be an explicit `block.outputs` entry visible to participants.

---

## 2. The five QABI JSON-RPC commands

All registered under the "rung" category.

### `qabi_buildblock` — assemble a QABIBlock

```
qabi_buildblock <coordinator_pubkey_hex> <prime_expiry_height>
                <batch_id_hex> <entries_array> <outputs_array>
```

**Returns:**
```json
{
  "qabi_block": "<hex serialised bytes>",
  "qabi_root":  "<hex SHA256>",
  "size":       <bytes>
}
```

**Inputs:**
- `coordinator_pubkey_hex` — FALCON-512 public key (exactly 897 bytes hex)
- `prime_expiry_height` — max block height at which the batch can execute
- `batch_id_hex` — 32-byte unique batch identifier
- `entries` — array of `{participant_id, contribution, destination_index}`
  - `participant_id` = SHA256(participant's Rung 0 FALCON pubkey), 32 bytes hex
  - `contribution` = satoshis this participant contributes
  - `destination_index` = index into outputs[] for this participant's destination
- `outputs` — array of `{amount, script_pubkey}` — MUST match `tx.vout` bit-exactly at spend time

### `qabi_blockinfo` — decode a serialised QABIBlock

```
qabi_blockinfo <qabi_block_hex>
```

Returns the full decoded block as JSON. Used for wallet review and debugging.

### `qabi_authchain` — derive auth chain tip and preimages

```
qabi_authchain <auth_seed_hex> <chain_length> [<depth>]
```

**Returns:**
```json
{
  "auth_tip": "<hex H^chain_length(auth_seed)>",
  "preimage": "<hex preimage at depth>"   // only if depth provided
}
```

Used by wallets to derive the committed `auth_tip` for new UTXOs and to produce preimages at priming/spend time.

**Note:** returned hex uses `uint256::GetHex()` convention (byte-reversed display). Integrators computing SHA256 manually must reverse bytes before hashing.

### `qabi_sighash` — compute SIGHASH_QABO

```
qabi_sighash <tx_hex>
```

Returns the SIGHASH_QABO that a coordinator would sign. Covers: version, vin (outpoints + sequences), vout (values + scripts), conditions_root, qabi_block, per-input witness stacks, nLockTime. Excludes: aggregated_sig (chicken-and-egg), creation_proof.

### `qabi_signqabo` — coordinator signing

```
qabi_signqabo <tx_hex> <coordinator_privkey_hex>
```

**Returns:**
```json
{
  "hex":      "<signed tx hex>",
  "sighash":  "<hex SIGHASH_QABO>",
  "sig_size": 666
}
```

Computes SIGHASH_QABO, signs it with the FALCON-512 private key, pads to exactly 666 bytes (consensus cap), and re-serialises the tx with `aggregated_sig` populated. Rejects txs without a `qabi_block` (not a QABIO batch).

---

## 3. Extended existing RPCs

### `createtxmlsc` — now accepts `qabi_block` (6th positional arg)

```
createtxmlsc <inputs> <outputs> <rungs> [<locktime> [<internal_pubkey> [<qabi_block_hex>]]]
```

When `qabi_block_hex` is non-empty, the RPC strict-parses it and populates `tx.qabi_block` on the returned tx. Coordinators use this to build QABIO batch tx templates before signing via `qabi_signqabo`.

### `signrungtx` — now handles `QABI_PRIME` block specs

To sign a priming tx's Rung 1, provide a block spec of:

```json
{
  "type": "QABI_PRIME",
  "new_committed_root":   "<hex 32 bytes>",
  "prime_depth":          <int>,
  "new_committed_expiry": <int>,
  "auth_seed":            "<hex 32 bytes>",
  "chain_length":         <int>
}
```

The RPC derives the spend preimage internally via `ComputeAuthChainPreimageAt`. Alternatively, provide `prime_preimage` directly instead of `auth_seed` + `chain_length`.

---

## 4. End-to-end coordinator workflow

### Setup — one-time per participant

Each participant generates their own auth chain:

```bash
# Generate a 32-byte random seed
AUTH_SEED=$(openssl rand -hex 32)

# Derive the tip (public commitment)
bitcoin-cli qabi_authchain "$AUTH_SEED" 20000
# → { "auth_tip": "..." }
```

Store `AUTH_SEED` as the wallet secret. `auth_tip` will be committed into new QABI-enabled UTXOs.

### Creating a QABI-enabled UTXO

```bash
bitcoin-cli createtxmlsc \
  '[{"txid":"<funding_txid>","vout":0}]' \
  '[0.001]' \
  '[
    {
      "output_index": 0,
      "blocks": [{"type": "SIG", "fields": [{"type": "SCHEME", "hex": "01"}]}],
      "pubkeys": ["<alice_rung0_pubkey>"]
    },
    {
      "output_index": 0,
      "blocks": [{"type": "QABI_PRIME", "fields": []}]
    },
    {
      "output_index": 0,
      "blocks": [{
        "type": "QABI_SPEND",
        "fields": [
          {"type": "HASH256",       "hex": "<auth_tip bytes in-memory order>"},
          {"type": "HASH256",       "hex": "0000...00"},
          {"type": "NUMERIC",       "hex": "00000000"},
          {"type": "NUMERIC",       "hex": "00000000"},
          {"type": "PUBKEY_COMMIT", "hex": "<sha256(alice_rung0_pubkey)>"}
        ]
      }]
    }
  ]'
```

Sign the funding input separately (depends on how the funding UTXO was created) and broadcast.

### Coordinator: build the QABIBlock

```bash
# Coordinator generates their FALCON keypair
COORD_KEYS=$(bitcoin-cli generatepqkeypair "FALCON512")
COORD_PK=$(echo "$COORD_KEYS" | jq -r .pubkey)
COORD_SK=$(echo "$COORD_KEYS" | jq -r .privkey)

# Build the block
BLOCK=$(bitcoin-cli qabi_buildblock \
  "$COORD_PK" \
  "$(($(bitcoin-cli getblockcount) + 144))" \
  "$(openssl rand -hex 32)" \
  '[
    {"participant_id": "<alice_id>", "contribution": "0.001",  "destination_index": 0},
    {"participant_id": "<bob_id>",   "contribution": "0.002",  "destination_index": 1}
  ]' \
  '[
    {"amount": "0.00099", "script_pubkey": "<alice_destination>"},
    {"amount": "0.00198", "script_pubkey": "<bob_destination>"}
  ]')

QABI_BLOCK=$(echo "$BLOCK" | jq -r .qabi_block)
QABI_ROOT=$(echo "$BLOCK"  | jq -r .qabi_root)
```

Distribute `QABI_BLOCK` to Alice and Bob off-chain. They must verify it matches what they agreed to.

### Participants: prime their UTXOs

Each participant constructs a priming tx that transitions their UTXO's `committed_root` from 0 to `QABI_ROOT`:

```bash
# Build the priming tx template
PRIMED_HEX=$(bitcoin-cli createtxmlsc \
  '[{"txid":"<alice_qabi_utxo>","vout":0}]' \
  '[0.00099]' \
  '[
    {
      "output_index": 0,
      "blocks": [{"type": "SIG", "fields": [{"type": "SCHEME", "hex": "01"}]}],
      "pubkeys": ["<alice_rung0_pubkey>"]
    },
    {
      "output_index": 0,
      "blocks": [{"type": "QABI_PRIME", "fields": []}]
    },
    {
      "output_index": 0,
      "blocks": [{
        "type": "QABI_SPEND",
        "fields": [
          {"type": "HASH256",       "hex": "<alice_auth_tip>"},
          {"type": "HASH256",       "hex": "<QABI_ROOT in-memory order>"},
          {"type": "NUMERIC",       "hex": "<prime_depth as 4-byte LE>"},
          {"type": "NUMERIC",       "hex": "<prime_expiry as 4-byte LE>"},
          {"type": "PUBKEY_COMMIT", "hex": "<alice_id>"}
        ]
      }]
    }
  ]' | jq -r .hex)

# Sign the Rung 1 QABI_PRIME spend
SIGNED_HEX=$(bitcoin-cli signrungtx \
  "$PRIMED_HEX" \
  '[{
    "input": 0, "rung": 1,
    "blocks": [{
      "type": "QABI_PRIME",
      "new_committed_root":   "<QABI_ROOT>",
      "prime_depth":          <int>,
      "new_committed_expiry": <int>,
      "auth_seed":            "<alice_auth_seed>",
      "chain_length":         20000
    }],
    "conditions": [{"blocks": [{"type": "QABI_PRIME", "fields": []}]}]
  }]' \
  '[{"amount": 0.001, "scriptPubKey": "<alice_utxo_scriptpubkey>"}]' | jq -r .hex)

bitcoin-cli sendrawtransaction "$SIGNED_HEX"
```

### Coordinator: assemble and sign the QABIO tx

Once all participants have primed:

```bash
# Build the batch tx — all primed inputs as vin, destinations as vout
# (vout MUST match block.outputs bit-exactly)
BATCH_HEX=$(bitcoin-cli createtxmlsc \
  '[
    {"txid": "<alice_primed_txid>", "vout": 0},
    {"txid": "<bob_primed_txid>",   "vout": 0}
  ]' \
  '[0.00099, 0.00198]' \
  '[...spend rungs...]' \
  0 "" \
  "$QABI_BLOCK")

# Sign with the coordinator's FALCON private key
SIGNED_BATCH=$(bitcoin-cli qabi_signqabo "$BATCH_HEX" "$COORD_SK")
FINAL_HEX=$(echo "$SIGNED_BATCH" | jq -r .hex)

bitcoin-cli sendrawtransaction "$FINAL_HEX"
```

On confirmation, all primed UTXOs are consumed and all destinations receive their specified amounts — atomically, under one FALCON-512 signature.

---

## 5. Common integration pitfalls

### Hex byte order

`uint256::GetHex()` returns hex in **reversed** (display) order. When passing values to `qabi_buildblock` or computing SHA256 on `auth_tip` manually, you may need to reverse the bytes. Rule of thumb: if you receive a hash from a Bitcoin RPC, reverse it before feeding into SHA256; if you're displaying a hash you computed, reverse it to match Bitcoin conventions.

### NUMERIC field canonical form

Wire format for `NUMERIC` fields is 4-byte little-endian. When building conditions specs for `createtxmlsc` or signing specs for `signrungtx`, encode integers as 4-byte LE hex:

```python
def u32_le_hex(n: int) -> str:
    return n.to_bytes(4, "little").hex()
```

### `conditions_root` must be non-zero for TX_MLSC path

The TX_MLSC serialiser takes the standard (non-MLSC) serialisation path when `conditions_root.IsNull() == true`. Any all-zero conditions_root will silently drop the `qabi_block` and `aggregated_sig` fields on re-encoding. Always set a non-zero conditions_root when constructing raw v4 txs.

### `tx.vout` must exactly match `block.outputs`

QABI_SPEND check 8 enforces bit-exact equality between `tx.vout` and `block.outputs`. Any mismatch (different value, different scriptPubKey, different order, extra outputs) rejects the whole tx. Coordinator fees must be explicit entries in `block.outputs`.

### SIGHASH_QABO stability

The sighash is deterministic over all tx fields **except** `tx.aggregated_sig`. A coordinator can compute it before signing, sign it, embed the result, and the sighash on the signed tx will match the pre-signing sighash exactly.

### Priming depth monotonicity

`EvalQABIPrimeBlock` requires `prime_depth > committed_depth`. Wallets must track which depth they've consumed per UTXO and always bump to a strictly deeper value for each re-prime. Starting at depth 1 is safe for an unprimed UTXO (`committed_depth = 0`).

---

## 6. Further reading

- **Design spec**: `doc/ladder-script/project_qabi.md` — 14 sections covering goals, definitions, UTXO structure, priming and spend flows, QABIBlock structure, size analysis, mempool policies, full security analysis with 15 attack scenarios
- **BIP adaptation**: `doc/ladder-script/bip-qabio.md` — standards-track format for integration into the main Ladder Script BIP
- **Reference implementation**:
  - Core: `src/rung/qabi.{h,cpp}`, `src/rung/evaluator.cpp` (EvalQABIPrimeBlock, EvalQABISpendBlock), `src/rung/policy.cpp` (RBD helpers)
  - Consensus wiring: `src/validation.cpp` (RBD in ReplacementChecks), `src/primitives/transaction.h` (tx-level fields)
  - RPC: `src/rung/rpc.cpp` (5 QABI commands + signrungtx/createtxmlsc extensions)
  - Descriptors: `src/rung/descriptor.cpp` (qabi_prime() / qabi_spend() tokens)
- **Tests**:
  - C++: `src/test/rung_tests.cpp` — 70 test cases in the `qabi_tests` suite covering serialisation, root determinism, sighash, full FALCON end-to-end, per-check failure modes, RBD policy, multi-party scale (up to 1000 participants), and adversarial edge cases
  - Python: `test/functional/feature_qabi.py` — 17 test cases covering the full RPC surface on regtest
