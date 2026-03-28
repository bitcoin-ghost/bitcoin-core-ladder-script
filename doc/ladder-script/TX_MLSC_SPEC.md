# TX_MLSC — Transaction-Level Merkelised Ladder Script Conditions

**Status:** Draft v0.3 · March 2026
**Base:** Bitcoin Core v30.0

---

## Overview

TX_MLSC is a transaction format for Bitcoin that uses a single shared
`conditions_root` per transaction instead of per-output scriptPubKeys.
Each output is just a value (8 bytes on the wire). Each rung's coil
declares which output it governs — the output-to-rung binding is
cryptographic (committed in the Merkle tree).

Conditions are revealed only at spend time via Merkle proofs. The
`conditions_root` is an opaque 32-byte commitment — validation happens
exclusively at spend time.

---

## Transaction format (v4 RUNG_TX with TX_MLSC)

```
nVersion:           int32 (= 4, RUNG_TX_VERSION)
dummy:              uint8 (= 0x00)
flags:              uint8 (= 0x02)
vin_count:          varint
vin[]:              prevout(36) + scriptSig_len(1) + nSequence(4) per input
conditions_root:    32 bytes                     ← ONE root for entire tx
vout_count:         varint
vout[]:             nValue(8) per output          ← just values, nothing else
witness[]:          per-input spending witness
aggregated_sig_len: varint (0 if no aggregation)
aggregated_sig:     half-aggregated Schnorr s value (32 bytes if present)
nLockTime:          uint32
```

Flag byte 0x02 signals TX_MLSC format. Flag 0x01 is SegWit. Flag 0x03
(combined) is rejected.

### Output format

```
nValue:    int64    (8 bytes, little-endian satoshi amount)
```

8 bytes per output. No scriptPubKey on the wire.

Consensus: nValue >= MIN_RUNG_OUTPUT_VALUE (546 sats) for non-DATA_RETURN.

On deserialization, outputs are inflated to CTxOut(value, 0xDF + root)
for compatibility with all existing code that accesses tx.vout[i].scriptPubKey.

### DATA_RETURN outputs

DATA_RETURN is identified by nValue == 0:

```
nValue:      int64    (must be 0)
payload_len: varint   (0-40 bytes)
payload:     bytes
```

Maximum 1 DATA_RETURN output per transaction.

---

## UTXO Set Storage

### Deduplication via synthetic root entry

TX_MLSC outputs share the same conditions_root. To avoid storing 33 bytes
of identical scriptPubKey per output, a synthetic UTXO entry stores the
root once per transaction:

```
Synthetic entry: (txid, 0xFFFFFFFF) → Coin(value=0, scriptPubKey=0xDF+root)
Real outputs:    (txid, 0..N)       → Coin(value, scriptPubKey=0xDF) [1 byte, compact]
```

At spend time, compact MLSC coins (1-byte scriptPubKey) are inflated by
looking up the synthetic root entry from the UTXO cache.

### UTXO cost comparison

| Type | Per output | 100 outputs |
|------|-----------|-------------|
| P2PKH | ~40 B | ~4,000 B |
| P2WPKH | ~37 B | ~3,700 B |
| P2TR | ~49 B | ~4,900 B |
| **TX_MLSC** | **~8 B** | **~840 B** |

---

## Spending

When spending output i from a TX_MLSC transaction:

### Spending paths

**Key-path (1-element witness):** `[signature(64)]`
- conditions_root treated as x-only public key
- Schnorr signature verified against it using LadderKeyPathSighash
- No conditions revealed, no Merkle proof needed

**Script-path (2-element witness):** `[LadderWitness, MLSCProof]`
- Rung conditions revealed + Merkle proof against conditions_root
- Evaluator runs all blocks in the satisfied rung

**Script-path tweaked (3-element witness):** `[LadderWitness, MLSCProof, internal_pubkey]`
- Merkle proof verified, then tweak check against conditions_root
- conditions_root = internal_pubkey + H(internal_pubkey || merkle_root) * G

### MLSCProof contents

```
proof_mode:       uint8 (FULL_LEAVES=0x00, MERKLE_PATH=0x01, SHARED=0x02)
total_rungs:      varint
total_relays:     varint
rung_index:       varint (which rung is being revealed)
revealed_rung:    full conditions data (block types, field values, coil)
n_proof_hashes:   varint
proof_hashes[]:   32 bytes each
```

O(log N) Merkle path proofs are the default. SHARED mode references
another input's verified proof for same-source transactions.

---

## Size and Fee Analysis

### Simple payment (1 input, 2 outputs)

| Format | vBytes | Fee (10 sat/vB) |
|--------|--------|-----------------|
| P2PKH | 226 | 2,260 sats |
| P2WPKH | 143 | 1,430 sats |
| P2TR key-path | 157 | 1,570 sats |
| **TX_MLSC key-path** | **119** | **1,190 sats** |
| **TX_MLSC script-path** | **140** | **1,400 sats** |

### Batch payment (1 input, N outputs)

| Outputs | P2WPKH | P2TR | **TX_MLSC key** | Saving vs P2WPKH |
|---------|--------|------|-----------------|------------------|
| 2 | 143 vB | 167 vB | **119 vB** | 17% |
| 10 | 391 vB | 511 vB | **194 vB** | 50% |
| 100 | 3,181 vB | 4,381 vB | **914 vB** | 71% |
| 1000 | 31,081 vB | 43,081 vB | **8,114 vB** | 74% |

### Full lifecycle (create 1 output + spend it)

| Type | Total | vs P2WPKH |
|------|-------|-----------|
| P2WPKH | 255 vB | baseline |
| P2TR key-path | 281 vB | -10% |
| **TX_MLSC key-path** | **241 vB** | **+6% cheaper** |

---

## Security Analysis

### Embeddable data per transaction

| Channel | Bytes | Permanent UTXO | Readable |
|---------|-------|---------------|----------|
| conditions_root | 32/tx | No (hash in deduped UTXO) | Yes |
| DATA_RETURN | 40 | No (zero-value) | Yes |
| PREIMAGE fields | 64 max | No (witness) | Yes |
| nLockTime | 4 | No | Yes |
| nSequence/input | 4/input | No | Yes |
| **Total (1 input)** | **144** | | |

Taproot: 32 bytes readable per OUTPUT.
TX_MLSC: 32 bytes per TRANSACTION. 100-output batch: 100× better.

### Anti-spam defences

1. **merkle_pub_key**: pubkeys folded into Merkle leaf, not in conditions
2. **Selective inversion**: key-consuming blocks never invertible
3. **Implicit field layouts**: fixed field counts/types per block
4. **Fail-closed deserialization**: unknown types/fields rejected
5. **PREIMAGE cap**: MAX_PREIMAGE_FIELDS_PER_TX = 2
6. **DATA restriction**: DATA type only in DATA_RETURN blocks
7. **Dust threshold**: MIN_RUNG_OUTPUT_VALUE = 546 sats (consensus)
8. **Per-tx root**: conditions_root shared across all outputs (not per-output)

---

## Proof Modes

### FULL_LEAVES (0x00)

All unrevealed leaf hashes provided. O(N) witness size.

### MERKLE_PATH (0x01)

O(log N) sibling hashes from leaf to root. Default mode.

### SHARED (0x02)

References another input's verified proof from the same source transaction.
Leaf membership verified against cached leaf set.

---

*TX_MLSC Specification v0.3 · Ladder Script Project · March 2026*
