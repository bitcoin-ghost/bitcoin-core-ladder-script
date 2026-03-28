# Block Library

Ladder Script defines 61 block types across 10 families. Each block type has a
uint16_t type code encoded little-endian on the wire.

## Legend

| Column | Meaning |
|--------|---------|
| Code | uint16_t type code (hex) |
| Inv | Invertible (result can be flipped SATISFIED/UNSATISFIED) |
| Key | Key-consuming (pubkeys folded into Merkle leaf; never invertible) |
| PK# | Pubkey count (0 = none, N = fixed, var = count from fields) |
| Conditions | Implicit layout fields on the locking (conditions) side |

## Signature Family (0x0001 - 0x00FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0001 | SIG | no | yes | 1 | SCHEME(1) | Single Schnorr/ECDSA/PQ signature |
| 0x0002 | MULTISIG | no | yes | var | NUMERIC(M) | M-of-N threshold signature |
| 0x0003 | ADAPTOR_SIG | no | yes | 2 | (none) | Adaptor signature verification |
| 0x0004 | MUSIG_THRESHOLD | no | yes | 1 | NUMERIC(M), NUMERIC(N) | MuSig2/FROST aggregate threshold |
| 0x0005 | KEY_REF_SIG | no | yes | 0 | NUMERIC(relay_idx), NUMERIC(block_idx) | Signature using key from a relay block |

## Timelock Family (0x0100 - 0x01FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0101 | CSV | yes | no | 0 | NUMERIC(blocks) | Relative timelock, block-height (BIP 68) |
| 0x0102 | CSV_TIME | yes | no | 0 | NUMERIC(seconds) | Relative timelock, median-time-past |
| 0x0103 | CLTV | yes | no | 0 | NUMERIC(height) | Absolute timelock, block-height |
| 0x0104 | CLTV_TIME | yes | no | 0 | NUMERIC(time) | Absolute timelock, median-time-past |

## Hash Family (0x0200 - 0x02FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0203 | TAGGED_HASH | yes | no | 0 | HASH256(32), HASH256(32) | BIP-340 tagged hash verification |
| 0x0204 | HASH_GUARDED | no | no | 0 | HASH256(32) | Raw SHA256 preimage verification |

## Covenant Family (0x0300 - 0x03FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0301 | CTV | yes | no | 0 | HASH256(32) | OP_CHECKTEMPLATEVERIFY covenant |
| 0x0302 | VAULT_LOCK | yes | yes | 2 | NUMERIC(hot_delay) | Vault timelock with hot/cold keys |
| 0x0303 | AMOUNT_LOCK | yes | no | 0 | NUMERIC(min), NUMERIC(max) | Output amount range constraint |

## Recursion Family (0x0400 - 0x04FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0401 | RECURSE_SAME | yes | no | 0 | NUMERIC(max_depth) | Re-encumber with identical conditions |
| 0x0402 | RECURSE_MODIFIED | yes | no | 0 | (none, variable) | Re-encumber with single mutation |
| 0x0403 | RECURSE_UNTIL | yes | no | 0 | NUMERIC(until_height) | Recurse until block height |
| 0x0404 | RECURSE_COUNT | yes | no | 0 | NUMERIC(max_count) | Recursive countdown |
| 0x0405 | RECURSE_SPLIT | yes | no | 0 | NUMERIC(max_splits), NUMERIC(min_sats) | Recursive output splitting |
| 0x0406 | RECURSE_DECAY | yes | no | 0 | (none, variable) | Recursive parameter decay |

## Anchor Family (0x0500 - 0x05FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0501 | ANCHOR | yes | no | 0 | NUMERIC(anchor_id) | Generic anchor marker |
| 0x0502 | ANCHOR_CHANNEL | yes | yes | 2 | NUMERIC(commitment_number) | Lightning channel anchor |
| 0x0503 | ANCHOR_POOL | yes | no | 0 | HASH256(vtxo_root), NUMERIC(count) | Pool anchor |
| 0x0504 | ANCHOR_RESERVE | yes | no | 0 | NUMERIC(n), NUMERIC(m), HASH256(guardian) | Reserve anchor (guardian set) |
| 0x0505 | ANCHOR_SEAL | yes | no | 0 | HASH256(32), HASH256(32) | Seal anchor |
| 0x0506 | ANCHOR_ORACLE | yes | yes | 1 | NUMERIC(outcome_count) | Oracle anchor |
| 0x0507 | DATA_RETURN | yes | no | 0 | DATA(var, max 40) | Unspendable data commitment (replaces OP_RETURN) |

## PLC Family (0x0600 - 0x06FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0601 | HYSTERESIS_FEE | yes | no | 0 | NUMERIC(high), NUMERIC(low) | Fee hysteresis band |
| 0x0602 | HYSTERESIS_VALUE | yes | no | 0 | NUMERIC(high), NUMERIC(low) | Value hysteresis band |
| 0x0611 | TIMER_CONTINUOUS | yes | no | 0 | NUMERIC(accumulated), NUMERIC(target) | Continuous timer (consecutive blocks) |
| 0x0612 | TIMER_OFF_DELAY | yes | no | 0 | NUMERIC(remaining) | Off-delay timer (hold after trigger) |
| 0x0621 | LATCH_SET | yes | yes | 1 | NUMERIC(state) | Latch set (state activation) |
| 0x0622 | LATCH_RESET | yes | yes | 1 | NUMERIC(state), NUMERIC(delay) | Latch reset (state deactivation) |
| 0x0631 | COUNTER_DOWN | yes | yes | 1 | NUMERIC(count) | Down counter (decrement on event) |
| 0x0632 | COUNTER_PRESET | yes | no | 0 | NUMERIC(current), NUMERIC(preset) | Preset counter (approval accumulator) |
| 0x0633 | COUNTER_UP | yes | yes | 1 | NUMERIC(current), NUMERIC(target) | Up counter (increment on event) |
| 0x0641 | COMPARE | yes | no | 0 | NUMERIC(op), NUMERIC(b), NUMERIC(c) | Comparator (amount vs thresholds) |
| 0x0651 | SEQUENCER | yes | no | 0 | NUMERIC(current_step), NUMERIC(total) | Step sequencer |
| 0x0661 | ONE_SHOT | yes | no | 0 | NUMERIC(state), HASH256(commitment) | One-shot activation window |
| 0x0671 | RATE_LIMIT | yes | no | 0 | NUMERIC(max), NUMERIC(cap), NUMERIC(refill) | Rate limiter |
| 0x0681 | COSIGN | no | yes | 0 | HASH256(32) | Cross-input co-spend constraint |

## Compound Family (0x0700 - 0x07FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0701 | TIMELOCKED_SIG | no | yes | 1 | SCHEME(1), NUMERIC(csv) | SIG + CSV in one block |
| 0x0702 | HTLC | no | yes | 2 | HASH256(32), NUMERIC(csv) | Hash + timelock + sig (Lightning HTLC) |
| 0x0703 | HASH_SIG | no | yes | 1 | HASH256(32), SCHEME(1) | Hash preimage + signature |
| 0x0704 | PTLC | no | yes | 2 | NUMERIC(csv) | Adaptor sig + CSV (point-locked channel) |
| 0x0705 | CLTV_SIG | no | yes | 1 | SCHEME(1), NUMERIC(cltv) | SIG + CLTV in one block |
| 0x0706 | TIMELOCKED_MULTISIG | no | yes | var | NUMERIC(M), NUMERIC(csv) | MULTISIG + CSV in one block |

## Governance Family (0x0800 - 0x08FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0801 | EPOCH_GATE | no | no | 0 | NUMERIC(period), NUMERIC(offset) | Periodic spending window |
| 0x0802 | WEIGHT_LIMIT | yes | no | 0 | NUMERIC(max_weight) | Maximum transaction weight |
| 0x0803 | INPUT_COUNT | yes | no | 0 | NUMERIC(min), NUMERIC(max) | Input count bounds |
| 0x0804 | OUTPUT_COUNT | yes | no | 0 | NUMERIC(min), NUMERIC(max) | Output count bounds |
| 0x0805 | RELATIVE_VALUE | no | no | 0 | NUMERIC(num), NUMERIC(denom) | Output value as ratio of input |
| 0x0806 | ACCUMULATOR | yes | no | 0 | HASH256(root) | Merkle accumulator set membership |
| 0x0807 | OUTPUT_CHECK | no | no | 0 | NUMERIC(idx), NUMERIC(min), NUMERIC(max), HASH256(script) | Per-output value and script constraint |

## Legacy Family (0x0900 - 0x09FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0901 | P2PK_LEGACY | no | yes | 1 | SCHEME(1) | Wrapped P2PK |
| 0x0902 | P2PKH_LEGACY | no | yes | 0 | HASH160(20) | Wrapped P2PKH |
| 0x0903 | P2SH_LEGACY | yes | no | 0 | HASH160(20) | Wrapped P2SH (inner conditions + witness) |
| 0x0904 | P2WPKH_LEGACY | no | yes | 0 | HASH160(20) | Wrapped P2WPKH |
| 0x0905 | P2WSH_LEGACY | yes | no | 0 | HASH256(32) | Wrapped P2WSH (inner conditions + witness) |
| 0x0906 | P2TR_LEGACY | no | yes | 1 | SCHEME(1) | Wrapped P2TR key-path |
| 0x0907 | P2TR_SCRIPT_LEGACY | no | yes | 1 | HASH256(32) | Wrapped P2TR script-path |

## Notes

- **Invertible** blocks may have their evaluation result flipped using the `inverted` flag
  (0x81 escape header). Key-consuming blocks are never invertible to prevent garbage-pubkey
  data embedding. The invertible set is an explicit allowlist; new block types default to
  non-invertible (fail-closed).
- **Key-consuming** blocks have their pubkeys folded into the TX_MLSC Merkle leaf via
  `merkle_pub_key`. Pubkeys appear in the witness but not in the conditions fields.
  In the TX_MLSC format, each output is 8 bytes (value only) with one shared
  conditions_root (0xDF prefix) per transaction.
- **PK#** = `var` means the pubkey count is determined at runtime by counting PUBKEY fields
  (MULTISIG, TIMELOCKED_MULTISIG). `0` for key-consuming blocks like P2PKH_LEGACY means the
  pubkey is in the witness but hashed to HASH160 in conditions (not intercepted to Merkle leaf).
- RECURSE_MODIFIED and RECURSE_DECAY have variable-length fields (no implicit layout).
  Anti-spam protection uses `IsDataEmbeddingType` rejection for layout-less blocks.
