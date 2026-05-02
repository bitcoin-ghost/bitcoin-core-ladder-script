# Block Library

Ladder Script defines **65 block types across 11 families**, all listed below.
The QABI / PQ family ([`QABIO.md`](QABIO.md), [`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md))
sits at `0x0A00`-`0x0AFF`. Each block type has a `uint16_t` type code encoded
little-endian on the wire.


> Each block has one of two on-wire encodings — **implicit** (single
> micro-header byte, fields packed in a fixed positional layout from
> the type's implicit-layout table) or **explicit** (escape header byte
> + CompactSize field count + per-field type byte + per-field data).
> Block types with an implicit layout serialise implicitly by default;
> the explicit form is reserved for layout-less types (`RECURSE_MODIFIED`,
> `RECURSE_DECAY`) and the inverted form. When an explicitly-encoded
> block uses a type that also has an implicit layout, the deserialiser
> requires the explicit field count and types to exactly match the
> implicit layout — alternate orderings or counts reject.

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
| 0x0002 | MULTISIG | no | yes | 0 | NUMERIC(K), SCHEME(1), HASH256(pubkey_root) | K-of-N threshold; N pubkeys committed via inner Merkle root, K revealed at spend as `(PUBKEY, MERKLE_PROOF, SIGNATURE)` triplets in strict ascending pubkey-lex order. |
| 0x0003 | ADAPTOR_SIG | no | yes | 1 | (none) | Adaptor signature verification. Witness: implicit `[PUBKEY, SIGNATURE]`. |
| 0x0004 | MUSIG_THRESHOLD | no | yes | 1 | NUMERIC(M), NUMERIC(N) | MuSig2/FROST aggregate threshold |
| 0x0005 | KEY_REF_SIG | no | yes | 0 | NUMERIC(relay_idx), NUMERIC(block_idx) | Signature using a key from a relay block. The relay leaf is folded into `conditions_root` so the referenced pubkey cannot be swapped at spend time. Witness: implicit `[SIGNATURE]` only — pubkey is resolved from the referenced relay block, never on the witness wire. |

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
| 0x0302 | VAULT_LOCK | no | yes | 2 | NUMERIC(hot_delay) | Vault timelock with hot/cold keys. Witness: implicit `[PUBKEY(recovery), PUBKEY(hot), SIGNATURE]` — `NUMERIC(hot_delay)` is conditions-side, arrives via merge. |
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
| 0x0502 | ANCHOR_CHANNEL | yes | no | 0 | NUMERIC(commitment_number) | Lightning channel anchor marker (pure commitment_number; the channel keys live in a sibling SIG rung). |
| 0x0503 | ANCHOR_POOL | yes | no | 0 | HASH256(vtxo_root), NUMERIC(count) | Pool anchor |
| 0x0504 | ANCHOR_RESERVE | yes | no | 0 | NUMERIC(n), NUMERIC(m), HASH256(guardian) | Reserve anchor (guardian set) |
| 0x0505 | ANCHOR_SEAL | yes | no | 0 | HASH256(32), HASH256(32) | Seal anchor |
| 0x0506 | ANCHOR_ORACLE | yes | yes | 1 | NUMERIC(outcome_count) | Oracle anchor. Witness: implicit `[PUBKEY(oracle)]`. |
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
| 0x0702 | HTLC | no | yes | 2 | HASH256(32), NUMERIC(csv), SCHEME(1) | True two-path HTLC: receiver(pubkeys[0])+preimage spend OR sender(pubkeys[1])+CSV refund. Witness: `[PUBKEY(receiver), PUBKEY(sender), SIGNATURE, PREIMAGE, NUMERIC(path)]`. |
| 0x0703 | HASH_SIG | no | yes | 1 | HASH256(32), SCHEME(1) | Hash preimage + signature |
| 0x0704 | PTLC | no | yes | 1 | NUMERIC(csv) | Point timelock contract — adaptor sig + CSV. Adaptor point T = t·G is off-chain only. Witness: implicit `[PUBKEY, SIGNATURE]` — `NUMERIC(csv)` is conditions-side. |
| 0x0705 | CLTV_SIG | no | yes | 1 | SCHEME(1), NUMERIC(cltv) | SIG + CLTV in one block |
| 0x0706 | TIMELOCKED_MULTISIG | no | yes | 0 | NUMERIC(K), NUMERIC(csv), SCHEME(1), HASH256(pubkey_root) | MULTISIG + CSV in one block. K triplets in strict ascending pubkey-lex order. |
| 0x0707 | ANCHOR_FEE | no | yes | 2 | SCHEME, NUMERIC(min_fee), NUMERIC(max_fee), NUMERIC(max_weight), NUMERIC(commitment) | Fee anchor: 2-of-2 sigs + fee rate band + weight limit (anti-pinning). Witness: implicit `[PUBKEY, PUBKEY, SIGNATURE, SIGNATURE]`. |

## Governance Family (0x0800 - 0x08FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0801 | EPOCH_GATE | no | no | 0 | NUMERIC(epoch_size), NUMERIC(window_size) | Periodic spending window: open when `block_height % epoch_size < window_size` |
| 0x0802 | WEIGHT_LIMIT | yes | no | 0 | NUMERIC(max_weight) | Maximum transaction weight |
| 0x0803 | INPUT_COUNT | yes | no | 0 | NUMERIC(min), NUMERIC(max) | Input count bounds |
| 0x0804 | OUTPUT_COUNT | yes | no | 0 | NUMERIC(min), NUMERIC(max) | Output count bounds |
| 0x0805 | RELATIVE_VALUE | no | no | 0 | NUMERIC(num), NUMERIC(denom) | Output value as ratio of input |
| 0x0806 | ACCUMULATOR | yes | no | 0 | HASH256(set_root) | v2: structured-leaf set-membership; witness = NUMERIC(element_id) + MERKLE_PROOF (≤4 levels = 128 B); leaf = `H_tag("LadderAccumulatorLeaf/v1", element_id_LE)` |
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

## QABIO Family (0x0A00 - 0x0AFF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0A01 | QABI_PRIME | no | no | 0 | (none) | Priming state transition --reveals next auth chain preimage, mutates committed_root/depth/expiry. See [QABIO.md](QABIO.md). |
| 0x0A02 | QABI_SPEND | no | no | 0 | HASH256(32)+HASH256(32)+NUMERIC+NUMERIC+PUBKEY_COMMIT(32) | Coordinator-governed batch spend with single FALCON-512 aggregated sig. See [QABIO.md](QABIO.md). |
| 0x0A03 | PQ_BATCH | no | no | 0 | HASH256(32) | PQ key-sharing pool --commits SHA256(falcon_pubkey); anchor input reveals pubkey + PQ sig, siblings short-circuit via tx-local cache. See [PQ_BATCH_SPEC.md](PQ_BATCH_SPEC.md). |

## Inverted Blocks — Normally Closed Contacts

In PLC ladder logic, a normally closed contact `[/]` passes current when
the underlying condition is FALSE. Ladder Script's `inverted` flag (wire
format: see Notes below) creates the same primitive on Bitcoin: the
evaluator runs the block's native logic, then flips `SATISFIED` &harr;
`UNSATISFIED` (with `ERROR` left untouched). This unlocks spending
conditions that have no direct equivalent in legacy Script.

| Inverted Block | Semantics | New Primitive Enabled |
|---|---|---|
| `[/CSV: N]` | Passes BEFORE N blocks elapsed | Dead man's switch, breach-remedy window |
| `[/CSV_TIME: T]` | Passes BEFORE relative time T elapses | Time-bounded response window |
| `[/CLTV: H]` | Passes BEFORE block height H | Spend deadline — must act before this date |
| `[/CLTV_TIME: T]` | Passes BEFORE absolute time T | Calendar-bound deadline |
| `[/COMPARE: GT N]` | Passes when amount &le; N | Small-amount fast path; large amounts require extra auth |
| `[/TIMER_CONTINUOUS: N]` | Passes when liveness proof broken | Inheritance — unlocks only if owner has gone silent |
| `[/AMOUNT_LOCK: lo, hi]` | Passes when output amount OUTSIDE `[lo, hi]` | Value-exclusion zone (privacy) |
| `[/CTV: H]` | Passes when output template differs | "Not this template" guard |

**Key-consuming blocks are NOT invertible** &mdash; the deserialiser rejects
the inverted bit on `SIG`, `MULTISIG`, `MUSIG_THRESHOLD`, `ADAPTOR_SIG`,
`PTLC`, `HTLC`, `HASH_SIG`, `TIMELOCKED_SIG`, `CLTV_SIG`,
`TIMELOCKED_MULTISIG`, `KEY_REF_SIG`, `VAULT_LOCK`, `ANCHOR_FEE`,
`COSIGN`, and the `*_LEGACY` family. Inverting a key-consuming block
would let a spender provide a garbage pubkey that fails verification,
flip the result to `SATISFIED`, and embed up to 33 bytes of arbitrary
data per block. To express "anyone EXCEPT key K can spend" or "n-of-m
have NOT signed", compose with non-key-consuming gating blocks (e.g.
`[CSV: N] AND [/COSIGN: hash(other_input_spk)]` for a key-exclusion
window) or use a different rung as the alternative path.

## Notes

- **Invertible** blocks may have their evaluation result flipped using the `inverted` flag
  (0x81 escape header). Key-consuming blocks are never invertible to prevent garbage-pubkey
  data embedding. The invertible set is an explicit allowlist; new block types default to
  non-invertible (fail-closed).
- **Key-consuming** blocks have their pubkeys folded into the MLSC Merkle leaf via
  `merkle_pub_key`. Pubkeys appear in the witness but not in the conditions fields.
  In a RUNG_TX, each output is 8 bytes (value only) with one shared
  conditions_root (MLSC `0xDF` prefix) per transaction.
- **PK#** = `var` means the pubkey count is determined at runtime by counting PUBKEY fields.
  `0` for key-consuming blocks like P2PKH_LEGACY means the pubkey is in the witness but hashed
  to HASH160 in conditions (not intercepted to Merkle leaf). MULTISIG and TIMELOCKED_MULTISIG
  also report `0`: they commit the N pubkeys via an inner Merkle root (`HASH256(pubkey_root)`
  in conditions), and the spend witness reveals K pubkeys with `MERKLE_PROOF` inclusion proofs
  — neither the conditions nor the outer leaf carries the raw N-pubkey list.
- RECURSE_MODIFIED and RECURSE_DECAY have variable-length fields (no implicit layout).
  Layout-less blocks reject any field whose type is in `IsDataEmbeddingType`
  (`HASH256` / `HASH160` / `PUBKEY_COMMIT` / `DATA`) on the witness side.
- **Conditions-only block witness:** block types whose evaluator reads
  only conditions-side fields (`ANCHOR` family, `RECURSE_*`, all PLC,
  governance, `CTV`, `AMOUNT_LOCK`, `CSV` / `CSV_TIME` / `CLTV` /
  `CLTV_TIME`, `COSIGN`) accept witnesses containing only `PUBKEY`
  fields (count ≤ `PubkeyCountForBlock`, used for Merkle-leaf
  reconstruction) and `PREIMAGE` fields (count ≤ 2 per block, used for
  hash-binding against a `HASH256` in conditions). Every other field
  type rejects. Exempt block types — `MULTISIG` /
  `TIMELOCKED_MULTISIG` (triplet enforcement at the deserialiser),
  `ACCUMULATOR` (`[NUMERIC, MERKLE_PROOF]` shape pinned), `P2SH_LEGACY`
  / `P2WSH_LEGACY` / `P2TR_SCRIPT_LEGACY` (the outer witness's stack-
  push count must match an inner rung's expected witness layout sum),
  `DATA_RETURN` (eval rejects all spends).
- **Per-tx field caps**: `MAX_PREIMAGE_FIELDS_PER_TX = 2`,
  `MAX_SCRIPT_BODY_FIELDS_PER_TX = 1`. These count `PREIMAGE` /
  `SCRIPT_BODY` across every MLSC-spending input's witness AND every
  diff-witness overlay. Bootstrap inputs (P2WPKH / P2WSH wallet
  spends) are excluded from the count.
- **Per-block / per-rung structural caps**: `MAX_FIELDS_PER_BLOCK = 16`,
  `MAX_BLOCKS_PER_RUNG = 8`, `MAX_RUNGS = 16`, `MAX_RELAYS = 8`,
  `MAX_LADDER_WITNESS_SIZE = 100 KB` per input.
