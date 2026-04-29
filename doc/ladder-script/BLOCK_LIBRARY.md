# Block Library

Ladder Script defines **65 block types across 11 families**, all listed below.
The QABI / PQ family ([`QABIO.md`](QABIO.md), [`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md))
sits at `0x0A00`-`0x0AFF`. Each block type has a `uint16_t` type code encoded
little-endian on the wire.

> **v0.12 (2026-04-29)** — audit 8a/8b follow-up:
> - **F1 (HIGH)**: `VerifyMutatedLeaves` cross-rung path and `EvalQABIPrimeBlock`
>   full-tree reconstruction now verify `ComputeTxMLSCLeaf(BuildCPRung(target.rung))`
>   matches the leaf the conditions_root committed to before applying any
>   mutation. Closes a covenant-escape vector where a spender substituted a
>   fake rung at non-revealed indices.
> - **F2 (HIGH)**: PQ_BATCH cross-input cache is now populated by a
>   sequential anchor pre-pass (`PreparePQBatchAnchorCache` in
>   `validation.cpp:2417`) before the parallel script-check loop dispatches.
>   Closes a consensus split between nodes with different `-par` settings.
> - **F3 (HIGH)**: `RELATIVE_VALUE` cross-multiply now uses `__int128`.
>   Closes signed-overflow UB at `(numerator-1) * denominator` near the
>   deserialiser cap (consensus split risk).
> - **#5 (MED)**: `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT` (`0xC0..0xC3`) and
>   `LADDER_SIGHASH_ANYPREVOUT` (`0x40..0x43`) are unconditionally rejected
>   by `SignatureHashLadder`. Until a future release introduces opt-in via
>   a dedicated block type (BIP-118 style), eltoo workflows are gated.
> - **F4 (MED)**: extended regression coverage for v0.11 #1 — added
>   `mlsc_proof_rejects_unsorted_revealed_relay_refs` to cover the
>   revealed_relays site.
> - **F6 / F7 (LOW)**: QABI parser enforces strict-ascending unique order
>   on `entries[*].participant_id`. Closes coordinator-side duplicate +
>   permutation channels.
> - **F8 (LOW, helper-only)**: `ComputeCanonicalBatchId` /
>   `ApplyCanonicalBatchId` helpers exposed; deserialiser enforcement
>   queued for QABIO v2.
> - **F9 (LOW)**: `MUSIG_THRESHOLD` evaluator now requires M and N
>   NUMERIC fields (was conditional). Defence-in-depth — implicit layout
>   already enforces 2 NUMERICs at deserialise.
>
> **v0.11 (2026-04-29)** — audit #7 follow-up:
> - **#1**: `MLSCProof` deserialise now enforces strict ascending unique
>   on the proof-side `relay_refs` (revealed_rung, revealed_relays,
>   mutation_target). v0.10's F-4 fix landed only on the wire-format
>   witness; the proof side bypassed canonical encoding because
>   `MergeConditionsAndWitness` takes `relay_refs` from the proof.
> - **#2**: `HashQABISection` length-prefixes both `qabi_block` and
>   `aggregated_sig` (CompactSize each). Defence-in-depth: makes the
>   binding structurally collision-resistant regardless of any future
>   change to the F-5 length enumeration.
> - **#4**: `CheckRungTxLevel` now rejects when `spent_outputs` is
>   missing or doesn't match input count. Prior nullptr branch was
>   silent fail-OPEN for preimage / script_body / accumulator caps;
>   production callers always populate, but the assumption is now
>   load-bearing.
> - **#14**: doc sweep — `MAX_PREIMAGE_FIELDS_PER_TX` etc. rewritten as
>   "across all MLSC-spending inputs" since v0.10 F-2 excluded bootstrap
>   inputs.
>
> **v0.10 (2026-04-29)** — audit #6 follow-up:
> - **F-1**: `BuildCPRung` (used by every recursive-covenant transition —
>   `RECURSE_DECAY` / `RECURSE_SPLIT` / `RECURSE_MODIFIED`) now propagates
>   `rung.relay_refs` into the leaf. v0.9 R-1 closed the spend-input bypass
>   but missed this output-side build site, re-opening relay enforcement
>   skip across covenant transitions.
> - **F-2**: `HasTxQABIInputs` / `CountTxPreimageFields` /
>   `CountTxScriptBodyFields` / `CountTxAccumulatorBlocks` now filter to
>   MLSC-spending inputs by checking each spent output against
>   `IsMLSCScript`. Without the filter, a crafted bootstrap input
>   (e.g. P2WSH `OP_DROP OP_TRUE`) with a fake QABI ladder in element[0]
>   bypassed every per-tx cap.
> - **F-3**: per-tx PREIMAGE / SCRIPT_BODY counters now also walk diff
>   witness entries (`witness_ref->diffs`). Pre-v0.10 a diff witness's
>   PREIMAGE/SCRIPT_BODY overlays contributed 0 to the count, allowing N
>   diff inputs to overlay 2 source positions with fresh attacker bytes
>   while passing the cap.
> - **F-4**: `relay_refs` must now be in strict ascending unique order at
>   deserialise. Closes the canonicalisation channel where `[0]`, `[0,0]`,
>   `[0,1,0]`, `[1,0]` were eval-equivalent (set semantics) but produced
>   different leaf hashes — funder-side embedding via the chosen encoding.
> - **F-5**: `tx.aggregated_sig` must be exactly 0 (no `QABI_SPEND`) or
>   666 bytes (when `QABI_SPEND` is present). Pre-v0.10 the deserialiser
>   accepted any 1..665 bytes for QABI_PRIME / PQ_BATCH-only txs.
> - **F-6** (defence-in-depth): `tx.qabi_block` and `tx.aggregated_sig`
>   are now folded into the sighash via a 32-byte SHA256 commitment.
> - **F-7**: `coil.output_index >= tx.output_count` now rejects at the
>   evaluator. Pre-v0.10 it silently fell back to `outputs[0]`.
> - **F-8**: `MergeConditionsAndWitness` now caps the post-merge field
>   count per block (`2 × MAX_FIELDS_PER_BLOCK`, with the wider
>   `MAX_FIELDS_PER_BLOCK + MAX_MULTISIG_WITNESS_FIELDS` cap for
>   `MULTISIG` / `TIMELOCKED_MULTISIG`).
>
> **v0.9 (2026-04-29)** — audit #5 follow-up:
> - **R-1**: `rung.relay_refs` is now folded into the rung's structural
>   template (the leaf hash). Before v0.9 this field was unbound, so a
>   spender could drop relay dependencies at spend time and skip relay
>   enforcement. Affects every rung that uses a relay — the funder must
>   declare `relay_refs` at fund time, and the spender cannot mutate them.
> - **T-1 / T-2**: `tx.qabi_block` and `tx.aggregated_sig` are now rejected
>   when no input carries a QABI block type (`QABI_SPEND` / `QABI_PRIME` /
>   `PQ_BATCH`). Closes a 64 KB / 666 B per-tx embedding channel for
>   non-QABIO transactions.
> - **D-1**: diff-witness deserialise now rejects duplicate
>   `(rung_index, block_index, field_index)` targets. Closes ~12 KB of
>   per-input witness inflation via no-op repeat diffs.
>
> **v0.8 (2026-04-29)** — six blocks gained strict implicit witness layouts
> (E-018a): `ADAPTOR_SIG`, `PTLC`, `KEY_REF_SIG`, `VAULT_LOCK`, `ANCHOR_FEE`,
> `ANCHOR_ORACLE`. `MULTISIG` / `TIMELOCKED_MULTISIG` triplets must now be in
> strict ascending pubkey-lex order (E-018b). The witness side of
> `KEY_REF_SIG` reduced to `[SIGNATURE]` only — the prior `PUBKEY` was unbound
> spender bytes since the evaluator pulls the key out of the referenced
> relay block.

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
| 0x0002 | MULTISIG | no | yes | 0 | NUMERIC(K), SCHEME(1), HASH256(pubkey_root) | K-of-N threshold; N pubkeys committed via inner Merkle root, K revealed at spend with MERKLE_PROOFs. v0.8: K triplets must be in strict ascending pubkey-lex order (E-018b). |
| 0x0003 | ADAPTOR_SIG | no | yes | 1 | (none) | Adaptor signature verification (v0.7: dropped dead second pubkey slot; v0.8: strict implicit witness `[PUBKEY, SIGNATURE]`). |
| 0x0004 | MUSIG_THRESHOLD | no | yes | 1 | NUMERIC(M), NUMERIC(N) | MuSig2/FROST aggregate threshold |
| 0x0005 | KEY_REF_SIG | no | yes | 0 | NUMERIC(relay_idx), NUMERIC(block_idx) | Signature using key from a relay block. v0.7 folds relay leaves into conditions_root so a spender cannot swap in a different relay pubkey at spend time (closes E-008). v0.8 witness reduces to `[SIGNATURE]` only — pubkey is resolved from the referenced relay block, never on the witness wire (E-018a). |

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
| 0x0302 | VAULT_LOCK | no | yes | 2 | NUMERIC(hot_delay) | Vault timelock with hot/cold keys. v0.8 witness: implicit `[PUBKEY(recovery), PUBKEY(hot), SIGNATURE]` (E-018a — `NUMERIC(hot_delay)` is conditions-side, arrives via merge). |
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
| 0x0502 | ANCHOR_CHANNEL | yes | no | 0 | NUMERIC(commitment_number) | Lightning channel anchor marker (v0.7: dropped dead local/remote pubkey slots — were a 66 B/spend data channel) |
| 0x0503 | ANCHOR_POOL | yes | no | 0 | HASH256(vtxo_root), NUMERIC(count) | Pool anchor |
| 0x0504 | ANCHOR_RESERVE | yes | no | 0 | NUMERIC(n), NUMERIC(m), HASH256(guardian) | Reserve anchor (guardian set) |
| 0x0505 | ANCHOR_SEAL | yes | no | 0 | HASH256(32), HASH256(32) | Seal anchor |
| 0x0506 | ANCHOR_ORACLE | yes | yes | 1 | NUMERIC(outcome_count) | Oracle anchor. v0.8 witness: implicit `[PUBKEY(oracle)]` (E-018a). |
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
| 0x0702 | HTLC | no | yes | 2 | HASH256(32), NUMERIC(csv), SCHEME(1) | v0.7 true two-path: receiver(pubkeys[0])+preimage spend OR sender(pubkeys[1])+CSV refund. Witness adds NUMERIC(path) discriminator. |
| 0x0703 | HASH_SIG | no | yes | 1 | HASH256(32), SCHEME(1) | Hash preimage + signature |
| 0x0704 | PTLC | no | yes | 1 | NUMERIC(csv) | Adaptor sig + CSV (v0.7: dropped dead adaptor-point pubkey slot; T = t·G is off-chain only). v0.8 witness: implicit `[PUBKEY, SIGNATURE]` — `NUMERIC(csv)` is conditions-side (E-018a). |
| 0x0705 | CLTV_SIG | no | yes | 1 | SCHEME(1), NUMERIC(cltv) | SIG + CLTV in one block |
| 0x0706 | TIMELOCKED_MULTISIG | no | yes | 0 | NUMERIC(K), NUMERIC(csv), SCHEME(1), HASH256(pubkey_root) | MULTISIG v2 + CSV in one block. v0.8: K triplets must be in strict ascending pubkey-lex order (E-018b). |
| 0x0707 | ANCHOR_FEE | no | yes | 2 | SCHEME, NUMERIC(min_fee), NUMERIC(max_fee), NUMERIC(max_weight), NUMERIC(commitment) | Fee anchor: 2-of-2 sigs + fee rate band + weight limit (anti-pinning). v0.8 witness: implicit `[PUBKEY, PUBKEY, SIGNATURE, SIGNATURE]` (E-018a). |

## Governance Family (0x0800 - 0x08FF)

| Code | Name | Inv | Key | PK# | Conditions | Description |
|--------|------|-----|-----|-----|------------|-------------|
| 0x0801 | EPOCH_GATE | no | no | 0 | NUMERIC(period), NUMERIC(offset) | Periodic spending window |
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
  Anti-spam protection uses `IsDataEmbeddingType` rejection for layout-less blocks.
