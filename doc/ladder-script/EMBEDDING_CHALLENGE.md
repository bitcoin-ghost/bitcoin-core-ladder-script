# Ladder Script — empirical data-embedding analysis

**Status:** reference numbers for the BIP draft and consensus reviewers.

**Companion artifacts (reproducible):**
- `tools/test-presets.py` — fund/spend driver for 56 spending-pattern
  presets covering every block type
- `test/functional/feature_deferred_vectors.py` — byte-mutation
  vectors against multi-input QABI / HTLC fixtures
- `doc/ladder-script/MEASUREMENTS.md` — companion size accounting

This doc records what attacker-chosen bytes a v4 RUNG_TX can carry
on-chain. Every number is **empirical** — the channel was tried against
a real bitcoind binary and the result recorded.

---

## 1. Headline

The protocol bounds embedding via **typed structured fields with
per-tx caps**. There is no equivalent of Tapscript `OP_FALSE OP_IF
<arbitrary> OP_ENDIF` — every byte in a v4 RUNG_TX witness is consumed
by consensus. There is no equivalent of P2WSH `OP_DROP` (push-and-
discard) — every field has a typed evaluator that reads it.

| Tx shape | Attacker-controllable bytes |
|---|---:|
| Smallest spendable (1 MLSC in / 1 MLSC out, key-path) | **~11 B** |
| Typical spend (1 MLSC in / 1 MLSC out, single-block SIG ladder) | ~150 B |
| Compound spend (HTLC + CSV + SIG, 1 in / 1 out) | ~400 B |
| Worst-case standard (1 in / 1 out using TAGGED_HASH × 2 + 6 SIG ladders, max blocks per rung) | **~600 B per input** |
| Multi-input ceiling (within standard relay, ~80 inputs at ~600 B/input) | **~50 KB per tx** |

For comparison:

| Tx type | Per-tx attacker-controllable ceiling |
|---|---:|
| **v4 RUNG_TX** | **~50 KB** (typed, structured) |
| P2TR script-path (Ordinals channel) | **~400 KB** (raw tapscript with `OP_IF` dead code) |
| P2WSH | ~3 KB per script + push-and-`OP_DROP` |
| P2WPKH / P2TR key-path | ~80 B (OP_RETURN standardness only) |

**v4 RUNG_TX is roughly 8× tighter than P2TR script-path** for the same
spend — and the cap is structural (block-type field-count enforcement)
not policy-based (relayed via standardness rules that any miner can
override).

---

## 2. The minimum: 11 B per tx

For the smallest spendable v4 RUNG_TX (1 MLSC input → 1 MLSC output,
key-path Schnorr signature, no PREIMAGE / SCRIPT_BODY, no DATA_RETURN):

| Source | Bytes | Why unremovable |
|---|---:|---|
| `nLockTime` | 4 | BIP-65 — every Bitcoin tx |
| `nSequence` | 4 | BIP-68 / BIP-112 — every Bitcoin input |
| Schnorr nonce grinding | ~3 | BIP-340 — randomised signatures |
| Sighash type byte (when ≠ DEFAULT) | ~3 bits | One of 7 valid encodings |

**This 11 B is the absolute Bitcoin protocol floor.** Every Bitcoin
transaction — Taproot, P2WPKH, anything — has the same minimum. v4
RUNG_TX cannot be tightened further without modifying base Bitcoin.

---

## 3. Above the floor: structural commitments

When a v4 RUNG_TX uses block types beyond the minimum, the commitments
those blocks define add to the tx size — and to the attacker-
controllable byte count. These are **application-defined** content,
not silent padding: every byte is structurally a typed field consumed
by a specific block evaluator.

| Channel | Per-instance | Per-tx cap | Structural binding |
|---|---|---|---|
| `DATA_RETURN` block | up to 40 B | ≤ 1 per tx | Zero-value output, intentional OP_RETURN replacement |
| Conditions-side `HASH256` (TAGGED_HASH tag, CTV template, COSIGN target, HTLC payment hash, ANCHOR_POOL/RESERVE/SEAL guardian) | 32 B per field | Per-block layout × `MAX_BLOCKS_PER_RUNG = 8` × revealed rungs | Application commitment — funder picks the hash, spender reveals the matching preimage |
| `PREIMAGE` (witness) | up to 32 B | `MAX_PREIMAGE_FIELDS_PER_TX = 2` | `SHA256(preimage) == HASH256` in conditions |
| `SCRIPT_BODY` (witness) | up to 80 B | `MAX_SCRIPT_BODY_FIELDS_PER_TX = 1` | `HASH256(script_body) == HASH160`/`HASH256` in conditions; used by P2SH/P2WSH/P2TR_SCRIPT wrappers |
| `PUBKEY` (witness, leaf reconstruction) | 32-65 B per ECC pubkey; up to 2048 B for PQ schemes (`FieldMaxSize(PUBKEY)`) | Bounded by `PubkeyCountForBlock` per block type | Must reproduce the committed leaf hash; PQ pubkeys must be valid under the declared scheme |
| `conditions_root` | 32 B | per MLSC output | Merkle commit — same shape as P2WSH script-hash, P2TR output-key |
| MLSC proof sibling hash | 32 B per sibling | depth ≤ 4 (log₂ of `MAX_RUNGS = 16`) per input | Each sibling hashes an attacker-chosen subtree |
| `nLockTime` + `nSequence` | 4 + 4 per input | standard Bitcoin | Inherited from base tx format |
| `OP_RETURN` outputs | up to 80 B (standardness) / 10 KB (consensus) | datacarrier policy | Standard Bitcoin, not v4-specific |

The honest framing: **the protocol bounds embedding by capping
*structure*, not by zeroing it.** Every commit-reveal scheme — P2WSH,
P2TR, MLSC — must allow the committer to choose the committed value.
What v4 adds is per-block-type field-count enforcement so that no
unread "padding" survives.

---

## 4. What v4 does NOT allow

These are the channels every other Bitcoin output type permits but v4
RUNG_TX rejects at the wire-format deserialiser:

| Channel | Available in | Why v4 rejects |
|---|---|---|
| Tapscript `OP_FALSE OP_IF <data> OP_ENDIF` (Ordinals) | P2TR script-path | No raw script — only typed blocks |
| `OP_DROP` push-and-discard | P2WSH | Every field is consumed by a typed evaluator |
| Unread witness fields (silent padding) | Several block types pre-fix | Per-block-type field-count enforcement at the deserialiser |
| `MERKLE_PROOF` outside MULTISIG / TIMELOCKED_MULTISIG / ACCUMULATOR | — | Type-restricted at deser |
| `DATA` field outside `DATA_RETURN` block | — | Type-restricted at deser |
| `HASH256` / `HASH160` / `PUBKEY_COMMIT` / `DATA` inside layout-less blocks (`RECURSE_MODIFIED`, `RECURSE_DECAY`) | — | `IsDataEmbeddingType` filter |
| Non-canonical `CompactSize` (e.g. `0xFD 0x01 0x00` for value 1) | — | Wire-format strict canonicalisation |
| Conditions-only block witnesses with NUMERIC / SIGNATURE / SCHEME / HASH256 fields | — | Conditions-only witness whitelist (only PUBKEY ≤ `PubkeyCountForBlock` and PREIMAGE ≤ 2 allowed) |

---

## 5. Confirmed-bound channels

Each row was constructed end-to-end and submitted via
`sendrawtransaction`; every mutation was rejected.

| Channel | Reject path | Reject reason |
|---|---|---|
| `qabi_block` non-empty on non-QABI tx | tx-level check (`evaluator.cpp`) | `tx.qabi_block must be empty when no QABI input is present` |
| `qabi_block > 256 KB` (hard cap) | wire-format deser (`transaction.h`) | `qabi_block too large` |
| `qabi_block > 64 KB` (relay soft cap) | policy (`policy.cpp`) | `qabi-block-soft-cap` |
| `aggregated_sig > 666 B` | wire-format deser | `aggregated_sig too large` |
| `aggregated_sig` non-empty on non-QABI tx | tx-level check | `tx.aggregated_sig must be empty when no QABI input is present` |
| Non-canonical `batch_id` | parser (`qabi.cpp`) | `qabi_block batch_id is not canonical SHA256 derivation` |
| Duplicate `participant_id` | parser | `duplicate participant_id in entries` |
| Reversed `participant_id` order (descending) | parser | strict-ascending check |
| Wide `shared_source_input` | proof deser (`conditions.cpp`) | `MLSC shared proof shared_source_input exceeds uint16 max` |
| Rung `relay_refs` descending (`[1, 0]`) | wire-format deser (`serialize.cpp`) | `rung X relay_refs not strict ascending at index Y` |
| Duplicate `relay_refs` (`[0, 0]`) | same | same |
| Unsorted MULTISIG triplets | spend-time check (`block_helpers.cpp`) | `EvalMultisigBlock` returns UNSATISFIED |
| HTLC bad preimage | eval (`compound.cpp`) | hash mismatch → UNSATISFIED |
| HTLC witness pubkey rec/snd swap | eval | SIG verifies against wrong pubkey → UNSATISFIED |
| `DATA_RETURN` `data_len` outside 1..40 | wire-format deser | `DATA_RETURN data_len out of range (1..40)` |
| ≥ 2 `DATA_RETURN` outputs per tx | tx-level check | `too many DATA_RETURN outputs: 2 (max 1)` |
| `NUMERIC` field length > 4 bytes | wire encoder + truncation guards | `NUMERIC too large: 8 > 4` |
| Witness stack count outside `{1, 2, 3}` | consensus (`evaluator.cpp`) | `WITNESS_PROGRAM_WITNESS_EMPTY` (count=0) or generic stack-shape rejection |
| Non-canonical `CompactSize` | wire-format deser (`serialize.h`) | `non-canonical ReadCompactSize()` |
| Sighash type 0x40 / 0xC1 family (BIP-118 ANYPREVOUT) | sig path (`sighash.cpp`) | `SignatureHashLadder` returns false |
| Conditions-only block witness with NUMERIC | wire-format deser (`serialize.cpp`) | `block X is conditions-only; witness can only carry PUBKEY/PREIMAGE, got NUMERIC` |
| PQ_BATCH non-anchor witness containing arbitrary types | eval (`qabi.cpp`) | positional type check rejects |
| Legacy P2SH/P2WSH/P2TR_SCRIPT outer block with extra stack-push fields | eval (`legacy.cpp`) | `EvalInnerConditions` rejects when no inner rung's witness layout matches the outer count |

---

## 6. Methodology

**Driver scripts (reproducible):**

- `tools/test-presets.py` — 56 fund/spend presets covering every block
  type. Confirms the canonical accept path for each block.
- `test/functional/feature_deferred_vectors.py` — byte-mutation attack
  vectors against multi-input QABI / HTLC scaffolding. Each vector
  builds a real valid tx, surgically mutates one field, then submits
  and asserts rejection.
- `doc/ladder-script/MEASUREMENTS.md` — size sweeps that produce the
  table in §1.

**Coverage:**

- Every wire-format check in `src/primitives/transaction.h` (qabi_block,
  aggregated_sig, DATA_RETURN, conditions_root format, CompactSize
  bounds).
- Every block-implicit-layout check in `src/rung/types.h`
  (`ImplicitFieldLayout` rows + `IsConditionDataType` +
  `IsDataEmbeddingType`).
- Every QABI parser check in `src/rung/blocks/qabi.cpp` (canonical
  batch_id, strict-ascending entries, reserve-size bounds).
- Every MLSC proof check in `src/rung/conditions.cpp` (proof_mode,
  total_rungs, total_relays, rung_index, shared_source_input cap,
  revealed_rung blocks, relay_refs canonicalisation).
- Every coil enum check in `src/rung/serialize.cpp` (type / attestation
  / scheme / output_index).
- Sighash type validation in `src/rung/sighash.cpp`.

**What the doc does NOT measure:** universal Bitcoin protocol fields
(`nLockTime`, `nSequence`, Schnorr nonce randomisation). These are
attacker-controllable by design at the BIP-65 / BIP-68 / BIP-340 level.
The bytes do survive on-chain (any wallet user can grind their nonce or
pick their lockTime), but those channels exist for every Bitcoin
transaction format and are not v4-specific.

---

## 7. Verdict

**v4 RUNG_TX is the tightest Bitcoin output type for embedding
resistance.** Specifically:

- **Same per-output commitment overhead** as P2WSH / P2TR (32 B
  Merkle root committing to the spending tree).
- **No raw-script dead-code channel.** Tapscripts can carry
  `OP_FALSE OP_IF <arbitrary> OP_ENDIF` blocks (the Ordinals
  pattern); MLSC has no equivalent because every block is a typed
  evaluator with explicit field-count enforcement.
- **No `OP_DROP` push-and-discard channel.** Every witness field is
  consumed by a specific evaluator.
- **Per-tx caps** on PREIMAGE (2), SCRIPT_BODY (1), DATA_RETURN (1).
- **Per-block witness whitelist** for conditions-only types: only
  PUBKEY (count ≤ `PubkeyCountForBlock`) and PREIMAGE (count ≤ 2).

The realistic per-tx ceiling for attacker-controllable bytes is **~50
KB within standard relay** (dominated by per-input MLSC reveal × ~80
inputs at ~600 B/input). For comparison, P2TR script-path tapscripts
with witness discount permit ~400 KB per tx — **v4 is roughly 8×
tighter**.

The minimum is the 11 B Bitcoin protocol floor.

## 8. How to regenerate

```bash
# Spending-pattern presets (56 covering every block type):
cd tools && python3 test-presets.py --api http://127.0.0.1:8801

# Byte-mutation deferred vectors:
build/test/functional/feature_deferred_vectors.py

# Size sweeps (companion):
./build/bin/test_bitcoin --run_test=*/mlsc_creation_tx_size_sweep --log_level=message
./build/bin/test_bitcoin --run_test=*/mlsc_spend_tx_size_sweep --log_level=message
./build/bin/test_bitcoin --run_test=*/mlsc_spend_path_sweep --log_level=message
./build/bin/test_bitcoin --run_test=*/mlsc_utxo_storage_size --log_level=message
```

If any wire-format check changes, every table here may shift.
`feature_deferred_vectors.py` lives in CI; size sweeps run on every
pre-tag build. The BIP draft cites these numbers, so drift here is
drift in the BIP.
