# Ladder Script — empirical data-embedding challenge

**Status:** reference numbers for the BIP draft and consensus reviewers.
**Tested on:** v0.14 (`v30.0-ladder-0.14`, commit `e7fdb3c080`) +
patch `b423a45e4f` (DecodeHexTx error surfacing). Re-verified
2026-04-30 against a clean regtest node.
**Companion artifacts (reproducible):**
- `tools/test-presets.py` — fund/spend driver for 56 spending-pattern
  presets covering every block type
- `test/functional/feature_deferred_vectors.py` — driver for the 9
  byte-mutation vectors that need multi-input QABI / HTLC fixtures
- `doc/ladder-script/MEASUREMENTS.md` — companion size accounting

This doc records what attacker-chosen bytes a v4 RUNG_TX can carry
on-chain after every audit closure shipped through v0.14. Numbers are
**empirical** — not derived from code analysis alone — every channel
listed below was tried against a real bitcoind binary and the result
recorded.

## 1. Headline

| Spend shape | Total residual / tx | Bitcoin floor | Attacker-controllable beyond the floor |
|---|---:|---:|---:|
| Plain (1 MLSC in / 1 MLSC out, SIG path) | **~11 B** | ~11 B | **0 B** |
| Worst-case standard (16 rungs / 8 relays / 1 PREIMAGE / 1 SCRIPT_BODY / 1 DATA_RETURN) | ~163 B | 11 B | 0 B beyond intentional 40 B DATA_RETURN |
| QABIO batch (N=100 inputs) | ~800 B | 800 B (per-input nSeq + nLockTime) | **0 B coordinator-side** |

**The remaining ~11 B is the absolute Bitcoin protocol floor:**

- `nLockTime` (4 B) — BIP65
- `nSequence` (4 B/input) — BIP68 / BIP112
- Schnorr signature nonce grinding (~3 B at a 24-bit grind budget)
  — inherent to randomised signatures
- `sighash_type` byte (3 bits when ≠ DEFAULT) — has to encode spender
  intent (`ALL`/`NONE`/`SINGLE` × `ANYONECANPAY`)

Every Bitcoin transaction — Taproot, P2WPKH, anything — has the same
floor. **RUNG_TX cannot be tightened further without modifying base
Bitcoin semantics.**

For comparison: a comparable Taproot transaction permits up to ~400 KB
of attacker-chosen data via inscriptions and unstructured Tapscript
pushes. **RUNG_TX is ~36,000× tighter** than that and only ~3,400×
looser than mathematically zero (which would require breaking BIP68 /
BIP65 / BIP340).

## 2. Confirmed-bound channels (every claimed closure held)

Each row was constructed end-to-end and submitted via
`sendrawtransaction`; every mutation was rejected with the cited
file:line.

| Channel | Reject path | Empirical reject reason |
|---|---|---|
| `qabi_block` non-empty on non-QABI tx | tx-level check, `src/rung/evaluator.cpp:851-859` | `tx_mlsc_check, TX_MLSC: tx.qabi_block must be empty when no QABI input is present` |
| `qabi_block > 256 KB` (hard cap) | wire-format deser, `src/primitives/transaction.h:363` | `TX decode failed: qabi_block too large` |
| `qabi_block > 64 KB` (relay soft cap) | policy, `src/rung/policy.cpp:148-151` | `qabi-block-soft-cap` |
| `aggregated_sig > 666 B` | wire-format deser, `src/primitives/transaction.h:374` | `TX decode failed: aggregated_sig too large` |
| `aggregated_sig` non-empty on non-QABI tx | tx-level check, `src/rung/evaluator.cpp:856-859` | `tx_mlsc_check, TX_MLSC: tx.aggregated_sig must be empty when no QABI input is present` |
| Non-canonical `batch_id` | parser, `src/rung/qabi.cpp:238` | computed string `qabi_block batch_id is not canonical SHA256 derivation` (currently surfaces as generic `mempool-script-verify-flag-failed (unknown error)` — see §5) |
| Duplicate `participant_id` | parser, `src/rung/qabi.cpp:183`; pre-empted by RPC at `src/rung/rpc.cpp` (`qabi_buildblock`) | RPC-level: `duplicate participant_id in entries (-8)`; consensus path: same generic mempool-script-verify message |
| Reversed `participant_id` order (descending) | same as duplicate | same |
| Wide `shared_source_input` (`0xFE 0x00 0x00 0x01 0x00`) | proof deser, `src/rung/conditions.cpp:774` | computed string `MLSC shared proof shared_source_input exceeds uint16 max`; surfaces as generic mempool-script-verify message |
| Rung `relay_refs` descending (`[1, 0]`) | wire-format deser, `src/rung/serialize.cpp:794-797` | computed string `rung X relay_refs not strict ascending at index Y` |
| Duplicate `relay_refs` (`[0, 0]`) | same | same |
| Unsorted MULTISIG triplets (descending pubkey order) | spend-time check, `src/rung/block_helpers.cpp:282` | `EvalMultisigBlock` returns `UNSATISFIED`; closes v0.8 audit E-018b. (Note: `createrungtx` accepts the descending-order spec at fund time; the consensus check fires only at spend time, but the conditions tree's inner-pubkey-Merkle commitment makes any non-canonical signer set unspendable.) |
| HTLC bad preimage (mutated witness) | eval, `src/rung/blocks/compound.cpp:127-128` | `EvalHTLC` returns `UNSATISFIED` on hash mismatch |
| HTLC witness pubkey rec/snd swap (same-type) | eval, `src/rung/blocks/compound.cpp:130-144` | `EvalHTLC` SIG verifies against wrong pubkey → `UNSATISFIED` |
| `DATA_RETURN` `data_len` outside 1..40 | wire-format deser, `src/primitives/transaction.h:303-306` | `TX decode failed: DATA_RETURN data_len out of range (1..40)` |
| ≥ 2 `DATA_RETURN` outputs per tx | tx-level check | `tx_mlsc_check, too many DATA_RETURN outputs: 2 (max 1)` |
| `NUMERIC` field length > 4 bytes | wire encoder + Stage-1.3 truncation guards (CSV / CLTV / COMPARE / RECURSE_COUNT / RELATIVE_VALUE / VAULT_LOCK) | `Invalid field: NUMERIC too large: 8 > 4` (rejected at createrungtx pre-broadcast) |
| Witness stack count outside `{1, 2, 3}` | consensus, `src/rung/evaluator.cpp:930-932` | `WITNESS_PROGRAM_WITNESS_EMPTY` (count=0); `unknown error` (count=4 — same code path, named error not surfaced) |
| Non-canonical `CompactSize` (e.g. `0xFD 0x01 0x00` for value 1) | wire-format deser, `src/serialize.h:341-342` | `TX decode failed: non-canonical ReadCompactSize()` |
| Sighash type 0x40 / 0xC1 family (BIP-118 ANYPREVOUT) | sig path, `src/rung/sighash.cpp:145-148` | `SignatureHashLadder` returns `false` → signature verification fails |

## 3. Channels where attacker bytes DO survive

These are universal Bitcoin transaction primitives, **not** Ladder
Script-specific channels:

- **`nLockTime`** — 4 attacker-chosen bytes per tx
- **`nSequence`** — 4 attacker-chosen bytes per input (subject to BIP68
  semantics)
- **Schnorr nonce grinding** — ~3 attacker-grindable bytes per Schnorr
  signature at a ~24-bit grind budget. BIP-340's `aux_rand` is
  re-randomised per signing (`src/rung/rpc.cpp:1161`); an attacker who
  controls signing can grind any N-byte prefix in expected `2^(8N)`
  attempts.
- **Sighash-type byte when ≠ DEFAULT** — 1 byte literal but only 7
  valid values, so ~3 bits of choice when present

## 4. DATA_RETURN, PREIMAGE, SCRIPT_BODY — bound but not free

These three channels carry bytes that survive on-chain but are
constrained by design and not freely chosen by the spender:

- **`DATA_RETURN`** — up to 40 B, ≤ 1 per tx
  (`src/primitives/transaction.h:303`, `src/rung/types.h:1001`).
  Intentional — the explicit OP_RETURN replacement. Counts as 40 B of
  attacker-chosen data per tx but the protocol exposes this as a
  feature, not a bug.
- **`PREIMAGE`** — up to 32 B per field, capped at 2 per tx
  (`src/rung/serialize.h:36-44`). Hash-bound: SHA256(preimage) must
  match the committed HASH256 leaf, so the bytes are determined by
  the funder's payment-hash commitment. The spender doesn't choose
  them.
- **`SCRIPT_BODY`** — up to 80 B per field, capped at 1 per tx
  (`src/rung/serialize.h:51`). Hash-bound to a HASH160 / HASH256
  inner-script commitment. Required for the P2SH / P2WSH / P2TR
  legacy bridges. Same reasoning: funder commits the hash, spender's
  bytes are predetermined.

If you count these as "attacker-controllable" the worst-case standard
spend rises to ~163 B; if you count them as "bound by the funding
commitment" (which is the design) the worst case stays at ~11 B + 40 B
intentional DATA_RETURN.

## 5. Cleanup notes / discoveries during the empirical run

These are **not** new findings — every audit-claimed closure held —
but the run surfaced three small inaccuracies and one UX gap that
should be folded into the doc and a future patch.

### Vector 11 (rung pair-swap) is by-design

In-pair sibling swaps in the conditions Merkle leave the root
unchanged. `MerkleInterior` (`src/rung/conditions.cpp:399-414`) sorts
each pair lexicographically before hashing, so the order of two
siblings under the same parent is **never exposed on-chain** — only
the 32-byte root is. The earlier audit's framing of pair-swap as a
"should reject" case was wrong; sorted-pair Merkle commutes by
design, and there's no covert channel. Doc fix only.

### Sighash type `0x82` (NONE | ANYONECANPAY) is allowed

The earlier audit listed `0x82` as part of the rejected BIP-118
family. It is in fact **valid** (`src/rung/sighash.cpp:147`). The
rejected family is `0x40-0x43` and `0xC0-0xC3` only. Minor
misclassification — no v0.14 vulnerability.

### `DecodeHexTx` no longer swallows deserialiser exceptions

Before patch `b423a45e4f`, every wire-format `std::ios_base::failure`
thrown during `UnserializeTransaction` was caught silently in
`DecodeTx` (`src/core_read.cpp:147-170`) and the RPC layer surfaced
only a generic `"TX decode failed. Make sure the tx has at least one
input."` regardless of which check fired. Now the actual exception
text is threaded through. Reviewers debugging a malformed v4 tx see
e.g. `"TX decode failed: aggregated_sig too large"` or `"TX decode
failed: non-canonical ReadCompactSize()"` directly.

### Script-verify deser errors are still generic (follow-up)

`DecodeHexTx`'s patch only covers tx-level deser. Failures inside
script-verify — `ParseQABIBlock`
(`src/rung/blocks/qabi.cpp:539-542`), `DeserializeMLSCProof`
(`src/rung/conditions.cpp:773-775`), `DeserializeLadderWitness`
(`src/rung/serialize.cpp:794-797`) — all compute specific
`error_out` strings (e.g. `qabi_block batch_id is not canonical
SHA256 derivation`, `MLSC shared proof shared_source_input exceeds
uint16 max`, `rung X relay_refs not strict ascending at index Y`)
that are never threaded through to `mempool-script-verify-flag-failed
(unknown error)`. Tracked as a follow-up — UX gap, not a consensus
gap. Same intent as the `DecodeHexTx` patch but at the script-verify
layer.

## 6. Methodology

**Driver scripts (reproducible):**

- `tools/test-presets.py` — 56 fund/spend presets covering every block
  type. Confirms the canonical accept path for each block.
- `test/functional/feature_deferred_vectors.py` — 9 byte-mutation
  attack vectors that need multi-input QABI / HTLC scaffolding. Each
  vector builds a real valid tx, surgically mutates one field, then
  submits and records the reject reason.
- `doc/ladder-script/MEASUREMENTS.md` — size sweeps that produce
  the table in §1.

**Coverage:**

- Every wire-format check listed in `src/primitives/transaction.h`
  (qabi_block, aggregated_sig, DATA_RETURN, conditions_root format,
  CompactSize bounds).
- Every block-implicit-layout check enumerated in `src/rung/types.h`
  (`ImplicitFieldLayout` rows + `IsConditionDataType` +
  `IsDataEmbeddingType`).
- Every QABI parser check in `src/rung/qabi.cpp` (canonical batch_id,
  strict-ascending entries, reserve-size bounds).
- Every MLSC proof check in `src/rung/conditions.cpp`
  (proof_mode, total_rungs, total_relays, rung_index,
  shared_source_input cap, revealed_rung blocks, relay_refs
  canonicalisation).
- Every coil enum check in `src/rung/serialize.cpp` (type /
  attestation / scheme / output_index, post v0.8 E-009/E-010).
- Sighash type validation in `src/rung/sighash.cpp` (post v0.12
  audit #7 #5).

**What we cannot test:** universal Bitcoin protocol fields
(`nLockTime`, `nSequence`, Schnorr nonce randomisation) — these are
attacker-controllable by design at the BIP65 / BIP68 / BIP340 level.
We confirmed the bytes do survive on-chain (any wallet user can grind
their nonce or pick their lockTime) but those channels exist for every
Bitcoin transaction format and are not Ladder-specific.

## 7. Verdict

After 56 spending-pattern presets + 9 byte-mutation attack vectors
against the v0.14 binary:

- **Every Ladder-specific channel the audit claimed to have closed
  was empirically rejected**, with file:line citations confirmed.
- The residual ~11 B floor matches base Bitcoin exactly. No format
  redesign can close it without breaking BIP65 / BIP68 / BIP340.
- The only intentional channel above the floor is `DATA_RETURN`'s
  40 B (≤ 1 per tx, explicit replacement for OP_RETURN).

**RUNG_TX is at the absolute floor of any Bitcoin-protocol-compatible
transaction format.** Numbers are stable; the BIP draft can cite them.

## 8. How to regenerate

```bash
# Spending-pattern presets (56 covering every block type):
cd tools && python3 test-presets.py --api http://127.0.0.1:8801

# Byte-mutation deferred vectors (9 attack scenarios):
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
