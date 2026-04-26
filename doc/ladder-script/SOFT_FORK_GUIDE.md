# Ladder Script Soft Fork Guide

How Ladder Script activates as a soft fork on Bitcoin. All 65 block types
activate together in a single deployment. Transactions use
`RUNG_TX_VERSION = 4`.

## Phased Approach

Ladder Script is not proposed as a direct mainnet deployment. The path to activation:

### Phase 1: Signet Proof (CURRENT)

Live signet at `85.9.213.194` with all 65 active block types verified
end-to-end. Engine, descriptor notation, and RPC tooling operational.
External review and testing invited. BIP-XXXX submitted for community
feedback.

**Status:** All 65 block types have fund+spend proof with recorded
transaction IDs. The signet mines every 10 minutes with real wall-clock
timestamps.

### Phase 2: External Review

Bitcoin Core developers and the broader community review:
- The 805-line integration patch to existing Bitcoin Core code (29 files)
- The 19,336-line self-contained `src/rung/` library (39 files)
- The 27 TLA+ formal specifications under `spec/`
- The anti-spam hardening and evaluation semantics

Fuzz testing targets are being expanded. Third-party adversarial testing encouraged
on the live signet.

### Phase 3: Activation — Coexistence

BIP 9 version bits signaling. At activation height:

- **v4 RUNG_TX transactions are valid alongside legacy transactions.** Both
  legacy Bitcoin Script (v1/v2 transactions) and Ladder Script (v4
  transactions) coexist on the same chain. Nodes validate each version
  with its respective rules.
- All 65 Ladder Script block types activate simultaneously. No phased
  block type rollout.
- The Legacy family (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT)
  allows wrapping existing Bitcoin output formats inside Ladder Script
  conditions, enabling migration from legacy to Ladder Script at the
  wallet's pace.
- `RUNG_VERIFY_MLSC_ONLY` flag enforced: v4 outputs must use MLSC
  (`0xDF` prefix). Inline conditions (`0xC1`) — an earlier design that
  was removed before the cleanup pass — remain rejected as a defence in
  depth.

**This phase is non-disruptive.** Existing wallets, transactions, and scripts continue
to work exactly as before. Ladder Script is opt-in — only wallets that create v4
transactions use it.

### Phase 4: Migration — Legacy Wrappers

Once Ladder Script adoption reaches sufficient levels:

- Encourage wallets to migrate from legacy output types (P2PKH, P2WSH, etc.) to their
  Ladder Script equivalents (P2PKH_LEGACY, P2WSH_LEGACY wrapped in v4 RUNG_TX).
- The Legacy block family provides 1:1 equivalents for every Bitcoin output type:
  `p2pkh(@key)`, `p2wsh(inner_hex)`, `p2tr(@key)`, etc.
- Wallets gain access to Ladder Script features (inversion, multi-rung OR paths,
  recursive covenants) while maintaining backward-compatible output formats.
- No consensus change required — this is a wallet-level migration.

### Phase 5: Sunset — RUNG_TX Only (Future)

A future soft fork could make v4 RUNG_TX the only valid transaction format:

- Legacy transaction versions (v1/v2) would be rejected in new blocks.
- All spending must go through the Ladder Script evaluator.
- The Legacy block family ensures no loss of functionality — every Bitcoin Script
  pattern has a Ladder Script equivalent.
- This eliminates the opcode-based attack surface entirely.

**This phase is far future** and would require its own BIP, community consensus,
and a long migration window. It is not part of the initial activation proposal.

### Why All Block Types Activate Together

Individual block type activation would create combinatorial complexity in testing
and validation. Each block type's evaluation is independent and self-contained.
The anti-spam rules and wire format are designed as a coherent system. Activating
subsets would require maintaining multiple validation codepaths.

## Activation Mechanics

Ladder Script introduces transaction version 4 (`RUNG_TX`). Pre-activation nodes treat v4
transactions as anyone-can-spend (standard soft fork semantics). Post-activation nodes
enforce the full Ladder Script validation rules.

## Output Format

All v4 transaction outputs use Merkelised Ladder Script Conditions
(MLSC):

```
Each output: 8 bytes (value only) on the wire — TX_MLSC encoding
Shared per transaction: 0xDF + conditions_root (32 bytes)
Flag byte 0x02 signals TX_MLSC serialisation format
```

One shared `conditions_root` per transaction. Each rung's coil has an
`output_index` field declaring which output it governs (PLC model: one
program, multiple output coils). The 32-byte root is recovered at spend
time from the synthetic root coin written at `(txid,
MLSC_ROOT_VOUT = 0xFFFFFFFF)` — see [`ANNOTATED_DIFF.md` §3](ANNOTATED_DIFF.md)
for the chainstate-deduplication mechanism.

`ValidateRungOutputs()` in `evaluator.cpp` enforces as a consensus rule
that every output of a v4 transaction must be a valid MLSC output
(`0xDF` prefix) or a DATA_RETURN output (`nValue == 0` + 1..40 bytes of
data, exactly one per transaction). Raw OP_RETURN and legacy
scriptPubKey types are rejected on v4.

## Consensus Validation Changes

### Transaction-Level

`VerifyRungTx()` in `evaluator.cpp` is the top-level entry point.

**Per-transaction (`CheckRungTxLevel`, runs once per tx):**

1. `ValidateRungOutputs()`: every output must be MLSC (`0xDF`), max 1
   DATA_RETURN, non-DATA_RETURN outputs ≥ `MIN_RUNG_OUTPUT_VALUE`
   (546 sats).
2. PREIMAGE/SCRIPT_BODY count across all inputs ≤
   `MAX_PREIMAGE_FIELDS_PER_TX` (2).
3. Cross-input invariants: PQ_BATCH cache consistency, QABIO output-set
   binding (when applicable).

**Per-input:**

4. Witness stack size determines spending path (1, 2, or 3 elements).
5. **Key-path** (1 element): verify Schnorr signature against conditions_root as
   x-only pubkey via `SignatureHashLadderKeyPath`. Done — no conditions revealed.
6. **Script-path** (2-3 elements): deserialise `LadderWitness` (stack[0]) and
   `MLSCProof` (stack[1]). The deserialiser enforces all structural limits:
   - `MAX_RUNGS = 16`, `MAX_BLOCKS_PER_RUNG = 8`, `MAX_FIELDS_PER_BLOCK = 16`
   - `MAX_LADDER_WITNESS_SIZE = 100000`
   - `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2` (per-input fast reject)
   - `MAX_RELAYS = 8`, `MAX_RELAY_DEPTH = 4`
   - Known block types only, non-invertible blocks cannot have `inverted = true`
   - Implicit layout enforcement, `IsDataEmbeddingType` rejection, DATA restriction
7. Extract pubkeys via `ExtractBlockPubkeys()` (merkle_pub_key).
8. Verify Merkle proof against conditions_root (or tweak for 3-element witness).
9. `MergeConditionsAndWitness()`: combine conditions from proof with witness fields.
10. `EvalLadder()`: evaluate relays (cached), then the revealed rung (AND/OR logic).

### Script Flags

`RUNG_VERIFY_MLSC_ONLY` (bit 28) is set for mainnet. When active, inline conditions (0xC1)
are always rejected; only MLSC (`0xDF`) is accepted. This
flag is checked in `ValidateRungOutputs()`.

### Integration Points

The soft fork modifies the following existing Bitcoin Core functions:

- **`CheckInputScripts()`** — detects v4 transactions and routes to `VerifyRungTx()`.
- **`CScriptCheck`** — extended to handle `SigVersion::LADDER`.
- **`GetBlockScriptFlags()`** — returns `RUNG_VERIFY_MLSC_ONLY` after activation height.

Pre-activation nodes see v4 transactions as valid (anyone-can-spend semantics). Post-activation
nodes enforce the full Ladder Script rules.

## Policy Changes

`IsStandardRungTx()` in `policy.cpp` provides mempool-level filtering:

1. Every input must have a non-empty witness that deserializes successfully via the consensus
   deserializer (`DeserializeLadderWitness`).
2. Every output must be MLSC (`IsMLSCScript()`).

Policy delegates all structural validation to the consensus deserializer. There is no
separate policy-only check for block types, field sizes, or layouts.

## Sighash

Ladder Script uses its own sighash algorithm: `SignatureHashLadder()` in
`sighash.cpp`. Similar to BIP-341 but without annex, tapscript, or
codeseparator extensions. Two tagged hashes:
`TaggedHash("LadderSighash/v1")` for script-path,
`TaggedHash("LadderKeyPathSighash/v1")` for key-path.

New sighash flags (BIP-118 analogues):
- `LADDER_SIGHASH_ANYPREVOUT = 0x40` — skip prevout commitment
- `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT = 0xC0` — skip prevout + conditions commitment

Valid hash types: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

## Block Types

All 65 block types activate simultaneously:

| Family | Types | Count |
|--------|-------|-------|
| Signature | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG | 5 |
| Timelock | CSV, CSV_TIME, CLTV, CLTV_TIME | 4 |
| Hash | TAGGED_HASH, HASH_GUARDED | 2 |
| Covenant | CTV, VAULT_LOCK, AMOUNT_LOCK | 3 |
| Recursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY | 6 |
| Anchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN | 7 |
| PLC | HYSTERESIS_FEE/VALUE, TIMER_CONTINUOUS/OFF_DELAY, LATCH_SET/RESET, COUNTER_DOWN/PRESET/UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN | 14 |
| Compound | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG, ANCHOR_FEE | 7 |
| Governance | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK | 7 |
| Legacy | P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY, P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY | 7 |
| QABI / PQ | QABI_PRIME, QABI_SPEND, PQ_BATCH | 3 |

Total: **65 across 11 families.**

## User-Chosen Data Limits

The soft fork limits user-chosen arbitrary data to 112 bytes per transaction. The following consensus rules enforce this:

1. **Fail-closed deserialization.** Unknown block types, unknown data types, and deprecated
   blocks are rejected at the wire format level.
2. **Selective inversion.** Explicit allowlist. Key-consuming blocks are never invertible.
3. **IsDataEmbeddingType.** PUBKEY_COMMIT, HASH256, HASH160, and DATA are blocked in blocks
   without implicit layouts.
4. **PREIMAGE/SCRIPT_BODY cap.** Maximum 2 per witness (combined), bounding user-chosen arbitrary
   data to 64 bytes.
5. **DATA type restriction.** Only allowed in DATA_RETURN blocks.
6. **merkle_pub_key.** Pubkeys folded into Merkle leaves, not stored as condition fields.
7. **Relay chain depth cap.** Maximum 4 levels of relay chaining.

## Test Coverage

| Suite | Count | Purpose |
|-------|-------|---------|
| Unit tests | 619 | All block evaluators, serialisation, Merkle tree, sighash, anti-spam (`rung_tests` + `qabi_tests` + `tx_mlsc_tests` boost suites combined) |
| Functional tests | 8 files / 52 methods | End-to-end regtest: create, sign, broadcast, verify v4 transactions (`feature_rung_tx.py`, `feature_rung_p2p.py`, `feature_rung_legacy.py`, `feature_rung_fuzz.py`, `feature_rung_pq_batch.py`, `feature_rung_pq_batch_stress.py`, `feature_qabi.py`, `feature_qabi_size.py`) |
| Signet verification | 65/65 | All active block types: fund + mine + spend on live signet with recorded txids |
| Engine + presets | 56 | `tools/test-presets.py` exercises 56 fund + spend ceremonies on live signet |
| TLA+ formal specs | 27 | Evaluation semantics, composition, anti-spam, wire format, Merkle, sighash, covenants, cross-input, per-family block evaluators |
| Fuzz targets | 1 (deserialiser) | `rung_deserialize_fuzz.cpp` — evaluator + sighash targets to be added |

All 27 TLA+ specifications under `spec/`:

**General evaluation (10):** `LadderEval`, `LadderEvalCheck`,
`LadderBlockEval`, `LadderComposition`, `LadderAntiSpam`,
`LadderWireFormat`, `LadderMerkle`, `LadderSighash`, `LadderCovenant`,
`LadderCrossInput`.

**Per-family block evaluators (10):** `BlockSignature`, `BlockTimelock`,
`BlockHash`, `BlockCovenant`, `BlockRecursion`, `BlockAnchor`, `BlockPLC`,
`BlockCompound`, `BlockGovernance`, `BlockLegacy`. The QABI / PQ surface
is covered by `LadderTxMLSC` and `LadderCrossInput`.

**Specialised invariants (7):** `LadderTxMLSC` (wire-format binding),
`AnchorFee`, `AutoKeyPath`, `HybridCreationProof`, `UTXODedup`,
`RecursiveCovenant`, `SharedProof`.

Bounded-state model checks pass cleanly. Full-constant runs on a
higher-RAM host are in progress.
