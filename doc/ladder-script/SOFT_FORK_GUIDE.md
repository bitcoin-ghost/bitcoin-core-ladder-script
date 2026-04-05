# Ladder Script Soft Fork Guide

How Ladder Script activates as a soft fork on Bitcoin. All 62 block types activate
together in a single deployment. Transactions use `RUNG_TX_VERSION = 4`.

## Phased Approach

Ladder Script is not proposed as a direct mainnet deployment. The path to activation:

### Phase 1: Signet Proof (CURRENT)

Live signet at `85.9.213.194` with all 62 active block types verified end-to-end.
Engine, descriptor notation, and RPC tooling operational. External review and testing
invited. BIP-XXXX submitted for community feedback.

**Status:** All 62 block types have fund+spend proof with recorded transaction IDs.
The signet mines every 10 minutes with real wall-clock timestamps.

### Phase 2: External Review

Bitcoin Core developers and the broader community review:
- The ~411-line integration patch to existing Bitcoin Core code
- The 14,771-line self-contained `src/rung/` library
- The 21 TLA+ formal specifications (80+ properties, 6.14M model-checked states)
- The anti-spam hardening and evaluation semantics

Fuzz testing targets are being expanded. Third-party adversarial testing encouraged
on the live signet.

### Phase 3: Activation — Coexistence

BIP 9 version bits signaling. At activation height:

- **v4 RUNG_TX transactions are valid alongside legacy transactions.** Both legacy
  Bitcoin Script (v1/v2 transactions) and Ladder Script (v4 transactions) coexist on
  the same chain. Nodes validate each version with its respective rules.
- All 62 Ladder Script block types activate simultaneously. No phased block type rollout.
- The Legacy family (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT) allows
  wrapping existing Bitcoin output formats inside Ladder Script conditions, enabling
  migration from legacy to Ladder Script at the wallet's pace.
- `RUNG_VERIFY_MLSC_ONLY` flag enforced: v4 outputs must use TX_MLSC (0xDF), not inline or per-output MLSC.

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

All v4 transaction outputs must use TX_MLSC (Transaction-level Merkelised Ladder Script
Conditions):

```
Each output: 8 bytes (value only)
Shared per transaction: 0xDF + conditions_root (32 bytes)
Flag byte 0x02 signals RUNG_TX serialization format
```

A creation proof in the witness section is validated at block acceptance. Each rung's
coil has an `output_index` field declaring which output it governs. One shared Merkle
tree per transaction (PLC model: one program, multiple output coils).

Inline conditions (0xC1) and per-output MLSC (0xC2) have been removed.
`ValidateRungOutputs()` in `evaluator.cpp` enforces this as a consensus rule: every
output of a v4 transaction must be a valid TX_MLSC output or a DATA_RETURN block (exactly
one per transaction, max 40 bytes). Raw OP_RETURN and legacy scriptPubKey types are
rejected.

## Consensus Validation Changes

### Transaction-Level

`VerifyRungTx()` in `evaluator.cpp` is the top-level entry point. For each input of a v4
transaction:

1. Witness `stack[0]` is deserialized via `DeserializeLadderWitness()`. The deserializer
   enforces all structural limits at consensus:
   - `MAX_RUNGS = 16`
   - `MAX_BLOCKS_PER_RUNG = 8`
   - `MAX_FIELDS_PER_BLOCK = 16`
   - `MAX_LADDER_WITNESS_SIZE = 100000`
   - `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2` (per-input fast reject)
   - `MAX_PREIMAGE_FIELDS_PER_TX = 2` (per-transaction binding constraint)
   - `MAX_RELAYS = 8`, `MAX_RELAY_DEPTH = 4`
   - Known block types only (`IsKnownBlockType` returns true)
   - Non-invertible block types cannot have `inverted = true`
   - Implicit layout enforcement (field count and types must match)
   - `IsDataEmbeddingType` rejection for layout-less blocks
   - DATA type restricted to DATA_RETURN blocks
   - No trailing bytes

2. Witness `stack[1]` is deserialized as an MLSC proof via `DeserializeMLSCProof()`.

3. `VerifyMLSCProof()` reconstructs the Merkle tree from revealed and proof data, verifies
   the computed root matches the UTXO's conditions root.

4. `EvalLadder()` evaluates relays (if any), then evaluates the revealed rung. All blocks
   in the rung must return `SATISFIED` (AND logic).

5. `BatchVerifier::Verify()` batch-verifies all collected Schnorr signatures.

6. `ValidateRungOutputs()` checks every output.

### Script Flags

`RUNG_VERIFY_MLSC_ONLY` (bit 28) is set for mainnet. When active, inline conditions (0xC1)
and per-output MLSC (0xC2) are always rejected; only TX_MLSC (0xDF) is accepted. This
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

Ladder Script uses its own sighash algorithm: `SignatureHashLadder()` in `sighash.cpp`.
It is similar to BIP-341 but without annex, tapscript, or codeseparator extensions.
Uses tagged hash `TaggedHash("LadderSighash")`.

New sighash flags (BIP-118 analogues):
- `LADDER_SIGHASH_ANYPREVOUT = 0x40` — skip prevout commitment
- `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT = 0xC0` — skip prevout + conditions commitment

Valid hash types: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

## Block Types

All 62 block types activate simultaneously:

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
| Legacy | P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT | 7 |

Total: 62

## Anti-Spam Hardening

The soft fork includes comprehensive anti-spam measures enforced at consensus:

1. **Fail-closed deserialization.** Unknown block types, unknown data types, and deprecated
   blocks are rejected at the wire format level.
2. **Selective inversion.** Explicit allowlist. Key-consuming blocks are never invertible.
3. **IsDataEmbeddingType.** PUBKEY_COMMIT, HASH256, HASH160, and DATA are blocked in blocks
   without implicit layouts.
4. **PREIMAGE/SCRIPT_BODY cap.** Maximum 2 per witness (combined), bounding user-chosen
   data to 64 bytes.
5. **DATA type restriction.** Only allowed in DATA_RETURN blocks.
6. **merkle_pub_key.** Pubkeys folded into Merkle leaves, not stored as condition fields.
7. **Relay chain depth cap.** Maximum 4 levels of relay chaining.

## Test Coverage

| Suite | Count | Purpose |
|-------|-------|---------|
| Unit tests | 528 | All block evaluators, serialization, Merkle tree, sighash, anti-spam |
| Functional tests | 60 | End-to-end regtest: create, sign, broadcast, verify v4 transactions |
| Signet verification | 62/62 | All active block types: fund + mine + spend on live signet with recorded txids |
| Documentation accuracy | 43 | types.h consistency, engine templates, block reference pages, markdown docs |
| Proxy unit tests | 15 | BIP32 derivation, base58, RIPEMD-160, WIF encoding |
| Engine smoke tests | 20 | 48 templates, 62 block types, getTypeHex coverage, dead code checks |
| TLA+ formal specs | 21 specs, 80+ properties, 6.14M states | Evaluation semantics, composition, anti-spam, wire format, Merkle, sighash, covenants, cross-input |
| Fuzz targets | 1 (deserializer) | `rung_deserialize_fuzz.cpp` — needs evaluator + sighash targets |

The first 10 of the 21 TLA+ specifications are:

1. **LadderEval** — rung/ladder evaluation with inversion and recursion termination
2. **LadderEvalCheck** — type invariants and safety properties
3. **LadderBlockEval** — individual block evaluation
4. **LadderComposition** — AND/OR composition with relays
5. **LadderAntiSpam** — anti-spam field limits
6. **LadderWireFormat** — serialization invariants
7. **LadderMerkle** — Merkle tree construction and verification
8. **LadderSighash** — sighash computation properties
9. **LadderCovenant** — covenant/recursion safety and termination
10. **LadderCrossInput** — cross-input (COSIGN) dependency safety
