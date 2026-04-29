# LADDER SCRIPT — Complete Block Library Reference

**Ladder Script · v1.0 · Draft**

---

## Table of Contents

1. [The Type System](#1-the-type-system)
2. [Signature Blocks](#2-signature-blocks)
3. [Timelock Blocks](#3-timelock-blocks)
4. [Hash Blocks](#4-hash-blocks)
5. [Covenant Blocks](#5-covenant-blocks)
6. [L2 Anchor Blocks](#6-l2-anchor-blocks)
7. [Recursive Covenant Blocks](#7-recursive-covenant-blocks)
8. [PLC Primitive Blocks](#8-plc-primitive-blocks)
9. [Contact Inversion — Normally Closed Contacts](#9-contact-inversion--normally-closed-contacts)
10. [Coil Types and Attestation Modes](#10-coil-types-and-attestation-modes)
11. [Complete Block Registry](#11-complete-block-registry)

---

## 1. The Type System

Every parameter in every block must be one of the following enumerated types. No untyped byte arrays exist in this format — an unknown type byte is a **parse error** before the transaction reaches the mempool.

| Type | Enum | Size | Constraint | Purpose |
|---|---|---|---|---|
| `PUBKEY` | `0x01` | 1–2048B | 32B x-only, 33B compressed, or PQ | EC/PQ public key — **witness only**. Conditions use merkle_pub_key (keys folded into Merkle leaf hash). |
| `PUBKEY_COMMIT` | `0x02` | 32B exact | *(Reserved)* | Removed by merkle_pub_key. Rejected in both conditions and witness. |
| `HASH256` | `0x03` | 32B exact | SHA-256 hash | State commitments, contract roots, anchors |
| `HASH160` | `0x04` | 20B exact | HASH160 | Legacy compatibility |
| `PREIMAGE` | `0x05` | 32B exact | SHA-256 preimage | Hash preimage reveal. Max 2 per witness and per transaction. |
| `SIGNATURE` | `0x06` | 1–50,000B | Schnorr=64B, ECDSA/DER≈73B, PQ up to 49,216B | INLINE attestation signatures only |
| `SPEND_INDEX` | `0x07` | 4B exact | uint32 spend index | Cross-input spend reference |
| `NUMERIC` | `0x08` | 1–8B | uint64 value | Timelocks, thresholds, counts, rates |
| `SCHEME` | `0x09` | 1B exact | Enum value from RungScheme | Signature algorithm selector |
| `SCRIPT_BODY` | `0x0A` | 1–80B | Serialised inner conditions | Legacy inner script delivery (P2SH/P2WSH/P2TR_SCRIPT). Witness-only. Shares PREIMAGE cap. |
| `DATA` | `0x0B` | 1–40B | Opaque data | DATA_RETURN blocks only. Rejected in all other block types. |

**Key principle:** Type enforcement happens at the deserializer — before any cryptographic operation, before mempool admission, before everything. PUBKEY is witness-only; conditions use merkle_pub_key (keys folded into the Merkle leaf hash — no key field in conditions at all). PUBKEY_COMMIT is reserved and rejected in both contexts. The condition data types are: HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX, DATA. Conditions contain zero user-chosen bytes. A maximum of 2 preimage-bearing fields are permitted per witness (`MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`, fast reject) and per transaction (`MAX_PREIMAGE_FIELDS_PER_TX = 2`, binding constraint across all inputs). The preimage-bearing blocks are TAGGED_HASH and HASH_GUARDED. Compound blocks HTLC and HASH_SIG also consume PREIMAGE fields. Enum values `0x0201` and `0x0202` are reserved and rejected at deserialization. This is what makes spam structurally impossible.

**TX_MLSC conditions:** Each output is 8 bytes (value only); the RUNG_TX carries one shared `conditions_root` with MLSC prefix byte `0xDF`. A creation proof in the witness is validated at block acceptance. Leaf computation uses `TaggedHash("LadderLeaf", structural_template || value_commitment)`. One shared Merkle tree per transaction (PLC model: one program, multiple output coils). Each rung's coil has an `output_index` field declaring which output it governs. Anti-spam surface: 112 bytes per transaction (flat, no contiguous block). UTXO spam: zero readable attacker data (root is protocol-derived). Simple payment: 110 vB (key-path, 1-in-1-out) / 118 vB (key-path, 1-in-2-out) / 124 vB (script-path SIG+CSV). Batch 100: 914 vB (71% cheaper than P2WPKH).

---

## 2. Signature Blocks

Signature blocks verify cryptographic proofs of authorisation. Signature blocks are key-consuming and therefore **not invertible** — inverting them would allow garbage-pubkey data embedding.

---

### `SIG` · `0x0001`

Verifies a single signature from a specified key under a specified scheme.

**Condition params:** `SCHEME scheme` (public key folded into Merkle leaf via merkle_pub_key)
**Witness params:** `PUBKEY key` · `SIGNATURE sig`

**Invertible:** No

**Use case:** Single-key payment, hot wallet spend, daily limit key

---

### `MULTISIG` · `0x0002`

Verifies n-of-m threshold signatures. Keys folded into Merkle leaf, signatures in witness.

**Condition params:** `NUMERIC threshold` (public keys folded into Merkle leaf via merkle_pub_key)
**Witness params:** `PUBKEY[N] keys` · `SIGNATURE[M] sigs`

**Invertible:** No

**Use case:** Corporate custody, cold storage, DAO multisig

---

### `ADAPTOR_SIG` · `0x0003`

Verifies an adaptor signature — a signature that becomes valid when combined with a secret adaptor point. Foundation of DLCs and atomic swaps.

**Condition params:** (explicit fields; both pubkeys folded into Merkle leaf — PubkeyCountForBlock = 2)
**Witness params:** `PUBKEY adaptor_point` · `PUBKEY signing_key` · `SIGNATURE adapted_sig`

**Invertible:** No

**Use case:** DLC oracle-attested contracts, cross-chain atomic swaps, point time-lock contracts

---

### `MUSIG_THRESHOLD` · `0x0004`

Aggregate threshold signature verification. The conditions commit NUMERIC fields for M and N. The aggregate public key is folded into the Merkle leaf. The witness provides the aggregate public key and a single Schnorr signature. The threshold signing ceremony occurs entirely off-chain; on-chain the spend is indistinguishable from a single-sig SIG block.

**Condition params:** `NUMERIC threshold_m` · `NUMERIC group_size_n` (aggregate key folded into Merkle leaf)
**Witness params:** `PUBKEY aggregate_key` · `SIGNATURE aggregate_sig`

**Invertible:** No

**Use case:** MuSig2/FROST threshold signing, key-aggregated multisig, privacy-preserving quorums

---

### `KEY_REF_SIG` · `0x0005`

Signature using a key resolved from a relay block. Enables multiple rungs to share a single key defined in a relay, avoiding duplication. PubkeyCountForBlock = 0 (key resolved from relay, not folded into this rung's leaf).

**Condition params:** `NUMERIC relay_index` · `NUMERIC block_index`
**Witness params:** `SIGNATURE sig`

**Invertible:** No

**Use case:** Multi-rung ladders sharing a common key, relay-based key indirection, reducing conditions size

---

### Signature Schemes

| Scheme | Enum | Sig Size | Notes |
|---|---|---|---|
| `SCHNORR` | `0x01` | 64 bytes | BIP-340. Primary scheme. Batch-verifiable. Use by default. |
| `ECDSA` | `0x02` | ~73 bytes | Legacy compatibility only. DER-encoded. Not batch-verifiable. |
| `FALCON512` | `0x10` | 666 bytes | NIST PQC standard. Post-quantum secure. |
| `FALCON1024` | `0x11` | 1280 bytes | Post-quantum. Higher security level. 256-bit post-quantum security. |
| `DILITHIUM3` | `0x12` | 3293 bytes | NIST PQC standard. Better batch verification properties than FALCON. |
| `SPHINCS_SHA` | `0x13` | 49,216 bytes | Post-quantum. Hash-based. Most conservative PQ assumption. |

---

## 3. Timelock Blocks

Timelock blocks enforce temporal spending constraints. All timelock blocks are invertible — an inverted timelock creates a **spend BEFORE** condition, a genuinely new Bitcoin primitive with no current equivalent in Bitcoin Script.

---

### `CSV` · `0x0101`

Check Sequence Verify. Input sequence number must be >= required blocks since UTXO creation. Relative block-height timelock.

**Params:** `NUMERIC blocks`

**Invertible:** Yes

**Use case:** Lightning channel breach remedy delay, vault recovery path, inheritance fallback

**Inverted semantics:** Passes BEFORE timeout. Enables breach remedy windows — `[/CSV: 144]` means "only valid in the first 144 blocks after spend attempt". New Bitcoin primitive with no current equivalent.

---

### `CSV_TIME` · `0x0102`

CSV by median-time-past. Input sequence encodes seconds rather than blocks.

**Params:** `NUMERIC seconds`

**Invertible:** Yes

**Use case:** Time-based payment channels, calendar-aligned spending windows

---

### `CLTV` · `0x0103`

Check Lock Time Verify. Transaction locktime must be >= required block height. Absolute block-height timelock.

**Params:** `NUMERIC height`

**Invertible:** Yes

**Use case:** Expiry dates, deadline enforcement, dated covenant termination

**Inverted semantics:** Passes BEFORE block height. Dead man's switch — `[/CLTV: 52000] [SIG: owner]` means owner must act before block 52000 or the fallback rung activates.

---

### `CLTV_TIME` · `0x0104`

CLTV by median-time-past. Locktime encodes Unix timestamp.

**Params:** `NUMERIC timestamp`

**Invertible:** Yes

**Use case:** Calendar date deadlines, time-of-day spending restrictions

---

## 4. Hash Blocks

Hash blocks verify preimage knowledge. Invertible hash blocks enable spend-if-NOT-revealed conditions — the refund path in HTLCs expressed as a first-class typed block.

---

### `TAGGED_HASH` · `0x0203`

BIP-340 tagged hash verification. Domain-separated hash prevents cross-context collisions.

**Params:** `HASH256 tag_hash` · `HASH256 expected_hash`

**Invertible:** Yes

**Use case:** Schnorr key tweaking, Taproot-style commitments, domain-separated proofs

---

### `HASH_GUARDED` · `0x0204`

Raw SHA-256 preimage verification. Non-invertible replacement for deprecated HASH_PREIMAGE.

**Condition params:** `HASH256 committed_hash`
**Witness params:** `PREIMAGE preimage`

**Evaluation:** SHA256(preimage) == committed_hash → SATISFIED

**Invertible:** No (fail-closed default — not in `IsInvertibleBlockType`)

**PubkeyCountForBlock:** 0 (not key-consuming)

**Use case:** Standalone hash lock without requiring a co-signature. Safe alternative to the deprecated HASH_PREIMAGE for cases where HTLC or HASH_SIG are not needed — e.g., revealing a commitment, proving data knowledge, or gating a spending path on preimage disclosure.

**Anti-spam safety:** Unlike the deprecated HASH_PREIMAGE, HASH_GUARDED is non-invertible. An attacker cannot use an inverted HASH_GUARDED with a garbage hash to embed arbitrary data — the block is rejected at deserialization if the inverted flag is set.

---

## 5. Covenant Blocks

Covenant blocks constrain how a UTXO can be spent — what outputs it must produce, what amounts must be preserved, what scripts the outputs must carry.

All Ladder Script covenant blocks are bounded by the type system: no accidental recursion, no unbounded encumbrance. The type system makes covenant expressiveness auditable — every constraint is a typed parameter.

---

### `CTV` · `0x0301`

CheckTemplateVerify. Output must spend to a specific pre-committed transaction template. Enables payment trees, batch payments, and non-interactive channel opens.

**Params:** `HASH256 template_hash`

**Invertible:** Yes

**Use case:** Payment trees, batch channel opens, non-interactive vaults, congestion control

**Note:** Addresses CTV/BIP-119 use cases in a typed, auditable block. Cannot create recursive covenants alone — template is fixed at creation time.

---

### `VAULT_LOCK` · `0x0302`

Two-path vault. Hot path requires delay. Cold recovery key can always sweep. Classic vault construction as a single typed block.

**Condition params:** `NUMERIC hot_delay` (recovery and hot keys folded into Merkle leaf — PubkeyCountForBlock = 2)
**Witness params:** `PUBKEY recovery_key` · `PUBKEY hot_key` · `SIGNATURE sig`

**Invertible:** No

**Use case:** Cold storage vault, exchange reserve, high-value custody with recovery

---

### `AMOUNT_LOCK` · `0x0303`

Output amount must fall within specified range. Prevents fee manipulation attacks and enforces expected payment amounts.

**Params:** `NUMERIC min_sats` · `NUMERIC max_sats`

**Invertible:** Yes

**Use case:** Lightning close amount verification, payment amount enforcement, fee attack prevention

---

## 6. L2 Anchor Blocks

Anchor blocks provide a standardised mechanism for L2 protocols to commit state to L1.

**Every anchor block carries:**
- `state_root` (HASH256) — L2 state commitment, opaque to L1
- `protocol_id` (HASH256) — which L2 protocol (standardised hash registry)
- `sequence_number` (NUMERIC) — monotonically increasing, anti-rollback at consensus level

**What this enables:**
- Universal watchtower support across all L2 protocols
- Cross-protocol composability (e.g. Lightning channel carrying RGB assets)
- L2 state visible at L1 without trusting L2 operators
- 50–86% smaller L2 anchor transactions

---

### `ANCHOR` · `0x0501`

Generic L2 state anchor. Any protocol can commit a state root to L1 with monotonic sequence number protection.

**Params:** `HASH256 state_root` · `HASH256 protocol_id` · `NUMERIC sequence_number`

**Use case:** Custom L2 protocols, experimental state commitments, RGB-style seals

---

### `ANCHOR_CHANNEL` · `0x0502`

Payment channel anchor. Carries channel state root, commitment number, funding keys, and HTLC payment hash. Enables universal watchtower monitoring across all Lightning implementations.

**Params:** `NUMERIC commitment_number` (local and remote keys folded into Merkle leaf — PubkeyCountForBlock = 2)

**Use case:** Lightning channels, Ghost Pay channels, any HTLC-based payment channel

**Note:** Commitment tx drops from ~300 vB to ~100 vB. Breach remedy drops from ~170 vB to ~50 vB (71% smaller) — directly improves Lightning security under high fee conditions.

---

### `ANCHOR_POOL` · `0x0503`

Shared UTXO pool anchor (Ark-style). Carries VTXO merkle tree root for all participants. One on-chain output represents N participants. Combined with `RECURSE_SPLIT` enables trustless unilateral exit.

**Params:** `HASH256 vtxo_tree_root` · `HASH256 protocol_id` · `NUMERIC round_number` · `NUMERIC participant_count` · `NUMERIC expiry_height` (ASP key folded into Merkle leaf)

**Use case:** Ark protocol, shared UTXO pools, payment pool factories

**Note:** Round tx drops from ~18 vB per participant to ~2.5 vB per participant — 86% reduction.

---

### `ANCHOR_RESERVE` · `0x0504`

Federation reserve anchor (Fedimint/Liquid-style). Carries epoch hash, guardian set hash, and emergency recovery parameters.

**Params:** `HASH256 epoch_hash` · `HASH256 protocol_id` · `NUMERIC epoch_number` · `NUMERIC threshold_n` · `NUMERIC threshold_m` · `HASH256 guardian_set_hash` · `NUMERIC emergency_height`

**Use case:** Fedimint federation, Liquid peg mechanism, institutional multisig custody

---

### `ANCHOR_SEAL` · `0x0505`

Single-use seal (RGB-style). Replaces OP_RETURN for asset state commitments. The asset state transition hash is a typed `HASH256` parameter rather than arbitrary OP_RETURN data.

**Params:** `HASH256 state_transition` · `HASH256 protocol_id` · `HASH256 asset_id` · `NUMERIC sequence_number`

**Use case:** RGB asset issuance and transfer, client-side validation protocols, token commitments

**Note:** Eliminates need for OP_RETURN. Asset commitment is a typed first-class parameter, not arbitrary data.

---

### `ANCHOR_ORACLE` · `0x0506`

Oracle-attested contract anchor (DLC-style). Commits the full contract outcome tree root and oracle parameters. Any outcome can be revealed via merkle proof at settlement.

**Params:** `NUMERIC outcome_count` (oracle key folded into Merkle leaf — PubkeyCountForBlock = 1)

**Use case:** DLC contracts, prediction markets, oracle-attested conditional payments

**Note:** DLC close tx drops from ~200 vB to ~90 vB. Oracle key in typed PUBKEY param rather than bespoke script.

---

## 7. Recursive Covenant Blocks

Recursive covenant blocks propagate spending conditions forward through a chain of UTXOs.

### Four Mandatory Safety Properties

All recursive blocks enforce these at consensus level:

1. **Explicit termination** — every recursive block requires a termination condition as a mandatory typed param. A covenant that recurses forever is a parse error — rejected before mempool.
2. **Value conservation** — recursive blocks must prove value is conserved or strictly decreasing. Covenant amplification is consensus-invalid.
3. **Typed mutation** — `RECURSE_MODIFIED` carries an explicit typed mutation spec. What changes between recursion levels is a typed, auditable parameter.
4. **No whitelist covenants** — there is no `ADDRESS_WHITELIST` block type. Government-enforced address restrictions cannot be constructed. Adding such a block requires an explicit, publicly debated softfork.

---

### `RECURSE_SAME` · `0x0401`

Output inherits the identical rung set as the input. Covenant propagates forward unchanged.

**Params:** `NUMERIC max_depth`

**Use case:** Perpetual custody rules, sustained governance covenants, channel state propagation


---

### `RECURSE_MODIFIED` · `0x0402`

Output inherits rung set with one typed mutation applied per recursion. The mutation is fully specified in params — no implicit changes.

**Params:** `NUMERIC max_depth` · `NUMERIC mutation_block_idx` · `NUMERIC mutation_param_idx` · `NUMERIC mutation_delta`

**Use case:** Decaying multisig thresholds, relaxing timelocks, escalating access over time

**Note:** Example — reduce CSV by 144 per recursion, each spend makes the next spend faster. Enables timeout-accelerating vaults.

---

### `RECURSE_UNTIL` · `0x0403`

Recurse until a termination block height is reached. After that height the covenant terminates and coins are unconditionally free.

**Params:** `NUMERIC until_height`

**Use case:** Time-bounded custody, expiring governance rules, temporary spending restrictions

**Note:** Fungibility restoration — coins are unconditionally free after `until_height`. Directly addresses the permanent encumbrance concern about covenants.

---

### `RECURSE_COUNT` · `0x0404`

Recurse exactly N times. After N recursions the covenant terminates. Counter verifiable on-chain via sequence numbers.

**Params:** `NUMERIC max_count`

**Use case:** Fixed-term custody agreements, N-round DLC resolution, graduated vesting schedules

---

### `RECURSE_SPLIT` · `0x0405`

Split output value, each piece re-encumbers with the same rung set minus one recursion count. Enables streaming and pool exit patterns.

**Params:** `NUMERIC max_splits` · `NUMERIC min_split_sats`

**Use case:** Salary streaming, subscription payments, Ark pool participant exit, vesting releases

**Note:** Combined with `ANCHOR_POOL` — each participant exit reduces the pool by their share, remainder re-encumbers automatically. This is what Ark has always needed from covenants.

---

### `RECURSE_DECAY` · `0x0406`

Each recursion relaxes one constraint. Uses `RECURSE_MODIFIED` semantics with negative delta. Inheritance and dead man's switch patterns.

**Params:** `NUMERIC max_depth` · `NUMERIC decay_block_idx` · `NUMERIC decay_param_idx` · `NUMERIC decay_per_step`

**Use case:** Inheritance with decreasing multisig requirement, gradually relaxing custody over time

**Note:** Example — starts 3-of-5 multisig, reduces by 1 per CSV period. After 3 periods any single heir can claim. Probate-free inheritance on Bitcoin.

---

## 8. PLC Primitive Blocks

Industrial PLC (Programmable Logic Controller) systems solved the problem of controlling safety-critical state machines over time. Bitcoin UTXOs are value containers that need to be controlled safely over time. The state machines are structurally identical.

PLC engineers have built a 50-year library of proven primitives. Every one maps directly to a Bitcoin custody or payment need. Ladder Script makes the full PLC primitive library available to Bitcoin for the first time.

### PLC → Bitcoin Mapping

| PLC Primitive | Bitcoin Equivalent | Ladder Script Block | Key Property |
|---|---|---|---|
| Hysteresis | Fee-aware covenants | `HYSTERESIS_FEE / VALUE` | Band not threshold — prevents hunting |
| TON Timer (On-Delay) | Continuous liveness proofs | `TIMER_CONTINUOUS` | Must stay true for N consecutive blocks |
| TOF Timer (Off-Delay) | Dispute hold windows | `TIMER_OFF_DELAY` | Stays locked N blocks after trigger |
| SR Latch | Governance state propagation | `LATCH_SET / RESET` | On-chain state memory across UTXOs |
| Up/Down Counter | Payment streaming | `COUNTER_UP / DOWN / PRESET` | Count events, release on threshold |
| Comparator | Amount-conditional custody | `COMPARE` | Value range checks without oracle |
| Sequencer | Multi-stage contracts | `SEQUENCER` | Enforce ordered execution |
| Monoflop | Single-use emergency access | `ONE_SHOT` | Fires once, cannot repeat |
| PID / Rate Limiter | Exchange spending limits | `RATE_LIMIT` | Max spend per block, accumulating allowance |

---

### 8.1 Hysteresis Blocks

Hysteresis prevents rapid switching by requiring a value to cross a higher threshold to activate and a lower threshold to deactivate. Eliminates hunting behaviour.

#### `HYSTERESIS_FEE` · `0x0601`

Spending path activates when mempool fee rate exceeds `high_sat_vb` and deactivates when below `low_sat_vb`.

**Params:** `NUMERIC high_sat_vb` · `NUMERIC low_sat_vb`

**Use case:** Treasury management, batched payment covenants that wait for low-fee windows, preventing accidental high-fee spends

**Note:** Fee rate checked against mempool minimum at validation time.

---

#### `HYSTERESIS_VALUE` · `0x0602`

Spending path activates when UTXO value exceeds `high_sats` and deactivates when below `low_sats`. Forced savings — cannot repeatedly dip below the low threshold.

**Params:** `NUMERIC high_sats` · `NUMERIC low_sats`

**Use case:** Forced savings accounts, minimum balance enforcement, reserve floors

---

### 8.2 Timer Blocks

PLC timers are more expressive than simple timelocks. CSV/CLTV measure elapsed time from a point. Timers measure **continuous satisfaction** of a condition over a duration.

#### `TIMER_CONTINUOUS` · `0x0611`

Condition must be continuously satisfied for N consecutive blocks. If condition is interrupted, the timer resets. Enables liveness proofs.

**Params:** `NUMERIC required_blocks` · `HASH256 condition_commitment`

**Use case:** Proof of continued custody, inheritance liveness check, watchtower active proof

**Note:** Distinct from CSV — CSV measures blocks since spend. `TIMER_CONTINUOUS` measures blocks of continuous condition satisfaction. New primitive with no current Bitcoin equivalent.

---

#### `TIMER_OFF_DELAY` · `0x0612`

Output stays locked for `hold_blocks` after a trigger condition becomes false. Generalised dispute window.

**Params:** `NUMERIC hold_blocks` · `HASH256 trigger_commitment`

**Use case:** Dispute hold windows, generalised breach remedy, challenge periods

**Note:** Generalises Lightning's `to_self_delay` into a first-class typed block applicable to any protocol.

---

### 8.3 Latch Block (SR Flip-Flop)

A latch has two coils — Set and Reset. Once Set, output stays active until explicitly Reset. State persists through covenant chains via `ANCHOR` sequence numbers.

#### `LATCH_SET` · `0x0621`

Sets latch state for a specific `state_id`. Once set, `LATCH_RESET` is required to clear. State propagates through `RECURSE_SAME`.

**Params:** `NUMERIC state` (setter key folded into Merkle leaf — PubkeyCountForBlock = 1)

**Use case:** On-chain governance locking, DAO treasury freeze, dispute state initiation

---

#### `LATCH_RESET` · `0x0622`

Clears latch state for `state_id`. Requires `reset_delay` blocks after set before reset is valid.

**Params:** `NUMERIC state` · `NUMERIC delay` (resetter key folded into Merkle leaf — PubkeyCountForBlock = 1)

**Use case:** Governance unlock after veto period, dispute resolution, treasury unfreeze

**Note:** `reset_delay` prevents flash resets — a board cannot immediately override their own freeze.

---

### 8.4 Counter Blocks

Counters count on-chain events and activate when reaching a threshold. Each increment is an authorised transaction, making the count verifiable on-chain.

#### `COUNTER_DOWN` · `0x0631`

Starts at `initial_count`, decrements with each authorised event. Combined with `RECURSE_SPLIT` releases a fraction of value per decrement. Terminates at zero.

**Params:** `NUMERIC count` (event signer key folded into Merkle leaf — PubkeyCountForBlock = 1)

**Use case:** Salary streaming (100 weekly payments), subscription billing, N-installment purchase

**Note:** Native payment streaming on L1. Each authorised decrement releases 1/N of funds. No Lightning required.

---

#### `COUNTER_PRESET` · `0x0632`

Requires N separate approvals within a block window. Approvals are **separate transactions**, not a single multisig transaction. Fires coil once N is reached.

**Params:** `NUMERIC required_count` · `HASH256 proposal_hash` · `NUMERIC window_blocks`

**Use case:** Time-bounded multi-party approval, distributed governance, multi-round ratification

**Note:** Fundamentally different from `MULTISIG` — signatures do not need to be in the same transaction. Each approver submits independently within the window. Currently impossible in Bitcoin.

---

#### `COUNTER_UP` · `0x0633`

Starts at zero, increments with each qualifying event. Spending allowed only when count reaches threshold.

**Params:** `NUMERIC current` · `NUMERIC target` (event signer key folded into Merkle leaf — PubkeyCountForBlock = 1)

**Use case:** Milestone-based vesting, accumulation targets, proof-of-activity gates

---

### 8.5 Comparator Block

Comparators check relationships between values, enabling amount-conditional spending paths without an oracle.

#### `COMPARE` · `0x0641`

Evaluates a comparison between transaction amounts or block height and a threshold. Supports EQ, NEQ, GT, LT, GTE, LTE, IN_RANGE operators.

**Params:** `NUMERIC operator` · `NUMERIC value_b` · `NUMERIC value_c` (IN_RANGE upper bound)

**Invertible:** Yes

**Operator values:** `0x01`=EQ · `0x02`=NEQ · `0x03`=GT · `0x04`=LT · `0x05`=GTE · `0x06`=LTE · `0x07`=IN_RANGE

**Use case:** Tiered custody by amount, minimum balance enforcement, fee attack prevention, amount-conditional spending paths

**Note:** Combine with CONFIDENTIAL amounts for ZK amount range proofs without revealing exact values.

---

### 8.6 Sequencer Block

Sequencers enforce ordered multi-stage execution. Each stage only activates after the previous stage completes.

#### `SEQUENCER` · `0x0651`

Enforces that this spend is step `current_step` of `total_steps` for `sequence_id`. Cannot skip steps or repeat steps.

**Params:** `NUMERIC current_step` · `NUMERIC total_steps` · `HASH256 sequence_id`

**Use case:** Staged escrow, multi-round DLC resolution, milestone construction payments, vesting cliff schedules

**Note:** Each stage is a separate UTXO. `UNLOCK_TO` coil constrains next output to carry `SEQUENCER` block with `step+1`. No off-chain coordination needed.

---

### 8.7 One-Shot Block (Monoflop)

A monoflop fires exactly once for a fixed duration. After the duration expires it cannot fire again — even if the triggering condition occurs again.

#### `ONE_SHOT` · `0x0661`

Emergency spending window that can only be activated once. Opens a window of `duration_blocks` then locks permanently.

**Params:** `NUMERIC duration_blocks` · `HASH256 commitment`

**Use case:** Single-use emergency key, one-time recovery window, audit trigger that cannot be repeated

**Note:** Directly addresses compromised emergency key risk — even if the key is leaked, it can only open one window. Cannot be triggered repeatedly. Current Bitcoin has no equivalent.

---

### 8.8 Rate Limit Block

Rate limiting constrains the maximum value that can be unlocked per block, with an accumulating allowance up to a cap.

#### `RATE_LIMIT` · `0x0671`

Maximum `max_per_block` sats can be unlocked per block. Unused allowance accumulates up to `accumulation_cap`. Rate refills at `refill_blocks` per unit.

**Params:** `NUMERIC max_per_block` · `NUMERIC accumulation_cap` · `NUMERIC refill_blocks`

**Use case:** Exchange hot wallet limits, treasury rate control, preventing catastrophic key-compromise drain

**Note:** A compromised exchange hot wallet can drain at most `max_per_block` sats per block — not the entire balance instantly. Combined with `RECURSE_SAME` the UTXO automatically re-encumbers with the same rate limit.

---

## 9. Contact Inversion — Normally Closed Contacts

In PLC ladder logic, a normally closed contact `[/]` passes current when the condition is FALSE. This is a fundamental PLC primitive that creates genuinely new Bitcoin spending conditions with no current equivalent.

**Implementation:** One `bool inverted` flag on `RungBlock`. The evaluator calls the block's native evaluator then flips `SATISFIED` ↔ `UNSATISFIED`. `ERROR` is not flipped. Unknown block type when inverted returns `SATISFIED` — absence of unknown condition passes (forward compatibility).

**Wire format:** One byte after `block_type` — `0x00` = normal, `0x01` = inverted.

| Inverted Block | Semantics | New Primitive Enabled |
|---|---|---|
| `[/CSV: N]` | Passes BEFORE N blocks elapsed | Dead man's switch, breach remedy window |
| `[/CLTV: H]` | Passes BEFORE block height H | Spend deadline — must act before this date |
| `[/MULTISIG: n-of-m]` | Passes when n-of-m have NOT signed | Governance veto — board blocks CEO spend |
| `[/SIG: key]` | Passes when key has NOT signed | Exclusion — anyone EXCEPT this key can spend |
| `[/COMPARE: GT N]` | Passes when amount <= N | Small-amount fast path, large requires extra auth |
| `[/TIMER_CONTINUOUS: N]` | Passes when liveness proof broken | Inheritance — unlocks only if owner gone silent |
| `[/CLTV + CSV combo]` | Deadline + relative delay | Complex temporal logic impossible in current Script |

---

## 10. Coil Types and Attestation Modes

The coil declares what happens when all contacts on a rung are satisfied. It is **not a cryptographic proof** — it is a claim type declaration. The attestation mode declares where the proof lives.

### Coil Types

| Coil | Enum | Semantics | Use Case |
|---|---|---|---|
| `UNLOCK` | `0x01` | Standard UTXO unlock. Output spendable freely by satisfying witness. | Simple payment, channel cooperative close |
| `UNLOCK_TO` | `0x02` | Reserved for a future wire format that binds output structure on-chain (e.g. via a CTV-style template hash). v0.8 dropped the `address_hash` / `rung_destinations` fields (E-009/E-010 — unbound spender data channels). | Forced routing patterns today should use rung-level `OUTPUT_CHECK` or `CTV` blocks. |

### Attestation Modes

| Mode | Enum | Witness Size | Proof Location |
|---|---|---|---|
| `INLINE` | `0x01` | Full sig (64B Schnorr / 666B FALCON512) | In transaction witness |
| `AGGREGATE` | `0x02` | R per input in witness, aggregated s-value at tx level | Half-aggregated Schnorr |

INLINE and AGGREGATE are active. AGGREGATE uses half-aggregated Schnorr signatures where each input contributes its R-value in the witness, and a single aggregated s-value is appended at the transaction level.

---

## 11. Complete Block Registry

All block type enum values. Unrecognised blocks return `UNSATISFIED` — forward compatibility preserved.

| Enum | Block | Category | Summary |
|---|---|---|---|
| `0x0001` | `SIG` | Signature | Single signature verification |
| `0x0002` | `MULTISIG` | Signature | n-of-m threshold signatures |
| `0x0003` | `ADAPTOR_SIG` | Signature | Adaptor signature (DLC / atomic swap) |
| `0x0004` | `MUSIG_THRESHOLD` | Signature | Aggregate threshold signature (MuSig2/FROST) |
| `0x0005` | `KEY_REF_SIG` | Signature | Signature via relay key reference |
| `0x0101` | `CSV` | Timelock | Relative block timelock |
| `0x0102` | `CSV_TIME` | Timelock | Relative time timelock |
| `0x0103` | `CLTV` | Timelock | Absolute block height timelock |
| `0x0104` | `CLTV_TIME` | Timelock | Absolute time timelock |
| `0x0201` | *(reserved)* | Hash | Reserved. Rejected at deserialization. |
| `0x0202` | *(reserved)* | Hash | Reserved. Rejected at deserialization. |
| `0x0203` | `TAGGED_HASH` | Hash | BIP-340 tagged hash |
| `0x0204` | `HASH_GUARDED` | Hash | Raw SHA-256 preimage verification (non-invertible) |
| `0x0301` | `CTV` | Covenant | CheckTemplateVerify |
| `0x0302` | `VAULT_LOCK` | Covenant | Vault with hot delay + cold recovery |
| `0x0303` | `AMOUNT_LOCK` | Covenant | Output amount range constraint |
| `0x0401` | `RECURSE_SAME` | Recurse | Inherit identical rung set |
| `0x0402` | `RECURSE_MODIFIED` | Recurse | Inherit with typed mutation |
| `0x0403` | `RECURSE_UNTIL` | Recurse | Recurse until block height |
| `0x0404` | `RECURSE_COUNT` | Recurse | Recurse N times maximum |
| `0x0405` | `RECURSE_SPLIT` | Recurse | Split value, re-encumber each piece |
| `0x0406` | `RECURSE_DECAY` | Recurse | Relax one constraint per recursion |
| `0x0501` | `ANCHOR` | L2 Anchor | Generic L2 state anchor |
| `0x0502` | `ANCHOR_CHANNEL` | L2 Anchor | Payment channel anchor |
| `0x0503` | `ANCHOR_POOL` | L2 Anchor | Shared UTXO pool anchor |
| `0x0504` | `ANCHOR_RESERVE` | L2 Anchor | Federation reserve anchor |
| `0x0505` | `ANCHOR_SEAL` | L2 Anchor | Single-use seal (RGB-style) |
| `0x0506` | `ANCHOR_ORACLE` | L2 Anchor | Oracle-attested contract |
| `0x0601` | `HYSTERESIS_FEE` | PLC | Fee-rate hysteresis band |
| `0x0602` | `HYSTERESIS_VALUE` | PLC | Value hysteresis band |
| `0x0611` | `TIMER_CONTINUOUS` | PLC | Continuous condition timer |
| `0x0612` | `TIMER_OFF_DELAY` | PLC | Off-delay dispute window |
| `0x0621` | `LATCH_SET` | PLC | SR flip-flop — set state |
| `0x0622` | `LATCH_RESET` | PLC | SR flip-flop — reset state |
| `0x0631` | `COUNTER_DOWN` | PLC | Decrementing event counter |
| `0x0632` | `COUNTER_PRESET` | PLC | N-approval preset counter |
| `0x0633` | `COUNTER_UP` | PLC | Incrementing event counter |
| `0x0641` | `COMPARE` | PLC | Value comparator (EQ/NEQ/GT/LT/IN_RANGE) |
| `0x0651` | `SEQUENCER` | PLC | Ordered multi-stage execution |
| `0x0661` | `ONE_SHOT` | PLC | Single-activation monoflop |
| `0x0671` | `RATE_LIMIT` | PLC | Per-block spending rate limiter |
| `0x0681` | `COSIGN` | PLC (cross-input) | Co-spend constraint (cross-input scriptPubKey hash) |
| `0x0701` | `TIMELOCKED_SIG` | Compound | SIG + CSV combined |
| `0x0702` | `HTLC` | Compound | Hash + Timelock + Sig (Lightning HTLC). 5-field witness: PUBKEY + SIGNATURE + PUBKEY + PREIMAGE + NUMERIC. |
| `0x0703` | `HASH_SIG` | Compound | Hash preimage + SIG combined |
| `0x0704` | `PTLC` | Compound | ADAPTOR_SIG + CSV (point time-lock contract) |
| `0x0705` | `CLTV_SIG` | Compound | SIG + CLTV combined |
| `0x0706` | `TIMELOCKED_MULTISIG` | Compound | MULTISIG + CSV combined |
| `0x0707` | `ANCHOR_FEE` | Compound | Anchor output with fee contribution |
| `0x0801` | `EPOCH_GATE` | Governance | Periodic spending window |
| `0x0802` | `WEIGHT_LIMIT` | Governance | Maximum transaction weight |
| `0x0803` | `INPUT_COUNT` | Governance | Input count bounds (min/max) |
| `0x0804` | `OUTPUT_COUNT` | Governance | Output count bounds (min/max) |
| `0x0805` | `RELATIVE_VALUE` | Governance | Output/input value ratio enforcement |
| `0x0806` | `ACCUMULATOR` | Governance | Merkle set membership proof. Max 10 HASH256 fields (root + 8 proof nodes + leaf). |
| `0x0807` | `OUTPUT_CHECK` | Governance | Per-output value and script constraint. Non-invertible (HASH256 field). Fields: NUMERIC(output_index) + NUMERIC(min_sats) + NUMERIC(max_sats) + HASH256(script_hash). Script_hash all-zeros = skip script check. |

**Total: 64 block types across 10 families (62 listed here, plus `QABI_PRIME` and
`QABI_SPEND` documented in [QABIO.md](QABIO.md)).**

---

*Ladder Script Block Library Reference v1.0 · Draft*
