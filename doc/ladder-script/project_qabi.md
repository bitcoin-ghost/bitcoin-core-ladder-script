# QABIO — Quantum Atomic Batch Input / Output

**Status:** Implemented and tested on the `QABIO` branch
**Date:** 2026-04-10
**Branch:** QABIO
**Goal:** Enable N independent parties to batch their rung_tx UTXOs into a single transaction authorised by ONE post-quantum signature, natively inside the rung_tx format, without anchors, escrow, commitment transactions, or pre-registration.

> **Status note (2026-05):** This is the original long-form design
> document, kept as an archival reference. For the canonical, current
> protocol description see [`QABIO.md`](QABIO.md); for the integration
> walkthrough see [`qabi_integrator_guide.md`](qabi_integrator_guide.md).
> Several claims in this doc reflect the pre-v0.14 design — notably
> `aggregated_sig` "exactly 666 B" — which were later revised (variable
> 1..666 B per consensus rules). Trust the canonical docs over this
> file when they conflict.
>
> **Related docs:**
> - Reference implementation: `src/rung/qabi.{h,cpp}`, `src/rung/blocks/qabi.cpp` (`EvalQABIPrimeBlock` / `EvalQABISpendBlock` / `EvalPQBatchBlock`), `src/rung/policy.cpp` (RBD helpers), `src/validation.cpp` (RBD mempool integration), `src/rung/rpc.cpp` (5 QABI JSON-RPC commands), `src/rung/descriptor.cpp` (`qabi_prime()` / `qabi_spend()` tokens).
> - Tests: `src/test/rung_tests.cpp` (49 Boost test cases with `qabi` in the name), `test/functional/feature_qabi.py` (24 Python functional test cases).

---

## 1. Goals and non-goals

### Goals

1. **Aggregation** — N independent parties' UTXOs spent together under ONE FALCON signature
2. **PQ-safe** — every component in the critical path is either hash-based or FALCON
3. **Native** — no separate commitment tx, no anchor UTXO, no dust; built directly into the rung_tx format
4. **Trustless** — no pre-commitment to coordinators at UTXO creation; participants pick their coordinator at spend time
5. **Non-leaking** — revealing consent material cannot be used to steal funds
6. **Retry-able** — failed batches don't burn UTXOs; participants re-prime or sweep via Rung 0
7. **Compact** — significantly smaller witness than per-input FALCON
8. **Zero creation cost** — no extra on-chain bytes at UTXO creation vs standard TX_MLSC
9. **Default-capable** — every rung_tx UTXO can participate in QABIO batches without opt-in
10. **Atomic** — both execution atomic (all inputs succeed or tx fails) and compositional atomic (no subset of a primed batch can execute)
11. **Time-bounded** — every batch has a consensus-enforced expiry; stale primings cannot be exploited indefinitely

### Non-goals

1. **Fully passive security** — participants should be online once per batch window (to reveal their spend preimage), but not continuously
2. **Protection against 51% mining attackers** — QABIO inherits Bitcoin's security assumptions
3. **Anonymity** — QABIO is not a mixer; participant identities are visible to other participants in the `QABIBlock`, though not to the wider network until the QABIO tx lands

---

## 2. Definitions / glossary

| Term | Meaning |
|---|---|
| **QABI** | Quantum Atomic Batch Input — the UTXO-side framework (priming, state, per-input checks) |
| **QABIO** | Quantum Atomic Batch Input/Output — a rung_tx that executes a batch (has `tx.qabi_block` and `tx.aggregated_sig` populated, with primed inputs) |
| **QABO** | Quantum Atomic Batch Output signature — the tx-level FALCON signature from the coordinator authorising the whole batch |
| **Auth chain** | The single hash chain per UTXO used for both priming and spending authorisation |
| **auth_seed** | Per-UTXO secret seed `mk`, held by the wallet, used to derive the auth chain |
| **auth_tip** | `H^N(auth_seed)` — the public commitment point of the auth chain; set once at UTXO creation and immutable |
| **Priming** | The covenant spend that writes `committed_root`, `committed_depth`, and `committed_expiry` into a UTXO's state via a `QABI_PRIME` block |
| **Compositional atomicity** | The invariant that no strict subset of a primed batch can execute; any change to participants/outputs/expiry/coordinator forces a full re-prime cycle |
| **Depth** | Position along the auth chain, counted from the tip. Depth `d` means revealing `H^{N-d}(auth_seed)`. Deeper = closer to the seed = harder to predict |
| **RBD** | Replace-By-Depth — mempool policy giving the deepest valid priming tx priority over conflicting shallower ones |
| **Rung 0** | The UTXO's owner-FALCON escape-hatch spend path, always available |
| **Rung 1** | The priming spend path (`QABI_PRIME` block) |
| **Rung 2** | The batch spend path (`QABI_SPEND` block) |
| **QABIBlock** | The tx-level structured data describing the batch (participants, amounts, outputs, coordinator, expiry) |
| **QABI_ROOT** | `SHA256(serialised QABIBlock)` — the value Alice commits to when she primes |

---

## 3. UTXO structure (default in every rung_tx output)

Every rung_tx UTXO includes QABI machinery by default as part of its conditions tree. Zero extra on-chain bytes at creation — everything lives inside the 33-byte TX_MLSC scriptPubKey via Merkle commitment.

### Wallet state (off-chain, per-UTXO)

```
auth_seed            — 32 B secret, the hash chain seed (mk)
auth_chain_length    — u32, default 20,000 depths
next_depth           — counter tracking the next depth to consume
falcon_sk            — FALCON-512 private key for Rung 0 escape hatch
```

### On-chain state (committed in conditions_root)

```
QABI_STATE_RELAY (Merkle-committed, 4 fields):
  auth_tip           (32 B, immutable — H^N(auth_seed), set once at UTXO creation)
  committed_root     (32 B, mutable via priming — 0 if unprimed)
  committed_depth    (varint, mutable via priming — depth of last-consumed preimage)
  committed_expiry   (u32,   mutable via priming — max block height for QABI_SPEND)

Rung 0 (self-spend, always available):
  [SIG(owner_falcon_pubkey, FALCON_512)]

Rung 1 (priming path — fires in a priming tx):
  [QABI_PRIME]

Rung 2 (batch spend path — fires in a QABIO tx):
  [QABI_SPEND]
```

**On-chain cost at creation: 33 bytes.** Same as any TX_MLSC output. The QABI state, rungs, and relay all live inside the Merkle-committed conditions tree.

---

## 4. Ladder logic diagram

```
         L1                                                       L2
         ┆                                                         ┆
 RELAY 0: QABI_STATE_RELAY                                          ┆
         ┆                                                         ┆
         ├──[state fields, no contacts — pure data]─────────────────┤
         ┆                                                         ┆
 RUNG 0: Self-spend                                                 ┆
         ┆                                                         ┆
         ├──[FALCON SIG @owner]──────────────────────────(SPEND_0)──┤
         ┆                                                         ┆
 RUNG 1: Priming                                                    ┆
         ┆                                                         ┆
         ├──[QABI_PRIME]─────────────────────────────────(SPEND_P)──┤
         ┆                                                         ┆
 RUNG 2: Batch spend                                                ┆
         ┆                                                         ┆
         ├──[QABI_SPEND]─────────────────────────────────(SPEND_Q)──┤
         ┆                                                         ┆
```

Exactly one rung fires per spend:
- **`SPEND_0`** — owner sweeps the UTXO via FALCON sig (opt-out / escape hatch)
- **`SPEND_P`** — owner primes the UTXO, rewriting the committed state fields via a covenant
- **`SPEND_Q`** — the UTXO is consumed as part of a QABIO batch tx

---

## 5. Phase 1 — Priming

### Purpose

Commit the UTXO to a specific `QABI_ROOT` and `committed_expiry` via a covenant spend. After priming, the UTXO is **only spendable in a QABIO tx whose `tx.qabi_block` hashes to this root, and only before the expiry height**.

### Flow

```
Alice wants to join a batch with QABI_ROOT = R and prime_expiry_height = E.
Her current UTXO state: committed_depth = d_prev, committed_root = r_prev.

Alice's priming tx:
  Input:  UTXO_alice (current)

  Witness stack (Rung 1 / QABI_PRIME):
    prime_preimage        — H^{N-d}(auth_seed) for chosen depth d > d_prev
    prime_depth           — d (NUMERIC varint)
    new_committed_root    — R (HASH256)
    new_committed_expiry  — E (NUMERIC, 4 B)

  Output: UTXO_alice'
    Same scriptPubKey family (TX_MLSC). The conditions tree is identical to
    the input except for the three mutable fields in QABI_STATE_RELAY:
      committed_root    = R
      committed_depth   = d
      committed_expiry  = E
    The immutable auth_tip, Rung 0, Rung 1, Rung 2 are all preserved bit-exact.
```

### Consensus check (`EvalQABIPrime`)

```
1. H^{prime_depth}(prime_preimage) == auth_tip           (preimage valid)
2. prime_depth > committed_depth                         (monotonic progression)
3. covenant: output UTXO's QABI_STATE_RELAY contains exactly
     (auth_tip          unchanged,
      committed_root    = new_committed_root,
      committed_depth   = prime_depth,
      committed_expiry  = new_committed_expiry)
4. covenant: all other conditions-tree leaves preserved bit-exact
```

### Depth accounting

- Priming consumes one depth
- Spending consumes one more depth (`committed_depth + 1`)
- Re-priming (after a failed batch, or a snipe recovery) consumes one more depth beyond whatever was previously committed
- Default `auth_chain_length = 20,000` supports ~10,000 clean batch rounds or ~6,600 fail-retry rounds per UTXO

### RBD (Replace-By-Depth) mempool policy

If multiple priming txs for the same UTXO are in the mempool, the one with the **deepest `prime_depth`** wins:

```
For QABI_PRIME transactions spending the same input UTXO:
  tx2 replaces tx1 if:
    tx2.prime_depth > tx1.prime_depth
    AND tx2 is valid
    AND tx2 meets standard relay requirements
```

**Rationale:** deeper preimages can only be produced by the UTXO owner (one-way hash). RBD gives the owner a cryptographic "last word" over any conflicting priming tx from an attacker who scraped a shallower preimage from the mempool.

### Priming failure modes

1. **Priming tx drops from mempool (low fee):** UTXO unchanged. Rebroadcast with higher fee.
2. **Non-mining snipe:** attacker scrapes the mempool preimage. RBD defeats this — Alice bumps to a deeper depth.
3. **Mining snipe:** attacker mines a block containing their own priming tx at the same depth with a malicious root. Alice's UTXO is briefly primed to the wrong root but is still safe — the attacker cannot build a `QABIO` tx spending it without the **deeper** spend preimage, which only Alice has. Alice recovers by re-priming at depth > current committed_depth.

---

## 6. Phase 2 — QABIO batch spend

### Purpose

Spend all primed UTXOs atomically in a single rung_tx authorised by ONE coordinator FALCON-512 signature.

### Flow

```
Coordinator collects spend preimages from all participants (off-chain, over a
secure channel). Once all preimages are gathered, coordinator builds:

QABIO rung_tx:
  Inputs:
    UTXO_alice   (primed to R, committed_depth = d_A, committed_expiry = E)
    UTXO_bob     (primed to R, committed_depth = d_B, committed_expiry = E)
    UTXO_carol   (primed to R, committed_depth = d_C, committed_expiry = E)
    ...
    [optionally] coordinator fee UTXO — unprimed, spent via its own Rung 0

  Outputs:
    Exactly block.outputs (bit-exact, same order, same values, same scripts)

  Witness per primed input (Rung 2 / QABI_SPEND):
    spend_preimage   — H^{N-(committed_depth+1)}(auth_seed) for this UTXO

  Witness for coordinator fee input (if any):
    Rung 0 FALCON sig, normal self-spend

  Tx-level fields:
    tx.qabi_block       — serialised QABIBlock bytes
    tx.aggregated_sig   — FALCON-512 sig by coordinator over SIGHASH_QABO
```

### Consensus check (`EvalQABISpend`, runs per primed input)

```
1. committed_root != 0                                    (UTXO is primed)

2. current_block_height <= committed_expiry               (batch not expired)

3. H^{committed_depth + 1}(spend_preimage) == auth_tip    (spend preimage valid)

4. SHA256(tx.qabi_block) == committed_root                (root match)

5. block = ParseQABIBlock(tx.qabi_block)
   block != nullptr                                       (block parses, well-formed)

6. block.prime_expiry_height == committed_expiry          (expiry match)

7. my_id = SHA256(this UTXO's Rung 0 falcon_pubkey)
   entry = block.entries.find(participant_id == my_id)
   entry != null                                          (identity present)

8. tx.outputs.size() == block.outputs.size()
   for i in 0 .. block.outputs.size():
     tx.outputs[i] == block.outputs[i]                    (FULL output set match —
                                                           no extras, no reorder,
                                                           no substitution; closes
                                                           the coordinator-skim hole)

9. FalconVerify(
     pubkey  = block.coordinator_pubkey,
     message = ComputeSighashQABO(tx),
     sig     = tx.aggregated_sig) == VALID                (QABO sig valid)
```

All nine checks must pass for each primed input. If any input fails, the whole tx is invalid. **Atomicity by construction.**

### Atomicity guarantees

**Execution atomicity:** the single QABIO tx either executes fully or not at all — standard transaction semantics.

**Compositional atomicity:** no strict subset of a primed batch can execute. Because `QABIBlock` commits to the full participant set, expiry, and output list, any attempt to build a QABIO tx with a different composition yields a different `QABI_ROOT`. Every primed input would then fail its per-input root match check. To proceed with a changed composition, a new block with a new root must be agreed, and **every remaining participant must re-prime** (consuming one more auth chain depth each). See §11 Attack 6 for the worked example.

### Why coordinators can't skim

Even with all participants' spend preimages in hand, the coordinator cannot siphon value:

- Check 8 enforces `tx.outputs` to **exactly match** `block.outputs` — no extra "coordinator fee" output can be added, no reordering, no value substitution
- Coordinators who want to collect a fee must include themselves as an entry in `block.outputs` with a stated amount, visible to all participants at block-review time
- Any implicit remainder from `sum(inputs) - sum(block.outputs)` is paid as a miner fee (standard tx validity)

---

## 7. QABIBlock structure

```
QABIBlock {
    version:               u8     (0x01 for v1)
    batch_id:              u256   (32 B random, unique per batch attempt)
    coordinator_pubkey:    bytes  (897 B, FALCON-512 pk)
    prime_expiry_height:   u32    (max block height at which QABI_SPEND may fire)

    entries: vector<QABIEntry> {
        participant_id:    u256   (32 B, = SHA256(participant's Rung 0 falcon pk))
        contribution:      i64    (sats this participant puts in)
        destination_index: varint (index into outputs[])
    }

    outputs: vector<CTxOut> {
        amount:            i64    (sats)
        script_pubkey:     bytes  (variable)
    }
}

QABI_ROOT = SHA256(canonical_serialise(QABIBlock))
```

### Design notes

- **Identity binding** — `participant_id` is the hash of the Rung 0 FALCON pubkey. This is stable across re-primings: Alice can re-prime to the same root using a new UTXO (created from a previous Rung 0 sweep) as long as her FALCON key is the same. The block's `entries` list does not need to be rewritten for re-primings.
- **Version byte** — reserved for future variants (e.g., a Merkle-commit version for very large batches, or a privacy-extended version). v1 is flat `SHA256(bytes)`.
- **Coordinator pubkey in-line** — carried inside the block (897 B) so every input's QABO check can read it without extra lookups.
- **prime_expiry_height in-block** — commits the expiry to the root. Changing the expiry changes the root, forcing a re-prime — which is the desired behaviour.
- **Canonical serialisation** — field order is fixed, integers are little-endian, varints use Bitcoin's standard `CompactSize`. A single bit difference in serialisation means a different `QABI_ROOT`, so every implementation must agree.

### Size estimate

```
Header:
  version              1 B
  batch_id             32 B
  coordinator_pubkey   897 B
  prime_expiry_height  4 B
                       ─────
                       934 B

Per entry:  32 (id) + 8 (contribution) + 1-5 (dest_index) = ~41 B
Per output: 8 (value) + 1 + 25-35 (script) = ~34-44 B

For N = 100 participants with standard P2WPKH destinations:
  Header:   934 B
  Entries:  100 × 41 = 4100 B
  Outputs:  100 × 40 = 4000 B
  Framing:  ~50 B
  Total:    ~9 KB

For N = 500:
  Header:   934 B
  Entries:  ~20500 B
  Outputs:  ~20000 B
  Total:    ~42 KB
```

### Size caps

- **Soft cap (standard relay):** `QABI_BLOCK_MAX_SOFT = 65536` (64 KB) — supports ~400-participant batches
- **Hard cap (consensus):** `QABI_BLOCK_MAX_HARD = 262144` (256 KB) — supports ~1600-participant batches
- Blocks larger than the soft cap won't relay via standard nodes but can be mined directly
- Blocks larger than the hard cap are rejected at consensus level

---

## 8. Transaction format

### New tx-level fields

Two fields sit alongside the existing TX_MLSC tx-level fields (`conditions_root`, `creation_proof`, `aggregated_sig`). They are serialised inside the `flags == 0x02` TX_MLSC block in `SerializeTransaction` / `UnserializeTransaction`:

```
TX_MLSC serialisation (flags == 0x02), after per-input witness stacks:
  CompactSize creation_proof_len + bytes
  CompactSize qabi_block_len + bytes          ← NEW
  CompactSize aggregated_sig_len + bytes      ← CAP RAISED 32 → 666
```

Both fields are `std::vector<uint8_t>` on `CTransaction` and `CMutableTransaction`:

| Field | Previous state | New state |
|---|---|---|
| `qabi_block` | *did not exist* | Optional, empty by default, max 64 KB soft / 256 KB hard |
| `aggregated_sig` | Reserved (always empty, wire compat), capped at 32 B | Optional, empty by default, capped at exactly 666 B (FALCON-512 sig size) |

### Tx-level rules

```
If any input has committed_root != 0 (i.e., any primed input):
  require tx.qabi_block non-empty
  require ParseQABIBlock(tx.qabi_block) succeeds
  require tx.aggregated_sig non-empty
  require tx.aggregated_sig.size() == 666 (FALCON-512 exact)

If no input has committed_root != 0:
  require tx.qabi_block empty
  require tx.aggregated_sig empty
```

### SIGHASH_QABO

New sighash mode for the coordinator's FALCON signature. Covers:

- `version`
- `vin` (all outpoints, sequences, order)
- `vout` (all values, scripts, order)
- `conditions_root`
- `creation_proof`
- **`qabi_block`** (critical — without this, block substitution is possible)
- All per-input witness stacks **except** the witnesses that contain the spend preimages of QABI_SPEND inputs (TBD — may need to include them to prevent witness malleation; decision in Phase 9)
- `nLockTime`

Excludes:

- `aggregated_sig` itself (chicken-and-egg)

---

## 9. Size and cost analysis

### At UTXO creation

- **33 bytes** (standard TX_MLSC scriptPubKey: `0xDF || conditions_root`)
- Zero extra cost for QABI state relay, Rung 1, Rung 2 — all Merkle-committed

### Per priming attempt

```
Rung 1 witness:
  prime_preimage:            32 B
  prime_depth:               1-5 B (varint)
  new_committed_root:        32 B
  new_committed_expiry:      4 B
  Merkle proofs (rung+relay): ~100 B
  Tx framing + input/output:  ~150 B
                              ─────
  ~320 B per priming tx
```

### Per QABIO batch spend (100-input batch)

```
Per-input witness (amortised):
  spend_preimage:              32 B
  Merkle proofs:               ~100 B
  Tx framing:                  ~20 B
                               ─────
  ~150 B × 100 = 15 KB

Tx-level (shared):
  qabi_block (serialised):     ~9 KB
  aggregated_sig (FALCON-512): 666 B
                               ─────
  ~10 KB

Total witness: ~25 KB
```

### Comparison vs per-input FALCON

```
Per-input FALCON (hypothetical):
  100 × (666 B sig + 897 B pubkey) = ~156 KB

QABIO batch: ~25 KB

Saving: ~84%
```

Saving grows with batch size because the FALCON sig and pubkey are tx-level constants.

---

## 10. Mempool policies

### RBD (Replace-By-Depth)

```
For QABI_PRIME transactions:
  A new priming tx T2 replaces existing priming tx T1 in the mempool if:
    - T2 spends the same UTXO as T1
    - T2.prime_depth > T1.prime_depth
    - T2 is valid
    - T2 meets standard relay requirements
```

**Rationale:** deeper preimages can only be produced by the UTXO owner (one-way hash property). RBD is the mempool-level expression of this cryptographic asymmetry.

### Standard RBF coexistence

For QABIO spend txs (not priming txs), standard RBF applies normally — higher fee replaces lower fee. RBD is orthogonal and only affects `QABI_PRIME` txs.

---

## 11. Security analysis

### Attack 1 — Spend-time preimage leakage

**Scenario:** QABIO tx is broadcast, every primed input's spend preimage is now publicly visible in the mempool.

**Defence:** The primed UTXO requires `tx.qabi_block` to hash to its `committed_root`. A changed block yields a changed hash, breaking the root match. An attacker rebroadcasting Alice's preimage with a different tx would need to reconstruct the same block (same entries, same outputs, same expiry, same coordinator pubkey) — which is Alice's intended tx. Replay of the intended batch is not theft.

**Residual risk:** none.

### Attack 2 — Priming snipe by non-mining attacker

**Scenario:** Alice broadcasts priming at depth `d`. Attacker scrapes the preimage from the mempool and broadcasts a conflicting priming at the same depth with `committed_root = R_evil`.

**Defence:** RBD mempool policy. Alice rebroadcasts at depth `d+1`. The attacker cannot produce deeper preimages (one-way hash) and Alice wins the depth war.

**Residual risk:** none.

### Attack 3 — Priming snipe by mining attacker

**Scenario:** Mining attacker `M` includes a priming tx for Alice's UTXO at depth `d` in a block `M` mines, with `committed_root = R_evil`. This bypasses RBD.

**Defence:** Alice's UTXO is briefly primed to `R_evil` but `M` cannot execute the attack: spending this UTXO in a QABIO tx requires revealing the spend preimage at depth `d+1`, which only Alice has. `M` has depth `d` but cannot compute depth `d+1` from it. Alice re-primes at depth `d+1` with the correct root, restoring her intended state. The attacker has wasted a block.

**Residual risk:** a 51%+ mining attacker targeting one user persistently — economically irrational (zero profit, infinite cost).

### Attack 4 — Coordinator colludes with mining attacker

**Scenario:** Evil coordinator `C` wants to steal Alice's UTXO. `C` colludes with mining attacker `M`. `M` snipes Alice's priming to `committed_root = R_evil` where `R_evil = SHA256(B_evil)` and `B_evil` sends Alice's funds to `C`.

**Defence:** Same as Attack 3. The spend still requires Alice's depth `d+1` preimage. `C` and `M` cannot produce it. Attack fails unless `C` also has Alice's spend preimage — which she only reveals to `C` after verifying that her own priming stuck and not `M`'s. Alice's wallet checks "is my UTXO currently committed to my intended root?" before revealing the spend preimage.

**Residual risk:** Alice must wait a few blocks of confirmation before releasing the spend preimage to verify no reorg displacement. Standard confirmation discipline.

### Attack 5 — Coordinator output skim

**Scenario:** Coordinator builds a valid QABIO tx with all participants' destinations listed correctly in `block.outputs`, but adds an extra output to themselves beyond what the block specifies. Participants thought the remainder went to miners; coordinator pockets it instead.

**Defence:** Check 8 of `EvalQABISpend` enforces `tx.outputs == block.outputs` bit-exact (full output set match, no extras allowed). Any extra output is rejected. Coordinators who want a fee must explicitly include themselves as an entry in `block.outputs`, visible to participants at block-review time.

**Residual risk:** none.

### Attack 6 — Participant dropout forces re-prime cycle

**Scenario:** Alice primes, then refuses to reveal her spend preimage (or goes offline). The batch cannot execute with the original composition (her input has no spend preimage).

**Defence:** Coordinator builds a new `QABIBlock` with a new `QABI_ROOT` excluding Alice. **Every remaining participant must re-prime** to the new root (compositional atomicity) — Bob and Carol each burn one more auth chain depth. Alice's primed UTXO remains locked to the dead root until she re-primes to another batch or Rung-0-sweeps.

**Residual risk:** one re-prime per remaining participant per dropout. Chain length of 20,000 absorbs many rounds. Social cost (delay, re-coordination) is real but bounded.

### Attack 7 — Batch expiry lapse

**Scenario:** The coordinator delays broadcasting the QABIO tx until after `prime_expiry_height` passes.

**Defence:** `EvalQABISpend` check 2 rejects any spend at `current_height > committed_expiry`. The batch cannot execute. Participants can re-prime into a new batch or Rung-0-sweep. The expiry is committed inside the block (via `prime_expiry_height`), so all participants agreed to the deadline when they primed.

**Residual risk:** priming effort wasted if the expiry lapses. Mitigated by setting realistic expiry windows (e.g., 144 blocks = ~1 day).

### Attack 8 — Block substitution at mining time

**Scenario:** A miner sees a valid QABIO tx with `tx.qabi_block = B1` in the mempool and tries to substitute `B2` in their block.

**Defence:** `SIGHASH_QABO` covers `tx.qabi_block`. Changing the block changes the sighash, invalidates the FALCON sig, tx is rejected.

**Residual risk:** none.

### Attack 9 — Malformed or oversized block

**Scenario:** Coordinator broadcasts a tx with `tx.qabi_block` that is 512 MB of garbage, or structurally invalid.

**Defence:** Hard cap `QABI_BLOCK_MAX_HARD` rejects oversized blocks at consensus. `ParseQABIBlock` strict validation rejects structurally invalid blocks at consensus check time. Tx fails before any real work is done.

**Residual risk:** none.

### Attack 10 — Double-spend via Rung 0

**Scenario:** Alice primes, then sweeps her UTXO via Rung 0 before the batch executes.

**Defence:** The primed UTXO and the Rung 0 sweep reference the same UTXO. Only one can confirm. If Rung 0 wins, the batch tx becomes invalid (missing input). Alice has exercised her escape hatch — this is a feature, not an attack. Other participants must re-prime (Attack 6 applies).

**Residual risk:** wasted priming effort for other participants. Standard coordination problem.

### Attack 11 — Participant ID collision

**Scenario:** Two participants have the same `H(FALCON pubkey)` = same `participant_id`.

**Defence:** 256-bit SHA256 collision is computationally infeasible. If two participants really share a key, they're the same entity.

**Residual risk:** none.

### Attack 12 — Phantom input

**Scenario:** Coordinator includes Alice's primed UTXO plus a stolen-but-primed UTXO belonging to attacker `X` in the batch.

**Defence:** Each input's identity check requires its own Rung 0 FALCON pubkey hash to appear in `block.entries`. `X`'s UTXO either (a) isn't primed to `committed_root` (its own state mismatches), or (b) is primed but `X`'s identity isn't in the block. Either way, the attack fails.

**Residual risk:** none.

### Attack 13 — Chain exhaustion DoS

**Scenario:** Persistent attacker repeatedly snipes Alice's primings, burning auth chain depths until exhausted.

**Defence:** Default chain length 20,000 depths. Each attack costs the attacker a priming tx fee. 20,000 attacks to exhaust Alice's chain. If exhausted, Alice sweeps via Rung 0 and creates a new QABI-enabled UTXO with a fresh chain.

**Residual risk:** accepted; economic cost to attacker dwarfs damage.

### Attack 14 — Off-chain coordinator shows inconsistent blocks to different participants

**Scenario:** Coordinator shows Alice `B1` and Bob `B2`. Alice primes to `SHA256(B1)`, Bob primes to `SHA256(B2)`. Coordinator cannot assemble a single QABIO tx that satisfies both.

**Defence:** Compositional atomicity. Any QABIO tx carries one `tx.qabi_block`. If it's `B1`, Bob's input fails; if it's `B2`, Alice's input fails. Neither can execute. Participants discover the inconsistency when the QABIO tx fails to materialise; they compare notes off-chain.

**Residual risk:** participants burn priming fees before discovering the inconsistency (this is the one real UX regression vs. a design with a pre-priming commitment anchor). Accepted for v1 — grief, not theft.

### Attack 15 — Reorg affecting priming

**Scenario:** Alice's priming confirms in block H, which is then reorged away.

**Defence:** Standard Bitcoin reorg handling. Alice re-primes in the new chain. If the reorg is deep enough to also revert the QABIO tx, funds still revert to the primed state and Alice can recover.

**Residual risk:** standard Bitcoin reorg risks.

---

## 12. Implementation requirements

### New block types (in `src/rung/types.h`)

```cpp
QABI_PRIME = 0x0A01,   // Priming state transition
QABI_SPEND = 0x0A02,   // Batch spend authorisation
// 0x0A03, 0x0A04 reserved for future QABI family members
```

### New tx-level field

Add `qabi_block: std::vector<uint8_t>` to `CTransaction` and `CMutableTransaction`, serialised inside the TX_MLSC path alongside `creation_proof` and `aggregated_sig`.

Raise the `aggregated_sig` cap from 32 to exactly 666 (FALCON-512 sig size).

### New files

- **`src/rung/qabi.h`** — `QABIBlock` struct, `QABIEntry` struct, forward declarations
- **`src/rung/qabi.cpp`** — `SerializeQABIBlock`, `ParseQABIBlock`, `ComputeQABIRoot`

### New consensus rules

1. Tx-level: if any input has `committed_root != 0`, require `tx.qabi_block` non-empty and parseable, `tx.aggregated_sig` exactly 666 B
2. `EvalQABIPrime` — the 4 checks described in §5
3. `EvalQABISpend` — the 9 checks described in §6
4. `ComputeSighashQABO` — covers everything except `aggregated_sig` itself

### New mempool policy

- **`POLICY_QABI_RBD`** — Replace-By-Depth for `QABI_PRIME` transactions

### Wallet requirements

1. Auth seed storage (one per QABI-enabled UTXO)
2. Depth tracking per UTXO
3. Priming tx construction with correct depth, covenant mutation fields
4. QABIBlock verification before priming
5. Spend preimage reveal to coordinator (off-chain, over authenticated channel)
6. Automatic Rung 0 sweep prompt on batch abandonment or expiry

### Test coverage

1. Happy path: 2-party, 10-party, 100-party batches
2. Priming snipe (non-mining) — RBD defeats
3. Priming snipe (mining) — Alice recovers at next block
4. Spend preimage leak — cryptographically safe
5. Expired batch — rejected
6. Coordinator skim (extra output) — rejected by check 8
7. Participant dropout — compositional atomicity forces re-prime
8. Rung 0 sweep during live batch — participants re-prime
9. Reorg handling
10. Oversized block — rejected
11. Malformed block — rejected

---

## 13. Open questions

1. **SIGHASH_QABO scope:** ~~open~~ **decided** (refined in Phase 18): **per-input witnesses ARE covered** as defence-in-depth against byte-level witness malleability. An attacker with the mempool-visible tx cannot modify LadderWitness framing, spend preimages, Merkle proofs, or extra stack padding without invalidating the coordinator's FALCON signature. SIGHASH_QABO covers: version, vin (prevouts + sequences), vout (values + scripts), conditions_root, qabi_block (length-prefixed), per-input scriptWitness stacks (count + length-prefixed elements), nLockTime. Excludes: aggregated_sig (chicken-and-egg), creation_proof. See `ComputeSighashQABO` in `src/rung/qabi.cpp`.

2. **Covenant primitive:** ~~open~~ **decided**: `QABI_PRIME` carries its own covenant check (see `EvalQABIPrimeBlock` in `src/rung/blocks/qabi.cpp`, check 5 — rebuild with mutated QABI_SPEND state) rather than reusing `RECURSE_MODIFIED`. The QABI case needs to mutate three committed fields in one step while preserving everything else in the input tree, which `RECURSE_MODIFIED` doesn't express directly.

3. **Priming tx fee source:** each participant pays their own priming tx fee. No shared fee accounting needed.

4. **Wallet UX for spend-preimage release:** when should a wallet auto-release the spend preimage to the coordinator? Options: after N confirmations of its own priming tx, after user manual confirmation, after a wallet-policy timer. Probably a wallet-side decision, not a consensus one.

5. **Max participants per batch:** practical limit from `QABI_BLOCK_MAX_HARD` is ~1600. Beyond that, batches would need a future `version 0x02` block format with Merkle-committed entries. Deferred.

6. **Integration with existing RECURSE_MODIFIED tests and covenant validation code:** needs careful review at Phase 5 implementation time.

---

## 14. Status

Design locked as of this revision. Implementation proceeding on the `QABIO` branch across phases:

| Phase | Subject | Status |
|---|---|---|
| 0 | Commit design doc | ✅ |
| 1 | Reserve enum slots (anchor-era names) | ✅ |
| 1c | Rename enum entries to QABI_PRIME / QABI_SPEND | pending |
| 2 | QABIBlock struct + serialisation + tx format | pending |
| 3 | Evaluator stubs | pending |
| 4 | `EvalQABISpend` real implementation | pending |
| 5 | `EvalQABIPrime` real implementation | pending |
| 8 | Wire tx-level aggregated_sig (raise cap) | pending |
| 9 | Define SIGHASH_QABO | pending |
| 10 | RBD mempool policy | pending |
| 11 | Unit tests per evaluator | pending |
| 12 | End-to-end 2-party batch integration test | pending |

**Hole-poking complete.** See §11 Attack 5 (coordinator skim, closed by check 8) and §11 Attack 14 (off-chain inconsistency, accepted for v1). No unresolved vulnerabilities known at design level.
