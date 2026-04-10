# QABI — Quantum Atomic Batch Input

**Status:** Draft (design iteration)
**Date:** 2026-04-10
**Goal:** Enable N independent parties to batch their UTXOs into a single transaction authorised by ONE post-quantum signature, trustlessly, without per-input PQ signatures.

---

## 1. Goals and non-goals

### Goals

1. **Aggregation**: N independent parties' UTXOs spent together under ONE quantum signature
2. **PQ-safe**: every component in the critical path is either hash-based or FALCON (no classical crypto exposed to quantum attack)
3. **Trustless**: no pre-commitment to coordinators at UTXO creation, no trusted parties
4. **Flexible**: user chooses their coordinator, batch, and recipients at spend time
5. **Non-leaking**: revealing consent material cannot be used to steal funds
6. **Retry-able**: failed batches don't burn the UTXO; user can retry with a new batch/coordinator
7. **Compact**: significantly smaller witness than per-input FALCON
8. **Zero creation cost**: no extra on-chain bytes at UTXO creation vs standard TX_MLSC
9. **Ubiquitous**: enabled by default on every `rung_tx`

### Non-goals

1. **Fully passive security**: no requirement that user must be online 24/7. But a user with a live wallet during priming is protected better than an offline user.
2. **Protection against 51% mining attackers**: a majority attacker can grief anyone in any protocol. QABI inherits Bitcoin's security assumptions.
3. **Anonymity**: QABI is not a mixer. Participants' identities are visible in the QABI_BLOCK to other participants (not on-chain).

---

## 2. Definitions

| Term | Meaning |
|---|---|
| **Chain A** | Hash chain used for PRIMING the UTXO (committing it to a specific batch) |
| **Chain B** | Hash chain used for CONSENTING to a specific spend (final authorisation) |
| **QABI_ROOT** | Merkle root of the QABI_BLOCK; commits to the exact batch composition |
| **QABI_BLOCK** | Structured data describing all participants, conditions, and the batch ID |
| **QABO** | Quantum Atomic Batch Output signature — a single FALCON signature over the sighash that authorises the whole batch |
| **Coordinator** | The party that builds the QABI_BLOCK and produces the QABO signature. Can be a participant. |
| **Priming** | Covenant transaction that commits a UTXO to a specific QABI_ROOT |
| **RBD** | Replace-By-Depth — mempool policy where deeper Chain A reveals replace shallower ones for conflicting priming txs |
| **Rung 0** | Self-spend rung using the owner's FALCON key (escape hatch) |
| **Rung QABI** | Batch spend rung |

---

## 3. UTXO structure (at creation)

Every `rung_tx` output with QABI enabled has the following committed structure (Merkle-committed in `conditions_root`, zero on-chain bytes beyond the standard 33-byte TX_MLSC scriptPubKey).

### Wallet state (off-chain)

```
mk_A        — master seed for Chain A (priming chain), 32 B
mk_B        — master seed for Chain B (consent chain), 32 B
falcon_sk   — FALCON private key for Rung 0 self-spend
current_A_depth — tracks which Chain A depth was last used
current_B_depth — tracks which Chain B depth was last used
```

### UTXO conditions (Merkle-committed)

```
Relay 0: QABI_CONDITIONS_RELAY
  Conditions: 
    H^N_A(mk_A)                      — Chain A tip commitment
    committed_QABI_ROOT (initially 0 — unprimed)
    creation_block_height           — for time-lock computation
  
Relay 1: QABI_CONSENT_RELAY
  Conditions:
    H^N_B(mk_B)                      — Chain B tip commitment

Rung 0: self-spend
  [SIG(falcon_pubkey, FALCON_512)]

Rung QABI: batch spend
  relay_refs = [0, 1]                 — both relays must be satisfied
  [QABI_BLOCK_CHECK]                  — verifies tx QABI_BLOCK hashes to committed QABI_ROOT
  [QABO_CHECK]                        — verifies tx.aggregated_sig is valid FALCON over sighash
```

**On-chain cost at creation: 33 bytes** (same as any TX_MLSC output). All the above is committed via the Merkle root.

---

## 4. Ladder logic diagram

```
         L1                                                       L2
         ┆                                                         ┆
         ┆                                                         ┆
 RELAY 0: QABI_CONDITIONS_RELAY                                     ┆
         ┆                                                         ┆
         ├──[Chain A preimage valid + depth check]──────(QCONDR)────┤
         ┆                                                         ┆
 RELAY 1: QABI_CONSENT_RELAY                                        ┆
         ┆                                                         ┆
         ├──[Chain B preimage valid]────────────────────(QCONSR)────┤
         ┆                                                         ┆
 RUNG 0: Self-spend                                                 ┆
         ┆                                                         ┆
         ├──[FALCON SIG @alice]──────────────────────────(SPEND_0)──┤
         ┆                                                         ┆
 RUNG QABI: Batch spend                                             ┆
         ┆                                                         ┆
         ├──[QCONDR]─[QCONSR]─[ROOT_MATCH]─[QABO]────────(SPEND_Q)──┤
         ┆                                                         ┆
```

All four contacts of RUNG QABI must close for `SPEND_Q` to fire:
- **QCONDR**: Chain A reveal is valid at current block height depth
- **QCONSR**: Chain B reveal is valid (Alice's explicit consent to this spend)
- **ROOT_MATCH**: tx's `QABI_BLOCK` hashes to the UTXO's committed `QABI_ROOT`
- **QABO**: tx's `aggregated_sig` contains a valid FALCON signature over the sighash

---

## 5. Phase 1 — Commitment tx

### Purpose

Publicly anchor the batch structure on-chain before any priming happens. This provides the single authoritative source of truth for `QABI_ROOT` and prevents coordinators from showing inconsistent blocks to different participants.

### Flow

```
Coordinator's commitment tx:
  Input:  coordinator pays fees
  Output: commitment anchor UTXO
    nValue: 546 sats (dust)
    scriptPubKey: 0xDF || H(QABI_BLOCK)
```

Once mined, the anchor UTXO is immutable. The `QABI_BLOCK` it commits to is fixed. Any attempt to "change" the batch requires broadcasting a NEW commitment tx with a new anchor — creating a fresh batch, not modifying the existing one.

**Participants lookup the anchor** to verify the batch structure before priming. Their wallet refuses to prime unless it can confirm the anchor's committed `QABI_BLOCK` matches what the coordinator claimed off-chain.

### Root change semantics

If anything in the batch changes — participants, outputs, amounts, coordinator — a new commitment tx with a new `QABI_BLOCK` must be broadcast, and **every remaining participant must re-prime to the new root**. There is no cheap "just drop a participant" path.

```
State before change:     Alice, Bob, Carol all primed to R1
Alice falls out.
Coordinator broadcasts:  new commitment tx with R2 (Bob + Carol only)
Bob re-primes R1 → R2    (burns one Chain A depth)
Carol re-primes R1 → R2  (burns one Chain A depth)
Only now can the QABIO tx execute.
```

This is enforced by consensus, not protocol courtesy. The QABIO tx validates each input's `committed_QABI_ROOT` against the tx's `QABI_BLOCK` root. If Bob is still primed to R1 and the coordinator tries to build a tx with R2 (Bob + Carol, no Alice), Bob's per-input root check fails — `R1 ≠ R2` — and the whole tx is invalid.

**Compositional atomicity invariant:** the batch is atomic not only in execution but in composition. No strict subset of a primed batch can execute. Any change to the participant set, outputs, amounts, or coordinator forces a full re-prime cycle across every remaining participant.

**Why this is a feature:** it eliminates the "silently reduced batch" attack class. A coordinator (or a subset of participants) cannot quietly exclude one party and execute the remainder on terms the excluded party wasn't shown. Every composition change is a public, observable event (new commitment tx) and requires active participation (re-priming) from everyone who wants to stay in.

**Cost of a dropout:** one re-prime per remaining participant. This creates strong incentive for coordinators to only broadcast a commitment when confident everyone will follow through, and for participants to stay online and responsive during the priming → spend window.

**Orphaned state:** UTXOs primed to the dead root R1 remain primed to R1. They can never be spent in an R2 batch (composition mismatch). Their owners either re-prime them into a new batch or sweep via Rung 0.

## 6. Phase 2 — Priming

### Purpose

Commit each participant's UTXO to the `QABI_ROOT` from the commitment tx, via a covenant spend. This locks the participant's UTXO to the specific batch composition cryptographically.

### Flow

```
Alice wants to join batch with QABI_ROOT = R

Alice's priming tx:
  Input:  UTXO_1 (Alice's current QABI-enabled UTXO)
  
  Witness:
    - Chain A preimage at current depth d
    - Merkle proof to QABI_CONDITIONS_RELAY
    - RECURSE_MODIFIED covenant data (mutation: committed_QABI_ROOT = R)
  
  Output: UTXO_1' 
    - Same scriptPubKey structure
    - Same Chain A tip (but depth now at d+1 in wallet tracking)
    - Same Chain B tip
    - Same FALCON pubkey
    - committed_QABI_ROOT = R (updated from 0 or previous R')
    - Same creation_block_height reference (for time-lock continuity)
```

### Chain A depth selection

Alice chooses any depth from her Chain A for a priming attempt. No time-based depth floor is required — RBD handles snipe resistance cryptographically via the depth-war mechanism (see section 9).

**Strategy:** Alice's wallet picks a starting depth (e.g., 1) for the first priming attempt. If RBD replacement is needed (an attacker sniped), she bumps to a deeper depth. She can always go one deeper than the attacker because only she holds `mk_A`.

### RBD (Replace-By-Depth) mempool policy

If two or more priming transactions spending the same UTXO are in the mempool, the tx with the **deepest Chain A depth** wins. Shallower ones are evicted.

```
Mempool RBD rule:
  For QABI priming txs spending the same input UTXO:
    tx2 replaces tx1 if:
      tx2.chain_a_depth > tx1.chain_a_depth
      AND both are valid
```

Tiebreaker (same depth): first-seen.

### Priming failure modes

1. **Priming tx drops from mempool (fee issue)**: UTXO unchanged. Alice rebroadcasts with higher fee. No depth change needed.
2. **Priming snipe (non-mining attacker)**: RBD defeats this. Alice bumps to a deeper preimage the attacker cannot produce.
3. **Priming snipe (mining attacker)**: A miner can force their own priming tx into a block they mine, committing UTXO to a malicious root. Alice recovers by re-priming at the next block — her new priming has a deeper depth and spends the (now-malicious) primed UTXO to create a new one with her good root.
4. **Mid-batch re-priming**: because QABI_BLOCK commits to participant identity (not outpoint), re-priming doesn't invalidate the batch. Alice just reports her new outpoint to the coordinator, who updates the batch tx inputs.

---

## 7. Phase 3 — QABIO batch spend

### Purpose

Spend all primed UTXOs atomically in a single transaction authorised by one FALCON signature.

### Flow

```
QABIO batch tx:
  Inputs:
    Commitment anchor UTXO (consumed here)
    UTXO_alice (primed to R)
    UTXO_bob   (primed to R)
    UTXO_carol (primed to R)
    ...
  
  Witness per primed input:
    - Chain B preimage (participant's consent to the spend)
    - Merkle proofs for rung + relays
    - Reference to the tx-level QABI_BLOCK
  
  Witness for commitment anchor input:
    - Proof that anchor's committed H(QABI_BLOCK) matches the tx's QABI_BLOCK
  
  Tx-level data:
    QABI_BLOCK (included once, every primed input references it)
    tx.aggregated_sig: FALCON signature over sighash (this IS the QABO sig)
  
  Outputs:
    Per-participant destinations as defined in QABI_BLOCK
    (each output is a standard TX_MLSC output with fresh QABI-enabled structure)
```

**Atomicity guarantee (execution):** the single QABIO tx either executes fully or not at all. Every primed input's root check must pass against the same tx-level QABI_BLOCK, ensuring all participants are primed to the same root. The commitment anchor consumption proves the batch was publicly committed to.

**Atomicity guarantee (composition):** no subset of a primed batch can execute. Because `QABI_BLOCK` commits to the full participant set and output list, any attempt to build a QABIO tx with fewer (or different) participants yields a different root. Every remaining primed input's `committed_QABI_ROOT` still points to the original root and fails the per-input root check. To proceed with a changed composition, a new commitment tx must be broadcast and every participant in the new set must re-prime. See Section 5 "Root change semantics".

### Evaluator logic for Rung QABI

```
eval_rung_qabi(ctx):
    # Step 1: Check QABI_CONDITIONS_RELAY (QCONDR coil)
    #         The coil was energised during priming; we're just confirming state.
    if ctx.utxo.committed_QABI_ROOT == 0:
        return UNSATISFIED  # UTXO not primed
    
    # Step 2: Check QABI_CONSENT_RELAY (QCONSR coil)
    chain_b_preimage = ctx.witness.chain_b_preimage
    chain_b_depth = ctx.witness.chain_b_depth
    expected_tip = ctx.utxo.chain_b_tip_commitment
    if hash_n_times(chain_b_preimage, chain_b_depth) != expected_tip:
        return UNSATISFIED
    
    # Step 3: Check ROOT_MATCH (tx QABI_BLOCK matches committed root)
    tx_qabi_block = ctx.witness.qabi_block
    computed_root = merkle_root(tx_qabi_block.entries)
    if computed_root != ctx.utxo.committed_QABI_ROOT:
        return UNSATISFIED
    
    # Step 4: Check identity — UTXO's Rung 0 FALCON pubkey must be in the block
    my_falcon_pk = ctx.utxo.rung_0.falcon_pubkey
    my_id = H(my_falcon_pk)
    if my_id not in [e.participant_id for e in tx_qabi_block.entries]:
        return UNSATISFIED
    
    # Step 5: Check QABO FALCON sig
    qabo_sig = ctx.tx.aggregated_sig
    qabo_pubkey = tx_qabi_block.coordinator_pubkey
    if not falcon_verify(qabo_pubkey, ctx.sighash, qabo_sig):
        return UNSATISFIED
    
    return SATISFIED
```

### Atomicity

All input Rung QABI evaluations must succeed simultaneously for the tx to be valid. If any one fails, the whole tx is rejected. Since all inputs reference the same `QABI_ROOT` (enforced by the root match check on each input), they all commit to the same QABI_BLOCK, and therefore the same outputs. The batch is atomic by construction.

---

## 7. QABI_BLOCK structure

**Design note:** QABI_BLOCK commits to STABLE batch content (identities, amounts, destinations, coordinator) and NOT to per-UTXO outpoints. This lets participants re-prime without invalidating the block.

```
QABI_BLOCK {
    batch_id: 32 bytes (unique per batch attempt)
    coordinator_pubkey: FALCON pubkey of the coordinator
    
    entries: list of participant rows {
        participant_id:    H(falcon_pubkey) — stable identity from Rung 0
        amount:            int64 (value being contributed)
        destination_index: varint (which output is their destination)
    }
    
    outputs: list of destinations {
        amount: int64
        script_pubkey: variable length
    }
}

QABI_ROOT = merkle_root(serialized QABI_BLOCK fields)
```

**Identity binding:** at spend time, each input's Rung QABI evaluator reads its own Rung 0 FALCON pubkey hash and verifies that hash appears in the block's `entries[*].participant_id` list. This proves the UTXO belongs to a participant without committing to an outpoint.

**Re-priming preserves identity:** when Alice re-primes, the new UTXO inherits the same FALCON pubkey from Rung 0. The QABI_BLOCK doesn't need to change — only the coordinator's off-chain mapping of "Alice → current outpoint" needs updating.

---

## 8. Size and cost analysis

### At creation
- **33 bytes** (standard TX_MLSC scriptPubKey: `0xDF || conditions_root`)
- No extra cost for QABI relays, rungs, or chain commitments (all Merkle-committed)

### Per priming attempt
- **~300 bytes** (one covenant tx per priming)
- Chain A preimage: 32 B
- Merkle proof to relay: ~100 B
- RECURSE_MODIFIED mutation data: ~50 B
- Tx overhead: ~100 B

### Per batch spend (100 inputs)
```
Per-input witness (amortised):
  Chain B preimage:        32 B
  Merkle proofs:           ~100 B
  QABI_BLOCK entry:        ~72 B
  
Shared across tx:
  QABI_BLOCK metadata:     ~100 B
  Coordinator pubkey:      ~900 B (FALCON pubkey)
  FALCON QABO sig:         666 B
  
Total for 100 inputs:     ~22 KB witness
```

**Compared to per-input FALCON (100 × 666 B = 66.6 KB):**
- QABI batch: ~22 KB
- Saving: ~67%

For larger batches (500 inputs), the saving grows because the FALCON sig is fixed.

---

## 9. Mempool policies

### RBD — Replace-By-Depth

```
For QABI priming transactions:
  A new priming tx T2 replaces an existing priming tx T1 if:
    - T2 spends the same UTXO as T1
    - T2.chain_a_depth > T1.chain_a_depth
    - T2 is valid
    - T2 meets standard relay requirements (min fee, weight, etc.)
```

**Rationale:** Deeper preimages can only be produced by the UTXO owner (one-way hash property). RBD gives the owner a cryptographic "last word" over any conflicting priming tx.

### Standard RBF coexistence

RBD operates alongside standard RBF. For priming txs, deeper depth takes precedence. For batch spend txs, RBF applies normally (fee-based replacement).

---

## 10. Security analysis

### Attack 1: Spend-time sniping (leaked Chain B)

**Scenario:** Batch tx broadcasts, Chain B preimages are visible in mempool. Tx drops. Attacker grabs preimages.

**Defense:** The primed UTXO requires `tx.QABI_BLOCK.root == committed_QABI_ROOT`. Attacker would need to construct a tx with the same QABI_BLOCK (which locks outputs). Any change to outputs changes the root, breaking the commitment. Attacker cannot steal.

**Residual risk:** Attacker can rebroadcast Alice's exact tx, but this isn't theft — it just executes Alice's intended batch.

### Attack 2: Priming-time sniping (leaked Chain A, non-mining attacker)

**Scenario:** Alice's priming tx in mempool. Attacker grabs Chain A preimage.

**Defense:** RBD mempool policy. Alice bumps to a deeper Chain A preimage. Attacker cannot counter (they cannot produce deeper preimages without `mk_A`).

**Residual risk:** None. Alice always wins the depth war.

### Attack 3: Priming-time sniping (mining attacker)

**Scenario:** Mining attacker includes their own shallow priming tx directly in a block they mine, bypassing RBD mempool policy.

**Defense:** Time-locked Chain A. Next block, required depth advances. Alice re-primes with fresh deeper preimage. Attacker's stale hash is rejected.

**Residual risk:** A persistent mining attacker controlling every block can continuously grief Alice. This requires 51%+ mining power applied to one user, which is economically irrational (no profit, infinite cost).

### Attack 4: Chain exhaustion (DoS by repeated grief)

**Scenario:** Attacker repeatedly snipes Alice's primings, burning her Chain A depths.

**Defense:** Chain A length is wallet-chosen, typically 10,000+. Burning a depth per attack means 10,000 attacks before exhaustion. Each attack costs the attacker a priming tx fee. Economically irrational for the attacker.

**Residual risk:** With infinite attacker budget, Alice's chain eventually exhausts. She sweeps via Rung 0 and creates a new QABI-enabled UTXO.

### Attack 5: Malicious coordinator

**Scenario:** Coordinator builds a QABI_BLOCK with outputs Alice didn't agree to.

**Defense:** Alice verifies the QABI_BLOCK before priming. If the outputs are wrong, she refuses to prime. Without Alice's priming, the batch cannot execute Alice's UTXO.

**Residual risk:** Alice must validate the block pre-priming. This is a UX requirement, not a cryptographic one.

### Attack 6: Participant abandonment

**Scenario:** Alice primes, then abandons (doesn't reveal Chain B or goes offline). Other participants cannot complete the original batch.

**Defense:** The batch tx requires Chain B preimages from every participant in the `QABI_BLOCK`. Without Alice's Chain B reveal, the original batch (root R1) cannot execute. The compositional atomicity invariant then kicks in: the coordinator cannot quietly drop Alice and execute an Alice-less subset of R1, because Bob and Carol's UTXOs are still `committed_QABI_ROOT = R1`, and any tx with a different composition has a different root.

**Recovery path:**
1. Coordinator broadcasts a new commitment tx with R2 (Alice excluded, possibly with a replacement participant).
2. Bob and Carol each re-prime from R1 → R2, burning one Chain A depth each.
3. The QABIO tx executes against R2.

**Residual risk:** One burned Chain A depth per remaining participant, per abandonment event. Chain A is typically 10,000+ depths, so the economic cost is trivial but the social cost (delay, re-coordination) is real. This creates the right incentive pressure: coordinators must vet participants, and participants have a reason not to abandon.

**What Alice cannot do:** Alice cannot grief by abandoning repeatedly across multiple commitments, because each new commitment explicitly lists participants — the coordinator simply stops including her. Her only remaining options are to fully participate, or to sweep her primed UTXO via Rung 0 (which confirms her exit publicly).

### Attack 7: Double-spend via Rung 0

**Scenario:** Alice primes, then sweeps her UTXO via Rung 0 before the batch executes.

**Defense:** Both the primed spend and Rung 0 spend reference the same UTXO. Only one can confirm. If Rung 0 wins, the batch tx becomes invalid. This is Alice's choice — she's opting out of the batch.

**Residual risk:** Other participants waste fees on primings. Standard coordination problem.

### Attack 8: Collusion between coordinator and participant

**Scenario:** Coordinator and a participant collude to steal another participant's funds.

**Defense:** Each participant's UTXO is independently primed to their chosen QABI_ROOT. If the colluders construct a malicious block, the victim's UTXO must already be primed to that block's root — which the victim wouldn't do unless deceived.

**Residual risk:** Social engineering the victim into priming to a malicious root. This is an out-of-band problem, not a cryptographic one.

### Attack 9: Reorg affecting priming

**Scenario:** Alice's priming tx is confirmed in block H, but a reorg causes block H to be replaced.

**Defense:** After the reorg, Alice's UTXO state reverts. Alice re-primes. Standard Bitcoin reorg handling.

**Residual risk:** If the batch tx also confirmed and gets reorged, the funds are still safe — they revert to primed state. If the reorg is deep enough to revert multiple blocks, standard Bitcoin reorg risks apply.

---

## 11. Open questions / things to verify

1. **Covenant mechanics**: Does `RECURSE_MODIFIED` support mutating a single committed field (the `committed_QABI_ROOT`) while preserving all other conditions? Needs verification against current Ladder Script code.

2. **Coordinator pubkey commitment**: Should the UTXO also commit to the coordinator's FALCON pubkey during priming? Currently the pubkey is in the QABI_BLOCK, which is bound to the root. Seems sufficient but worth verifying.

3. **Chain B necessity**: If the root commitment alone prevents spend-time theft, is Chain B redundant? Current design keeps Chain B as an explicit "abandonment" mechanism (Alice can choose not to reveal Chain B to prevent spend). Could be simplified to just Chain A + root commitment.

4. **QABI_BLOCK serialization**: Precise format, ordering, and hashing needs to be specified so that independent implementations produce the same root.

5. **RBD consensus implications**: RBD is a mempool policy, not a consensus rule. If different nodes implement it differently, what are the effects on block propagation and reorg behaviour?

6. **Fee handling**: Who pays priming fees? Each participant pays their own. Who pays batch fees? Deducted proportionally from inputs? Specified in QABI_BLOCK?

7. **Max participants per batch**: Practical limit imposed by tx size (4 MB standard, more with blocks). ~1000 participants per batch is realistic.

8. **Chain length defaults**: Chain A at 10,000 depths? Chain B at 1 depth (single-use per primed state)? Worth tuning based on expected usage.

9. **Integration with TX_MLSC**: Current TX_MLSC has specific rules about `conditions_root` and Merkle tree structure. The QABI relays and rungs need to fit cleanly into this existing structure.

10. **Rung 0 escape hatch UX**: If a user needs to abandon a primed UTXO, Rung 0 lets them sweep it. But the user must know to do this. Wallet UX should make this automatic on batch abandonment.

---

## 12. Implementation requirements

### New block types (in `src/rung/types.h`)

```cpp
// New family 0x0Axx — QABI
QABI_COND_RELAY    = 0x0A01, // QABI conditions relay (Chain A priming state)
QABI_CONSENT_RELAY = 0x0A02, // QABI consent relay (Chain B spend consent)
QABI_BLOCK_CHECK   = 0x0A03, // Verifies tx QABI_BLOCK hashes to committed_QABI_ROOT
QABO               = 0x0A04, // Verifies tx.aggregated_sig is valid FALCON
```

Slot family `0x0Axx` is currently unallocated in the existing `RungBlockType` enum (families in use: signature `0x00xx`, timelock `0x01xx`, hash `0x02xx`, covenant `0x03xx`, recursion `0x04xx`, anchor `0x05xx`, PLC `0x06xx`, compound `0x07xx`, governance `0x08xx`, legacy `0x09xx`). QABI gets its own family.

### New consensus rules

1. `RECURSE_MODIFIED` extended (or a new recursion type) to support mutation of the `committed_QABI_ROOT` field
2. `QABI_BLOCK` serialization and hashing
3. `tx.aggregated_sig` parsing for FALCON signature
4. Chain A depth computation from block height

### New mempool policy

1. RBD replacement rule for QABI priming txs

### Wallet requirements

1. Chain A and Chain B master seed storage
2. Depth tracking per UTXO
3. Priming tx construction with correct depth for current block
4. QABI_BLOCK construction and verification before priming
5. Automatic Rung 0 sweep on batch abandonment

### Test coverage

1. Happy path: 2-party, 5-party, 100-party batches
2. Priming snipe (non-mining attacker) — RBD successfully defeats
3. Priming snipe (mining attacker) — Alice recovers at next block
4. Spend snipe — cryptographically impossible
5. Chain exhaustion — Alice sweeps via Rung 0
6. Coordinator refusal — participants recover
7. Reorg handling
8. Mempool eviction recovery

---

## Status

This is a design draft. **Hole-poking required before implementation.** See Section 10 for current security analysis; real review needed to find what I've missed.
