# Ladder Script: Worked Examples

This document presents detailed, end-to-end examples of Ladder Script
configurations. Each example shows the use case, descriptor notation (when
applicable), block structure, evaluation logic, and approximate wire format size.

All examples use `RUNG_TX_VERSION = 4` and TX_MLSC (`0xDF`) outputs. Each
output is 8 bytes (value only) on the wire with one shared `conditions_root`
per transaction. The 32-byte root is recovered at spend time from the
synthetic UTXO entry at `(txid, MLSC_ROOT_VOUT = 0xFFFFFFFF)`. Inline
conditions (`0xC1`) — an earlier draft format — are rejected as defence in
depth.

---

## Example 1: Simple Schnorr Spend (SIG)

**Use case**: The simplest Ladder Script transaction. A single owner controls a
UTXO with one Schnorr signature.

### Descriptor

```
ladder(sig(@alice))
```

### Conditions structure

```
Ladder:
  Rung 0:
    Block 0: SIG
      Conditions fields: [SCHEME(0x01)]      -- Schnorr
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation

1. `EvalSigBlock` is called.
2. Finds PUBKEY field (32-byte x-only pubkey from witness).
3. Finds SIGNATURE field (64-byte Schnorr sig from witness).
4. Finds SCHEME field (0x01 = SCHNORR).
5. Library computes the Ladder sighash via `api::SignatureHashLadder` using
   `TaggedHash("LadderSighash/v1")`, committing to epoch, hash_type, tx
   version, locktime, prevouts, amounts, sequences, outputs, spend_type,
   input index, and conditions hash.
6. Calls `sig_checker.CheckSchnorrSignature(sig, pubkey, sighash)` on the
   supplied `api::LadderSigChecker` adapter.
7. Returns SATISFIED on valid signature.

### Wire format size (TX_MLSC)

**Output**: 8 bytes (value only) on the wire.

**Shared conditions_root**: `0xDF` + 32-byte Merkle root (once per transaction).

**Simple payment (1-in, 1-out)**: **109 vB** (key-path) — 1 vB smaller than
P2WPKH (110), 2 vB smaller than P2TR key-path (111). **148 vB** for
script-path no-tweak.

**Batch 100 outputs**: **911 vB** — 71% smaller than P2WPKH (3,179 vB).

Full sizing breakdown for every shape lives in [`SIZING.md`](SIZING.md).

---

## Example 2: 2-of-3 Multisig Vault with CSV Recovery

**Use case**: A corporate treasury vault requiring 2-of-3 director signatures
for normal spending, with a single recovery key that activates after 26,280
blocks (~6 months).

### Descriptor

```
ladder(or(
  multisig(2, @alice, @bob, @carol),
  timelocked_sig(@recovery, 26280)
))
```

### Conditions structure

```
Ladder:
  Rung 0: (hot path: 2-of-3 multisig, v2 inner-Merkle)
    Block 0: MULTISIG
      Conditions fields: [NUMERIC(2), SCHEME(0x01), HASH256(pubkey_root, 32)]
                         -- K=2, Schnorr, pubkey_root commits the 3-pubkey set
      Witness fields:    K=2 triplets of (PUBKEY, MERKLE_PROOF, SIGNATURE)
                         -- the third pubkey is never on chain, only its
                         contribution to pubkey_root is
  Rung 1: (recovery path: timelocked single sig)
    Block 0: TIMELOCKED_SIG
      Conditions fields: [SCHEME(0x01), NUMERIC(26280)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation (Rung 0 path)

1. `EvalMultisigBlock` is called.
2. Reads `NUMERIC(K=2)` and `HASH256(pubkey_root)` from conditions.
3. Witness must contain exactly `3K = 6` fields in repeating
   `(PUBKEY, MERKLE_PROOF, SIGNATURE)` triplet order.
4. For each triplet: verify the MERKLE_PROOF binds the revealed PUBKEY to
   `pubkey_root`, then verify the SIGNATURE under that PUBKEY.
5. Reject if any pubkey is revealed twice (no double-counting).
6. All K verified, all distinct → SATISFIED.

### Evaluation (Rung 1 path)

1. `EvalTimelockedSigBlock` is called.
2. Verifies Schnorr signature against the recovery pubkey.
3. Reads NUMERIC(26280) and checks `checker.CheckSequence(26280)`.
4. Both must pass for SATISFIED.

### Wire format size (spending via Rung 0)

**MLSC proof**: ~42 bytes (reveal rung 0, provide rung 1 leaf hash)

**Witness**: n_rungs(1) + n_blocks(1) + MULTISIG escape header(3) + n_fields(1)
+ 2 × (PUBKEY(33+1) + MERKLE_PROOF(64+1) + SIGNATURE(64+1)) + coil(6)
= ~340 bytes (depth-2 inner tree, each proof carries 1 sibling × 32 B,
plus length prefixes). Conditions side stays constant ~38 B regardless of N
because the pubkey set is committed via the 32-byte HASH256 root.

---

## Example 3: HTLC Atomic Swap

**Use case**: Cross-chain atomic swap. Alice pays Bob 1 BTC on Bitcoin,
locked by a hash. Bob reveals the preimage to claim, or Alice reclaims after a
timeout. This uses the compound HTLC block, which combines hash check + CSV +
SIG into one block per rung.

### Descriptor (manual, HTLC not in descriptor parser)

```
Rung 0: HTLC block (Bob claims with preimage + sig)
Rung 1: TIMELOCKED_SIG block (Alice reclaims after timeout)
```

### Conditions structure

```
Ladder:
  Rung 0: (claim path)
    Block 0: HTLC (0x0702)
      Conditions fields: [HASH256(payment_hash), NUMERIC(0), SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64), PUBKEY(32), PREIMAGE(32), NUMERIC]
  Rung 1: (refund path)
    Block 0: TIMELOCKED_SIG (0x0701)
      Conditions fields: [SCHEME(0x01), NUMERIC(144)]          -- 144 blocks (~24h)
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation (Rung 0: Bob claims)

1. `EvalHTLCBlock` is called.
2. Step 1: Hash preimage check.
   - Finds HASH256 field (payment_hash, 32 bytes from conditions).
   - Finds PREIMAGE field (32 bytes from witness).
   - Computes `SHA256(preimage)` and compares to payment_hash.
   - Must match to proceed.
3. Step 2: CSV check.
   - Reads NUMERIC(0). With the locktime disable flag not set and value 0, the
     sequence check passes immediately.
4. Step 3: Signature check.
   - Finds PUBKEY (Bob's key, bound by Merkle proof).
   - Finds SIGNATURE (Bob's Schnorr sig).
   - Verifies signature via `CheckSchnorrSignature`.
5. All three sub-checks pass: returns SATISFIED.

### Evaluation (Rung 1: Alice refunds)

1. `EvalTimelockedSigBlock` is called.
2. Verifies Alice's Schnorr signature.
3. Checks `CheckSequence(144)`: the UTXO must be at least 144 blocks old.
4. Both pass: returns SATISFIED.

### Wire format size (claim path via Rung 0)

**MLSC proof**: ~75 bytes (rung 0 blocks + rung 1 leaf hash; no separate coil leaf)

**Witness**: HTLC micro-header(1) + HASH256(32) + PREIMAGE(1+32) + NUMERIC(1+1)
+ PUBKEY(1+32) + SIGNATURE(1+64) + coil(6) = ~172 bytes

---

## Example 4: CTV Covenant Chain

**Use case**: A covenant that constrains the spending transaction to a
predetermined template. This can be used to create pre-signed transaction trees,
payment pools, or congestion control batches.

### Conditions structure

```
Ladder:
  Rung 0:
    Block 0: CTV (0x0301)
      Conditions fields: [HASH256(template_hash)]
      Witness fields:    (none -- CTV is witness-free)
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation

1. `EvalCTVBlock` is called with the `RungEvalContext`.
2. Extracts the 32-byte HASH256 (template_hash) from conditions.
3. Calls `ComputeCTVHash(tx, input_index)` which computes:
   ```
   SHA256(version || locktime || scriptsigs_hash || num_inputs ||
          sequences_hash || num_outputs || outputs_hash || input_index)
   ```
4. Compares computed hash to committed template_hash byte-for-byte.
5. Returns SATISFIED on exact match.

### CTV template hash details

The template hash commits to every structural aspect of the spending
transaction except the input prevouts (allowing the same template to be used
regardless of which UTXO funds it). The `outputs_hash` includes each output's
amount (8 bytes LE), scriptPubKey length (8 bytes LE), and scriptPubKey bytes.

### Wire format size

**Conditions (implicit layout)**: CTV micro-header(1) + HASH256(32) = 33 bytes
in conditions.

**MLSC output**: 33 bytes.

**Witness**: n_rungs(1) + n_blocks(1) + CTV micro-header(1) + coil(6) = 9 bytes.
CTV requires no witness data fields. This makes it one of the most compact
block types.

---

## Example 5: Rate-Limited Cold Storage (SIG + RATE_LIMIT)

**Use case**: A cold storage wallet that can spend at most 100,000 satoshis per
transaction. This prevents a compromised key from draining the entire wallet
in a single transaction.

### Conditions structure

```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
    Block 1: RATE_LIMIT (0x0671)
      Conditions fields: [NUMERIC(100000), NUMERIC(1000000), NUMERIC(144)]
                          -- max_per_block=100000, accumulation_cap=1000000,
                          -- refill_blocks=144
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation

1. **Block 0 (SIG)**: `EvalSigBlock` verifies the Schnorr signature against the
   pubkey. Returns SATISFIED on valid sig.

2. **Block 1 (RATE_LIMIT)**: `EvalRateLimitBlock` is called.
   - Reads 3 NUMERIC fields: max_per_block(100000), accumulation_cap(1000000),
     refill_blocks(144).
   - Checks `output_amount <= max_per_block`. If the output exceeds 100,000
     sats, returns UNSATISFIED.
   - Accumulation tracking (across UTXO chain) uses covenant state.
   - Returns SATISFIED if the single-tx limit is met.

3. Both blocks must be SATISFIED (AND logic within rung).

### Wire format size

**Conditions**: SIG block(1+1) + RATE_LIMIT micro-header(1) + 3xNUMERIC(~9)
= ~12 bytes in conditions.

**Witness**: SIG fields(1+32+1+64) + RATE_LIMIT fields(0) + coil(6) = ~105 bytes

---

## Example 6: Dead Man's Switch

**Use case**: Funds go to the heir if the owner does not spend for 52,560
blocks (~1 year). Normal spending requires only the owner's signature. After
the timeout, the heir's signature suffices.

### Descriptor

```
ladder(or(
  sig(@owner),
  and(csv(52560), sig(@heir))
))
```

### Conditions structure

```
Ladder:
  Rung 0: (owner spends normally)
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
  Rung 1: (heir claims after timeout)
    Block 0: CSV (0x0101)
      Conditions fields: [NUMERIC(52560)]
    Block 1: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation (Rung 0: owner path)

1. `EvalSigBlock`: verifies owner's Schnorr signature.
2. One block, one check. SATISFIED.

### Evaluation (Rung 1: heir path)

1. `EvalCSVBlock`: reads NUMERIC(52560), calls `checker.CheckSequence(52560)`.
   The input's nSequence must encode at least 52,560 blocks since the UTXO
   was confirmed. SATISFIED if the timelock has elapsed.
2. `EvalSigBlock`: verifies heir's Schnorr signature. SATISFIED on valid sig.
3. Both blocks SATISFIED (AND logic): rung 1 passes.

### Privacy note

When the owner spends via Rung 0, the MLSC proof reveals only Rung 0's
conditions. The heir's recovery path (Rung 1) remains hidden behind its Merkle
leaf hash. An observer cannot determine that a dead man's switch exists.

### Wire format size (owner path)

**MLSC proof**: ~42 bytes (rung 0 revealed, rung 1 leaf hash; no separate coil leaf)

**Witness**: SIG(1+1+1+32+1+64) + coil(6) = ~106 bytes

---

## Example 7: OUTPUT_CHECK Governance (SIG + OUTPUT_CHECK)

**Use case**: A DAO treasury that requires a director's signature and
constrains the spending transaction to send at least 500,000 sats to the DAO's
operating address (output index 0) and at least 100,000 sats to a fee reserve
address (output index 1).

### Conditions structure

```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
    Block 1: OUTPUT_CHECK (0x0807)
      Conditions fields: [NUMERIC(0), NUMERIC(500000), NUMERIC(4294967295),
                          HASH256(sha256_of_dao_scriptPubKey)]
    Block 2: OUTPUT_CHECK (0x0807)
      Conditions fields: [NUMERIC(1), NUMERIC(100000), NUMERIC(4294967295),
                          HASH256(sha256_of_reserve_scriptPubKey)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation

1. **Block 0 (SIG)**: Verifies director's signature. SATISFIED.

2. **Block 1 (OUTPUT_CHECK index 0)**:
   - Reads output_index=0, min_sats=500000, max_sats=4294967295.
   - Checks `tx.vout[0].nValue >= 500000`.
   - Computes `SHA256(tx.vout[0].scriptPubKey)` and compares to committed hash.
   - SATISFIED if both value and script match.

3. **Block 2 (OUTPUT_CHECK index 1)**:
   - Same logic for output index 1 with min_sats=100000.
   - SATISFIED if the reserve address receives at least 100,000 sats.

4. All 3 blocks SATISFIED: rung passes.

### Descriptor notation

```
ladder(and(
  sig(@director),
  output_check(0, 500000, 4294967295, <dao_script_hash>),
  output_check(1, 100000, 4294967295, <reserve_script_hash>)
))
```

### Wire format size

**Conditions**: SIG(1+1) + OUTPUT_CHECK(1+3x~3+32) + OUTPUT_CHECK(1+3x~3+32)
= ~82 bytes in conditions per rung.

---

## Example 8: COSIGN Paired UTXOs

**Use case**: Two UTXOs that can only be spent together in the same transaction.
UTXO_A requires UTXO_B to be present, and vice versa. This is useful for
atomic multi-party settlements or linked state channels.

### Conditions structure

**UTXO_A**:
```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
    Block 1: COSIGN (0x0681)
      Conditions fields: [HASH256(SHA256(scriptPubKey_B))]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

**UTXO_B**:
```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
    Block 1: COSIGN (0x0681)
      Conditions fields: [HASH256(SHA256(scriptPubKey_A))]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation (UTXO_A, input 0)

1. **Block 0 (SIG)**: Verifies Alice's signature. SATISFIED.

2. **Block 1 (COSIGN)**: `EvalCosignBlock` is called.
   - Extracts the 32-byte HASH256 = `SHA256(scriptPubKey_B)`.
   - Iterates over other inputs in the transaction.
   - For input 1 (UTXO_B), computes `SHA256(spent_outputs[1].scriptPubKey)`.
   - Compares to the committed hash.
   - Match found: returns SATISFIED.

3. Both blocks SATISFIED: rung passes.

The same evaluation happens symmetrically for UTXO_B (input 1), checking that
UTXO_A (input 0) is present.

### Wire format size

**Conditions per UTXO**: SIG(1+1) + COSIGN(1+32) = 35 bytes per rung.

---

## Example 9: Recursive Countdown (RECURSE_COUNT)

**Use case**: A vesting schedule that releases funds after 12 monthly intervals.
Each spend decrements the counter and re-encumbers the output with the new
count. When the counter reaches 0, the covenant terminates and the funds are
freely spendable.

### Conditions structure

```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
    Block 1: RECURSE_COUNT (0x0404)
      Conditions fields: [NUMERIC(12)]   -- 12 remaining steps
    Block 2: CSV (0x0101)
      Conditions fields: [NUMERIC(4380)] -- ~1 month between steps
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation (count > 0)

1. **Block 0 (SIG)**: Verifies the owner's signature. SATISFIED.

2. **Block 1 (RECURSE_COUNT)**: `EvalRecurseCountBlock` is called.
   - Reads NUMERIC field: count = 12.
   - count > 0, so the output must re-encumber with count-1.
   - Builds a copy of the revealed rung with RECURSE_COUNT NUMERIC decremented
     to 11.
   - Computes the new rung leaf hash: `ComputeRungLeaf(mutated_rung, pubkeys)`.
   - Replaces the revealed rung's leaf in the verified leaf array.
   - Rebuilds the Merkle tree: `BuildMerkleTree(mutated_leaves)`.
   - Checks that the output's MLSC root matches the expected root.
   - SATISFIED if roots match.

3. **Block 2 (CSV)**: Checks that at least 4,380 blocks have elapsed since the
   UTXO was confirmed. SATISFIED if timelock met.

4. All blocks SATISFIED: rung passes. The output carries MLSC root with count=11.

### Evaluation (count == 0: final spend)

1. **Block 0 (SIG)**: Verifies signature. SATISFIED.
2. **Block 1 (RECURSE_COUNT)**: count = 0. The covenant terminates. Returns
   SATISFIED without checking the output. The funds can go anywhere.
3. **Block 2 (CSV)**: Checks timelock. SATISFIED.

### Wire format size

**Conditions**: SIG(1+1) + RECURSE_COUNT(1+1) + CSV(1+2) = 7 bytes in
conditions. Plus coil overhead.

---

## Example 10: ANYPREVOUT Eltoo Channel — not currently supported

LN-Symmetry / eltoo channels would require ANYPREVOUT (`0x40-0x43`)
or ANYPREVOUTANYSCRIPT (`0xC0-0xC3`) sighash flags. Both are
unconditionally rejected by `SignatureHashLadder` /
`SignatureHashLadderKeyPath` in the current implementation — the
flags allow signature replay against UTXOs the signer did not intend
to spend, and Ladder Script does not yet provide the dedicated
pubkey-prefix scheme that BIP-118 mitigates the risk with.

A future opt-in mechanism (a dedicated block type or pubkey-prefix
scheme) is required before this pattern becomes available. See the
sighash entry in [`GLOSSARY.md`](GLOSSARY.md) for the rejected hash-
type ranges.

---

## Example 11: Post-Quantum Vault (SIG with FALCON-512)

**Use case**: A quantum-resistant vault using FALCON-512 signatures. Protects
funds against future quantum computers that could break elliptic curve
cryptography.

### Conditions structure

```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x10)]         -- FALCON512
      Witness fields:    [PUBKEY(897), SIGNATURE(666)]
  Coil: UNLOCK(0x01), INLINE(0x01), FALCON512(0x10)
```

### Evaluation

1. `EvalSigBlock` is called.
2. Finds SCHEME field: `0x10` = FALCON512.
3. `IsPQScheme(FALCON512)` returns true.
4. Routes to `EvalPQSig`:
   a. Computes the 32-byte ladder sighash via `api::SignatureHashLadder`
      (always `SIGHASH_DEFAULT` for PQ schemes).
   b. Calls `VerifyPQSignature(FALCON512, sig, sighash, pubkey)`.
   c. liboqs FALCON-512 verifier checks the signature.
5. Returns SATISFIED on valid PQ signature.

### Field sizes

- PUBKEY: 897 bytes (FALCON-512 public key)
- SIGNATURE: 666 bytes (FALCON-512 signature — exact, fixed size)
- SCHEME: 1 byte (`0x10`)

`FieldMaxSize(PUBKEY) = 2,048` and `FieldMaxSize(SIGNATURE) = 50,000`
accommodate all supported PQ schemes. `MAX_LADDER_WITNESS_SIZE = 100,000`
provides headroom for SPHINCS+ signatures (49,216 bytes).

### Wire format size

**Witness**: SIG micro-header(1) + SCHEME(1) + PUBKEY(2+897) + SIGNATURE(2+666)
+ coil(6) = ~1,575 bytes.

This is significantly larger than a Schnorr spend (~109 vB) but provides
quantum resistance. A hybrid approach could use two rungs: Rung 0 with Schnorr
(compact, pre-quantum), Rung 1 with FALCON-512 (quantum-safe fallback). For
**batched** PQ spends (multiple inputs gated by the same FALCON key), see
the `PQ_BATCH` block — amortises to ~55 vB per input by revealing the pubkey
+ signature once per tx via an anchor input. See
[`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md) and [`SIZING.md`](SIZING.md).

---

## Example 12: Accumulator-Based Access Control

**Use case**: A membership system where spending is allowed only for parties
whose identity hash is in a Merkle accumulator. The accumulator root can be
updated through RECURSE_MODIFIED to add or remove members without changing
the UTXO structure.

### Conditions structure (v0.6 inner-Merkle redesign)

```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
    Block 1: ACCUMULATOR (0x0806)
      Conditions fields: [HASH256(set_root)]
      Witness fields:    [NUMERIC(element_id), MERKLE_PROOF(siblings)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

The set members are addressed by positional `element_id` (0 ≤ id ≤ 65535).
The leaf hash for member i is `TaggedHash("LadderAccumulatorLeaf/v1", i_LE)`
— not free attacker bytes, which closes the v0.5 audit-2 finding E-001.

### Evaluation

1. **Block 0 (SIG)**: Verifies signer's Schnorr signature. SATISFIED.
2. **Block 1 (ACCUMULATOR)**: `EvalAccumulatorBlock` reads the conditions
   `set_root`, the witness `element_id` and `MERKLE_PROOF`. Computes
   `leaf = TaggedHash("LadderAccumulatorLeaf/v1", element_id_LE)`, walks
   `current = TaggedHash("LadderAccumulatorInterior/v1", min(current, sibling) || max(current, sibling))`
   for each 32-byte sibling in MERKLE_PROOF (max depth = 4), and SATISFIED
   iff the final `current` equals `set_root`.

Caps: 1 ACCUMULATOR per rung; 2 ACCUMULATOR blocks per tx (across all MLSC-spending inputs; bootstrap inputs excluded — see audit #6 F-2).

### Inverted accumulator (blocklist)

ACCUMULATOR is invertible. An inverted ACCUMULATOR acts as a **blocklist**:
SATISFIED when the proof fails (element NOT in the set).

```
Block: !ACCUMULATOR (inverted)
  -- SATISFIED when membership proof fails (element not in set)
  -- UNSATISFIED when proof succeeds (element is blocked)
```

### Wire format size

**Conditions**: 38 bytes (block header + 1 HASH256), constant in set size.

**Witness**: NUMERIC(element_id, ~3 B) + MERKLE_PROOF(depth × 32 B).
At max depth 4: 5 + 130 = 135 bytes. Plus SIG witness ≈ 235 bytes total
per spend.

---

## Additional Notes

### Compound block advantages

Compound blocks (TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG,
TIMELOCKED_MULTISIG, ANCHOR_FEE) save wire format overhead by combining multiple condition
checks into a single block. Instead of:

```
Rung:
  Block 0: SIG   (1 byte micro-header + fields)
  Block 1: CSV   (1 byte micro-header + fields)
```

A TIMELOCKED_SIG block encodes both in one:

```
Rung:
  Block 0: TIMELOCKED_SIG  (1 byte micro-header + SCHEME + NUMERIC)
```

This saves 1 byte per additional block eliminated (the micro-header overhead)
and enables tighter implicit field layouts.

### Relay usage patterns

**Key sharing**: Multiple rungs reference the same signing key via a relay.
The relay contains a SIG block; rungs declare a relay_ref. The key is committed
once in the Merkle tree (via relay leaf), reducing conditions size.

**Tiered authorisation**: Relay 0 requires an admin signature. Relay 1 requires
Relay 0 + a department signature. Rungs reference Relay 1 for department-level
actions. Maximum chain depth is 4.

**KEY_REF_SIG**: A rung can use `KEY_REF_SIG(relay_index, block_index)` to
verify a signature against a pubkey stored in a relay block. The relay must
be in the rung's relay_refs. This separates key storage (relay) from key
usage (rung).

### MLSC privacy characteristics

When spending via rung N of a K-rung ladder:
- Only rung N's conditions are revealed
- Rungs 0..N-1 and N+1..K-1 are represented by opaque leaf hashes
- Referenced relays are revealed; unreferenced relays are opaque
- The coil is always revealed (it travels in the witness, not as a
  separate Merkle leaf — the four coil bytes are folded into the
  spending rung's structural template)
- An observer learns K (total rungs) and N (which rung was used), but not the
  conditions of unrevealed rungs

For a 2-rung ladder (e.g., normal + recovery), the MLSC proof includes:
- 1 revealed rung leaf (with blocks + pubkeys + folded-in coil)
- 1 proof hash (the other rung's leaf)
- Padded to 2 leaves (the next power of 2) with MLSC_EMPTY_LEAF if
  needed

### Diff witness savings

For transactions with multiple inputs spending identical conditions (e.g.,
consolidating UTXOs from the same address), diff witnesses provide significant
savings. Input 0 carries the full witness; inputs 1..N carry only:

```
0 (sentinel) + input_index(1) + n_diffs(1) + per-diff overhead
```

Each diff specifies (rung_index, block_index, field_index) + the replacement
field. For a simple SIG spend where only the SIGNATURE differs, each diff
witness is approximately:

```
sentinel(1) + input_index(1) + n_diffs(1) + rung_idx(1) + block_idx(1) +
field_idx(1) + type(1) + sig_len(1) + signature(64) + coil(6) = 78 bytes
```

Compared to a full witness (~108 bytes), this saves ~30 bytes per additional
input. For 10 consolidation inputs, the saving is approximately 270 bytes.

### Signature scheme routing

The SCHEME field controls signature verification routing:

| Scheme value | Routing |
|-------------|---------|
| `0x01` (SCHNORR) | `CheckSchnorrSignature` with x-only pubkey |
| `0x02` (ECDSA) | `CheckECDSASignature` with compressed pubkey |
| `0x10` (FALCON512) | `VerifyPQSignature(FALCON512, ...)` via liboqs |
| `0x11` (FALCON1024) | `VerifyPQSignature(FALCON1024, ...)` via liboqs |
| `0x12` (DILITHIUM3) | `VerifyPQSignature(DILITHIUM3, ...)` via liboqs |
| `0x13` (SPHINCS_SHA) | `VerifyPQSignature(SPHINCS_SHA, ...)` via liboqs |
| No SCHEME field | Size-based routing: 64-65 bytes = Schnorr, 8-72 bytes = ECDSA |

PQ schemes require `HasPQSupport()` to return true (liboqs compiled in).
Without PQ support, PQ signature verification returns ERROR.

### Template reference (conditions inheritance)

When conditions use a template reference (`n_rungs == 0` in conditions), the
conditions are inherited from another input with optional field-level diffs.
`ResolveTemplateReference` copies the source input's rungs, coil, and relays,
then applies diffs (which must match field types). Template references cannot
chain (source must not itself be a template reference).

### Coil type semantics (v0.8)

- **UNLOCK**: Standard spend. The spender must satisfy at least one rung;
  output destinations are unconstrained at the coil level.
- **UNLOCK_TO**: Reserved for a future wire format that binds output structure
  on-chain (e.g. via a CTV-style template hash). v0.8 removed the
  `coil.address_hash` and `coil.rung_destinations` fields (E-009/E-010 — they
  were unbound spender data channels). For on-chain output binding today,
  use rung-level `OUTPUT_CHECK` or `CTV` blocks.

### Evaluation result semantics

| Result | Meaning | Inversion |
|--------|---------|-----------|
| SATISFIED | Condition met | Flips to UNSATISFIED |
| UNSATISFIED | Condition not met (valid witness, just fails) | Flips to SATISFIED |
| ERROR | Malformed block (consensus failure) | Stays ERROR |
| UNKNOWN_BLOCK_TYPE | Forward compatibility | Inverted: becomes ERROR |

UNKNOWN_BLOCK_TYPE allows future soft forks to add new block types. Existing
nodes treat unknown types as UNSATISFIED, so ladders with unknown blocks in
non-taken rungs remain valid. However, inverting an unknown type produces ERROR
to prevent attackers from creating "always-satisfied" conditions with invented
block types.
