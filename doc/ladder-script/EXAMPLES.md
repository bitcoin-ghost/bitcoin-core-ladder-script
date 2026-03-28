# Ladder Script: Worked Examples

This document presents detailed, end-to-end examples of Ladder Script
configurations. Each example shows the use case, descriptor notation (when
applicable), block structure, evaluation logic, and approximate wire format size.

All examples use `RUNG_TX_VERSION = 4` and TX_MLSC (`0xDF`) outputs. Each
output is 8 bytes (value only) with one shared conditions_root per transaction.
A creation proof in the witness is validated at block acceptance. Inline
conditions (`0xC1`) and per-output MLSC (`0xC2`) are removed.

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
5. Calls `checker.CheckSchnorrSignature(sig, pubkey, SigVersion::LADDER, ...)`.
6. Internally, `LadderSignatureChecker` computes `SignatureHashLadder` with
   `TaggedHash("LadderSighash")`, committing to epoch, hash_type, tx version,
   locktime, prevouts, amounts, sequences, outputs, spend_type, input index,
   and conditions hash.
7. Verifies the 64-byte Schnorr signature against the x-only pubkey and sighash.
8. Returns SATISFIED on valid signature.

### Wire format size (TX_MLSC)

**Output**: 8 bytes (value only)

**Shared conditions_root**: `0xDF` + 32-byte Merkle root (once per transaction)

**Simple payment**: 647 WU / 162 vB

**Batch 100 outputs**: 7,867 WU / ~1,967 vB (cheapest format in existence)

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
  Rung 0: (hot path: 2-of-3 multisig)
    Block 0: MULTISIG
      Conditions fields: [NUMERIC(2)]         -- threshold M=2
      Witness fields:    [PUBKEY(32), PUBKEY(32), PUBKEY(32),
                          SIGNATURE(64), SIGNATURE(64)]
  Rung 1: (recovery path: timelocked single sig)
    Block 0: TIMELOCKED_SIG
      Conditions fields: [SCHEME(0x01), NUMERIC(26280)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation (Rung 0 path)

1. `EvalMultisigBlock` is called.
2. Reads NUMERIC threshold field: M=2.
3. Finds 3 PUBKEY fields and 2 SIGNATURE fields in the merged block.
4. For each signature, iterates over unused pubkeys.
5. Schnorr verification: 64-byte sig against 32-byte x-only pubkey.
6. Tracks `pubkey_used` bitmask to ensure each pubkey is used at most once.
7. If `valid_count >= 2`, returns SATISFIED.

### Evaluation (Rung 1 path)

1. `EvalTimelockedSigBlock` is called.
2. Verifies Schnorr signature against the recovery pubkey.
3. Reads NUMERIC(26280) and checks `checker.CheckSequence(26280)`.
4. Both must pass for SATISFIED.

### Wire format size (spending via Rung 0)

**MLSC proof**: ~42 bytes (reveal rung 0, provide rung 1 leaf hash)

**Witness**: n_rungs(1) + n_blocks(1) + MULTISIG micro-header(1) + NUMERIC(1+1)
+ 3xPUBKEY(3x33) + 2xSIGNATURE(2x65) + coil(6) = ~240 bytes

---

## Example 3: HTLC Atomic Swap

**Use case**: Cross-chain atomic swap. Alice pays Bob 1 BTC on Ghost Chain,
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
      Conditions fields: [HASH256(payment_hash), NUMERIC(0)]  -- 0 = no CSV for claim
      Witness fields:    [PREIMAGE(32), PUBKEY(32), SIGNATURE(64)]
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

**MLSC proof**: ~75 bytes (rung 0 blocks + rung 1 leaf hash + coil leaf hash)

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

**MLSC proof**: ~42 bytes (rung 0 revealed, rung 1 leaf hash, coil leaf hash)

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

## Example 10: ANYPREVOUT Eltoo Channel (SIG with APO Sighash)

**Use case**: An eltoo/LN-Symmetry payment channel using ANYPREVOUT signatures.
Each channel state update creates a new transaction that can spend any previous
state, enabling a clean replace-by-state mechanism without penalty transactions.

### Conditions structure

```
Ladder:
  Rung 0: (update path: either party can publish latest state)
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(65)]  -- 65 bytes: 64 + sighash type
  Rung 1: (settlement path: after CSV delay)
    Block 0: TIMELOCKED_SIG (0x0701)
      Conditions fields: [SCHEME(0x01), NUMERIC(144)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation (update path)

1. `EvalSigBlock` is called.
2. SIGNATURE field is 65 bytes: 64-byte sig + 1-byte sighash type.
3. `LadderSignatureChecker::CheckSchnorrSignature` extracts hashtype = `0x41`
   (ANYPREVOUT | ALL).
4. `SignatureHashLadder` is called with `hash_type = 0x41`:
   - `anyprevout = true` (bit 0x40 set).
   - Skips `m_prevouts_single_hash` in the sighash computation.
   - Still commits to amounts, sequences, outputs, and conditions.
5. The signature is verified against the pubkey using the APO sighash.
6. Returns SATISFIED.

### Why ANYPREVOUT matters

Because the signature does not commit to the specific prevout, the same
signed update transaction can spend any previous channel state output.
This eliminates the need for revocation mechanisms: the latest state
simply replaces any older state.

The conditions hash is still committed (unless ANYPREVOUTANYSCRIPT is used),
so the signature is bound to this specific channel's conditions.

### Wire format size

Same as Example 1 except SIGNATURE is 65 bytes instead of 64 (extra sighash
type byte). Total witness: ~109 bytes.

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
      Witness fields:    [PUBKEY(897), SIGNATURE(~690)]
  Coil: UNLOCK(0x01), INLINE(0x01), FALCON512(0x10)
```

### Evaluation

1. `EvalSigBlock` is called.
2. Finds SCHEME field: `0x10` = FALCON512.
3. `IsPQScheme(FALCON512)` returns true.
4. Routes to `EvalPQSig`:
   a. Casts checker to `LadderSignatureChecker`.
   b. Calls `ComputeSighash(SIGHASH_DEFAULT, sighash)` to get the 32-byte
      ladder sighash.
   c. Calls `VerifyPQSignature(FALCON512, sig, sighash, pubkey)`.
   d. liboqs FALCON-512 verifier checks the signature.
5. Returns SATISFIED on valid PQ signature.

### Field sizes

- PUBKEY: 897 bytes (FALCON-512 public key)
- SIGNATURE: ~690 bytes (FALCON-512 signature, variable)
- SCHEME: 1 byte (0x10)

The `FieldMaxSize(PUBKEY) = 2048` and `FieldMaxSize(SIGNATURE) = 50000`
accommodate all supported PQ schemes. `MAX_LADDER_WITNESS_SIZE = 100000`
provides headroom for SPHINCS+ signatures (49,216 bytes).

### Wire format size

**Witness**: SIG micro-header(1) + SCHEME(1) + PUBKEY(2+897) + SIGNATURE(2+690)
+ coil(6) = ~1599 bytes.

This is significantly larger than a Schnorr spend (~108 bytes) but provides
quantum resistance. A hybrid approach could use two rungs: Rung 0 with Schnorr
(compact, pre-quantum), Rung 1 with FALCON-512 (quantum-safe fallback).

---

## Example 12: Accumulator-Based Access Control

**Use case**: A membership system where spending is allowed only for parties
whose identity hash is in a Merkle accumulator. The accumulator root can be
updated through RECURSE_MODIFIED to add or remove members without changing
the UTXO structure.

### Conditions structure

```
Ladder:
  Rung 0:
    Block 0: SIG (0x0001)
      Conditions fields: [SCHEME(0x01)]
      Witness fields:    [PUBKEY(32), SIGNATURE(64)]
    Block 1: ACCUMULATOR (0x0806)
      Conditions fields: [HASH256(merkle_root)]
      Witness fields:    [HASH256(proof_node_1), ..., HASH256(proof_node_N),
                          HASH256(leaf_hash)]
  Coil: UNLOCK(0x01), INLINE(0x01), SCHNORR(0x01)
```

### Evaluation

1. **Block 0 (SIG)**: Verifies signer's Schnorr signature. SATISFIED.

2. **Block 1 (ACCUMULATOR)**: `EvalAccumulatorBlock` is called.
   - Collects all HASH256 fields. Minimum 3 required (root + 1 proof node + leaf).
     Maximum 10 allowed (root + 8 proof nodes + leaf, supporting trees up to
     256 leaves).
   - `hashes[0]` = merkle_root (from conditions).
   - `hashes[N]` = leaf_hash (the member's identity being proven).
   - `hashes[1..N-1]` = sibling proof nodes.
   - Computes the Merkle path bottom-up:
     ```
     current = leaf_hash
     for each sibling:
       if current < sibling:
         current = SHA256(current || sibling)
       else:
         current = SHA256(sibling || current)
     ```
   - Compares final `current` to `merkle_root`.
   - SATISFIED if the Merkle proof verifies (member is in the accumulator).

### Inverted accumulator (blocklist)

ACCUMULATOR is invertible. An inverted ACCUMULATOR acts as a **blocklist**:
SATISFIED when the leaf is NOT in the Merkle tree. This could be used to ban
specific identities from spending.

```
Block: !ACCUMULATOR (inverted)
  -- SATISFIED when Merkle proof fails (identity not in set)
  -- UNSATISFIED when proof succeeds (identity is blocked)
```

### Wire format size

**Conditions**: ACCUMULATOR uses explicit encoding (no implicit layout;
whitelisted from data-embedding rejection). Root hash: escape(3) + n_fields(1) +
type(1) + HASH256(1+32) = 38 bytes.

**Witness**: Additional HASH256 fields for proof (each: type(1) + hash(1+32)).
For an 8-level tree: 8 siblings + 1 leaf = 9 x 34 = 306 bytes. Plus SIG
witness = ~406 bytes total.

---

## Additional Notes

### Compound block advantages

Compound blocks (TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG,
TIMELOCKED_MULTISIG) save wire format overhead by combining multiple condition
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

**Tiered authorization**: Relay 0 requires an admin signature. Relay 1 requires
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
- The coil is always revealed
- An observer learns K (total rungs) and N (which rung was used), but not the
  conditions of unrevealed rungs

For a 2-rung ladder (e.g., normal + recovery), the MLSC proof includes:
- 1 revealed rung leaf (with blocks + pubkeys)
- 1 proof hash (the other rung's leaf)
- 1 coil leaf (always computed)
- Padded to 4 leaves with MLSC_EMPTY_LEAF

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

### Coil type semantics

- **UNLOCK**: Standard spend. The output value goes to the address in the
  spending transaction.
- **UNLOCK_TO**: Directed spend. The output value goes to the address specified
  in the coil's `address_hash` field. Per-rung destinations
  (`rung_destinations`) can override this per rung.
- **UNLOCK**: Standard spend. Covenant/recursion constraints are enforced by block types (CTV, RECURSE_*, VAULT_LOCK), not the coil.
  blocks in the rung. The output must carry specific MLSC conditions.

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
