# LADDER SCRIPT — Implementation Notes & Spec Deviations

**Bitcoin Ghost Project · March 2026 · v1.0 · Not for distribution**

This document records all deviations between the Ladder Script Block Library spec (v1.0) and the signet implementation in `src/rung/`. Each deviation is intentional — the implementation reflects what was needed to ship a working system on a Bitcoin Core v30 fork.

---

## 1. COMPARE Operator: NUMERIC, Not SCHEME

**Spec says:** `SCHEME operator · NUMERIC value_b · NUMERIC value_c`

**Implementation:** All three fields are `NUMERIC`. The operator byte (0x01–0x07) is encoded as the first NUMERIC field, not as a SCHEME field.

**Rationale:** Using SCHEME for an operator enum was a spec-level overload of the SCHEME type, which semantically represents signature algorithms. NUMERIC is the correct container for a small integer selector. The operator codes are unchanged:

| Code | Operator |
|------|----------|
| 0x01 | EQ |
| 0x02 | NEQ |
| 0x03 | GT |
| 0x04 | LT |
| 0x05 | GTE |
| 0x06 | LTE |
| 0x07 | IN_RANGE (requires third NUMERIC for upper bound) |

COMPARE evaluates `input_amount` against `value_b` (and optionally `value_c` for IN_RANGE).

---

## 2. SIG Block: Scheme Inferred from Signature Length

**Spec says:** `SCHEME scheme · PUBKEY key`

**Implementation:** SIG requires only `PUBKEY` + `SIGNATURE` fields. The signature scheme is inferred from signature size:

| Size | Inferred Scheme |
|------|-----------------|
| 64–65 bytes | Schnorr (BIP-340) |
| 8–72 bytes | ECDSA (DER-encoded) |

No explicit SCHEME field is parsed or required.

**Rationale:** Signature formats are unambiguous by length. Requiring an explicit SCHEME field would add a byte per signature block for zero additional information. If post-quantum schemes are activated, the SCHEME field can be added as an optional discriminator for the overlapping size ranges.

---

## 3. MULTISIG Block: Single Threshold, Not Separate N and M

**Spec says:** `NUMERIC n · NUMERIC m · PUBKEY[m] keys · SCHEME scheme`

**Implementation:** Single `NUMERIC` field for threshold (M). The total key count (N) is implicit from the number of PUBKEY fields present. No SCHEME field.

```
Block layout: [NUMERIC threshold] [PUBKEY key_1] ... [PUBKEY key_N] [SIGNATURE sig_1] ... [SIGNATURE sig_M]
```

**Rationale:** Encoding M separately from the PUBKEY array count would be redundant. The evaluator counts PUBKEY fields to derive N and reads the single NUMERIC for M. This matches Bitcoin Core's OP_CHECKMULTISIG design where N is implicit from the key array.

---

## 4. PREIMAGE Max Size: 32 Bytes

**Spec says:** max 32 bytes

**Implementation:** max 32 bytes (`FieldMaxSize` in types.h)

**Rationale:** PREIMAGE capped at 32 bytes (SHA-256 preimage width). Lightning HTLCs use 32-byte payment hash preimages. Larger preimages are not needed for standard hash-lock protocols and would create a data embedding channel.

---

## 5. SIGNATURE Max Size: 50,000 Bytes (PQ-Ready)

**Spec says:** max 50,000 bytes

**Implementation:** max 50,000 bytes (`FieldMaxSize` in types.h)

**Rationale:** The spec's limit accommodates the largest post-quantum scheme (SPHINCS+-SHA2-256f at 49,216 bytes). This is a size validation bound, not a policy limit — policy can restrict to classical sizes before post-quantum activation.

---

## 6. Recursion Blocks: No value_rule Parameter

**Spec says:** RECURSE_SAME, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT all carry `SCHEME value_rule` (VALUE_CONSERVED or VALUE_DECREASING).

**Implementation:** No value_rule field exists. Recursion blocks enforce covenant propagation via direct output condition comparison. Value conservation is implicit:

| Block | What the code enforces |
|-------|----------------------|
| RECURSE_SAME | Output conditions byte-identical to input conditions |
| RECURSE_MODIFIED | Single NUMERIC parameter delta matches spec |
| RECURSE_UNTIL | Re-encumber before height, terminate after (nLockTime proxy) |
| RECURSE_COUNT | Output RECURSE_COUNT decremented by exactly 1 |
| RECURSE_SPLIT | Each output re-encumbers, total value <= input |
| RECURSE_DECAY | Target parameter decreased by decay_per_step |

**Rationale:** Value conservation was intended to prevent covenant amplification, but the type system already prevents it — outputs can only carry the same or fewer sats than the input (minus fees). An explicit VALUE_CONSERVED/VALUE_DECREASING flag adds complexity without preventing any real attack.

---

## 7. RECURSE_UNTIL: nLockTime as Height Proxy

**Spec says:** `NUMERIC until_height` with block height checked at consensus.

**Implementation:** Uses `max(ctx.block_height, tx.nLockTime)` as effective height. When `nLockTime < LOCKTIME_THRESHOLD` (500,000,000), it is treated as a block height.

**Rationale:** This follows the CLTV precedent exactly. CLTV (BIP-65) does not access the block height directly — it compares against `nLockTime`, and consensus rules ensure the transaction cannot be mined before that height. RECURSE_UNTIL uses the same mechanism. The spending transaction sets `nLockTime` to the current height (standard anti-fee-sniping behaviour), and RECURSE_UNTIL compares against it. This avoids threading block height through the entire validation stack, which would touch consensus-critical Bitcoin Core code.

---

## 8. Anchor Blocks: Structural Validation Only

**Spec says:** Each anchor type validates specific semantic parameters (state_root format, protocol_id registry, sequence monotonicity).

**Implementation:** Anchor evaluators perform structural checks only:

| Block | What is validated |
|-------|------------------|
| ANCHOR | At least one field present |
| ANCHOR_CHANNEL | 2 pubkeys present, optional commitment > 0 |
| ANCHOR_POOL | 1 hash present, optional count > 0 |
| ANCHOR_RESERVE | 2 numerics (n <= m) + 1 hash |
| ANCHOR_SEAL | 2 hashes present |
| ANCHOR_ORACLE | 1 pubkey present, optional count > 0 |

**Rationale:** Semantic validation of L2 state (protocol_id registry, state root correctness, sequence monotonicity) requires L2 context that L1 consensus does not have. Anchor blocks are commitment slots — L1 validates structure, L2 validates semantics. This matches the OP_RETURN paradigm where L1 accepts any 80-byte payload.

---

## 9. Policy: All Families Standard

**Spec implies:** Base blocks standard, covenant/recursion/PLC blocks non-standard until activation.

**Implementation:** All 62 active block types pass `IsStandardRungTx()` policy checks. Family classification functions (`IsBaseBlockType`, `IsCovenantBlockType`, `IsStatefulBlockType`) exist but are not used as policy gates.

**Rationale:** Ghost Core operates on its own signet where all nodes run the same software. All block types are consensus-valid from genesis. The classification functions are retained for documentation and for potential mainnet activation logic.

---

## 10. PUBKEY Validation: Compressed Prefix Only

**Spec says:** max 64 bytes, compressed keys validated

**Implementation:**
- 32-byte keys (x-only/Schnorr): no prefix validation (correct — x-only keys have no prefix)
- 33-byte keys (compressed SEC): must start with 0x02 or 0x03
- 34–64 bytes (reserved for PQ): no format validation beyond size bounds

**Rationale:** X-only keys are inherently valid 32-byte scalars (any 32 bytes is a valid x-coordinate candidate). Post-quantum key formats are not yet standardized — validation will be added when PQ schemes are specified.

---

## Wire Format Summary

The serialization format matches the spec with one structural note:

```
LadderWitness (v2 binary):
  [n_rungs: varint]
    per rung:
      [n_blocks: varint]
        per block:
          [block_type: uint16 LE]
          [inverted: uint8]
          [n_fields: varint]
            per field:
              [data_type: uint8]
              [data_len: varint]
              [data: bytes]
  [coil_type: uint8]
  [attestation: uint8]
  [scheme: uint8]
  [address_hash_len: varint]           // 0 = none, 32 = SHA256
  [address_hash: bytes]                // SHA256(destination spk), raw address never on-chain
  [n_coil_conditions: varint]
    per coil condition rung: (same as input rung format)

RUNG_TX wire format with TX_MLSC conditions:
  Flag byte 0x02 signals RUNG_TX serialization
  Shared per-tx: [0xDF MLSC prefix] + [conditions_root (32 bytes)]
  Each output: 8 bytes (value only)
  Creation proof validated at block acceptance
  Leaf: TaggedHash("LadderLeaf", structural_template || value_commitment)
  Each rung coil has output_index declaring which output it governs
```

**Transaction version:** `RUNG_TX_VERSION = 4`

**Signature hash:** `SignatureHashLadder` using tagged hash `"LadderSighash"`, commits to serialised rung conditions from spent output. `SigVersion::LADDER = 4`.

---

## Policy Limits

| Limit | Value |
|-------|-------|
| Max rungs per ladder | 16 |
| Max blocks per rung | 8 |
| Max fields per block | 16 |
| Max ladder witness size | 100,000 bytes |
| Max coil address size | 42 bytes |

---

## RPC Interface

| RPC | Purpose |
|-----|---------|
| `createrung` | Build ladder witness hex from JSON rung spec |
| `decoderung` | Decode ladder witness hex to JSON |
| `validateladder` | Validate all witnesses in a v4 RUNG_TX |
| `createtxmlsc` | Create unsigned v4 TX_MLSC transaction (replaces `createrungtx`) |
| `signladder` | Sign v4 tx inputs with funding tx auto-lookup (replaces `signrungtx`) |
| `computectvhash` | Compute BIP-119 template hash for a v4 tx |
| `generatepqkeypair` | Generate a PQ keypair |
| `pqpubkeycommit` | Compute PQ pubkey commitment |
| `extractadaptorsecret` | Extract adaptor secret from completed signature |
| `verifyadaptorpresig` | Verify an adaptor pre-signature |
| `parseladder` | Parse descriptor string to conditions |
| `formatladder` | Format conditions as descriptor string |
| `decodetxmlsc` | Decode a TX_MLSC transaction |
| `validaterungtx` | Validate a rung transaction |
| `getladdertxinfo` | Get ladder transaction info |

---

## Test Coverage

Functional tests in `test/functional/feature_rung_tx.py`:

**Core:** createrung, decoderung, validateladder, malformed input, SIG spend, HASH_PREIMAGE, CSV, CLTV, MULTISIG, SIG+CSV compound, OR logic, inverted CSV, inverted HASH_PREIMAGE

**Covenant/PLC:** TAGGED_HASH, AMOUNT_LOCK, AMOUNT_LOCK out-of-range, ANCHOR, COMPARE, CTV template, VAULT_LOCK

**Negative:** wrong sig, wrong preimage, CSV too early, CLTV too early, CTV wrong template, VAULT wrong key, COMPARE fails, TAGGED_HASH wrong preimage

**Recursion:** RECURSE_SAME single hop, RECURSE_SAME negative (different conditions), RECURSE_SAME 3-hop chain, RECURSE_UNTIL re-encumber before termination, RECURSE_UNTIL termination at height, RECURSE_UNTIL negative (no re-encumber), RECURSE_COUNT countdown 2->0 + free spend

**Multi-input/output:** multi-input multi-output spend

---

*Ladder Script Implementation Notes v1.0 · Bitcoin Ghost Project · March 2026 · Not for distribution*
