<!--
  INTEGRATION STATUS
  ==================
  This file is a standalone QABIO specification in BIP format, intended
  to be merged into the main BIP-XXXX.md (the Ladder Script BIP) as a
  new section once that file's current in-flight edits are committed.

  QABIO is not a separate BIP with its own number — it is an extension
  to the Ladder Script proposal and should appear inside BIP-XXXX.md as
  a subsection (e.g., "Extension: QABIO — Quantum Atomic Batch Input /
  Output"). The content below is structured to drop directly into
  BIP-XXXX.md with minimal reshaping:

    1. The top-of-file BIP header block is dropped on integration
       (replaced by a subsection heading in the host BIP).
    2. The "Abstract" becomes an introductory paragraph for the
       subsection.
    3. "Specification" through "Test Vectors" map directly to
       subsections of the host BIP's QABIO section.
    4. "Reference Implementation" and "Copyright" are absorbed into
       the host BIP's existing equivalents.

  The canonical design doc remains doc/ladder-script/project_qabi.md
  (693 lines, fully up to date). This bip-qabio.md is the BIP-format
  adaptation for eventual integration into the Ladder Script BIP.
-->

<pre>
  Layer: Consensus (soft fork)
  Title: QABIO — Quantum Atomic Batch Input / Output
  Author: Defenwycke &lt;defenwycke@icloud.com&gt;
  Status: Draft (to be merged into Ladder Script BIP)
  Type: Extension to BIP-RUNG / Ladder Script
  Created: 2026-04-10
  License: BSD-2-Clause
  Depends-On: BIP-RUNG (Ladder Script, TX_MLSC, RUNG_TX_VERSION=4)
</pre>

## Abstract

This BIP specifies **QABIO** (Quantum Atomic Batch Input / Output): a native Ladder Script facility that allows N independent parties to batch their `rung_tx` UTXOs into a single transaction authorised by **one** post-quantum FALCON-512 signature from a designated coordinator, without requiring per-input PQ signatures, escrow, pre-registration, or a separate commitment transaction.

QABIO introduces two new block types (`QABI_PRIME` and `QABI_SPEND`), two new tx-level fields (`qabi_block`, `aggregated_sig`), one new sighash mode (`SIGHASH_QABO`), and a mempool policy (`RBD` — Replace-By-Depth) for priming transactions. It is compositionally atomic: no strict subset of a primed batch can execute.

## Motivation

The Ladder Script fork (BIP-RUNG) introduces post-quantum signature schemes (FALCON-512, DILITHIUM, SPHINCS+). FALCON-512 signatures are ~666 bytes each — roughly 10× the size of a Schnorr signature. For multi-party aggregation patterns (coinjoins, CoinPools, channel batch closes, staking pools), requiring a per-input PQ signature defeats the economic viability of batching: a 100-input batch would carry ~66 KB of signatures alone.

Classical signature aggregation schemes (MuSig2, half-aggregation) do not survive quantum attack, and existing PQ aggregation techniques (threshold FALCON, lattice-based pairing) are either not standardised, not constant-size, or require trusted setup.

**QABIO achieves N-party aggregation under ONE FALCON signature** by combining:

1. A two-phase commitment flow (priming + batch spend) that replaces cryptographic aggregation with **structural** aggregation — all inputs cryptographically commit to the same block, which is signed once by the coordinator.
2. Per-UTXO hash chains that give each participant a non-forgeable "consent token" at spend time, preventing coordinator theft even with the single shared signature.
3. Compositional atomicity enforced at consensus: any change to the batch composition (participants, outputs, expiry, coordinator) forces every participant to re-prime.

## Specification

### 1. New `RungBlockType` values

Added to the `RungBlockType` enum in the new QABI family:

| Value | Name | Purpose |
|---|---|---|
| `0x0A01` | `QABI_PRIME` | Priming state transition (covenant) |
| `0x0A02` | `QABI_SPEND` | Batch spend authorisation (fat block) |
| `0x0A03` | *reserved* | Future QABI family member |
| `0x0A04` | *reserved* | Future QABI family member |

### 2. New tx-level fields

Added to the `TX_MLSC` serialisation format (flags `0x02`, after `creation_proof`, before `aggregated_sig`):

```
  CompactSize qabi_block_len
  unsigned char qabi_block[]
```

And the existing `aggregated_sig` field (previously reserved, capped at 32 bytes) is repurposed to carry the coordinator's FALCON-512 QABO signature. The cap is raised from 32 to exactly **666** bytes (FALCON-512 signature size).

`qabi_block` consensus caps:

| Cap | Value | Enforcement |
|---|---|---|
| Hard cap | 262144 (256 KB) | Consensus — rejected in `UnserializeTransaction` |
| Soft cap | 65536 (64 KB) | Standard relay policy |

### 3. `QABIBlock` structure

Carried in `tx.qabi_block` as canonical serialised bytes:

```
QABIBlock {
    version:               u8    (0x01 for this spec)
    batch_id:              u256  (32 bytes)
    coordinator_pubkey:    bytes (897 bytes, FALCON-512 pk)
    prime_expiry_height:   u32
    entries:               vector<QABIEntry>
    outputs:               vector<CTxOut>
}

QABIEntry {
    participant_id:        u256  (= SHA256(participant's Rung 0 FALCON pubkey))
    contribution:          i64
    destination_index:     varint
}

QABI_ROOT = SHA256(canonical_serialise(QABIBlock))
```

Canonical serialisation: little-endian integers, Bitcoin `CompactSize` varints, vectors length-prefixed. A single bit difference in the serialised bytes must produce a different `QABI_ROOT`.

### 4. UTXO structure (native default)

Every `rung_tx` output SHOULD include the following in its Merkle-committed conditions tree (wallet convention, not consensus-mandated):

```
QABI_STATE_RELAY:
    auth_tip           u256 (immutable, H^N(auth_seed) — the hash chain tip)
    committed_root     u256 (0 if unprimed)
    committed_depth    varint (0 if unprimed)
    committed_expiry   u32 (0 if unprimed)

Rung 0: self-spend via owner's FALCON key (escape hatch)
Rung 1: QABI_PRIME       (priming state transition)
Rung 2: QABI_SPEND       (batch spend authorisation)
```

The hash chain: `auth_seed → H(auth_seed) → H^2(auth_seed) → ... → H^N(auth_seed) = auth_tip`. Each depth `d ∈ [0..N]` corresponds to a preimage `P_d` such that `H^d(P_d) == auth_tip`. Deeper depths (closer to the seed) are cryptographically harder to predict from shallower reveals.

Default `N = 20,000`.

### 5. `QABI_PRIME` — priming

**Block field layout (witness-only, 4 fields):**

| Index | Type | Name |
|---|---|---|
| 0 | `HASH256` | `new_committed_root` |
| 1 | `NUMERIC` | `prime_depth` |
| 2 | `NUMERIC` | `new_committed_expiry` |
| 3 | `PREIMAGE` | `prime_preimage` |

**Consensus checks:**

1. Field count and types match the implicit `QABI_PRIME_WITNESS` layout.
2. Exactly one `QABI_SPEND` block exists in the input UTXO's conditions tree.
3. `prime_depth > committed_depth` — monotonic depth progression.
4. `SHA256^prime_depth(prime_preimage) == auth_tip` — preimage valid.
5. **Covenant**: the output UTXO's committed conditions tree must equal the input UTXO's conditions tree with the following mutations applied to the `QABI_SPEND` block's state fields:
   - `committed_root ← new_committed_root`
   - `committed_depth ← prime_depth`
   - `committed_expiry ← new_committed_expiry`

   Every other leaf in the Merkle tree (including `auth_tip`, `owner_id`, Rung 0, all other rungs, all relays, coil metadata) MUST be preserved bit-exact.

### 6. `QABI_SPEND` — batch spend authorisation

**Block field layout:**

Conditions context (committed at UTXO creation, 5 fields):

| Index | Type | Name |
|---|---|---|
| 0 | `HASH256` | `auth_tip` |
| 1 | `HASH256` | `committed_root` |
| 2 | `NUMERIC` | `committed_depth` |
| 3 | `NUMERIC` | `committed_expiry` |
| 4 | `PUBKEY_COMMIT` | `owner_id` |

Witness context (6 fields — the conditions plus the spend preimage):

| Index | Type | Name |
|---|---|---|
| 0–4 | *(same as conditions)* | |
| 5 | `PREIMAGE` | `spend_preimage` |

**Consensus checks (run per primed input):**

1. `committed_root != 0` — UTXO is primed.
2. `current_block_height <= committed_expiry` — batch not expired.
3. `SHA256^(committed_depth + 1)(spend_preimage) == auth_tip` — spend preimage valid, one depth deeper than the priming.
4. `SHA256(tx.qabi_block) == committed_root` — root match.
5. `tx.qabi_block` parses as a well-formed `QABIBlock` with version byte `0x01`, coordinator pubkey of exactly 897 bytes, non-negative contributions, destination indices within `outputs.size()`, and no trailing data.
6. `parsed.prime_expiry_height == committed_expiry` — expiry binding.
7. `owner_id` appears in `parsed.entries[*].participant_id` — identity match.
8. **Full output-set match**: `tx.vout` must be bit-exact equal to `parsed.outputs`. Same length, same values, same scriptPubKeys, same order. This closes the coordinator-skim attack where extra outputs could siphon value beyond what participants agreed to.
9. `FalconVerify(parsed.coordinator_pubkey, SIGHASH_QABO(tx), tx.aggregated_sig) == VALID`.

All nine checks must pass. Any failure invalidates the whole transaction (atomicity).

### 7. `SIGHASH_QABO`

New sighash mode used exclusively for `QABI_SPEND`'s FALCON verification. Hash ordering:

1. `tx.version` (u32 LE)
2. For each `tx.vin[i]`: `prevout.hash` (32 B), `prevout.n` (u32 LE), `nSequence` (u32 LE) — in order.
3. For each `tx.vout[i]`: `nValue` (i64 LE), `scriptPubKey` length (u64 LE), `scriptPubKey` bytes — in order.
4. `tx.conditions_root` (32 B)
5. `tx.qabi_block` length (u64 LE), `tx.qabi_block` bytes
6. `tx.nLockTime` (u32 LE)

**Excluded:**
- `tx.aggregated_sig` (chicken-and-egg: the sig signs over the hash)
- `tx.creation_proof` (not consensus-relevant for batch authorisation)
- Per-input witness stacks (each input's `spend_preimage` is independently validated against the UTXO's committed `auth_tip`, so witness malleation is prevented at the evaluator layer rather than the sighash layer)

The sighash is the same for every input — the coordinator signs once, every primed input's `QABI_SPEND` evaluator verifies against the identical hash.

### 8. Compositional atomicity

A consequence of the consensus design, not a separate rule: because `QABI_SPEND` check #4 requires every primed input's `committed_root` to equal `SHA256(tx.qabi_block)`, and every participant's `committed_root` is written at priming time based on a specific block, **no subset of a primed batch can execute**.

If any participant drops out, the coordinator cannot simply remove them and broadcast an altered batch — doing so would yield a different `QABI_BLOCK` with a different root, and every *other* participant's input would then fail check #4. To proceed with reduced composition, the coordinator must issue a new block, and every remaining participant must re-prime to the new root, burning one auth-chain depth each.

This is the invariant. It eliminates the "silently reduced batch" attack class.

### 9. Mempool policy: Replace-By-Depth (RBD)

For QABI priming transactions, mempool replacement follows a **deeper-depth-wins** rule instead of standard Replace-By-Fee:

```
A priming transaction T2 replaces an existing priming transaction T1 if:
  - T1 and T2 spend the same UTXO (share a prevout),
  - Both T1 and T2 carry a QABI_PRIME block for that input,
  - T2's prime_depth > T1's prime_depth on every shared prevout.
```

This is integrated into `MemPoolAccept::ReplacementChecks`: if the new tx and all conflicting txs are priming txs, RBD is applied in place of the fee-based `PaysMoreThanConflicts` (Rule #6) and `PaysForRBF` (Rules #3/#4). Mempool hygiene rules (Rule #2 `HasNoNewUnconfirmed`, Rule #5 max-replacements) are still enforced.

**Rationale**: deeper preimages can only be produced by the UTXO owner (one-way hash property). RBD gives the legitimate owner a cryptographic "last word" over any sniper who scrapes a shallower preimage from the mempool. Fee-based RBF does not capture this property — a sniper could attach a higher fee and still steal the priming.

**Mixed cases** (some conflicts are priming, others are standard): RBD is not applied. Fee-based RBF runs as normal. This is a deliberate safety fallback — combining the two policies is semantically ambiguous.

## Rationale

### Why structural aggregation instead of cryptographic aggregation

No post-quantum signature aggregation scheme is currently standardised, constant-size, and trusted-setup-free. Rather than wait for such a scheme, QABIO achieves the same end — one signature authorising N UTXOs — by requiring all inputs to commit to the same block and signing the block once. The per-input `spend_preimage` provides the missing "each owner consented" property without requiring per-input PQ signatures.

### Why a single hash chain instead of two

Earlier iterations of this design used two chains per UTXO: Chain A for priming, Chain B for spend consent. Consolidating them into a single chain (prime at depth `d`, spend at depth `d+1`) preserves security (a sniper with the priming preimage cannot compute the spend preimage — one-way hash) while halving the state and simplifying the wallet.

### Why native `tx.qabi_block` instead of a commitment anchor

An earlier iteration used a separate commitment transaction creating an anchor UTXO that committed to `QABI_BLOCK`. This provided on-chain commitment before priming but cost ~$0.65 per batch attempt (plus a ~$1-3 sweep on failure). Carrying `qabi_block` natively in the batch tx eliminates this cost entirely: failed batches cost zero because the coordinator never broadcasts anything until all participants are ready. The only thing lost — pre-priming inconsistency detection — is a UX concern, not a security one: compositional atomicity at consensus still prevents any actual theft.

### Why `prime_expiry_height` in the block

Each batch has a hard deadline committed to the root. This prevents a coordinator from holding a primed UTXO hostage indefinitely, and it creates a natural retry cadence. Participants agree to the expiry when they prime, so there is no surprise.

### Why full output-set match (not per-entry)

An earlier iteration of the `QABI_SPEND` evaluator only verified each participant's own destination output against `block.outputs[dest_index]`. This allowed a coordinator to add an extra output (e.g., to themselves) for value that participants thought was going to miner fees. The full output-set match — `tx.vout` must be bit-exact equal to `block.outputs` — closes this hole. Coordinators who want to charge a fee must include themselves as an explicit entry in the block, visible to all participants at block-review time.

### Why Replace-By-Depth instead of Replace-By-Fee for priming

Fee-based RBF does not capture the cryptographic asymmetry of hash chains. A sniper who scrapes a mempool preimage can attach a higher fee and steal the priming. RBD uses the one-way hash property: only the legitimate owner can produce a deeper preimage.

## Backwards Compatibility

QABIO is a soft fork on top of `RUNG_TX_VERSION=4` (TX_MLSC format). Pre-QABIO nodes would:

- Reject `qabi_block` serialisation (unknown tx-level field) — requires the deserialiser extension.
- Reject the new block types (`QABI_PRIME` = `0x0A01`, `QABI_SPEND` = `0x0A02`) as unknown block type, per the existing `IsKnownBlockType` machinery.

Activation requires a coordinated upgrade across all ladder-script nodes. The deployment mechanism is the standard `RUNG_TX_VERSION` soft-fork process (see BIP-RUNG).

UTXOs created before QABIO activation do not include `QABI_STATE_RELAY`, Rung 1 (`QABI_PRIME`), or Rung 2 (`QABI_SPEND`). They cannot participate in batches until re-created (e.g., via a Rung 0 self-spend to a new QABI-enabled UTXO).

## Reference Implementation

A working reference implementation exists on the `QABIO` branch of `github.com:bitcoin-ghost/bitcoin-core-ladder.git`:

- **Enum + serialisation**: `src/rung/types.h`, `src/rung/qabi.h`, `src/rung/qabi.cpp`
- **Tx format**: `src/primitives/transaction.h`, `src/primitives/transaction.cpp`
- **Evaluators**: `EvalQABIPrimeBlock`, `EvalQABISpendBlock` in `src/rung/evaluator.cpp`
- **Sighash**: `ComputeSighashQABO` in `src/rung/qabi.cpp`
- **Mempool policy**: `rung::IsValidRBDReplacement` in `src/rung/policy.cpp`, integrated into `MemPoolAccept::ReplacementChecks` in `src/validation.cpp`
- **Wallet helpers**: `BuildQABIPrimeBlock`, `BuildQABISpendBlock`, `ComputeAuthChainTip`, `ComputeAuthChainPreimageAt` in `src/rung/qabi.h`

All consensus logic builds clean on top of Bitcoin Core v30. Test coverage: 41 unit and integration tests in `src/test/rung_tests.cpp` (suite `qabi_tests`), including a full end-to-end test with real FALCON-512 signing via liboqs.

## Test Vectors

Canonical `QABIBlock` serialisation for a minimal valid block:

```
Version:                          0x01
batch_id:                         32 × 0xA1
coordinator_pubkey length:        0xFD 0x81 0x03   (CompactSize 897)
coordinator_pubkey:               897 × 0xB2
prime_expiry_height:              0x39 0x30 0x00 0x00   (12345 LE)
entries length:                   0x01
  entry[0] participant_id:        32 × 0xC3
  entry[0] contribution:          0xA0 0x86 0x01 0x00 0x00 0x00 0x00 0x00   (100000 LE)
  entry[0] destination_index:     0x00
outputs length:                   0x01
  outputs[0] nValue:              0x58 0x82 0x01 0x00 0x00 0x00 0x00 0x00   (99000 LE)
  outputs[0] scriptPubKey:        0x17 OP_0 0x14 (20 × 0xD4)
```

QABI_ROOT of this block is deterministic and can be reproduced via `ComputeQABIRoot(SerializeQABIBlock(block))`.

Additional test vectors (hash chain preimages, end-to-end signing) are in `src/test/rung_tests.cpp`.

## Copyright

This document is licensed under the BSD 2-clause license.
