# Ladder Script

Ladder Script is a typed, structured replacement for Bitcoin Script designed for
version 4 (`RUNG_TX_VERSION = 4`) transactions. It eliminates the untyped stack machine
in favour of 62 declarative function blocks across 10 families: Signature, Timelock,
Hash, Covenant, Recursion, Anchor, PLC, Compound, Governance, and Legacy.

Based on Bitcoin Core v30.0.

## Core Concepts

A **ladder** is a set of spending paths for a single output. Each path is a **rung**
containing one or more **blocks**. Blocks within a rung are combined with AND logic
(all must be satisfied). Rungs within a ladder are combined with OR logic (first
satisfied rung wins).

Every field has an explicit **data type** (11 types: PUBKEY, SIGNATURE, HASH256,
HASH160, PREIMAGE, NUMERIC, SCHEME, SPEND_INDEX, SCRIPT_BODY, DATA, PUBKEY_COMMIT).
There are no arbitrary data pushes. Every byte belongs to a known type with enforced
size constraints.

## Transaction Format

Outputs use **TX_MLSC** (Transaction-level Merkelised Ladder Script Conditions): 8 bytes
per output (value only) with one shared `conditions_root` (32 bytes on the wire) per
transaction. The RUNG_TX wire format uses flag byte `0x02`. Conditions are revealed only
at spend time via Merkle proofs. Inline conditions (`0xC1`) have been removed — all
outputs use MLSC (`0xDF`).

## Performance

- **Key-path spending:** 119 vB — cheaper than P2WPKH (143 vB), P2TR (157 vB), and P2PKH (226 vB).
- **Script-path:** 140 vB — still beats every legacy type.
- **Full lifecycle** (create + spend): 6% cheaper than P2WPKH.
- **Batch 100 outputs:** 914 vB (71% cheaper than P2WPKH).
- **UTXO footprint:** ~8 bytes per output (5× more efficient than P2TR's ~41 bytes) via synthetic root entry and 1-byte MLSC compression.
- **Anti-spam:** 112 bytes of user-chosen arbitrary data per transaction (flat, regardless of output count).

## Key Properties

- **merkle_pub_key.** Public keys for key-consuming blocks are folded into the Merkle
  leaf hash, not stored in conditions fields. This prevents arbitrary data embedding
  through the PUBKEY_COMMIT writable surface.
- **Selective inversion.** Blocks on an explicit allowlist may be inverted
  (SATISFIED becomes UNSATISFIED and vice versa). Key-consuming blocks are never invertible.
- **Anti-spam.** Fail-closed deserialisation rejects unknown block types, unknown data types,
  and trailing bytes. `IsDataEmbeddingType` blocks high-bandwidth types in layout-less blocks.
  PREIMAGE and SCRIPT_BODY fields are capped at 2 per witness and 2 per transaction.
- **Post-quantum readiness.** The SCHEME field supports FALCON-512, FALCON-1024, Dilithium3,
  and SPHINCS+-SHA2-256f alongside Schnorr and ECDSA.
- **Relays.** Shared condition sets that can be referenced by multiple rungs, enabling
  DRY composition and cross-rung AND dependencies.
- **Half-aggregated Schnorr signatures.** `AGGREGATE` attestation mode verifies a shared
  s-value across all inputs at the transaction level. `BatchVerifier` infrastructure
  supports deferred batch verification.
- **ANYPREVOUT sighash.** BIP-118 analogue flags (0x40, 0xC0) enable LN-Symmetry/eltoo.
- **O(log N) Merkle path proofs.** Default proof mode for spend-time condition revelation.
- **Creation proof.** Required for transactions with 3 or more spendable outputs, binding
  each output to the shared condition tree and preventing UTXO spam.
