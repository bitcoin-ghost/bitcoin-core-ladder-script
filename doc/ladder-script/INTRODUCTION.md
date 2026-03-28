# Introduction to Ladder Script

Ladder Script is a typed, structured replacement for Bitcoin Script designed for
version 4 (`RUNG_TX_VERSION = 4`) transactions. It eliminates the untyped stack machine
in favor of declarative function blocks organized into rungs and ladders.

## Core Concepts

A **ladder** is a set of spending paths for a single output. Each path is a **rung**
containing one or more **blocks**. Blocks within a rung are combined with AND logic
(all must be satisfied). Rungs within a ladder are combined with OR logic (first
satisfied rung wins).

Every field in a Ladder Script witness has an explicit **data type** (PUBKEY, SIGNATURE,
HASH256, NUMERIC, SCHEME, etc.). There are no arbitrary data pushes. Every byte must
belong to a known type with enforced size constraints.

## Key Properties

- **Typed fields.** 11 data types with fixed size ranges. No free-form data.
- **AND/OR evaluation.** Blocks within a rung are AND; rungs within a ladder are OR.
- **TX_MLSC (Transaction-level Merkelized Ladder Script Conditions).** Each output
  is 8 bytes (value only); the transaction carries one shared `conditions_root` with
  prefix `0xDF`. A creation proof in the witness is validated at block acceptance.
  Leaf computation: `TaggedHash("LadderLeaf", structural_template || value_commitment)`.
  One shared Merkle tree per transaction (PLC model: one program, multiple output coils).
  Full conditions are revealed only at spend time. Inline conditions (0xC1) and per-output
  MLSC (0xC2) have been removed.
- **merkle_pub_key.** Public keys for key-consuming blocks are folded into the Merkle
  leaf hash, not stored in conditions fields. This prevents arbitrary data embedding
  through the PUBKEY_COMMIT writable surface.
- **Selective inversion.** Blocks on an explicit allowlist may be inverted
  (SATISFIED becomes UNSATISFIED and vice versa). Key-consuming blocks are never invertible.
- **Anti-spam.** Fail-closed deserialization rejects unknown block types, unknown data types,
  and trailing bytes. `IsDataEmbeddingType` blocks high-bandwidth types in layout-less blocks.
  PREIMAGE and SCRIPT_BODY fields are capped at 2 per witness.
- **Post-quantum readiness.** The SCHEME field supports FALCON-512, FALCON-1024, Dilithium3,
  and SPHINCS+-SHA2-256f alongside Schnorr and ECDSA.
- **Relays.** Shared condition sets that can be referenced by multiple rungs, enabling
  DRY composition and cross-rung AND dependencies.
- **Batch verification.** Schnorr signatures are collected during evaluation and verified
  in a single batch after all inputs pass.
- **ANYPREVOUT sighash.** BIP-118 analogue flags (0x40, 0xC0) enable LN-Symmetry/eltoo.

## Further Reading

- [Block Library](BLOCK_LIBRARY.md) for all 61 block types
- [Glossary](GLOSSARY.md) for term definitions
- [Integration Guide](INTEGRATION.md) for wallet developers
- [Soft Fork Guide](SOFT_FORK_GUIDE.md) for activation mechanics
- [Possibilities](POSSIBILITIES.md) for what Ladder Script enables
- [Review Guide](REVIEW_GUIDE.md) for code reviewers
