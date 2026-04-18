# Ladder Script Summary

Ladder Script is a typed, structured transaction scripting system that replaces Bitcoin
Script's untyped stack machine with 61 declarative function blocks
across 10 families: Signature, Timelock, Hash, Covenant, Recursion, Anchor, PLC, Compound,
Governance, and Legacy. Blocks are grouped into rungs (AND logic) and ladders (OR logic),
with all data constrained to 11 typed fields. Outputs use TX_MLSC (Transaction-level Merkelized Ladder Script
Conditions): 8 bytes per output (value only) with one shared `0xDF + SHA256 root` per
transaction. A creation proof in the witness is validated at block acceptance. Leaf
computation: `TaggedHash("LadderLeaf", structural_template || value_commitment)`.
Conditions are revealed only at spend time. Simple payment: 647 WU / 162 vB. Batch 100:
7,867 WU / ~1,967 vB.
Public keys are folded into Merkle leaves via `merkle_pub_key`, and key-consuming blocks
are never invertible, closing data-embedding vectors. The system supports post-quantum
signatures (FALCON-512/1024, Dilithium3, SPHINCS+), ANYPREVOUT sighash flags for
LN-Symmetry, batch Schnorr verification, relays for cross-rung composition, and recursive
covenants. Transactions use `RUNG_TX_VERSION = 4`. Test coverage: 480 unit tests,
60 functional tests, 10 TLA+ specs with 80+ checked properties (6.14M states verified, zero errors).

- [Full Documentation](README.md)
- [Block Library](BLOCK_LIBRARY.md)
- [Integration Guide](INTEGRATION.md)
