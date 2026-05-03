# Ladder Script Summary

Ladder Script is a typed, structured transaction scripting system that replaces Bitcoin
Script's untyped stack machine with 65 declarative function blocks
across 11 families: Signature, Timelock, Hash, Covenant, Recursion, Anchor, PLC, Compound,
Governance, Legacy, and QABI/PQ. Blocks are grouped into rungs (AND logic) and ladders (OR logic),
with all condition data constrained to 11 typed fields. Outputs use TX_MLSC (Transaction-level
Merkelised Ladder Script Conditions): 8 bytes per output (value only) with one shared
`conditions_root` per transaction, recovered at spend time as `0xDF || root`. An MLSCProof in
the witness is validated at script-verify time. Leaf computation:
`TaggedHash("LadderLeaf/v1", structural_template || value_commitment)`. Conditions are
revealed only at spend time. Key-path spend (1-in, 1-out): 110 vB. Standard payment (1-in,
2-out): 118 vB. 100-output batch: 911 vB.
Public keys are folded into Merkle leaves via `merkle_pub_key`, and key-consuming blocks
are never invertible, closing data-embedding vectors. The system supports post-quantum
signatures (FALCON-512/1024, Dilithium3, SPHINCS+) selected via the per-block SCHEME byte,
relays for cross-rung composition, and recursive covenants. The BIP-118 ANYPREVOUT
hash-type family is unconditionally rejected; spend mode (key-path vs script-path) is
implicit in the witness stack count.
Transactions use `RUNG_TX_VERSION = 4`. Test coverage: 660 unit tests (`src/test/rung_tests.cpp`),
~52 functional test methods across 9 files (`test/functional/feature_rung_*.py`,
`feature_qabi*.py`, `feature_deferred_vectors.py`), and 27 TLA+ specifications.

- [Full Documentation](README.md)
- [Block Library](BLOCK_LIBRARY.md)
- [Integration Guide](INTEGRATION.md)
