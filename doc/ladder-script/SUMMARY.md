# Ladder Script Summary

Ladder Script is a typed, structured transaction scripting system that replaces Bitcoin
Script's untyped stack machine with 62 declarative function blocks across 10 families:
Signature, Timelock, Hash, Covenant, Recursion, Anchor, PLC, Compound, Governance, and
Legacy. Blocks are grouped into rungs (AND logic) and ladders (OR logic), with all data
constrained to 11 typed fields.

Outputs use TX_MLSC (Transaction-level Merkelised Ladder Script Conditions): 8 bytes per
output (value only) with one shared `conditions_root` (32 bytes) per transaction. Conditions
are revealed only at spend time via Merkle proofs.

Key-path spending: 119 vB (simple payment). Script-path: 140 vB. Batch 100 outputs: 914 vB
(71% cheaper than P2WPKH). Full lifecycle 6% cheaper than P2WPKH.

UTXO deduplication: ~8 bytes per output (5× more efficient than P2TR's ~41 bytes) via
synthetic root entry. Anti-spam: 112 bytes of user-chosen arbitrary data per transaction
(flat, regardless of output count).

Public keys folded into Merkle leaves via `merkle_pub_key`. Key-consuming blocks never
invertible. Post-quantum ready (FALCON-512/1024, Dilithium3, SPHINCS+). ANYPREVOUT sighash
for LN-Symmetry. O(log N) Merkle path proofs. Half-aggregated Schnorr signatures.

Transactions use `RUNG_TX_VERSION = 4`. The RUNG_TX wire format uses flag byte `0x02`.

Based on Bitcoin Core v30.0.
