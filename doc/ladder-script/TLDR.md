# TL;DR

Ladder Script is a typed spending condition system for Bitcoin. 62 declarative blocks
organised into 10 families. Soft-fork compatible — existing transactions continue to work.
Legacy script types are supported via wrappers.

Live on signet today. Post-quantum signatures verified on-chain.

---

## Transaction Sizes

| Transaction Type | P2PKH | P2WPKH | P2TR | **Ladder Script** |
|-----------------|-------|--------|------|-------------------|
| Key-path spend (1-in, 1-out) | 192 vB | 110 vB | 111 vB | **110 vB** |
| Standard payment (1-in, 2-out) | 226 vB | 143 vB | 157 vB | **118 vB** |
| Script-path spend | — | — | ~170 vB | **124 vB** |
| 10-output batch | — | 391 vB | 511 vB | **194 vB** |
| 100-output batch | — | 3,181 vB | 4,381 vB | **914 vB** |

Script-path spends are smaller than P2WPKH key-path spends.
One signature covers all outputs — 100 outputs, one sig.

## UTXO Footprint

| | P2WPKH | P2TR | **Ladder Script** |
|--|--------|------|-------------------|
| Output on wire | 31 bytes | 43 bytes | **8 bytes** |

Each output is value-only on the wire. Spending conditions are committed in a shared
Merkle root and revealed only at spend time.

## Post-Quantum

FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+ signatures verified on signet today.
Not a proposal — working transactions on a live network.

## Anti-Spam

~112 bytes of user-writable surface per transaction. Inscription-style data embedding
is structurally impossible. Conditions contain zero user-chosen bytes.

## Usability

| Interface | What it does |
|-----------|-------------|
| **Engine** | Visual drag-and-drop transaction builder — compose blocks, simulate, deploy to signet |
| **Descriptor notation** | Human-readable: `ladder(or(sig(@alice), and(csv(1000), sig(@bob))))` |
| **15 RPCs** | Full programmatic access — create, sign, broadcast, parse, decode, validate |
| **Block explorer** | Live signet explorer with mempool viewer |
| **Block reference** | Documentation for all 64 block types |

## What the 64 Blocks Cover

Signatures. Timelocks. Hash locks. Covenants. Recursive covenants. Vaults. Rate limiters.
Counters. Latches. Timers. Sequencers. Multi-party signing. Adaptor signatures. Atomic
swaps. Payment channels. Oracle attestations. Transaction weight limits. Input/output
count constraints. Value ratio enforcement. Cross-input binding. Data anchoring.
Post-quantum signatures. Legacy P2PKH/P2WPKH/P2TR wrapping.

All type-safe. All formally specified. All live on signet.

## Soft-Fork Compatibility

Version 4 transactions (`RUNG_TX`) activate alongside existing transaction types. Legacy
P2PKH, P2WPKH, P2SH, P2WSH, and P2TR outputs continue to work unchanged. Ladder Script
includes wrapper blocks for all legacy types — existing scripts are phased out gradually,
not broken.
