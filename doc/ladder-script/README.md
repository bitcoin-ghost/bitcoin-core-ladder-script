# Ladder Script Documentation

Ladder Script (TX_MLSC / RUNG_TX v4) is a typed transaction condition system for Bitcoin,
implemented as a fork of Bitcoin Core v30.0. It replaces Bitcoin Script's stack machine with
65 declarative function blocks across 11 families, 11 typed condition data types, and
Merkelised conditions (MLSC).

## Documentation Index

### Specification

| Document | Description |
|----------|-------------|
| [BIP-XXXX.md](BIP-XXXX.md) | Full BIP specification (65 block types, wire format, sighash, evaluation) |
| [TX_MLSC_SPEC.md](TX_MLSC_SPEC.md) | TX_MLSC transaction format specification |
| [MERKLE-UTXO-SPEC.md](MERKLE-UTXO-SPEC.md) | Merkle tree, UTXO dedup, proof verification |

### Guides

| Document | Description |
|----------|-------------|
| [INTRODUCTION.md](INTRODUCTION.md) | What Ladder Script is, key properties, and design rationale |
| [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md) | Complete table of all 65 block types with fields and properties |
| [BLOCK_LIBRARY_IMPL.md](BLOCK_LIBRARY_IMPL.md) | Detailed block reference with evaluation rules |
| [EXAMPLES.md](EXAMPLES.md) | 12 worked examples from simple spends to recursive covenants |
| [GLOSSARY.md](GLOSSARY.md) | Alphabetical glossary of every term and block type |
| [FAQ.md](FAQ.md) | 23 detailed Q&A covering all aspects of the system |

### Integration & Review

| Document | Description |
|----------|-------------|
| [INTEGRATION.md](INTEGRATION.md) | Wallet integration, RPC commands, descriptor language |
| [REVIEW_GUIDE.md](REVIEW_GUIDE.md) | Full library walkthrough: purpose / behaviour / load-bearing invariants / optional-for-MVP, per file |
| [ANNOTATED_DIFF.md](ANNOTATED_DIFF.md) | Core Integration Patch walkthrough (~961 lines added across 33 modified files) |
| [MEASUREMENTS.md](MEASUREMENTS.md) | Empirical tx / vsize / UTXO measurements vs P2WPKH and P2TR |

### Deployment

| Document | Description |
|----------|-------------|
| [SUMMARY.md](SUMMARY.md) | One-paragraph summary with key stats |
| [SOFT_FORK_GUIDE.md](SOFT_FORK_GUIDE.md) | Activation mechanics, validation changes, deployment |
| [POSSIBILITIES.md](POSSIBILITIES.md) | Capabilities enabled beyond Bitcoin Script |
| [ENGINE_GUIDE.md](ENGINE_GUIDE.md) | Browser-based Ladder Script builder guide |

### Web Pages

Interactive HTML pages in [`tools/`](../../tools/) (served at `ladder-script.org` by
`deploy/deploy-ladder-script.sh`):
- [`tools/ladder-script.html`](../../tools/ladder-script.html) — Overview and philosophy
- [`tools/rung-tx-anatomy.html`](../../tools/rung-tx-anatomy.html) — Transaction structure byte-by-byte
- [`tools/block-docs/`](../../tools/block-docs/) — 65 block reference pages (one per block type + index)
- [`tools/docs/txs/`](../../tools/docs/txs/) — 40 transaction example pages
- [`tools/descriptor-notation.html`](../../tools/descriptor-notation.html) — Descriptor language reference
- [`tools/comparison.html`](../../tools/comparison.html) — Bitcoin Script vs Ladder Script
- [`tools/patch-overview.html`](../../tools/patch-overview.html) — Patch impact analysis
- [`tools/get-started.html`](../../tools/get-started.html) — Getting started guide
- [`tools/explorer.html`](../../tools/explorer.html) — Live signet block explorer
- [`tools/qabio-playground.html`](../../tools/qabio-playground.html) — QABIO sandbox

## Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/rung/rpc.cpp` | 4,556 | JSON-RPC command handlers |
| `src/rung/descriptor.cpp` | 1,924 | Descriptor language parser and formatter |
| `src/rung/evaluator.cpp` | 1,704 | Block dispatch + VerifyRungTx (per-block evaluators moved to `src/rung/blocks/*.cpp`) |
| `src/rung/types.h` | 1,696 | 65 block types across 11 families, 11 condition data types, implicit layouts, micro-header table |
| `src/rung/conditions.cpp` | 1,385 | MLSC proof verification, Merkle tree, creation proofs |
| `src/rung/serialize.cpp` | 1,130 | Wire format, micro-headers, anti-spam validation |
| `src/rung/policy.cpp` | 341 | Mempool policy checks |
| `src/rung/sighash.cpp` | 265 | `SignatureHashLadder` (script-path) and `SignatureHashLadderKeyPath` (key-path); valid hash-type set `{0x00..0x03, 0x81..0x83}` (BIP-118 ANYPREVOUT family `{0x40..0x43, 0xC0..0xC3}` rejected) |
| `src/rung/adaptor.cpp` | 188 | Adaptor signature utilities |
| `src/rung/pq_verify.cpp` | 149 | Post-quantum signature verification (FALCON-512/1024, Dilithium3, SPHINCS+) via `liboqs` |
| **Total src/rung/** | **20,888** | **37 files** (`.cpp` + `.h`, excl. `CMakeLists.txt`) |

## Test Coverage

| Suite | Count |
|-------|-------|
| Unit tests (BOOST cases in `src/test/rung_tests.cpp`) | 655 |
| Functional tests (~52 test methods across `feature_rung_*.py`, `feature_qabi*.py`, `feature_deferred_vectors.py`) | 9 files |
| TLA+ formal specs (`spec/`) | 27 specs |

## Repository

Source: [github.com/defenwycke/bitcoin-core-ladder-script](https://github.com/defenwycke/bitcoin-core-ladder-script)
Base: Bitcoin Core v30.0 (`ladder-script` branch)
