# Ladder Script Documentation

Ladder Script (TX_MLSC / RUNG_TX v4) is a typed transaction condition system for Bitcoin,
implemented as a fork of Bitcoin Core v30.0. It replaces Bitcoin Script's stack machine with
62 declarative function blocks, 11 typed fields, and Merkelised conditions (MLSC).

## Documentation Index

### Specification

| Document | Description |
|----------|-------------|
| [BIP-XXXX.md](BIP-XXXX.md) | Full BIP specification (62 block types, wire format, sighash, evaluation) |
| [TX_MLSC_SPEC.md](TX_MLSC_SPEC.md) | TX_MLSC transaction format specification |
| [MERKLE-UTXO-SPEC.md](MERKLE-UTXO-SPEC.md) | Merkle tree, UTXO dedup, proof verification |

### Guides

| Document | Description |
|----------|-------------|
| [INTRODUCTION.md](INTRODUCTION.md) | What Ladder Script is, key properties, and design rationale |
| [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md) | Complete table of all 62 block types with fields and properties |
| [BLOCK_LIBRARY_IMPL.md](BLOCK_LIBRARY_IMPL.md) | Detailed block reference with evaluation rules |
| [EXAMPLES.md](EXAMPLES.md) | 12 worked examples from simple spends to recursive covenants |
| [GLOSSARY.md](GLOSSARY.md) | Alphabetical glossary of every term and block type |
| [FAQ.md](FAQ.md) | 24 detailed Q&A covering all aspects of the system |

### Integration & Review

| Document | Description |
|----------|-------------|
| [INTEGRATION.md](INTEGRATION.md) | Wallet integration, RPC commands, descriptor language |
| [REVIEW_GUIDE.md](REVIEW_GUIDE.md) | Code reviewer's walkthrough with file-by-file guide |
| [ANNOTATED_DIFF.md](ANNOTATED_DIFF.md) | Annotated diff explaining every change to Bitcoin Core v30.0 |
| [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md) | Implementation details and spec deviations |

### Deployment

| Document | Description |
|----------|-------------|
| [SUMMARY.md](SUMMARY.md) | One-paragraph summary with key stats |
| [SOFT_FORK_GUIDE.md](SOFT_FORK_GUIDE.md) | Activation mechanics, validation changes, deployment |
| [POSSIBILITIES.md](POSSIBILITIES.md) | Capabilities enabled beyond Bitcoin Script |
| [ENGINE_GUIDE.md](ENGINE_GUIDE.md) | Browser-based Ladder Script builder guide |

### Web Pages

Interactive HTML pages in [`web/`](web/):
- [`web/ladder-script.html`](web/ladder-script.html) — Overview and philosophy
- [`web/rung-tx-anatomy.html`](web/rung-tx-anatomy.html) — Transaction structure byte-by-byte
- [`web/blocks/`](web/blocks/) — 63 block reference pages (one per block type + index)
- [`web/txs/`](web/txs/) — 41 transaction example pages
- [`web/descriptor-notation.html`](web/descriptor-notation.html) — Descriptor language reference
- [`web/comparison.html`](web/comparison.html) — Bitcoin Script vs Ladder Script
- [`web/patch-overview.html`](web/patch-overview.html) — Patch impact analysis
- [`web/get-started.html`](web/get-started.html) — Getting started guide
- [`web/ladder-data-flow.html`](web/ladder-data-flow.html) — Data flow and anti-spam visualization
- [`web/mainnet-checklist.html`](web/mainnet-checklist.html) — Mainnet readiness tracker
- [`web/explorer.html`](web/explorer.html) — Live signet block explorer
- [`web/dashboard.html`](web/dashboard.html) — Telemetry dashboard

## Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/rung/types.h` | 1,428 | 62 block types, 11 data types, implicit layouts, micro-header table |
| `src/rung/evaluator.cpp` | 4,217 | All 62 block evaluators, EvalBlock dispatch, VerifyRungTx |
| `src/rung/rpc.cpp` | 3,370 | 15 RPC commands |
| `src/rung/descriptor.cpp` | 1,711 | Descriptor language parser and formatter |
| `src/rung/conditions.cpp` | 1,045 | MLSC proof verification, Merkle tree, creation proofs |
| `src/rung/serialize.cpp` | 984 | Wire format, micro-headers, anti-spam validation |
| `src/rung/sighash.cpp` | 234 | LadderSighash with ANYPREVOUT/ANYPREVOUTANYSCRIPT |
| `src/rung/adaptor.cpp` | 187 | Adaptor signature utilities |
| `src/rung/pq_verify.cpp` | 145 | Post-quantum signature verification |
| `src/rung/policy.cpp` | 137 | Mempool policy checks |
| `src/rung/aggregate.cpp` | 41 | Half-aggregated signature support |
| **Total src/rung/** | **14,771** | **22 files (incl. CMakeLists.txt)** |

## Test Coverage

| Suite | Count |
|-------|-------|
| Unit tests (`rung_tests.cpp`) | 528 |
| Functional tests | 60 |
| TLA+ formal specs (`spec/`) | 21 specs |

## Repository

Source: [github.com/defenwycke/bitcoin-core-ladder-script](https://github.com/defenwycke/bitcoin-core-ladder-script)
Base: Bitcoin Core v30.0 (`ladder-script` branch)
