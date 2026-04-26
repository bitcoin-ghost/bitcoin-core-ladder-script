# Ladder Script Documentation

Ladder Script (TX_MLSC / RUNG_TX v4) is a typed transaction condition system for Bitcoin,
implemented as a fork of Bitcoin Core v30.0. It replaces Bitcoin Script's stack machine with
64 declarative function blocks, 11 typed fields, and Merkelised conditions (MLSC).

## Documentation Index

### Specification

| Document | Description |
|----------|-------------|
| [BIP-XXXX.md](BIP-XXXX.md) | Full BIP specification (64 block types, wire format, sighash, evaluation) |
| [TX_MLSC_SPEC.md](TX_MLSC_SPEC.md) | TX_MLSC transaction format specification |
| [MERKLE-UTXO-SPEC.md](MERKLE-UTXO-SPEC.md) | Merkle tree, UTXO dedup, proof verification |

### Guides

| Document | Description |
|----------|-------------|
| [INTRODUCTION.md](INTRODUCTION.md) | What Ladder Script is, key properties, and design rationale |
| [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md) | Complete table of all 64 block types with fields and properties |
| [BLOCK_LIBRARY_IMPL.md](BLOCK_LIBRARY_IMPL.md) | Detailed block reference with evaluation rules |
| [EXAMPLES.md](EXAMPLES.md) | 12 worked examples from simple spends to recursive covenants |
| [GLOSSARY.md](GLOSSARY.md) | Alphabetical glossary of every term and block type |
| [FAQ.md](FAQ.md) | 23 detailed Q&A covering all aspects of the system |

### Integration & Review

| Document | Description |
|----------|-------------|
| [INTEGRATION.md](INTEGRATION.md) | Wallet integration, RPC commands, descriptor language |
| [REVIEW_GUIDE.md](REVIEW_GUIDE.md) | Full library walkthrough: purpose / behaviour / load-bearing invariants / optional-for-MVP, per file |
| [ANNOTATED_DIFF.md](ANNOTATED_DIFF.md) | Core Integration Patch (~740 LOC) walkthrough, with load-bearing vs optional summary table |
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
| `src/rung/types.h` | 1,496 | 64 block types, 11 data types, implicit layouts, micro-header table |
| `src/rung/evaluator.cpp` | 1,244 | Block dispatch + VerifyRungTx (per-block evaluators moved to `src/rung/blocks/*.cpp`) |
| `src/rung/rpc.cpp` | 4,283 | JSON-RPC command handlers |
| `src/rung/descriptor.cpp` | 1,841 | Descriptor language parser and formatter |
| `src/rung/conditions.cpp` | 1,027 | MLSC proof verification, Merkle tree, creation proofs |
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
| Unit tests (`rung_tests` + `qabi_tests` + `tx_mlsc_tests` boost suites in `rung_tests.cpp`) | 613 |
| Functional tests (`feature_rung_tx`, `feature_rung_p2p`, `feature_rung_fuzz`, `feature_qabi`) | 37 |
| TLA+ formal specs (`spec/`) | 21 specs |

## Repository

Source: [github.com/defenwycke/bitcoin-core-ladder-script](https://github.com/defenwycke/bitcoin-core-ladder-script)
Base: Bitcoin Core v30.0 (`ladder-script` branch)
