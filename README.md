# Ladder Script

A typed transaction format for Bitcoin, derived from industrial PLC ladder logic. This repository is a Bitcoin Core v30.0 fork (branch `ladder-script`) carrying the consensus implementation, the spec, the BIP wireframe, the website source, and the live-signet tooling.

**[Live signet, engine, playground, block reference, full docs](https://ladder-script.org)** | **[Ladder Engine](https://ladder-script.org/ladder-engine.html)** | **[QABIO Playground](https://ladder-script.org/qabio-playground/)** | **[Block Reference](https://ladder-script.org/block-docs/)**

```
  RUNG 0: ──[ SIG: Alice ]──[ CSV: 144 ]──────────────( UNLOCK )──
  RUNG 1: ──[ MULTISIG: 2-of-3 ]──────────────────────( UNLOCK )──
  RUNG 2: ──[ /CSV: 144 ]──[ SIG: Bob ]───────────────( UNLOCK )──   ← breach remedy
```

Bitcoin Script is a stack machine where every element is an opaque byte array. A public key, a hash, a timelock, and a JPEG are indistinguishable at the protocol level. Each new capability requires a new opcode, a soft fork, and years of coordination.

Ladder Script replaces this with **typed function blocks** organised into **rungs**. Every byte has a declared type. Every condition is a named block with validated fields. Evaluation is deterministic: AND within rungs, OR across rungs, first satisfied rung wins. Untyped data is a parse error — not policy, not non-standard, a *parse error*.

## Status

**Prototype on a private signet.** The protocol runs end-to-end. The Ladder Engine at ladder-script.org lets you build, sign, and broadcast real transactions on the live signet backed by a node built from this repo. The QABIO playground successfully broadcasts multi-party FALCON-512 batches.

**Not yet BIP-ready.** An earlier full-length draft surfaced enough load-bearing spec gaps (prose-only sighash, consensus rules living in `types.h` rather than the spec) that submission would have been premature. The library boundary is now in place — `src/rung/` compiles standalone against the adapter types in `src/rung_shims.h` with no Bitcoin Core types crossing the line. The current [`doc/ladder-script/BIP-XXXX.md`](doc/ladder-script/BIP-XXXX.md) is a wireframe; the BIP will normatively reference the library, in the BIP340 → libsecp256k1 model.

**Not for mainnet.** This is research-stage protocol work. Don't point real money at it.

## Verifying releases

Pre-built binaries on the [Releases page](https://github.com/defenwycke/bitcoin-core-ladder-script/releases) ship a `SHA256SUMS` file plus a detached PGP signature `SHA256SUMS.asc`.

Release-signing key fingerprint:

```
777FE81F8CC077FD3D08055E852C2B3190F5B928
```

This README and [ladder-script.org/get-started.html#verify](https://ladder-script.org/get-started.html#verify) are the canonical publications. If `gpg --verify` reports any other key, do not trust the binary.

```bash
gpg --keyserver keys.openpgp.org --recv-keys 777FE81F8CC077FD3D08055E852C2B3190F5B928
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

## How it works

The name and structure are borrowed from ladder logic, the programming model used in industrial PLCs (programmable logic controllers) for decades. A spending policy is a ladder. Each rung is a possible spending path containing typed condition blocks. Blocks on the same rung are AND — all must be satisfied. Rungs are OR — the first satisfied rung authorises the spend.

The output format is **TX_MLSC** (Transaction-level Merkelised Ladder Script Conditions): one shared 32-byte `conditions_root` per transaction with `0xDF` prefix. Each output is 8 bytes on the wire (value only); each rung's coil declares its `output_index`. Only the exercised spending path is revealed at spend time. Unused paths stay permanently hidden behind their Merkle leaf hash.

In chainstate, the per-coin cost drops to **3 bytes** (1-byte SPK after compressor type `0x06`) versus 24 B for P2WPKH and 36 B for P2TR — **8–12× smaller per coin**. The 32-byte root is recovered at spend time from a synthetic UTXO entry at `(txid, MLSC_ROOT_VOUT = 0xFFFFFFFF)`.

Transaction version 4 (`RUNG_TX`). Soft fork activation — non-upgraded nodes see v4 as anyone-can-spend, the same upgrade path as SegWit and Taproot.

## What makes it different

**Contact inversion.** Non-key blocks can be inverted. `[/CSV: 144]` means "spend BEFORE 144 blocks" — a primitive Bitcoin has never had. Key-consuming blocks (SIG, MULTISIG, etc.) cannot be inverted, closing the garbage-pubkey data embedding vector. This enables breach remedies, dead man's switches, governance vetoes, and time-bounded escrows natively.

**Anti-spam hardening.** Eleven data types, enforced at the deserialiser before any cryptographic operation. Coordinated defences close all practical data embedding surfaces: `merkle_pub_key` folds public keys into the Merkle leaf hash (no writable pubkey field in conditions); selective inversion prevents key-consuming blocks from being inverted; PREIMAGE/SCRIPT_BODY fields are capped at 2 per witness *and* 2 per transaction (binding cap closes multi-input data embedding); typed-field DATA is restricted to DATA_RETURN. Total user-chosen arbitrary data per tx: **112 bytes flat**, regardless of output count.

**Post-quantum signatures.** FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+ are native signature schemes, implemented and running on the live signet. A single SCHEME field on any signature block routes verification to classical Schnorr or any PQ algorithm. Incremental migration without a flag day.

**Lightweight PQ batches (PQ_BATCH).** A single-block primitive that commits `SHA256(falcon_pubkey)` per output. One "anchor" input in the spend tx reveals the pubkey + signature once; every other input gated by the same hash short-circuits via a tx-local cache. **~55 vB amortised per input** — about an order of magnitude cheaper than per-input FALCON. No coordinator, no priming round. See [`doc/ladder-script/PQ_BATCH_SPEC.md`](doc/ladder-script/PQ_BATCH_SPEC.md).

**Multi-party PQ batches (QABIO).** An N-party extension that lets a set of participants settle a single atomic batch transaction under one FALCON-512 coordinator signature. Each participant commits to the batch via a priming transaction, the coordinator assembles the batch and signs once, and the batch either settles atomically or every participant recovers their funds via an escape-rung SIG sweep. `QABI_PRIME` and `QABI_SPEND` are the two new block types that implement the commit-reveal protocol. **~143 vB per cosigner at N=100** — roughly equivalent to a P2WPKH payment, fully PQ-safe. See [`doc/ladder-script/QABIO.md`](doc/ladder-script/QABIO.md).

**Wire efficiency.** Compound blocks collapse common multi-block patterns (HTLC, PTLC, TIMELOCKED_MULTISIG) into single blocks. Relays allow shared conditions across rungs without duplication. Template references let inputs inherit conditions with field-level diffs.

**Legacy migration.** Seven legacy block types wrap P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR key-path, and P2TR script-path as typed Ladder Script blocks. Identical spending semantics, fully typed fields. Designed for a three-phase migration: coexistence, legacy-in-blocks, then sunset of raw legacy formats.

## 65 Block Types

| Family | Blocks |
|--------|--------|
| Signature | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG |
| Timelock | CSV, CSV_TIME, CLTV, CLTV_TIME |
| Hash | TAGGED_HASH, HASH_GUARDED |
| Covenant | CTV, VAULT_LOCK, AMOUNT_LOCK |
| Recursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| Anchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN |
| PLC | HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN |
| Compound | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG, ANCHOR_FEE |
| Governance | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK |
| Legacy | P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY, P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY |
| QABI / PQ | QABI_PRIME, QABI_SPEND, PQ_BATCH |

## Where things live in this repo

| Path | What |
|------|------|
| `src/rung/` | C++ consensus implementation (RUNG_TX, MLSC, QABIO, PQ verification) |
| `doc/ladder-script/` | Spec docs, BIP wireframe, design notes |
| `tools/` | Visual engine, QABIO playground, block reference (deployed to ladder-script.org) |
| `proxy/` | FastAPI signet proxy backing `/api/ladder/*` |
| `deploy/` | nginx vhost, deploy script, runbook for ladder-script.org |
| `spec/` | TLA+ specs |
| `test/functional/feature_rung_*.py` | Bitcoin functional tests for the consensus changes |
| `test/functional/feature_qabi.py` | QABIO functional tests |
| `test/tools/` | Smoke tests for the engine and signet API |
| `index.html` | ladder-script.org landing page source |

The rest of the tree is upstream Bitcoin Core v30.0.

## Branches

- `master` — tracks upstream Bitcoin Core v30.0 unchanged.
- `ladder-script` — the canonical Ladder Script branch (this is where you are if you're reading this README on GitHub).
- `feature/buds`, `feature/exorcism`, `feature/reaper`, `feature/shroud` — unrelated experiments on vanilla v30.0; not part of this project.

## Try it

- **[Ladder Engine](https://ladder-script.org/ladder-engine.html)** — browser-based visual builder. Load a preset, switch to SIMULATE, step through evaluation. The RPC tab shows wire-format JSON. The SIGNET tab funds, signs, and broadcasts real transactions on the live signet.
- **[QABIO Playground](https://ladder-script.org/qabio-playground/)** — multi-party batch sandbox. N participants prime UTXOs against a shared QABIO block, the coordinator assembles and signs, batch broadcasts. Includes the coordinator-bails escape-sweep flow.
- **[Block Reference](https://ladder-script.org/block-docs/)** — visual documentation for every block type.

All three tools talk to the live signet at `ladder-script.org/api/ladder/*`, which reverse-proxies to a node built from this repo.

## Build

Build instructions follow upstream Bitcoin Core — see [`doc/build-unix.md`](doc/build-unix.md), [`doc/build-osx.md`](doc/build-osx.md), [`doc/build-windows.md`](doc/build-windows.md). Use CMake. **`liboqs` is a hard dependency** — `find_package(liboqs REQUIRED)` in `src/rung/CMakeLists.txt` — because PQ signature schemes are part of the consensus surface; a node built without liboqs would silently disagree with PQ-enabled nodes on whether a PQ-signed spend is valid (consensus split). The QABIO extension (the multi-party batch ceremony) can be compiled out with `-DENABLE_QABIO=OFF` if you only want the base block set.

## Documentation

- [`doc/ladder-script/INTRODUCTION.md`](doc/ladder-script/INTRODUCTION.md) — what Ladder Script is and why
- [`doc/ladder-script/SIZING.md`](doc/ladder-script/SIZING.md) — measured wire and chainstate sizes for every shape
- [`doc/ladder-script/BLOCK_LIBRARY.md`](doc/ladder-script/BLOCK_LIBRARY.md) — every block type with fields and semantics
- [`doc/ladder-script/TX_MLSC_SPEC.md`](doc/ladder-script/TX_MLSC_SPEC.md) — transaction-level MLSC specification
- [`doc/ladder-script/MERKLE-UTXO-SPEC.md`](doc/ladder-script/MERKLE-UTXO-SPEC.md) — MLSC Merkle commitment and UTXO layout
- [`doc/ladder-script/QABIO.md`](doc/ladder-script/QABIO.md) — N-party PQ batch I/O extension
- [`doc/ladder-script/PQ_BATCH_SPEC.md`](doc/ladder-script/PQ_BATCH_SPEC.md) — lightweight PQ batch primitive
- [`doc/ladder-script/RPC_REFERENCE.md`](doc/ladder-script/RPC_REFERENCE.md) — every RPC the library adds
- [`doc/ladder-script/EXAMPLES.md`](doc/ladder-script/EXAMPLES.md) — worked scenarios with RPC JSON
- [`doc/ladder-script/ENGINE_GUIDE.md`](doc/ladder-script/ENGINE_GUIDE.md) — how to use the visual builder
- [`doc/ladder-script/INTEGRATION.md`](doc/ladder-script/INTEGRATION.md) — wallet and application integration guide
- [`doc/ladder-script/ANNOTATED_DIFF.md`](doc/ladder-script/ANNOTATED_DIFF.md) — per-section walkthrough of the 805-line Core patch
- [`doc/ladder-script/ANNOTATED_LIBRARY.md`](doc/ladder-script/ANNOTATED_LIBRARY.md) — file-by-file walkthrough of the 19,336-line library
- [`doc/ladder-script/REVIEW_GUIDE.md`](doc/ladder-script/REVIEW_GUIDE.md) — recommended reading order for reviewers
- [`doc/ladder-script/SOFT_FORK_GUIDE.md`](doc/ladder-script/SOFT_FORK_GUIDE.md) — proposed activation path
- [`doc/ladder-script/POSSIBILITIES.md`](doc/ladder-script/POSSIBILITIES.md) — design space exploration
- [`doc/ladder-script/FAQ.md`](doc/ladder-script/FAQ.md) — common questions
- [`doc/ladder-script/GLOSSARY.md`](doc/ladder-script/GLOSSARY.md) — terminology reference
- [`doc/ladder-script/BIP-XXXX.md`](doc/ladder-script/BIP-XXXX.md) — BIP wireframe (pre-draft)

## License

MIT (Bitcoin Core upstream + Ladder Script additions, both).

---

The remainder of this README is the upstream Bitcoin Core text.

Bitcoin Core integration/staging tree
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

What is Bitcoin Core?
---------------------

Bitcoin Core connects to the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions. It also includes a wallet and graphical user
interface, which can be optionally built.

Further information about Bitcoin Core is available in the [doc folder](/doc).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/license/MIT.

Development Process
-------------------

The `master` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable. [Tags](https://github.com/bitcoin/bitcoin/tags) are created
regularly from release branches to indicate new official, stable release versions of Bitcoin Core.

The https://github.com/bitcoin-core/gui repository is used exclusively for the
development of the GUI. Its master branch is identical in all monotree
repositories. Release branches and tags do not exist, so please do not fork
that repository unless it is for development reasons.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).
