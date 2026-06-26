# Changelog

Ladder Script is distributed as a patch set on top of Bitcoin Core. Releases are
tagged `v30.0-ladder-0.N` — Bitcoin Core base **30.0** plus Ladder Script release
**0.N**. **The release tag is the only public version.** Older design notes use
internal labels like "v0.6 / v0.7 / v0.8" to track audit cycles (audit findings
E-0xx); those are not release versions and should not be quoted as such.

The canonical list of releases is the git tags (`git tag -l 'v30.0-ladder-*'`).
Binaries and signed `SHA256SUMS` are published on the GitHub Releases page; verify
against the signing key documented at
[ladder-script.org/get-started.html#download](https://ladder-script.org/get-started.html).

## v30.0-ladder-0.23 — 2026-05-04 (current)

Current public signet release. Highlights of the 0.1x–0.23 line:

- **Block library** — 65 typed block types over the v4 `RUNG_TX` / `TX_MLSC` wire
  format, with `~8 B`/output MLSC storage (value only; one shared `conditions_root`
  per tx, revealed at spend).
- **Post-quantum signatures** — FALCON-512/1024, Dilithium3, SPHINCS+ via the
  per-block `SCHEME` byte (liboqs, pinned to 0.10.1).
- **QABIO** — N-party batch I/O with `QABI_PRIME` / `QABI_SPEND` covenants and
  `SIGHASH_QABO`; escape-sweep path for non-cooperating participants.
- **Data-embedding closure** — pubkeys folded into Merkle leaves; key-consuming
  blocks are non-invertible. Audit #3 (0.7-era) closed the dead-pubkey slot
  channels (HTLC two-path, PTLC/ADAPTOR single-key, ANCHOR_CHANNEL marker-only)
  and capped `SCRIPT_BODY` at 1 field/tx (112 B/tx ceiling).
- **Formal verification** — 12 exhaustive TLA+ PASSes over the consensus
  invariants (incl. recursive covenants at 301M states).
- **Tests** — 665 boost cases (`rung_tests`) plus the functional suite
  (`feature_rung_*`, `feature_qabi*`), including the positive/negative/spend/sighash
  vector locks.

## Unreleased

- **tools** — Pinned the in-browser React/Babel CDN dependencies of the engine and
  playgrounds (`@babel/standalone@7.26.4`, `react`/`react-dom@18.3.1`). The
  previously unpinned `@babel/standalone` had begun resolving to Babel 8, whose
  transform broke the pages. Doc fix: `SUMMARY.md` key-path spend 110 → 109 vB.
- **ci** — `ci-rung.yml` now also runs the rung tx vector suites
  (`feature_rung_tx_vectors` / `_neg_vectors` / `_spend_vectors` /
  `feature_rung_sighash_vectors`); corrected the boost count to 665.
- **release** — Tagged releases now fail closed if no `GPG_PRIVATE_KEY` signing
  secret is configured (no more silently-unsigned `SHA256SUMS`).
