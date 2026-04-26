# Ladder Script

Ladder Script replaces Bitcoin Script with **65 typed function blocks**.
Instead of an untyped stack machine, every spending condition is a named
block with declared fields. Blocks are grouped into **rungs** (AND — all
must pass) and **ladders** (OR — first satisfied rung wins). Every byte
in a transaction belongs to one of 11 typed fields with enforced size
constraints.

A version 4 transaction (`RUNG_TX`) carries a single shared Merkle root
covering all outputs. Each output is **8 bytes on the wire** (value
only). The full spending conditions are committed in the Merkle tree
and revealed only at spend time — the unrevealed paths stay private.
The wire format is called Merkelised Ladder Script Conditions (MLSC).

Based on Bitcoin Core v30.0.

## Why Use It

**Smallest single payment in Bitcoin.** A key-path spend is **109 vB**
(1-in, 1-out) — 1 vB cheaper than P2WPKH (110), 2 vB cheaper than P2TR
key-path (111). No regression at the simplest case. Script-path spends
add ~39 vB for the LadderWitness + MLSCProof — that's the cost of the
richer block-typed semantics. (Numbers from
[`SIZING.md`](SIZING.md) — reproducible via the `mlsc_spend_path_sweep`
boost test.)

**Smallest UTXO footprint.** Each MLSC coin compresses to **3 bytes**
in chainstate after the standard UTXO compressor (1-byte SPK marker via
script type `0x06`). P2WPKH is 24 B; P2TR is 36 B. The 32-byte
`conditions_root` is stored once per transaction in a synthetic UTXO
entry, not once per output. Chainstate lives in RAM on every full node,
so this is **8–12× smaller per coin** than Taproot.

**Cheapest batch transactions.** A 100-output payout is **911 vB** in
MLSC vs **3,179 vB** P2WPKH and **4,369 vB** P2TR — 3.5× and 4.8×
smaller. Per-output marginal cost asymptotes to **8 vB** (MLSC) vs ~31
(P2WPKH) and ~43 (P2TR).

**Inscriptions are structurally impossible.** Every byte must belong to
a typed field. There is no contiguous attacker-chosen data block in a
RUNG_TX. The total user-chosen arbitrary data surface is **112 bytes
per transaction**, flat, regardless of output count: 64 B (2 PREIMAGE
fields × 32) + 40 B (one DATA_RETURN payload) + 8 B (locktime +
sequence). Fail-closed deserialisation rejects unknown types, unknown
fields, and trailing bytes.

**Privacy by default.** When you spend via one rung, only that rung's
conditions are revealed. Every other spending path stays hidden behind
its Merkle leaf hash. An observer sees how many paths exist but not
what they contain.

**Post-quantum ready, three ways.**

- **Per-input PQ signatures.** Swap the SCHEME field to FALCON-512,
  FALCON-1024, Dilithium3, or SPHINCS+ and the same transaction
  structure works with quantum-resistant signatures. No new opcodes, no
  new transaction format — just a different scheme byte.
- **`PQ_BATCH`** commits `SHA256(falcon_pubkey)` per output. One
  "anchor" input in the spend tx reveals the pubkey + signature once;
  every other input gated by the same hash short-circuits via a
  tx-local cache. **~55 vB amortised per input** — about an order of
  magnitude cheaper than per-input FALCON. No coordinator, no priming
  round.
- **QABIO** (Quantum Atomic Batch I/O) is a multi-party batch
  ceremony: a coordinator + N participants, one FALCON-512 aggregate
  signature covers the whole tx. **~143 vB per cosigner at N=100** —
  roughly equivalent to a P2WPKH payment, fully PQ-safe and atomically
  settled.

**Native covenants and state machines.** CTV template verification,
recursive covenants (`RECURSE_SAME`, `RECURSE_MODIFIED`, `RECURSE_COUNT`,
`RECURSE_SPLIT`, `RECURSE_DECAY`, `RECURSE_UNTIL`), vaults with
clawback (`VAULT_LOCK`), rate limiters, latches, counters, sequencers,
and cross-input constraints (`COSIGN`) — all as single typed blocks,
not fragile opcode sequences.

**ANYPREVOUT for payment channels.** BIP-118 analogue sighash flags
(`0x40`, `0xC0`) enable LN-Symmetry / eltoo-style channels where the
latest state simply replaces any older state.

## How It Works

A **ladder** is a set of spending paths. Each path is a **rung** of one
or more **blocks**. A `SIG` block checks a signature. A `CSV` block
checks a relative timelock. An `HTLC` block checks a hash preimage +
timelock + signature in one block. You combine them with AND logic
within a rung, and OR logic across rungs.

Public keys are folded into the Merkle leaf hash (`merkle_pub_key`)
rather than stored in the on-chain conditions. This eliminates the
writable surface that inscriptions exploit in Taproot. Key-consuming
blocks are never invertible — you cannot embed arbitrary data by
providing a garbage pubkey and inverting the result.

The whole conditions tree is committed once per transaction via the
shared `conditions_root`. At spend time, the spender reveals one rung
plus a Merkle proof against that root; only that rung's bytes hit the
chain.

## Where to next

- [`SIZING.md`](SIZING.md) — measured wire and chainstate sizes for
  every common shape.
- [`RPC_REFERENCE.md`](RPC_REFERENCE.md) — every RPC the library adds
  (`createrungtx`, `signrungtx`, `parseladder` / `signladder`,
  `qabi_*`, etc.).
- [`SOFT_FORK_GUIDE.md`](SOFT_FORK_GUIDE.md) — activation path and
  consensus rules.
- [`ANNOTATED_DIFF.md`](ANNOTATED_DIFF.md) and
  [`ANNOTATED_LIBRARY.md`](ANNOTATED_LIBRARY.md) — patch and library
  walkthroughs for reviewers.
- [`REVIEW_GUIDE.md`](REVIEW_GUIDE.md) — load-bearing vs optional
  callouts for each file.
