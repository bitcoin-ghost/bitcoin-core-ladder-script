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

**No inscription-style channel.** Every byte in an MLSC witness
belongs to a typed field that a specific block evaluator reads.
There is no equivalent of `OP_DROP` (push-and-discard) and no
equivalent of `OP_FALSE OP_IF ... OP_ENDIF` dead-code blocks — the
two patterns Ordinals and other inscription protocols use to embed
arbitrary bytes inside Tapscripts and P2WSH redeem scripts. Fail-
closed deserialisation rejects unknown block types, unknown field
types, oversize fields, and trailing bytes.

The minimum spendable v4 transaction has roughly 11 bytes of
attacker-controllable content (`nLockTime`, `nSequence`, the Schnorr
nonce). Above that floor, the per-tx ceiling depends on which block
types are revealed — every additional `HASH256`, `PREIMAGE`, or
`PUBKEY` field is structurally bounded by per-block field-count
enforcement (`MAX_FIELDS_PER_BLOCK = 16`), per-rung block count
(`MAX_BLOCKS_PER_RUNG = 8`), per-tx caps
(`MAX_PREIMAGE_FIELDS_PER_TX = 2`,
`MAX_SCRIPT_BODY_FIELDS_PER_TX = 1`), and the per-input
`MAX_LADDER_WITNESS_SIZE = 100 KB` cap. See
[`EMBEDDING_CHALLENGE.md`](EMBEDDING_CHALLENGE.md) for the full
empirical analysis.

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
  tx-local cache. **~17.8 vB amortised per input at N=100** — about
  22&times; cheaper than per-input FALCON-512. No coordinator, no
  priming round. (See [`PQ_BATCH_SPEC.md`](PQ_BATCH_SPEC.md) for the
  full cost table; pq-batch.html mirrors it.)
- **QABIO** (Quantum Atomic Batch I/O) is a multi-party batch
  ceremony: a coordinator + N participants, one FALCON-512 aggregate
  signature covers the whole tx. **~143 vB per cosigner at N=100**
  (converges to ~139 vB at N=500+) — roughly in the P2WPKH ballpark,
  fully PQ-safe and atomically settled. (See [`SIZING.md`](SIZING.md)
  §5 for the full N-vs-vB table; QABIO.md §8 covers the protocol
  derivation.)

**Native covenants and state machines.** CTV template verification,
recursive covenants (`RECURSE_SAME`, `RECURSE_MODIFIED`, `RECURSE_COUNT`,
`RECURSE_SPLIT`, `RECURSE_DECAY`, `RECURSE_UNTIL`), vaults with
clawback (`VAULT_LOCK`), rate limiters, latches, counters, sequencers,
and cross-input constraints (`COSIGN`) — all as single typed blocks,
not fragile opcode sequences.

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
