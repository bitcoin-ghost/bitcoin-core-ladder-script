# QABIO scaling — v1 launch, v2 future optimisation

**Status:** decision captured, v2 deferred
**Measured on:** commit `019bcdb2e5`
**Companion tests:** `qabi_tests/qabi_tx_size_sweep` and `qabi_tests/qabi_tx_size_sweep_v2_projection`

## 1. What v1 costs today

Measured empirically on a realistic batch-spend tx with FALCON-512
coordinator signature, 1-rung MLSC proof per input, per-input
LadderWitness carrying the full QABI_SPEND block.

| N     | qabi_block | full tx bytes | vsize   | block % (of 4M WU) |
|-------|------------|---------------|---------|-------------------|
| 1     | 1,011      | 2,085         | 583     | 0.06%             |
| 10    | 1,659      | 5,946         | 2,034   | 0.20%             |
| 100   | 8,139      | 44,556        | 16,547  | 1.65%             |
| 500   | 37,437     | 216,658       | 81,175  | 8.12%             |
| 1,000 | 74,437     | 432,160       | 162,051 | 16.21%            |
| 2,000 | 148,437    | 863,160       | 323,801 | 32.38%            |
| 3,000 | 222,437    | 1,294,160     | 485,551 | 48.56%            |

**Asymptotic per-input cost:** ~432 bytes of serialised tx, ~162
vbytes after witness discount. Converges from N≈50 upward.

**Binding constraints:**

- **Standard-relay ceiling (`MAX_STANDARD_TX_WEIGHT = 400,000 WU`)**
  — hits at ~**618 participants**. Above this, the tx is non-
  standard and must be submitted directly to a miner (Stratum V2,
  private mempool, or cooperative pool API) to land in a block.
- **QABI block hard cap (`QABI_BLOCK_MAX_HARD = 262,144 bytes`)** —
  at ~74 bytes per participant inside `qabi_block`, this caps a
  single batch at **~3,500 participants** (before the tx itself
  would exceed block weight).
- **Block weight (`MAX_BLOCK_WEIGHT = 4,000,000 WU`)** — a single
  tx cannot exceed the whole block. At v1's per-input cost this
  gives an absolute ceiling of ~**6,100 participants**, but the
  qabi_block cap binds first.

For most realistic deployment shapes (tens to a few hundred
participants per batch), v1 is comfortably inside the standard-
relay envelope and none of the ceilings bind. Fee cost is
amortised across participants, each paying their proportional
share of the ~432 bytes per input.

## 2. The v2 design space

Two candidate v2 shapes have been considered. One is a trap, one
is a real optimisation. The distinction matters because they look
superficially similar.

### 2a. Merkle-committed v2 (DO NOT IMPLEMENT)

Replace `entries` and `outputs` vectors in `qabi_block` with two
32-byte Merkle roots. Each input's witness then carries its own
entry leaf + output leaf + two Merkle inclusion proofs so
consensus can verify the input's membership in the committed set.

**Measured effect:** strictly worse at every N.

    v2_merkle per-input witness = v1 + 73 + 64 * log2(N)
                                = v1 + 713 bytes at N=1,000
                                = v1 + 841 bytes at N=3,000

    At N=1,000 the tx GROWS by ~650 KB compared to v1.

The O(log N) proof overhead per input overwhelms the amortised
`qabi_block` saving from the full tree. The only situation where
Merkle commit helps is when the coordinator needs to prove a very
large static set to many **separate** consumers — which is not
the QABIO shape at all, since every "consumer" is already an
input in the same tx.

**Mark this design as a trap in any future discussion.** If a
reviewer suggests "just Merkle-commit the entries", the answer is
that the measurement is in `qabi_tx_size_sweep_v2_projection` and
it makes the problem worse.

### 2b. Eliminate entries + outputs entirely (real optimisation)

`entries` and `outputs` in `qabi_block` are both potentially
redundant with commitments that SIGHASH_QABO already makes at the
tx level:

- **`entries` is redundant with per-UTXO preimage binding.** Each
  `QABI_SPEND` witness must present a spend preimage that hashes
  (via SHA256 iterated `committed_depth` times) to the `auth_tip`
  committed into *that specific* UTXO's conditions tree. Only the
  legitimate owner of a UTXO knows its preimage. The set of valid
  QABI_SPEND inputs in a tx is therefore exactly the set of
  legitimate participants — no separate `entries` list is needed
  to enumerate them.

- **`outputs` is redundant with SIGHASH_QABO's `hashOutputs`.**
  The coordinator's aggregated signature covers the full tx-level
  sighash, which already includes `hashOutputs`. The coordinator
  cannot substitute or re-order outputs without invalidating the
  signature. The per-tx "`tx.vout` bit-exact equal to
  `block.outputs`" consensus check (check 8 in EvalQABISpendBlock)
  becomes a tautology under SIGHASH_QABO's existing commitments.

If both observations hold, both lists can be **eliminated**
(not just Merkle-committed) from `qabi_block`, and consensus
checks 7 and 8 in `EvalQABISpendBlock` can be removed. The
`qabi_block` then reduces to a fixed-size header:

    version              1 byte
    batch_id            32 bytes
    coordinator_pubkey  897 bytes   (FALCON-512)
    prime_expiry_height   4 bytes
    framing               3 bytes
    ─────────────────────────────
    ~937 bytes, independent of N

**Measured projection** (simulated by replacing the v1 qabi_block
with a header-only stub in `qabi_tx_size_sweep_v2_projection`,
leaving everything else identical):

| N     | v1 tx     | v2 tx     | saved B  | v1 vsize | v2 vsize | v1 %blk | v2 %blk |
|-------|-----------|-----------|----------|----------|----------|---------|---------|
| 100   | 44,556    | 37,354    | 7,202    | 16,547   | 14,746   | 1.65%   | 1.47%   |
| 500   | 216,658   | 180,158   | 36,500   | 81,175   | 72,050   | 8.12%   | 7.21%   |
| 1,000 | 432,160   | 358,658   | 73,502   | 162,051  | 143,675  | 16.21%  | 14.37%  |
| 2,000 | 863,160   | 715,658   | 147,502  | 323,801  | 286,925  | 32.38%  | 28.69%  |
| 3,000 | 1,294,160 | 1,072,658 | 221,502  | 485,551  | 430,175  | 48.56%  | 43.02%  |

**~17% smaller at every N, 74 bytes saved per participant**, all
in the witness section.

**Operational impact:**

| Metric                             | v1     | v2 (projected) | Δ       |
|------------------------------------|--------|----------------|---------|
| Standard-relay ceiling (~N)        | 618    | 697            | +13%    |
| Single-block consensus ceiling (~N) | 3,500 | 6,965          | +99%    |
| Block % at N=3,000                 | 48.56% | 43.02%         | -5.5 pp |
| `qabi_block` hard cap binding?     | yes    | no             | —       |

The real win is not the 17% byte reduction — it's that
`QABI_BLOCK_MAX_HARD` **ceases to be the binding ceiling**. The
new ceiling is block weight itself, which is ~2× further out.

## 3. Why v1 is the launch design

Despite the v2b elimination looking attractive on the numbers,
**v1 is the right shape to launch with**:

1. **17% is modest relative to the risk.** For realistic batch
   sizes (50–500 participants) fees are amortised across inputs,
   and v1's per-input cost is already in a fine range. Saving 74
   bytes per participant is real, but it's not a step-change.

2. **v2b removes two consensus rules.** Both check 7 (owner_id
   lookup) and check 8 (vout match) are argued redundant in
   section 2b, but the argument is informal. Removing consensus
   rules is a "prove a negative" exercise — you have to convince
   yourself that no adversarial shape exists that bypassed the
   rule. This is a real audit cost, not a drive-by edit.

3. **v1 is proven and shipped.** Full mined lifecycle works on
   regtest and live signet. 77 qabi_tests + 513 rung_tests pass.
   QABI_PRIME covenant covenant works across both a pure QABIO
   tree and a 3-rung `[SIG_escape, QABI_PRIME, QABI_SPEND]` tree
   with real Schnorr escape keys. Adding v2 to the pre-launch
   critical path would:
   - delay BIP submission
   - put an un-audited optimisation in front of reviewers who'd
     rightly ask "why are you already bumping the version byte
     before v1 has ever been used?"
   - trade a proven design for an unproven one right before
     external review

4. **No realistic deployment is hitting v1's ceilings.** The
   standard-relay cap of ~618 participants is comfortably above
   realistic coordinator batch sizes. The `qabi_block` hard cap
   of ~3,500 participants is academic for v1 — nobody will hit
   it before v2 gets reconsidered organically.

## 4. When to revisit v2

Defer v2 until one of these is true:

- A real deployment hits the standard-relay cap (~618 participants)
  and wants higher without a direct-to-miner submission pipeline.
- A real deployment needs batches above ~3,500 participants.
- A formal adversarial audit of the check 7 / check 8 redundancy
  argument is complete and the conclusion is "both checks are
  safely removable".

None of those is true today. When any of them becomes true, the
v2b design (section 2b) is the target. The v2a Merkle-commit
design (section 2a) is never the answer — it should be explicitly
rejected in any future discussion.

## 5. Forward-compatible design notes

The `qabi_block` wire format already starts with a version byte
(`QABI_BLOCK_VERSION_CURRENT = 0x01`). A v2 activation would:

1. Bump the version byte to `0x02`.
2. Change the parser at `src/rung/qabi.cpp:ParseQABIBlock` to
   accept the new layout (header-only: version, batch_id,
   coord_pk, prime_expiry_height — no entries/outputs vectors).
3. Remove consensus checks 7 and 8 from
   `src/rung/evaluator.cpp:EvalQABISpendBlock` under a version-
   gated condition (accept either rule set based on the
   `qabi_block` version).
4. Ship a soft-fork activation so old nodes don't reject v2 txs.

The soft-fork is non-trivial because v2 is more permissive than
v1 (fewer checks, smaller block). A versioned evaluator is the
cleanest path — old nodes continue to enforce v1 rules on v1
txs, new nodes additionally accept v2 txs.

## 6. Size-reduction avenues that are NOT in v2

Two axes of potential size reduction worth noting, not addressed
by v2:

- **Per-input witness compression.** The 308 bytes of
  LadderWitness + MLSCProof per input is the dominant per-input
  cost (not the qabi_block). Template-based compression (since
  every QABI_SPEND witness has the same block type + field
  layout) could plausibly cut this by 30-50%. Would require a
  new witness format version, not related to qabi_block v2.

- **FALCON signature aggregation for per-input PQ sigs.** Not
  applicable today because QABI_SPEND doesn't carry per-input PQ
  signatures (the aggregated coordinator sig covers the batch).
  Relevant if future QABI_SPEND variants require per-participant
  PQ authorisation.

Neither is planned. Documented here so future contributors don't
conflate "QABI block v2" with "QABIO size optimisation in
general" — they're different projects.
