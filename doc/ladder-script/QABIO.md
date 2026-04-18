# QABIO — Quantum Atomic Batch Input / Output

QABIO lets N independent parties collapse their UTXOs into a single
transaction authorised by one post-quantum signature from a coordinator.
The whole batch either settles atomically in one block or it does not
settle at all. Nothing is escrowed, nothing is pre-registered, no keys
are shared. Each participant opts in with a one-shot covenant commitment
and retains a unilateral escape path back to their own key the entire
time.

QABIO is a consensus-native feature of Ladder Script, built on two new
block types — `QABI_PRIME` (0x0A01) and `QABI_SPEND` (0x0A02) — a new
transaction-level `SIGHASH_QABO`, and a new Replace-By-Depth (RBD)
mempool policy that lets coordinators re-target a batch before it fires.

This page walks through what QABIO does, who the actors are, how the
lifecycle works on-chain, what it costs in bytes and fees, and how to
build and test a real QABIO UTXO via the Ladder Engine.

---

## 1. Why it exists

Bitcoin has no native way for N independent parties to batch their funds
into a single transaction authorised by one signature. The usual
workarounds are:

- **Multisig / FROST / MuSig2.** Every party holds a fragment of the
  shared key. Requires coordination during key generation and during
  signing. Not post-quantum. Fails if any one party is offline at sign
  time.
- **Coordinator-held escrow.** A trusted coordinator collects funds,
  holds them, and makes the payout. Custodial. Loss of coordinator =
  loss of funds.
- **CoinJoin-style blind construction.** Each participant signs their
  own input after the coordinator assembles the joint transaction.
  Requires every participant to be online during signing. Slow.
- **Commitment + reveal protocols.** Two-phase: pre-commit to intent,
  then reveal. Either two on-chain transactions per batch or complex
  off-chain state machines.

QABIO replaces all of these with a single-shot primitive:

1. Each participant creates a UTXO with a QABI-aware conditions tree
   (one-time, on-chain).
2. Each participant unilaterally **primes** their UTXO for a specific
   upcoming batch by revealing an auth-chain preimage (one-shot,
   on-chain, no coordinator involvement).
3. The coordinator assembles a single N-input transaction that
   consumes every primed UTXO at once, signs it once with their own
   post-quantum key, and broadcasts.
4. Consensus atomically accepts the whole batch, or rejects it. There
   is no partial settlement.

The coordinator never holds participants' funds, never sees their
private keys, and cannot cause partial settlement. Participants retain
a standard signature-based escape path for the entire window.

---

## 2. Actors

**Participants.** The N users whose UTXOs are being batched. Each
participant holds:

- an `auth_seed` (32-byte secret) that generates their auth hash chain;
- an `owner_id` (SHA-256 of their Rung 0 post-quantum pubkey) committed
  to their UTXO;
- their own signature keys for the SIG escape rung.

**Coordinator.** One party — an exchange, mixer, payroll service, DEX
settlement layer, anything — who assembles and signs the batch
transaction. The coordinator holds:

- a FALCON-512 keypair. The pubkey (897 B) is published in advance; the
  privkey is used once per batch to sign `SIGHASH_QABO`.

The coordinator's role is bounded: they see the finalised
transaction before signing and can refuse to sign if the participant
set or output list is wrong. They cannot *modify* the transaction
after signing, and they cannot *steal* from it: consensus check 8
(see §6) requires `tx.vout` to bit-exact match the `outputs` list
inside the signed `qabi_block`.

---

## 3. The UTXO lifecycle

A QABI-enabled UTXO passes through up to three states during its life,
each as a regular on-chain transaction:

```
    ┌────────────┐   QABI_PRIME   ┌──────────┐   QABI_SPEND   ┌────────┐
    │ unprimed   │ ─────────────▶ │  primed  │ ─────────────▶ │ spent  │
    └────────────┘                └──────────┘                └────────┘
          │                             │
          │ SIG escape                  │ SIG escape
          │ (unilateral)                │ (unilateral, always valid)
          ▼                             ▼
    ┌──────────────┐              ┌──────────────┐
    │ participant  │              │ participant  │
    │ recovered    │              │ recovered    │
    │ (1-rung SIG) │              │ (1-rung SIG) │
    └──────────────┘              └──────────────┘
```

### Unprimed

The participant creates a v4 `rung_tx` whose output is an MLSC UTXO
with a 3-rung conditions tree:

```
  rung 0: SIG(participant_pubkey)           ← escape hatch
  rung 1: QABI_PRIME                        ← priming entry point
  rung 2: QABI_SPEND(auth_tip, 0, 0, 0, owner_id)  ← batch-spend entry
```

- `auth_tip` is `SHA256^N(auth_seed)` — the far end of the participant's
  hash chain.
- `committed_root`, `committed_depth`, and `committed_expiry` are all
  zero because the UTXO has not yet been primed to any batch.
- `owner_id` is `SHA256(FALCON_pubkey_of_participant)`.

At this state the UTXO is spendable via any of the three rungs. Rung 0
is the normal unilateral exit. Rung 1 is what the participant fires to
prime into a specific batch. Rung 2 is not yet valid — the evaluator
rejects any attempt to batch-spend while `committed_root` is zero.

### Primed

The participant runs a `QABI_PRIME` transaction that spends the
unprimed UTXO and produces a new MLSC UTXO whose conditions tree is
bit-exact the same *except* for the QABI_SPEND rung, where:

- `committed_root` ← the coordinator's announced `SHA256(qabi_block)`;
- `committed_depth` ← a fresh depth strictly greater than the
  previous committed depth;
- `committed_expiry` ← a block height after which the primed
  commitment auto-expires.

The consensus evaluator enforces this as a **covenant** — it rebuilds
the expected output conditions tree with the mutated QABI_SPEND rung,
recomputes the MLSC Merkle root, and checks it matches the output
UTXO's scriptPubKey bit-exact.

The participant authorises QABI_PRIME by revealing `prime_preimage`,
the hash-chain value at the chosen `prime_depth`. The evaluator checks
`SHA256^prime_depth(prime_preimage) == auth_tip`. Only the `auth_seed`
holder can produce this; no coordinator signature is required at
priming time.

After priming, the UTXO is in the "committed to batch R, expiring at
height H" state. Rung 0 (SIG escape) is still valid. Rung 2 (QABI_SPEND)
becomes valid for the specific batch whose root equals
`committed_root`.

### Batch spent

The coordinator collects K primed UTXOs (not necessarily all at once —
any subset of UTXOs whose `committed_root` matches the coordinator's
batch root can participate), assembles a single `rung_tx` with K inputs
and the output set defined in `qabi_block`, computes `SIGHASH_QABO`,
and signs once with their FALCON-512 key.

When the transaction is broadcast, consensus runs all 9 QABI_SPEND
checks per-input (§6), but the expensive FALCON-512 verification is
cached *across* inputs — one verify per transaction, shared by every
primed input, because all inputs reference the same `aggregated_sig`
and the same `qabi_block`.

Each primed UTXO's contribution lands at the destination address the
coordinator committed to in `qabi_block.outputs`. No skim is possible
because consensus requires `tx.vout` to bit-exact equal
`qabi_block.outputs` (check 8).

If any single input fails any check, consensus rejects the whole
transaction. Partial settlement is impossible.

### Escape — the coordinator bails

Every state of a QABI UTXO has the SIG escape rung enabled throughout.
If the coordinator never produces a valid `QABI_SPEND` tx, or produces
one that doesn't match the participant's committed state, or simply
goes dark after priming, the participant can sweep the UTXO with their
own key by spending the SIG rung:

```
  participant signs the primed UTXO with their own Schnorr key
       ↓
  primed UTXO consumed
       ↓
  fresh 1-rung [SIG(participant_pubkey)] MLSC UTXO appears
       ↓
  participant owns it unilaterally, can spend freely
```

This works on both unprimed and primed UTXOs — the SIG rung's content
is identical in both cases, so the Merkle leaf for rung 0 is
byte-identical, and the signature-authorised spend path always works.

The recovered UTXO is an MLSC UTXO (not a plain P2WPKH), because
consensus requires every output of a v4 rung_tx to be MLSC
(`rung-non-mlsc-output` rule). The recovered UTXO has a single SIG
rung bound to the participant's own key and is spendable at any time
via a normal rung_tx signature. Functionally equivalent to a wallet
recovery, one level of indirection away.

---

## 4. The QABI block

A `QABIBlock` is a small structured blob attached to the transaction
at the `tx.qabi_block` field. It carries everything the consensus
evaluator needs to verify the batch without any per-input duplication:

```
struct QABIBlock {
    version              : 1 byte    (currently 0x01)
    batch_id             : 32 bytes  (unique batch identifier)
    coordinator_pubkey   : 897 bytes (FALCON-512)
    prime_expiry_height  : 4 bytes   (uint32 LE)
    entries[]            : N × QABIEntry
    outputs[]            : K × CTxOut
};

struct QABIEntry {
    participant_id   : 32 bytes  (SHA-256 of participant's pubkey)
    contribution     : 8 bytes   (sats)
    destination_index: 1-4 bytes (compact-size index into outputs[])
};
```

The `qabi_block` is serialised into the witness section of the v4
transaction (flag 0x02 TX_MLSC format), along with the per-input
witnesses, creation proof, and aggregated signature. Witness data is
weight-discounted 4:1 under BIP-141, so `qabi_block` bytes cost 1
weight unit each, not 4.

The coordinator's signature commits to `SHA256(serialised qabi_block)`
via `committed_root` in every primed input's `QABI_SPEND` rung. This
pins the batch: participants can see *exactly* which batch they are
priming into before they sign their priming transaction, because
`committed_root` is a field they set with their own hands. The
coordinator cannot switch the batch out from under them.

The consensus evaluator caps `qabi_block` size at `QABI_BLOCK_MAX_HARD
= 256 KB` (hard, enforced at block acceptance) and at 64 KB for
standard relay (soft, enforced at mempool acceptance).

---

## 5. The coordinator signature

`SIGHASH_QABO` is a new sighash type defined for the coordinator's
batch signature. It commits to:

- the transaction version, locktime, and all input prevouts
  (`hashPrevouts` from BIP-143);
- the full `tx.vout` set (`hashOutputs`);
- every input's `scriptWitness.stack` (the LadderWitness + MLSCProof
  bytes per input — this is what makes the sig "atomic", because
  substituting any witness stack invalidates the signature);
- the `qabi_block` contents (so the coordinator cannot be tricked
  into signing over an altered entries/outputs list);
- the `coordinator_pubkey` and `batch_id` from inside `qabi_block`.

It deliberately excludes `aggregated_sig` itself (otherwise the sig
would be self-referential). The evaluator computes `SIGHASH_QABO`
identically for every input of a batch-spend transaction — which is
why the verification can be cached. The first input pays the FALCON
verify cost, every subsequent input of the same transaction hits a
cache entry.

Cached verification is measured at ~865 µs per input for N=1000, vs.
~4.1 ms per input uncached. The FALCON-512 verification itself is the
dominant cost at roughly 2 ms; the cache amortises it to a ~5× speedup
across all primed inputs of a single transaction.

---

## 6. Consensus evaluation

When a primed UTXO is spent via its QABI_SPEND rung, the consensus
evaluator runs nine checks per-input. They are listed here in the
order they fire, with the failure mode for each:

1. **Field shape.** All 6 witness+conditions fields present, correct
   types, correct sizes. Failure → ERROR.
2. **Expiry window.** `block_height <= committed_expiry`. Failure →
   UNSATISFIED.
3. **Spend preimage valid.** `SHA256^(committed_depth + 1)(spend_preimage)
   == auth_tip`. Failure → UNSATISFIED.
4. **Aggregated signature size.** `tx.aggregated_sig.size() ==
   QABI_AGGREGATED_SIG_MAX (666)` and `tx.qabi_block` non-empty.
   Failure → ERROR.
5. **qabi_block parses and matches committed root.** Parse
   `qabi_block`; check `coord_pk.size() == QABI_COORDINATOR_PUBKEY_SIZE
   (897)`; verify `SHA256(qabi_block) == committed_root`. Failure →
   UNSATISFIED.
6. **FALCON-512 verification.** Compute `SIGHASH_QABO` over the tx +
   per-input witnesses + qabi_block; verify `FALCON-512(coord_pk,
   sighash, aggregated_sig)`. Cached across inputs via the per-tx
   QABO sig cache. Failure → UNSATISFIED.
7. **Identity in block.** This input's `owner_id` must appear in
   `qabi_block.entries[*].participant_id`. Performed as an O(1)
   hash-indexed lookup via a pre-built `std::unordered_set` to keep
   total identity-check work at O(N) across the whole batch rather
   than O(N²). Failure → UNSATISFIED.
8. **Full output set match.** `tx.vout` bit-exact equal to
   `qabi_block.outputs` — same count, same order, same values, same
   scriptPubKeys. Closes the coordinator-skim hole. Failure →
   UNSATISFIED.
9. **Expiry binding.** `qabi_block.prime_expiry_height ==
   committed_expiry`. Prevents the coordinator signing over a
   qabi_block with a different expiry than what participants primed
   against. Failure → UNSATISFIED.

If any single check on any single input fails, the whole transaction
is rejected. There is no partial acceptance path.

---

## 7. Replace-By-Depth (RBD)

QABIO introduces a small mempool policy called Replace-By-Depth,
specific to QABI_PRIME transactions. It replaces the usual BIP-125
Replace-By-Fee for priming, because priming cost isn't a fee
auction — it's a depth commitment.

The rule: a participant can replace their own primed transaction in
the mempool by submitting a new priming transaction with a strictly
deeper `prime_depth`. The old transaction is evicted, the new one
takes its slot, and the UTXO ends up committed to the deeper state.

This lets a participant re-aim their commitment if the coordinator
announces a revised batch, without having to wait for their first
priming tx to confirm. It also prevents a malicious actor from
stuffing the mempool with stale QABI_PRIME transactions at shallow
depths.

---

## 8. Size and scale

Measured on v1 QABIBlock format with FALCON-512 coordinator signature,
1-rung MLSC proof per input, per-input LadderWitness carrying the
full QABI_SPEND block:

| participants | qabi_block | tx bytes | vsize | block %   |
|--------------|------------|----------|-------|-----------|
| 10           | 1,659      | 5,946    | 2,034 | 0.20 %    |
| 100          | 8,139      | 44,556   | 16,547 | 1.65 %   |
| 500          | 37,437     | 216,658  | 81,175 | 8.12 %   |
| 1,000        | 74,437     | 432,160  | 162,051 | 16.21 % |
| 2,000        | 148,437    | 863,160  | 323,801 | 32.38 % |
| 3,000        | 222,437    | 1,294,160 | 485,551 | 48.56 % |

Asymptotic cost is ~432 bytes per participant, converging from N=50
upward. After witness discount: ~162 vbytes per participant.

There are three binding ceilings on the maximum number of participants
in a single QABIO batch:

- **Standard-relay (`MAX_STANDARD_TX_WEIGHT = 400,000 WU`).** Binds at
  roughly **618 participants**. Batches above this do not propagate
  through normal p2p relay and must be submitted directly to a mining
  pool (Stratum V2 selection, private API, or cooperative pool
  agreement).
- **QABIO block cap (`QABI_BLOCK_MAX_HARD = 256 KB`).** Binds at
  roughly **3,500 participants**. This is the `qabi_block` serialised-
  size limit.
- **Block weight (`MAX_BLOCK_WEIGHT = 4,000,000 WU`).** Binds at
  roughly **6,100 participants** — an absolute ceiling since a single
  transaction cannot exceed the weight of an entire block. In practice
  the qabi_block cap binds first.

The coordinator signature (666 bytes) and pubkey (897 bytes) are
fixed-size overheads amortised across every participant. Their
relative share drops from 38 % of the total transaction at N=10 to
under 0.5 % at N=500.

---

## 9. Why FALCON-512

The coordinator signature is hardcoded to FALCON-512. The
`QABI_COORDINATOR_PUBKEY_SIZE = 897` and `QABI_AGGREGATED_SIG_MAX = 666`
constants are baked into the consensus evaluator. Other post-quantum
schemes (FALCON-1024, DILITHIUM3, SPHINCS+) are not currently usable
for QABIO.

The choice is driven by size, not security. FALCON-512 has the
smallest signature of any NIST-standardised post-quantum signature
scheme — 666 bytes vs. 1280 for FALCON-1024, 3293 for DILITHIUM3, and
~8 KB+ for SPHINCS+. Since the signature is a fixed per-transaction
overhead amortised across every primed input, smaller is strictly
better for the amortised per-input cost.

A future `QABI_BLOCK_VERSION = 0x02` could unlock scheme selection via
a dispatch byte in the qabi_block header. The design leaves room for
this — `QABI_BLOCK_VERSION_CURRENT` is already a field — but no such
extension is wired today.

---

## 10. Scaling beyond v1

At ~3,500 participants the current block format hits the
`QABI_BLOCK_MAX_HARD` ceiling and a future v2 block format is needed
to go further. Two v2 designs have been considered:

- **Merkle-committed entries and outputs (v2a).** Replace the entries
  and outputs vectors in `qabi_block` with two 32-byte Merkle roots.
  Each spending input carries its own entry leaf + output leaf + two
  inclusion proofs. *Measured result: strictly worse.* The O(log N)
  proof overhead per input overwhelms the amortised qabi_block saving,
  so transactions grow ~2× larger at N=1000. This design should not
  be pursued.

- **Eliminate entries and outputs entirely (v2b).** Both lists are
  arguably redundant with existing SIGHASH_QABO commitments: the
  per-UTXO preimage binding already enumerates legitimate
  participants, and `hashOutputs` already pins the output set.
  Removing both lists shrinks qabi_block to a fixed ~937-byte header
  (independent of N) and saves roughly 74 bytes per participant
  across the transaction. Requires removing consensus checks 7 and 8,
  which is a non-trivial audit exercise.

v1 is the launch design. v2 is deferred until a real deployment hits
the standard-relay cap or asks for batches beyond 3,500 participants.

For the full scaling analysis including measured numbers at every N
and the forward-compatible soft-fork activation path, see the QABIO
scaling decision note at `doc/ladder-script/project_qabi_scaling.md`
in the bitcoin-core-ladder repository.

---

## 11. Building and testing a QABIO UTXO

The Ladder Engine has native support for placing QABI_PRIME and
QABI_SPEND blocks into a rung tree, filling in committed state,
preimages, and covenant targets, and visualising the resulting
conditions tree. Four preset examples are available in the Examples
menu:

- **QABIO UTXO — FRESH (unprimed)**: the 3-rung
  `[SIG_escape, QABI_PRIME, QABI_SPEND]` deployment shape with
  committed_root, depth, and expiry all zero.
- **QABIO UTXO — PRIMED**: the same UTXO after a priming transaction
  has fired, with committed state populated.
- **QABIO COORDINATOR BAILS — ESCAPE**: the 1-rung SIG-only target
  the participant sweeps into via the escape path.
- **QABIO BATCH PAYOUT — COORDINATOR VIEW**: a single QABI_SPEND rung
  authorising an N-party batch.

Load any of these, modify the fields, and use the engine's BUILD /
SIMULATE / CONVERT tabs to see the resulting JSON descriptor and hex
serialisation.

Beyond visual construction, the ladder-proxy serves six QABI-specific
JSON endpoints for client-side scripting and browser integration:

```
POST /api/ladder/qabi/authchain   — compute auth_tip + preimage
POST /api/ladder/qabi/buildblock  — serialise a QABIBlock from
                                     coord_pk + entries + outputs
POST /api/ladder/qabi/blockinfo   — decode a QABIBlock hex blob
POST /api/ladder/qabi/sighash     — compute SIGHASH_QABO for a v4 tx
POST /api/ladder/qabi/signqabo    — coordinator FALCON-512 signing
GET  /api/ladder/qabi/info        — static metadata: scheme, sizes,
                                     caps, per-input costs
```

Each endpoint is a thin wrapper over the corresponding bitcoind
`qabi_*` JSON-RPC with minimal input validation. A browser or client
script can drive the whole QABIO lifecycle end-to-end without building
bitcoin-cli or the test harness. See `contrib/qabi/` in the
bitcoin-core-ladder repository for a reference Python driver
(`signet_lifecycle.py`) that exercises the full priming + spending
flow against a live signet node.

For consensus-level reference material:

- **Block reference pages:** the
  [QABI_PRIME block doc](../block-docs/qabi-prime.html) and
  [QABI_SPEND block doc](../block-docs/qabi-spend.html) cover fields,
  wire format, evaluator checks, worked examples, and use cases.
- **Descriptor notation.** QABIO conditions trees can be written in
  descriptor form (`qabi_prime()` and `qabi_spend()` tokens) for
  programmatic construction.

---

## 12. Status

QABIO is implemented, tested, and running on the Ladder Script
signet. The consensus implementation lives in
`src/rung/qabi.{h,cpp}`, `src/rung/evaluator.cpp`
(`EvalQABIPrimeBlock` / `EvalQABISpendBlock`), `src/rung/policy.cpp`
(RBD helpers), and `src/validation.cpp` (RBD mempool integration) in
the bitcoin-core-ladder repository.

Test coverage includes:

- 77 unit tests in the `qabi_tests` suite covering all 9 consensus
  checks, the QABO sig cache amortisation, multi-party scale testing
  up to N=3,000, and the SIG escape rung end-to-end.
- Functional regression tests in `test/functional/feature_qabi.py`
  exercising the full mined priming lifecycle, the SIG escape after
  priming, and reorg survival on a regtest node.
- Live-signet smoke tests via `contrib/qabi/signet_lifecycle.py` and
  `contrib/qabi/signet_escape.py`, verified end-to-end on the
  ladder-script signet chain.

The first real QABIO transactions on a live non-regtest chain are
published on the ladder-script signet; references:

- Priming transaction: `8f379e0c8c0a6acaa48d260be6b869efe8e159c1be85aed9b221d77496ac4ea5`
- Escape transaction: `7bd0d5e4ced77cb2b5d1f12a0494273e1f61c9e988ede6f38b3e4ad126e4c66a`

QABIO is ready for production use. The remaining work is a BIP
submission, an external security audit, and — eventually — a v2
block format for batches beyond ~3,500 participants.
