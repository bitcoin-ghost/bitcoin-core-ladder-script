# Plan: MULTISIG inner-Merkle redesign

**Status:** drafted 2026-04-27. Awaiting code work.
**Driver:** the K<N data-embedding bypass demonstrated on signet
2026-04-27 (spend tx `8f3eb8f82b14ddf7a7c3bcbf19e6c4451c083cf7841194d1381f2221bedc1f7c`,
3,584 B of arbitrary data in a single MULTISIG-stuffed witness).

The current MULTISIG block exposes `(N − K)` unused PUBKEY slots as a
free arbitrary-data surface. This plan replaces the inline-N-pubkeys
format with a Merkle-committed pubkey set: only the `K` actually-
signing pubkeys ever appear on-chain.

The change is consensus-side. It must land **before** the BIP draft is
submitted and **before** any release is tagged for review. Pre-
activation, no migration concerns — the block hasn't been deployed.

---

## 1. What changes / what doesn't

**Changes**

- Wire format of MULTISIG conditions: list of N pubkeys → single `pubkey_root` HASH256.
- Wire format of MULTISIG witness: `K` × `(PUBKEY + MERKLE_PROOF + SIGNATURE)` instead of N pubkeys + K sigs.
- `EvalMultisigBlock`: rewrite the eval loop. Per revealed pubkey, verify Merkle inclusion against `pubkey_root` first, then signature.
- `BuildWitnessBlock` MULTISIG branch (`SignMultiKey`): build the inner Merkle tree at fund time, generate inclusion proofs at spend time.
- `signrungtx` RPC: accept N pubkeys + K privkeys at fund time (computes root); accept K signing privkeys at spend time (computes proofs).
- `createrungtx` RPC: accept the new conditions shape (`{type: MULTISIG, fields: [NUMERIC(K), HASH256(pubkey_root)]}`).
- Descriptor notation: `multisig(K, @a, @b, @c, @d, @e)` continues to work at the parser level; the parser computes `pubkey_root` internally and emits the new wire format.

**Doesn't change**

- Block type code (still `MULTISIG = 0x0102` per the registry).
- K-of-N semantics from the user's perspective.
- Other signature blocks (SIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG).
- The `value_commitment` rule for the MULTISIG block (the field shape changes, but the leaf hash construction is the same).

---

## 2. Spec definition

### Conditions (committed at fund time)

```
MULTISIG block fields:
    [0] NUMERIC      threshold K (1 ≤ K ≤ MAX_PUBKEYS_PER_MULTISIG)
    [1] HASH256      pubkey_root
```

`pubkey_root` is the BIP-340 tagged-hash Merkle root over the N pubkey
commitments:

```
pubkey_root = MerkleRoot([leaf_0, leaf_1, …, leaf_{N-1}])
where leaf_i = TaggedHash("LadderMultisigPubkey/v1", canonical_pubkey_bytes_i)
```

`canonical_pubkey_bytes_i` is the 32-byte x-only encoding for Schnorr
or the FALCON / Dilithium / SPHINCS+ canonical encoding for PQ schemes.
The PQ encoding uses the same `length_public_key` bytes as
`OQS_SIG_new(scheme)->length_public_key`.

Pad to next power of two using the existing `MLSC_EMPTY_LEAF` constant.
Interior hashing follows the same `min(L, R) || max(L, R)` byte-sorted
pattern as the MLSC tree, with tag `"LadderMultisigInternal/v1"`.

The `SCHEME` field, if present, lives in the same slot it does today
(after the threshold and pubkey_root, ordering preserved).

### Witness (revealed at spend time)

For each of K signing positions:

```
PUBKEY            canonical pubkey bytes
MERKLE_PROOF      list of sibling hashes from leaf to pubkey_root
SIGNATURE         valid sig over SIGHASH_LADDER for this input
```

`MERKLE_PROOF` is a new field type — see §4 for the wire encoding.

The witness fields appear in K consecutive groups of three: `(P_0, M_0,
S_0), (P_1, M_1, S_1), …, (P_{K-1}, M_{K-1}, S_{K-1})`. Order is
significant only insofar as proofs and sigs must align with their
pubkey by position.

### Evaluator

```
EvalMultisigBlock:
    threshold K = NUMERIC field [0]
    pubkey_root = HASH256 field [1]

    Group witness fields into K groups of (PUBKEY, MERKLE_PROOF, SIGNATURE).
    If group count < K: return UNSATISFIED (insufficient sigs).
    If group count > K: return ERROR (too many — bound spend size).

    seen_pubkeys: set of bytes
    valid_count: 0
    For each (P, M, S):
        if P in seen_pubkeys: return ERROR (duplicate — drop equivocation)
        if not VerifyMerkleInclusion(leaf=TaggedHash("LadderMultisigPubkey/v1", P),
                                      proof=M, root=pubkey_root):
            return UNSATISFIED  (pubkey not in committed set)
        if not VerifySignature(scheme, P, sighash, S):
            return UNSATISFIED  (signature invalid)
        seen_pubkeys.add(P)
        valid_count += 1

    return (valid_count >= K) ? SATISFIED : UNSATISFIED
```

Worst-case work: K × (Merkle-verify O(log N) + signature-verify). For
typical 3-of-5: 3 × (3 hashes + 1 Schnorr verify) = ~3 × 60 µs ≈ 180 µs.
Comparable to current MULTISIG.

### Limits

- `MAX_PUBKEYS_PER_MULTISIG = 1024` — bounds the inner Merkle tree to 10
  levels, MERKLE_PROOF to ≤320 bytes per signing position. Replaces
  the implicit cap that came from `MAX_FIELDS_PER_BLOCK = 16`.
- `MIN_THRESHOLD = 1`, `MAX_THRESHOLD = MAX_PUBKEYS_PER_MULTISIG`.

### Wire-format size table

| K-of-N    | Old conditions | New conditions | Old witness | New witness | Δ witness |
|----------:|---------------:|---------------:|------------:|------------:|----------:|
| 1-of-1    |   1 + 32 = 33 B |   1 + 32 = 33 B |    33 + 64 = 97 B  |    33 + 0 + 64 = 97 B    |   0 |
| 2-of-3    |   1 + 96 = 97 B |   1 + 32 = 33 B |   96 + 128 = 224 B |  2×(33 + 32 + 64) = 258 B | +34 |
| 3-of-5    |   1 + 160 = 161 B |   1 + 32 = 33 B |  160 + 192 = 352 B |  3×(33 + 96 + 64) = 579 B | +227 |
| 7-of-11   |   1 + 352 = 353 B |   1 + 32 = 33 B |  352 + 448 = 800 B |  7×(33 + 128 + 64) = 1575 B | +775 |
| 1-of-1024 |     would not fit |   1 + 32 = 33 B |          n/a       | 1×(33 + 320 + 64) = 417 B  |  n/a |

Conditions size strictly drops (always 33 B vs O(N)). Witness size
grows for K > 1 because each signing position carries a Merkle proof.
The growth is sublinear in N (`log N` per signer). The 1-of-1024 column
illustrates that the new format unlocks set sizes the old format
couldn't represent.

---

## 3. Implementation order

The order matters — each step should leave the tree compiling and the
existing test suite passing.

### Step 1: deserialiser + constants  (smallest possible PR)

`src/rung/serialize.h`: add `MAX_PUBKEYS_PER_MULTISIG = 1024`.
`src/rung/serialize.cpp`: extend the MULTISIG conditions parser to
accept the new shape (NUMERIC + HASH256), reject the legacy shape
(NUMERIC + N×PUBKEY) with a clear error.
`src/rung/conditions.cpp`: add `BuildPubkeyMerkleRoot()` and
`VerifyPubkeyMerkleProof()` helpers using
`TaggedHash("LadderMultisigPubkey/v1", …)` and
`TaggedHash("LadderMultisigInternal/v1", …)`.

Tests: extend `src/test/rung_tests.cpp` MULTISIG tests to verify both
parse paths and the helpers' round-trip. ~80 LOC of test code.

### Step 2: MERKLE_PROOF field type

`src/rung/types.h`: add `RungDataType::MERKLE_PROOF = 0x0C` (next
unused). Wire encoding: CompactSize depth, then `depth × 32` sibling
bytes.
`src/rung/serialize.cpp`: add deserialiser + cap (depth ≤ 10).
`src/rung/conditions.cpp`: mark MERKLE_PROOF as witness-only in
`IsConditionDataType`.

Tests: round-trip per depth 0..10, oversize rejection. ~40 LOC.

### Step 3: evaluator rewrite

`src/rung/blocks/sig.cpp::EvalMultisigBlock`: replace the K-of-N loop
with the new spec. Drop the early-break-on-first-valid-sig anti-pattern
that enabled the original bug.

Tests: K=1, K=K=N (all-sign), K<N happy path, K<N with one bad sig in
the K, K<N with one pubkey not in the set, duplicate-pubkey rejection,
oversize witness, MERKLE_PROOF tampering, PQ schemes parity (FALCON,
Dilithium, SPHINCS+). ~300 LOC of test code, exhaustive on the new
surface. Reuse fund/spend helpers from existing MULTISIG tests.

### Step 4: signing-side support

`src/rung/rpc.cpp::SignMultiKey`: rewrite. At fund time it computes
`pubkey_root` from the user-supplied N pubkeys and writes the new
conditions field shape. At spend time it generates K Merkle inclusion
proofs and signs each.

Tests: `signrungtx` test cases covering fund-then-spend round trip with
K=1, 2, 3, K=N, varying N up to 1024. Adds ~150 LOC.

### Step 5: descriptor parser

`src/rung/descriptor.cpp`: `multisig(K, @a, @b, @c, @d, @e)` parser
already exists. Update its codegen to emit the new conditions shape. No
changes to the descriptor *grammar* — purely an internal codegen swap.

Tests: descriptor round-trip for the existing `multisig(...)` examples.
Existing tests should pass after the codegen change. ~30 LOC of new
assertions.

### Step 6: deprecation notice on `pubkeys` array in signing API

`signrungtx` no longer needs the spender to enumerate all N pubkeys at
spend time — only the K signing keys. The `pubkeys` array becomes
optional (used only at fund time for root computation). Update the RPC
help text and the proxy.

### Step 7: BIP, docs, web, engine

- `doc/ladder-script/BIP-XXXX.md`: rewrite the MULTISIG entry under
  *Block registry* and the rationale subsection. Document that
  K<N is implemented via inner Merkle commitment — close the
  data-embedding loophole that motivates this design.
- `doc/ladder-script/BLOCK_LIBRARY.md`: same update.
- `tools/block-docs/multisig.html`: redraw the ladder diagram with the
  new field shape; update the worked example with a 3-of-5 walkthrough.
- `tools/comparison.html`: nothing to change (the MULTISIG comparison
  examples don't depend on the wire format).
- `tools/ladder-engine/`: update the MULTISIG block builder UI to
  collect N pubkeys + threshold and emit the new conditions shape.
- `proxy/ladder_proxy.py`: update the createrungtx / signrungtx
  endpoints to forward the new shape (probably no Python-side change
  needed if the RPC layer handles it).
- Live signet: chain reset is **not** required (no MULTISIG blocks have
  been deployed on the current signet so far per
  `MEASUREMENTS.md` — confirm before assuming).

### Step 8: regression

Run `feature_rung_tx.py`, `feature_rung_p2p.py`, the boost suite, and
the signet smoke test. Re-publish the demonstration script
`/tmp/embed-max.py` and verify it now fails at spend-time
(MULTISIG with 14 unused pubkeys should reject — no Merkle proofs
provided for the data slots).

---

## 4. New wire-format details

### Tagged-hash domain strings

Two new tags. Both versioned `/v1` per the project convention:

- `LadderMultisigPubkey/v1` — leaf hash of an N-set member
- `LadderMultisigInternal/v1` — interior pair hash for the pubkey tree

Both use the BIP-340 double-hash construction
`TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)`.

### MERKLE_PROOF wire encoding

```
[ CompactSize depth ]
[ depth × 32-byte sibling ]
```

The leaf side (this position) is implicit from the position-aligned
PUBKEY field. The root is the `pubkey_root` HASH256 from conditions.
At each level, the verifier reconstructs `TaggedHash(internal_tag,
min(current, sibling) || max(current, sibling))`.

### Padding and ordering

Inner Merkle tree pads to next power of two using
`MLSC_EMPTY_LEAF`. Construction-time leaf order is canonical and
defined by the funder; the verifier doesn't enforce any specific
ordering — it just checks inclusion. (Different orderings produce
different roots, so the funder's choice is effectively pinned by the
committed root.)

---

## 5. Test surface (concrete)

In `src/test/rung_tests.cpp`, group new test cases as `BOOST_FIXTURE_TEST_CASE`s
under a `multisig_inner_merkle` suite. Each case takes < 50 LOC.

| Case | Asserts |
|:--|:--|
| `multisig_v2_round_trip_1of1` | fund + spend, single-key MULTISIG (K = N = 1) |
| `multisig_v2_round_trip_2of3` | 2-of-3 with first 2 keys signing |
| `multisig_v2_round_trip_2of3_other_pair` | 2-of-3 with a different pair signing |
| `multisig_v2_round_trip_3of5` | 3-of-5 (the user's "lost-friend" scenario) |
| `multisig_v2_round_trip_kn_full` | K=N=11 (all-sign), regression for full multisig |
| `multisig_v2_round_trip_large_n` | 5-of-1024, exercises depth-10 proofs |
| `multisig_v2_reject_proof_tamper` | flip one sibling byte → UNSATISFIED |
| `multisig_v2_reject_pubkey_not_in_set` | reveal a pubkey not in the original N → UNSATISFIED |
| `multisig_v2_reject_duplicate_pubkey` | reveal the same pubkey twice in K → ERROR |
| `multisig_v2_reject_too_many_groups` | reveal K+1 groups → ERROR |
| `multisig_v2_reject_oversize_proof` | proof depth > 10 → ERROR at deserialise |
| `multisig_v2_pq_falcon` | K=2, N=3 with FALCON-512 keys |
| `multisig_v2_pq_dilithium` | K=2, N=3 with Dilithium3 keys |
| `multisig_v2_legacy_format_rejected` | old (NUMERIC + N×PUBKEY) parse → deserialiser ERROR |
| `multisig_v2_anti_embed_dat_pubkey_attack` | replay of the 2026-04-27 attack — must fail at spend |

The last case is the regression-anchor for the audit finding.

Functional test: extend `feature_rung_tx.py` with two cases — a happy
3-of-5 round trip and a re-run of the data-embedding attack to assert
rejection at the new spec. ~100 LOC of Python.

---

## 6. Rollout

The MULTISIG block has not been activated on mainnet (Ladder Script
itself is pre-activation, on signet only). Per
`SOFT_FORK_GUIDE.md` Phase 1 the live signet at `ladder-script.org`
carries every block type's fund + spend cycle, but no real users have
funded production MULTISIG outputs.

This is therefore **not a soft-fork-incompatible change**. We can ship
it in the same activation as the rest of Ladder Script. The wire
format is being revised before any real deployment.

For the live signet:

1. Land the code change (steps 1-7).
2. Tag a new release (`v30.0-ladder-0.5`).
3. Deploy to the seed node.
4. Reset the signet chain (`/home/ghost/.bitcoin/signet/{blocks,chainstate,...}`)
   so any prior test MULTISIG outputs from the old format are
   discarded. Wallet preserved.
5. Mine fresh blocks with the new binary; confirm the
   `feature_rung_tx.py` 3-of-5 case round-trips end-to-end.
6. Re-publish the data-embedding attack script and confirm it now
   fails at spend.

---

## 7. Risks and watch-outs

- **Tagged-hash domain collisions.** Two new tags (`LadderMultisigPubkey/v1`,
  `LadderMultisigInternal/v1`). They must NOT collide with the existing
  five tags (`LadderLeaf/v1`, `LadderInternal/v1`, `LadderSighash/v1`,
  `LadderKeyPathSighash/v1`, `LadderTweak/v1`). All-tag string-uniqueness
  is checked structurally (tags are different strings) so this is
  trivially safe — call out in the BIP for review clarity.

- **Field-type collision for MERKLE_PROOF.** The next free
  `RungDataType` enum value should be `0x0C`. Verify in `types.h`
  before assigning.

- **Padding the inner tree to next power of two.** N=5 pads to 8 with
  three `MLSC_EMPTY_LEAF`s. The funder must use `MLSC_EMPTY_LEAF`, not
  raw zero bytes — easy to get wrong. Add a unit test for N=5 and N=7
  that asserts the root matches a hand-computed expected value.

- **Spend-side bandwidth growth.** A 3-of-5 spend grows from ~352 B
  witness to ~580 B. A 7-of-11 grows from ~800 B to ~1,575 B.
  Document in the BIP rationale; this is the price of closing the
  embedding hole.

- **Wallet UX.** A wallet authorising a 3-of-5 spend now needs the
  inner Merkle inclusion proofs at spend time, which means it needs
  to know the original pubkey set. Most wallets keep that set in
  metadata anyway (it's part of the descriptor), so the impact is
  small.

- **Existing call sites that build MULTISIG witnesses.** Grep the tree
  for `RungBlockType::MULTISIG` and audit each construction site
  (RPC, descriptor, tests, engine). Each must learn the new format.

- **The audit's C-1 (qabo_sig_cache wiring) and the other landed fixes
  are independent of this change.** They stay.

---

## 8. Estimated effort

| Step | Files touched | LOC delta | Time |
|:--|:--|--:|:--|
| 1. Deserialiser + helpers | 3 | +120 | 1 h |
| 2. MERKLE_PROOF field type | 3 | +60 | 30 min |
| 3. Evaluator rewrite | 1 | +40 (net; replaces ~30) | 1 h |
| 4. Signing RPC | 1 | +200 (net; replaces ~80) | 2 h |
| 5. Descriptor parser | 1 | +30 | 30 min |
| 6. RPC help text + proxy | 2 | +20 | 30 min |
| 7. BIP, BLOCK_LIBRARY, block-doc, engine | ~6 | +200 | 2 h |
| 8. Tests (unit + functional) | 2 | +600 | 3 h |
| 9. Signet rollout | n/a | n/a | 30 min |
| **Total** | **~20 files** | **~+1,250 LOC** | **~11 h focused work** |

Net library line count change: roughly +800 LOC after replacements
(MULTISIG eval was ~80 LOC, signing was ~80 LOC; new versions are
larger). LIBRARY_LINES ticks up from 19,345 to ~20,150. Bulk-update
across the docs as a final pass.

---

## 9. Open question

Should the same inner-Merkle treatment be applied to **MUSIG_THRESHOLD**?
That block aggregates K signers' contributions into a single Schnorr
signature against an aggregated pubkey, so today it has only 1 PUBKEY
field on the wire — no slot for arbitrary data. The `pubkeys` array in
its signing spec is purely off-chain coordination input; it doesn't end
up in the witness. So MUSIG_THRESHOLD is not affected by the
data-embedding attack, and probably needs no change.

Sanity-check this by reading `EvalMusigThresholdBlock` before assuming
it's safe.

---

## 10. After this lands

- Refresh the audit notes (`~/audits/2026-04-26-adversarial-review.md`)
  with C-5 status: **closed**.
- Cut `v30.0-ladder-0.5` and publish.
- Update the BIP draft to reflect the redesigned MULTISIG.
- Write a follow-up blog/note: "Why we redesigned MULTISIG before
  shipping". Useful for credibility — shows the project responds to
  audit findings before they become deployed-and-stuck.
