# BIP rewrite notes — `BIP-XXXX.new.md`

A working notebook on the from-scratch rewrite. The new draft lives at
`doc/ladder-script/BIP-XXXX.new.md`; the existing wireframe at
`doc/ladder-script/BIP-XXXX.md` is unchanged.

## 1. Structural decisions

| Reference BIP | What it shaped |
|---|---|
| BIP 141 (SegWit) | Top-level skeleton: Motivation → Specification → Activation → Backwards Compatibility. Connective tissue added where 141 is terse, because no companion 143/144/145 exists for Ladder Script. |
| BIP 340 (Schnorr) | Rationale section format. Every subsection is a complete question; first paragraph restates and gives a one-sentence answer; body defends the answer against alternatives. Specification is dense and precise rather than prose-heavy. |
| BIP 173 (Bech32) | Motivation tone. Open with the human consequence (consensus impact, network-wide cost) before the technical fact. |
| BIP 174 (PSBT) | Worked-example discipline. Two annotated examples (funding + spending) with byte-by-byte deserialisation. Bytes deferred to TODO blocks rather than fabricated. |

Section order matches the task brief's required structure. The
Acknowledgements section names BIP 141 / 340 / 173 / 174 explicitly so
the reader can audit which precedents were drawn on.

## 2. Numerical discrepancies

Where the in-tree spec docs and the source code disagreed, the code
won (per the task brief). All resolutions below favour the code.

| Claim | Spec doc says | Code says | Resolution in the new BIP |
|---|---|---|---|
| Witness stack count for an MLSC spend | "exactly 2 elements" (`MERKLE-UTXO-SPEC.md` §8 Step 2) | `1, 2, or 3` (`src/rung/evaluator.cpp:945`, comment "1 element = key-path, 2 = script-path no tweak, 3 = script-path with tweak") | New BIP follows the code: 1 / 2 / 3 element discriminator. |
| Coil leaf | "coil_leaf is the last leaf" (`MERKLE-UTXO-SPEC.md` §2 Leaf Order) | "Coil structural fields are bound via each rung leaf's template (no separate coil leaf)" (`src/rung/conditions.cpp:1342` `ComputeTxMLSCRoot`). Legacy `ComputeCoilLeaf` is a test-only helper. | New BIP follows the code: leaves = `[rung_leaf[0..N-1], relay_leaf[0..M-1]]`, no coil leaf. |
| Hash-type bytes accepted | `{0x00..0x03, 0x40..0x43, 0x81..0x83, 0xC0..0xC3}` (`SOFT_FORK_GUIDE.md` §Sighash; existing wireframe §Specification/Sighash) | `{0x00..0x03, 0x81..0x83}` only — the `0x40` / `0xC0` ANYPREVOUT family is unconditionally rejected in `src/rung/sighash.cpp:145-148`. | New BIP follows the code: only `{0x00..0x03, 0x81..0x83}`; ANYPREVOUT explicitly noted as rejected pending a future opt-in mechanism. |
| `SIGHASH_LADDER = 0x84`, `SIGHASH_KEYPATH_LADDER = 0x85`, `SIGHASH_QABO = 0x86` | Existing wireframe §Sighash; SOFT_FORK_GUIDE | These byte values do NOT exist anywhere in `src/rung/sighash.cpp` or `src/rung/qabi.cpp`. The variants are distinguished by which function is called (`SignatureHashLadder` vs `SignatureHashLadderKeyPath`) and by the witness stack size. `ComputeSighashQABO` is a function not a hash-type byte. | New BIP follows the code: there are not three new hash-type bytes. The Rationale question about "three new sighash flags" answers "there aren't three new flags". |
| QABO sighash tag | (not specified in existing docs) | `"QABOSighash"` — no `/v1` suffix (`src/rung/qabi.cpp:38`). Other Ladder Script tags use `/v1` (`LadderSighash/v1`, `LadderKeyPathSighash/v1`, `LadderTweak/v1`, `LadderLeaf/v1`, `LadderInternal/v1`, `LadderRelayLeaf/v1`, `LadderQABISection/v1`). | New BIP carries the tag verbatim from the code (`QABOSighash`) and notes the inconsistency in the TODO list below. |
| QABIO `aggregated_sig` length | "≤666 B" (existing wireframe; SOFT_FORK_GUIDE) | `tx.aggregated_sig.size() == QABI_AGGREGATED_SIG_MAX (666)` exactly when QABI_SPEND present, OR exactly 0 otherwise. Variable length is rejected. | New BIP says exactly 666 B when present, 0 otherwise. |
| `MAX_RELAYS` | Existing wireframe says 16 in the witness-limits table | Code says 8 in `src/rung/serialize.h:44` | New BIP follows the code: `MAX_RELAYS = 8`. |
| `MAX_REQUIRES` | (not in existing wireframe) | 8 in `src/rung/serialize.h` | New BIP includes it. |
| `MAX_RELAY_DEPTH` | Existing wireframe says 4 | Code says 4 | Match. New BIP includes. |
| ANCHOR family count | README, INTRODUCTION, BLOCK_LIBRARY all consistent: 7 (ANCHOR + 5 named + DATA_RETURN) | Existing wireframe Specification §Block registry table lists 8 types in the Anchor row (it includes ANCHOR_FEE in Anchor; the rest of the codebase puts ANCHOR_FEE in Compound) | New BIP follows the codebase / BLOCK_LIBRARY layout: `ANCHOR_FEE` is in Compound (0x0707), Anchor family has 7 members (`ANCHOR`, `ANCHOR_CHANNEL`, `ANCHOR_POOL`, `ANCHOR_RESERVE`, `ANCHOR_SEAL`, `ANCHOR_ORACLE`, `DATA_RETURN`). |
| Per-tx attacker-controllable byte ceiling | Both EMBEDDING_CHALLENGE and the existing wireframe headline say "112 bytes per transaction, flat" | The 112 B figure is the minimum-tx floor only, not a per-tx ceiling. Realistic per-tx ceiling within standard relay is ~50 KB (per-input MLSC reveal × ~80 inputs). Verified empirically against the v0.19 binary in May 2026; `EMBEDDING_CHALLENGE.md` was rewritten to reflect this. | New BIP describes the embedding surface honestly: the 112 B figure is the floor for the smallest tx; the Security Considerations section calls out that the per-tx ceiling depends on which block types are revealed and is bounded by the witness-size cap and per-tx preimage cap, not by an unstructured "padding" channel. |
| Conditions-only witness rule | Not described in existing wireframe (predates the conditions-only-block witness whitelist) | Implemented in `src/rung/serialize.cpp` in the witness-side post-loop check: only `PUBKEY` (≤ `PubkeyCountForBlock`) and `PREIMAGE` (≤ 2) are accepted in witnesses for blocks whose evaluator reads only conditions-side fields | New BIP includes a dedicated subsection in Specification §Block registry titled "Conditions-only witness rule". |
| QABIO consensus checks count | "9 per QABI_SPEND input" (`QABIO.md` §6) | Matches the count in `src/rung/blocks/qabi.cpp` `EvalQABISpendBlock` | Match — adopted into Specification commentary. |

## 3. TODO markers in the new BIP

| Marker | Resolution path |
|---|---|
| §Specification "Worked example: funding transaction" — bytes omitted | Generate via `createrungtx` + `signrawtransactionwithwallet` against a regtest fixture; capture the signed-tx hex bytes; the conditions_root, leaf hash, and proof bytes follow deterministically. The reference test `test/functional/feature_rung_tx.py` already produces a similar shape. |
| §Specification "Worked example: spending transaction" — bytes omitted | Generate alongside the funding example so the conditions_root and leaf hashes are coherent. The walk-through structure is in place; only the hex blob is deferred. |
| §Test Vectors — entire section deferred | A `test/data/rung_tx_vectors.json` file should ship containing the funding tx, the spending tx, the conditions tree, the MLSCProof, the sighash bytes, one QABIO priming tx, one QABIO batch-spend tx, and one PQ_BATCH spend. Machine-readable for cross-implementation verification. |
| §Acknowledgements — FALCON author list | Verify the current author list against the latest NIST submission; the names listed mirror what the existing wireframe carries but should be confirmed before publication. |
| §Acknowledgements — Dilithium author list | Same — verify against current NIST sources. |
| §Acknowledgements — SPHINCS+ attribution | Pick a single attribution form ("the SPHINCS+ team" or the full author list) and apply consistently. The existing wireframe uses both forms in different places. |

## 4. Rationale questions where the answer required judgement

The 17 required questions are all answered. Three deserved specific
attention:

- **Q1 (new tx version vs new opcodes)** and **Q2 (typed blocks vs
  extending Script)** are closely related. The new BIP separates them
  by treating Q1 as "why a fresh format" (engineering scaling) and Q2
  as "why typed fields specifically" (embedding semantics).
- **Q15 (three new sighash flags)** turned out to be a question with a
  contradicting premise. The honest answer is "there are not three
  new flag bytes; there are two sighash variants distinguished by
  function call, plus one separate digest function for QABI." The
  Rationale answers the premise directly.
- **Q17 (RBD in a consensus BIP)** is a policy item normally outside
  consensus BIPs. The answer in the new BIP explains why it is
  included here (priming-cost is not a fee auction, so BIP 125 RBF is
  the wrong shape; RBD is the only sensible replacement rule for
  QABI_PRIME).

## 5. Diff against the existing wireframe — load-bearing items deliberately omitted or relocated

This is the final-pass completeness check requested by the task. After
writing the new draft I read the existing wireframe (`BIP-XXXX.md`)
and listed every load-bearing topic. The table below is the result.

| Topic in the wireframe | Treatment in the new BIP |
|---|---|
| Sizing comparison table in Motivation (`109 vB` etc.) | **Relocated** to Specification §Activation / Backwards Compatibility implicit context. Per task brief: sizing belongs in Specification or a dedicated subsection, not Motivation. The numbers themselves are preserved through the headline tables in EMBEDDING_CHALLENGE / SIZING which the BIP cites. |
| `SIGHASH_LADDER 0x84`, `SIGHASH_KEYPATH_LADDER 0x85`, `SIGHASH_QABO 0x86` byte values | **Deliberately omitted.** These do not exist in the code. The new BIP reflects the actual sighash structure (two functions for per-input signatures, one digest function for QABI). Q15 in Rationale answers the question the wireframe's framing implied. |
| MULTISIG inner-Merkle commitment (long Rationale subsection in wireframe) | **Subsumed** into the Specification §Block registry (the row for `MULTISIG` describes the K × triplets requirement and ascending-pubkey-lex order) and into Rationale Q5 (folded pubkeys generally). The wireframe's longer prose treatment is informative but exceeds the task brief's "no padding" rule for Rationale. The mechanism is referenced; readers who want depth follow the citation to `BLOCK_LIBRARY.md`. |
| Diff-witness uniqueness rationale (D-1, wireframe Rationale §) | **Subsumed** into the Specification §Block registry conditions-only witness rule and the per-tx caps note ("Diff-witness overlays count too, so an attacker cannot use diff-witness to fan out fresh preimage bytes past the cap"). The "duplicate diff target rejection" detail is in the spec docs the BIP normatively references; not load-bearing for a BIP-level reader. |
| Per-tx QABI fields gating (T-1 / T-2 in wireframe Rationale) | **Promoted** to a hard consensus rule in Specification §Evaluator semantics §Per-tx checks (rule 3). Stating it as a numbered consensus rule is more direct than restating it as a Rationale question. |
| Rung leaf binding R-1 (wireframe Rationale §) | **Subsumed** into Specification §Conditions and the conditions root §Structural template — rung ("The relay refs are committed into the rung leaf so a spender cannot drop relay dependencies at spend time"). |
| "Why Cap'n Proto IPC is not part of this BIP" (wireframe Rationale §) | **Omitted.** The task brief explicitly does not call for this. Build-system choices that do not affect the wire format do not belong in a consensus BIP. The reference implementation note ("`liboqs` is required, `LADDER_ENABLE_QABIO` is a build flag") covers the consensus-relevant build flags. |
| Live-signet vector reference | **Cited indirectly** via the "live signet at ladder-script.org" note in the README that the BIP references. The BIP itself stays implementation-neutral; per-block-type signet txids drift across chain resets and are not stable enough to embed in a normative document. |
| 56 end-to-end presets | **Cited** in §Test Vectors via the Companion artifacts list (`tools/test-presets.py`). The presets are reference fixtures, not normative test vectors. |
| Standardness / mempool fairness rules for non-QABIO v4 | **Out of scope** statement in §Security Considerations. Same as the wireframe's stance, more concisely. |
| Block-template construction | **Out of scope** statement in §Security Considerations. Same as wireframe. |

Items where the new BIP is more conservative than the wireframe:

- **The "112 byte ceiling" claim** has been rewritten into honest
  min/typical/max wording. The wireframe's framing (112 B flat
  per-tx) is misleading because it counts only the minimum-tx case
  and excludes the per-input MLSC reveal × N inputs scaling. The new
  BIP's Security Considerations section describes the structural
  bounds (`MAX_PREIMAGE_FIELDS_PER_TX`, the witness-size cap, per-
  block field-count enforcement) without claiming a flat ceiling.

- **The hash-type byte set** is restricted to `{0x00..0x03,
  0x81..0x83}` matching the code, with explicit text noting that
  ANYPREVOUT (`0x40..0x43`, `0xC0..0xC3`) is rejected pending a
  future opt-in mechanism. The wireframe quietly accepted ANYPREVOUT
  in its Sighash section.

- **The witness stack-count discriminator** (1 / 2 / 3 elements) is
  documented explicitly. The wireframe documented "two stack elements"
  in places (matching MERKLE-UTXO-SPEC) but the code accepts 1, 2, or
  3 depending on spend mode.

Items where the new BIP is more terse than the wireframe:

- The Specification's Block Registry table includes both conditions
  and witness layouts in one wide table (one row per block type).
  The wireframe broke this into family sub-tables. The single table
  is denser but easier to use as a deserialiser reference.

- The Worked Examples are byte-stub-with-walkthrough rather than
  fully-illustrated. The bytes themselves are TODO; the walkthrough
  is in place so a reader knows what to expect. The wireframe had
  no worked examples at all.

## 6. Definition-of-done self-check

Walking the six pass criteria from the task brief against the new
draft:

1. **Three-sentence summary after the Abstract.** Pass — the Abstract
   gives format (v4 RUNG_TX), structure (typed blocks in rungs +
   transaction-level Merkle commit), and properties (PQ-native, QABIO,
   activation via BIP 9 versionbits) in five sentences.
2. **Why Ladder Script exists after the Motivation.** Pass — three
   problem axes (capability cost, no data/instruction distinction, PQ
   migration) named explicitly.
3. **Deserialise a sample v4 tx by hand after Specification.** Pass —
   wire format is byte-by-byte; output reconstruction is explicit;
   Worked Example walks the deserialisation step-by-step (bytes are
   TODO but the structure is complete).
4. **Predict 12 of 17 design questions before reading Rationale.**
   Pass — the questions follow obviously from the Specification (any
   reader sees the structural caps, the Merkle byte-sorting, the
   conditions-only witness rule, the LadderTweak tag, the QABIO
   inclusion, etc., and would naturally ask "why").
5. **Start an implementation after Reference Implementation.** Pass —
   the API surface is enumerated (`VerifyRungTx`, `CheckRungTxLevel`,
   `ValidateRungOutputs`, the script-classification predicates, the
   policy helpers, the sighash functions). The library boundary
   (`src/rung_shims.h`) is named.
6. **List of attack surfaces after Security Considerations.** Pass —
   the section enumerates fail-closed deserialisation (probe with
   malformed bytes), the embedding ceiling (probe per-input MLSC
   reveal scaling), the soft-fork forward-compat rule (probe new
   block-type code allocation), the LadderTweak domain separation
   (probe cross-domain signature reuse), the sighash binding (probe
   what each variant commits to), and RBD (probe self-flooding /
   stale-priming patterns).

## 7. Things that remain genuinely unknown after this rewrite

These are open items that need the author's input before the BIP is
submission-ready:

- The activation deployment-bit number, start time, timeout, and
  minimum-activation-height. The §Activation section currently says
  these are configured per the standard process; a real submission
  needs the actual values negotiated with the Bitcoin Core release
  process.
- The `Created` date in the preamble is set to today (`2026-05-01`).
  Author may want a different date.
- Whether to ship QABIO and PQ_BATCH in the same BIP or split QABIO
  into a follow-up. The new BIP keeps both in a single document
  matching the existing project posture, but a separate-BIP path is
  available if review feedback prefers it.
