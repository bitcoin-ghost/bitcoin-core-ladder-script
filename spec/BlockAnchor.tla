------------------------- MODULE BlockAnchor -------------------------
(***************************************************************************)
(* Model of the anchor / L2 family block types:                            *)
(*   0x0501 ANCHOR           - Generic anchor (non-empty fields)           *)
(*   0x0502 ANCHOR_CHANNEL   - Lightning channel (2 pubkeys + commitment)  *)
(*   0x0503 ANCHOR_POOL      - VTXO tree (hash-preimage binding)           *)
(*   0x0504 ANCHOR_RESERVE   - Reserve (threshold + guardian hash binding)  *)
(*   0x0505 ANCHOR_SEAL      - Seal (asset_id + state transition hashes)   *)
(*   0x0506 ANCHOR_ORACLE    - Oracle (pubkey + outcome_count)             *)
(*   0x0507 DATA_RETURN      - Unspendable data commitment (always ERROR)  *)
(*   0x0707 ANCHOR_FEE       - Anti-pinning (modeled separately)           *)
(*                                                                         *)
(* Invertibility: ANCHOR, POOL, RESERVE, SEAL, DATA_RETURN are invertible. *)
(* CHANNEL and ORACLE are key-consuming and NOT invertible.                *)
(* Hash-preimage binding: each HASH256 needs a matching PREIMAGE.          *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

CONSTANTS
    MaxFields,        \* e.g. 3 (VPS: 8)
    MaxCommitment     \* e.g. 3 (VPS: 100)

FieldCounts == 0..MaxFields
CommitmentNums == 0..MaxCommitment

(***************************************************************************)
(* Block types                                                             *)
(***************************************************************************)

BlockTypes == {
    "ANCHOR", "ANCHOR_CHANNEL", "ANCHOR_POOL",
    "ANCHOR_RESERVE", "ANCHOR_SEAL", "ANCHOR_ORACLE",
    "DATA_RETURN"
}

IsInvertible(btype) ==
    btype \in {"ANCHOR", "ANCHOR_POOL", "ANCHOR_RESERVE",
               "ANCHOR_SEAL", "DATA_RETURN"}

(***************************************************************************)
(* Block parameters                                                        *)
(***************************************************************************)

\* Generic block with all possible fields abstracted
BlockParams == [
    btype: BlockTypes,
    num_fields: FieldCounts,                \* total typed fields present
    num_pubkeys: FieldCounts,               \* PUBKEY fields present
    num_hashes: FieldCounts,                \* HASH256 fields present
    num_preimages: FieldCounts,             \* PREIMAGE fields present
    commitment_number: CommitmentNums,      \* NUMERIC: commitment / outcome_count
    hash_binding_valid: BOOLEAN,            \* SHA256(preimage_i) == hash_i for all i
    threshold_n: CommitmentNums,            \* ANCHOR_RESERVE: threshold N
    threshold_m: CommitmentNums,            \* ANCHOR_RESERVE: threshold M
    data_size: FieldCounts,                 \* DATA_RETURN: data payload size (≤ 32)
    inverted: BOOLEAN                       \* block has the inverted flag
]

(***************************************************************************)
(* Hash-preimage binding check (VerifyHashPreimageBinding)                  *)
(***************************************************************************)

\* Binding passes when: no hashes, or enough preimages AND all match
HashPreimageOK(bp) ==
    IF bp.num_hashes = 0 THEN TRUE
    ELSE bp.num_preimages >= bp.num_hashes /\ bp.hash_binding_valid

(***************************************************************************)
(* Per-type evaluators (raw result before inversion)                        *)
(***************************************************************************)

EvalAnchor(bp) ==
    IF bp.num_fields = 0 THEN "ERROR"
    ELSE "SATISFIED"

EvalAnchorChannel(bp) ==
    \* Requires 2 valid pubkeys
    IF bp.num_pubkeys < 2 THEN "ERROR"
    \* commitment_number must be > 0 (when present, always present in model)
    ELSE IF bp.commitment_number = 0 THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalAnchorPool(bp) ==
    \* Requires at least 1 HASH256
    IF bp.num_hashes < 1 THEN "ERROR"
    \* Hash binding must verify
    ELSE IF ~HashPreimageOK(bp) THEN "UNSATISFIED"
    \* Optional NUMERIC count > 0
    ELSE IF bp.commitment_number = 0 THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalAnchorReserve(bp) ==
    \* Requires 2 NUMERICs (threshold_n, threshold_m) + 1 HASH256
    IF bp.num_hashes < 1 THEN "ERROR"
    \* Hash binding must verify
    ELSE IF ~HashPreimageOK(bp) THEN "UNSATISFIED"
    \* threshold_n <= threshold_m, both >= 0 (0 means no valid threshold)
    ELSE IF bp.threshold_n > bp.threshold_m THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalAnchorSeal(bp) ==
    \* Requires 2 HASH256 fields (asset_id + state_transition)
    IF bp.num_hashes < 2 THEN "ERROR"
    \* Hash binding must verify
    ELSE IF ~HashPreimageOK(bp) THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalAnchorOracle(bp) ==
    \* Requires 1 valid pubkey
    IF bp.num_pubkeys < 1 THEN "ERROR"
    \* outcome_count > 0
    ELSE IF bp.commitment_number = 0 THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalDataReturn ==
    \* Always ERROR — output is unspendable (evaluator.cpp line 3236)
    "ERROR"

(***************************************************************************)
(* Dispatch raw evaluation                                                 *)
(***************************************************************************)

EvalRaw(bp) ==
    CASE bp.btype = "ANCHOR"         -> EvalAnchor(bp)
      [] bp.btype = "ANCHOR_CHANNEL" -> EvalAnchorChannel(bp)
      [] bp.btype = "ANCHOR_POOL"    -> EvalAnchorPool(bp)
      [] bp.btype = "ANCHOR_RESERVE" -> EvalAnchorReserve(bp)
      [] bp.btype = "ANCHOR_SEAL"    -> EvalAnchorSeal(bp)
      [] bp.btype = "ANCHOR_ORACLE"  -> EvalAnchorOracle(bp)
      [] bp.btype = "DATA_RETURN"    -> EvalDataReturn

(***************************************************************************)
(* Inversion logic (ApplyInversion)                                        *)
(***************************************************************************)

ApplyInversion(raw, inv) ==
    IF ~inv THEN raw
    ELSE CASE raw = "SATISFIED"   -> "UNSATISFIED"
           [] raw = "UNSATISFIED" -> "SATISFIED"
           [] raw = "ERROR"       -> "ERROR"

(***************************************************************************)
(* Full evaluation: inversion guard + raw + apply                          *)
(***************************************************************************)

EvalBlock(bp) ==
    \* Non-invertible types with inverted flag → ERROR
    IF bp.inverted /\ ~IsInvertible(bp.btype) THEN "ERROR"
    ELSE ApplyInversion(EvalRaw(bp), bp.inverted)

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES bp, result, phase

vars == <<bp, result, phase>>

Init ==
    /\ bp \in BlockParams
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalBlock(bp)
    /\ phase' = "done"
    /\ UNCHANGED <<bp>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: ANCHOR with non-empty fields → SATISFIED
Inv_AnchorSatisfied ==
    (phase = "done" /\ bp.btype = "ANCHOR"
     /\ bp.num_fields > 0 /\ ~bp.inverted)
    => result = "SATISFIED"

\* I2: ANCHOR_CHANNEL with 2 valid pubkeys + positive commitment → SATISFIED
Inv_ChannelSatisfied ==
    (phase = "done" /\ bp.btype = "ANCHOR_CHANNEL"
     /\ bp.num_pubkeys >= 2 /\ bp.commitment_number > 0
     /\ ~bp.inverted)
    => result = "SATISFIED"

\* I3: ANCHOR_CHANNEL missing pubkey → ERROR
Inv_ChannelNoPubkeyError ==
    (phase = "done" /\ bp.btype = "ANCHOR_CHANNEL"
     /\ bp.num_pubkeys < 2 /\ ~bp.inverted)
    => result = "ERROR"

\* I4: ANCHOR_POOL with hash-preimage binding → SATISFIED
Inv_PoolBoundSatisfied ==
    (phase = "done" /\ bp.btype = "ANCHOR_POOL"
     /\ bp.num_hashes >= 1 /\ HashPreimageOK(bp)
     /\ bp.commitment_number > 0
     /\ ~bp.inverted)
    => result = "SATISFIED"

\* I5: ANCHOR_POOL without binding → UNSATISFIED
Inv_PoolUnbound ==
    (phase = "done" /\ bp.btype = "ANCHOR_POOL"
     /\ bp.num_hashes >= 1 /\ ~HashPreimageOK(bp)
     /\ ~bp.inverted)
    => result = "UNSATISFIED"

\* I6: ANCHOR_RESERVE with threshold > 0 + guardian hash → SATISFIED
Inv_ReserveSatisfied ==
    (phase = "done" /\ bp.btype = "ANCHOR_RESERVE"
     /\ bp.num_hashes >= 1 /\ HashPreimageOK(bp)
     /\ bp.threshold_n <= bp.threshold_m
     /\ ~bp.inverted)
    => result = "SATISFIED"

\* I7: ANCHOR_ORACLE with pubkey + positive outcome_count → SATISFIED
Inv_OracleSatisfied ==
    (phase = "done" /\ bp.btype = "ANCHOR_ORACLE"
     /\ bp.num_pubkeys >= 1 /\ bp.commitment_number > 0
     /\ ~bp.inverted)
    => result = "SATISFIED"

\* I8: DATA_RETURN always ERROR (unspendable)
Inv_DataReturnError ==
    (phase = "done" /\ bp.btype = "DATA_RETURN"
     /\ ~bp.inverted)
    => result = "ERROR"

\* I9: Non-invertible types (CHANNEL, ORACLE) with inverted → ERROR
Inv_NonInvertibleError ==
    (phase = "done" /\ bp.inverted /\ ~IsInvertible(bp.btype))
    => result = "ERROR"

\* I10: Invertible types inversion flips result (except ERROR stays ERROR)
\* For invertible types: if raw is SATISFIED, inverted gives UNSATISFIED and vice versa.
\* ERROR remains ERROR even when inverted.
Inv_InversionFlips ==
    (phase = "done" /\ bp.inverted /\ IsInvertible(bp.btype))
    => \/ (EvalRaw(bp) = "SATISFIED"   /\ result = "UNSATISFIED")
       \/ (EvalRaw(bp) = "UNSATISFIED" /\ result = "SATISFIED")
       \/ (EvalRaw(bp) = "ERROR"       /\ result = "ERROR")

SafetyInvariant ==
    /\ Inv_AnchorSatisfied
    /\ Inv_ChannelSatisfied
    /\ Inv_ChannelNoPubkeyError
    /\ Inv_PoolBoundSatisfied
    /\ Inv_PoolUnbound
    /\ Inv_ReserveSatisfied
    /\ Inv_OracleSatisfied
    /\ Inv_DataReturnError
    /\ Inv_NonInvertibleError
    /\ Inv_InversionFlips

=============================================================================
