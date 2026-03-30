------------------------- MODULE BlockHash -------------------------
(***************************************************************************)
(* Model of the hash family block types:                                   *)
(*   - TAGGED_HASH (0x0203): BIP-340 tagged hash verification             *)
(*   - HASH_GUARDED (0x0204): Raw SHA256 preimage verification            *)
(*                                                                         *)
(* TAGGED_HASH: domain-separated hash.                                     *)
(*   Conditions: 2× HASH256 (tag_hash, expected_hash).                    *)
(*   Witness: 2× HASH256 (tag_hash, expected_hash) + PREIMAGE.            *)
(*   Verifies: SHA256(SHA256(tag) || SHA256(tag) || preimage) == expected. *)
(*   Tag in witness must match tag in conditions.                          *)
(*   Invertible.                                                           *)
(*                                                                         *)
(* HASH_GUARDED: raw SHA256 preimage check.                                *)
(*   Conditions: HASH256 (expected_hash).                                  *)
(*   Witness: PREIMAGE.                                                    *)
(*   Verifies: SHA256(preimage) == expected_hash.                          *)
(*   NOT invertible (inverted → ERROR).                                    *)
(*                                                                         *)
(* Both consume a PREIMAGE field (counted toward MAX_PREIMAGE_FIELDS_PER_TX) *)
(* and fail-closed without witness data.                                   *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

CONSTANTS
    MaxHashValues   \* e.g. 5; VPS: MaxHashValues = 10

HashValues == 1..MaxHashValues

(***************************************************************************)
(* TAGGED_HASH evaluation                                                  *)
(***************************************************************************)

\* Conditions set at fund time
TaggedHashConditions == [
    cond_tag:      HashValues,   \* SHA256(tag) committed in conditions
    cond_expected: HashValues    \* expected hash committed in conditions
]

\* Witness provided at spend time
TaggedHashWitness == [
    has_witness:  BOOLEAN,
    wit_tag:      HashValues,    \* tag echoed in witness (must match cond_tag)
    preimage:     HashValues     \* raw preimage
]

\* Abstract hash model: SHA256(tag || tag || preimage) mapped to a value.
\* Match iff TaggedHash(tag, preimage) == expected.
\* We model this as: matching when (tag, preimage) is the pair that
\* produces expected.  In the abstract model the "correct" preimage
\* for a given (tag, expected) is simply: tag = cond_tag, preimage = expected.
\* Any other preimage value is wrong.
TaggedHashComputed(tag, preimage) == tag + preimage

EvalTaggedHash(cond, wit) ==
    IF ~wit.has_witness THEN "ERROR"
    \* Tag in witness must match tag in conditions
    ELSE IF wit.wit_tag # cond.cond_tag THEN "UNSATISFIED"
    \* Verify: TaggedHash(tag, preimage) == expected
    ELSE IF TaggedHashComputed(cond.cond_tag, wit.preimage) = cond.cond_expected
         THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* HASH_GUARDED evaluation                                                 *)
(***************************************************************************)

\* Conditions set at fund time
HashGuardedConditions == [
    expected: HashValues   \* committed SHA256 hash
]

\* Witness provided at spend time
HashGuardedWitness == [
    has_witness: BOOLEAN,
    preimage:    HashValues   \* raw preimage
]

\* Abstract hash: SHA256(preimage).  Match iff preimage is the value
\* whose hash equals expected.  Modelled as: SHA256(preimage) == preimage.
HashGuardedComputed(preimage) == preimage

EvalHashGuarded(cond, wit) ==
    IF ~wit.has_witness THEN "ERROR"
    ELSE IF HashGuardedComputed(wit.preimage) = cond.expected
         THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* Inversion logic (ApplyInversion from evaluator.cpp)                     *)
(***************************************************************************)

ApplyInversion(raw) ==
    IF raw = "SATISFIED" THEN "UNSATISFIED"
    ELSE IF raw = "UNSATISFIED" THEN "SATISFIED"
    ELSE raw   \* ERROR never flips

(***************************************************************************)
(* Block type enum                                                         *)
(***************************************************************************)

BlockTypes == {"TAGGED_HASH", "HASH_GUARDED"}

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    block_type,
    th_cond, th_wit,
    hg_cond, hg_wit,
    inverted,
    result, phase

vars == <<block_type, th_cond, th_wit, hg_cond, hg_wit, inverted, result, phase>>

Init ==
    /\ block_type \in BlockTypes
    /\ th_cond \in TaggedHashConditions
    /\ th_wit \in TaggedHashWitness
    /\ hg_cond \in HashGuardedConditions
    /\ hg_wit \in HashGuardedWitness
    /\ inverted \in BOOLEAN
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' =
        LET raw ==
            IF block_type = "TAGGED_HASH" THEN EvalTaggedHash(th_cond, th_wit)
            ELSE EvalHashGuarded(hg_cond, hg_wit)
        IN
        \* Non-invertible block types ERROR when inverted
        IF inverted /\ block_type = "HASH_GUARDED" THEN "ERROR"
        ELSE IF inverted THEN ApplyInversion(raw)
        ELSE raw
    /\ phase' = "done"
    /\ UNCHANGED <<block_type, th_cond, th_wit, hg_cond, hg_wit, inverted>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: TAGGED_HASH with matching preimage → SATISFIED
Inv_TaggedHash_MatchSatisfied ==
    (phase = "done"
     /\ block_type = "TAGGED_HASH"
     /\ ~inverted
     /\ th_wit.has_witness
     /\ th_wit.wit_tag = th_cond.cond_tag
     /\ TaggedHashComputed(th_cond.cond_tag, th_wit.preimage) = th_cond.cond_expected)
    => result = "SATISFIED"

\* I2: TAGGED_HASH with wrong preimage → UNSATISFIED
Inv_TaggedHash_WrongPreimage ==
    (phase = "done"
     /\ block_type = "TAGGED_HASH"
     /\ ~inverted
     /\ th_wit.has_witness
     /\ th_wit.wit_tag = th_cond.cond_tag
     /\ TaggedHashComputed(th_cond.cond_tag, th_wit.preimage) # th_cond.cond_expected)
    => result = "UNSATISFIED"

\* I3: TAGGED_HASH with mismatched tag (conditions vs witness) → UNSATISFIED
Inv_TaggedHash_TagMismatch ==
    (phase = "done"
     /\ block_type = "TAGGED_HASH"
     /\ ~inverted
     /\ th_wit.has_witness
     /\ th_wit.wit_tag # th_cond.cond_tag)
    => result = "UNSATISFIED"

\* I4: TAGGED_HASH is invertible (inversion flips result)
Inv_TaggedHash_Invertible ==
    (phase = "done"
     /\ block_type = "TAGGED_HASH"
     /\ inverted
     /\ th_wit.has_witness
     /\ th_wit.wit_tag = th_cond.cond_tag
     /\ TaggedHashComputed(th_cond.cond_tag, th_wit.preimage) = th_cond.cond_expected)
    => result = "UNSATISFIED"

\* I5: HASH_GUARDED with matching preimage → SATISFIED
Inv_HashGuarded_MatchSatisfied ==
    (phase = "done"
     /\ block_type = "HASH_GUARDED"
     /\ ~inverted
     /\ hg_wit.has_witness
     /\ HashGuardedComputed(hg_wit.preimage) = hg_cond.expected)
    => result = "SATISFIED"

\* I6: HASH_GUARDED with wrong preimage → UNSATISFIED
Inv_HashGuarded_WrongPreimage ==
    (phase = "done"
     /\ block_type = "HASH_GUARDED"
     /\ ~inverted
     /\ hg_wit.has_witness
     /\ HashGuardedComputed(hg_wit.preimage) # hg_cond.expected)
    => result = "UNSATISFIED"

\* I7: HASH_GUARDED is NOT invertible (inverted → ERROR)
Inv_HashGuarded_NotInvertible ==
    (phase = "done"
     /\ block_type = "HASH_GUARDED"
     /\ inverted)
    => result = "ERROR"

\* I8: Missing witness → ERROR
Inv_MissingWitnessError ==
    (phase = "done"
     /\ ((block_type = "TAGGED_HASH" /\ ~th_wit.has_witness /\ ~inverted)
         \/ (block_type = "HASH_GUARDED" /\ ~hg_wit.has_witness /\ ~inverted)))
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_TaggedHash_MatchSatisfied
    /\ Inv_TaggedHash_WrongPreimage
    /\ Inv_TaggedHash_TagMismatch
    /\ Inv_TaggedHash_Invertible
    /\ Inv_HashGuarded_MatchSatisfied
    /\ Inv_HashGuarded_WrongPreimage
    /\ Inv_HashGuarded_NotInvertible
    /\ Inv_MissingWitnessError

=============================================================================
