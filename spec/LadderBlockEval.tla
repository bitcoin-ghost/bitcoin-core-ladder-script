------------------------ MODULE LadderBlockEval ------------------------
(***************************************************************************)
(* Model the evaluation semantics for each block family in Ladder Script. *)
(* Covers structural rules: required fields, field validity, and external *)
(* condition satisfaction for all 9 block types.                          *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Block types and evaluation results                                      *)
(***************************************************************************)

BlockTypes == {
    "SIG", "CSV", "CLTV", "HASH_GUARDED", "AMOUNT_LOCK",
    "OUTPUT_CHECK", "CTV", "COSIGN", "MULTISIG"
}

EvalResults == {"SATISFIED", "UNSATISFIED", "ERROR"}

(***************************************************************************)
(* Block evaluation function                                               *)
(* fields_present: are all required fields present?                        *)
(* fields_valid: are field values structurally valid? (e.g. min <= max)    *)
(* ext_met: is the external condition satisfied?                           *)
(***************************************************************************)

EvalBlock(btype, fields_present, fields_valid, ext_met) ==
    CASE btype = "SIG" ->
        \* Requires SCHEME + PUBKEY + SIGNATURE. Returns SATISFIED iff sig valid.
        IF ~fields_present THEN "ERROR"
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "CSV" ->
        \* Requires NUMERIC(sequence). SATISFIED iff input sequence >= committed.
        IF ~fields_present THEN "ERROR"
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "CLTV" ->
        \* Requires NUMERIC(height). SATISFIED iff tx locktime >= committed.
        IF ~fields_present THEN "ERROR"
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "HASH_GUARDED" ->
        \* Requires HASH256(commitment) in conditions, PREIMAGE in witness.
        \* SATISFIED iff SHA256(preimage) == commitment.
        IF ~fields_present THEN "ERROR"
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "AMOUNT_LOCK" ->
        \* Requires NUMERIC(min), NUMERIC(max). SATISFIED iff min <= amount <= max.
        \* ERROR if min > max or fields missing.
        IF ~fields_present THEN "ERROR"
        ELSE IF ~fields_valid THEN "ERROR"  \* min > max
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "OUTPUT_CHECK" ->
        \* Requires NUMERIC(idx), NUMERIC(min), NUMERIC(max), HASH256(script_hash).
        \* SATISFIED iff output exists, value in range, script matches.
        \* Index out of bounds → UNSATISFIED (not ERROR).
        IF ~fields_present THEN "ERROR"
        ELSE IF ~fields_valid THEN "UNSATISFIED"  \* index out of bounds
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "CTV" ->
        \* Requires HASH256(template). SATISFIED iff tx matches template.
        IF ~fields_present THEN "ERROR"
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "COSIGN" ->
        \* Requires HASH256(spk_hash). SATISFIED iff another input's SPK matches.
        IF ~fields_present THEN "ERROR"
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

      [] btype = "MULTISIG" ->
        \* Requires NUMERIC(M), N pubkeys. SATISFIED iff >= M valid sigs.
        \* ERROR if M > N or fields missing.
        IF ~fields_present THEN "ERROR"
        ELSE IF ~fields_valid THEN "ERROR"  \* M > N
        ELSE IF ext_met THEN "SATISFIED"
        ELSE "UNSATISFIED"

(***************************************************************************)
(* State machine: enumerate all block evaluation configurations            *)
(***************************************************************************)

VARIABLES
    blockType,
    fieldsPresent,
    fieldsValid,
    extMet,
    phase

vars == <<blockType, fieldsPresent, fieldsValid, extMet, phase>>

Init ==
    /\ blockType \in BlockTypes
    /\ fieldsPresent \in BOOLEAN
    /\ fieldsValid \in BOOLEAN
    /\ extMet \in BOOLEAN
    /\ phase = "checking"

Next ==
    \/ /\ phase = "checking"
       /\ blockType' \in BlockTypes
       /\ fieldsPresent' \in BOOLEAN
       /\ fieldsValid' \in BOOLEAN
       /\ extMet' \in BOOLEAN
       /\ phase' = "done"
    \/ /\ phase = "done"
       /\ blockType' \in BlockTypes
       /\ fieldsPresent' \in BOOLEAN
       /\ fieldsValid' \in BOOLEAN
       /\ extMet' \in BOOLEAN
       /\ phase' = "checking"

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* Every block returns a valid result
Inv_ResultInRange ==
    EvalBlock(blockType, fieldsPresent, fieldsValid, extMet) \in EvalResults

\* Every block returns ERROR when required fields are missing
Inv_MissingFieldsError ==
    \A bt \in BlockTypes :
        EvalBlock(bt, FALSE, TRUE, TRUE) = "ERROR"

\* Every block returns SATISFIED only when all conditions are met
Inv_SatisfiedRequiresAll ==
    \A bt \in BlockTypes :
        \A fp, fv, em \in BOOLEAN :
            EvalBlock(bt, fp, fv, em) = "SATISFIED" =>
                /\ fp = TRUE
                /\ em = TRUE

\* No block returns SATISFIED when external condition fails
Inv_ExtFailMeansNotSatisfied ==
    \A bt \in BlockTypes :
        \A fp, fv \in BOOLEAN :
            EvalBlock(bt, fp, fv, FALSE) # "SATISFIED"

\* AMOUNT_LOCK: invalid fields (min > max) → ERROR
Inv_AmountLockInvalidError ==
    EvalBlock("AMOUNT_LOCK", TRUE, FALSE, TRUE) = "ERROR"

\* MULTISIG: invalid fields (M > N) → ERROR
Inv_MultisigInvalidError ==
    EvalBlock("MULTISIG", TRUE, FALSE, TRUE) = "ERROR"

\* OUTPUT_CHECK: index out of bounds → UNSATISFIED (not ERROR)
Inv_OutputCheckOOB ==
    LET r == EvalBlock("OUTPUT_CHECK", TRUE, FALSE, TRUE)
    IN r = "UNSATISFIED"

\* OUTPUT_CHECK: index out of bounds is not ERROR
Inv_OutputCheckOOBNotError ==
    EvalBlock("OUTPUT_CHECK", TRUE, FALSE, TRUE) # "ERROR"

\* Blocks with valid fields and met conditions → SATISFIED
Inv_AllMetIsSatisfied ==
    \A bt \in BlockTypes :
        EvalBlock(bt, TRUE, TRUE, TRUE) = "SATISFIED"

\* Blocks with valid fields but unmet conditions → UNSATISFIED
Inv_UnmetIsUnsatisfied ==
    \A bt \in BlockTypes :
        EvalBlock(bt, TRUE, TRUE, FALSE) = "UNSATISFIED"

\* Combined safety invariant
SafetyInvariant ==
    /\ Inv_ResultInRange
    /\ Inv_MissingFieldsError
    /\ Inv_SatisfiedRequiresAll
    /\ Inv_ExtFailMeansNotSatisfied
    /\ Inv_AmountLockInvalidError
    /\ Inv_MultisigInvalidError
    /\ Inv_OutputCheckOOB
    /\ Inv_OutputCheckOOBNotError
    /\ Inv_AllMetIsSatisfied
    /\ Inv_UnmetIsUnsatisfied

=============================================================================
