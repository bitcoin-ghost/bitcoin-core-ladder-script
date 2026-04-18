------------------------ MODULE LadderCrossInput ------------------------
(***************************************************************************)
(* Model multi-input transaction semantics for Ladder Script.             *)
(* Covers COSIGN cross-input validation and witness reference (diff       *)
(* witness) semantics including forward-only, no-chaining, and type       *)
(* matching constraints.                                                  *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    NumInputs      \* Number of inputs in transaction (e.g. 3)

\* Abstract SPK hashes (small integers)
SpkHashes == 1..NumInputs
\* Field types (reduced set for tractability — code allows all 9 data types
\* in diffs, only constraint is type must match source field)
FieldTypes == {"PUBKEY", "SIGNATURE"}

(***************************************************************************)
(* COSIGN evaluation                                                       *)
(***************************************************************************)

EvalCosign(inputIdx, committedHash, spkHashes) ==
    IF inputIdx < 1 \/ inputIdx > Len(spkHashes) THEN "ERROR"
    ELSE LET otherMatches == {i \in 1..Len(spkHashes) :
                                 i # inputIdx /\ spkHashes[i] = committedHash}
         IN IF otherMatches # {} THEN "SATISFIED" ELSE "UNSATISFIED"

(***************************************************************************)
(* Witness reference validation                                            *)
(***************************************************************************)

ValidateWitnessRef(inputIdx, sourceIdx, sourceIsRef, sourceFieldType, targetFieldType) ==
    IF sourceIdx >= inputIdx THEN "REJECT_FORWARD_ONLY"
    ELSE IF sourceIdx < 1 THEN "REJECT_INVALID_SOURCE"
    ELSE IF sourceIsRef THEN "REJECT_CHAINING"
    ELSE IF sourceFieldType # targetFieldType THEN "REJECT_TYPE_MISMATCH"
    ELSE "ACCEPT"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    cosignInputIdx,
    cosignCommitted,
    spkHashes,
    refInputIdx,
    refSourceIdx,
    sourceIsRef,
    sourceFieldType,
    targetFieldType,
    phase

vars == <<cosignInputIdx, cosignCommitted, spkHashes,
          refInputIdx, refSourceIdx, sourceIsRef,
          sourceFieldType, targetFieldType, phase>>

Init ==
    /\ cosignInputIdx \in 1..NumInputs
    /\ cosignCommitted \in SpkHashes
    /\ spkHashes \in [1..NumInputs -> SpkHashes]
    /\ refInputIdx \in 1..NumInputs
    /\ refSourceIdx \in 0..NumInputs
    /\ sourceIsRef \in BOOLEAN
    /\ sourceFieldType \in FieldTypes
    /\ targetFieldType \in FieldTypes
    /\ phase = "check"

Next ==
    \/ /\ phase = "check"
       /\ phase' = "done"
       /\ UNCHANGED <<cosignInputIdx, cosignCommitted, spkHashes,
                      refInputIdx, refSourceIdx, sourceIsRef,
                      sourceFieldType, targetFieldType>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* COSIGN result is always valid
Inv_CosignResultValid ==
    EvalCosign(cosignInputIdx, cosignCommitted, spkHashes) \in
        {"SATISFIED", "UNSATISFIED", "ERROR"}

\* COSIGN with no matching OTHER input -> UNSATISFIED
Inv_CosignNoMatch ==
    (\A i \in 1..NumInputs : i = cosignInputIdx \/ spkHashes[i] # cosignCommitted)
    => EvalCosign(cosignInputIdx, cosignCommitted, spkHashes) = "UNSATISFIED"

\* COSIGN with matching other input -> SATISFIED
Inv_CosignMatch ==
    (\E i \in 1..NumInputs : i # cosignInputIdx /\ spkHashes[i] = cosignCommitted)
    => EvalCosign(cosignInputIdx, cosignCommitted, spkHashes) = "SATISFIED"

\* COSIGN self-reference doesn't count
Inv_CosignNoSelfRef ==
    (spkHashes[cosignInputIdx] = cosignCommitted
     /\ \A i \in 1..NumInputs : i # cosignInputIdx => spkHashes[i] # cosignCommitted)
    => EvalCosign(cosignInputIdx, cosignCommitted, spkHashes) = "UNSATISFIED"

\* Witness ref to higher-indexed input -> rejected
Inv_WitRefForwardOnly ==
    (refSourceIdx >= refInputIdx /\ refSourceIdx >= 1)
    => ValidateWitnessRef(refInputIdx, refSourceIdx, sourceIsRef,
                          sourceFieldType, targetFieldType) = "REJECT_FORWARD_ONLY"

\* Witness ref chaining -> rejected
Inv_WitRefNoChaining ==
    (refSourceIdx >= 1 /\ refSourceIdx < refInputIdx /\ sourceIsRef)
    => ValidateWitnessRef(refInputIdx, refSourceIdx, sourceIsRef,
                          sourceFieldType, targetFieldType) = "REJECT_CHAINING"

\* Witness ref with type mismatch -> rejected
Inv_WitRefTypeMismatch ==
    (refSourceIdx >= 1 /\ refSourceIdx < refInputIdx /\ ~sourceIsRef
     /\ sourceFieldType # targetFieldType)
    => ValidateWitnessRef(refInputIdx, refSourceIdx, sourceIsRef,
                          sourceFieldType, targetFieldType) = "REJECT_TYPE_MISMATCH"

\* Witness ref with valid everything -> accepted
Inv_WitRefValidAccepted ==
    (refSourceIdx >= 1 /\ refSourceIdx < refInputIdx /\ ~sourceIsRef
     /\ sourceFieldType = targetFieldType)
    => ValidateWitnessRef(refInputIdx, refSourceIdx, sourceIsRef,
                          sourceFieldType, targetFieldType) = "ACCEPT"

\* Invalid source index -> rejected
Inv_WitRefInvalidSource ==
    refSourceIdx = 0
    => ValidateWitnessRef(refInputIdx, refSourceIdx, sourceIsRef,
                          sourceFieldType, targetFieldType) = "REJECT_INVALID_SOURCE"

\* Combined
SafetyInvariant ==
    /\ Inv_CosignResultValid
    /\ Inv_CosignNoMatch
    /\ Inv_CosignMatch
    /\ Inv_CosignNoSelfRef
    /\ Inv_WitRefForwardOnly
    /\ Inv_WitRefNoChaining
    /\ Inv_WitRefTypeMismatch
    /\ Inv_WitRefValidAccepted
    /\ Inv_WitRefInvalidSource

=============================================================================
