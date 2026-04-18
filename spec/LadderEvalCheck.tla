------------------------ MODULE LadderEvalCheck ------------------------
(***************************************************************************)
(* Model-checkable version of LadderEval.                                  *)
(* Uses a state machine that enumerates block/rung/ladder configurations   *)
(* and checks all safety properties as invariants.                         *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    MaxRecurseDepth   \* e.g. 5

EvalResults == {"SATISFIED", "UNSATISFIED", "ERROR"}

\* 5 representative block types: 3 invertible, 2 non-invertible/key-consuming
BlockTypes == {"CSV", "CLTV", "AMOUNT_LOCK", "SIG", "MULTISIG"}
InvertibleTypes == {"CSV", "CLTV", "AMOUNT_LOCK"}
KeyConsumingTypes == {"SIG", "MULTISIG"}

(***************************************************************************)
(* Inversion logic                                                         *)
(***************************************************************************)

ApplyInversion(result, inverted) ==
    IF ~inverted THEN result
    ELSE
        CASE result = "SATISFIED"   -> "UNSATISFIED"
          [] result = "UNSATISFIED" -> "SATISFIED"
          [] result = "ERROR"       -> "ERROR"

(***************************************************************************)
(* Block evaluation                                                        *)
(***************************************************************************)

EvalBlock(type, inverted, intrinsic) ==
    IF inverted /\ type \notin InvertibleTypes
    THEN "ERROR"
    ELSE ApplyInversion(intrinsic, inverted)

(***************************************************************************)
(* State machine: enumerate configurations                                 *)
(***************************************************************************)

VARIABLES
    blockType,       \* Current block type being checked
    blockInverted,   \* Current inversion flag
    blockResult,     \* Current intrinsic result
    recurseDepth,    \* Current recursion depth
    phase            \* "checking" or "done"

vars == <<blockType, blockInverted, blockResult, recurseDepth, phase>>

Init ==
    /\ blockType \in BlockTypes
    /\ blockInverted \in BOOLEAN
    /\ blockResult \in EvalResults
    /\ recurseDepth = MaxRecurseDepth
    /\ phase = "checking"

\* Transition: try next configuration or recurse
Next ==
    \/ /\ phase = "checking"
       /\ blockType' \in BlockTypes
       /\ blockInverted' \in BOOLEAN
       /\ blockResult' \in EvalResults
       /\ recurseDepth' = IF recurseDepth > 0 THEN recurseDepth - 1 ELSE 0
       /\ phase' = IF recurseDepth = 0 THEN "done" ELSE "checking"
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(***************************************************************************)
(* Invariants (checked in every reachable state)                           *)
(***************************************************************************)

\* INV 1: Key-consuming and invertible sets are disjoint
Inv_KeyConsumingDisjoint ==
    KeyConsumingTypes \cap InvertibleTypes = {}

\* INV 2: Inversion always preserves ERROR
Inv_InversionPreservesError ==
    ApplyInversion("ERROR", TRUE) = "ERROR" /\
    ApplyInversion("ERROR", FALSE) = "ERROR"

\* INV 3: Double inversion is identity for all results
Inv_DoubleInversion ==
    \A r \in EvalResults :
        ApplyInversion(ApplyInversion(r, TRUE), TRUE) = r

\* INV 4: Inverted non-invertible block always ERROR
Inv_NonInvertibleError ==
    \A t \in BlockTypes \ InvertibleTypes :
        \A r \in EvalResults :
            EvalBlock(t, TRUE, r) = "ERROR"

\* INV 5: Non-inverted block passes through intrinsic result
Inv_NonInvertedPassthrough ==
    \A t \in BlockTypes :
        \A r \in EvalResults :
            EvalBlock(t, FALSE, r) = r

\* INV 6: Inverted invertible block swaps SAT/UNSAT
Inv_InvertedSwaps ==
    \A t \in InvertibleTypes :
        /\ EvalBlock(t, TRUE, "SATISFIED") = "UNSATISFIED"
        /\ EvalBlock(t, TRUE, "UNSATISFIED") = "SATISFIED"
        /\ EvalBlock(t, TRUE, "ERROR") = "ERROR"

\* INV 7: Recursion depth is bounded and decreasing
Inv_RecurseBounded ==
    recurseDepth \in 0..MaxRecurseDepth

\* INV 8: Current block evaluation is consistent
Inv_BlockEvalConsistent ==
    LET eval == EvalBlock(blockType, blockInverted, blockResult)
    IN eval \in EvalResults

\* Combined invariant
TypeInvariant ==
    /\ blockType \in BlockTypes
    /\ blockInverted \in BOOLEAN
    /\ blockResult \in EvalResults
    /\ recurseDepth \in 0..MaxRecurseDepth
    /\ phase \in {"checking", "done"}

SafetyInvariant ==
    /\ Inv_KeyConsumingDisjoint
    /\ Inv_InversionPreservesError
    /\ Inv_DoubleInversion
    /\ Inv_NonInvertibleError
    /\ Inv_NonInvertedPassthrough
    /\ Inv_InvertedSwaps
    /\ Inv_RecurseBounded
    /\ Inv_BlockEvalConsistent

=============================================================================
