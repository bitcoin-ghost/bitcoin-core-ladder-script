-------------------- MODULE RecursiveCovenant --------------------
(***************************************************************************)
(* Model of the RECURSE_* block type family (0x0401–0x0406):               *)
(*   - RECURSE_SAME: identity re-encumber (output root == input root)      *)
(*   - RECURSE_MODIFIED: output root matches after field mutation          *)
(*   - RECURSE_UNTIL: recursive until target block height reached          *)
(*   - RECURSE_COUNT: countdown tracker, terminates at zero                *)
(*   - RECURSE_SPLIT: split across outputs with value conservation         *)
(*   - RECURSE_DECAY: value reduced by decay_rate per spend                *)
(*                                                                         *)
(* Common rules:                                                           *)
(*   - All RECURSE_* blocks are invertible (types.h IsInvertibleBlockType) *)
(*   - Non-MLSC output → ERROR                                             *)
(*   - Depth/count bounds prevent infinite recursion                       *)
(*   - Fail-closed: ERROR when spending_output context missing             *)
(*                                                                         *)
(* Verifies: termination conditions, value conservation,                   *)
(* re-encumbrance matching, fail-closed behavior.                          *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxDepth,    \* e.g. 4  (VPS: 10)
    MaxCount,    \* e.g. 4  (VPS: 20)
    MaxSplits,   \* e.g. 3  (VPS: 8)
    MinSats      \* e.g. 546 (dust limit)

Depths == 0..MaxDepth
Counts == 0..MaxCount
Splits == 1..MaxSplits
Heights == 0..10

BlockTypes == {"SAME", "MODIFIED", "UNTIL", "COUNT", "SPLIT", "DECAY"}

\* Bounded value range for SPLIT outputs (keeps state space finite)
SplitValues == (MinSats - 1)..( MinSats * MaxSplits + 1 )

\* All sequences of length n drawn from set S
RECURSIVE SeqsOfLen(_, _)
SeqsOfLen(S, n) ==
    IF n = 0 THEN {<<>>}
    ELSE { Append(s, v) : s \in SeqsOfLen(S, n - 1), v \in S }

\* Union of all sequences of length 1..MaxSplits over SplitValues
BoundedSplitSeqs == UNION { SeqsOfLen(SplitValues, n) : n \in Splits }

(***************************************************************************)
(* RECURSE_* evaluation                                                    *)
(***************************************************************************)

\* Covenant parameters set at fund time (in conditions)
CovenantParams == [
    block_type: BlockTypes,
    depth: Depths,                \* remaining recursion depth (SAME, MODIFIED, DECAY)
    count: Counts,                \* remaining countdown (COUNT)
    target_height: Heights,       \* termination height (UNTIL)
    num_splits: Splits,           \* number of output splits (SPLIT)
    input_value: MinSats..(MinSats * MaxSplits),  \* input UTXO value in sats
    decay_rate: 1..MinSats        \* sats removed per spend (DECAY)
]

\* Spending transaction / output context
SpendCtx == [
    has_context: BOOLEAN,         \* spending_output present
    output_is_mlsc: BOOLEAN,      \* output carries 0xDF MLSC prefix
    root_matches: BOOLEAN,        \* output conditions_root == input conditions_root
    decremented_count: BOOLEAN,   \* output carries count - 1
    decremented_depth: BOOLEAN,   \* output carries depth - 1
    block_height: Heights,        \* current block height
    output_values: BoundedSplitSeqs,  \* per-output values for SPLIT
    decayed_value_matches: BOOLEAN  \* output value == input_value - decay_rate
]

\* Helper: sum of a sequence of integers
RECURSIVE SeqSum(_)
SeqSum(s) ==
    IF s = <<>> THEN 0
    ELSE Head(s) + SeqSum(Tail(s))

\* Helper: all elements of a sequence are >= threshold
RECURSIVE AllAbove(_, _)
AllAbove(s, threshold) ==
    IF s = <<>> THEN TRUE
    ELSE Head(s) >= threshold /\ AllAbove(Tail(s), threshold)

EvalRecurseCovenant(params, spend) ==
    \* Fail-closed: no spending_output context → ERROR
    IF ~spend.has_context THEN "ERROR"
    \* Non-MLSC output → ERROR (for all RECURSE_* types)
    ELSE IF ~spend.output_is_mlsc THEN "ERROR"
    \* --- RECURSE_SAME (0x0401) ---
    ELSE IF params.block_type = "SAME" THEN
        IF params.depth = 0 THEN "UNSATISFIED"
        ELSE IF spend.root_matches THEN "SATISFIED"
        ELSE "UNSATISFIED"
    \* --- RECURSE_MODIFIED (0x0402) ---
    ELSE IF params.block_type = "MODIFIED" THEN
        IF params.depth = 0 THEN "UNSATISFIED"
        ELSE IF spend.root_matches THEN "SATISFIED"
        ELSE "UNSATISFIED"
    \* --- RECURSE_UNTIL (0x0403) ---
    ELSE IF params.block_type = "UNTIL" THEN
        IF spend.block_height >= params.target_height THEN "SATISFIED"
        ELSE IF spend.root_matches THEN "SATISFIED"
        ELSE "UNSATISFIED"
    \* --- RECURSE_COUNT (0x0404) ---
    ELSE IF params.block_type = "COUNT" THEN
        IF params.count = 0 THEN "SATISFIED"
        ELSE IF spend.decremented_count /\ spend.root_matches THEN "SATISFIED"
        ELSE "UNSATISFIED"
    \* --- RECURSE_SPLIT (0x0405) ---
    ELSE IF params.block_type = "SPLIT" THEN
        IF params.num_splits < 1 THEN "UNSATISFIED"
        ELSE IF Len(spend.output_values) /= params.num_splits THEN "UNSATISFIED"
        ELSE IF ~AllAbove(spend.output_values, MinSats) THEN "UNSATISFIED"
        ELSE IF SeqSum(spend.output_values) /= params.input_value THEN "UNSATISFIED"
        ELSE IF ~spend.root_matches THEN "UNSATISFIED"
        ELSE "SATISFIED"
    \* --- RECURSE_DECAY (0x0406) ---
    ELSE IF params.block_type = "DECAY" THEN
        IF params.depth = 0 THEN "UNSATISFIED"
        ELSE IF spend.decayed_value_matches /\ spend.root_matches THEN "SATISFIED"
        ELSE "UNSATISFIED"
    ELSE "ERROR"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES params, spend, result, phase

vars == <<params, spend, result, phase>>

Init ==
    /\ params \in CovenantParams
    /\ spend \in SpendCtx
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalRecurseCovenant(params, spend)
    /\ phase' = "done"
    /\ UNCHANGED <<params, spend>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: RECURSE_SAME with matching root → SATISFIED
Inv_SameMatching ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "SAME" /\ params.depth > 0
     /\ spend.root_matches)
    => result = "SATISFIED"

\* I2: RECURSE_SAME with mismatched root → UNSATISFIED
Inv_SameMismatched ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "SAME" /\ params.depth > 0
     /\ ~spend.root_matches)
    => result = "UNSATISFIED"

\* I3: RECURSE_UNTIL past target height → SATISFIED (terminates covenant)
Inv_UntilPastTarget ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "UNTIL"
     /\ spend.block_height >= params.target_height)
    => result = "SATISFIED"

\* I4: RECURSE_UNTIL before target with matching output → SATISFIED
Inv_UntilBeforeTarget ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "UNTIL"
     /\ spend.block_height < params.target_height
     /\ spend.root_matches)
    => result = "SATISFIED"

\* I5: RECURSE_COUNT at 0 → SATISFIED (terminates covenant)
Inv_CountZero ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "COUNT"
     /\ params.count = 0)
    => result = "SATISFIED"

\* I6: RECURSE_COUNT > 0 with decremented output → SATISFIED
Inv_CountDecremented ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "COUNT"
     /\ params.count > 0
     /\ spend.decremented_count /\ spend.root_matches)
    => result = "SATISFIED"

\* I7: RECURSE_SPLIT value conservation: sum(outputs) = input_value
Inv_SplitConservation ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "SPLIT"
     /\ params.num_splits >= 1
     /\ Len(spend.output_values) = params.num_splits
     /\ AllAbove(spend.output_values, MinSats)
     /\ SeqSum(spend.output_values) = params.input_value
     /\ spend.root_matches)
    => result = "SATISFIED"

\* I8: RECURSE_SPLIT value violation → UNSATISFIED
Inv_SplitViolation ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "SPLIT"
     /\ params.num_splits >= 1
     /\ Len(spend.output_values) = params.num_splits
     /\ SeqSum(spend.output_values) /= params.input_value)
    => result = "UNSATISFIED"

\* I9: Non-MLSC output → ERROR (for all RECURSE_* types)
Inv_NonMLSCError ==
    (phase = "done" /\ spend.has_context /\ ~spend.output_is_mlsc)
    => result = "ERROR"

\* I10: No context → ERROR (fail-closed)
Inv_NoContextError ==
    (phase = "done" /\ ~spend.has_context)
    => result = "ERROR"

\* I11: RECURSE_DECAY reduces value by decay_rate
Inv_DecayReduction ==
    (phase = "done" /\ spend.has_context /\ spend.output_is_mlsc
     /\ params.block_type = "DECAY" /\ params.depth > 0
     /\ spend.decayed_value_matches /\ spend.root_matches)
    => result = "SATISFIED"

SafetyInvariant ==
    /\ Inv_SameMatching
    /\ Inv_SameMismatched
    /\ Inv_UntilPastTarget
    /\ Inv_UntilBeforeTarget
    /\ Inv_CountZero
    /\ Inv_CountDecremented
    /\ Inv_SplitConservation
    /\ Inv_SplitViolation
    /\ Inv_NonMLSCError
    /\ Inv_NoContextError
    /\ Inv_DecayReduction

=============================================================================
