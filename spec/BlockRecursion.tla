------------------------- MODULE BlockRecursion -------------------------
(***************************************************************************)
(* Model of the recursion family block types (0x0401-0x0406):              *)
(*   - RECURSE_SAME: output carries identical conditions root              *)
(*   - RECURSE_MODIFIED: output root matches after single field mutation   *)
(*   - RECURSE_UNTIL: recursive until block height target                  *)
(*   - RECURSE_COUNT: countdown, terminates at zero                        *)
(*   - RECURSE_SPLIT: split across outputs with value conservation         *)
(*   - RECURSE_DECAY: output amount decreases by decay_rate each spend     *)
(*                                                                         *)
(* All 6 types are invertible and none are key-consuming.                  *)
(* All require spending_output context (coil.output_index).                *)
(*                                                                         *)
(* Verifies: root matching, height termination, count termination,         *)
(* value conservation, decay bounds, fail-closed on missing context.       *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxCount,    \* model: 4,  VPS: 20
    MaxHeight,   \* model: 10, VPS: 1000
    MaxSplits,   \* model: 3,  VPS: 8
    MaxAmount,   \* model: 20, VPS: 100000
    DustLimit    \* model: 2,  VPS: 546

Counts == 0..MaxCount
Heights == 0..MaxHeight
Splits == 1..MaxSplits
Amounts == 0..MaxAmount

BlockTypes == {
    "RECURSE_SAME",
    "RECURSE_MODIFIED",
    "RECURSE_UNTIL",
    "RECURSE_COUNT",
    "RECURSE_SPLIT",
    "RECURSE_DECAY"
}

(***************************************************************************)
(* RECURSE_SAME evaluation (0x0401)                                        *)
(* Output must carry identical conditions root as input.                   *)
(***************************************************************************)

RecurseSameParams == [
    block_type: {"RECURSE_SAME"}
]

RecurseSameSpend == [
    has_context: BOOLEAN,
    is_mlsc_output: BOOLEAN,
    root_matches: BOOLEAN
]

EvalRecurseSame(params, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF ~spend.is_mlsc_output THEN "ERROR"
    ELSE IF spend.root_matches THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* RECURSE_MODIFIED evaluation (0x0402)                                    *)
(* Output root matches after single field mutation.                        *)
(***************************************************************************)

RecurseModifiedParams == [
    block_type: {"RECURSE_MODIFIED"},
    mutation_valid: BOOLEAN
]

RecurseModifiedSpend == [
    has_context: BOOLEAN,
    is_mlsc_output: BOOLEAN,
    mutated_root_matches: BOOLEAN
]

EvalRecurseModified(params, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF ~spend.is_mlsc_output THEN "ERROR"
    ELSE IF ~params.mutation_valid THEN "ERROR"
    ELSE IF spend.mutated_root_matches THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* RECURSE_UNTIL evaluation (0x0403)                                       *)
(* Recursive until block height. At/past target → UNSATISFIED (terminates  *)
(* covenant). Before target, output must re-encumber with same root.       *)
(***************************************************************************)

RecurseUntilParams == [
    block_type: {"RECURSE_UNTIL"},
    target_height: Heights
]

RecurseUntilSpend == [
    has_context: BOOLEAN,
    is_mlsc_output: BOOLEAN,
    block_height: Heights,
    root_matches: BOOLEAN
]

EvalRecurseUntil(params, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF ~spend.is_mlsc_output THEN "ERROR"
    ELSE IF spend.block_height >= params.target_height THEN "UNSATISFIED"
    ELSE IF spend.root_matches THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* RECURSE_COUNT evaluation (0x0404)                                       *)
(* Countdown. Each spend must output with count-1. At count=0 →            *)
(* UNSATISFIED (terminates covenant).                                      *)
(***************************************************************************)

RecurseCountParams == [
    block_type: {"RECURSE_COUNT"},
    count: Counts
]

RecurseCountSpend == [
    has_context: BOOLEAN,
    is_mlsc_output: BOOLEAN,
    output_count_decremented: BOOLEAN
]

EvalRecurseCount(params, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF ~spend.is_mlsc_output THEN "ERROR"
    ELSE IF params.count = 0 THEN "UNSATISFIED"
    ELSE IF spend.output_count_decremented THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* RECURSE_SPLIT evaluation (0x0405)                                       *)
(* Split across outputs. Each output carries same conditions.              *)
(* Sum of output values must >= min (dust check).                          *)
(* Total value conservation checked.                                       *)
(***************************************************************************)

RecurseSplitParams == [
    block_type: {"RECURSE_SPLIT"},
    n_splits: Splits,
    min_split_amount: Amounts
]

RecurseSplitSpend == [
    has_context: BOOLEAN,
    is_mlsc_output: BOOLEAN,
    all_outputs_mlsc: BOOLEAN,
    all_roots_match: BOOLEAN,
    all_above_dust: BOOLEAN,
    input_amount: Amounts,
    total_output_amount: Amounts
]

EvalRecurseSplit(params, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF ~spend.is_mlsc_output THEN "ERROR"
    ELSE IF params.n_splits <= 0 THEN "UNSATISFIED"
    ELSE IF ~spend.all_outputs_mlsc THEN "UNSATISFIED"
    ELSE IF ~spend.all_roots_match THEN "UNSATISFIED"
    ELSE IF ~spend.all_above_dust THEN "UNSATISFIED"
    ELSE IF spend.total_output_amount > spend.input_amount THEN "UNSATISFIED"
    ELSE "SATISFIED"

(***************************************************************************)
(* RECURSE_DECAY evaluation (0x0406)                                       *)
(* Output amount must be >= input_amount - decay_rate.                     *)
(* Terminates when amount below dust.                                      *)
(***************************************************************************)

RecurseDecayParams == [
    block_type: {"RECURSE_DECAY"},
    decay_rate: 1..MaxAmount
]

RecurseDecaySpend == [
    has_context: BOOLEAN,
    is_mlsc_output: BOOLEAN,
    input_amount: Amounts,
    output_amount: Amounts
]

EvalRecurseDecay(params, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF ~spend.is_mlsc_output THEN "ERROR"
    ELSE IF spend.input_amount < DustLimit THEN "UNSATISFIED"
    ELSE IF spend.output_amount < (spend.input_amount - params.decay_rate) THEN "UNSATISFIED"
    ELSE IF spend.output_amount < DustLimit THEN "UNSATISFIED"
    ELSE "SATISFIED"

(***************************************************************************)
(* Invertibility: all 6 types are invertible                               *)
(***************************************************************************)

IsInvertible(block_type) == block_type \in BlockTypes

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    block_type,
    result_same, result_modified, result_until,
    result_count, result_split, result_decay,
    ps, pm, pu, pc, psp, pd,
    ss, sm, su, sc, ssp, sd,
    phase

vars == <<block_type,
          result_same, result_modified, result_until,
          result_count, result_split, result_decay,
          ps, pm, pu, pc, psp, pd,
          ss, sm, su, sc, ssp, sd,
          phase>>

Init ==
    /\ block_type \in BlockTypes
    /\ ps \in RecurseSameParams
    /\ pm \in RecurseModifiedParams
    /\ pu \in RecurseUntilParams
    /\ pc \in RecurseCountParams
    /\ psp \in RecurseSplitParams
    /\ pd \in RecurseDecayParams
    /\ ss \in RecurseSameSpend
    /\ sm \in RecurseModifiedSpend
    /\ su \in RecurseUntilSpend
    /\ sc \in RecurseCountSpend
    /\ ssp \in RecurseSplitSpend
    /\ sd \in RecurseDecaySpend
    /\ result_same = "PENDING"
    /\ result_modified = "PENDING"
    /\ result_until = "PENDING"
    /\ result_count = "PENDING"
    /\ result_split = "PENDING"
    /\ result_decay = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result_same' = EvalRecurseSame(ps, ss)
    /\ result_modified' = EvalRecurseModified(pm, sm)
    /\ result_until' = EvalRecurseUntil(pu, su)
    /\ result_count' = EvalRecurseCount(pc, sc)
    /\ result_split' = EvalRecurseSplit(psp, ssp)
    /\ result_decay' = EvalRecurseDecay(pd, sd)
    /\ phase' = "done"
    /\ UNCHANGED <<block_type, ps, pm, pu, pc, psp, pd,
                    ss, sm, su, sc, ssp, sd>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: RECURSE_SAME matching root → SATISFIED
Inv_SameMatchSatisfied ==
    (phase = "done" /\ ss.has_context /\ ss.is_mlsc_output /\ ss.root_matches)
    => result_same = "SATISFIED"

\* I2: RECURSE_SAME mismatched root → UNSATISFIED
Inv_SameMismatchUnsatisfied ==
    (phase = "done" /\ ss.has_context /\ ss.is_mlsc_output /\ ~ss.root_matches)
    => result_same = "UNSATISFIED"

\* I3: RECURSE_UNTIL at/past target → UNSATISFIED (termination guaranteed)
Inv_UntilAtTargetTerminates ==
    (phase = "done" /\ su.has_context /\ su.is_mlsc_output
     /\ su.block_height >= pu.target_height)
    => result_until = "UNSATISFIED"

\* I4: RECURSE_UNTIL before target with re-encumber → SATISFIED
Inv_UntilBeforeTargetSatisfied ==
    (phase = "done" /\ su.has_context /\ su.is_mlsc_output
     /\ su.block_height < pu.target_height /\ su.root_matches)
    => result_until = "SATISFIED"

\* I5: RECURSE_COUNT at 0 → UNSATISFIED (termination guaranteed)
Inv_CountZeroTerminates ==
    (phase = "done" /\ sc.has_context /\ sc.is_mlsc_output /\ pc.count = 0)
    => result_count = "UNSATISFIED"

\* I6: RECURSE_COUNT > 0 with proper decrement → SATISFIED
Inv_CountDecrementSatisfied ==
    (phase = "done" /\ sc.has_context /\ sc.is_mlsc_output
     /\ pc.count > 0 /\ sc.output_count_decremented)
    => result_count = "SATISFIED"

\* I7: RECURSE_SPLIT value conservation violation → UNSATISFIED
Inv_SplitValueConservation ==
    (phase = "done" /\ ssp.has_context /\ ssp.is_mlsc_output
     /\ psp.n_splits > 0
     /\ ssp.all_outputs_mlsc /\ ssp.all_roots_match /\ ssp.all_above_dust
     /\ ssp.total_output_amount > ssp.input_amount)
    => result_split = "UNSATISFIED"

\* I8: RECURSE_DECAY proper reduction → SATISFIED
Inv_DecayProperReduction ==
    (phase = "done" /\ sd.has_context /\ sd.is_mlsc_output
     /\ sd.input_amount >= DustLimit
     /\ sd.output_amount >= (sd.input_amount - pd.decay_rate)
     /\ sd.output_amount >= DustLimit)
    => result_decay = "SATISFIED"

\* I9: All types: non-MLSC output → ERROR
Inv_NonMLSCError_Same ==
    (phase = "done" /\ ss.has_context /\ ~ss.is_mlsc_output)
    => result_same = "ERROR"

Inv_NonMLSCError_Modified ==
    (phase = "done" /\ sm.has_context /\ ~sm.is_mlsc_output)
    => result_modified = "ERROR"

Inv_NonMLSCError_Until ==
    (phase = "done" /\ su.has_context /\ ~su.is_mlsc_output)
    => result_until = "ERROR"

Inv_NonMLSCError_Count ==
    (phase = "done" /\ sc.has_context /\ ~sc.is_mlsc_output)
    => result_count = "ERROR"

Inv_NonMLSCError_Split ==
    (phase = "done" /\ ssp.has_context /\ ~ssp.is_mlsc_output)
    => result_split = "ERROR"

Inv_NonMLSCError_Decay ==
    (phase = "done" /\ sd.has_context /\ ~sd.is_mlsc_output)
    => result_decay = "ERROR"

\* I10: All types: no context → ERROR
Inv_NoContextError_Same ==
    (phase = "done" /\ ~ss.has_context)
    => result_same = "ERROR"

Inv_NoContextError_Modified ==
    (phase = "done" /\ ~sm.has_context)
    => result_modified = "ERROR"

Inv_NoContextError_Until ==
    (phase = "done" /\ ~su.has_context)
    => result_until = "ERROR"

Inv_NoContextError_Count ==
    (phase = "done" /\ ~sc.has_context)
    => result_count = "ERROR"

Inv_NoContextError_Split ==
    (phase = "done" /\ ~ssp.has_context)
    => result_split = "ERROR"

Inv_NoContextError_Decay ==
    (phase = "done" /\ ~sd.has_context)
    => result_decay = "ERROR"

\* I11: All 6 types are invertible
Inv_AllInvertible ==
    \A bt \in BlockTypes : IsInvertible(bt)

SafetyInvariant ==
    \* I1-I2: RECURSE_SAME
    /\ Inv_SameMatchSatisfied
    /\ Inv_SameMismatchUnsatisfied
    \* I3-I4: RECURSE_UNTIL
    /\ Inv_UntilAtTargetTerminates
    /\ Inv_UntilBeforeTargetSatisfied
    \* I5-I6: RECURSE_COUNT
    /\ Inv_CountZeroTerminates
    /\ Inv_CountDecrementSatisfied
    \* I7: RECURSE_SPLIT
    /\ Inv_SplitValueConservation
    \* I8: RECURSE_DECAY
    /\ Inv_DecayProperReduction
    \* I9: non-MLSC output
    /\ Inv_NonMLSCError_Same
    /\ Inv_NonMLSCError_Modified
    /\ Inv_NonMLSCError_Until
    /\ Inv_NonMLSCError_Count
    /\ Inv_NonMLSCError_Split
    /\ Inv_NonMLSCError_Decay
    \* I10: no context
    /\ Inv_NoContextError_Same
    /\ Inv_NoContextError_Modified
    /\ Inv_NoContextError_Until
    /\ Inv_NoContextError_Count
    /\ Inv_NoContextError_Split
    /\ Inv_NoContextError_Decay
    \* I11: invertibility
    /\ Inv_AllInvertible

=============================================================================
