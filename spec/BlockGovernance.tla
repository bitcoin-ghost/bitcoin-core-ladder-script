----------------------- MODULE BlockGovernance -----------------------
(***************************************************************************)
(* Model of the governance family block types (0x0801-0x0807):             *)
(*   - EPOCH_GATE:     periodic spending window (epoch_size, window_size)  *)
(*   - WEIGHT_LIMIT:   max transaction weight                              *)
(*   - INPUT_COUNT:    min/max input count bounds                          *)
(*   - OUTPUT_COUNT:   min/max output count bounds                         *)
(*   - RELATIVE_VALUE: output >= ratio of input value                      *)
(*   - ACCUMULATOR:    Merkle set membership proof                         *)
(*   - OUTPUT_CHECK:   per-output value range + script hash               *)
(*                                                                         *)
(* Invertible: WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, ACCUMULATOR        *)
(* NOT invertible: EPOCH_GATE, RELATIVE_VALUE, OUTPUT_CHECK                *)
(* None are key-consuming. All require tx context (except ACCUMULATOR).    *)
(*                                                                         *)
(* Verifies: correct acceptance/rejection for each type, inversion         *)
(* behavior, fail-closed when context missing.                             *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

CONSTANTS
    MaxWeight,    \* e.g. 5  (VPS: 4000)
    MaxCount,     \* e.g. 4  (VPS: 100)
    MaxHeight,    \* e.g. 10 (VPS: 1000)
    MaxAmount     \* e.g. 10 (VPS: 100000)

BlockTypes == {
    "EPOCH_GATE", "WEIGHT_LIMIT", "INPUT_COUNT", "OUTPUT_COUNT",
    "RELATIVE_VALUE", "ACCUMULATOR", "OUTPUT_CHECK"
}

InvertibleTypes == {
    "WEIGHT_LIMIT", "INPUT_COUNT", "OUTPUT_COUNT", "ACCUMULATOR"
}

Heights == 0..MaxHeight
Weights == 1..MaxWeight
Counts == 0..MaxCount
Amounts == 0..MaxAmount

\* Abstract hash domain: a small set of distinct hash values
HashValues == 0..3

(***************************************************************************)
(* Block parameters (conditions set at fund time)                          *)
(***************************************************************************)

EpochGateParams == [
    epoch_size:  1..MaxHeight,    \* blocks per epoch (must be > 0)
    window_size: 1..MaxHeight     \* spending window within epoch (must be > 0)
]

WeightLimitParams == [
    max_weight: Weights
]

InputCountParams == [
    min_inputs: Counts,
    max_inputs: Counts
]

OutputCountParams == [
    min_outputs: Counts,
    max_outputs: Counts
]

RelativeValueParams == [
    numerator:   0..MaxAmount,
    denominator: 1..MaxAmount     \* must be > 0
]

AccumulatorParams == [
    root:       HashValues,
    leaf:       HashValues,
    proof_valid: BOOLEAN          \* abstract: does the Merkle proof verify?
]

OutputCheckParams == [
    output_index: Counts,
    min_sats:     Amounts,
    max_sats:     Amounts,
    script_hash:  HashValues,
    skip_script:  BOOLEAN         \* TRUE when script_hash is all-zeros
]

(***************************************************************************)
(* Spending transaction properties                                         *)
(***************************************************************************)

SpendTx == [
    has_context:   BOOLEAN,
    block_height:  Heights,
    tx_weight:     Weights,
    n_inputs:      Counts,
    n_outputs:     Counts,
    input_amount:  Amounts,
    output_amount: Amounts,
    \* Per-output: indexed output value and script hash
    out_value:     Amounts,
    out_script:    HashValues
]

(***************************************************************************)
(* Evaluation operators                                                    *)
(***************************************************************************)

EvalEpochGate(p, tx) ==
    IF ~tx.has_context THEN "ERROR"
    ELSE IF p.window_size > p.epoch_size THEN "ERROR"
    ELSE LET position == tx.block_height % p.epoch_size
         IN IF position < p.window_size THEN "SATISFIED"
            ELSE "UNSATISFIED"

EvalWeightLimit(p, tx) ==
    IF ~tx.has_context THEN "ERROR"
    ELSE IF tx.tx_weight <= p.max_weight THEN "SATISFIED"
         ELSE "UNSATISFIED"

EvalInputCount(p, tx) ==
    IF ~tx.has_context THEN "ERROR"
    ELSE IF p.min_inputs > p.max_inputs THEN "ERROR"
    ELSE IF tx.n_inputs >= p.min_inputs /\ tx.n_inputs <= p.max_inputs
         THEN "SATISFIED"
         ELSE "UNSATISFIED"

EvalOutputCount(p, tx) ==
    IF ~tx.has_context THEN "ERROR"
    ELSE IF p.min_outputs > p.max_outputs THEN "ERROR"
    ELSE IF tx.n_outputs >= p.min_outputs /\ tx.n_outputs <= p.max_outputs
         THEN "SATISFIED"
         ELSE "UNSATISFIED"

EvalRelativeValue(p, tx) ==
    IF ~tx.has_context THEN "ERROR"
    \* output_amount * denominator >= input_amount * numerator
    ELSE IF tx.output_amount * p.denominator >= tx.input_amount * p.numerator
         THEN "SATISFIED"
         ELSE "UNSATISFIED"

EvalAccumulator(p) ==
    \* No tx context needed -- pure hash proof
    IF p.proof_valid THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalOutputCheck(p, tx) ==
    IF ~tx.has_context THEN "ERROR"
    ELSE IF p.min_sats > p.max_sats THEN "ERROR"
    \* Bounds check: output_index must exist
    ELSE IF p.output_index >= tx.n_outputs THEN "UNSATISFIED"
    \* Value check
    ELSE IF tx.out_value < p.min_sats \/ tx.out_value > p.max_sats
         THEN "UNSATISFIED"
    \* Script check (skip if flag set)
    ELSE IF ~p.skip_script /\ tx.out_script # p.script_hash
         THEN "UNSATISFIED"
    ELSE "SATISFIED"

(***************************************************************************)
(* Inversion logic (mirrors ApplyInversion in evaluator.cpp)               *)
(***************************************************************************)

ApplyInversion(raw, inverted) ==
    IF ~inverted THEN raw
    ELSE IF raw = "SATISFIED" THEN "UNSATISFIED"
    ELSE IF raw = "UNSATISFIED" THEN "SATISFIED"
    ELSE raw  \* ERROR never flips

(***************************************************************************)
(* Top-level dispatch                                                      *)
(***************************************************************************)

\* Choose a block type, parameter record, and whether inverted
VARIABLES blockType, inverted, params, spend, result, phase

vars == <<blockType, inverted, params, spend, result, phase>>

Init ==
    /\ blockType \in BlockTypes
    /\ inverted \in BOOLEAN
    /\ spend \in SpendTx
    /\ result = "PENDING"
    /\ phase = "eval"
    /\ \/ (blockType = "EPOCH_GATE"     /\ params \in EpochGateParams)
       \/ (blockType = "WEIGHT_LIMIT"   /\ params \in WeightLimitParams)
       \/ (blockType = "INPUT_COUNT"    /\ params \in InputCountParams)
       \/ (blockType = "OUTPUT_COUNT"   /\ params \in OutputCountParams)
       \/ (blockType = "RELATIVE_VALUE" /\ params \in RelativeValueParams)
       \/ (blockType = "ACCUMULATOR"    /\ params \in AccumulatorParams)
       \/ (blockType = "OUTPUT_CHECK"   /\ params \in OutputCheckParams)

EvalRaw ==
    \* Gate: non-invertible type marked inverted => ERROR
    IF inverted /\ blockType \notin InvertibleTypes THEN "ERROR"
    ELSE LET raw ==
        IF blockType = "EPOCH_GATE"     THEN EvalEpochGate(params, spend)
        ELSE IF blockType = "WEIGHT_LIMIT"   THEN EvalWeightLimit(params, spend)
        ELSE IF blockType = "INPUT_COUNT"    THEN EvalInputCount(params, spend)
        ELSE IF blockType = "OUTPUT_COUNT"   THEN EvalOutputCount(params, spend)
        ELSE IF blockType = "RELATIVE_VALUE" THEN EvalRelativeValue(params, spend)
        ELSE IF blockType = "ACCUMULATOR"    THEN EvalAccumulator(params)
        ELSE EvalOutputCheck(params, spend)
    IN ApplyInversion(raw, inverted)

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalRaw
    /\ phase' = "done"
    /\ UNCHANGED <<blockType, inverted, params, spend>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: EPOCH_GATE at correct epoch offset => SATISFIED
Inv_EpochGateSatisfied ==
    (phase = "done" /\ blockType = "EPOCH_GATE" /\ ~inverted
     /\ spend.has_context
     /\ params.window_size <= params.epoch_size
     /\ (spend.block_height % params.epoch_size) < params.window_size)
    => result = "SATISFIED"

\* I2: EPOCH_GATE at wrong offset => UNSATISFIED
Inv_EpochGateUnsatisfied ==
    (phase = "done" /\ blockType = "EPOCH_GATE" /\ ~inverted
     /\ spend.has_context
     /\ params.window_size <= params.epoch_size
     /\ (spend.block_height % params.epoch_size) >= params.window_size)
    => result = "UNSATISFIED"

\* I3: WEIGHT_LIMIT within limit => SATISFIED
Inv_WeightLimitSatisfied ==
    (phase = "done" /\ blockType = "WEIGHT_LIMIT" /\ ~inverted
     /\ spend.has_context
     /\ spend.tx_weight <= params.max_weight)
    => result = "SATISFIED"

\* I4: WEIGHT_LIMIT over limit => UNSATISFIED
Inv_WeightLimitUnsatisfied ==
    (phase = "done" /\ blockType = "WEIGHT_LIMIT" /\ ~inverted
     /\ spend.has_context
     /\ spend.tx_weight > params.max_weight)
    => result = "UNSATISFIED"

\* I5: INPUT_COUNT within bounds => SATISFIED
Inv_InputCountSatisfied ==
    (phase = "done" /\ blockType = "INPUT_COUNT" /\ ~inverted
     /\ spend.has_context
     /\ params.min_inputs <= params.max_inputs
     /\ spend.n_inputs >= params.min_inputs
     /\ spend.n_inputs <= params.max_inputs)
    => result = "SATISFIED"

\* I6: INPUT_COUNT outside bounds => UNSATISFIED
Inv_InputCountUnsatisfied ==
    (phase = "done" /\ blockType = "INPUT_COUNT" /\ ~inverted
     /\ spend.has_context
     /\ params.min_inputs <= params.max_inputs
     /\ (spend.n_inputs < params.min_inputs \/ spend.n_inputs > params.max_inputs))
    => result = "UNSATISFIED"

\* I7: OUTPUT_COUNT within bounds => SATISFIED
Inv_OutputCountSatisfied ==
    (phase = "done" /\ blockType = "OUTPUT_COUNT" /\ ~inverted
     /\ spend.has_context
     /\ params.min_outputs <= params.max_outputs
     /\ spend.n_outputs >= params.min_outputs
     /\ spend.n_outputs <= params.max_outputs)
    => result = "SATISFIED"

\* I8: OUTPUT_COUNT outside bounds => UNSATISFIED
Inv_OutputCountUnsatisfied ==
    (phase = "done" /\ blockType = "OUTPUT_COUNT" /\ ~inverted
     /\ spend.has_context
     /\ params.min_outputs <= params.max_outputs
     /\ (spend.n_outputs < params.min_outputs \/ spend.n_outputs > params.max_outputs))
    => result = "UNSATISFIED"

\* I9: RELATIVE_VALUE ratio met => SATISFIED
Inv_RelativeValueSatisfied ==
    (phase = "done" /\ blockType = "RELATIVE_VALUE" /\ ~inverted
     /\ spend.has_context
     /\ spend.output_amount * params.denominator >= spend.input_amount * params.numerator)
    => result = "SATISFIED"

\* I10: OUTPUT_CHECK all constraints met => SATISFIED
Inv_OutputCheckSatisfied ==
    (phase = "done" /\ blockType = "OUTPUT_CHECK" /\ ~inverted
     /\ spend.has_context
     /\ params.min_sats <= params.max_sats
     /\ params.output_index < spend.n_outputs
     /\ spend.out_value >= params.min_sats
     /\ spend.out_value <= params.max_sats
     /\ (params.skip_script \/ spend.out_script = params.script_hash))
    => result = "SATISFIED"

\* I11: OUTPUT_CHECK wrong script hash => UNSATISFIED
Inv_OutputCheckScriptFail ==
    (phase = "done" /\ blockType = "OUTPUT_CHECK" /\ ~inverted
     /\ spend.has_context
     /\ params.min_sats <= params.max_sats
     /\ params.output_index < spend.n_outputs
     /\ spend.out_value >= params.min_sats
     /\ spend.out_value <= params.max_sats
     /\ ~params.skip_script
     /\ spend.out_script # params.script_hash)
    => result = "UNSATISFIED"

\* I12: Invertible types: inversion flips SATISFIED <-> UNSATISFIED
Inv_InversionFlips ==
    \* When an invertible type would produce SATISFIED without inversion,
    \* inverted form must produce UNSATISFIED (and vice versa).
    \* We check the concrete case: WEIGHT_LIMIT within limit + inverted => UNSATISFIED
    /\ ((phase = "done" /\ blockType = "WEIGHT_LIMIT" /\ inverted
         /\ spend.has_context
         /\ spend.tx_weight <= params.max_weight)
        => result = "UNSATISFIED")
    \* WEIGHT_LIMIT over limit + inverted => SATISFIED
    /\ ((phase = "done" /\ blockType = "WEIGHT_LIMIT" /\ inverted
         /\ spend.has_context
         /\ spend.tx_weight > params.max_weight)
        => result = "SATISFIED")
    \* INPUT_COUNT within bounds + inverted => UNSATISFIED
    /\ ((phase = "done" /\ blockType = "INPUT_COUNT" /\ inverted
         /\ spend.has_context
         /\ params.min_inputs <= params.max_inputs
         /\ spend.n_inputs >= params.min_inputs
         /\ spend.n_inputs <= params.max_inputs)
        => result = "UNSATISFIED")
    \* OUTPUT_COUNT outside bounds + inverted => SATISFIED
    /\ ((phase = "done" /\ blockType = "OUTPUT_COUNT" /\ inverted
         /\ spend.has_context
         /\ params.min_outputs <= params.max_outputs
         /\ (spend.n_outputs < params.min_outputs \/ spend.n_outputs > params.max_outputs))
        => result = "SATISFIED")
    \* ACCUMULATOR valid proof + inverted => UNSATISFIED (blocklist)
    /\ ((phase = "done" /\ blockType = "ACCUMULATOR" /\ inverted
         /\ params.proof_valid)
        => result = "UNSATISFIED")
    \* ACCUMULATOR invalid proof + inverted => SATISFIED
    /\ ((phase = "done" /\ blockType = "ACCUMULATOR" /\ inverted
         /\ ~params.proof_valid)
        => result = "SATISFIED")

\* I13: Non-invertible types: inverted => ERROR
Inv_NonInvertibleError ==
    (phase = "done" /\ inverted /\ blockType \notin InvertibleTypes)
    => result = "ERROR"

\* I14: No context => ERROR (except ACCUMULATOR which needs no tx context)
Inv_NoContextError ==
    (phase = "done" /\ ~spend.has_context /\ blockType # "ACCUMULATOR"
     /\ ~(inverted /\ blockType \notin InvertibleTypes))
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_EpochGateSatisfied
    /\ Inv_EpochGateUnsatisfied
    /\ Inv_WeightLimitSatisfied
    /\ Inv_WeightLimitUnsatisfied
    /\ Inv_InputCountSatisfied
    /\ Inv_InputCountUnsatisfied
    /\ Inv_OutputCountSatisfied
    /\ Inv_OutputCountUnsatisfied
    /\ Inv_RelativeValueSatisfied
    /\ Inv_OutputCheckSatisfied
    /\ Inv_OutputCheckScriptFail
    /\ Inv_InversionFlips
    /\ Inv_NonInvertibleError
    /\ Inv_NoContextError

=============================================================================
