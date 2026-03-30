------------------------- MODULE BlockPLC -------------------------
(***************************************************************************)
(* Model of the PLC (Programmable Logic Controller) block family           *)
(* (0x0600-0x06FF).  Representative subset of 6 out of 14 types:          *)
(*                                                                         *)
(*   HYSTERESIS_FEE (0x0601) - Fee rate within [low, high] band            *)
(*   COMPARE        (0x0641) - Numeric comparison against threshold        *)
(*   LATCH_SET      (0x0621) - Activates when state == 0 (key-consuming)   *)
(*   COUNTER_DOWN   (0x0631) - Decrement counter (key-consuming)           *)
(*   SEQUENCER      (0x0651) - Step sequencer state validation             *)
(*   COSIGN         (0x0681) - Cross-input conditions-hash matching        *)
(*                                                                         *)
(* Invertibility:                                                          *)
(*   HYSTERESIS_FEE, COMPARE, SEQUENCER are invertible.                    *)
(*   LATCH_SET, COUNTER_DOWN, COSIGN are NOT (key-consuming / special).    *)
(*   Inverted + non-invertible => ERROR.                                   *)
(*                                                                         *)
(* Verifies: accept/reject semantics for each type, inversion logic,       *)
(* fail-closed on missing context, operator coverage for COMPARE.          *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

CONSTANTS
    MaxValue,    \* Small model: 5.   VPS: 100.
    MaxSteps     \* Small model: 4.   VPS: 16.

Values == 0..MaxValue
Steps  == 0..(MaxSteps - 1)

(***************************************************************************)
(* Block types                                                             *)
(***************************************************************************)

BlockTypes == {
    "HYSTERESIS_FEE",
    "COMPARE",
    "LATCH_SET",
    "COUNTER_DOWN",
    "SEQUENCER",
    "COSIGN"
}

InvertibleTypes == {
    "HYSTERESIS_FEE",
    "COMPARE",
    "SEQUENCER"
}

\* COMPARE operators: 0=EQ, 1=NE, 2=GT, 3=LT, 4=GE, 5=LE
CompareOps == 0..5

(***************************************************************************)
(* Parameters for each block type                                          *)
(***************************************************************************)

HysteresisFeeParams == [
    low:  Values,
    high: Values
]

CompareParams == [
    op:      CompareOps,
    value_b: Values
]

LatchSetParams == [
    state:     {0, 1},
    has_signer: BOOLEAN
]

CounterDownParams == [
    count:     Values,
    has_signer: BOOLEAN
]

SequencerParams == [
    current: Steps,
    total:   1..MaxSteps
]

CosignParams == [
    has_context:      BOOLEAN,
    has_matching_input: BOOLEAN
]

(***************************************************************************)
(* Spending context                                                        *)
(***************************************************************************)

SpendCtx == [
    fee_rate:     Values,
    input_amount: Values,
    has_context:  BOOLEAN
]

(***************************************************************************)
(* Evaluation functions                                                    *)
(***************************************************************************)

EvalHysteresisFee(p, ctx) ==
    IF ~ctx.has_context THEN "ERROR"
    ELSE IF p.low > p.high THEN "UNSATISFIED"
    ELSE IF ctx.fee_rate >= p.low /\ ctx.fee_rate <= p.high THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalCompare(p, ctx) ==
    LET a == ctx.input_amount
        b == p.value_b
    IN
    CASE p.op = 0 -> IF a = b  THEN "SATISFIED" ELSE "UNSATISFIED"
      [] p.op = 1 -> IF a # b  THEN "SATISFIED" ELSE "UNSATISFIED"
      [] p.op = 2 -> IF a > b  THEN "SATISFIED" ELSE "UNSATISFIED"
      [] p.op = 3 -> IF a < b  THEN "SATISFIED" ELSE "UNSATISFIED"
      [] p.op = 4 -> IF a >= b THEN "SATISFIED" ELSE "UNSATISFIED"
      [] p.op = 5 -> IF a <= b THEN "SATISFIED" ELSE "UNSATISFIED"
      [] OTHER    -> "ERROR"

EvalLatchSet(p) ==
    IF ~p.has_signer THEN "ERROR"
    ELSE IF p.state = 0 THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalCounterDown(p) ==
    IF ~p.has_signer THEN "ERROR"
    ELSE IF p.count > 0 THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalSequencer(p) ==
    IF p.current < 0 \/ p.total <= 0 THEN "ERROR"
    ELSE IF p.current < p.total THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalCosign(p) ==
    IF ~p.has_context THEN "ERROR"
    ELSE IF p.has_matching_input THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* Inversion (ApplyInversion from evaluator.cpp)                           *)
(***************************************************************************)

ApplyInversion(raw, inverted) ==
    IF ~inverted THEN raw
    ELSE IF raw = "SATISFIED" THEN "UNSATISFIED"
    ELSE IF raw = "UNSATISFIED" THEN "SATISFIED"
    ELSE raw  \* ERROR never flips

(***************************************************************************)
(* Top-level block evaluation                                              *)
(***************************************************************************)

EvalBlock(btype, inverted, hfp, cmp, lsp, cdp, sqp, cop, ctx) ==
    \* Non-invertible types + inverted flag => ERROR (defense-in-depth)
    IF inverted /\ btype \notin InvertibleTypes THEN "ERROR"
    ELSE LET raw ==
        CASE btype = "HYSTERESIS_FEE" -> EvalHysteresisFee(hfp, ctx)
          [] btype = "COMPARE"        -> EvalCompare(cmp, ctx)
          [] btype = "LATCH_SET"      -> EvalLatchSet(lsp)
          [] btype = "COUNTER_DOWN"   -> EvalCounterDown(cdp)
          [] btype = "SEQUENCER"      -> EvalSequencer(sqp)
          [] btype = "COSIGN"         -> EvalCosign(cop)
         IN ApplyInversion(raw, inverted)

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES btype, inverted, hfp, cmp, lsp, cdp, sqp, cop, ctx, result, phase

vars == <<btype, inverted, hfp, cmp, lsp, cdp, sqp, cop, ctx, result, phase>>

Init ==
    /\ btype \in BlockTypes
    /\ inverted \in BOOLEAN
    /\ hfp \in HysteresisFeeParams
    /\ cmp \in CompareParams
    /\ lsp \in LatchSetParams
    /\ cdp \in CounterDownParams
    /\ sqp \in SequencerParams
    /\ cop \in CosignParams
    /\ ctx \in SpendCtx
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalBlock(btype, inverted, hfp, cmp, lsp, cdp, sqp, cop, ctx)
    /\ phase' = "done"
    /\ UNCHANGED <<btype, inverted, hfp, cmp, lsp, cdp, sqp, cop, ctx>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

Done == phase = "done"
NotInverted == ~inverted

\* I1: HYSTERESIS_FEE within band => SATISFIED
Inv_HysFeeInBand ==
    (Done /\ NotInverted /\ btype = "HYSTERESIS_FEE"
     /\ ctx.has_context /\ hfp.low <= hfp.high
     /\ ctx.fee_rate >= hfp.low /\ ctx.fee_rate <= hfp.high)
    => result = "SATISFIED"

\* I2: HYSTERESIS_FEE outside band => UNSATISFIED
Inv_HysFeeOutOfBand ==
    (Done /\ NotInverted /\ btype = "HYSTERESIS_FEE"
     /\ ctx.has_context /\ hfp.low <= hfp.high
     /\ (ctx.fee_rate < hfp.low \/ ctx.fee_rate > hfp.high))
    => result = "UNSATISFIED"

\* I3: COMPARE with correct operator result => SATISFIED
Inv_CompareCorrect ==
    (Done /\ NotInverted /\ btype = "COMPARE"
     /\ (  (cmp.op = 0 /\ ctx.input_amount = cmp.value_b)
         \/ (cmp.op = 1 /\ ctx.input_amount # cmp.value_b)
         \/ (cmp.op = 2 /\ ctx.input_amount > cmp.value_b)
         \/ (cmp.op = 3 /\ ctx.input_amount < cmp.value_b)
         \/ (cmp.op = 4 /\ ctx.input_amount >= cmp.value_b)
         \/ (cmp.op = 5 /\ ctx.input_amount <= cmp.value_b)))
    => result = "SATISFIED"

\* I4: COMPARE with incorrect result => UNSATISFIED
Inv_CompareIncorrect ==
    (Done /\ NotInverted /\ btype = "COMPARE"
     /\ (  (cmp.op = 0 /\ ctx.input_amount # cmp.value_b)
         \/ (cmp.op = 1 /\ ctx.input_amount = cmp.value_b)
         \/ (cmp.op = 2 /\ ctx.input_amount <= cmp.value_b)
         \/ (cmp.op = 3 /\ ctx.input_amount >= cmp.value_b)
         \/ (cmp.op = 4 /\ ctx.input_amount < cmp.value_b)
         \/ (cmp.op = 5 /\ ctx.input_amount > cmp.value_b)))
    => result = "UNSATISFIED"

\* I5: LATCH_SET with state=0 and valid signer => SATISFIED
Inv_LatchSetZero ==
    (Done /\ NotInverted /\ btype = "LATCH_SET"
     /\ lsp.state = 0 /\ lsp.has_signer)
    => result = "SATISFIED"

\* I6: LATCH_SET with state != 0 and valid signer => UNSATISFIED
Inv_LatchSetNonZero ==
    (Done /\ NotInverted /\ btype = "LATCH_SET"
     /\ lsp.state # 0 /\ lsp.has_signer)
    => result = "UNSATISFIED"

\* I7: COUNTER_DOWN with count > 0 and valid signer => SATISFIED
Inv_CounterDownPositive ==
    (Done /\ NotInverted /\ btype = "COUNTER_DOWN"
     /\ cdp.count > 0 /\ cdp.has_signer)
    => result = "SATISFIED"

\* I8: SEQUENCER correct step (current < total) => SATISFIED
Inv_SequencerValid ==
    (Done /\ NotInverted /\ btype = "SEQUENCER"
     /\ sqp.current >= 0 /\ sqp.total > 0
     /\ sqp.current < sqp.total)
    => result = "SATISFIED"

\* I9: COSIGN with matching input => SATISFIED
Inv_CosignMatch ==
    (Done /\ NotInverted /\ btype = "COSIGN"
     /\ cop.has_context /\ cop.has_matching_input)
    => result = "SATISFIED"

\* I10: COSIGN without matching input => UNSATISFIED
Inv_CosignNoMatch ==
    (Done /\ NotInverted /\ btype = "COSIGN"
     /\ cop.has_context /\ ~cop.has_matching_input)
    => result = "UNSATISFIED"

\* I11: Non-invertible types with inverted flag => ERROR
Inv_NonInvertibleError ==
    (Done /\ inverted /\ btype \notin InvertibleTypes)
    => result = "ERROR"

\* I12: Invertible types — inversion flips SATISFIED <-> UNSATISFIED
\*      (Verify by checking that inverted SATISFIED becomes UNSATISFIED
\*       and inverted UNSATISFIED becomes SATISFIED; ERROR stays ERROR.)
Inv_InversionFlips ==
    \* If an invertible type would be SATISFIED without inversion,
    \* then with inversion it must be UNSATISFIED, and vice versa.
    \* We verify this structurally for HYSTERESIS_FEE as representative.
    (Done /\ inverted /\ btype = "HYSTERESIS_FEE"
     /\ ctx.has_context /\ hfp.low <= hfp.high
     /\ ctx.fee_rate >= hfp.low /\ ctx.fee_rate <= hfp.high)
    => result = "UNSATISFIED"

Inv_InversionFlipsReverse ==
    (Done /\ inverted /\ btype = "HYSTERESIS_FEE"
     /\ ctx.has_context /\ hfp.low <= hfp.high
     /\ (ctx.fee_rate < hfp.low \/ ctx.fee_rate > hfp.high))
    => result = "SATISFIED"

Inv_InversionPreservesError ==
    (Done /\ inverted /\ btype = "HYSTERESIS_FEE"
     /\ ~ctx.has_context)
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_HysFeeInBand
    /\ Inv_HysFeeOutOfBand
    /\ Inv_CompareCorrect
    /\ Inv_CompareIncorrect
    /\ Inv_LatchSetZero
    /\ Inv_LatchSetNonZero
    /\ Inv_CounterDownPositive
    /\ Inv_SequencerValid
    /\ Inv_CosignMatch
    /\ Inv_CosignNoMatch
    /\ Inv_NonInvertibleError
    /\ Inv_InversionFlips
    /\ Inv_InversionFlipsReverse
    /\ Inv_InversionPreservesError

=============================================================================
