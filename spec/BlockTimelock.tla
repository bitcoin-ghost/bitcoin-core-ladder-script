------------------------- MODULE BlockTimelock -------------------------
(***************************************************************************)
(* Model of the timelock block type family:                                *)
(*   - CSV       (0x0101): relative, block-height (BIP 68)                *)
(*   - CSV_TIME  (0x0102): relative, time-based (BIP 68 type flag)        *)
(*   - CLTV      (0x0103): absolute, block-height                         *)
(*   - CLTV_TIME (0x0104): absolute, MTP-based                            *)
(*                                                                         *)
(* All are invertible (not key-consuming).                                 *)
(* Fail-closed: ERROR when tx context missing.                             *)
(*                                                                         *)
(* Reference: evaluator.cpp -- EvalCSVBlock, EvalCSVTimeBlock,             *)
(*            EvalCLTVBlock, EvalCLTVTimeBlock                             *)
(***************************************************************************)

EXTENDS Integers

CONSTANTS
    MaxHeight,    \* VPS: 1000
    MaxTime,      \* VPS: 1000
    MaxSequence   \* VPS: 65535

Heights == 0..MaxHeight
Times   == 0..MaxTime

\* BIP 68 sequence encoding constants (scaled to model range)
SEQUENCE_LOCKTIME_DISABLE_FLAG == 2147483648   \* bit 31
SEQUENCE_LOCKTIME_TYPE_FLAG    == 4194304      \* bit 22
SEQUENCE_MASK                  == 65535        \* lower 16 bits

\* CLTV domain boundary
LOCKTIME_THRESHOLD == 500000000

BlockTypes == {"CSV", "CSV_TIME", "CLTV", "CLTV_TIME"}

(***************************************************************************)
(* Block parameters (from conditions)                                      *)
(***************************************************************************)

CSVParams == [
    block_type: {"CSV"},
    delay_blocks: Heights
]

CSVTimeParams == [
    block_type: {"CSV_TIME"},
    delay_time: Times
]

CLTVParams == [
    block_type: {"CLTV"},
    target_height: Heights
]

CLTVTimeParams == [
    block_type: {"CLTV_TIME"},
    target_time: Times
]

AllParams == CSVParams \union CSVTimeParams \union CLTVParams \union CLTVTimeParams

(***************************************************************************)
(* Spending transaction properties                                         *)
(***************************************************************************)

SpendTx == [
    has_context: BOOLEAN,
    nSequence: 0..MaxSequence,
    nSequence_disable: BOOLEAN,     \* bit 31 set
    nSequence_type_flag: BOOLEAN,   \* bit 22 set (TRUE = time-based)
    nLockTime: 0..(MaxHeight + MaxTime),
    nLockTime_is_time: BOOLEAN      \* TRUE when nLockTime >= 500000000
]

(***************************************************************************)
(* Evaluation functions                                                    *)
(***************************************************************************)

EvalCSV(p, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF spend.nSequence_disable THEN "UNSATISFIED"
    ELSE IF spend.nSequence >= p.delay_blocks THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalCSVTime(p, spend) ==
    IF ~spend.has_context THEN "ERROR"
    ELSE IF spend.nSequence_disable THEN "UNSATISFIED"
    ELSE IF spend.nSequence_type_flag /\ spend.nSequence >= p.delay_time
         THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalCLTV(p, spend) ==
    IF ~spend.has_context THEN "ERROR"
    \* Cross-domain: height target but time locktime
    ELSE IF spend.nLockTime_is_time THEN "UNSATISFIED"
    ELSE IF spend.nLockTime >= p.target_height THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalCLTVTime(p, spend) ==
    IF ~spend.has_context THEN "ERROR"
    \* Cross-domain: time target but height locktime
    ELSE IF ~spend.nLockTime_is_time THEN "UNSATISFIED"
    ELSE IF spend.nLockTime >= p.target_time THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalTimelock(p, spend) ==
    CASE p.block_type = "CSV"       -> EvalCSV(p, spend)
      [] p.block_type = "CSV_TIME"  -> EvalCSVTime(p, spend)
      [] p.block_type = "CLTV"      -> EvalCLTV(p, spend)
      [] p.block_type = "CLTV_TIME" -> EvalCLTVTime(p, spend)

(***************************************************************************)
(* Inversion (SATISFIED <-> UNSATISFIED, ERROR stays ERROR)                *)
(***************************************************************************)

ApplyInversion(raw, inv) ==
    IF ~inv THEN raw
    ELSE CASE raw = "SATISFIED"   -> "UNSATISFIED"
           [] raw = "UNSATISFIED" -> "SATISFIED"
           [] raw = "ERROR"       -> "ERROR"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES params, spend, inverted, result, phase

vars == <<params, spend, inverted, result, phase>>

Init ==
    /\ params \in AllParams
    /\ spend \in SpendTx
    /\ inverted \in BOOLEAN
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = ApplyInversion(EvalTimelock(params, spend), inverted)
    /\ phase' = "done"
    /\ UNCHANGED <<params, spend, inverted>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: CSV with nSequence >= delay -> SATISFIED
Inv_CSVSatisfied ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CSV"
     /\ spend.has_context
     /\ ~spend.nSequence_disable
     /\ spend.nSequence >= params.delay_blocks)
    => result = "SATISFIED"

\* I2: CSV with nSequence < delay -> UNSATISFIED
Inv_CSVUnsatisfied ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CSV"
     /\ spend.has_context
     /\ ~spend.nSequence_disable
     /\ spend.nSequence < params.delay_blocks)
    => result = "UNSATISFIED"

\* I3: CSV with disable flag -> UNSATISFIED
Inv_CSVDisableFlag ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CSV"
     /\ spend.has_context
     /\ spend.nSequence_disable)
    => result = "UNSATISFIED"

\* I4: CSV_TIME with time-nSequence >= delay -> SATISFIED
Inv_CSVTimeSatisfied ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CSV_TIME"
     /\ spend.has_context
     /\ ~spend.nSequence_disable
     /\ spend.nSequence_type_flag
     /\ spend.nSequence >= params.delay_time)
    => result = "SATISFIED"

\* I5: CLTV with nLockTime >= target (both height domain) -> SATISFIED
Inv_CLTVSatisfied ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CLTV"
     /\ spend.has_context
     /\ ~spend.nLockTime_is_time
     /\ spend.nLockTime >= params.target_height)
    => result = "SATISFIED"

\* I6: CLTV with nLockTime < target -> UNSATISFIED
Inv_CLTVUnsatisfied ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CLTV"
     /\ spend.has_context
     /\ ~spend.nLockTime_is_time
     /\ spend.nLockTime < params.target_height)
    => result = "UNSATISFIED"

\* I7: CLTV cross-domain (height target, time locktime) -> UNSATISFIED
Inv_CLTVCrossDomain ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CLTV"
     /\ spend.has_context
     /\ spend.nLockTime_is_time)
    => result = "UNSATISFIED"

\* I8: CLTV_TIME cross-domain (time target, height locktime) -> UNSATISFIED
Inv_CLTVTimeCrossDomain ==
    (phase = "done" /\ ~inverted
     /\ params.block_type = "CLTV_TIME"
     /\ spend.has_context
     /\ ~spend.nLockTime_is_time)
    => result = "UNSATISFIED"

\* I9: All timelocks invertible (inversion flips SATISFIED <-> UNSATISFIED)
Inv_InversionFlips ==
    /\ (phase = "done" /\ inverted
        /\ spend.has_context
        /\ EvalTimelock(params, spend) = "SATISFIED")
       => result = "UNSATISFIED"
    /\ (phase = "done" /\ inverted
        /\ spend.has_context
        /\ EvalTimelock(params, spend) = "UNSATISFIED")
       => result = "SATISFIED"

\* I10: No context -> ERROR (fail-closed, even under inversion)
Inv_NoContextError ==
    (phase = "done" /\ ~spend.has_context)
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_CSVSatisfied
    /\ Inv_CSVUnsatisfied
    /\ Inv_CSVDisableFlag
    /\ Inv_CSVTimeSatisfied
    /\ Inv_CLTVSatisfied
    /\ Inv_CLTVUnsatisfied
    /\ Inv_CLTVCrossDomain
    /\ Inv_CLTVTimeCrossDomain
    /\ Inv_InversionFlips
    /\ Inv_NoContextError

=============================================================================
