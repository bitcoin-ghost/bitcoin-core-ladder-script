------------------------ MODULE LadderCovenant ------------------------
(***************************************************************************)
(* Model the recursion/covenant blocks in Ladder Script.                  *)
(* Verifies termination, depth bounding, and enforcement semantics for    *)
(* RECURSE_SAME, RECURSE_COUNT, RECURSE_UNTIL, RECURSE_SPLIT,           *)
(* RECURSE_MODIFIED, RECURSE_DECAY, and CTV.                             *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, Naturals

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    MaxDepth,         \* Maximum recursion depth (e.g. 3)
    MaxSplits,        \* Maximum split count (e.g. 3)
    MinSats           \* Minimum satoshis per output (e.g. 546)

CovenantTypes == {
    "RECURSE_SAME", "RECURSE_COUNT", "RECURSE_UNTIL",
    "RECURSE_SPLIT", "RECURSE_MODIFIED", "RECURSE_DECAY", "CTV"
}

(***************************************************************************)
(* RECURSE_SAME: output root must equal input root, depth bounded         *)
(***************************************************************************)

VARIABLES
    covType,         \* Current covenant type
    depth,           \* Current depth / count / remaining steps
    blockHeight,     \* Current block height (for RECURSE_UNTIL)
    untilHeight,     \* Target height (for RECURSE_UNTIL)
    splitCount,      \* Current split budget (for RECURSE_SPLIT)
    outputSats,      \* Satoshis in output (for RECURSE_SPLIT)
    parameter,       \* Current parameter value (for RECURSE_DECAY)
    decayPerStep,    \* Decay amount per step (for RECURSE_DECAY)
    rootMatch,       \* Whether output root matches input root
    templateMatch,   \* Whether output matches CTV template
    terminated,      \* Whether the covenant has terminated
    phase

vars == <<covType, depth, blockHeight, untilHeight, splitCount, outputSats,
          parameter, decayPerStep, rootMatch, templateMatch, terminated, phase>>

Init ==
    /\ covType \in CovenantTypes
    /\ depth \in 0..MaxDepth
    /\ blockHeight \in 0..5
    /\ untilHeight \in 0..5
    /\ splitCount \in 0..MaxSplits
    /\ outputSats \in {MinSats - 1, MinSats, MinSats + 100, MinSats + 1000}
    /\ parameter \in 0..MaxDepth
    /\ decayPerStep \in 1..2
    /\ rootMatch \in BOOLEAN
    /\ templateMatch \in BOOLEAN
    /\ terminated = FALSE
    /\ phase = "step"

(***************************************************************************)
(* Covenant step evaluation                                                *)
(* Returns [result, newDepth, terminated]                                  *)
(***************************************************************************)

EvalStep(ct, d, bh, uh, sc, osat, param, dps, rm, tm) ==
    CASE ct = "RECURSE_SAME" ->
        \* Depth must be > 0 to continue. Output root must match.
        IF d = 0 THEN [result |-> "TERMINATED", newDepth |-> 0, term |-> TRUE]
        ELSE IF ~rm THEN [result |-> "UNSATISFIED", newDepth |-> d, term |-> FALSE]
        ELSE [result |-> "SATISFIED", newDepth |-> d - 1, term |-> FALSE]

      [] ct = "RECURSE_COUNT" ->
        \* Count decreases by 1 each step. Terminates at 0.
        IF d = 0 THEN [result |-> "TERMINATED", newDepth |-> 0, term |-> TRUE]
        ELSE [result |-> "SATISFIED", newDepth |-> d - 1, term |-> FALSE]

      [] ct = "RECURSE_UNTIL" ->
        \* Terminates when block_height >= until_height
        IF bh >= uh THEN [result |-> "TERMINATED", newDepth |-> d, term |-> TRUE]
        ELSE IF ~rm THEN [result |-> "UNSATISFIED", newDepth |-> d, term |-> FALSE]
        ELSE [result |-> "SATISFIED", newDepth |-> d, term |-> FALSE]

      [] ct = "RECURSE_SPLIT" ->
        \* Split count bounded by max_splits. min_sats enforced.
        IF sc = 0 THEN [result |-> "TERMINATED", newDepth |-> d, term |-> TRUE]
        ELSE IF osat < MinSats THEN [result |-> "ERROR", newDepth |-> d, term |-> FALSE]
        ELSE [result |-> "SATISFIED", newDepth |-> d, term |-> FALSE]

      [] ct = "RECURSE_MODIFIED" ->
        \* Single field mutation. Depth bounded.
        IF d = 0 THEN [result |-> "TERMINATED", newDepth |-> 0, term |-> TRUE]
        ELSE [result |-> "SATISFIED", newDepth |-> d - 1, term |-> FALSE]

      [] ct = "RECURSE_DECAY" ->
        \* Parameter decreases by decay_per_step. Terminates at 0.
        IF param = 0 THEN [result |-> "TERMINATED", newDepth |-> 0, term |-> TRUE]
        ELSE LET newParam == IF param >= dps THEN param - dps ELSE 0
             IN [result |-> "SATISFIED", newDepth |-> newParam, term |-> FALSE]

      [] ct = "CTV" ->
        \* Template hash binds outputs exactly. No recursion.
        IF tm THEN [result |-> "SATISFIED", newDepth |-> 0, term |-> TRUE]
        ELSE [result |-> "UNSATISFIED", newDepth |-> 0, term |-> TRUE]

Next ==
    \/ /\ phase = "step"
       /\ ~terminated
       /\ LET eval == EvalStep(covType, depth, blockHeight, untilHeight,
                                splitCount, outputSats, parameter, decayPerStep,
                                rootMatch, templateMatch)
          IN \* Only continue stepping if SATISFIED (covenant continues)
             \* UNSATISFIED/ERROR/TERMINATED all end the chain
             /\ terminated' = (eval.term \/ eval.result \in {"UNSATISFIED", "ERROR", "TERMINATED"})
             /\ depth' = eval.newDepth
             \* Block height monotonically increases (bounded for tractability)
             /\ blockHeight' = IF blockHeight < 8 THEN blockHeight + 1 ELSE blockHeight
             /\ parameter' = IF covType = "RECURSE_DECAY" /\ eval.result = "SATISFIED"
                             THEN (IF parameter >= decayPerStep THEN parameter - decayPerStep ELSE 0)
                             ELSE parameter
             /\ splitCount' = IF covType = "RECURSE_SPLIT" /\ eval.result = "SATISFIED" /\ splitCount > 0
                              THEN splitCount - 1
                              ELSE splitCount
             /\ phase' = IF (eval.term \/ eval.result \in {"UNSATISFIED", "ERROR", "TERMINATED"})
                         THEN "done" ELSE "step"
             /\ UNCHANGED <<covType, untilHeight, outputSats, decayPerStep,
                            rootMatch, templateMatch>>
    \/ /\ phase = "step"
       /\ terminated
       /\ phase' = "done"
       /\ UNCHANGED <<covType, depth, blockHeight, untilHeight, splitCount,
                      outputSats, parameter, decayPerStep, rootMatch,
                      templateMatch, terminated>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* RECURSE_SAME: depth bounded
Inv_RecurseSameDepthBounded ==
    covType = "RECURSE_SAME" => depth \in 0..MaxDepth

\* RECURSE_COUNT: strictly decreasing, terminates at 0
Inv_RecurseCountBounded ==
    covType = "RECURSE_COUNT" => depth \in 0..MaxDepth

\* RECURSE_SPLIT: split count bounded, min_sats enforced
Inv_RecurseSplitBounded ==
    covType = "RECURSE_SPLIT" => splitCount \in 0..MaxSplits

\* RECURSE_SPLIT: dust prevention
Inv_RecurseSplitNoDust ==
    covType = "RECURSE_SPLIT" =>
        LET eval == EvalStep(covType, depth, blockHeight, untilHeight,
                             splitCount, outputSats, parameter, decayPerStep,
                             rootMatch, templateMatch)
        IN (outputSats < MinSats /\ splitCount > 0) => eval.result = "ERROR"

\* RECURSE_DECAY: parameter bounded
Inv_RecurseDecayBounded ==
    covType = "RECURSE_DECAY" => parameter \in 0..MaxDepth

\* Block height is bounded
Inv_HeightBounded ==
    blockHeight \in 0..8

\* CTV: template hash binds exactly (no freedom)
Inv_CTVBindsExactly ==
    covType = "CTV" =>
        LET eval == EvalStep(covType, depth, blockHeight, untilHeight,
                             splitCount, outputSats, parameter, decayPerStep,
                             rootMatch, templateMatch)
        IN /\ (templateMatch => eval.result = "SATISFIED")
           /\ (~templateMatch => eval.result = "UNSATISFIED")
           /\ eval.term = TRUE  \* CTV is always terminal

\* RECURSE_UNTIL: terminates when height >= target
Inv_RecurseUntilTermination ==
    covType = "RECURSE_UNTIL" =>
        LET eval == EvalStep(covType, depth, blockHeight, untilHeight,
                             splitCount, outputSats, parameter, decayPerStep,
                             rootMatch, templateMatch)
        IN blockHeight >= untilHeight => eval.term = TRUE

\* No recursion pattern loops indefinitely: all have bounded depth/count/parameter
Inv_TerminationBounded ==
    \/ depth \in 0..MaxDepth
    \/ parameter \in 0..MaxDepth
    \/ splitCount \in 0..MaxSplits

\* Temporal property: all covenants eventually terminate
EventualTermination == <>(terminated = TRUE)

\* Combined invariants
SafetyInvariant ==
    /\ Inv_RecurseSameDepthBounded
    /\ Inv_RecurseCountBounded
    /\ Inv_RecurseSplitBounded
    /\ Inv_RecurseSplitNoDust
    /\ Inv_RecurseDecayBounded
    /\ Inv_HeightBounded
    /\ Inv_CTVBindsExactly
    /\ Inv_RecurseUntilTermination
    /\ Inv_TerminationBounded

=============================================================================
