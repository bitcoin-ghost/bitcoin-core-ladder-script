---------------------- MODULE LadderComposition ----------------------
(***************************************************************************)
(* Formal verification of Ladder Script AND/OR composition semantics.      *)
(* Proves rung AND logic, ladder OR logic, and relay evaluation order.     *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxBlocks,       \* Max blocks per rung (e.g. 3)
    MaxRungs,        \* Max rungs per ladder (e.g. 3)
    MaxRelays        \* Max relays (e.g. 2)

Results == {"SAT", "UNSAT", "ERR"}

(***************************************************************************)
(* Rung evaluation: AND logic                                              *)
(***************************************************************************)

\* A rung is a sequence of block results
\* AND: all must be SAT, any ERR → ERR, otherwise UNSAT
EvalRung(blockResults) ==
    IF Len(blockResults) = 0 THEN "ERR"
    ELSE IF \E i \in 1..Len(blockResults) : blockResults[i] = "ERR"
    THEN "ERR"
    ELSE IF \A i \in 1..Len(blockResults) : blockResults[i] = "SAT"
    THEN "SAT"
    ELSE "UNSAT"

(***************************************************************************)
(* Ladder evaluation: OR logic (first-wins)                                *)
(***************************************************************************)

\* A ladder is a sequence of rung results
\* OR: first SAT wins, any ERR → ERR, all UNSAT → UNSAT
RECURSIVE EvalLadderHelper(_, _)
EvalLadderHelper(rungResults, idx) ==
    IF idx > Len(rungResults) THEN [result |-> "UNSAT", rungIdx |-> 0]
    ELSE
        CASE rungResults[idx] = "SAT" ->
                [result |-> "SAT", rungIdx |-> idx]
          [] rungResults[idx] = "ERR" ->
                [result |-> "ERR", rungIdx |-> 0]
          [] OTHER ->
                EvalLadderHelper(rungResults, idx + 1)

EvalLadder(rungResults) ==
    IF Len(rungResults) = 0 THEN [result |-> "UNSAT", rungIdx |-> 0]
    ELSE EvalLadderHelper(rungResults, 1)

(***************************************************************************)
(* Relay evaluation: forward-only DAG                                      *)
(***************************************************************************)

\* Relay graph: relay i can depend on relays 0..i-1
\* intrinsics[i] = intrinsic result of relay i (ignoring deps)
\* deps[i] = set of relay indices that relay i requires
\*
\* Evaluation: relay i is SAT iff all deps are SAT AND intrinsic is SAT
RECURSIVE EvalRelaysHelper(_, _, _, _)
EvalRelaysHelper(intrinsics, deps, results, idx) ==
    IF idx > Len(intrinsics) THEN results
    ELSE
        LET depsMet == \A d \in deps[idx] :
                           d >= 1 /\ d <= Len(results) /\ results[d] = "SAT"
        IN
        IF ~depsMet THEN
            EvalRelaysHelper(intrinsics, deps, Append(results, "UNSAT"), idx + 1)
        ELSE
            EvalRelaysHelper(intrinsics, deps, Append(results, intrinsics[idx]), idx + 1)

EvalRelays(intrinsics, deps) ==
    EvalRelaysHelper(intrinsics, deps, <<>>, 1)

(***************************************************************************)
(* State machine for model checking                                        *)
(***************************************************************************)

VARIABLES
    blocks,      \* Sequence of block results for current rung
    rungs,       \* Sequence of rung results for current ladder
    phase        \* "rung_check" | "ladder_check" | "relay_check" | "done"

vars == <<blocks, rungs, phase>>

Init ==
    /\ blocks \in [1..MaxBlocks -> Results]
    /\ rungs \in [1..MaxRungs -> Results]
    /\ phase = "rung_check"

Next ==
    \/ /\ phase = "rung_check"
       /\ phase' = "ladder_check"
       /\ UNCHANGED <<blocks, rungs>>
    \/ /\ phase = "ladder_check"
       /\ phase' = "relay_check"
       /\ UNCHANGED <<blocks, rungs>>
    \/ /\ phase = "relay_check"
       /\ phase' = "done"
       /\ UNCHANGED <<blocks, rungs>>
    \/ /\ phase = "done"
       /\ blocks' \in [1..MaxBlocks -> Results]
       /\ rungs' \in [1..MaxRungs -> Results]
       /\ phase' = "rung_check"

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* AND semantics: rung with all SAT blocks → SAT
Inv_AllSatRungIsSat ==
    LET allSat == [i \in 1..MaxBlocks |-> "SAT"]
    IN EvalRung(allSat) = "SAT"

\* AND semantics: single ERR block → ERR
Inv_SingleErrRungIsErr ==
    \A pos \in 1..MaxBlocks :
        LET withErr == [i \in 1..MaxBlocks |-> IF i = pos THEN "ERR" ELSE "SAT"]
        IN EvalRung(withErr) = "ERR"

\* AND semantics: single UNSAT (no ERR) → UNSAT
Inv_SingleUnsatRungIsUnsat ==
    \A pos \in 1..MaxBlocks :
        LET withUnsat == [i \in 1..MaxBlocks |-> IF i = pos THEN "UNSAT" ELSE "SAT"]
        IN EvalRung(withUnsat) = "UNSAT"

\* AND semantics: ERR takes priority over UNSAT
Inv_ErrPriorityOverUnsat ==
    \A pos1, pos2 \in 1..MaxBlocks :
        pos1 # pos2 =>
            LET mixed == [i \in 1..MaxBlocks |->
                    IF i = pos1 THEN "ERR"
                    ELSE IF i = pos2 THEN "UNSAT"
                    ELSE "SAT"]
            IN EvalRung(mixed) = "ERR"

\* OR semantics: first SAT wins
Inv_FirstSatWins ==
    LET eval == EvalLadder(rungs)
    IN eval.result = "SAT" =>
        \* rungIdx is the first SAT
        /\ rungs[eval.rungIdx] = "SAT"
        /\ \A i \in 1..(eval.rungIdx - 1) : rungs[i] # "SAT"

\* OR semantics: if no SAT appears before the first ERR, result is ERR
Inv_AnyErrLadderIsErr ==
    LET eval == EvalLadder(rungs)
        \* Check if any ERR appears with no prior SAT
        errBeforeSat == \E i \in 1..MaxRungs :
                            rungs[i] = "ERR" /\
                            \A j \in 1..(i-1) : rungs[j] # "SAT"
    IN errBeforeSat => eval.result = "ERR"

\* OR semantics: all UNSAT → UNSAT
Inv_AllUnsatLadderIsUnsat ==
    (\A i \in 1..MaxRungs : rungs[i] = "UNSAT") =>
        EvalLadder(rungs).result = "UNSAT"

\* Relay forward-only: deps < own index
Inv_RelayForwardOnly ==
    \A n \in 1..MaxRelays :
        LET deps == [i \in 1..n |-> IF i = 1 THEN {} ELSE {i-1}]
            intrinsics == [i \in 1..n |-> "SAT"]
            results == EvalRelays(intrinsics, deps)
        IN
        \* All SAT with forward-only deps → all SAT
        \A i \in 1..n : results[i] = "SAT"

\* Relay cascading failure: failed dep → failed relay
Inv_RelayCascade ==
    LET deps == [i \in 1..2 |-> IF i = 1 THEN {} ELSE {1}]
        intrinsics == [i \in 1..2 |-> IF i = 1 THEN "UNSAT" ELSE "SAT"]
        results == EvalRelays(intrinsics, deps)
    IN
    /\ results[1] = "UNSAT"
    /\ results[2] = "UNSAT"  \* Cascades: dep 1 failed → relay 2 fails

\* Empty rung is ERROR
Inv_EmptyRungError ==
    EvalRung(<<>>) = "ERR"

\* Empty ladder is UNSAT (not SAT)
Inv_EmptyLadderUnsat ==
    EvalLadder(<<>>).result = "UNSAT"

\* Current blocks evaluation is consistent
Inv_CurrentRungConsistent ==
    EvalRung(blocks) \in Results

\* Combined safety
SafetyInvariant ==
    /\ Inv_AllSatRungIsSat
    /\ Inv_SingleErrRungIsErr
    /\ Inv_SingleUnsatRungIsUnsat
    /\ Inv_ErrPriorityOverUnsat
    /\ Inv_FirstSatWins
    /\ Inv_AnyErrLadderIsErr
    /\ Inv_AllUnsatLadderIsUnsat
    /\ Inv_RelayForwardOnly
    /\ Inv_RelayCascade
    /\ Inv_EmptyRungError
    /\ Inv_EmptyLadderUnsat
    /\ Inv_CurrentRungConsistent

=============================================================================
