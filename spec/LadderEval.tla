------------------------- MODULE LadderEval -------------------------
(***************************************************************************)
(* Model of the core AND/OR evaluation logic in evaluator.cpp:             *)
(*   - A ladder has rungs (OR logic: first satisfied rung wins)            *)
(*   - Each rung has blocks (AND logic: all must be SATISFIED)             *)
(*   - Relays are evaluated before rungs; each relay has blocks (AND)      *)
(*     and relay_refs (forward-only DAG to earlier relays)                 *)
(*   - Inversion flips SATISFIED<->UNSATISFIED but preserves ERROR;       *)
(*     non-invertible (key-consuming) blocks with inverted=TRUE -> ERROR   *)
(*   - Empty rung -> ERROR, empty ladder -> UNSATISFIED (false)            *)
(*   - First-wins: once a rung is SATISFIED, its index is returned         *)
(*   - AND short-circuit: first non-SATISFIED result returned              *)
(*                                                                         *)
(* Verifies: empty-ladder/rung semantics, first-wins ordering,             *)
(* inversion correctness, relay dependency propagation, AND/OR logic.      *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxRungs,          \* WSL2: 3, VPS: 6
    MaxBlocksPerRung,  \* WSL2: 3, VPS: 6
    MaxRelays          \* WSL2: 2, VPS: 4

(***************************************************************************)
(* Block and result types                                                  *)
(***************************************************************************)

Results == {"SATISFIED", "UNSATISFIED", "ERROR"}

\* A block has a raw evaluation result and inversion/invertibility flags.
\* invertible=FALSE models key-consuming blocks (SIG, MULTISIG, etc).
BlockType == [
    raw_result  : Results,
    inverted    : BOOLEAN,
    invertible  : BOOLEAN
]

\* Apply inversion per ApplyInversion() in evaluator.cpp
ApplyInversion(raw, inv) ==
    IF ~inv THEN raw
    ELSE IF raw = "SATISFIED"   THEN "UNSATISFIED"
    ELSE IF raw = "UNSATISFIED" THEN "SATISFIED"
    ELSE "ERROR"  \* ERROR never flips

\* Evaluate a single block: non-invertible + inverted -> ERROR
EvalBlock(block) ==
    IF block.inverted /\ ~block.invertible THEN "ERROR"
    ELSE ApplyInversion(block.raw_result, block.inverted)

(***************************************************************************)
(* AND evaluation (rung / relay blocks)                                    *)
(* Short-circuits on first non-SATISFIED result.                           *)
(* Empty block sequence -> ERROR (per evaluator.cpp).                      *)
(***************************************************************************)

RECURSIVE EvalAND(_)
EvalAND(blocks) ==
    IF Len(blocks) = 0 THEN "ERROR"
    ELSE LET r == EvalBlock(blocks[1])
         IN IF r # "SATISFIED" THEN r
            ELSE IF Len(blocks) = 1 THEN "SATISFIED"
            ELSE EvalAND(SubSeq(blocks, 2, Len(blocks)))

(***************************************************************************)
(* Relay evaluation                                                        *)
(* Relays form a forward-only DAG: relay i can reference only relays < i.  *)
(* Each relay has blocks (AND) and relay_refs.                             *)
(* If any relay_ref is not SATISFIED, relay is UNSATISFIED.                *)
(* Empty relay blocks -> ERROR (propagates as ladder failure).             *)
(***************************************************************************)

RelayType == [
    blocks     : Seq(BlockType),
    relay_refs : SUBSET (0..(MaxRelays - 1))
]

\* Evaluate relays in order, returning a function relay_index -> result.
\* error_flag is set TRUE if any relay has ERROR (ladder fails).
RECURSIVE EvalRelaysHelper(_, _, _, _)
EvalRelaysHelper(relays, idx, acc, err) ==
    IF idx > Len(relays) THEN <<acc, err>>
    ELSE
        LET relay == relays[idx]
            \* relay indices are 0-based in C++; TLA+ sequences are 1-based.
            \* relay_refs contains 0-based indices; acc maps 0-based index -> result.
            refs_met == \A ref \in relay.relay_refs :
                            ref < (idx - 1) /\ acc[ref] = "SATISFIED"
            raw_and  == EvalAND(relay.blocks)
            result   == IF raw_and = "ERROR" THEN "ERROR"
                        ELSE IF ~refs_met THEN "UNSATISFIED"
                        ELSE raw_and
            new_acc  == [acc EXCEPT ![idx - 1] = result]
            new_err  == err \/ (result = "ERROR")
        IN EvalRelaysHelper(relays, idx + 1, new_acc, new_err)

EvalRelays(relays) ==
    LET init == [i \in 0..(MaxRelays - 1) |-> "UNSATISFIED"]
    IN EvalRelaysHelper(relays, 1, init, FALSE)

(***************************************************************************)
(* Rung evaluation                                                         *)
(* Blocks must all be SATISFIED (AND). relay_refs must all be SATISFIED.   *)
(* Empty blocks -> ERROR.                                                  *)
(***************************************************************************)

RungType == [
    blocks     : Seq(BlockType),
    relay_refs : SUBSET (0..(MaxRelays - 1))
]

EvalRung(rung, relay_results) ==
    IF Len(rung.blocks) = 0 THEN "ERROR"
    ELSE
        LET refs_met == \A ref \in rung.relay_refs :
                            relay_results[ref] = "SATISFIED"
        IN IF ~refs_met THEN "UNSATISFIED"
           ELSE EvalAND(rung.blocks)

(***************************************************************************)
(* Ladder evaluation                                                       *)
(* OR logic across rungs: first SATISFIED rung wins.                       *)
(* Empty ladder -> UNSATISFIED (returns false).                            *)
(* If relay evaluation hits ERROR, ladder fails (returns false).           *)
(***************************************************************************)

LadderType == [
    rungs  : Seq(RungType),
    relays : Seq(RelayType)
]

RECURSIVE FindSatisfiedRung(_, _, _)
FindSatisfiedRung(rungs, relay_results, idx) ==
    IF idx > Len(rungs) THEN <<"UNSATISFIED", -1>>
    ELSE
        LET r == EvalRung(rungs[idx], relay_results)
        IN IF r = "SATISFIED" THEN <<"SATISFIED", idx - 1>>  \* 0-based index
           ELSE FindSatisfiedRung(rungs, relay_results, idx + 1)
           \* Per evaluator.cpp: ERROR rungs are not SATISFIED, loop continues

\* EvalLadder returns <<result, satisfied_rung_index>>.
\* Per evaluator.cpp, EvalLadder returns bool (true/false); we map
\* true -> "SATISFIED" and false -> "UNSATISFIED". Relay errors cause
\* the ladder to return false (UNSATISFIED), not a separate ERROR state.
EvalLadder(lad) ==
    IF Len(lad.rungs) = 0 THEN <<"UNSATISFIED", -1>>
    ELSE
        LET relay_eval == EvalRelays(lad.relays)
            relay_results == relay_eval[1]
            relay_error   == relay_eval[2]
        IN IF relay_error THEN <<"UNSATISFIED", -1>>
           ELSE FindSatisfiedRung(lad.rungs, relay_results, 1)

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES ladder, result, satisfied_rung, phase

vars == <<ladder, result, satisfied_rung, phase>>

\* Block sequences of length 0..MaxBlocksPerRung
BlockSeqs == UNION {[1..n -> BlockType] : n \in 0..MaxBlocksPerRung}

\* Relay ref subsets: relay at 1-based position p may reference 0..(p-2).
RelayRefSets(pos) ==
    IF pos <= 1 THEN {{}}
    ELSE SUBSET (0..(pos - 2))

\* Rung relay ref subsets given actual relay count.
RungRelayRefSets(num_relays) ==
    IF num_relays = 0 THEN {{}}
    ELSE SUBSET (0..(num_relays - 1))

\* Build the set of valid relay sequences of length n.
\* Each relay's relay_refs are constrained to earlier indices (forward DAG).
RECURSIVE ValidRelaySeqs(_)
ValidRelaySeqs(n) ==
    IF n = 0 THEN {<<>>}
    ELSE
        LET prev == ValidRelaySeqs(n - 1)
        IN {Append(s, r) : s \in prev,
                            r \in [blocks     : BlockSeqs,
                                   relay_refs : RelayRefSets(n)]}

AllValidRelaySeqs == UNION {ValidRelaySeqs(n) : n \in 0..MaxRelays}

\* Rung sequences of length n, with relay_refs valid for num_relays relays.
RungSeqs(num_relays) ==
    UNION {[1..n -> [blocks     : BlockSeqs,
                     relay_refs : RungRelayRefSets(num_relays)]]
           : n \in 0..MaxRungs}

Init ==
    \E relays \in AllValidRelaySeqs :
        /\ ladder \in [rungs  : RungSeqs(Len(relays)),
                       relays : {relays}]
        /\ result = "PENDING"
        /\ satisfied_rung = -1
        /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ LET eval == EvalLadder(ladder)
       IN /\ result' = eval[1]
          /\ satisfied_rung' = eval[2]
    /\ phase' = "done"
    /\ UNCHANGED ladder

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Empty ladder -> UNSATISFIED
Inv_EmptyLadderUnsatisfied ==
    (phase = "done" /\ Len(ladder.rungs) = 0)
    => result = "UNSATISFIED"

\* I2: Empty rung (blocks=[]) -> EvalRung returns ERROR (not UNSATISFIED).
\*     At the ladder level, ERROR rungs are non-satisfying (same as UNSATISFIED).
Inv_EmptyRungError ==
    \A rung \in [blocks : {<<>>}, relay_refs : {{}}] :
        EvalRung(rung, [j \in 0..(MaxRelays - 1) |-> "UNSATISFIED"]) = "ERROR"

\* I3: All-SATISFIED rung -> ladder SATISFIED
Inv_AllSatisfiedRungSatisfiesLadder ==
    (phase = "done"
     /\ Len(ladder.relays) = 0
     /\ \E i \in 1..Len(ladder.rungs) :
            /\ ladder.rungs[i].relay_refs = {}
            /\ Len(ladder.rungs[i].blocks) > 0
            /\ \A j \in 1..Len(ladder.rungs[i].blocks) :
                   EvalBlock(ladder.rungs[i].blocks[j]) = "SATISFIED")
    => result = "SATISFIED"

\* I4: First-wins: if rung 0 satisfies, satisfied_rung = 0
Inv_FirstWins ==
    (phase = "done"
     /\ Len(ladder.relays) = 0
     /\ Len(ladder.rungs) > 0
     /\ ladder.rungs[1].relay_refs = {}
     /\ Len(ladder.rungs[1].blocks) > 0
     /\ \A j \in 1..Len(ladder.rungs[1].blocks) :
            EvalBlock(ladder.rungs[1].blocks[j]) = "SATISFIED")
    => satisfied_rung = 0

\* I5: Inversion flips SATISFIED<->UNSATISFIED but preserves ERROR
Inv_InversionPreservesError ==
    \A r \in Results :
        /\ ApplyInversion(r, FALSE) = r
        /\ (r = "ERROR" => ApplyInversion(r, TRUE) = "ERROR")
        /\ (r = "SATISFIED" => ApplyInversion(r, TRUE) = "UNSATISFIED")
        /\ (r = "UNSATISFIED" => ApplyInversion(r, TRUE) = "SATISFIED")

\* I6: Key-consuming block with inverted=TRUE -> ERROR
Inv_KeyConsumingInvertedError ==
    \A b \in BlockType :
        (b.inverted /\ ~b.invertible) => EvalBlock(b) = "ERROR"

\* I7: Unsatisfied relay_ref -> rung UNSATISFIED (even if blocks pass)
Inv_UnsatisfiedRelayBlocksRung ==
    LET relay_eval == EvalRelays(ladder.relays)
        rr == relay_eval[1]
    IN (phase = "done"
        /\ Len(ladder.relays) > 0
        /\ Len(ladder.rungs) > 0
        /\ ~relay_eval[2]  \* no relay errors
        /\ \A i \in 1..Len(ladder.rungs) :
               \/ Len(ladder.rungs[i].blocks) = 0  \* empty rung -> ERROR (non-satisfying)
               \/ \E ref \in ladder.rungs[i].relay_refs : rr[ref] # "SATISFIED")
       => result # "SATISFIED"

\* I8: All rungs UNSATISFIED -> ladder UNSATISFIED
Inv_AllRungsUnsatisfiedMeansLadderUnsatisfied ==
    (phase = "done"
     /\ Len(ladder.rungs) > 0
     /\ Len(ladder.relays) = 0
     /\ \A i \in 1..Len(ladder.rungs) :
            /\ Len(ladder.rungs[i].blocks) > 0
            /\ EvalRung(ladder.rungs[i], [j \in 0..(MaxRelays - 1) |-> "UNSATISFIED"]) = "UNSATISFIED")
    => result = "UNSATISFIED"

\* I9: AND short-circuit: first ERROR in rung -> rung ERROR
Inv_ANDShortCircuitError ==
    \A blocks \in BlockSeqs :
        (Len(blocks) > 0
         /\ \E k \in 1..Len(blocks) :
                /\ EvalBlock(blocks[k]) = "ERROR"
                /\ \A j \in 1..(k - 1) : EvalBlock(blocks[j]) = "SATISFIED")
        => EvalAND(blocks) = "ERROR"

SafetyInvariant ==
    /\ Inv_EmptyLadderUnsatisfied
    /\ Inv_EmptyRungError
    /\ Inv_AllSatisfiedRungSatisfiesLadder
    /\ Inv_FirstWins
    /\ Inv_InversionPreservesError
    /\ Inv_KeyConsumingInvertedError
    /\ Inv_UnsatisfiedRelayBlocksRung
    /\ Inv_AllRungsUnsatisfiedMeansLadderUnsatisfied
    /\ Inv_ANDShortCircuitError

=============================================================================
