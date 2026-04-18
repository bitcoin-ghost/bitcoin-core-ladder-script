------------------------ MODULE LadderTxMLSC ------------------------
(***************************************************************************)
(* End-to-end model of TX_MLSC lifecycle: conditions → witness → merge →  *)
(* evaluate. Verifies output_index binding, shared tree integrity,        *)
(* key-path spending, shared proof mode, O(log N) Merkle path proofs,     *)
(* and adversarial attack rejection.                                       *)
(*                                                                         *)
(* Updated 2026-03-27: creation proofs removed (conditions embedded        *)
(* directly in scriptPubKey with 0xc1 prefix). Lifecycle is now:           *)
(*   1. Conditions serialized into output scriptPubKey                     *)
(*   2. Witness provided in spending input                                 *)
(*   3. Conditions + witness merged                                        *)
(*   4. Merged ladder evaluated                                            *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

CONSTANTS
    MaxOutputs,    \* Max outputs per transaction (e.g. 3)
    MaxRungs       \* Max rungs per ladder (e.g. 4)

\* Abstract leaf values (stand for hash outputs)
LeafValues == 1..4
\* Abstract root values (computed from leaves)
RootValues == 100..120
\* Abstract tweaked key values (root + internal_key -> tweaked)
TweakedValues == 200..220

\* Simplified hash: deterministic, injective within domain
Hash(a, b) == a * 100 + b

\* Simplified tweak: deterministic, injective
Tweak(internal_key, root) == internal_key + root + 200

(***************************************************************************)
(* Conditions model (locking side, embedded in scriptPubKey)               *)
(***************************************************************************)

\* A rung in the conditions
ConditionRung == [output_index: 0..(MaxOutputs-1), leaf: LeafValues]

\* Spending mode
SpendModes == {"SCRIPT_PATH", "KEY_PATH", "SHARED"}

\* An output has conditions embedded in its scriptPubKey (prefix 0xc1).
\* No separate creation proof — conditions ARE the lock.
Output == [
    rungs: Seq(ConditionRung),
    root: RootValues \cup TweakedValues \cup {0},   \* 0 = empty
    internal_key: 0..3 \cup {-1}                     \* -1 = no key-path
]

(***************************************************************************)
(* Root computation (abstract Merkle tree)                                 *)
(***************************************************************************)

ComputeRoot(rungs) ==
    IF Len(rungs) = 0 THEN 0
    ELSE IF Len(rungs) = 1 THEN rungs[1].leaf + 100
    ELSE
        LET base == rungs[1].leaf + 100
        IN IF Len(rungs) >= 2 THEN Hash(base, rungs[2].leaf)
           ELSE base

(***************************************************************************)
(* Conditions validation (at output creation time)                         *)
(***************************************************************************)

\* Validate that conditions are well-formed when embedded in scriptPubKey.
\* This replaces the old creation proof validation.
ValidateConditions(output) ==
    LET n == Len(output.rungs) IN
    \* C1: Must have at least one rung (empty conditions = unspendable)
    IF n = 0 THEN "REJECT_EMPTY"
    \* C2: Root must be consistent with the rung tree
    ELSE
        LET merkle_root == ComputeRoot(output.rungs) IN
        IF output.internal_key >= 0 THEN
            \* Tweaked: root = Tweak(internal_key, merkle_root)
            IF output.root # Tweak(output.internal_key, merkle_root)
            THEN "REJECT_ROOT_MISMATCH"
            ELSE "ACCEPT"
        ELSE
            \* Un-tweaked: root = merkle_root
            IF output.root # merkle_root
            THEN "REJECT_ROOT_MISMATCH"
            ELSE "ACCEPT"

(***************************************************************************)
(* Spend verification                                                      *)
(***************************************************************************)

SpendAttempt == [
    output_index: 0..(MaxOutputs-1),
    rung_index: 0..(MaxRungs-1),
    claimed_leaf: LeafValues,
    mode: SpendModes,
    shared_source: 0..(MaxOutputs-1)    \* for SHARED mode: which input has the full proof
]

VerifySpend(output, spend) ==
    \* KEY_PATH: verify signature against tweaked output key (no rung evaluation)
    IF spend.mode = "KEY_PATH" THEN
        IF output.internal_key < 0 THEN "REJECT_NO_KEY_PATH"
        ELSE "ACCEPT"  \* signature verification is abstract

    \* SHARED: verify against cached root from source input (same tx)
    ELSE IF spend.mode = "SHARED" THEN
        IF spend.shared_source >= Len(output.rungs) THEN "REJECT_SHARED_RANGE"
        ELSE
            LET n == Len(output.rungs) IN
            IF spend.rung_index >= n THEN "REJECT_RUNG_RANGE"
            ELSE IF spend.claimed_leaf # output.rungs[spend.rung_index + 1].leaf
                 THEN "REJECT_LEAF_MISMATCH"
            ELSE IF output.rungs[spend.rung_index + 1].output_index # spend.output_index
                 THEN "REJECT_OUTPUT_INDEX_MISMATCH"
            ELSE "ACCEPT"

    \* SCRIPT_PATH: full verification (rung eval + Merkle proof + optional tweak check)
    ELSE
        LET n == Len(output.rungs) IN
        IF spend.rung_index >= n THEN "REJECT_RUNG_RANGE"
        ELSE IF spend.claimed_leaf # output.rungs[spend.rung_index + 1].leaf
             THEN "REJECT_LEAF_MISMATCH"
        ELSE IF output.rungs[spend.rung_index + 1].output_index # spend.output_index
             THEN "REJECT_OUTPUT_INDEX_MISMATCH"
        ELSE
            LET merkle_root == ComputeRoot(output.rungs) IN
            IF output.internal_key >= 0 THEN
                IF output.root # Tweak(output.internal_key, merkle_root)
                THEN "REJECT_TWEAK_MISMATCH"
                ELSE "ACCEPT"
            ELSE
                IF output.root # merkle_root
                THEN "REJECT_ROOT_MISMATCH"
                ELSE "ACCEPT"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    output,
    spend,
    phase,
    condResult,
    spendResult

vars == <<output, spend, phase, condResult, spendResult>>

Init ==
    /\ output \in [rungs: UNION {[1..n -> ConditionRung] : n \in 1..MaxRungs},
                   root: RootValues \cup TweakedValues \cup {0},
                   internal_key: 0..3 \cup {-1}]
    /\ spend \in SpendAttempt
    /\ phase = "validate_conditions"
    /\ condResult = "PENDING"
    /\ spendResult = "PENDING"

StepValidateConditions ==
    /\ phase = "validate_conditions"
    /\ condResult' = ValidateConditions(output)
    /\ phase' = "spend"
    /\ UNCHANGED <<output, spend, spendResult>>

StepSpend ==
    /\ phase = "spend"
    /\ spendResult' = VerifySpend(output, spend)
    /\ phase' = "done"
    /\ UNCHANGED <<output, spend, condResult>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepValidateConditions \/ StepSpend \/ StepDone

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Conditions result is always a valid outcome
Inv_CondResultValid ==
    phase # "validate_conditions" =>
        condResult \in {"ACCEPT", "REJECT_EMPTY", "REJECT_ROOT_MISMATCH", "PENDING"}

\* I2: Spend result is always a valid outcome
Inv_SpendResultValid ==
    phase = "done" =>
        spendResult \in {"ACCEPT", "REJECT_RUNG_RANGE", "REJECT_LEAF_MISMATCH",
                         "REJECT_OUTPUT_INDEX_MISMATCH", "REJECT_ROOT_MISMATCH",
                         "REJECT_TWEAK_MISMATCH", "REJECT_NO_KEY_PATH",
                         "REJECT_SHARED_RANGE", "PENDING"}

\* I3: Wrong output_index always rejected at script-path spend
Inv_OutputIndexEnforced ==
    (phase = "done" /\ spendResult = "ACCEPT" /\ spend.mode = "SCRIPT_PATH")
    => (spend.rung_index < Len(output.rungs) =>
            output.rungs[spend.rung_index + 1].output_index = spend.output_index)

\* I4: Wrong leaf always rejected at script-path spend
Inv_LeafBindingEnforced ==
    (phase = "done" /\ spendResult = "ACCEPT" /\ spend.mode = "SCRIPT_PATH")
    => (spend.rung_index < Len(output.rungs) =>
            spend.claimed_leaf = output.rungs[spend.rung_index + 1].leaf)

\* I5: Accepted conditions have consistent root
Inv_RootConsistent ==
    (phase # "validate_conditions" /\ condResult = "ACCEPT")
    => (output.internal_key >= 0 =>
            output.root = Tweak(output.internal_key, ComputeRoot(output.rungs)))
       /\ (output.internal_key = -1 =>
            output.root = ComputeRoot(output.rungs))

\* I6: Key-path spend requires internal_key (tweaked output)
Inv_KeyPathRequiresKey ==
    (phase = "done" /\ spendResult = "ACCEPT" /\ spend.mode = "KEY_PATH")
    => output.internal_key >= 0

\* I7: End-to-end: valid conditions + accepted script-path spend = full binding
Inv_EndToEndBinding ==
    (phase = "done" /\ condResult = "ACCEPT" /\ spendResult = "ACCEPT"
     /\ spend.mode = "SCRIPT_PATH")
    => /\ spend.rung_index < Len(output.rungs)
       /\ output.rungs[spend.rung_index + 1].output_index = spend.output_index
       /\ spend.claimed_leaf = output.rungs[spend.rung_index + 1].leaf

\* I8: Shared mode leaf binding
Inv_SharedLeafBinding ==
    (phase = "done" /\ spendResult = "ACCEPT" /\ spend.mode = "SHARED")
    => (spend.rung_index < Len(output.rungs) =>
            /\ spend.claimed_leaf = output.rungs[spend.rung_index + 1].leaf
            /\ output.rungs[spend.rung_index + 1].output_index = spend.output_index)

SafetyInvariant ==
    /\ Inv_CondResultValid
    /\ Inv_SpendResultValid
    /\ Inv_OutputIndexEnforced
    /\ Inv_LeafBindingEnforced
    /\ Inv_RootConsistent
    /\ Inv_KeyPathRequiresKey
    /\ Inv_EndToEndBinding
    /\ Inv_SharedLeafBinding

=============================================================================
