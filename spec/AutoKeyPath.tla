------------------------- MODULE AutoKeyPath -------------------------
(***************************************************************************)
(* Model of auto key-path detection and routing in signladder:             *)
(*   - Single SIG rung → key-path candidate                                *)
(*   - Tweak check: conditions_root == Tweak(internal_key, merkle_root)    *)
(*   - If tweak matches → key-path (1-element witness, 64-byte sig)        *)
(*   - If tweak fails → script-path (2-element witness)                    *)
(*   - Multi-rung or non-SIG → always script-path                          *)
(*                                                                         *)
(* Verifies: correct routing, tweak verification, no false positives,      *)
(* fallback to script-path on mismatch.                                    *)
(***************************************************************************)

EXTENDS Integers

CONSTANTS
    NumKeys     \* Number of distinct keys (e.g. 3)

Keys == 1..NumKeys
TweakedValues == 100..120

\* Simplified tweak: deterministic from key + root
Tweak(key, root) == key + root + 100

(***************************************************************************)
(* Spending context                                                        *)
(***************************************************************************)

\* Conditions: single SIG or multi-block/multi-rung
ConditionType == {"SINGLE_SIG", "MULTI_RUNG", "MULTI_BLOCK", "NON_SIG"}

\* The output to spend
Output == [
    conditions_root: TweakedValues \cup (1..20),  \* tweaked or plain
    condition_type: ConditionType,
    internal_key: Keys \cup {0},    \* 0 = no key (plain root)
    merkle_root: 1..10
]

\* The signer
Signer == [
    key: Keys,
    has_privkey: BOOLEAN
]

(***************************************************************************)
(* Auto-detect key-path                                                    *)
(***************************************************************************)

DetectKeyPath(output, signer) ==
    \* Must be single SIG
    IF output.condition_type # "SINGLE_SIG" THEN "SCRIPT_PATH"
    \* Must have the privkey
    ELSE IF ~signer.has_privkey THEN "SCRIPT_PATH"
    \* Check tweak: conditions_root must equal Tweak(signer.key, merkle_root)
    ELSE IF output.conditions_root = Tweak(signer.key, output.merkle_root)
         THEN "KEY_PATH"
    \* Tweak doesn't match — maybe wrong key or plain root
    ELSE "SCRIPT_PATH"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES output, signer, spend_type, phase

vars == <<output, signer, spend_type, phase>>

Init ==
    /\ output \in Output
    /\ signer \in Signer
    /\ spend_type = "PENDING"
    /\ phase = "detect"

StepDetect ==
    /\ phase = "detect"
    /\ spend_type' = DetectKeyPath(output, signer)
    /\ phase' = "done"
    /\ UNCHANGED <<output, signer>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepDetect \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Key-path only when conditions are single SIG
Inv_KeyPathOnlySingleSig ==
    (phase = "done" /\ spend_type = "KEY_PATH")
    => output.condition_type = "SINGLE_SIG"

\* I2: Key-path only when signer has privkey
Inv_KeyPathNeedsPrivkey ==
    (phase = "done" /\ spend_type = "KEY_PATH")
    => signer.has_privkey

\* I3: Key-path only when tweak matches
Inv_KeyPathTweakCorrect ==
    (phase = "done" /\ spend_type = "KEY_PATH")
    => output.conditions_root = Tweak(signer.key, output.merkle_root)

\* I4: Multi-rung/multi-block always goes to script-path
Inv_MultiAlwaysScript ==
    (phase = "done" /\ output.condition_type \in {"MULTI_RUNG", "MULTI_BLOCK", "NON_SIG"})
    => spend_type = "SCRIPT_PATH"

\* I5: No privkey → script-path
Inv_NoKeyScript ==
    (phase = "done" /\ ~signer.has_privkey)
    => spend_type = "SCRIPT_PATH"

\* I6: Valid single SIG + correct tweak + privkey → key-path
Inv_ValidKeyPath ==
    (phase = "done"
     /\ output.condition_type = "SINGLE_SIG"
     /\ signer.has_privkey
     /\ output.conditions_root = Tweak(signer.key, output.merkle_root))
    => spend_type = "KEY_PATH"

SafetyInvariant ==
    /\ Inv_KeyPathOnlySingleSig
    /\ Inv_KeyPathNeedsPrivkey
    /\ Inv_KeyPathTweakCorrect
    /\ Inv_MultiAlwaysScript
    /\ Inv_NoKeyScript
    /\ Inv_ValidKeyPath

=============================================================================
