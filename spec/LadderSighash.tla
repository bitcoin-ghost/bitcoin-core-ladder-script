---------------------- MODULE LadderSighash ----------------------
(***************************************************************************)
(* Model of the Ladder Script sighash commitment structure:                *)
(*   - Two spend modes: script-path vs key-path (domain separation)       *)
(*   - Base hash types: ALL(0), NONE(1), SINGLE(2), DEFAULT(3→ALL)       *)
(*   - ANYPREVOUT flag (0x40): skips prevouts commitment (LN-Symmetry)    *)
(*   - ANYPREVOUTANYSCRIPT flag (0xC0): skips prevouts + conditions       *)
(*   - ANYONECANPAY flag (0x80): commits only to current input            *)
(*   - Key-path: no conditions hash, no ANYPREVOUT types                  *)
(*                                                                         *)
(* Reference: sighash.cpp — SignatureHashLadder (L41),                    *)
(*            SignatureHashLadderKeyPath (L131)                            *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

(***************************************************************************)
(* Hash type encoding                                                      *)
(***************************************************************************)

\* All 256 possible byte values for exhaustive validation check
AllBytes == 0..255

\* Valid hash_type values from sighash.cpp
ValidHashTypes == {0, 1, 2, 3}                   \* DEFAULT/ALL/NONE/SINGLE
              \cup {64, 65, 66, 67}              \* 0x40-0x43: ANYPREVOUT
              \cup {129, 130, 131}               \* 0x81-0x83: ANYONECANPAY (no 0x80)
              \cup {192, 193, 194, 195}          \* 0xC0-0xC3: ANYPREVOUTANYSCRIPT

\* Key-path only allows standard types (no ANYPREVOUT)
KeyPathValidTypes == {0, 1, 2, 3, 129, 130, 131}

\* Flag extraction
BaseType(ht) == ht % 4

OutputType(ht) ==
    IF ht = 0 \/ BaseType(ht) = 0 THEN 1  \* DEFAULT/0 → ALL
    ELSE BaseType(ht)

HasAnyPrevOut(ht) == ((ht \div 64) % 2) = 1         \* bit 6 set (0x40)
HasAnyPrevOutAnyScript(ht) == (ht \div 64) = 3       \* bits 6+7 both set (0xC0)
HasAnyOneCanPay(ht) == ht \in {129, 130, 131}  \* 0x81-0x83

SpendModes == {"script_path", "key_path"}

(***************************************************************************)
(* Commitment set computation                                              *)
(***************************************************************************)

\* Every valid (hash_type, spend_mode) pair produces a set of commitments
Commitments(ht, mode) ==
    LET base_commits == {"version", "nLockTime", "epoch", "hash_type", "spend_type"}

        \* Input commitments: ANYONECANPAY → current input only
        input_commits ==
            IF HasAnyOneCanPay(ht)
            THEN {"current_input_amount", "current_input_sequence"}
                 \cup (IF mode = "key_path" \/ ~HasAnyPrevOut(ht)
                       THEN {"current_input_prevout"}
                       ELSE {})
            ELSE {"amounts_hash", "sequences_hash", "input_index"}
                 \cup (IF mode = "key_path" \/ ~HasAnyPrevOut(ht)
                       THEN {"prevouts_hash"}
                       ELSE {})

        \* Output commitments: depends on base type
        output_commits ==
            IF OutputType(ht) = 1 THEN {"outputs_hash"}           \* ALL
            ELSE IF OutputType(ht) = 3 THEN {"single_output"}     \* SINGLE
            ELSE {}                                                \* NONE

        \* Conditions: script-path only, unless ANYPREVOUTANYSCRIPT
        conditions_commits ==
            IF mode = "script_path" /\ ~HasAnyPrevOutAnyScript(ht)
            THEN {"conditions_hash"}
            ELSE {}

    IN base_commits \cup input_commits \cup output_commits \cup conditions_commits

(***************************************************************************)
(* Hasher context (domain separation)                                      *)
(***************************************************************************)

HasherTag(mode) ==
    IF mode = "key_path" THEN "LadderKeyPathSighash"
    ELSE "LadderSighash"

(***************************************************************************)
(* Evaluation: returns commitment set or "ERROR"                           *)
(***************************************************************************)

\* Using a string result to match AnchorFee style
EvalSighash(ht, mode) ==
    IF mode = "key_path" /\ ht \notin KeyPathValidTypes THEN "ERROR"
    ELSE IF ht \notin ValidHashTypes THEN "ERROR"
    ELSE "OK"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES hash_type, spend_mode, result, commits, phase

vars == <<hash_type, spend_mode, result, commits, phase>>

Init ==
    /\ hash_type \in AllBytes
    /\ spend_mode \in SpendModes
    /\ result = "PENDING"
    /\ commits = {}
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalSighash(hash_type, spend_mode)
    /\ commits' = IF result' = "OK"
                  THEN Commitments(hash_type, spend_mode)
                  ELSE {}
    /\ phase' = "done"
    /\ UNCHANGED <<hash_type, spend_mode>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Key-path and script-path use different hasher contexts
Inv_DomainSeparation ==
    HasherTag("key_path") # HasherTag("script_path")

\* I2: Key-path never commits to conditions_hash
Inv_KeyPathNoConditions ==
    (phase = "done" /\ result = "OK" /\ spend_mode = "key_path")
    => "conditions_hash" \notin commits

\* I3: Script-path with ANYPREVOUTANYSCRIPT skips conditions_hash
Inv_APOASSkipsConditions ==
    (phase = "done" /\ result = "OK" /\ spend_mode = "script_path"
     /\ HasAnyPrevOutAnyScript(hash_type))
    => "conditions_hash" \notin commits

\* I4: Script-path without ANYPREVOUTANYSCRIPT commits to conditions_hash
Inv_ScriptPathCommitsConditions ==
    (phase = "done" /\ result = "OK" /\ spend_mode = "script_path"
     /\ ~HasAnyPrevOutAnyScript(hash_type))
    => "conditions_hash" \in commits

\* I5: ANYPREVOUT skips prevouts commitment
Inv_APOSkipsPrevouts ==
    (phase = "done" /\ result = "OK" /\ spend_mode = "script_path"
     /\ HasAnyPrevOut(hash_type))
    => ("prevouts_hash" \notin commits /\ "current_input_prevout" \notin commits)

\* I6: ANYONECANPAY commits only to current input (no aggregate hashes)
Inv_AnyOneCanPayCurrentInput ==
    (phase = "done" /\ result = "OK" /\ HasAnyOneCanPay(hash_type))
    => (/\ "current_input_amount" \in commits
        /\ "current_input_sequence" \in commits
        /\ "amounts_hash" \notin commits
        /\ "sequences_hash" \notin commits
        /\ "input_index" \notin commits)

\* I7: SIGHASH_ALL commits to all outputs
Inv_AllCommitsOutputs ==
    (phase = "done" /\ result = "OK" /\ OutputType(hash_type) = 1)
    => "outputs_hash" \in commits

\* I8: SIGHASH_NONE commits to no outputs
Inv_NoneNoOutputs ==
    (phase = "done" /\ result = "OK" /\ OutputType(hash_type) = 2)
    => ("outputs_hash" \notin commits /\ "single_output" \notin commits)

\* I9: SIGHASH_SINGLE commits to matching output only
Inv_SingleMatchingOutput ==
    (phase = "done" /\ result = "OK" /\ OutputType(hash_type) = 3)
    => ("single_output" \in commits /\ "outputs_hash" \notin commits)

\* I10: Key-path rejects ANYPREVOUT hash types
Inv_KeyPathRejectsAPO ==
    (phase = "done" /\ spend_mode = "key_path"
     /\ HasAnyPrevOut(hash_type) /\ hash_type \notin KeyPathValidTypes)
    => result = "ERROR"

\* I11: Invalid hash_type → ERROR
Inv_InvalidTypeError ==
    (phase = "done" /\ hash_type \notin ValidHashTypes)
    => result = "ERROR"

\* I12: All valid types produce non-empty commitment set
Inv_ValidNonEmpty ==
    (phase = "done" /\ result = "OK")
    => Cardinality(commits) > 0

SafetyInvariant ==
    /\ Inv_DomainSeparation
    /\ Inv_KeyPathNoConditions
    /\ Inv_APOASSkipsConditions
    /\ Inv_ScriptPathCommitsConditions
    /\ Inv_APOSkipsPrevouts
    /\ Inv_AnyOneCanPayCurrentInput
    /\ Inv_AllCommitsOutputs
    /\ Inv_NoneNoOutputs
    /\ Inv_SingleMatchingOutput
    /\ Inv_KeyPathRejectsAPO
    /\ Inv_InvalidTypeError
    /\ Inv_ValidNonEmpty

=============================================================================
