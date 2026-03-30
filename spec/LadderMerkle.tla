----------------------- MODULE LadderMerkle -----------------------
(***************************************************************************)
(* Model of Merkle tree construction and proof verification for            *)
(* Ladder Script conditions (MLSC):                                        *)
(*   - Leaves: rung serialized + pubkeys -> TaggedHash("LadderLeaf")       *)
(*   - Interior: sorted children (min/max) -> TaggedHash("LadderInternal") *)
(*   - Tree padded to power-of-2 with MLSC_EMPTY_LEAF                     *)
(*   - Three proof modes:                                                  *)
(*       FULL_LEAVES:  all unrevealed leaf hashes, reconstruct full tree   *)
(*       MERKLE_PATH:  O(log N) sibling hashes from leaf to root          *)
(*       SHARED:       reference same-source proof from cache              *)
(*                                                                         *)
(* Constants: NumLeaves = 4 (small model).                                 *)
(* VPS: NumLeaves = 8 for deeper coverage.                                 *)
(*                                                                         *)
(* Verifies: path verification, tamper detection, sorted interiors,        *)
(* power-of-2 padding, full-leaf reconstruction, shared proof routing.     *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    NumLeaves   \* e.g. 4

(***************************************************************************)
(* Abstract hash model                                                     *)
(***************************************************************************)

\* We model hashes as integers.  Real hashes are opaque 256-bit values;
\* here we need only equality / inequality and a deterministic function.

EMPTY_LEAF == 0

\* LeafHash(i) — distinct non-zero value representing TaggedHash("LadderLeaf", rung_i)
LeafHash(i) == i + 1   \* 1..NumLeaves

\* A tampered leaf produces a different hash
TamperedLeafHash(i) == NumLeaves + i + 1   \* NumLeaves+1 .. 2*NumLeaves

\* Abstract "sorted interior hash": deterministic, commutative, collision-free
\* in this small model.  Sorted ordering means Interior(a,b) == Interior(b,a).
\* We encode as (min+1) * (MaxHash+1) + (max+1) to guarantee injectivity.
MaxHash == (NumLeaves * 4) + 100   \* enough headroom for tree depth

SortedInterior(a, b) ==
    LET lo == IF a <= b THEN a ELSE b
        hi == IF a <= b THEN b ELSE a
    IN  (lo + 1) * (MaxHash + 1) + (hi + 1)

(***************************************************************************)
(* Power-of-2 padding                                                      *)
(***************************************************************************)

NextPow2(n) ==
    CHOOSE p \in 1..256 :
        /\ \E k \in 0..8 : p = 2^k
        /\ p >= n
        /\ \A q \in 1..(p-1) : (\E k \in 0..8 : q = 2^k) => q < n

PadLeaves(leaves) ==
    LET padded_len == NextPow2(Len(leaves))
    IN  [i \in 1..padded_len |->
            IF i <= Len(leaves) THEN leaves[i] ELSE EMPTY_LEAF]

(***************************************************************************)
(* Merkle tree construction (bottom-up, matches BuildMerkleTree)           *)
(***************************************************************************)

RECURSIVE BuildTreeRec(_)
BuildTreeRec(nodes) ==
    IF Len(nodes) = 1 THEN nodes[1]
    ELSE LET half == Len(nodes) \div 2
             parents == [i \in 1..half |->
                            SortedInterior(nodes[2*i - 1], nodes[2*i])]
         IN  BuildTreeRec(parents)

BuildMerkleTree(leaves) ==
    IF Len(leaves) = 0 THEN EMPTY_LEAF
    ELSE IF Len(leaves) = 1 THEN leaves[1]
    ELSE BuildTreeRec(PadLeaves(leaves))

(***************************************************************************)
(* Merkle path construction (matches BuildMerklePath)                      *)
(***************************************************************************)

RECURSIVE BuildPathRec(_, _, _)
BuildPathRec(nodes, idx, acc) ==
    IF Len(nodes) = 1 THEN acc
    ELSE LET sibling_idx == IF idx % 2 = 1 THEN idx + 1 ELSE idx - 1
             sib == IF sibling_idx >= 1 /\ sibling_idx <= Len(nodes)
                    THEN nodes[sibling_idx]
                    ELSE EMPTY_LEAF
             half == Len(nodes) \div 2
             parents == [i \in 1..half |->
                            SortedInterior(nodes[2*i - 1], nodes[2*i])]
             parent_idx == ((idx - 1) \div 2) + 1
         IN  BuildPathRec(parents, parent_idx, Append(acc, sib))

BuildMerklePath(leaves, target) ==
    IF Len(leaves) <= 1 THEN <<>>
    ELSE BuildPathRec(PadLeaves(leaves), target, <<>>)

(***************************************************************************)
(* Merkle path verification (matches VerifyMerklePath / ComputeRoot)       *)
(***************************************************************************)

RECURSIVE ComputeRootFromPath(_, _)
ComputeRootFromPath(leaf, path) ==
    IF Len(path) = 0 THEN leaf
    ELSE ComputeRootFromPath(
            SortedInterior(leaf, Head(path)),
            Tail(path))

VerifyMerklePath(leaf, path, expected_root) ==
    ComputeRootFromPath(leaf, path) = expected_root

(***************************************************************************)
(* Correct leaf sequence (canonical)                                       *)
(***************************************************************************)

CorrectLeaves == [i \in 1..NumLeaves |-> LeafHash(i)]
CorrectRoot   == BuildMerkleTree(CorrectLeaves)

(***************************************************************************)
(* Proof modes                                                             *)
(***************************************************************************)

ProofModes == {"FULL_LEAVES", "MERKLE_PATH", "SHARED"}

\* FULL_LEAVES: verifier receives all leaf hashes, rebuilds tree
FullLeavesVerify(supplied_leaves, expected_root) ==
    BuildMerkleTree(supplied_leaves) = expected_root

\* SHARED: source input index must match
SharedVerify(source_input, expected_source) ==
    source_input = expected_source

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    target_leaf_idx,    \* which leaf we are proving (1..NumLeaves)
    proof_mode,         \* one of ProofModes
    tamper_leaf,        \* BOOLEAN: corrupt the proved leaf?
    tamper_path,        \* BOOLEAN: corrupt one sibling in the path?
    tamper_full,        \* BOOLEAN: corrupt one leaf in FULL_LEAVES?
    shared_source,      \* source input for SHARED mode (0..1)
    shared_expected,    \* expected source input for SHARED mode (always 0)
    result,             \* "MATCH" | "MISMATCH" | "ACCEPTED" | "REJECTED" | "PENDING"
    phase               \* "eval" | "done"

vars == <<target_leaf_idx, proof_mode, tamper_leaf, tamper_path,
          tamper_full, shared_source, shared_expected, result, phase>>

Init ==
    /\ target_leaf_idx \in 1..NumLeaves
    /\ proof_mode \in ProofModes
    /\ tamper_leaf \in BOOLEAN
    /\ tamper_path \in BOOLEAN
    /\ tamper_full \in BOOLEAN
    /\ shared_source \in {0, 1}
    /\ shared_expected = 0
    /\ result = "PENDING"
    /\ phase = "eval"

(***************************************************************************)
(* Evaluation step                                                         *)
(***************************************************************************)

EvalMerklePath ==
    LET leaf == IF tamper_leaf
                THEN TamperedLeafHash(target_leaf_idx)
                ELSE LeafHash(target_leaf_idx)
        correct_path == BuildMerklePath(CorrectLeaves, target_leaf_idx)
        path == IF tamper_path
                THEN IF Len(correct_path) > 0
                     THEN [correct_path EXCEPT ![1] = EMPTY_LEAF + 9999]
                     ELSE correct_path
                ELSE correct_path
    IN  IF VerifyMerklePath(leaf, path, CorrectRoot)
        THEN "MATCH"
        ELSE "MISMATCH"

EvalFullLeaves ==
    LET supplied == IF tamper_full
                    THEN [i \in 1..NumLeaves |->
                            IF i = 1 THEN TamperedLeafHash(1)
                            ELSE LeafHash(i)]
                    ELSE CorrectLeaves
    IN  IF FullLeavesVerify(supplied, CorrectRoot)
        THEN "MATCH"
        ELSE "MISMATCH"

EvalShared ==
    IF SharedVerify(shared_source, shared_expected)
    THEN "ACCEPTED"
    ELSE "REJECTED"

StepEval ==
    /\ phase = "eval"
    /\ result' = CASE proof_mode = "MERKLE_PATH" -> EvalMerklePath
                   [] proof_mode = "FULL_LEAVES" -> EvalFullLeaves
                   [] proof_mode = "SHARED"      -> EvalShared
    /\ phase' = "done"
    /\ UNCHANGED <<target_leaf_idx, proof_mode, tamper_leaf, tamper_path,
                   tamper_full, shared_source, shared_expected>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Correct leaf + correct path -> root matches (MERKLE_PATH succeeds)
Inv_CorrectPathVerifies ==
    (phase = "done" /\ proof_mode = "MERKLE_PATH"
     /\ ~tamper_leaf /\ ~tamper_path)
    => result = "MATCH"

\* I2: Wrong leaf + correct path -> root mismatch (tamper detection)
Inv_WrongLeafDetected ==
    (phase = "done" /\ proof_mode = "MERKLE_PATH"
     /\ tamper_leaf /\ ~tamper_path)
    => result = "MISMATCH"

\* I3: Correct leaf + wrong path -> root mismatch
Inv_WrongPathDetected ==
    (phase = "done" /\ proof_mode = "MERKLE_PATH"
     /\ ~tamper_leaf /\ tamper_path)
    => result = "MISMATCH"

\* I4: Interior nodes always sorted (deterministic)
\*     SortedInterior is commutative by construction — verify for all pairs
Inv_InteriorSorted ==
    \A a, b \in 0..NumLeaves :
        SortedInterior(a, b) = SortedInterior(b, a)

\* I5: Power-of-2 padding with empty leaves does not change root for given content
\*     Building with explicit padding equals building without (padding is internal)
Inv_PaddingDeterministic ==
    LET leaves3 == [i \in 1..3 |-> LeafHash(i)]
        leaves4 == [i \in 1..4 |-> IF i <= 3 THEN LeafHash(i) ELSE EMPTY_LEAF]
    IN  BuildMerkleTree(leaves3) = BuildMerkleTree(leaves4)

\* I6: FULL_LEAVES with all correct hashes -> root matches
Inv_FullLeavesCorrect ==
    (phase = "done" /\ proof_mode = "FULL_LEAVES" /\ ~tamper_full)
    => result = "MATCH"

\* I7: FULL_LEAVES with one wrong hash -> root mismatch
Inv_FullLeavesWrongDetected ==
    (phase = "done" /\ proof_mode = "FULL_LEAVES" /\ tamper_full)
    => result = "MISMATCH"

\* I8: SHARED proof from same source -> accepted
Inv_SharedSameSource ==
    (phase = "done" /\ proof_mode = "SHARED" /\ shared_source = shared_expected)
    => result = "ACCEPTED"

\* I9: SHARED proof from different source -> rejected
Inv_SharedDiffSource ==
    (phase = "done" /\ proof_mode = "SHARED" /\ shared_source # shared_expected)
    => result = "REJECTED"

SafetyInvariant ==
    /\ Inv_CorrectPathVerifies
    /\ Inv_WrongLeafDetected
    /\ Inv_WrongPathDetected
    /\ Inv_InteriorSorted
    /\ Inv_PaddingDeterministic
    /\ Inv_FullLeavesCorrect
    /\ Inv_FullLeavesWrongDetected
    /\ Inv_SharedSameSource
    /\ Inv_SharedDiffSource

=============================================================================
