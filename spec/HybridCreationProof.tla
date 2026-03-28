---------------------- MODULE HybridCreationProof ----------------------
(***************************************************************************)
(* Model of the hybrid creation proof rule:                                *)
(*   - 3+ spendable outputs: creation proof REQUIRED                       *)
(*   - 1-2 spendable outputs: creation proof OPTIONAL                      *)
(*   - If proof present: leaves must rebuild to conditions_root            *)
(*   - DATA_RETURN outputs (nValue=0) excluded from spendable count        *)
(*                                                                         *)
(* Verifies: no UTXO spam for 3+ outputs, correct root binding,           *)
(* rejection of invalid proofs, and acceptance of valid optional proofs.   *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxOutputs,     \* Max outputs per transaction (e.g. 5)
    MaxLeaves       \* Max leaves in creation proof (e.g. 5)

\* Abstract leaf and root values
LeafValues == 1..8
RootValues == 100..120

\* Simplified Merkle root: deterministic from leaves
RECURSIVE MerkleRoot(_, _)
MerkleRoot(leaves, idx) ==
    IF idx > Len(leaves) THEN 0
    ELSE IF idx = Len(leaves) THEN leaves[idx] + 100
    ELSE leaves[idx] + MerkleRoot(leaves, idx + 1)

ComputeRoot(leaves) ==
    IF Len(leaves) = 0 THEN 0
    ELSE MerkleRoot(leaves, 1)

(***************************************************************************)
(* Transaction model                                                       *)
(***************************************************************************)

\* An output has a value (0 = DATA_RETURN, >0 = spendable)
OutputValues == 0..2  \* 0 = DATA_RETURN, 1-2 = spendable amounts

\* A transaction
Transaction == [
    n_outputs: 1..MaxOutputs,
    output_values: Seq(OutputValues),
    conditions_root: RootValues \cup {0},
    has_proof: BOOLEAN,
    proof_leaves: Seq(LeafValues)
]

(***************************************************************************)
(* Validation                                                              *)
(***************************************************************************)

CountSpendable(tx) ==
    LET vals == tx.output_values
    IN Cardinality({i \in 1..Len(vals) : vals[i] > 0})

ValidateCreationProof(tx) ==
    LET n_spendable == CountSpendable(tx)
        computed_root == ComputeRoot(tx.proof_leaves)
    IN
    \* Rule 1: 3+ spendable outputs require proof
    IF n_spendable > 2 THEN
        IF ~tx.has_proof THEN "REJECT_MISSING_PROOF"
        ELSE IF Len(tx.proof_leaves) < n_spendable THEN "REJECT_TOO_FEW_LEAVES"
        ELSE IF computed_root # tx.conditions_root THEN "REJECT_ROOT_MISMATCH"
        ELSE "ACCEPT"
    \* Rule 2: 1-2 spendable outputs — proof optional
    ELSE IF tx.has_proof THEN
        IF Len(tx.proof_leaves) < n_spendable THEN "REJECT_TOO_FEW_LEAVES"
        ELSE IF computed_root # tx.conditions_root THEN "REJECT_ROOT_MISMATCH"
        ELSE "ACCEPT"
    ELSE "ACCEPT"  \* No proof, ≤2 outputs — accepted

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES tx, result, phase

vars == <<tx, result, phase>>

Init ==
    /\ tx \in [
        n_outputs: 1..MaxOutputs,
        output_values: UNION {[1..n -> OutputValues] : n \in 1..MaxOutputs},
        conditions_root: RootValues \cup {0},
        has_proof: BOOLEAN,
        proof_leaves: UNION {[1..n -> LeafValues] : n \in 0..MaxLeaves}
       ]
    /\ Len(tx.output_values) = tx.n_outputs
    /\ result = "PENDING"
    /\ phase = "validate"

StepValidate ==
    /\ phase = "validate"
    /\ result' = ValidateCreationProof(tx)
    /\ phase' = "done"
    /\ UNCHANGED tx

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepValidate \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: 3+ spendable outputs without proof → always rejected
Inv_RequireProofFor3Plus ==
    (phase = "done" /\ CountSpendable(tx) > 2 /\ ~tx.has_proof)
    => result = "REJECT_MISSING_PROOF"

\* I2: Valid proof with matching root → accepted
Inv_ValidProofAccepted ==
    (phase = "done" /\ tx.has_proof
     /\ Len(tx.proof_leaves) >= CountSpendable(tx)
     /\ ComputeRoot(tx.proof_leaves) = tx.conditions_root)
    => result = "ACCEPT"

\* I3: No proof + ≤2 spendable → accepted
Inv_NoProofSmallAccepted ==
    (phase = "done" /\ ~tx.has_proof /\ CountSpendable(tx) <= 2)
    => result = "ACCEPT"

\* I4: Wrong root → rejected
Inv_WrongRootRejected ==
    (phase = "done" /\ tx.has_proof
     /\ ComputeRoot(tx.proof_leaves) # tx.conditions_root
     /\ Len(tx.proof_leaves) >= CountSpendable(tx))
    => result = "REJECT_ROOT_MISMATCH"

\* I5: Too few leaves → rejected
Inv_TooFewLeavesRejected ==
    (phase = "done" /\ tx.has_proof
     /\ Len(tx.proof_leaves) < CountSpendable(tx))
    => result = "REJECT_TOO_FEW_LEAVES"

SafetyInvariant ==
    /\ Inv_RequireProofFor3Plus
    /\ Inv_ValidProofAccepted
    /\ Inv_NoProofSmallAccepted
    /\ Inv_WrongRootRejected
    /\ Inv_TooFewLeavesRejected

=============================================================================
