------------------------- MODULE AnchorFee -------------------------
(***************************************************************************)
(* Model of the ANCHOR_FEE block type (0x0707):                            *)
(*   - 2-of-2 signature verification                                       *)
(*   - Fee rate must be within [min_fee, max_fee] band                     *)
(*   - Transaction weight must be ≤ max_weight                             *)
(*   - Commitment number must be non-negative                              *)
(*   - Fail-closed: ERROR when tx context missing                          *)
(*                                                                         *)
(* Verifies: fee pinning rejected, valid spends accepted,                  *)
(* all parameters enforced, fail-closed behavior.                          *)
(***************************************************************************)

EXTENDS Integers

CONSTANTS
    MaxFeeRate,   \* e.g. 1000
    MaxWeight     \* e.g. 4000

FeeRates == 0..MaxFeeRate
Weights == 1..MaxWeight

(***************************************************************************)
(* ANCHOR_FEE evaluation                                                   *)
(***************************************************************************)

\* Parameters set at fund time (in conditions)
Commitments == 0..3

AnchorFeeParams == [
    min_fee: FeeRates,
    max_fee: FeeRates,
    max_weight: Weights,
    commitment: Commitments
]

\* Spending transaction properties
SpendTx == [
    fee_rate: FeeRates,
    weight: Weights,
    has_context: BOOLEAN,
    sig1_valid: BOOLEAN,
    sig2_valid: BOOLEAN
]

EvalAnchorFee(params, spend) ==
    \* Fail-closed: no context → ERROR
    IF ~spend.has_context THEN "ERROR"
    \* Invalid parameters
    ELSE IF params.min_fee > params.max_fee THEN "UNSATISFIED"
    \* Signature check: both must verify
    ELSE IF ~spend.sig1_valid \/ ~spend.sig2_valid THEN "UNSATISFIED"
    \* Fee rate band
    ELSE IF spend.fee_rate < params.min_fee THEN "UNSATISFIED"
    ELSE IF spend.fee_rate > params.max_fee THEN "UNSATISFIED"
    \* Weight limit
    ELSE IF spend.weight > params.max_weight THEN "UNSATISFIED"
    \* All checks pass
    ELSE "SATISFIED"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES params, spend, result, phase

vars == <<params, spend, result, phase>>

Init ==
    /\ params \in AnchorFeeParams
    /\ spend \in SpendTx
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalAnchorFee(params, spend)
    /\ phase' = "done"
    /\ UNCHANGED <<params, spend>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: No context → ERROR (fail-closed)
Inv_NoContextError ==
    (phase = "done" /\ ~spend.has_context)
    => result = "ERROR"

\* I2: Fee below minimum → UNSATISFIED (anti-pinning)
Inv_LowFeeRejected ==
    (phase = "done" /\ spend.has_context
     /\ spend.sig1_valid /\ spend.sig2_valid
     /\ params.min_fee <= params.max_fee
     /\ spend.fee_rate < params.min_fee)
    => result = "UNSATISFIED"

\* I3: Fee above maximum → UNSATISFIED
Inv_HighFeeRejected ==
    (phase = "done" /\ spend.has_context
     /\ spend.sig1_valid /\ spend.sig2_valid
     /\ params.min_fee <= params.max_fee
     /\ spend.fee_rate > params.max_fee)
    => result = "UNSATISFIED"

\* I4: Weight over limit → UNSATISFIED
Inv_OverweightRejected ==
    (phase = "done" /\ spend.has_context
     /\ spend.sig1_valid /\ spend.sig2_valid
     /\ params.min_fee <= params.max_fee
     /\ spend.fee_rate >= params.min_fee /\ spend.fee_rate <= params.max_fee
     /\ spend.weight > params.max_weight)
    => result = "UNSATISFIED"

\* I5: Missing signature → UNSATISFIED
Inv_BadSigRejected ==
    (phase = "done" /\ spend.has_context
     /\ (~spend.sig1_valid \/ ~spend.sig2_valid)
     /\ params.min_fee <= params.max_fee)
    => result = "UNSATISFIED"

\* I6: All valid → SATISFIED
Inv_ValidAccepted ==
    (phase = "done" /\ spend.has_context
     /\ spend.sig1_valid /\ spend.sig2_valid
     /\ params.min_fee <= params.max_fee
     /\ spend.fee_rate >= params.min_fee /\ spend.fee_rate <= params.max_fee
     /\ spend.weight <= params.max_weight)
    => result = "SATISFIED"

SafetyInvariant ==
    /\ Inv_NoContextError
    /\ Inv_LowFeeRejected
    /\ Inv_HighFeeRejected
    /\ Inv_OverweightRejected
    /\ Inv_BadSigRejected
    /\ Inv_ValidAccepted

=============================================================================
