------------------------- MODULE BlockCompound -------------------------
(***************************************************************************)
(* Model of the compound family block types (0x0701-0x0707):               *)
(*   1. TIMELOCKED_SIG   (0x0701): SIG + CSV combined                     *)
(*   2. HTLC             (0x0702): Hash + Timelock + Sig (claim/refund)    *)
(*   3. HASH_SIG         (0x0703): Hash preimage + SIG combined            *)
(*   4. PTLC             (0x0704): Adaptor sig + CSV combined              *)
(*   5. CLTV_SIG         (0x0705): SIG + CLTV combined                    *)
(*   6. TIMELOCKED_MULTISIG (0x0706): Multisig + CSV combined              *)
(*   7. ANCHOR_FEE       (0x0707): 2-of-2 + fee band + weight limit       *)
(*                                                                         *)
(* All compound blocks are key-consuming and non-invertible.               *)
(* Fail-closed: ERROR when tx context missing.                             *)
(*                                                                         *)
(* Verifies: each block type accepts valid spends, rejects invalid,        *)
(* all are non-invertible, fail-closed behavior.                           *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

CONSTANTS
    MaxKeys,      \* e.g. 3  (VPS: 8)
    MaxDelay,     \* e.g. 5  (VPS: 144)
    MaxHeight     \* e.g. 10 (VPS: 1000)

Delays == 0..MaxDelay
Heights == 0..MaxHeight

(***************************************************************************)
(* Block type enumeration                                                  *)
(***************************************************************************)

BlockTypes == {
    "TIMELOCKED_SIG",
    "HTLC",
    "HASH_SIG",
    "PTLC",
    "CLTV_SIG",
    "TIMELOCKED_MULTISIG",
    "ANCHOR_FEE"
}

(***************************************************************************)
(* Parameters (conditions set at fund time)                                *)
(***************************************************************************)

CompoundParams == [
    block_type: BlockTypes,
    inverted: BOOLEAN,
    delay: Delays,                   \* CSV delay (TIMELOCKED_SIG, HTLC, PTLC, TIMELOCKED_MULTISIG)
    target_height: Heights,          \* CLTV target (CLTV_SIG)
    threshold: 1..MaxKeys,           \* M-of-N threshold (TIMELOCKED_MULTISIG)
    num_keys: 1..MaxKeys,            \* N total keys (TIMELOCKED_MULTISIG)
    min_fee: 0..10,                  \* ANCHOR_FEE
    max_fee: 0..10,                  \* ANCHOR_FEE
    max_weight: 1..10                \* ANCHOR_FEE
]

(***************************************************************************)
(* Spending transaction / witness                                          *)
(***************************************************************************)

SpendTx == [
    has_context: BOOLEAN,
    sig_valid: BOOLEAN,              \* primary signature valid
    sig2_valid: BOOLEAN,             \* second signature (ANCHOR_FEE)
    adaptor_sig_valid: BOOLEAN,      \* adapted signature (PTLC)
    preimage_valid: BOOLEAN,         \* hash preimage matches (HTLC, HASH_SIG)
    sequence: Delays,                \* nSequence (CSV blocks)
    locktime: Heights,               \* nLockTime (CLTV blocks)
    num_valid_sigs: 0..MaxKeys,      \* valid sigs provided (TIMELOCKED_MULTISIG)
    branch: 0..1,                    \* HTLC: 1=claim, 0=refund
    fee_rate: 0..10,                 \* ANCHOR_FEE
    weight: 1..10                    \* ANCHOR_FEE
]

(***************************************************************************)
(* Evaluation operators                                                    *)
(***************************************************************************)

EvalTimelockedSig(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.inverted THEN "ERROR"
    ELSE IF ~s.sig_valid THEN "UNSATISFIED"
    ELSE IF s.sequence < p.delay THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalHTLC(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.inverted THEN "ERROR"
    ELSE IF s.branch = 1 THEN
        \* Claim path: valid preimage + valid sig required
        IF ~s.preimage_valid THEN "UNSATISFIED"
        ELSE IF ~s.sig_valid THEN "UNSATISFIED"
        ELSE "SATISFIED"
    ELSE
        \* Refund path (branch=0): timeout + valid sig required
        IF s.sequence < p.delay THEN "UNSATISFIED"
        ELSE IF ~s.sig_valid THEN "UNSATISFIED"
        ELSE "SATISFIED"

EvalHashSig(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.inverted THEN "ERROR"
    ELSE IF ~s.preimage_valid THEN "UNSATISFIED"
    ELSE IF ~s.sig_valid THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalPTLC(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.inverted THEN "ERROR"
    ELSE IF ~s.adaptor_sig_valid THEN "UNSATISFIED"
    ELSE IF s.sequence < p.delay THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalCLTVSig(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.inverted THEN "ERROR"
    ELSE IF ~s.sig_valid THEN "UNSATISFIED"
    ELSE IF s.locktime < p.target_height THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalTimelockedMultisig(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.inverted THEN "ERROR"
    ELSE IF p.threshold > p.num_keys THEN "ERROR"
    ELSE IF s.num_valid_sigs < p.threshold THEN "UNSATISFIED"
    ELSE IF s.sequence < p.delay THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalAnchorFee(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.inverted THEN "ERROR"
    ELSE IF p.min_fee > p.max_fee THEN "UNSATISFIED"
    ELSE IF ~s.sig_valid \/ ~s.sig2_valid THEN "UNSATISFIED"
    ELSE IF s.fee_rate < p.min_fee THEN "UNSATISFIED"
    ELSE IF s.fee_rate > p.max_fee THEN "UNSATISFIED"
    ELSE IF s.weight > p.max_weight THEN "UNSATISFIED"
    ELSE "SATISFIED"

EvalCompound(p, s) ==
    CASE p.block_type = "TIMELOCKED_SIG"      -> EvalTimelockedSig(p, s)
      [] p.block_type = "HTLC"               -> EvalHTLC(p, s)
      [] p.block_type = "HASH_SIG"            -> EvalHashSig(p, s)
      [] p.block_type = "PTLC"               -> EvalPTLC(p, s)
      [] p.block_type = "CLTV_SIG"           -> EvalCLTVSig(p, s)
      [] p.block_type = "TIMELOCKED_MULTISIG" -> EvalTimelockedMultisig(p, s)
      [] p.block_type = "ANCHOR_FEE"         -> EvalAnchorFee(p, s)

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES params, spend, result, phase

vars == <<params, spend, result, phase>>

Init ==
    /\ params \in CompoundParams
    /\ spend \in SpendTx
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalCompound(params, spend)
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

\* I1: TIMELOCKED_SIG valid sig + sequence met -> SATISFIED
Inv_TimelockedSig_Accept ==
    (phase = "done"
     /\ params.block_type = "TIMELOCKED_SIG"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.sig_valid
     /\ spend.sequence >= params.delay)
    => result = "SATISFIED"

\* I2: TIMELOCKED_SIG valid sig + sequence not met -> UNSATISFIED
Inv_TimelockedSig_SeqFail ==
    (phase = "done"
     /\ params.block_type = "TIMELOCKED_SIG"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.sig_valid
     /\ spend.sequence < params.delay)
    => result = "UNSATISFIED"

\* I3: HTLC claim path: valid sig + valid preimage -> SATISFIED
Inv_HTLC_ClaimAccept ==
    (phase = "done"
     /\ params.block_type = "HTLC"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.branch = 1
     /\ spend.sig_valid
     /\ spend.preimage_valid)
    => result = "SATISFIED"

\* I4: HTLC refund path: valid sig + timeout -> SATISFIED
Inv_HTLC_RefundAccept ==
    (phase = "done"
     /\ params.block_type = "HTLC"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.branch = 0
     /\ spend.sig_valid
     /\ spend.sequence >= params.delay)
    => result = "SATISFIED"

\* I5: HTLC claim path: invalid preimage -> UNSATISFIED
Inv_HTLC_ClaimBadPreimage ==
    (phase = "done"
     /\ params.block_type = "HTLC"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.branch = 1
     /\ ~spend.preimage_valid)
    => result = "UNSATISFIED"

\* I6: HASH_SIG valid hash + valid sig -> SATISFIED
Inv_HashSig_Accept ==
    (phase = "done"
     /\ params.block_type = "HASH_SIG"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.preimage_valid
     /\ spend.sig_valid)
    => result = "SATISFIED"

\* I7: PTLC valid adapted sig + sequence met -> SATISFIED
Inv_PTLC_Accept ==
    (phase = "done"
     /\ params.block_type = "PTLC"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.adaptor_sig_valid
     /\ spend.sequence >= params.delay)
    => result = "SATISFIED"

\* I8: CLTV_SIG valid sig + locktime met -> SATISFIED
Inv_CLTVSig_Accept ==
    (phase = "done"
     /\ params.block_type = "CLTV_SIG"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.sig_valid
     /\ spend.locktime >= params.target_height)
    => result = "SATISFIED"

\* I9: CLTV_SIG valid sig + locktime not met -> UNSATISFIED
Inv_CLTVSig_LocktimeFail ==
    (phase = "done"
     /\ params.block_type = "CLTV_SIG"
     /\ ~params.inverted
     /\ spend.has_context
     /\ spend.sig_valid
     /\ spend.locktime < params.target_height)
    => result = "UNSATISFIED"

\* I10: TIMELOCKED_MULTISIG M-of-N + sequence met -> SATISFIED
Inv_TimelockedMultisig_Accept ==
    (phase = "done"
     /\ params.block_type = "TIMELOCKED_MULTISIG"
     /\ ~params.inverted
     /\ spend.has_context
     /\ params.threshold <= params.num_keys
     /\ spend.num_valid_sigs >= params.threshold
     /\ spend.sequence >= params.delay)
    => result = "SATISFIED"

\* I11: All compound blocks non-invertible (inverted -> ERROR)
Inv_NonInvertible ==
    (phase = "done" /\ params.inverted)
    => result = "ERROR"

\* I12: No context -> ERROR
Inv_NoContextError ==
    (phase = "done" /\ ~spend.has_context)
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_TimelockedSig_Accept
    /\ Inv_TimelockedSig_SeqFail
    /\ Inv_HTLC_ClaimAccept
    /\ Inv_HTLC_RefundAccept
    /\ Inv_HTLC_ClaimBadPreimage
    /\ Inv_HashSig_Accept
    /\ Inv_PTLC_Accept
    /\ Inv_CLTVSig_Accept
    /\ Inv_CLTVSig_LocktimeFail
    /\ Inv_TimelockedMultisig_Accept
    /\ Inv_NonInvertible
    /\ Inv_NoContextError

=============================================================================
