------------------------- MODULE BlockCovenant -------------------------
(***************************************************************************)
(* Model of the covenant family block types:                               *)
(*   - CTV (0x0301): OP_CHECKTEMPLATEVERIFY covenant                       *)
(*   - VAULT_LOCK (0x0302): Two-path vault timelock covenant               *)
(*   - AMOUNT_LOCK (0x0303): Output amount range check                     *)
(*                                                                         *)
(* CTV verifies template hash of spending tx (invertible).                 *)
(* VAULT_LOCK: recovery path (cold key, no delay) vs hot path              *)
(*   (hot key + CSV delay). Key-consuming (not invertible).                *)
(* AMOUNT_LOCK checks min_sats <= output_amount <= max_sats (invertible).  *)
(*                                                                         *)
(* All three fail-closed: ERROR when tx context is missing.                *)
(***************************************************************************)

EXTENDS Integers

CONSTANTS
    MaxAmount,   \* e.g. 1000
    MaxDelay     \* e.g. 144

Amounts == 0..MaxAmount
Delays == 0..MaxDelay

BlockTypes == {"CTV", "VAULT_LOCK", "AMOUNT_LOCK"}

(***************************************************************************)
(* CTV (0x0301) evaluation                                                 *)
(***************************************************************************)

\* Template hash commits to: nVersion, nLockTime, scriptSigs hash,
\* number of inputs, sequences hash, number of outputs, outputs hash,
\* input index.
CTVParams == [
    template_hash: {0, 1}   \* 0 = matches spending tx, 1 = mismatch
]

CTVSpend == [
    has_context: BOOLEAN
]

EvalCTV(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.template_hash = 0 THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* VAULT_LOCK (0x0302) evaluation                                          *)
(***************************************************************************)

\* Two PUBKEYs (hot_key, cold_key) + NUMERIC (csv_delay).
\* Recovery path: cold key, immediate. Hot path: hot key + CSV delay.
VaultLockParams == [
    csv_delay: Delays
]

VaultLockSpend == [
    has_context: BOOLEAN,
    signing_key: {"cold", "hot", "none"},   \* which key signs
    elapsed_delay: Delays,                  \* CSV blocks elapsed
    inverted: BOOLEAN                       \* attempt to invert block
]

EvalVaultLock(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF s.inverted THEN "ERROR"         \* key-consuming, not invertible
    ELSE IF s.signing_key = "cold" THEN "SATISFIED"
    ELSE IF s.signing_key = "hot" THEN
        IF s.elapsed_delay >= p.csv_delay THEN "SATISFIED"
        ELSE "UNSATISFIED"
    ELSE "UNSATISFIED"                      \* no valid signature

(***************************************************************************)
(* AMOUNT_LOCK (0x0303) evaluation                                         *)
(***************************************************************************)

\* Conditions: NUMERIC (min_sats), NUMERIC (max_sats).
\* Checks: min_sats <= output_amount <= max_sats.
AmountLockParams == [
    min_sats: Amounts,
    max_sats: Amounts
]

AmountLockSpend == [
    has_context: BOOLEAN,
    output_amount: Amounts
]

EvalAmountLock(p, s) ==
    IF ~s.has_context THEN "ERROR"
    ELSE IF p.min_sats > p.max_sats THEN "UNSATISFIED"
    ELSE IF s.output_amount >= p.min_sats /\ s.output_amount <= p.max_sats
        THEN "SATISFIED"
    ELSE "UNSATISFIED"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES block_type, ctv_params, ctv_spend,
          vault_params, vault_spend,
          amount_params, amount_spend,
          result, phase

vars == <<block_type, ctv_params, ctv_spend,
          vault_params, vault_spend,
          amount_params, amount_spend,
          result, phase>>

Init ==
    /\ block_type \in BlockTypes
    /\ ctv_params \in CTVParams
    /\ ctv_spend \in CTVSpend
    /\ vault_params \in VaultLockParams
    /\ vault_spend \in VaultLockSpend
    /\ amount_params \in AmountLockParams
    /\ amount_spend \in AmountLockSpend
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = CASE block_type = "CTV" -> EvalCTV(ctv_params, ctv_spend)
                   [] block_type = "VAULT_LOCK" -> EvalVaultLock(vault_params, vault_spend)
                   [] block_type = "AMOUNT_LOCK" -> EvalAmountLock(amount_params, amount_spend)
    /\ phase' = "done"
    /\ UNCHANGED <<block_type, ctv_params, ctv_spend,
                    vault_params, vault_spend,
                    amount_params, amount_spend>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: CTV with matching template hash -> SATISFIED
Inv_CTVMatch ==
    (phase = "done" /\ block_type = "CTV"
     /\ ctv_spend.has_context
     /\ ctv_params.template_hash = 0)
    => result = "SATISFIED"

\* I2: CTV with wrong template hash -> UNSATISFIED
Inv_CTVMismatch ==
    (phase = "done" /\ block_type = "CTV"
     /\ ctv_spend.has_context
     /\ ctv_params.template_hash = 1)
    => result = "UNSATISFIED"

\* I3: CTV is invertible (never returns ERROR when context present)
Inv_CTVInvertible ==
    (phase = "done" /\ block_type = "CTV"
     /\ ctv_spend.has_context)
    => result /= "ERROR"

\* I4: VAULT_LOCK cold key path -> SATISFIED (no delay)
Inv_VaultColdKey ==
    (phase = "done" /\ block_type = "VAULT_LOCK"
     /\ vault_spend.has_context
     /\ ~vault_spend.inverted
     /\ vault_spend.signing_key = "cold")
    => result = "SATISFIED"

\* I5: VAULT_LOCK hot key path with sufficient delay -> SATISFIED
Inv_VaultHotKeyDelayed ==
    (phase = "done" /\ block_type = "VAULT_LOCK"
     /\ vault_spend.has_context
     /\ ~vault_spend.inverted
     /\ vault_spend.signing_key = "hot"
     /\ vault_spend.elapsed_delay >= vault_params.csv_delay)
    => result = "SATISFIED"

\* I6: VAULT_LOCK hot key path without sufficient delay -> UNSATISFIED
Inv_VaultHotKeyNoDelay ==
    (phase = "done" /\ block_type = "VAULT_LOCK"
     /\ vault_spend.has_context
     /\ ~vault_spend.inverted
     /\ vault_spend.signing_key = "hot"
     /\ vault_spend.elapsed_delay < vault_params.csv_delay)
    => result = "UNSATISFIED"

\* I7: VAULT_LOCK non-invertible (inverted -> ERROR)
Inv_VaultNotInvertible ==
    (phase = "done" /\ block_type = "VAULT_LOCK"
     /\ vault_spend.has_context
     /\ vault_spend.inverted)
    => result = "ERROR"

\* I8: AMOUNT_LOCK within range -> SATISFIED
Inv_AmountInRange ==
    (phase = "done" /\ block_type = "AMOUNT_LOCK"
     /\ amount_spend.has_context
     /\ amount_params.min_sats <= amount_params.max_sats
     /\ amount_spend.output_amount >= amount_params.min_sats
     /\ amount_spend.output_amount <= amount_params.max_sats)
    => result = "SATISFIED"

\* I9: AMOUNT_LOCK below min -> UNSATISFIED
Inv_AmountBelowMin ==
    (phase = "done" /\ block_type = "AMOUNT_LOCK"
     /\ amount_spend.has_context
     /\ amount_params.min_sats <= amount_params.max_sats
     /\ amount_spend.output_amount < amount_params.min_sats)
    => result = "UNSATISFIED"

\* I10: AMOUNT_LOCK above max -> UNSATISFIED
Inv_AmountAboveMax ==
    (phase = "done" /\ block_type = "AMOUNT_LOCK"
     /\ amount_spend.has_context
     /\ amount_params.min_sats <= amount_params.max_sats
     /\ amount_spend.output_amount > amount_params.max_sats)
    => result = "UNSATISFIED"

\* I11: No context -> ERROR (fail-closed, all block types)
Inv_NoContextError ==
    (phase = "done" /\
     ((block_type = "CTV" /\ ~ctv_spend.has_context)
      \/ (block_type = "VAULT_LOCK" /\ ~vault_spend.has_context)
      \/ (block_type = "AMOUNT_LOCK" /\ ~amount_spend.has_context)))
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_CTVMatch
    /\ Inv_CTVMismatch
    /\ Inv_CTVInvertible
    /\ Inv_VaultColdKey
    /\ Inv_VaultHotKeyDelayed
    /\ Inv_VaultHotKeyNoDelay
    /\ Inv_VaultNotInvertible
    /\ Inv_AmountInRange
    /\ Inv_AmountBelowMin
    /\ Inv_AmountAboveMax
    /\ Inv_NoContextError

=============================================================================
