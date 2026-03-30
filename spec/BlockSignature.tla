------------------------ MODULE BlockSignature ------------------------
(***************************************************************************)
(* Model of the signature family block types (0x0001-0x0005):              *)
(*   - SIG: single signature (Schnorr/ECDSA/PQ via SCHEME)                *)
(*   - MULTISIG: M-of-N threshold with distinct pubkey matching           *)
(*   - ADAPTOR_SIG: adaptor signature with tweak point                    *)
(*   - MUSIG_THRESHOLD: MuSig2/FROST aggregate (single Schnorr verify)    *)
(*   - KEY_REF_SIG: signature using pubkey from relay block reference      *)
(*                                                                         *)
(* All signature blocks are key-consuming and non-invertible.              *)
(* Missing pubkey/signature fields are fail-closed (ERROR).                *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxKeys,       \* e.g. 4  (VPS: 8)
    MaxThreshold   \* e.g. 4  (VPS: 8)

BlockTypes == {"SIG", "MULTISIG", "ADAPTOR_SIG", "MUSIG_THRESHOLD", "KEY_REF_SIG"}
Keys == 1..MaxKeys
Thresholds == 1..MaxThreshold

(***************************************************************************)
(* Block parameters and witness inputs                                     *)
(***************************************************************************)

\* Which signatures are valid (modelled as a set of key indices)
\* valid_sigs[i] = TRUE means the i-th signature verifies against its
\* matched pubkey.

SigBlockParams == [
    block_type: BlockTypes,
    \* SIG fields
    has_pubkey: BOOLEAN,        \* witness contains PUBKEY
    has_sig: BOOLEAN,           \* witness contains SIGNATURE
    sig_valid: BOOLEAN,         \* signature verifies against pubkey
    \* MULTISIG fields
    threshold: 0..MaxThreshold, \* M (NUMERIC field; 0 = missing)
    num_keys: 0..MaxKeys,       \* N pubkeys in witness
    num_valid_sigs: 0..MaxKeys, \* how many sigs verify against distinct keys
    \* ADAPTOR_SIG fields
    has_tweak_pubkey: BOOLEAN,  \* second pubkey (tweak point) present
    adapted_sig_valid: BOOLEAN, \* adapted signature verifies
    \* MUSIG_THRESHOLD fields (reuses has_pubkey, has_sig, sig_valid)
    \* KEY_REF_SIG fields
    relay_satisfied: BOOLEAN,   \* referenced relay block is satisfied
    relay_has_pubkey: BOOLEAN,  \* referenced relay block has a pubkey
    \* Common
    inverted: BOOLEAN           \* block has inversion flag set
]

(***************************************************************************)
(* Evaluation logic                                                        *)
(***************************************************************************)

EvalSig(p) ==
    IF p.inverted THEN "ERROR"
    ELSE IF ~p.has_pubkey \/ ~p.has_sig THEN "ERROR"
    ELSE IF p.sig_valid THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalMultisig(p) ==
    IF p.inverted THEN "ERROR"
    ELSE IF p.threshold = 0 THEN "ERROR"              \* missing/invalid threshold
    ELSE IF p.num_keys = 0 THEN "ERROR"               \* no pubkeys
    ELSE IF p.threshold > p.num_keys THEN "ERROR"     \* M > N
    ELSE IF p.num_valid_sigs >= p.threshold THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalAdaptorSig(p) ==
    IF p.inverted THEN "ERROR"
    ELSE IF ~p.has_pubkey THEN "ERROR"
    ELSE IF ~p.has_sig THEN "ERROR"
    ELSE IF p.adapted_sig_valid THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalMusigThreshold(p) ==
    IF p.inverted THEN "ERROR"
    ELSE IF ~p.has_pubkey \/ ~p.has_sig THEN "ERROR"
    ELSE IF p.sig_valid THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalKeyRefSig(p) ==
    IF p.inverted THEN "ERROR"
    ELSE IF ~p.relay_satisfied THEN "ERROR"
    ELSE IF ~p.relay_has_pubkey THEN "ERROR"
    ELSE IF ~p.has_sig THEN "ERROR"
    ELSE IF p.sig_valid THEN "SATISFIED"
    ELSE "UNSATISFIED"

EvalBlockSignature(p) ==
    CASE p.block_type = "SIG"              -> EvalSig(p)
      [] p.block_type = "MULTISIG"         -> EvalMultisig(p)
      [] p.block_type = "ADAPTOR_SIG"      -> EvalAdaptorSig(p)
      [] p.block_type = "MUSIG_THRESHOLD"  -> EvalMusigThreshold(p)
      [] p.block_type = "KEY_REF_SIG"      -> EvalKeyRefSig(p)

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES params, result, phase

vars == <<params, result, phase>>

Init ==
    /\ params \in SigBlockParams
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalBlockSignature(params)
    /\ phase' = "done"
    /\ UNCHANGED <<params>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: SIG with valid sig -> SATISFIED
Inv_SigValidSatisfied ==
    (phase = "done" /\ params.block_type = "SIG"
     /\ ~params.inverted
     /\ params.has_pubkey /\ params.has_sig
     /\ params.sig_valid)
    => result = "SATISFIED"

\* I2: SIG with invalid sig -> UNSATISFIED
Inv_SigInvalidUnsatisfied ==
    (phase = "done" /\ params.block_type = "SIG"
     /\ ~params.inverted
     /\ params.has_pubkey /\ params.has_sig
     /\ ~params.sig_valid)
    => result = "UNSATISFIED"

\* I3: MULTISIG with M valid distinct sigs -> SATISFIED
Inv_MultisigValidSatisfied ==
    (phase = "done" /\ params.block_type = "MULTISIG"
     /\ ~params.inverted
     /\ params.threshold > 0 /\ params.num_keys > 0
     /\ params.threshold <= params.num_keys
     /\ params.num_valid_sigs >= params.threshold)
    => result = "SATISFIED"

\* I4: MULTISIG with fewer than M valid sigs -> UNSATISFIED
Inv_MultisigInsufficientUnsatisfied ==
    (phase = "done" /\ params.block_type = "MULTISIG"
     /\ ~params.inverted
     /\ params.threshold > 0 /\ params.num_keys > 0
     /\ params.threshold <= params.num_keys
     /\ params.num_valid_sigs < params.threshold)
    => result = "UNSATISFIED"

\* I5: MULTISIG with M > N -> ERROR (invalid params)
Inv_MultisigBadParamsError ==
    (phase = "done" /\ params.block_type = "MULTISIG"
     /\ ~params.inverted
     /\ params.threshold > 0 /\ params.num_keys > 0
     /\ params.threshold > params.num_keys)
    => result = "ERROR"

\* I6: ADAPTOR_SIG with valid adapted sig -> SATISFIED
Inv_AdaptorValidSatisfied ==
    (phase = "done" /\ params.block_type = "ADAPTOR_SIG"
     /\ ~params.inverted
     /\ params.has_pubkey /\ params.has_sig
     /\ params.adapted_sig_valid)
    => result = "SATISFIED"

\* I7: MUSIG_THRESHOLD with valid aggregate -> SATISFIED
Inv_MusigValidSatisfied ==
    (phase = "done" /\ params.block_type = "MUSIG_THRESHOLD"
     /\ ~params.inverted
     /\ params.has_pubkey /\ params.has_sig
     /\ params.sig_valid)
    => result = "SATISFIED"

\* I8: KEY_REF_SIG with valid relay ref + valid sig -> SATISFIED
Inv_KeyRefValidSatisfied ==
    (phase = "done" /\ params.block_type = "KEY_REF_SIG"
     /\ ~params.inverted
     /\ params.relay_satisfied /\ params.relay_has_pubkey
     /\ params.has_sig /\ params.sig_valid)
    => result = "SATISFIED"

\* I9: KEY_REF_SIG with unsatisfied relay -> ERROR
Inv_KeyRefUnsatisfiedRelayError ==
    (phase = "done" /\ params.block_type = "KEY_REF_SIG"
     /\ ~params.inverted
     /\ ~params.relay_satisfied)
    => result = "ERROR"

\* I10: All sig blocks are non-invertible (inverted -> ERROR)
Inv_InvertedError ==
    (phase = "done" /\ params.inverted)
    => result = "ERROR"

\* I11: Missing pubkey -> ERROR (fail-closed)
Inv_MissingPubkeyError ==
    (phase = "done" /\ ~params.inverted
     /\ \/ (params.block_type = "SIG" /\ ~params.has_pubkey)
        \/ (params.block_type = "ADAPTOR_SIG" /\ ~params.has_pubkey)
        \/ (params.block_type = "MUSIG_THRESHOLD" /\ ~params.has_pubkey)
        \/ (params.block_type = "MULTISIG" /\ params.num_keys = 0)
        \/ (params.block_type = "KEY_REF_SIG" /\ params.relay_satisfied /\ ~params.relay_has_pubkey))
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_SigValidSatisfied
    /\ Inv_SigInvalidUnsatisfied
    /\ Inv_MultisigValidSatisfied
    /\ Inv_MultisigInsufficientUnsatisfied
    /\ Inv_MultisigBadParamsError
    /\ Inv_AdaptorValidSatisfied
    /\ Inv_MusigValidSatisfied
    /\ Inv_KeyRefValidSatisfied
    /\ Inv_KeyRefUnsatisfiedRelayError
    /\ Inv_InvertedError
    /\ Inv_MissingPubkeyError

=============================================================================
