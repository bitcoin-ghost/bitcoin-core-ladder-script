------------------------- MODULE BlockLegacy -------------------------
(***************************************************************************)
(* Model of the legacy wrapper block family (0x0901-0x0907):               *)
(*   - P2PK_LEGACY:         sig against committed pubkey                   *)
(*   - P2PKH_LEGACY:        HASH160(pubkey) match + sig                    *)
(*   - P2SH_LEGACY:         HASH160(script) match + inner eval            *)
(*   - P2WPKH_LEGACY:       delegates to P2PKH semantics                   *)
(*   - P2WSH_LEGACY:        SHA256(script) match + inner eval             *)
(*   - P2TR_LEGACY:         Schnorr sig against committed pubkey           *)
(*   - P2TR_SCRIPT_LEGACY:  script hash match + inner eval                *)
(*                                                                         *)
(* Key-consuming: P2PK, P2PKH, P2WPKH, P2TR, P2TR_SCRIPT                  *)
(* Invertible:    P2SH, P2WSH only                                         *)
(* Missing witness always yields ERROR (fail-closed)                       *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

CONSTANTS
    MaxHashValues   \* e.g. 4  (VPS: 8)

HashValues == 1..MaxHashValues

(***************************************************************************)
(* Block types                                                             *)
(***************************************************************************)

BlockTypes == {
    "P2PK_LEGACY",
    "P2PKH_LEGACY",
    "P2SH_LEGACY",
    "P2WPKH_LEGACY",
    "P2WSH_LEGACY",
    "P2TR_LEGACY",
    "P2TR_SCRIPT_LEGACY"
}

KeyConsumingTypes == {
    "P2PK_LEGACY",
    "P2PKH_LEGACY",
    "P2WPKH_LEGACY",
    "P2TR_LEGACY",
    "P2TR_SCRIPT_LEGACY"
}

InvertibleTypes == {
    "P2SH_LEGACY",
    "P2WSH_LEGACY"
}

\* Signature-only types: P2PK and P2TR delegate to SIG block
SigDelegateTypes == {
    "P2PK_LEGACY",
    "P2TR_LEGACY"
}

\* Hash-then-sig types: P2PKH, P2WPKH
HashSigTypes == {
    "P2PKH_LEGACY",
    "P2WPKH_LEGACY"
}

\* Script-hash types: P2SH, P2WSH, P2TR_SCRIPT
ScriptHashTypes == {
    "P2SH_LEGACY",
    "P2WSH_LEGACY",
    "P2TR_SCRIPT_LEGACY"
}

(***************************************************************************)
(* Block structure                                                         *)
(***************************************************************************)

\* Conditions committed at fund time
Conditions == [
    committed_hash: HashValues,     \* HASH160 or HASH256 depending on type
    committed_pubkey: HashValues    \* PUBKEY_COMMIT (used by P2PK, P2TR, P2TR_SCRIPT)
]

\* Witness provided at spend time
Witness == [
    has_witness: BOOLEAN,
    pubkey: HashValues,             \* witness pubkey
    sig_valid: BOOLEAN,             \* signature verification result
    script_hash: HashValues,        \* hash of provided script body
    inner_eval: {"SATISFIED", "UNSATISFIED", "ERROR"}   \* inner script evaluation
]

\* Block descriptor
Block == [
    type: BlockTypes,
    conditions: Conditions,
    witness: Witness,
    inverted: BOOLEAN
]

(***************************************************************************)
(* Evaluation functions                                                    *)
(***************************************************************************)

\* P2PK_LEGACY and P2TR_LEGACY: sig block semantics
\* Conditions: PUBKEY_COMMIT. Witness: PUBKEY + SIGNATURE.
EvalSigDelegate(block) ==
    IF ~block.witness.has_witness THEN "ERROR"
    ELSE IF block.witness.sig_valid THEN "SATISFIED"
    ELSE "UNSATISFIED"

\* P2PKH_LEGACY and P2WPKH_LEGACY: HASH160(pubkey) must match, then sig
\* Conditions: HASH160. Witness: PUBKEY + SIGNATURE.
\* We model HASH160(pubkey) match as: pubkey value == committed hash value
EvalHashSig(block) ==
    IF ~block.witness.has_witness THEN "ERROR"
    ELSE IF block.witness.pubkey # block.conditions.committed_hash THEN "UNSATISFIED"
    ELSE IF block.witness.sig_valid THEN "SATISFIED"
    ELSE "UNSATISFIED"

\* P2SH_LEGACY: HASH160(script) must match, then inner eval
\* P2WSH_LEGACY: SHA256(script) must match, then inner eval
\* P2TR_SCRIPT_LEGACY: SHA256(script) must match, then inner eval
\* We model hash match as: script_hash == committed_hash
EvalScriptHash(block) ==
    IF ~block.witness.has_witness THEN "ERROR"
    ELSE IF block.witness.script_hash # block.conditions.committed_hash THEN "UNSATISFIED"
    ELSE block.witness.inner_eval

\* Top-level raw evaluation (before inversion)
EvalRaw(block) ==
    IF block.type \in SigDelegateTypes THEN EvalSigDelegate(block)
    ELSE IF block.type \in HashSigTypes THEN EvalHashSig(block)
    ELSE IF block.type \in ScriptHashTypes THEN EvalScriptHash(block)
    ELSE "ERROR"

\* Inversion: only flips SATISFIED <-> UNSATISFIED; ERROR stays ERROR
ApplyInversion(raw, inverted) ==
    IF ~inverted THEN raw
    ELSE IF raw = "SATISFIED" THEN "UNSATISFIED"
    ELSE IF raw = "UNSATISFIED" THEN "SATISFIED"
    ELSE "ERROR"

\* Full evaluation with inversion guard
EvalBlock(block) ==
    \* Defense in depth: inverted + non-invertible → ERROR
    IF block.inverted /\ block.type \notin InvertibleTypes THEN "ERROR"
    ELSE ApplyInversion(EvalRaw(block), block.inverted)

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES block, result, phase

vars == <<block, result, phase>>

Init ==
    /\ block \in Block
    /\ result = "PENDING"
    /\ phase = "eval"

StepEval ==
    /\ phase = "eval"
    /\ result' = EvalBlock(block)
    /\ phase' = "done"
    /\ UNCHANGED <<block>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEval \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: P2PK valid sig against committed pubkey → SATISFIED
Inv_P2PK_ValidSig ==
    (phase = "done"
     /\ block.type = "P2PK_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.sig_valid)
    => result = "SATISFIED"

\* I2: P2PKH pubkey matches hash160 + valid sig → SATISFIED
Inv_P2PKH_ValidSig ==
    (phase = "done"
     /\ block.type = "P2PKH_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.pubkey = block.conditions.committed_hash
     /\ block.witness.sig_valid)
    => result = "SATISFIED"

\* I3: P2PKH pubkey doesn't match hash → UNSATISFIED
Inv_P2PKH_HashMismatch ==
    (phase = "done"
     /\ block.type = "P2PKH_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.pubkey # block.conditions.committed_hash)
    => result = "UNSATISFIED"

\* I4: P2SH script matches hash + inner evaluates → SATISFIED
Inv_P2SH_Valid ==
    (phase = "done"
     /\ block.type = "P2SH_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.script_hash = block.conditions.committed_hash
     /\ block.witness.inner_eval = "SATISFIED")
    => result = "SATISFIED"

\* I5: P2SH script doesn't match hash → UNSATISFIED
Inv_P2SH_HashMismatch ==
    (phase = "done"
     /\ block.type = "P2SH_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.script_hash # block.conditions.committed_hash)
    => result = "UNSATISFIED"

\* I6: P2WSH script matches hash256 + inner evaluates → SATISFIED
Inv_P2WSH_Valid ==
    (phase = "done"
     /\ block.type = "P2WSH_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.script_hash = block.conditions.committed_hash
     /\ block.witness.inner_eval = "SATISFIED")
    => result = "SATISFIED"

\* I7: P2TR valid Schnorr sig → SATISFIED
Inv_P2TR_ValidSig ==
    (phase = "done"
     /\ block.type = "P2TR_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.sig_valid)
    => result = "SATISFIED"

\* I8: P2TR_SCRIPT script hash matches + inner evaluates → SATISFIED
Inv_P2TR_Script_Valid ==
    (phase = "done"
     /\ block.type = "P2TR_SCRIPT_LEGACY"
     /\ ~block.inverted
     /\ block.witness.has_witness
     /\ block.witness.script_hash = block.conditions.committed_hash
     /\ block.witness.inner_eval = "SATISFIED")
    => result = "SATISFIED"

\* I9: Key-consuming types inverted → ERROR
Inv_KeyConsuming_NotInvertible ==
    (phase = "done"
     /\ block.type \in KeyConsumingTypes
     /\ block.inverted)
    => result = "ERROR"

\* I10: P2SH, P2WSH invertible (inversion flips result)
Inv_Invertible_Flips ==
    (phase = "done"
     /\ block.type \in InvertibleTypes
     /\ block.inverted
     /\ block.witness.has_witness
     /\ block.witness.script_hash = block.conditions.committed_hash
     /\ block.witness.inner_eval = "SATISFIED")
    => result = "UNSATISFIED"

\* I11: Missing witness → ERROR
Inv_MissingWitness ==
    (phase = "done"
     /\ ~block.witness.has_witness
     /\ ~(block.inverted /\ block.type \notin InvertibleTypes))
    => result = "ERROR"

SafetyInvariant ==
    /\ Inv_P2PK_ValidSig
    /\ Inv_P2PKH_ValidSig
    /\ Inv_P2PKH_HashMismatch
    /\ Inv_P2SH_Valid
    /\ Inv_P2SH_HashMismatch
    /\ Inv_P2WSH_Valid
    /\ Inv_P2TR_ValidSig
    /\ Inv_P2TR_Script_Valid
    /\ Inv_KeyConsuming_NotInvertible
    /\ Inv_Invertible_Flips
    /\ Inv_MissingWitness

=============================================================================
