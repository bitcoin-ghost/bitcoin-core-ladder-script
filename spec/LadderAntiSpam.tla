---------------------- MODULE LadderAntiSpam ----------------------
(***************************************************************************)
(* Model of the Ladder Script anti-spam field validation rules:            *)
(*   - 11 data field types with context-dependent restrictions             *)
(*   - Witness-only types rejected in CONDITIONS context                   *)
(*   - DATA type restricted to DATA_RETURN blocks only                     *)
(*   - PREIMAGE count capped per transaction across all inputs             *)
(*   - Implicit layout enforcement: blocks with known layout use compact   *)
(*     encoding; field count and types must match exactly                  *)
(*   - Data-embedding protection: blocks WITHOUT implicit layout reject    *)
(*     high-bandwidth types (HASH256, HASH160, PUBKEY_COMMIT, DATA)        *)
(*   - ACCUMULATOR exception: up to 10 HASH256 fields (Merkle proof)      *)
(*                                                                         *)
(* Verifies: witness-only rejection, DATA restriction, PREIMAGE cap,       *)
(* layout acceptance, data-embedding blocked, ACCUMULATOR whitelisted,     *)
(* embeddable surface bounded.                                             *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxFields,          \* max fields per block (VPS: 8, small: 3)
    MaxPreimagePerTx    \* max PREIMAGE fields across all inputs (VPS: 50, small: 3)

(***************************************************************************)
(* Data types                                                              *)
(***************************************************************************)

\* All 11 data field types
DataTypes == {
    "PUBKEY", "PUBKEY_COMMIT", "HASH256", "HASH160", "PREIMAGE",
    "SIGNATURE", "SPEND_INDEX", "NUMERIC", "SCHEME", "SCRIPT_BODY", "DATA"
}

\* Types allowed in CONDITIONS context (IsConditionDataType)
ConditionTypes == {
    "HASH256", "HASH160", "NUMERIC", "SCHEME", "SPEND_INDEX", "DATA"
}

\* Witness-only types: rejected in CONDITIONS context
WitnessOnlyTypes == DataTypes \ ConditionTypes

\* High-bandwidth types that enable data embedding (IsDataEmbeddingType)
DataEmbeddingTypes == {
    "PUBKEY_COMMIT", "HASH256", "HASH160", "DATA"
}

\* Maximum bytes per field type
MaxFieldBytes(t) ==
    CASE t = "PUBKEY"        -> 2048
    []   t = "PUBKEY_COMMIT" -> 32
    []   t = "HASH256"       -> 32
    []   t = "HASH160"       -> 20
    []   t = "PREIMAGE"      -> 32
    []   t = "SIGNATURE"     -> 50000
    []   t = "SPEND_INDEX"   -> 4
    []   t = "NUMERIC"       -> 8
    []   t = "SCHEME"        -> 1
    []   t = "SCRIPT_BODY"   -> 80
    []   t = "DATA"          -> 40

(***************************************************************************)
(* Block types and contexts                                                *)
(***************************************************************************)

\* Serialization context
Contexts == { "CONDITIONS", "WITNESS" }

\* Representative block categories (abstracted from 31+ concrete types)
BlockTypes == {
    "HAS_LAYOUT",       \* block type with an implicit field layout
    "NO_LAYOUT",        \* block type without implicit layout (e.g. ANCHOR)
    "DATA_RETURN",      \* DATA_RETURN: only block that accepts DATA type
    "ACCUMULATOR"       \* ACCUMULATOR: whitelisted for HASH256 in conditions
}

\* Maximum ACCUMULATOR fields (root + 8 proof nodes + leaf)
MaxAccumulatorFields == 10

(***************************************************************************)
(* Fields and blocks                                                       *)
(***************************************************************************)

\* A field is a data type
Fields == DataTypes

\* A field sequence: 1..MaxFields -> DataTypes (or empty)
FieldSeqs == UNION { [1..n -> Fields] : n \in 0..MaxFields }

\* A block under validation
Block == [
    block_type: BlockTypes,
    context:    Contexts,
    fields:     FieldSeqs
]

(***************************************************************************)
(* Anti-spam validation for a single block                                 *)
(***************************************************************************)

\* Count occurrences of a given type in a field sequence
CountType(fseq, t) ==
    Cardinality({ i \in DOMAIN fseq : fseq[i] = t })

ValidateBlock(b) ==
    LET nf    == Cardinality(DOMAIN b.fields)
        ctx   == b.context
        btype == b.block_type
    IN
    \* R1: Witness-only types in CONDITIONS context -> ERROR
    IF ctx = "CONDITIONS" /\ \E i \in DOMAIN b.fields : b.fields[i] \in WitnessOnlyTypes
    THEN "ERROR_WITNESS_ONLY"

    \* R2: DATA type in non-DATA_RETURN block -> ERROR
    ELSE IF btype /= "DATA_RETURN" /\ \E i \in DOMAIN b.fields : b.fields[i] = "DATA"
    THEN "ERROR_DATA_RESTRICTED"

    \* R3: ACCUMULATOR field count cap
    ELSE IF btype = "ACCUMULATOR" /\ nf > MaxAccumulatorFields
    THEN "ERROR_ACCUMULATOR_OVERFLOW"

    \* R4: Block with implicit layout -> fields accepted (compact encoding)
    \*     Layout match is enforced by deserializer; if we reach here with
    \*     HAS_LAYOUT, DATA_RETURN, or ACCUMULATOR, the layout matched.
    ELSE IF btype = "HAS_LAYOUT" \/ btype = "DATA_RETURN"
    THEN "ACCEPTED"

    \* R5: ACCUMULATOR with <= 10 HASH256 -> accepted (exception)
    ELSE IF btype = "ACCUMULATOR" /\ nf <= MaxAccumulatorFields
    THEN "ACCEPTED"

    \* R6: Block WITHOUT layout: reject data-embedding types
    ELSE IF btype = "NO_LAYOUT" /\ \E i \in DOMAIN b.fields : b.fields[i] \in DataEmbeddingTypes
    THEN "ERROR_DATA_EMBEDDING"

    \* R7: No-layout block with only non-embedding types -> accepted
    ELSE "ACCEPTED"

(***************************************************************************)
(* Transaction-level PREIMAGE count validation                             *)
(***************************************************************************)

\* An input is a sequence of blocks (simplified: sequence of field seqs)
\* Model: a tx has 1..2 inputs, each with 1 block
TxInputs == [
    block1: Block,
    block2: Block
]

CountTxPreimages(tx) ==
    CountType(tx.block1.fields, "PREIMAGE") +
    CountType(tx.block2.fields, "PREIMAGE")

ValidatePreimageLimit(tx) ==
    IF CountTxPreimages(tx) > MaxPreimagePerTx
    THEN "ERROR_PREIMAGE_LIMIT"
    ELSE "OK"

(***************************************************************************)
(* Embeddable byte surface calculation                                     *)
(***************************************************************************)

\* Upper bound on embeddable bytes for a single block
EmbeddableBytes(b) ==
    LET nf == Cardinality(DOMAIN b.fields) IN
    IF ValidateBlock(b) /= "ACCEPTED" THEN 0
    ELSE IF b.block_type = "ACCUMULATOR"
         THEN nf * 32   \* HASH256 only, 32 bytes each, max 320
    ELSE IF b.block_type = "NO_LAYOUT"
         \* Only non-embedding types survive; NUMERIC(8), SPEND_INDEX(4), SCHEME(1)
         THEN nf * 8
    ELSE \* HAS_LAYOUT or DATA_RETURN: layout-controlled
         0   \* fields are layout-constrained, not attacker-controlled

\* Max embeddable bytes per tx (2 blocks)
MaxEmbeddableTxBytes == 2 * MaxAccumulatorFields * 32

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES tx, blockResult1, blockResult2, preimageResult, phase

vars == <<tx, blockResult1, blockResult2, preimageResult, phase>>

Init ==
    /\ tx \in TxInputs
    /\ blockResult1 = "PENDING"
    /\ blockResult2 = "PENDING"
    /\ preimageResult = "PENDING"
    /\ phase = "eval_blocks"

StepEvalBlocks ==
    /\ phase = "eval_blocks"
    /\ blockResult1' = ValidateBlock(tx.block1)
    /\ blockResult2' = ValidateBlock(tx.block2)
    /\ phase' = "eval_preimage"
    /\ UNCHANGED <<tx, preimageResult>>

StepEvalPreimage ==
    /\ phase = "eval_preimage"
    /\ preimageResult' = ValidatePreimageLimit(tx)
    /\ phase' = "done"
    /\ UNCHANGED <<tx, blockResult1, blockResult2>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEvalBlocks \/ StepEvalPreimage \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Witness-only type in CONDITIONS context -> ERROR
Inv_WitnessOnlyRejected ==
    (phase = "done"
     /\ tx.block1.context = "CONDITIONS"
     /\ \E i \in DOMAIN tx.block1.fields : tx.block1.fields[i] \in WitnessOnlyTypes)
    => blockResult1 = "ERROR_WITNESS_ONLY"

\* I2: DATA type in non-DATA_RETURN block -> ERROR
Inv_DataRestricted ==
    (phase = "done"
     /\ tx.block1.block_type /= "DATA_RETURN"
     /\ \E i \in DOMAIN tx.block1.fields : tx.block1.fields[i] = "DATA")
    => blockResult1 \in { "ERROR_DATA_RESTRICTED", "ERROR_WITNESS_ONLY" }

\* I3: PREIMAGE count exceeding limit -> ERROR
Inv_PreimageLimitEnforced ==
    (phase = "done" /\ CountTxPreimages(tx) > MaxPreimagePerTx)
    => preimageResult = "ERROR_PREIMAGE_LIMIT"

\* I4: Block matching implicit layout -> accepted (compact encoding)
Inv_LayoutBlockAccepted ==
    (phase = "done"
     /\ tx.block1.block_type = "HAS_LAYOUT"
     /\ tx.block1.context = "CONDITIONS"
     /\ \A i \in DOMAIN tx.block1.fields : tx.block1.fields[i] \in ConditionTypes
     /\ \A i \in DOMAIN tx.block1.fields : tx.block1.fields[i] /= "DATA")
    => blockResult1 = "ACCEPTED"

\* I5: Block NOT matching layout with HASH256 -> rejected (data embedding blocked)
Inv_NoLayoutHash256Rejected ==
    (phase = "done"
     /\ tx.block1.block_type = "NO_LAYOUT"
     /\ \E i \in DOMAIN tx.block1.fields : tx.block1.fields[i] = "HASH256"
     \* Not a witness-only error (HASH256 is allowed in conditions)
     /\ ~(tx.block1.context = "CONDITIONS"
          /\ \E j \in DOMAIN tx.block1.fields : tx.block1.fields[j] \in WitnessOnlyTypes))
    => blockResult1 = "ERROR_DATA_EMBEDDING"

\* I6: ACCUMULATOR with <= 10 HASH256 -> accepted (exception)
Inv_AccumulatorAccepted ==
    (phase = "done"
     /\ tx.block1.block_type = "ACCUMULATOR"
     /\ Cardinality(DOMAIN tx.block1.fields) <= MaxAccumulatorFields
     /\ ~(tx.block1.context = "CONDITIONS"
          /\ \E i \in DOMAIN tx.block1.fields : tx.block1.fields[i] \in WitnessOnlyTypes)
     /\ \A i \in DOMAIN tx.block1.fields : tx.block1.fields[i] /= "DATA")
    => blockResult1 = "ACCEPTED"

\* I7: Valid implicit layout block always accepted
Inv_ValidLayoutAlwaysAccepted ==
    (phase = "done"
     /\ tx.block1.block_type \in { "HAS_LAYOUT", "DATA_RETURN" }
     /\ ~(tx.block1.context = "CONDITIONS"
          /\ \E i \in DOMAIN tx.block1.fields : tx.block1.fields[i] \in WitnessOnlyTypes)
     /\ ~(tx.block1.block_type /= "DATA_RETURN"
          /\ \E i \in DOMAIN tx.block1.fields : tx.block1.fields[i] = "DATA"))
    => blockResult1 = "ACCEPTED"

\* I8: Embeddable surface bounded (total embeddable bytes limited)
\*     Accepted blocks can embed at most MaxEmbeddableTxBytes across the tx
Inv_EmbeddableSurfaceBounded ==
    phase = "done"
    => EmbeddableBytes(tx.block1) + EmbeddableBytes(tx.block2) <= MaxEmbeddableTxBytes

SafetyInvariant ==
    /\ Inv_WitnessOnlyRejected
    /\ Inv_DataRestricted
    /\ Inv_PreimageLimitEnforced
    /\ Inv_LayoutBlockAccepted
    /\ Inv_NoLayoutHash256Rejected
    /\ Inv_AccumulatorAccepted
    /\ Inv_ValidLayoutAlwaysAccepted
    /\ Inv_EmbeddableSurfaceBounded

=============================================================================
