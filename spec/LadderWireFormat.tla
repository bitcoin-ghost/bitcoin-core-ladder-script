--------------------- MODULE LadderWireFormat ---------------------
(***************************************************************************)
(* Model of the TX_MLSC wire format encoding/decoding:                     *)
(*   - Micro-header encoding: slots 0x00-0x7F map to block types          *)
(*   - Escape codes: 0x80 = full header, 0x81 = full header (inverted)    *)
(*   - Full header: escape byte + 16-bit block type (little-endian)       *)
(*   - TX_MLSC: version=4, dummy=0x00, flags=0x02                         *)
(*   - Flag 0x01 = SegWit, 0x02 = TX_MLSC, 0x03 = INVALID                *)
(*   - Value-only outputs (8 bytes each, no scriptPubKey on wire)         *)
(*   - Creation proof: CompactSize + leaves (max 252 x 32 bytes)          *)
(*   - Aggregated sig: max 32 bytes                                       *)
(*   - Implicit field encoding: no type byte, no field count              *)
(*   - Explicit field encoding: field count + per-field (type + data)     *)
(*                                                                         *)
(* Verifies: round-trip fidelity, flag rejection, micro-header            *)
(* injectivity, escape semantics, output inflation, proof bounds.         *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxSlots      \* VPS: MaxSlots = 128.  Model: 5 (abstract micro-header table)

(***************************************************************************)
(* Block types and micro-header lookup table                               *)
(***************************************************************************)

\* Abstract block-type universe: 0..65535 (uint16_t).  We model a small
\* representative set that fits into MaxSlots plus a few that require
\* full-header encoding.
SlotRange   == 0..(MaxSlots - 1)
BlockTypes  == 0..((MaxSlots + 3) - 1)  \* some types beyond slot range

\* Lookup table: slot -> block type.  Injective partial function.
\* We model a concrete table as a function from SlotRange to BlockTypes
\* where each slot maps to a distinct block type.
MicroHeaderTables == { t \in [SlotRange -> BlockTypes] :
    \A i, j \in SlotRange : i # j => t[i] # t[j] }

\* Escape byte constants (0x80 = 128, 0x81 = 129)
ESCAPE_FULL    == 128
ESCAPE_INV     == 129

\* Check whether a block type has a slot in the table
HasSlot(tbl, btype) ==
    \E s \in SlotRange : tbl[s] = btype

SlotOf(tbl, btype) ==
    CHOOSE s \in SlotRange : tbl[s] = btype

(***************************************************************************)
(* Micro-header encoding                                                   *)
(***************************************************************************)

\* Encoded header representation
\*   <<"micro", slot>>          -- 1-byte micro-header
\*   <<"full", btype, FALSE>>   -- 0x80 + 2-byte type (non-inverted)
\*   <<"full", btype, TRUE>>    -- 0x81 + 2-byte type (inverted)

EncodeMicroHeader(tbl, btype, inv) ==
    IF ~inv /\ HasSlot(tbl, btype)
    THEN <<"micro", SlotOf(tbl, btype)>>
    ELSE IF ~inv
    THEN <<"full", btype, FALSE>>
    ELSE <<"full", btype, TRUE>>

DecodeMicroHeader(tbl, enc) ==
    IF enc[1] = "micro"
    THEN [type |-> tbl[enc[2]], inverted |-> FALSE, ok |-> TRUE]
    ELSE IF enc[1] = "full" /\ enc[3] = FALSE
    THEN [type |-> enc[2], inverted |-> FALSE, ok |-> TRUE]
    ELSE IF enc[1] = "full" /\ enc[3] = TRUE
    THEN [type |-> enc[2], inverted |-> TRUE, ok |-> TRUE]
    ELSE [type |-> 0, inverted |-> FALSE, ok |-> FALSE]

(***************************************************************************)
(* TX_MLSC flag byte semantics                                             *)
(***************************************************************************)

FlagValues == 0..3

\* 0x00 = legacy (no extended format)
\* 0x01 = SegWit
\* 0x02 = TX_MLSC
\* 0x03 = INVALID (SegWit + MLSC combined)

ClassifyFlag(f) ==
    IF f = 0 THEN "LEGACY"
    ELSE IF f = 1 THEN "SEGWIT"
    ELSE IF f = 2 THEN "TX_MLSC"
    ELSE "REJECT"

(***************************************************************************)
(* TX_MLSC transaction wire format                                         *)
(***************************************************************************)

MaxOutputs     == 4
MaxProofLeaves == 252   \* CompactSize < 253 encoding boundary
MaxAggSigLen   == 32

\* Abstract proof-leaf counts: representative values from the three
\* CompactSize-relevant ranges (0, small, boundary).  Full range is
\* 0..252 in production; we keep model state space tractable.
ProofLeafCounts == {0, 1, 4, 252}

\* Abstract aggregated-sig lengths
AggSigLens == {0, 16, 32}

\* Fixed output values for model (4 outputs max)
OutputVals == {<<10, 20, 30, 40>>}

\* Wire size of value-only outputs (8 bytes each, no scriptPubKey)
WireOutputBytes(n) == n * 8

\* Wire size of full CTxOut outputs (8-byte value + scriptPubKey)
FullOutputBytes(n) == n * (8 + 33)  \* 0xDF + 32-byte root

(***************************************************************************)
(* Field encoding: implicit vs explicit                                    *)
(***************************************************************************)

\* Abstract field: <<type_name, data_len>>
\* Implicit layout: known at both ends.  No field count, no type bytes.
\* Wire cost = sum of data lengths only.
ImplicitWireCost(flds) ==
    IF Len(flds) = 0 THEN 0
    ELSE LET SumData[i \in 1..Len(flds)] ==
             IF i = 1 THEN flds[i][2]
             ELSE SumData[i-1] + flds[i][2]
         IN SumData[Len(flds)]

\* Explicit layout: field count (1 byte) + per-field type byte + data.
\* Wire cost = 1 + sum of (1 + data_len) per field.
ExplicitWireCost(flds) ==
    IF Len(flds) = 0 THEN 1   \* just the field count byte (0)
    ELSE LET SumExplicit[i \in 1..Len(flds)] ==
             IF i = 1 THEN 1 + flds[i][2]
             ELSE SumExplicit[i-1] + 1 + flds[i][2]
         IN 1 + SumExplicit[Len(flds)]

(***************************************************************************)
(* Compact coil encoding                                                   *)
(***************************************************************************)

\* Default coil: 0x00 + 2-byte output_index = 3 bytes total
CompactCoilBytes == 3

(***************************************************************************)
(* Decode-side output inflation                                            *)
(***************************************************************************)

\* At decode time, each value-only output is inflated to a full CTxOut
\* with scriptPubKey = 0xDF + conditions_root (33 bytes).
InflatedOutput(value, root) ==
    [nValue |-> value, scriptPubKey |-> root]

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES tbl, block_type, inv, enc, dec,
          flag, tx, inflated_outputs,
          flds, phase

vars == <<tbl, block_type, inv, enc, dec,
          flag, tx, inflated_outputs,
          flds, phase>>

Init ==
    /\ tbl \in MicroHeaderTables
    /\ block_type \in BlockTypes
    /\ inv \in BOOLEAN
    /\ enc = <<"init">>
    /\ dec = [type |-> 0, inverted |-> FALSE, ok |-> FALSE]
    /\ flag \in FlagValues
    /\ tx \in [version: {4}, flag: {2}, n_inputs: {1, 2},
               conditions_root: {1}, n_outputs: 1..MaxOutputs,
               output_values: OutputVals,
               proof_leaves: ProofLeafCounts,
               agg_sig_len: AggSigLens]
    /\ inflated_outputs = [i \in {} |-> 0]
    /\ flds = <<>>
    /\ phase = "encode"

StepEncode ==
    /\ phase = "encode"
    /\ enc' = EncodeMicroHeader(tbl, block_type, inv)
    /\ phase' = "decode"
    /\ UNCHANGED <<tbl, block_type, inv, dec, flag, tx,
                   inflated_outputs, flds>>

StepDecode ==
    /\ phase = "decode"
    /\ dec' = DecodeMicroHeader(tbl, enc)
    /\ phase' = "inflate"
    /\ UNCHANGED <<tbl, block_type, inv, enc, flag, tx,
                   inflated_outputs, flds>>

StepInflate ==
    /\ phase = "inflate"
    \* Build inflated outputs for the TX_MLSC transaction
    /\ inflated_outputs' =
        [i \in 1..tx.n_outputs |->
            InflatedOutput(tx.output_values[i], tx.conditions_root)]
    \* Representative field layout: PUBKEY(33) + NUMERIC(4) + HASH256(32)
    /\ flds' = <<<<"PUBKEY", 33>>, <<"NUMERIC", 4>>, <<"HASH256", 32>>>>
    /\ phase' = "done"
    /\ UNCHANGED <<tbl, block_type, inv, enc, dec, flag, tx>>

StepDone ==
    /\ phase = "done"
    /\ UNCHANGED vars

Next == StepEncode \/ StepDecode \/ StepInflate \/ StepDone
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: Micro-header slot -> deterministic block type (injective within used range)
Inv_SlotInjective ==
    \A i, j \in SlotRange :
        i # j => tbl[i] # tbl[j]

\* I2: Escape 0x80 -> full header, non-inverted
Inv_Escape80NonInverted ==
    (phase = "done" /\ enc[1] = "full" /\ enc[3] = FALSE)
    => dec.inverted = FALSE

\* I3: Escape 0x81 -> full header, inverted
Inv_Escape81Inverted ==
    (phase = "done" /\ enc[1] = "full" /\ enc[3] = TRUE)
    => dec.inverted = TRUE

\* I4: Flag byte 0x03 -> REJECT (SegWit + MLSC conflict)
Inv_Flag03Reject ==
    ClassifyFlag(3) = "REJECT"

\* I5: Flag byte 0x02 -> TX_MLSC format
Inv_Flag02MLSC ==
    ClassifyFlag(2) = "TX_MLSC"

\* I6: Round-trip: encode then decode recovers original block type and inversion
Inv_RoundTrip ==
    (phase = "done" /\ dec.ok)
    => (dec.type = block_type /\ dec.inverted = inv)

\* I7: Creation proof leaves <= 252 (CompactSize < 253 encoding)
Inv_ProofLeavesBound ==
    tx.proof_leaves <= MaxProofLeaves

\* I8: Value-only outputs inflated to full CTxOut at decode time
Inv_InflatedOutputs ==
    (phase = "done")
    => \A i \in 1..tx.n_outputs :
        inflated_outputs[i].scriptPubKey = tx.conditions_root

\* I9: Implicit layout encoding shorter than explicit
Inv_ImplicitShorter ==
    (phase = "done" /\ Len(flds) > 0)
    => ImplicitWireCost(flds) < ExplicitWireCost(flds)

SafetyInvariant ==
    /\ Inv_SlotInjective
    /\ Inv_Escape80NonInverted
    /\ Inv_Escape81Inverted
    /\ Inv_Flag03Reject
    /\ Inv_Flag02MLSC
    /\ Inv_RoundTrip
    /\ Inv_ProofLeavesBound
    /\ Inv_InflatedOutputs
    /\ Inv_ImplicitShorter

=============================================================================
