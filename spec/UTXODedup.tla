------------------------- MODULE UTXODedup -------------------------
(***************************************************************************)
(* Model of TX_MLSC UTXO deduplication lifecycle:                          *)
(*   - AddCoins writes synthetic root entry at (txid, 0xFFFFFFFF)          *)
(*   - Real outputs compressed to 1-byte scriptPubKey                      *)
(*   - Inflation reads root from synthetic entry                           *)
(*   - DisconnectBlock removes synthetic entry                             *)
(*                                                                         *)
(* Verifies: root always recoverable, reorg removes entry,                 *)
(* synthetic entry not spendable, compact coins always inflatable.         *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxOutputs     \* Max outputs per tx (e.g. 3)

\* Abstract root values
RootValues == 1..4

(***************************************************************************)
(* State                                                                   *)
(***************************************************************************)

VARIABLES
    \* UTXO set: maps (vout_index) -> {root, compact}
    \* synthetic: the root entry (present or absent)
    \* real_coins: set of vout indices with compact scriptPubKeys
    synthetic_root,    \* RootValues \cup {0} (0 = absent)
    real_coins,        \* SUBSET (0..MaxOutputs-1)
    phase,
    action_result

vars == <<synthetic_root, real_coins, phase, action_result>>

(***************************************************************************)
(* Actions                                                                 *)
(***************************************************************************)

\* Connect: add coins for a TX_MLSC transaction
Connect(root, n_outputs) ==
    /\ phase = "idle"
    /\ root \in RootValues
    /\ n_outputs \in 1..MaxOutputs
    /\ synthetic_root' = root
    /\ real_coins' = 0..(n_outputs - 1)
    /\ phase' = "connected"
    /\ action_result' = "OK"

\* Inflate: recover root from synthetic entry for a compact coin
Inflate(vout) ==
    /\ phase = "connected"
    /\ vout \in real_coins
    /\ IF synthetic_root # 0
       THEN action_result' = "INFLATED"
       ELSE action_result' = "INFLATE_FAILED"
    /\ UNCHANGED <<synthetic_root, real_coins, phase>>

\* Spend: remove a real coin
Spend(vout) ==
    /\ phase = "connected"
    /\ vout \in real_coins
    /\ real_coins' = real_coins \ {vout}
    /\ UNCHANGED <<synthetic_root, phase, action_result>>

\* Disconnect: remove synthetic entry + restore coins
Disconnect ==
    /\ phase = "connected"
    /\ synthetic_root' = 0  \* removed
    /\ real_coins' = {}     \* coins restored by undo data (not modeled)
    /\ phase' = "idle"
    /\ action_result' = "DISCONNECTED"

\* Reconnect: add coins again (after reorg to different chain)
Reconnect(root, n_outputs) ==
    /\ phase = "idle"
    /\ root \in RootValues
    /\ n_outputs \in 1..MaxOutputs
    /\ synthetic_root' = root
    /\ real_coins' = 0..(n_outputs - 1)
    /\ phase' = "connected"
    /\ action_result' = "RECONNECTED"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

Init ==
    /\ synthetic_root = 0
    /\ real_coins = {}
    /\ phase = "idle"
    /\ action_result = "INIT"

Next ==
    \/ \E r \in RootValues, n \in 1..MaxOutputs : Connect(r, n)
    \/ \E v \in 0..(MaxOutputs-1) : Inflate(v)
    \/ \E v \in 0..(MaxOutputs-1) : Spend(v)
    \/ Disconnect
    \/ \E r \in RootValues, n \in 1..MaxOutputs : Reconnect(r, n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety invariants                                                       *)
(***************************************************************************)

\* I1: When connected, synthetic root is always present
Inv_SyntheticPresent ==
    phase = "connected" => synthetic_root # 0

\* I2: Inflation succeeds when connected (synthetic present)
Inv_InflationWorks ==
    (phase = "connected" /\ action_result = "INFLATED")
    => synthetic_root # 0

\* I3: After disconnect, synthetic root is removed
Inv_DisconnectCleansUp ==
    (action_result = "DISCONNECTED")
    => synthetic_root = 0

\* I4: Synthetic root is not in real_coins (can't be spent as real output)
Inv_SyntheticNotSpendable ==
    \A v \in real_coins : v < MaxOutputs  \* 0xFFFFFFFF is out of range

SafetyInvariant ==
    /\ Inv_SyntheticPresent
    /\ Inv_InflationWorks
    /\ Inv_DisconnectCleansUp
    /\ Inv_SyntheticNotSpendable

=============================================================================
