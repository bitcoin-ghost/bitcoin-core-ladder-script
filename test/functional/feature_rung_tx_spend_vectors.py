#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Generate src/test/data/rung_tx_spend_vectors.json — round-trip
fund+spend vectors for v4 RUNG_TX outputs.

Each vector funds an MLSC output, spends it back into a fresh MLSC
output via signrungtx, and broadcasts both transactions. Captures the
fund tx, spend tx, and a witness shape summary.

Note: Schnorr signatures inside spend witnesses use fresh aux_rand each
run, so the raw sig bytes are NOT reproducible across runs. The witness
*shape* (block layout, field types and sizes) IS deterministic and is
captured separately under `witness_shape` for byte-level equivalence
testing across implementations.

Run:
    python3 test/functional/generate_rung_tx_spend_vectors.py
"""

import hashlib
import json
import os
import sys
from decimal import Decimal
from pathlib import Path

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import (
    CTransaction,
    tx_from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = REPO_ROOT / "src" / "test" / "data" / "rung_tx_spend_vectors.json"


def derive_key(seed: str) -> ECKey:
    h = hashlib.sha256(seed.encode()).digest()
    if h == b"\x00" * 32:
        h = b"\x01" * 32
    k = ECKey()
    k.set(h, True)
    return k


def schnorr_pk(k: ECKey) -> str:
    return k.get_pubkey().get_bytes().hex()


# ── Fields that vary across runs (Schnorr aux_rand → fresh sig bytes
# every signing call). These are stripped before structural comparison.
_NONDETERMINISTIC_PATHS = {
    "spend.spend_hex",
    "spend.spend_txid",
    # `spend_size_bytes` IS deterministic for Schnorr (64 B sigs), but
    # we recompute it from the stripped hex anyway so leave it in.
}


def _strip_nondet(vec: dict) -> dict:
    """Return a copy of `vec` with non-deterministic fields removed
    so the rest can be byte-compared across runs."""
    out = json.loads(json.dumps(vec))  # deep copy
    for path in _NONDETERMINISTIC_PATHS:
        parts = path.split(".")
        cur = out
        for p in parts[:-1]:
            if not isinstance(cur, dict) or p not in cur:
                cur = None
                break
            cur = cur[p]
        if isinstance(cur, dict) and parts[-1] in cur:
            del cur[parts[-1]]
    return out


def write_or_verify_vectors(vectors: list, source_description: str):
    """Default behaviour is VERIFY. Spend vectors contain Schnorr
    signature bytes that differ each run (fresh aux_rand), so the
    comparison strips `spend.spend_hex` and `spend.spend_txid`. Every
    other field — including witness shape, fund tx, and conditions
    root — is deterministic and is byte-compared."""
    payload = {
        "version": 1,
        "description": source_description,
        "vectors": vectors,
    }
    new_text = json.dumps(payload, indent=2) + "\n"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    if os.environ.get("VECTORS_REGENERATE") == "1":
        tmp = OUTPUT_PATH.with_suffix(".json.tmp")
        tmp.write_text(new_text)
        tmp.replace(OUTPUT_PATH)
        print(f"wrote {len(vectors)} spend vectors -> {OUTPUT_PATH}")
        return

    if not OUTPUT_PATH.exists():
        raise AssertionError(
            f"{OUTPUT_PATH} does not exist; "
            f"run with VECTORS_REGENERATE=1 to create it"
        )
    committed = json.loads(OUTPUT_PATH.read_text())
    committed_vectors = committed.get("vectors", [])

    if len(committed_vectors) != len(vectors):
        raise AssertionError(
            f"FIXTURE DRIFT in {OUTPUT_PATH.name}: vector count "
            f"changed (committed={len(committed_vectors)}, "
            f"regenerated={len(vectors)}). If intentional, re-run "
            f"with VECTORS_REGENERATE=1."
        )

    for i, (a, b) in enumerate(zip(vectors, committed_vectors)):
        a_stripped = _strip_nondet(a)
        b_stripped = _strip_nondet(b)
        if json.dumps(a_stripped, sort_keys=True) != json.dumps(b_stripped, sort_keys=True):
            import difflib
            a_text = json.dumps(a_stripped, indent=2, sort_keys=True)
            b_text = json.dumps(b_stripped, indent=2, sort_keys=True)
            diff_lines = list(difflib.unified_diff(
                b_text.splitlines(), a_text.splitlines(),
                fromfile=f"committed[id={b.get('id')}]",
                tofile=f"regenerated[id={a.get('id')}]",
                n=2,
                lineterm="",
            ))
            diff = "\n".join(diff_lines[:60])
            raise AssertionError(
                f"FIXTURE DRIFT in {OUTPUT_PATH.name} vector {i} "
                f"(id={a.get('id')}): structural mismatch. "
                f"If intentional, re-run with VECTORS_REGENERATE=1."
                f"\n\n{diff}"
            )

    print(f"verified {len(vectors)} spend vectors structurally == "
          f"{OUTPUT_PATH.name} (sig bytes excluded)")


write_vectors = write_or_verify_vectors


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────


def _fund_mlsc(node, wallet, rungs):
    """Fund a single-output MLSC tx and return the bundle."""
    utxo = wallet.get_utxo()
    amt = (Decimal(str(utxo["value"])) - Decimal("0.001")).quantize(Decimal("0.00000001"))
    result = node.createrungtx(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [amt],
        rungs,
    )
    tx = tx_from_hex(result["hex"])
    wallet.sign_tx(tx)
    fund_hex = tx.serialize().hex()
    fund_txid = node.sendrawtransaction(fund_hex)
    return {
        "fund_txid": fund_txid,
        "fund_hex": fund_hex,
        "fund_size_bytes": len(fund_hex) // 2,
        "spk": result["scriptPubKey"],
        "amount": amt,
        "conditions_root": result["conditions_root"],
    }


def _build_unsigned_spend(node, fund, spend_rungs, fee=Decimal("0.001"),
                           sequence=None):
    """Build an unsigned tx that spends the MLSC output to a fresh MLSC
    output governed by `spend_rungs`. Pass `sequence` to set the input's
    nSequence (e.g. 0 to clear BIP-68 disable flag for CSV-checked
    blocks like PTLC/ADAPTOR_SIG/CLTV_SIG when CSV=0)."""
    spend_amt = (fund["amount"] - fee).quantize(Decimal("0.00000001"))
    in_obj = {"txid": fund["fund_txid"], "vout": 0}
    if sequence is not None:
        in_obj["sequence"] = sequence
    result = node.createrungtx([in_obj], [spend_amt], spend_rungs)
    return {
        "unsigned_hex": result["hex"],
        "spend_amount": spend_amt,
        "destination_spk": result["scriptPubKey"],
        "destination_conditions_root": result["conditions_root"],
    }


def _witness_shape(spend_hex: str) -> dict:
    """Decode the spend tx and extract a deterministic witness summary
    (input count, witness stack item counts and sizes per input)."""
    tx = tx_from_hex(spend_hex)
    inputs = []
    for i, txin in enumerate(tx.vin):
        wit = tx.wit.vtxinwit[i] if i < len(tx.wit.vtxinwit) else None
        stack = wit.scriptWitness.stack if wit else []
        inputs.append({
            "input_index": i,
            "stack_items": len(stack),
            "stack_item_sizes": [len(s) for s in stack],
            "stack_total_bytes": sum(len(s) for s in stack),
        })
    return {
        "version": tx.version,
        "vin_count": len(tx.vin),
        "vout_count": len(tx.vout),
        "size_bytes": len(spend_hex) // 2,
        "inputs": inputs,
    }


def _round_trip(node, fund, spender_blocks, conditions_arr, dest_seed,
                sequence=None):
    """Common round-trip: build unsigned spend → signrungtx → broadcast."""
    dest_pk = derive_key(dest_seed)
    spend_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": schnorr_pk(dest_pk)},
        ]}],
    }]
    unsigned = _build_unsigned_spend(node, fund, spend_rungs, sequence=sequence)
    sign_result = node.signrungtx(
        unsigned["unsigned_hex"],
        [{"input": 0, "blocks": spender_blocks,
          "conditions": conditions_arr}],
        [{"amount": float(fund["amount"]), "scriptPubKey": fund["spk"]}],
    )
    assert sign_result["complete"], f"signrungtx incomplete: {sign_result}"
    spend_hex = sign_result["hex"]
    spend_txid = node.sendrawtransaction(spend_hex)
    return {
        "spend_txid": spend_txid,
        "spend_hex": spend_hex,
        "spend_size_bytes": len(spend_hex) // 2,
        "destination_pubkey": schnorr_pk(dest_pk),
        "destination_seed": dest_seed,
        "destination_spk": unsigned["destination_spk"],
        "witness_shape": _witness_shape(spend_hex),
    }


# ──────────────────────────────────────────────────────────────────
# Spend specs
# ──────────────────────────────────────────────────────────────────


def spend_1_sig(node, wallet) -> dict:
    """SIG keypath spend — single Schnorr key."""
    seed = "bip-xxxx-spend1-sig-key"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{"type": "SIG", "privkey": bytes_to_wif(pk.get_bytes(), True)}]
    conditions_arr = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "01"},
        {"type": "PUBKEY", "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend1-dest")
    return {
        "id": 1,
        "name": "SIG single-rung Schnorr spend (round-trip)",
        "block_types": ["SIG"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness contains one SIG block: PUBKEY (33 B) + "
                 "SIGNATURE (64 B). SIGNATURE bytes vary per run "
                 "(fresh Schnorr aux_rand); witness_shape is "
                 "deterministic.",
    }


def spend_5_cltv(node, wallet) -> dict:
    """CLTV at height 0 — immediately spendable."""
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "CLTV", "fields": [
            {"type": "NUMERIC", "hex": "00000000"},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{"type": "CLTV"}]
    conditions_arr = [{"blocks": [{"type": "CLTV", "fields": [
        {"type": "NUMERIC", "hex": "00000000"},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend5-dest")
    return {
        "id": 5,
        "name": "CLTV=0 immediate spend (Empty witness rule)",
        "block_types": ["CLTV"],
        "cltv_height": 0,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "CLTV witness is empty after E-022; tx-level nLockTime "
                 "must satisfy the conditions NUMERIC.",
    }


def spend_10_anchor(node, wallet) -> dict:
    """ANCHOR pure marker — empty witness, immediately spendable."""
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "ANCHOR", "fields": [
            {"type": "NUMERIC", "hex": "0a000000"},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{"type": "ANCHOR"}]
    conditions_arr = [{"blocks": [{"type": "ANCHOR", "fields": [
        {"type": "NUMERIC", "hex": "0a000000"},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend10-dest")
    return {
        "id": 10,
        "name": "ANCHOR marker spend (Empty witness rule)",
        "block_types": ["ANCHOR"],
        "anchor_id": 10,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "ANCHOR has no witness — pure marker block.",
    }


def spend_14_hash_guarded(node, wallet) -> dict:
    """HASH_GUARDED spend — reveal preimage."""
    preimage = b"spend14-hash-guarded-preimage"
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "HASH_GUARDED", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{"type": "HASH_GUARDED", "preimage": preimage.hex()}]
    # Conditions side: pass PREIMAGE (signrungtx auto-derives HASH256
    # the same way createrungtx did at fund time, so the conditions_root
    # reconstructs identically).
    commit = hashlib.sha256(preimage).hexdigest()
    conditions_arr = [{"blocks": [{"type": "HASH_GUARDED", "fields": [
        {"type": "PREIMAGE", "hex": preimage.hex()},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend14-dest")
    return {
        "id": 14,
        "name": "HASH_GUARDED preimage reveal (Reveal P)",
        "block_types": ["HASH_GUARDED"],
        "preimage_hex": preimage.hex(),
        "commit_hex": commit,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = PREIMAGE only. Evaluator computes "
                 "SHA256(preimage) and compares to conditions HASH256.",
    }


def spend_68_cltv_sig(node, wallet) -> dict:
    """CLTV_SIG spend — sig + absolute nLockTime=0 (immediately
    spendable; no mining required)."""
    seed = "bip-xxxx-spend68-cltvsig"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "CLTV_SIG", "fields": [
            {"type": "SCHEME",  "hex": "01"},
            {"type": "NUMERIC", "hex": "00000000"},
            {"type": "PUBKEY",  "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "CLTV_SIG",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "CLTV_SIG", "fields": [
        {"type": "SCHEME",  "hex": "01"},
        {"type": "NUMERIC", "hex": "00000000"},
        {"type": "PUBKEY",  "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend68-dest")
    return {
        "id": 68,
        "name": "CLTV_SIG spend (sig + absolute nLockTime=0)",
        "block_types": ["CLTV_SIG"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "cltv_height": 0,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY, SIGNATURE]. Compound: SIG check "
                 "AND nLockTime ≥ conditions NUMERIC.",
    }


def spend_18b_vault_lock_hot(node, wallet, mine) -> dict:
    """VAULT_LOCK hot-key spend — sign with the hot key + nSequence
    must satisfy the conditions CSV (hot_delay)."""
    seed_recovery = "bip-xxxx-spend18b-recovery"
    seed_hot = "bip-xxxx-spend18b-hot"
    rec_pk = derive_key(seed_recovery)
    hot_pk = derive_key(seed_hot)
    rec_pk_hex = schnorr_pk(rec_pk)
    hot_pk_hex = schnorr_pk(hot_pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "VAULT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": "02000000"},  # hot_delay = 2 blocks
            {"type": "PUBKEY",  "hex": rec_pk_hex},
            {"type": "PUBKEY",  "hex": hot_pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    mine(3)  # mature past the CSV delay
    spender_blocks = [{
        "type": "VAULT_LOCK",
        "pubkeys": [rec_pk_hex, hot_pk_hex],
        "privkey": bytes_to_wif(hot_pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
        {"type": "NUMERIC", "hex": "02000000"},
        {"type": "PUBKEY",  "hex": rec_pk_hex},
        {"type": "PUBKEY",  "hex": hot_pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend18b-dest", sequence=2)
    return {
        "id": 32,
        "name": "VAULT_LOCK hot-key spend (CSV=2 elapsed)",
        "block_types": ["VAULT_LOCK"],
        "recovery_pubkey": rec_pk_hex,
        "hot_pubkey": hot_pk_hex,
        "hot_delay": 2,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Hot-key path — recovery sig fails first (the sig is "
                 "by hot), then hot sig verifies AND CheckSequence "
                 "(hot_delay) passes because nSequence=2 ≥ 2.",
    }


def spend_23_timelocked_multisig(node, wallet, mine) -> dict:
    """TIMELOCKED_MULTISIG 2-of-3 spend after CSV elapsed."""
    seeds = ["bip-xxxx-spend23-tlms-a",
             "bip-xxxx-spend23-tlms-b",
             "bip-xxxx-spend23-tlms-c"]
    pks = [derive_key(s) for s in seeds]
    pk_hexes = [schnorr_pk(k) for k in pks]
    wifs = [bytes_to_wif(k.get_bytes(), True) for k in pks]
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "TIMELOCKED_MULTISIG", "fields": [
            {"type": "NUMERIC", "hex": "02000000"},  # K = 2
            {"type": "NUMERIC", "hex": "02000000"},  # CSV = 2
            {"type": "SCHEME",  "hex": "01"},
            {"type": "PUBKEY",  "hex": pk_hexes[0]},
            {"type": "PUBKEY",  "hex": pk_hexes[1]},
            {"type": "PUBKEY",  "hex": pk_hexes[2]},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    mine(3)
    spender_blocks = [{
        "type": "TIMELOCKED_MULTISIG",
        "privkeys": [wifs[0], wifs[1]],
        "pubkeys": pk_hexes,
    }]
    conditions_arr = [{"blocks": [{"type": "TIMELOCKED_MULTISIG", "fields": [
        {"type": "NUMERIC", "hex": "02000000"},
        {"type": "NUMERIC", "hex": "02000000"},
        {"type": "SCHEME",  "hex": "01"},
        {"type": "PUBKEY",  "hex": pk_hexes[0]},
        {"type": "PUBKEY",  "hex": pk_hexes[1]},
        {"type": "PUBKEY",  "hex": pk_hexes[2]},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend23-dest", sequence=2)
    return {
        "id": 23,
        "name": "TIMELOCKED_MULTISIG 2-of-3 spend (CSV=2 elapsed)",
        "block_types": ["TIMELOCKED_MULTISIG"],
        "key_seeds": {f"k{i}": s for i, s in enumerate(seeds)},
        "pubkeys": pk_hexes,
        "signing_indices": [0, 1],
        "threshold": 2,
        "csv_blocks": 2,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = K × (PUBKEY, MERKLE_PROOF, SIGNATURE). "
                 "CSV NUMERIC arrives via conditions merge; "
                 "nSequence ≥ CSV.",
    }


def spend_26_p2pkh_legacy(node, wallet) -> dict:
    """P2PKH_LEGACY spend — sig + pubkey, evaluator checks
    HASH160(pubkey) match."""
    seed = "bip-xxxx-spend26-p2pkh-key"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "P2PKH_LEGACY", "fields": [
            {"type": "PUBKEY", "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "P2PKH_LEGACY",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "P2PKH_LEGACY", "fields": [
        {"type": "PUBKEY", "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend26-dest")
    return {
        "id": 26,
        "name": "P2PKH_LEGACY spend (HASH160-bound pubkey + sig)",
        "block_types": ["P2PKH_LEGACY"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Same shape as P2WPKH_LEGACY — distinct evaluator "
                 "(legacy P2PKH descriptor binding).",
    }


def spend_51_p2pk_legacy(node, wallet) -> dict:
    """P2PK_LEGACY spend — bare pubkey, no hash."""
    seed = "bip-xxxx-spend51-p2pk-key"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "P2PK_LEGACY", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "P2PK_LEGACY",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "P2PK_LEGACY", "fields": [
        {"type": "SCHEME", "hex": "01"},
        {"type": "PUBKEY", "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend51-dest")
    return {
        "id": 51,
        "name": "P2PK_LEGACY spend (bare pubkey + sig)",
        "block_types": ["P2PK_LEGACY"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY, SIGNATURE]. Conditions "
                 "commit only SCHEME; pubkey folds into Merkle leaf.",
    }


def spend_52_p2tr_legacy(node, wallet) -> dict:
    """P2TR_LEGACY spend — taproot key-path."""
    seed = "bip-xxxx-spend52-p2tr-key"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "P2TR_LEGACY", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "P2TR_LEGACY",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "P2TR_LEGACY", "fields": [
        {"type": "SCHEME", "hex": "01"},
        {"type": "PUBKEY", "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend52-dest")
    return {
        "id": 52,
        "name": "P2TR_LEGACY spend (BIP-341 key-path wrapper)",
        "block_types": ["P2TR_LEGACY"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Same wire shape as P2PK_LEGACY; distinct evaluator.",
    }


def spend_42_anchor_oracle(node, wallet) -> dict:
    """ANCHOR_ORACLE spend — oracle pubkey reveal in witness."""
    seed = "bip-xxxx-spend42-oracle"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "ANCHOR_ORACLE", "fields": [
            {"type": "NUMERIC", "hex": "03000000"},   # outcome_count = 3
            {"type": "PUBKEY",  "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "ANCHOR_ORACLE",
        "pubkeys": [pk_hex],
    }]
    conditions_arr = [{"blocks": [{"type": "ANCHOR_ORACLE", "fields": [
        {"type": "NUMERIC", "hex": "03000000"},
        {"type": "PUBKEY",  "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend42-dest")
    return {
        "id": 42,
        "name": "ANCHOR_ORACLE spend (oracle pubkey reveal)",
        "block_types": ["ANCHOR_ORACLE"],
        "fund_seed": seed,
        "oracle_pubkey": pk_hex,
        "outcome_count": 3,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY(oracle)]. Pure marker reveal of "
                 "the oracle pubkey committed via Merkle leaf.",
    }


def spend_2_p2wpkh_legacy(node, wallet) -> dict:
    """P2WPKH_LEGACY spend — sign with privkey, witness reveals pubkey."""
    seed = "bip-xxxx-spend2-p2wpkh-key"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "P2WPKH_LEGACY", "fields": [
            {"type": "PUBKEY", "hex": pk_hex},  # auto → HASH160
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "P2WPKH_LEGACY",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    # At spend time, conditions hold the HASH160 — pass PUBKEY again so
    # the node re-derives identically (same auto-conversion path).
    conditions_arr = [{"blocks": [{"type": "P2WPKH_LEGACY", "fields": [
        {"type": "PUBKEY", "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend2-dest")
    return {
        "id": 2,
        "name": "P2WPKH_LEGACY spend (HASH160-bound pubkey + sig)",
        "block_types": ["P2WPKH_LEGACY"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY, SIGNATURE]. Evaluator checks "
                 "HASH160(pubkey) == conditions HASH160 then verifies "
                 "the Schnorr sig.",
    }


def spend_27_adaptor_sig(node, wallet) -> dict:
    """ADAPTOR_SIG spend — plain Schnorr pre-sig (no adaptor_secret).
    Used for testing the witness shape; an actual adaptor flow would
    pass `adaptor_secret` to produce the adapted sig."""
    seed = "bip-xxxx-spend27-adaptor"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "ADAPTOR_SIG", "fields": [
            {"type": "PUBKEY", "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "ADAPTOR_SIG",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "ADAPTOR_SIG", "fields": [
        {"type": "PUBKEY", "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend27-dest")
    return {
        "id": 27,
        "name": "ADAPTOR_SIG spend (plain Schnorr pre-sig form)",
        "block_types": ["ADAPTOR_SIG"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY, SIGNATURE] (same shape as SIG). "
                 "Plain Schnorr sig used here; the adaptor flow uses "
                 "the same shape with an adapter-secret-tweaked sig.",
    }


def spend_21_ptlc(node, wallet) -> dict:
    """PTLC spend — plain Schnorr (no adaptor secret)."""
    seed = "bip-xxxx-spend21-ptlc"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "PTLC", "fields": [
            {"type": "NUMERIC", "hex": "00000000"},  # CSV = 0
            {"type": "PUBKEY",  "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "PTLC",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "PTLC", "fields": [
        {"type": "NUMERIC", "hex": "00000000"},
        {"type": "PUBKEY",  "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend21-dest", sequence=0)
    return {
        "id": 21,
        "name": "PTLC spend (plain Schnorr, CSV=0)",
        "block_types": ["PTLC"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY, SIGNATURE]. CSV NUMERIC arrives "
                 "via conditions merge.",
    }


def spend_3_htlc_claim(node, wallet) -> dict:
    """HTLC receiver-path claim — preimage + receiver sig."""
    seed_recv = "bip-xxxx-spend3-htlc-recv"
    seed_send = "bip-xxxx-spend3-htlc-send"
    recv_pk = derive_key(seed_recv)
    send_pk = derive_key(seed_send)
    recv_pk_hex = schnorr_pk(recv_pk)
    send_pk_hex = schnorr_pk(send_pk)
    preimage = b"\x42" * 32
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "HTLC", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()},  # auto → HASH256
            {"type": "NUMERIC",  "hex": "00000000"},      # CSV = 0
            {"type": "SCHEME",   "hex": "01"},
            {"type": "PUBKEY",   "hex": recv_pk_hex},
            {"type": "PUBKEY",   "hex": send_pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "HTLC",
        "path": 0,                                          # receiver path
        "pubkeys": [recv_pk_hex, send_pk_hex],
        "privkey": bytes_to_wif(recv_pk.get_bytes(), True),
        "preimage": preimage.hex(),
    }]
    conditions_arr = [{"blocks": [{"type": "HTLC", "fields": [
        {"type": "PREIMAGE", "hex": preimage.hex()},
        {"type": "NUMERIC",  "hex": "00000000"},
        {"type": "SCHEME",   "hex": "01"},
        {"type": "PUBKEY",   "hex": recv_pk_hex},
        {"type": "PUBKEY",   "hex": send_pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend3-dest")
    return {
        "id": 3,
        "name": "HTLC claim (receiver path: preimage + sig)",
        "block_types": ["HTLC"],
        "fund_seeds": {"recv": seed_recv, "send": seed_send},
        "recv_pubkey": recv_pk_hex,
        "send_pubkey": send_pk_hex,
        "preimage_hex": preimage.hex(),
        "csv_blocks": 0,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY(recv), PUBKEY(send), SIGNATURE, "
                 "PREIMAGE, NUMERIC(path=0)]. Receiver path: SHA256 "
                 "(preimage) == hash AND sig verifies pubkeys[0].",
    }


def spend_3b_htlc_refund(node, wallet, mine) -> dict:
    """HTLC refund path — sender sig + empty preimage + CSV elapsed."""
    seed_recv = "bip-xxxx-spend3b-htlc-recv"
    seed_send = "bip-xxxx-spend3b-htlc-send"
    recv_pk = derive_key(seed_recv)
    send_pk = derive_key(seed_send)
    recv_pk_hex = schnorr_pk(recv_pk)
    send_pk_hex = schnorr_pk(send_pk)
    preimage = b"\x99" * 32
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "HTLC", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()},
            {"type": "NUMERIC",  "hex": "02000000"},  # CSV = 2 blocks
            {"type": "SCHEME",   "hex": "01"},
            {"type": "PUBKEY",   "hex": recv_pk_hex},
            {"type": "PUBKEY",   "hex": send_pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    mine(3)
    spender_blocks = [{
        "type": "HTLC",
        "path": 1,                                          # refund path
        "pubkeys": [recv_pk_hex, send_pk_hex],
        "privkey": bytes_to_wif(send_pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "HTLC", "fields": [
        {"type": "PREIMAGE", "hex": preimage.hex()},
        {"type": "NUMERIC",  "hex": "02000000"},
        {"type": "SCHEME",   "hex": "01"},
        {"type": "PUBKEY",   "hex": recv_pk_hex},
        {"type": "PUBKEY",   "hex": send_pk_hex},
    ]}]}]
    # Use nSequence ≥ CSV so refund path's CSV check passes.
    dest_pk = derive_key("bip-xxxx-spend3b-dest")
    spend_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": schnorr_pk(dest_pk)},
        ]}],
    }]
    spend_amt = (fund["amount"] - Decimal("0.001")).quantize(Decimal("0.00000001"))
    raw = node.createrungtx(
        [{"txid": fund["fund_txid"], "vout": 0, "sequence": 2}],
        [spend_amt],
        spend_rungs,
    )
    sign_result = node.signrungtx(
        raw["hex"],
        [{"input": 0, "blocks": spender_blocks,
          "conditions": conditions_arr}],
        [{"amount": float(fund["amount"]), "scriptPubKey": fund["spk"]}],
    )
    assert sign_result["complete"]
    spend_hex = sign_result["hex"]
    spend_txid = node.sendrawtransaction(spend_hex)
    return {
        "id": 31,
        "name": "HTLC refund (sender path: empty preimage + CSV elapsed)",
        "block_types": ["HTLC"],
        "fund_seeds": {"recv": seed_recv, "send": seed_send},
        "recv_pubkey": recv_pk_hex,
        "send_pubkey": send_pk_hex,
        "csv_blocks": 2,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": {
            "spend_txid": spend_txid,
            "spend_hex": spend_hex,
            "spend_size_bytes": len(spend_hex) // 2,
            "nSequence": 2,
            "destination_pubkey": schnorr_pk(dest_pk),
            "witness_shape": _witness_shape(spend_hex),
        },
        "notes": "Witness = [PUBKEY(recv), PUBKEY(send), SIGNATURE, "
                 "PREIMAGE(empty), NUMERIC(path=1)]. Refund path: "
                 "sig verifies pubkeys[1] AND nSequence ≥ CSV.",
    }


def spend_22_anchor_fee(node, wallet) -> dict:
    """ANCHOR_FEE 2-of-2 sig check."""
    seed_a = "bip-xxxx-spend22-anchorfee-a"
    seed_b = "bip-xxxx-spend22-anchorfee-b"
    pk_a = derive_key(seed_a)
    pk_b = derive_key(seed_b)
    pk_a_hex = schnorr_pk(pk_a)
    pk_b_hex = schnorr_pk(pk_b)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "ANCHOR_FEE", "fields": [
            {"type": "SCHEME",  "hex": "01"},
            {"type": "NUMERIC", "hex": "01000000"},   # min_fee_rate = 1
            {"type": "NUMERIC", "hex": "10270000"},   # max_fee_rate = 10000
            {"type": "NUMERIC", "hex": "a0860100"},   # max_weight = 100k
            {"type": "NUMERIC", "hex": "01000000"},   # commitment = 1
            {"type": "PUBKEY",  "hex": pk_a_hex},
            {"type": "PUBKEY",  "hex": pk_b_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "ANCHOR_FEE",
        "pubkeys": [pk_a_hex, pk_b_hex],
        "privkeys": [bytes_to_wif(pk_a.get_bytes(), True),
                     bytes_to_wif(pk_b.get_bytes(), True)],
    }]
    conditions_arr = [{"blocks": [{"type": "ANCHOR_FEE", "fields": [
        {"type": "SCHEME",  "hex": "01"},
        {"type": "NUMERIC", "hex": "01000000"},
        {"type": "NUMERIC", "hex": "10270000"},   # max_fee_rate = 10000
        {"type": "NUMERIC", "hex": "a0860100"},
        {"type": "NUMERIC", "hex": "01000000"},
        {"type": "PUBKEY",  "hex": pk_a_hex},
        {"type": "PUBKEY",  "hex": pk_b_hex},
    ]}]}]
    # ANCHOR_FEE enforces fee_rate ∈ [min_fee_rate, max_fee_rate].
    # max=100 sat/vB; pass a small fee so the actual rate fits.
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend22-dest")
    return {
        "id": 22,
        "name": "ANCHOR_FEE 2-of-2 spend (compound anchor + fee band)",
        "block_types": ["ANCHOR_FEE"],
        "fund_seeds": {"a": seed_a, "b": seed_b},
        "pubkeys": [pk_a_hex, pk_b_hex],
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY, PUBKEY, SIGNATURE, SIGNATURE]. "
                 "Both keys must sign for the 2-of-2 check.",
    }


def spend_28_musig_threshold(node, wallet) -> dict:
    """MUSIG_THRESHOLD spend — single aggregated key signs."""
    seed = "bip-xxxx-spend28-musig"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "MUSIG_THRESHOLD", "fields": [
            {"type": "NUMERIC", "hex": "01000000"},   # M = 1
            {"type": "NUMERIC", "hex": "01000000"},   # N = 1
            {"type": "PUBKEY",  "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "MUSIG_THRESHOLD",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "MUSIG_THRESHOLD", "fields": [
        {"type": "NUMERIC", "hex": "01000000"},
        {"type": "NUMERIC", "hex": "01000000"},
        {"type": "PUBKEY",  "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend28-dest")
    return {
        "id": 28,
        "name": "MUSIG_THRESHOLD spend (aggregated key 1-of-1)",
        "block_types": ["MUSIG_THRESHOLD"],
        "fund_seed": seed,
        "agg_pubkey": pk_hex,
        "threshold": 1,
        "group_size": 1,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY, SIGNATURE]. The aggregated key "
                 "is treated as a single Schnorr key for verification.",
    }


def spend_12_amount_lock(node, wallet) -> dict:
    """AMOUNT_LOCK spend — Empty witness, output amount must be in
    [min, max] band. We split the spend into a small in-band output[0]
    + remainder change."""
    pinned_value = Decimal("0.001")
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": "10270000"},   # min = 10_000
            {"type": "NUMERIC", "hex": "00e1f505"},   # max = 100_000_000 (1 BTC)
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    pinned_pk_hex = schnorr_pk(derive_key("bip-xxxx-spend12-pinned"))
    change_pk_hex = schnorr_pk(derive_key("bip-xxxx-spend12-change"))
    change_value = (fund["amount"] - pinned_value - Decimal("0.001")).quantize(
        Decimal("0.00000001"))
    spend_rungs = [
        {"output_index": 0, "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": pinned_pk_hex},
        ]}]},
        {"output_index": 1, "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": change_pk_hex},
        ]}]},
    ]
    raw = node.createrungtx(
        [{"txid": fund["fund_txid"], "vout": 0}],
        [pinned_value, change_value],
        spend_rungs,
    )
    conditions_arr = [{"blocks": [{"type": "AMOUNT_LOCK", "fields": [
        {"type": "NUMERIC", "hex": "10270000"},
        {"type": "NUMERIC", "hex": "00e1f505"},
    ]}]}]
    sign_result = node.signrungtx(
        raw["hex"],
        [{"input": 0, "blocks": [{"type": "AMOUNT_LOCK"}],
          "conditions": conditions_arr}],
        [{"amount": float(fund["amount"]), "scriptPubKey": fund["spk"]}],
    )
    assert sign_result["complete"]
    spend_hex = sign_result["hex"]
    spend_txid = node.sendrawtransaction(spend_hex)
    return {
        "id": 12,
        "name": "AMOUNT_LOCK spend (output[0] in band, change in vout[1])",
        "block_types": ["AMOUNT_LOCK"],
        "min_sats": 10_000,
        "max_sats": 100_000_000,
        "pinned_value_btc": float(pinned_value),
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": {
            "spend_txid": spend_txid,
            "spend_hex": spend_hex,
            "spend_size_bytes": len(spend_hex) // 2,
            "vout_count": 2,
            "witness_shape": _witness_shape(spend_hex),
        },
        "notes": "Witness empty. AMOUNT_LOCK enforces the spent "
                 "output's value (`ctx.output_amount`) is within "
                 "[min, max].",
    }


def spend_18_vault_lock(node, wallet) -> dict:
    """VAULT_LOCK — sign with hot key (any of the 2 leaf pubkeys works)."""
    seed_recovery = "bip-xxxx-spend18-recovery"
    seed_hot = "bip-xxxx-spend18-hot"
    rec_pk = derive_key(seed_recovery)
    hot_pk = derive_key(seed_hot)
    rec_pk_hex = schnorr_pk(rec_pk)
    hot_pk_hex = schnorr_pk(hot_pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "VAULT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": "00000000"},  # hot_delay = 0
            {"type": "PUBKEY",  "hex": rec_pk_hex},
            {"type": "PUBKEY",  "hex": hot_pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "VAULT_LOCK",
        "pubkeys": [rec_pk_hex, hot_pk_hex],
        # Recovery path (cold sweep) — index 0, no CSV check.
        "privkey": bytes_to_wif(rec_pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
        {"type": "NUMERIC", "hex": "00000000"},
        {"type": "PUBKEY",  "hex": rec_pk_hex},
        {"type": "PUBKEY",  "hex": hot_pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend18-dest")
    return {
        "id": 18,
        "name": "VAULT_LOCK hot-key spend (delay=0)",
        "block_types": ["VAULT_LOCK"],
        "recovery_pubkey": rec_pk_hex,
        "hot_pubkey": hot_pk_hex,
        "hot_delay": 0,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = [PUBKEY(recovery), PUBKEY(hot), SIGNATURE]. "
                 "Both pubkeys revealed so the rung leaf can be "
                 "reconstructed (PubkeyCountForBlock=2). Either key "
                 "may sign; this vector uses the hot key.",
    }


def spend_29_cosign(node, wallet) -> dict:
    """COSIGN — cross-input check. The COSIGN evaluator scans OTHER
    inputs in the same tx and verifies one of their spent SPKs matches
    the conditions HASH256. We pair the COSIGN MLSC with a MiniWallet
    (P2TR script-path OP_TRUE) UTXO whose SPK is committed."""
    wallet_utxo = wallet.get_utxo()           # consumed by the spend
    wallet_spk = bytes(wallet._scriptPubKey)
    spk_commit = hashlib.sha256(wallet_spk).hexdigest()

    # Fund the COSIGN MLSC.
    cosign_fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "COSIGN", "fields": [
            {"type": "HASH256", "hex": spk_commit},
        ]}],
    }]
    cosign_fund = _fund_mlsc(node, wallet, cosign_fund_rungs)

    # Build unsigned 2-input spend: input[0] = COSIGN MLSC,
    # input[1] = wallet P2TR utxo. Output[0] = SIG MLSC.
    dest_seed = "bip-xxxx-spend29-dest"
    dest_pk_hex = schnorr_pk(derive_key(dest_seed))
    spend_amt = (cosign_fund["amount"] + Decimal(str(wallet_utxo["value"]))
                 - Decimal("0.001")).quantize(Decimal("0.00000001"))
    spend_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": dest_pk_hex},
        ]}],
    }]
    raw = node.createrungtx(
        [
            {"txid": cosign_fund["fund_txid"], "vout": 0},
            {"txid": wallet_utxo["txid"], "vout": wallet_utxo["vout"]},
        ],
        [spend_amt],
        spend_rungs,
    )

    conditions_arr = [{"blocks": [{"type": "COSIGN", "fields": [
        {"type": "HASH256", "hex": spk_commit},
    ]}]}]
    sign_result = node.signrungtx(
        raw["hex"],
        [{"input": 0, "blocks": [{"type": "COSIGN"}],
          "conditions": conditions_arr}],
        [
            {"amount": float(cosign_fund["amount"]),
             "scriptPubKey": cosign_fund["spk"]},
            {"amount": float(wallet_utxo["value"]),
             "scriptPubKey": wallet_spk.hex()},
        ],
    )
    # complete=False is expected — only input[0] (COSIGN) is signed by
    # signrungtx; input[1] gets its OP_TRUE witness attached below.

    # Attach the wallet's P2TR script-path OP_TRUE witness to input[1].
    tx = tx_from_hex(sign_result["hex"])
    leaf_info = list(wallet._taproot_info.leaves.values())[0]
    tx.wit.vtxinwit[1].scriptWitness.stack = [
        leaf_info.script,
        bytes([leaf_info.version | wallet._taproot_info.negflag])
        + wallet._taproot_info.internal_pubkey,
    ]
    spend_hex = tx.serialize().hex()
    spend_txid = node.sendrawtransaction(spend_hex)

    return {
        "id": 29,
        "name": "COSIGN cross-input SPK check (2-input spend)",
        "block_types": ["COSIGN"],
        "wallet_input_spk_hex": wallet_spk.hex(),
        "spk_commit_hex": spk_commit,
        "destination_pubkey": dest_pk_hex,
        "fund_txid": cosign_fund["fund_txid"],
        "fund_hex": cosign_fund["fund_hex"],
        "fund_size_bytes": cosign_fund["fund_size_bytes"],
        "fund_spk": cosign_fund["spk"],
        "fund_amount": float(cosign_fund["amount"]),
        "spend": {
            "spend_txid": spend_txid,
            "spend_hex": spend_hex,
            "spend_size_bytes": len(spend_hex) // 2,
            "input_count": 2,
            "input1_witness_kind": "P2TR script-path OP_TRUE",
            "witness_shape": _witness_shape(spend_hex),
        },
        "notes": "Spend tx has 2 inputs. The COSIGN evaluator at "
                 "input[0] scans OTHER inputs and checks "
                 "SHA256(spent_scriptPubKey) == conditions HASH256. "
                 "input[1] is a P2TR script-path OP_TRUE wallet UTXO "
                 "whose SPK matches the commit.",
    }


def spend_4_csv(node, wallet, mine) -> dict:
    """CSV with delay — mine the delay before spending."""
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "CSV", "fields": [
            {"type": "NUMERIC", "hex": "02000000"},  # delay = 2 blocks
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    # Mine the CSV delay so the spend is mature.
    mine(3)
    spender_blocks = [{"type": "CSV"}]
    conditions_arr = [{"blocks": [{"type": "CSV", "fields": [
        {"type": "NUMERIC", "hex": "02000000"},
    ]}]}]
    # Build spend with nSequence ≥ 2 so CSV is satisfied.
    dest_pk = derive_key("bip-xxxx-spend4-dest")
    spend_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": schnorr_pk(dest_pk)},
        ]}],
    }]
    spend_amt = (fund["amount"] - Decimal("0.001")).quantize(Decimal("0.00000001"))
    raw = node.createrungtx(
        [{"txid": fund["fund_txid"], "vout": 0, "sequence": 2}],
        [spend_amt],
        spend_rungs,
    )
    sign_result = node.signrungtx(
        raw["hex"],
        [{"input": 0, "blocks": spender_blocks,
          "conditions": conditions_arr}],
        [{"amount": float(fund["amount"]), "scriptPubKey": fund["spk"]}],
    )
    assert sign_result["complete"], f"signrungtx incomplete: {sign_result}"
    spend_hex = sign_result["hex"]
    spend_txid = node.sendrawtransaction(spend_hex)
    return {
        "id": 4,
        "name": "CSV=2 spend after delay elapsed",
        "block_types": ["CSV"],
        "csv_blocks": 2,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": {
            "spend_txid": spend_txid,
            "spend_hex": spend_hex,
            "spend_size_bytes": len(spend_hex) // 2,
            "nSequence": 2,
            "destination_pubkey": schnorr_pk(dest_pk),
            "witness_shape": _witness_shape(spend_hex),
        },
        "notes": "CSV witness empty after E-022; nSequence ≥ conditions "
                 "NUMERIC and the spent UTXO must be ≥ NUMERIC blocks "
                 "old.",
    }


def spend_19_timelocked_sig(node, wallet, mine) -> dict:
    """TIMELOCKED_SIG — sign + CSV elapsed."""
    seed = "bip-xxxx-spend19-tlsig"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "TIMELOCKED_SIG", "fields": [
            {"type": "SCHEME",  "hex": "01"},
            {"type": "NUMERIC", "hex": "02000000"},  # CSV = 2
            {"type": "PUBKEY",  "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    mine(3)
    spender_blocks = [{
        "type": "TIMELOCKED_SIG",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
    }]
    conditions_arr = [{"blocks": [{"type": "TIMELOCKED_SIG", "fields": [
        {"type": "SCHEME",  "hex": "01"},
        {"type": "NUMERIC", "hex": "02000000"},
        {"type": "PUBKEY",  "hex": pk_hex},
    ]}]}]
    dest_pk = derive_key("bip-xxxx-spend19-dest")
    spend_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": schnorr_pk(dest_pk)},
        ]}],
    }]
    spend_amt = (fund["amount"] - Decimal("0.001")).quantize(Decimal("0.00000001"))
    raw = node.createrungtx(
        [{"txid": fund["fund_txid"], "vout": 0, "sequence": 2}],
        [spend_amt],
        spend_rungs,
    )
    sign_result = node.signrungtx(
        raw["hex"],
        [{"input": 0, "blocks": spender_blocks,
          "conditions": conditions_arr}],
        [{"amount": float(fund["amount"]), "scriptPubKey": fund["spk"]}],
    )
    assert sign_result["complete"]
    spend_hex = sign_result["hex"]
    spend_txid = node.sendrawtransaction(spend_hex)
    return {
        "id": 19,
        "name": "TIMELOCKED_SIG spend (CSV=2, sig + delay elapsed)",
        "block_types": ["TIMELOCKED_SIG"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "csv_blocks": 2,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": {
            "spend_txid": spend_txid,
            "spend_hex": spend_hex,
            "spend_size_bytes": len(spend_hex) // 2,
            "nSequence": 2,
            "destination_pubkey": schnorr_pk(dest_pk),
            "witness_shape": _witness_shape(spend_hex),
        },
        "notes": "Compound rule: SIG verifies pubkey + nSequence ≥ "
                 "conditions NUMERIC. Witness = PUBKEY + SIGNATURE.",
    }


def spend_6_multisig(node, wallet) -> dict:
    """MULTISIG 2-of-3 spend — sign with 2 keys, supply Merkle proofs."""
    seeds = ["bip-xxxx-spend6-msig-a",
             "bip-xxxx-spend6-msig-b",
             "bip-xxxx-spend6-msig-c"]
    pks = [derive_key(s) for s in seeds]
    pk_hexes = [schnorr_pk(k) for k in pks]
    wifs = [bytes_to_wif(k.get_bytes(), True) for k in pks]
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "MULTISIG", "fields": [
            {"type": "NUMERIC", "hex": "02000000"},  # K = 2
            {"type": "SCHEME",  "hex": "01"},
            {"type": "PUBKEY",  "hex": pk_hexes[0]},
            {"type": "PUBKEY",  "hex": pk_hexes[1]},
            {"type": "PUBKEY",  "hex": pk_hexes[2]},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "MULTISIG",
        "privkeys": [wifs[0], wifs[2]],   # any K = 2 of the N pubkeys
        "pubkeys": pk_hexes,                # full N-list in commit order
    }]
    conditions_arr = [{"blocks": [{"type": "MULTISIG", "fields": [
        {"type": "NUMERIC", "hex": "02000000"},
        {"type": "SCHEME",  "hex": "01"},
        {"type": "PUBKEY",  "hex": pk_hexes[0]},
        {"type": "PUBKEY",  "hex": pk_hexes[1]},
        {"type": "PUBKEY",  "hex": pk_hexes[2]},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend6-dest")
    return {
        "id": 6,
        "name": "MULTISIG 2-of-3 spend (Triplets K + Merkle proofs)",
        "block_types": ["MULTISIG"],
        "key_seeds": {f"k{i}": s for i, s in enumerate(seeds)},
        "pubkeys_compressed": pk_hexes,
        "signing_indices": [0, 2],
        "threshold": 2,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Witness = K × (PUBKEY, MERKLE_PROOF, SIGNATURE) "
                 "triplets. Inner pubkey-Merkle root in conditions "
                 "binds the N-set; spender reveals K with proofs.",
    }


def spend_25_output_check(node, wallet) -> dict:
    """OUTPUT_CHECK: pin output[0] to a value band only (script_hash =
    all-zeros disables the SPK check). Spend tx is split: output[0]
    (small value within band) + output[1] (change). NUMERIC caps at
    2^32-1 sats so max_sats can't cover a full coinbase value, hence
    the split."""
    pinned_seed = "bip-xxxx-spend25-pinned"
    change_seed = "bip-xxxx-spend25-change"
    pinned_pk_hex = schnorr_pk(derive_key(pinned_seed))
    change_pk_hex = schnorr_pk(derive_key(change_seed))
    pinned_value = Decimal("0.001")
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "OUTPUT_CHECK", "fields": [
            {"type": "NUMERIC", "hex": "00000000"},        # output_index = 0
            {"type": "NUMERIC", "hex": "10270000"},        # min_sats = 10_000
            {"type": "NUMERIC", "hex": "00e1f505"},        # max_sats = 100_000_000 (1 BTC)
            {"type": "HASH256", "hex": "00" * 32},          # skip script-hash check
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    change_value = (fund["amount"] - pinned_value - Decimal("0.001")).quantize(
        Decimal("0.00000001"))
    spend_rungs = [
        {"output_index": 0, "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": pinned_pk_hex},
        ]}]},
        {"output_index": 1, "blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": change_pk_hex},
        ]}]},
    ]
    raw = node.createrungtx(
        [{"txid": fund["fund_txid"], "vout": 0}],
        [pinned_value, change_value],
        spend_rungs,
    )
    conditions_arr = [{"blocks": [{"type": "OUTPUT_CHECK", "fields": [
        {"type": "NUMERIC", "hex": "00000000"},
        {"type": "NUMERIC", "hex": "10270000"},
        {"type": "NUMERIC", "hex": "00e1f505"},
        {"type": "HASH256", "hex": "00" * 32},
    ]}]}]
    sign_result = node.signrungtx(
        raw["hex"],
        [{"input": 0, "blocks": [{"type": "OUTPUT_CHECK"}],
          "conditions": conditions_arr}],
        [{"amount": float(fund["amount"]), "scriptPubKey": fund["spk"]}],
    )
    assert sign_result["complete"]
    spend_hex = sign_result["hex"]
    spend_txid = node.sendrawtransaction(spend_hex)
    return {
        "id": 25,
        "name": "OUTPUT_CHECK spend (pin output[0] value band, no SPK)",
        "block_types": ["OUTPUT_CHECK"],
        "pinned_pubkey": pinned_pk_hex,
        "change_pubkey": change_pk_hex,
        "pinned_value_btc": float(pinned_value),
        "min_sats": 10_000,
        "max_sats": 100_000_000,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": {
            "spend_txid": spend_txid,
            "spend_hex": spend_hex,
            "spend_size_bytes": len(spend_hex) // 2,
            "vout_count": 2,
            "witness_shape": _witness_shape(spend_hex),
        },
        "notes": "Witness empty. Spend tx vout[output_index] must "
                 "have value ∈ [min_sats, max_sats]. script_hash = "
                 "all-zeros means SPK check is skipped (a multi-vout "
                 "MLSC tx shares one conditions_root and so all "
                 "outputs share one SPK — pinning a specific SPK "
                 "would be circular).",
    }


def spend_20_hash_sig(node, wallet) -> dict:
    """HASH_SIG — preimage + sig combined."""
    seed = "bip-xxxx-spend20-hashsig"
    pk = derive_key(seed)
    pk_hex = schnorr_pk(pk)
    preimage = b"spend20-hash-sig-preimage"
    commit = hashlib.sha256(preimage).hexdigest()
    fund_rungs = [{
        "output_index": 0,
        "blocks": [{"type": "HASH_SIG", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()},
            {"type": "SCHEME",   "hex": "01"},
            {"type": "PUBKEY",   "hex": pk_hex},
        ]}],
    }]
    fund = _fund_mlsc(node, wallet, fund_rungs)
    spender_blocks = [{
        "type": "HASH_SIG",
        "privkey": bytes_to_wif(pk.get_bytes(), True),
        "preimage": preimage.hex(),
    }]
    conditions_arr = [{"blocks": [{"type": "HASH_SIG", "fields": [
        {"type": "PREIMAGE", "hex": preimage.hex()},  # auto → HASH256
        {"type": "SCHEME",   "hex": "01"},
        {"type": "PUBKEY",   "hex": pk_hex},
    ]}]}]
    spend = _round_trip(node, fund, spender_blocks, conditions_arr,
                        "bip-xxxx-spend20-dest")
    return {
        "id": 20,
        "name": "HASH_SIG spend (preimage + Schnorr sig)",
        "block_types": ["HASH_SIG"],
        "fund_seed": seed,
        "fund_pubkey": pk_hex,
        "preimage_hex": preimage.hex(),
        "commit_hex": commit,
        "fund_txid": fund["fund_txid"],
        "fund_hex": fund["fund_hex"],
        "fund_size_bytes": fund["fund_size_bytes"],
        "fund_spk": fund["spk"],
        "fund_amount": float(fund["amount"]),
        "spend": spend,
        "notes": "Compound rule (Reveal P + Fixed N). Witness = "
                 "[PUBKEY, SIGNATURE, PREIMAGE].",
    }


# ──────────────────────────────────────────────────────────────────
# Generator entry
# ──────────────────────────────────────────────────────────────────


class GenerateRungTxSpendVectors(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, COINBASE_MATURITY + 30)

        # v3 round-trip set.
        mine = lambda n: self.generate(node, n)
        # builder, needs_mine
        builders = [
            (spend_1_sig, False),
            (spend_5_cltv, False),
            (spend_10_anchor, False),
            (spend_14_hash_guarded, False),
            (spend_20_hash_sig, False),
            (spend_6_multisig, False),
            (spend_25_output_check, False),
            (spend_4_csv, True),
            (spend_19_timelocked_sig, True),
            (spend_18_vault_lock, False),
            (spend_29_cosign, False),
            (spend_2_p2wpkh_legacy, False),
            (spend_27_adaptor_sig, False),
            (spend_21_ptlc, False),
            (spend_3_htlc_claim, False),
            (spend_3b_htlc_refund, True),
            (spend_22_anchor_fee, False),
            (spend_28_musig_threshold, False),
            (spend_12_amount_lock, False),
            (spend_18b_vault_lock_hot, True),
            (spend_23_timelocked_multisig, True),
            (spend_26_p2pkh_legacy, False),
            (spend_51_p2pk_legacy, False),
            (spend_52_p2tr_legacy, False),
            (spend_42_anchor_oracle, False),
            (spend_68_cltv_sig, False),
        ]
        vectors = []
        for builder, needs_mine in builders:
            args = (node, wallet, mine) if needs_mine else (node, wallet)
            v = builder(*args)
            vectors.append(v)
            self.generate(node, 1)
            self.log.info(f"  {builder.__name__}: ok (id {v['id']})")

        write_vectors(
            vectors,
            "Reproducible v4 RUNG_TX fund+spend round-trip vectors. "
            "Each vector funds an MLSC output, spends it via "
            "signrungtx, and records both transactions plus a "
            "deterministic witness shape summary. Schnorr signature "
            "bytes vary across runs (fresh aux_rand) but witness "
            "structure is deterministic and is the artifact under "
            "test for cross-implementation byte-equivalence. "
            "Generated by test/functional/generate_rung_tx_spend_"
            "vectors.py — re-run to regenerate.",
        )

        self.log.info(f"Generated {len(vectors)} spend vectors → {OUTPUT_PATH}")


if __name__ == "__main__":
    GenerateRungTxSpendVectors(__file__).main()
