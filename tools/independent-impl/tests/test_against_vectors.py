#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license.
"""Cross-implementation check: the independent verifier must reproduce
the committed conditions_root for every SIG-only fund vector in
src/test/data/rung_tx_vectors.json.

Run from repo root:
    python3 tools/independent-impl/tests/test_against_vectors.py

Exits 0 if all vectors agree, non-zero otherwise."""

import json
import sys
from pathlib import Path

# Make the verifier importable from a sibling directory.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import ladder_verify as lv  # noqa: E402


REPO_ROOT = _HERE.parents[2]
POS_VECTORS = REPO_ROOT / "src" / "test" / "data" / "rung_tx_vectors.json"


# Per-vector handlers: each takes the JSON vector and returns
# either a recomputed conditions Merkle root (bytes) or None
# if the block shape isn't yet supported by this skeleton.

def _root_sig(vec: dict):
    pk_hex = vec.get("fund_pubkey_compressed")
    if not pk_hex:
        return None
    return lv.conditions_root_for_single_sig_rung(bytes.fromhex(pk_hex), 0)


def _root_csv(vec: dict):
    n = vec.get("csv_blocks")
    if n is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_CSV,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(n))],
    )


def _root_cltv(vec: dict):
    h = vec.get("cltv_height")
    if h is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_CLTV,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(h))],
    )


def _root_cltv_time(vec: dict):
    v = vec.get("cltv_time_value")
    if v is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_CLTV_TIME,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(v))],
    )


def _root_csv_time(vec: dict):
    v = vec.get("csv_time_value")
    if v is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_CSV_TIME,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(v))],
    )


def _root_anchor(vec: dict):
    v = vec.get("anchor_id")
    if v is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_ANCHOR,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(v))],
    )


def _root_anchor_channel(vec: dict):
    v = vec.get("commitment_number")
    if v is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_ANCHOR_CHANNEL,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(v))],
    )


def _root_amount_lock(vec: dict):
    lo, hi = vec.get("min_sats"), vec.get("max_sats")
    if lo is None or hi is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_AMOUNT_LOCK,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(lo)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(hi))],
    )


def _root_weight_limit(vec: dict):
    w = vec.get("max_weight")
    if w is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_WEIGHT_LIMIT,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(w))],
    )


# ---- single-numeric no-pubkey blocks ----

def _h_one_num(bt_const, key):
    def f(vec):
        v = vec.get(key)
        if v is None:
            return None
        return lv.conditions_root_for_no_pubkey_rung(
            bt_const,
            [(lv.DT_NUMERIC, lv._numeric_le_4b(v))],
        )
    return f


# ---- two-numeric no-pubkey blocks ----

def _h_two_num(bt_const, k_a, k_b):
    def f(vec):
        a, b = vec.get(k_a), vec.get(k_b)
        if a is None or b is None:
            return None
        return lv.conditions_root_for_no_pubkey_rung(
            bt_const,
            [(lv.DT_NUMERIC, lv._numeric_le_4b(a)),
             (lv.DT_NUMERIC, lv._numeric_le_4b(b))],
        )
    return f


# ---- three-numeric no-pubkey blocks ----

def _h_three_num(bt_const, k_a, k_b, k_c):
    def f(vec):
        a, b, c = vec.get(k_a), vec.get(k_b), vec.get(k_c)
        if a is None or b is None or c is None:
            return None
        return lv.conditions_root_for_no_pubkey_rung(
            bt_const,
            [(lv.DT_NUMERIC, lv._numeric_le_4b(a)),
             (lv.DT_NUMERIC, lv._numeric_le_4b(b)),
             (lv.DT_NUMERIC, lv._numeric_le_4b(c))],
        )
    return f


# ---- single-hash256 no-pubkey blocks ----

def _h_one_hash(bt_const, key):
    def f(vec):
        h = vec.get(key)
        if h is None:
            return None
        return lv.conditions_root_for_no_pubkey_rung(
            bt_const,
            [(lv.DT_HASH256, bytes.fromhex(h))],
        )
    return f


# ---- two-hash256 no-pubkey blocks ----

def _h_two_hash(bt_const, k_a, k_b):
    def f(vec):
        a, b = vec.get(k_a), vec.get(k_b)
        if a is None or b is None:
            return None
        return lv.conditions_root_for_no_pubkey_rung(
            bt_const,
            [(lv.DT_HASH256, bytes.fromhex(a)),
             (lv.DT_HASH256, bytes.fromhex(b))],
        )
    return f


# ---- ANCHOR_POOL: HASH256 + NUMERIC ----

def _root_anchor_pool(vec: dict):
    root_hex = vec.get("vtxo_tree_root_hex")
    n = vec.get("participant_count")
    if root_hex is None or n is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_ANCHOR_POOL,
        [(lv.DT_HASH256, bytes.fromhex(root_hex)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(n))],
    )


# ---- ANCHOR_RESERVE: NUMERIC + NUMERIC + HASH256 ----

def _root_anchor_reserve(vec: dict):
    n = vec.get("threshold_n")
    m = vec.get("threshold_m")
    g = vec.get("guardian_hash_hex")
    if n is None or m is None or g is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_ANCHOR_RESERVE,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(n)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(m)),
         (lv.DT_HASH256, bytes.fromhex(g))],
    )


# ---- TAGGED_HASH: HASH256(tag_hash) + HASH256(expected) ----

def _root_tagged_hash(vec: dict):
    tag_hex = vec.get("tag_hash_hex")
    exp_hex = vec.get("expected_hex")
    if tag_hex is None or exp_hex is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_TAGGED_HASH,
        [(lv.DT_HASH256, bytes.fromhex(tag_hex)),
         (lv.DT_HASH256, bytes.fromhex(exp_hex))],
    )


# ---- COMPARE: 3-numeric (op, value_b, value_c) ----

def _root_compare(vec: dict):
    op = vec.get("op")
    vb = vec.get("value_b")
    vc = vec.get("value_c")
    # op is sometimes a string; only support the int form here.
    if op is None or vb is None:
        return None
    if isinstance(op, str):
        return None
    fields = [(lv.DT_NUMERIC, lv._numeric_le_4b(op)),
              (lv.DT_NUMERIC, lv._numeric_le_4b(vb))]
    if vc is not None:
        fields.append((lv.DT_NUMERIC, lv._numeric_le_4b(vc)))
    return lv.conditions_root_for_no_pubkey_rung(lv.BT_COMPARE, fields)


# ---- single-pubkey block handlers ----

def _h_pk_two_field(bt_const, pk_key, fields_fn):
    """fields_fn(vec) returns a list of (DT_*, bytes) for the conditions."""
    def f(vec):
        pk_hex = vec.get(pk_key)
        fields = fields_fn(vec)
        if pk_hex is None or fields is None:
            return None
        return lv.conditions_root_for_pubkey_rung(
            bt_const, fields, bytes.fromhex(pk_hex),
        )
    return f


def _root_timelocked_sig(vec):
    csv = vec.get("csv_blocks")
    if csv is None:
        return None
    return [(lv.DT_SCHEME, b"\x01"),
            (lv.DT_NUMERIC, lv._numeric_le_4b(csv))]


def _root_cltv_sig(vec):
    h = vec.get("cltv_height")
    if h is None:
        return None
    return [(lv.DT_SCHEME, b"\x01"),
            (lv.DT_NUMERIC, lv._numeric_le_4b(h))]


def _root_hash_sig(vec):
    commit = vec.get("commit_hex")
    if commit is None:
        return None
    return [(lv.DT_HASH256, bytes.fromhex(commit)),
            (lv.DT_SCHEME, b"\x01")]


def _root_musig_threshold(vec):
    m = vec.get("threshold")
    n = vec.get("group_size")
    if m is None or n is None:
        return None
    return [(lv.DT_NUMERIC, lv._numeric_le_4b(m)),
            (lv.DT_NUMERIC, lv._numeric_le_4b(n))]


def _root_adaptor_sig(_vec):
    # ADAPTOR_SIG has nullptr conditions: empty field list.
    return []


def _root_ptlc(vec):
    csv = vec.get("csv_blocks")
    if csv is None:
        return None
    return [(lv.DT_NUMERIC, lv._numeric_le_4b(csv))]


def _root_anchor_oracle(vec):
    n = vec.get("outcome_count")
    if n is None:
        return None
    return [(lv.DT_NUMERIC, lv._numeric_le_4b(n))]


def _root_latch_set(vec):
    s = vec.get("initial_state")
    if s is None:
        return None
    return [(lv.DT_NUMERIC, lv._numeric_le_4b(s))]


def _root_counter_down(vec):
    c = vec.get("count")
    if c is None:
        return None
    return [(lv.DT_NUMERIC, lv._numeric_le_4b(c))]


def _root_counter_up(vec):
    a = vec.get("current")
    b = vec.get("target")
    if a is None or b is None:
        return None
    return [(lv.DT_NUMERIC, lv._numeric_le_4b(a)),
            (lv.DT_NUMERIC, lv._numeric_le_4b(b))]


# Map block-type-list → handler.
_HANDLERS = {
    # Existing
    ("SIG",):              _root_sig,
    ("CSV",):              _root_csv,
    ("CLTV",):             _root_cltv,
    ("CLTV_TIME",):        _root_cltv_time,
    ("CSV_TIME",):         _root_csv_time,
    ("ANCHOR",):           _root_anchor,
    ("ANCHOR_CHANNEL",):   _root_anchor_channel,
    ("AMOUNT_LOCK",):      _root_amount_lock,
    ("WEIGHT_LIMIT",):     _root_weight_limit,
    # F-NEW: covenant + recursion + governance + PLC + anchor families
    # — every no-pubkey block type with a stable JSON schema.
    ("CTV",):              _h_one_hash(lv.BT_CTV, "template_hash_hex"),
    ("HASH_GUARDED",):     _h_one_hash(lv.BT_HASH_GUARDED, "commit_hex"),
    ("TAGGED_HASH",):      _root_tagged_hash,
    ("ANCHOR_SEAL",):      _h_two_hash(lv.BT_ANCHOR_SEAL, "seal_a_hex", "seal_b_hex"),
    ("ANCHOR_POOL",):      _root_anchor_pool,
    ("ANCHOR_RESERVE",):   _root_anchor_reserve,
    ("RECURSE_SAME",):     _h_one_num(lv.BT_RECURSE_SAME, "max_depth"),
    ("RECURSE_UNTIL",):    _h_one_num(lv.BT_RECURSE_UNTIL, "until_height"),
    ("RECURSE_COUNT",):    _h_one_num(lv.BT_RECURSE_COUNT, "max_count"),
    ("RECURSE_SPLIT",):    _h_two_num(lv.BT_RECURSE_SPLIT, "max_splits", "min_split_sats"),
    ("EPOCH_GATE",):       _h_two_num(lv.BT_EPOCH_GATE, "epoch_start", "epoch_end"),
    ("INPUT_COUNT",):      _h_two_num(lv.BT_INPUT_COUNT, "min_inputs", "max_inputs"),
    ("OUTPUT_COUNT",):     _h_two_num(lv.BT_OUTPUT_COUNT, "min_outputs", "max_outputs"),
    ("RELATIVE_VALUE",):   _h_two_num(lv.BT_RELATIVE_VALUE, "numerator", "denominator"),
    ("HYSTERESIS_FEE",):   _h_two_num(lv.BT_HYSTERESIS_FEE, "high_sat_vb", "low_sat_vb"),
    ("HYSTERESIS_VALUE",): _h_two_num(lv.BT_HYSTERESIS_VALUE, "high_sats", "low_sats"),
    ("TIMER_CONTINUOUS",): _h_two_num(lv.BT_TIMER_CONTINUOUS, "accumulated", "target"),
    ("TIMER_OFF_DELAY",):  _h_one_num(lv.BT_TIMER_OFF_DELAY, "remaining"),
    ("COUNTER_PRESET",):   _h_two_num(lv.BT_COUNTER_PRESET, "current", "preset"),
    ("SEQUENCER",):        _h_two_num(lv.BT_SEQUENCER, "current_step", "total_steps"),
    ("RATE_LIMIT",):       _h_three_num(lv.BT_RATE_LIMIT, "max_per_block",
                                          "accumulation_cap", "refill_blocks"),
    ("COMPARE",):          _root_compare,
    # Two-pubkey blocks (PubkeyCountForBlock=2)
    ("HTLC",):             None,         # set below — needs custom handler
    ("VAULT_LOCK",):       None,
    ("ANCHOR_FEE",):       None,
    # Inner-Merkle pubkey-tree (PubkeyCountForBlock=0)
    ("MULTISIG",):         None,
    # Single-pubkey blocks (PubkeyCountForBlock=1)
    ("TIMELOCKED_SIG",):   _h_pk_two_field(0x0701, "pubkey_compressed", _root_timelocked_sig),
    ("CLTV_SIG",):         _h_pk_two_field(0x0705, "pubkey_compressed", _root_cltv_sig),
    ("HASH_SIG",):         _h_pk_two_field(0x0703, "pubkey_compressed", _root_hash_sig),
    ("MUSIG_THRESHOLD",):  _h_pk_two_field(0x0004, "agg_pubkey_compressed", _root_musig_threshold),
    ("ADAPTOR_SIG",):      _h_pk_two_field(0x0003, "adaptor_pubkey_compressed", _root_adaptor_sig),
    ("PTLC",):             _h_pk_two_field(0x0704, "adaptor_pubkey_compressed", _root_ptlc),
    ("ANCHOR_ORACLE",):    _h_pk_two_field(0x0506, "oracle_pubkey_compressed", _root_anchor_oracle),
    ("LATCH_SET",):        _h_pk_two_field(0x0621, "setter_pubkey_compressed", _root_latch_set),
    ("COUNTER_DOWN",):     _h_pk_two_field(0x0631, "event_signer_pubkey_compressed", _root_counter_down),
    ("COUNTER_UP",):       _h_pk_two_field(0x0633, "event_signer_pubkey_compressed", _root_counter_up),
}


def _root_htlc(vec):
    recv = vec.get("recv_pubkey_compressed")
    send = vec.get("send_pubkey_compressed")
    pay_hash = vec.get("payment_hash_hex")
    csv = vec.get("csv_blocks")
    if not all((recv, send, pay_hash)) or csv is None:
        return None
    fields = [(lv.DT_HASH256, bytes.fromhex(pay_hash)),
              (lv.DT_NUMERIC, lv._numeric_le_4b(csv)),
              (lv.DT_SCHEME, b"\x01")]
    return lv.conditions_root_for_two_pubkey_rung(
        lv.BT_HTLC, fields,
        bytes.fromhex(recv), bytes.fromhex(send),
    )


def _root_vault_lock(vec):
    rec = vec.get("recovery_pubkey_compressed")
    hot = vec.get("hot_pubkey_compressed")
    delay = vec.get("hot_delay")
    if not all((rec, hot)) or delay is None:
        return None
    fields = [(lv.DT_NUMERIC, lv._numeric_le_4b(delay))]
    return lv.conditions_root_for_two_pubkey_rung(
        lv.BT_VAULT_LOCK, fields,
        bytes.fromhex(rec), bytes.fromhex(hot),
    )


def _root_anchor_fee(vec):
    pks = vec.get("pubkeys_compressed") or []
    if len(pks) != 2:
        return None
    min_fee = vec.get("min_fee_rate")
    max_fee = vec.get("max_fee_rate")
    max_w = vec.get("max_weight")
    commit = vec.get("commitment_number")
    if None in (min_fee, max_fee, max_w, commit):
        return None
    fields = [(lv.DT_SCHEME, b"\x01"),
              (lv.DT_NUMERIC, lv._numeric_le_4b(min_fee)),
              (lv.DT_NUMERIC, lv._numeric_le_4b(max_fee)),
              (lv.DT_NUMERIC, lv._numeric_le_4b(max_w)),
              (lv.DT_NUMERIC, lv._numeric_le_4b(commit))]
    return lv.conditions_root_for_two_pubkey_rung(
        lv.BT_ANCHOR_FEE, fields,
        bytes.fromhex(pks[0]), bytes.fromhex(pks[1]),
    )


def _root_multisig(vec):
    pks_hex = vec.get("pubkeys_compressed") or []
    threshold = vec.get("threshold")
    if not pks_hex or threshold is None:
        return None
    # Conditions = NUMERIC(K) + SCHEME + HASH256(BuildPubkeyMerkleRoot(pks))
    pubkey_root = lv.build_pubkey_merkle_root(
        [bytes.fromhex(p) for p in pks_hex])
    fields = [(lv.DT_NUMERIC, lv._numeric_le_4b(threshold)),
              (lv.DT_SCHEME, b"\x01"),
              (lv.DT_HASH256, pubkey_root)]
    # PubkeyCountForBlock(MULTISIG) = 0 (outer leaf doesn't fold pubkeys)
    return lv.conditions_root_for_no_pubkey_rung(lv.BT_MULTISIG, fields)


_HANDLERS[("HTLC",)]       = _root_htlc
_HANDLERS[("VAULT_LOCK",)] = _root_vault_lock
_HANDLERS[("ANCHOR_FEE",)] = _root_anchor_fee
_HANDLERS[("MULTISIG",)]   = _root_multisig


# Header-only fixtures (no mutations / no decays / etc.)
def _root_recurse_modified(vec):
    md = vec.get("max_depth")
    mc = vec.get("mutation_count")
    if md is None or mc is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_RECURSE_MODIFIED,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(md)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(mc))],
    )


def _root_recurse_decay(vec):
    md = vec.get("max_depth")
    dc = vec.get("decay_count")
    if md is None or dc is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_RECURSE_DECAY,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(md)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(dc))],
    )


def _root_qabi_prime(_vec):
    # No committed fields — purely witness-driven.
    return lv.conditions_root_for_no_pubkey_rung(lv.BT_QABI_PRIME, [])


def _root_latch_reset(vec):
    pk = vec.get("resetter_pubkey_compressed")
    state = vec.get("current_state")
    delay = vec.get("delay")
    if pk is None or state is None or delay is None:
        return None
    return lv.conditions_root_for_pubkey_rung(
        lv.BT_LATCH_RESET,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(state)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(delay))],
        bytes.fromhex(pk),
    )


def _root_one_shot(vec):
    state = vec.get("initial_state")
    commit = vec.get("commit_hex")
    if state is None or commit is None:
        return None
    # PubkeyCountForBlock(ONE_SHOT) = 0 in this fixture (no PUBKEY field
    # supplied in vec_39); commit is HASH256(PREIMAGE) auto-derived by
    # the serializer.
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_ONE_SHOT,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(state)),
         (lv.DT_HASH256, bytes.fromhex(commit))],
    )


def _root_timelocked_multisig(vec):
    pks_hex = vec.get("pubkeys_compressed") or []
    threshold = vec.get("threshold")
    csv = vec.get("csv_blocks")
    if not pks_hex or threshold is None or csv is None:
        return None
    pubkey_root = lv.build_pubkey_merkle_root(
        [bytes.fromhex(p) for p in pks_hex])
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_TIMELOCKED_MULTISIG,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(threshold)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(csv)),
         (lv.DT_SCHEME, b"\x01"),
         (lv.DT_HASH256, pubkey_root)],
    )


_HANDLERS[("RECURSE_MODIFIED",)]   = _root_recurse_modified
_HANDLERS[("RECURSE_DECAY",)]      = _root_recurse_decay
_HANDLERS[("QABI_PRIME",)]         = _root_qabi_prime
_HANDLERS[("LATCH_RESET",)]        = _root_latch_reset
_HANDLERS[("ONE_SHOT",)]           = _root_one_shot
_HANDLERS[("TIMELOCKED_MULTISIG",)] = _root_timelocked_multisig


def _root_key_ref_sig(vec):
    relay = vec.get("relay_index")
    blk = vec.get("block_index")
    if relay is None or blk is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_KEY_REF_SIG,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(relay)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(blk))],
    )


def _root_output_check(vec):
    idx = vec.get("output_index_pinned")
    lo = vec.get("min_sats")
    hi = vec.get("max_sats")
    h = vec.get("spk_hash_hex")
    if None in (idx, lo, hi, h):
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_OUTPUT_CHECK,
        [(lv.DT_NUMERIC, lv._numeric_le_4b(idx)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(lo)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(hi)),
         (lv.DT_HASH256, bytes.fromhex(h))],
    )


# P2PK_LEGACY / P2TR_LEGACY: PUBKEY in Merkle leaf + SCHEME conditions.
def _root_p2pk_legacy(vec):
    pk = vec.get("p2pk_pubkey_compressed")
    if pk is None:
        return None
    return lv.conditions_root_for_pubkey_rung(
        lv.BT_P2PK_LEGACY,
        [(lv.DT_SCHEME, b"\x01")],
        bytes.fromhex(pk),
    )


def _root_p2tr_legacy(vec):
    pk = vec.get("p2tr_pubkey_compressed")
    if pk is None:
        return None
    return lv.conditions_root_for_pubkey_rung(
        lv.BT_P2TR_LEGACY,
        [(lv.DT_SCHEME, b"\x01")],
        bytes.fromhex(pk),
    )


# P2PKH / P2WPKH: HASH160(pubkey) in conditions, no pubkey in leaf.
# Try OpenSSL backend first; fall back to the bundled pure-Python
# RIPEMD-160 (which is what the functional-test framework uses for the
# same reason — distros increasingly drop OpenSSL ripemd160).
def _hash160(b: bytes) -> bytes:
    import hashlib
    sha = hashlib.sha256(b).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except (ValueError, AttributeError):
        sys.path.insert(0, str(REPO_ROOT / "test" / "functional"))
        from test_framework.crypto.ripemd160 import ripemd160  # noqa: E402
        return ripemd160(sha)


def _root_p2pkh_legacy(vec):
    pk = vec.get("p2pkh_pubkey_compressed")
    if pk is None:
        return None
    h160 = _hash160(bytes.fromhex(pk))
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_P2PKH_LEGACY,
        [(lv.DT_HASH160, h160)],
    )


def _root_p2wpkh_legacy(vec):
    pk = vec.get("p2wpkh_pubkey_compressed")
    if pk is None:
        return None
    h160 = _hash160(bytes.fromhex(pk))
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_P2WPKH_LEGACY,
        [(lv.DT_HASH160, h160)],
    )


_HANDLERS[("KEY_REF_SIG",)]    = _root_key_ref_sig
_HANDLERS[("OUTPUT_CHECK",)]   = _root_output_check
_HANDLERS[("P2PK_LEGACY",)]    = _root_p2pk_legacy
_HANDLERS[("P2TR_LEGACY",)]    = _root_p2tr_legacy
_HANDLERS[("P2PKH_LEGACY",)]   = _root_p2pkh_legacy
_HANDLERS[("P2WPKH_LEGACY",)]  = _root_p2wpkh_legacy


# ─── Final batch: PQ_BATCH, ACCUMULATOR, COSIGN, P2*_LEGACY (script),
#     P2TR_SCRIPT_LEGACY, QABI_SPEND. ─────────────────────────────────

def _root_pq_batch(vec):
    commit = vec.get("commit_sha256_hex")
    if commit is None:
        return None
    # Generator stores PREIMAGE(seed) which the serializer auto-folds
    # to HASH256(SHA256(seed)) = commit_sha256_hex.
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_PQ_BATCH,
        [(lv.DT_HASH256, bytes.fromhex(commit))],
    )


def _root_accumulator(vec):
    root = vec.get("merkle_root_hex")
    if root is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_ACCUMULATOR,
        [(lv.DT_HASH256, bytes.fromhex(root))],
    )


def _root_cosign(vec):
    commit = vec.get("spk_commit_hex")
    if commit is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_COSIGN,
        [(lv.DT_HASH256, bytes.fromhex(commit))],
    )


def _root_p2sh_legacy(vec):
    h160 = vec.get("hash160_hex")
    if h160 is None:
        return None
    # SCRIPT_BODY in fixture; serializer folds → HASH160 in conditions.
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_P2SH_LEGACY,
        [(lv.DT_HASH160, bytes.fromhex(h160))],
    )


def _root_p2wsh_legacy(vec):
    h256 = vec.get("hash256_hex")
    if h256 is None:
        return None
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_P2WSH_LEGACY,
        [(lv.DT_HASH256, bytes.fromhex(h256))],
    )


def _root_p2tr_script_legacy(vec):
    leaf = vec.get("leaf_commit_hex")
    pk = vec.get("internal_pubkey_compressed")
    if leaf is None or pk is None:
        return None
    # PubkeyCountForBlock(P2TR_SCRIPT_LEGACY) = 1; conditions hold the
    # script-leaf HASH256, the internal key goes into the Merkle leaf.
    return lv.conditions_root_for_pubkey_rung(
        lv.BT_P2TR_SCRIPT_LEGACY,
        [(lv.DT_HASH256, bytes.fromhex(leaf))],
        bytes.fromhex(pk),
    )


def _root_qabi_spend(vec):
    auth = vec.get("auth_tip_hex")
    root = vec.get("committed_root_hex")
    depth = vec.get("depth")
    expiry = vec.get("expiry")
    owner = vec.get("owner_id_hex")
    if None in (auth, root, depth, expiry, owner):
        return None
    # PubkeyCountForBlock(QABI_SPEND) = 0. PUBKEY_COMMIT (DT=0x02) is
    # the canonical owner identity; serializes the same as any other
    # 32-byte field by length+bytes.
    return lv.conditions_root_for_no_pubkey_rung(
        lv.BT_QABI_SPEND,
        [(lv.DT_HASH256, bytes.fromhex(auth)),
         (lv.DT_HASH256, bytes.fromhex(root)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(depth)),
         (lv.DT_NUMERIC, lv._numeric_le_4b(expiry)),
         (lv.DT_PUBKEY_COMMIT, bytes.fromhex(owner))],
    )


_HANDLERS[("PQ_BATCH",)]            = _root_pq_batch
_HANDLERS[("ACCUMULATOR",)]         = _root_accumulator
_HANDLERS[("COSIGN",)]              = _root_cosign
_HANDLERS[("P2SH_LEGACY",)]         = _root_p2sh_legacy
_HANDLERS[("P2WSH_LEGACY",)]        = _root_p2wsh_legacy
_HANDLERS[("P2TR_SCRIPT_LEGACY",)]  = _root_p2tr_script_legacy
_HANDLERS[("QABI_SPEND",)]          = _root_qabi_spend
# vec_9 DATA_RETURN+SIG: 2-rung tx (DATA_RETURN at output 0, SIG at
# output 1). The JSON omits the placeholder SIG pubkey, so we hardcode
# it here from the generator's deterministic seed
# ("bip-xxxx-vec9-placeholder") — the only piece of generator-side
# knowledge the verifier carries.
_VEC9_PLACEHOLDER_PUBKEY_HEX = (
    "033de67355ffbac58718bd4e123086a86a0eebcbd3673c097cdc5ac336f9339179"
)


def _root_data_return_plus_sig(vec):
    payload = vec.get("data_return_payload_hex")
    if payload is None:
        return None
    leaf_0 = lv.compute_tx_mlsc_leaf(
        blocks=[(lv.BT_DATA_RETURN, 0)],
        rung_blocks_with_fields=[
            (lv.BT_DATA_RETURN, [(lv.DT_DATA, bytes.fromhex(payload))])
        ],
        pubkeys=[],
        relay_refs=[],
        coil_type=lv.COIL_TYPE_UNLOCK,
        coil_attestation=lv.COIL_ATTESTATION_INLINE,
        coil_scheme=lv.SCHEME_SCHNORR,
        coil_output_index=0,
    )
    leaf_1 = lv.compute_tx_mlsc_leaf(
        blocks=[(lv.BT_SIG, 0)],
        rung_blocks_with_fields=[
            (lv.BT_SIG, [(lv.DT_SCHEME, b"\x01")])
        ],
        pubkeys=[bytes.fromhex(_VEC9_PLACEHOLDER_PUBKEY_HEX)],
        relay_refs=[],
        coil_type=lv.COIL_TYPE_UNLOCK,
        coil_attestation=lv.COIL_ATTESTATION_INLINE,
        coil_scheme=lv.SCHEME_SCHNORR,
        coil_output_index=1,
    )
    return lv.build_merkle_tree([leaf_0, leaf_1])


_HANDLERS[("DATA_RETURN", "SIG")] = _root_data_return_plus_sig


def _vec_handler(vec: dict):
    bt = tuple(vec.get("block_types") or [])
    return _HANDLERS.get(bt)


def _u256_from_rpc_hex(s: str) -> bytes:
    """Bitcoin Core's `uint256::GetHex()` returns the bytes in
    *reverse* order (txid convention). The wire-format embedding of
    the same root inside the MLSC scriptPubKey or the v4 tx body uses
    the natural byte order. This helper undoes the reversal so the
    JSON `conditions_root` / `merkle_root` strings can be compared
    against bytes computed by the verifier (which work in wire order
    throughout)."""
    raw = bytes.fromhex(s)
    return raw[::-1]


def _check_vec(vec: dict) -> tuple[bool, str]:
    handler = _vec_handler(vec)
    if handler is None:
        return False, "no handler"

    actual_root = handler(vec)
    if actual_root is None:
        return False, "handler returned None"

    # `conditions_root` may be the BIP-341-tweaked root (when
    # key_path=true). Compare against `merkle_root` (untweaked) so
    # the verifier exercises only leaf+tree logic. Tweak verification
    # is a separate (BIP-341) step that uses standard EC ops.
    expected_merkle_rpc = vec["fund_tx"].get("merkle_root") \
                          or vec["fund_tx"]["conditions_root"]
    expected_root = _u256_from_rpc_hex(expected_merkle_rpc)
    expected_spk_hex = vec["fund_tx"]["mlsc_scriptpubkey"]

    if actual_root != expected_root:
        return False, (
            f"merkle_root mismatch:\n"
            f"  expected: {expected_root.hex()}\n"
            f"  computed: {actual_root.hex()}"
        )

    # The MLSC scriptPubKey is just 0xDF || conditions_root (the
    # tweaked one, if applicable). Confirm round-trip parsing equals
    # the on-wire conditions_root field.
    expected_spk = bytes.fromhex(expected_spk_hex)
    parsed = lv.parse_mlsc_spk(expected_spk)
    if parsed is None:
        return False, "MLSC SPK parser returned None"
    on_wire_root = _u256_from_rpc_hex(vec["fund_tx"]["conditions_root"])
    if parsed != on_wire_root:
        return False, (
            f"SPK parser disagrees with on-wire conditions_root:\n"
            f"  parsed:   {parsed.hex()}\n"
            f"  expected: {on_wire_root.hex()}"
        )

    # Also exercise the v4 wire-format reader on the fund tx.
    fund_hex = vec["fund_tx"]["hex"]
    tx = lv.parse_v4_tx(fund_hex)
    if tx.version != lv.RUNG_TX_VERSION:
        return False, f"parse_v4_tx returned version={tx.version}"
    if tx.conditions_root != on_wire_root:
        return False, (
            f"v4 wire parser conditions_root != on-wire field:\n"
            f"  parsed:     {tx.conditions_root.hex()}\n"
            f"  expected:   {on_wire_root.hex()}"
        )
    return True, "ok"


def main() -> int:
    if not POS_VECTORS.exists():
        print(f"FAIL: {POS_VECTORS} not found", file=sys.stderr)
        return 2

    payload = json.loads(POS_VECTORS.read_text())
    all_vecs = payload.get("vectors", [])
    in_scope = [v for v in all_vecs if _vec_handler(v) is not None]
    out_of_scope = [v for v in all_vecs if _vec_handler(v) is None]

    print(f"committed vectors:    {len(all_vecs)}")
    print(f"  in scope:           {len(in_scope)}")
    print(f"  out of scope:       {len(out_of_scope)}")
    print()

    if not in_scope:
        print("WARN: no in-scope vectors found")
        return 0

    failures = []
    for vec in in_scope:
        ok, msg = _check_vec(vec)
        status = "OK" if ok else "FAIL"
        print(f"  vec[{vec['id']:>2}] {vec.get('name','')[:60]}: {status}")
        if not ok:
            print(f"    {msg}")
            failures.append(vec["id"])

    print()
    if failures:
        print(f"FAILED: {len(failures)} vector(s) did not match: {failures}")
        return 1
    print(f"PASSED: independent verifier reproduces conditions_root for "
          f"{len(in_scope)} vector(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
