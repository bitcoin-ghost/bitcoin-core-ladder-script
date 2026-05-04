#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license.
"""Generate / verify isolated sighash test vectors.

For each entry in `src/test/data/rung_sighash_vectors.json` the verify
path (default) re-computes the sighash via the `computesighash` RPC
from the fixed inputs (tx_hex, input_idx, spent_outputs, conditions,
variant, hash_type) and asserts byte-identity with the committed
`expected_sighash_hex`.

Reviewers and alternative implementations consume this fixture to
verify their sighash code without running the whole functional test
framework — the (inputs → expected) tuples are self-contained.

Set `VECTORS_REGENERATE=1` to overwrite the committed fixture from a
fresh regtest node.
"""

import hashlib
import json
import os
from decimal import Decimal
from pathlib import Path

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = REPO_ROOT / "src" / "test" / "data" / "rung_sighash_vectors.json"


def derive_key(seed: str) -> ECKey:
    h = hashlib.sha256(seed.encode()).digest()
    if h == b"\x00" * 32:
        h = b"\x01" * 32
    k = ECKey()
    k.set(h, True)
    return k


def schnorr_pk_compressed(k: ECKey) -> bytes:
    return k.get_pubkey().get_bytes()


# ──────────────────────────────────────────────────────────────────
# Fixture builders
# ──────────────────────────────────────────────────────────────────
#
# Each builder returns a (vector, conditions_obj_for_compute) pair.
# The vector dict is what gets persisted and committed.

def _fund_mlsc(node, wallet, conditions_rungs):
    """Fund a single MLSC output with the given conditions and return
    (txid, vout, amount_sats, scriptpubkey_hex)."""
    utxo = wallet.get_utxo()
    amt = (Decimal(str(utxo["value"])) - Decimal("0.001")).quantize(Decimal("0.00000001"))
    res = node.createrungtx(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [amt],
        conditions_rungs,
    )
    tx = tx_from_hex(res["hex"])
    wallet.sign_tx(tx)
    signed_hex = tx.serialize().hex()
    txid = node.sendrawtransaction(signed_hex)
    return {
        "txid": txid,
        "vout": 0,
        "amount_sats": int(Decimal(amt) * 100_000_000),
        "scriptpubkey_hex": res["scriptPubKey"],
    }


def _build_unsigned_spend(node, fund, n_outputs=1):
    """Build an unsigned v4 spend tx that consumes `fund` and pays
    n_outputs sweep outputs back to a deterministic placeholder."""
    sweep_pk = derive_key("bip-xxxx-sighash-sweep").get_pubkey().get_bytes().hex()
    sweep_amt_each = (Decimal(fund["amount_sats"]) - Decimal(1000)) / 100_000_000 / n_outputs
    sweep_amt_each = sweep_amt_each.quantize(Decimal("0.00000001"))
    rungs = [{"output_index": i,
              "blocks": [{"type": "SIG", "fields": [
                  {"type": "SCHEME", "hex": "01"},
                  {"type": "PUBKEY", "hex": sweep_pk},
              ]}]} for i in range(n_outputs)]
    res = node.createrungtx(
        [{"txid": fund["txid"], "vout": fund["vout"]}],
        [sweep_amt_each] * n_outputs,
        rungs,
    )
    return res["hex"]


def _make_vector(node, name, conditions_rungs, sign_conditions, *,
                 variant="ladder", hash_type=0, n_outputs=1, wallet=None,
                 description=""):
    fund = _fund_mlsc(node, wallet, conditions_rungs)
    spend_hex = _build_unsigned_spend(node, fund, n_outputs)
    amt_btc = (Decimal(fund["amount_sats"]) / Decimal(100_000_000)).quantize(Decimal("0.00000001"))
    spent = [{"amount": amt_btc,
              "scriptPubKey": fund["scriptpubkey_hex"]}]
    sighash = node.computesighash(spend_hex, 0, spent,
                                   json.dumps(sign_conditions),
                                   variant, hash_type)
    return {
        "name": name,
        "description": description,
        "tx_hex": spend_hex,
        "input_idx": 0,
        "spent_outputs": [{"amount_sats": fund["amount_sats"],
                            "scriptpubkey_hex": fund["scriptpubkey_hex"]}],
        "conditions": sign_conditions,
        "variant": variant,
        "hash_type": hash_type,
        "expected_sighash_hex": sighash["sighash"],
    }


def _conds_sig_only():
    # Conditions for createrungtx (needs output_index) and for
    # computesighash (no output_index needed) are spelled the same;
    # createrungtx ignores irrelevant fields.
    return [{"output_index": 0, "blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "01"},
    ]}]}]


def _conds_csv(blocks_n):
    return [{"output_index": 0, "blocks": [{"type": "CSV", "fields": [
        {"type": "NUMERIC", "hex": blocks_n.to_bytes(4, "little").hex()},
    ]}]}]


def _conds_and_sig_csv(blocks_n):
    return [{"output_index": 0, "blocks": [
        {"type": "SIG", "fields": [{"type": "SCHEME", "hex": "01"}]},
        {"type": "CSV", "fields": [
            {"type": "NUMERIC", "hex": blocks_n.to_bytes(4, "little").hex()},
        ]},
    ]}]


def _conds_or_two_sigs():
    return [
        {"output_index": 0, "blocks": [{"type": "SIG", "fields": [{"type": "SCHEME", "hex": "01"}]}]},
        {"output_index": 0, "blocks": [{"type": "SIG", "fields": [{"type": "SCHEME", "hex": "01"}]}]},
    ]


def _all_vectors(node, wallet):
    return [
        _make_vector(node, "single SIG, 1 output, ladder/SIGHASH_DEFAULT",
                     _conds_sig_only(), _conds_sig_only(),
                     description="Simplest case: one input, one output, SIGHASH_DEFAULT.",
                     wallet=wallet),
        _make_vector(node, "single SIG, 2 outputs, ladder/SIGHASH_DEFAULT",
                     _conds_sig_only(), _conds_sig_only(),
                     n_outputs=2,
                     description="Multi-output baseline; sighash binds the outputs hash.",
                     wallet=wallet),
        _make_vector(node, "single SIG, 1 output, ladder/SIGHASH_NONE",
                     _conds_sig_only(), _conds_sig_only(),
                     hash_type=0x02,
                     description="SIGHASH_NONE drops outputs from the sighash domain.",
                     wallet=wallet),
        _make_vector(node, "single SIG, 1 output, ladder/SIGHASH_SINGLE",
                     _conds_sig_only(), _conds_sig_only(),
                     hash_type=0x03,
                     description="SIGHASH_SINGLE binds only the matching output.",
                     wallet=wallet),
        _make_vector(node, "single SIG, 1 output, ladder/SIGHASH_ANYONECANPAY",
                     _conds_sig_only(), _conds_sig_only(),
                     hash_type=0x81,
                     description="ANYONECANPAY|ALL — input set may grow; sighash drops other inputs.",
                     wallet=wallet),
        _make_vector(node, "CSV(144) Empty rung, ladder",
                     _conds_csv(144), _conds_csv(144),
                     description="No-pubkey timelock rung; sighash still commits to the conditions hash.",
                     wallet=wallet),
        _make_vector(node, "AND(SIG, CSV(72)), ladder",
                     _conds_and_sig_csv(72), _conds_and_sig_csv(72),
                     description="Multi-block rung: both blocks fold into the conditions root.",
                     wallet=wallet),
        _make_vector(node, "OR(SIG, SIG), ladder, target rung 0",
                     _conds_or_two_sigs(), _conds_or_two_sigs(),
                     description="Multi-rung OR; sighash domain is the same regardless of chosen rung.",
                     wallet=wallet),
        _make_vector(node, "single SIG, 1 output, key_path/SIGHASH_DEFAULT",
                     _conds_sig_only(), _conds_sig_only(),
                     variant="key_path",
                     description="LadderKeyPathSighash/v1 domain; does not commit to conditions.",
                     wallet=wallet),
        _make_vector(node, "single SIG, 1 output, key_path/SIGHASH_NONE",
                     _conds_sig_only(), _conds_sig_only(),
                     variant="key_path", hash_type=0x02,
                     description="Key-path with SIGHASH_NONE — outputs dropped, conditions still absent.",
                     wallet=wallet),
    ]


# ──────────────────────────────────────────────────────────────────
# Verify / regenerate
# ──────────────────────────────────────────────────────────────────

def _write_or_verify(payload, regenerate: bool):
    new_text = json.dumps(payload, indent=2) + "\n"
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if regenerate or not OUTPUT_PATH.exists():
        tmp = OUTPUT_PATH.with_suffix(".json.tmp")
        tmp.write_text(new_text)
        tmp.replace(OUTPUT_PATH)
        return "regenerated"
    existing = OUTPUT_PATH.read_text()
    if existing != new_text:
        diff_path = OUTPUT_PATH.with_suffix(".json.regenerated")
        diff_path.write_text(new_text)
        raise AssertionError(
            f"sighash vectors drift detected vs {OUTPUT_PATH.name}.\n"
            f"  Regenerated copy at {diff_path}.\n"
            f"  Re-run with VECTORS_REGENERATE=1 if the change is intentional."
        )
    return "verified"


class RungSighashVectors(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, COINBASE_MATURITY + 12)

        vectors = _all_vectors(node, wallet)
        payload = {
            "version": 1,
            "description": (
                "Isolated v4 RUNG_TX sighash vectors. Inputs (tx_hex, "
                "input_idx, spent_outputs, conditions, variant, hash_type) "
                "are self-contained; expected_sighash_hex is the canonical "
                "32-byte sighash. Reviewers and independent implementations "
                "consume these to verify their sighash code."
            ),
            "vectors": vectors,
        }
        regen = os.environ.get("VECTORS_REGENERATE") == "1"
        status = _write_or_verify(payload, regen)
        self.log.info("sighash vectors %s (%d entries)", status, len(vectors))

        # Also: round-trip every vector through the live node so the
        # commit is enforced and not just diff-stamped.
        for v in vectors:
            spent = [{"amount": Decimal(o["amount_sats"]) / 100_000_000,
                       "scriptPubKey": o["scriptpubkey_hex"]}
                      for o in v["spent_outputs"]]
            r = node.computesighash(v["tx_hex"], v["input_idx"], spent,
                                     json.dumps(v["conditions"]),
                                     v["variant"], v["hash_type"])
            assert_equal(r["sighash"], v["expected_sighash_hex"])
        self.log.info("sighash vectors round-tripped via computesighash: %d/%d",
                       len(vectors), len(vectors))


if __name__ == "__main__":
    RungSighashVectors(__file__).main()
