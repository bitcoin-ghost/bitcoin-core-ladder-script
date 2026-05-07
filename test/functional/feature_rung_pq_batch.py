#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end coverage for the PQ_BATCH block (wire ID 0x0A03).

The block commits to SHA256(falcon_pubkey). The "anchor" input in a tx
reveals the pubkey + a FALCON signature over the per-input ladder
sighash. Subsequent inputs in the same tx that commit to the same hash
need no PQ witness — they short-circuit through a tx-local cache the
anchor populates. That cache is the v2 evaluator's reason for existing;
v1 made every input carry a full ~666 B FALCON sig.

Six scenarios:
  1. Single-input fund + anchor-witnessed spend.
  2. Two-output batch fund, one anchor + one cache-driven non-anchor spend.
  3. Non-anchor input ordered before the anchor → UNSATISFIED.
  4. Anchor signature corrupted → anchor + non-anchors all fail.
  5. Anchor pubkey doesn't match the committed hash → anchor fails.
  6. Two distinct commits in one tx, each with its own anchor → both pass.
"""

import hashlib
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


FALCON512_PUBKEY_SIZE = 897
FALCON512_SIG_SIZE = 666


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class RungPQBatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.generate(self.wallet, COINBASE_MATURITY + 1)

        # Probe liboqs at runtime (node is up by now). Without FALCON support
        # PQ_BATCH evaluation can't proceed; skip cleanly rather than fail.
        try:
            self.node.generatepqkeypair("FALCON512")
        except Exception as e:
            if "liboqs" in str(e).lower():
                raise SkipTest("PQ_BATCH requires liboqs (FALCON support)")
            raise

        self.test_single_input_anchor()
        self.test_batch_anchor_plus_cache()
        self.test_non_anchor_before_anchor_now_passes()
        self.test_bad_signature_fails_all()
        self.test_wrong_pubkey_fails_anchor()
        self.test_mixed_commits_two_anchors()

        self.log.info("All PQ_BATCH scenarios passed.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _new_falcon(self):
        """Return (pubkey_hex, privkey_hex, commit_hex) for a fresh FALCON-512 key."""
        kp = self.node.generatepqkeypair("FALCON512")
        assert_equal(len(bytes.fromhex(kp["pubkey"])), FALCON512_PUBKEY_SIZE)
        commit = sha256(bytes.fromhex(kp["pubkey"])).hex()
        return kp["pubkey"], kp["privkey"], commit

    def _pq_batch_conditions(self, commit_hex):
        """Conditions JSON for one PQ_BATCH-gated rung."""
        return [{"blocks": [{
            "type": "PQ_BATCH",
            "fields": [{"type": "HASH256", "hex": commit_hex}],
        }]}]

    def _fund_pq_batch(self, commits):
        """Fund one MLSC output per commit, each via its own createrungtx
        call. Returns a list of {txid, vout, amount, spk, commit, conditions}
        dicts. We fund per-commit (rather than multi-vout in one tx) so
        each output's conditions_root is independently determined — the
        wire-format `0xDF + conditions_root` SPK is per-vout, and
        createrungtx requires all vouts in one tx to share the same root."""
        funded = []
        for commit in commits:
            utxo = self.wallet.get_utxo()
            amount_btc = (Decimal(str(utxo["value"])) - Decimal("0.001"))
            amount_btc = amount_btc.quantize(Decimal("0.00000001"))
            result = self.node.createrungtx(
                [{"txid": utxo["txid"], "vout": utxo["vout"]}],
                [amount_btc],
                [{"output_index": 0, "blocks": self._pq_batch_conditions(commit)[0]["blocks"]}],
            )
            tx = tx_from_hex(result["hex"])
            self.wallet.sign_tx(tx)
            txid = self.node.sendrawtransaction(tx.serialize().hex())
            self.generate(self.node, 1)

            txout = self.node.gettxout(txid, 0)
            assert txout is not None, f"funded vout missing for commit {commit[:8]}"
            assert txout["scriptPubKey"]["hex"].startswith("df")
            funded.append({
                "txid": txid,
                "vout": 0,
                "amount": float(txout["value"]),
                "spk": txout["scriptPubKey"]["hex"],
                "commit": commit,
                "conditions": self._pq_batch_conditions(commit),
            })
        return funded

    def _build_spend(self, funded_inputs, sink_amount_btc=None):
        """Create an unsigned spend tx that consumes every entry in
        funded_inputs and sends the residual (minus 0.0005 BTC fee) to
        a single OP_TRUE-style MLSC output gated by the FIRST commit
        (cheapest valid sink — we never spend it)."""
        total_in = sum(Decimal(str(fi["amount"])) for fi in funded_inputs)
        if sink_amount_btc is None:
            sink_amount_btc = total_in - Decimal("0.0005")
        sink_conditions = self._pq_batch_conditions(funded_inputs[0]["commit"])
        result = self.node.createrungtx(
            [{"txid": fi["txid"], "vout": fi["vout"]} for fi in funded_inputs],
            [sink_amount_btc],
            [{"output_index": 0, "blocks": sink_conditions[0]["blocks"]}],
        )
        return result["hex"]

    def _signer_anchor(self, input_idx, funded, pubkey_hex, privkey_hex,
                       *, override_pubkey=None, override_sig_hex=None):
        """Build a signrungtx signer entry for an anchor PQ_BATCH input.
        override_pubkey lets a test inject a hash-mismatched key.
        override_sig_hex lets a test inject a corrupt pre-computed sig."""
        block = {"type": "PQ_BATCH"}
        if override_sig_hex is not None:
            block["pubkey"] = override_pubkey or pubkey_hex
            block["signature"] = override_sig_hex
        else:
            block["scheme"] = "FALCON512"
            block["pq_pubkey"] = override_pubkey or pubkey_hex
            block["pq_privkey"] = privkey_hex
        return {
            "input": input_idx,
            "blocks": [block],
            "conditions": funded["conditions"],
        }

    def _signer_non_anchor(self, input_idx, funded):
        """Signer entry for a non-anchor PQ_BATCH input (no witness fields)."""
        return {
            "input": input_idx,
            "blocks": [{"type": "PQ_BATCH"}],
            "conditions": funded["conditions"],
        }

    def _spent_outputs(self, funded_inputs):
        return [
            {"amount": fi["amount"], "scriptPubKey": fi["spk"]}
            for fi in funded_inputs
        ]

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def test_single_input_anchor(self):
        """1 fund vout, 1 spend input — anchor reveals pubkey + sig."""
        self.log.info("Scenario 1: single-input anchor spend")

        pubkey, privkey, commit = self._new_falcon()
        funded = self._fund_pq_batch([commit])
        unsigned = self._build_spend(funded)

        signed = self.node.signrungtx(
            unsigned,
            [self._signer_anchor(0, funded[0], pubkey, privkey)],
            self._spent_outputs(funded),
        )
        assert_equal(signed["complete"], True)

        spend_txid = self.node.sendrawtransaction(signed["hex"])
        self.generate(self.node, 1)
        assert self.node.gettxout(funded[0]["txid"], 0) is None
        assert self.node.gettxout(spend_txid, 0) is not None
        self.log.info("  Scenario 1: OK")

    def test_batch_anchor_plus_cache(self):
        """2 fund vouts share one commit. Spend tx: input 0 = anchor with
        full witness, input 1 = empty witness, validates from cache."""
        self.log.info("Scenario 2: 2-input batch, cache-driven non-anchor")

        pubkey, privkey, commit = self._new_falcon()
        funded = self._fund_pq_batch([commit, commit])
        unsigned = self._build_spend(funded)

        signers = [
            self._signer_anchor(0, funded[0], pubkey, privkey),
            self._signer_non_anchor(1, funded[1]),
        ]
        signed = self.node.signrungtx(unsigned, signers, self._spent_outputs(funded))
        assert_equal(signed["complete"], True)

        spend_txid = self.node.sendrawtransaction(signed["hex"])
        self.generate(self.node, 1)
        assert self.node.gettxout(funded[0]["txid"], 0) is None
        assert self.node.gettxout(funded[0]["txid"], 1) is None
        assert self.node.gettxout(spend_txid, 0) is not None
        self.log.info("  Scenario 2: OK")

    def test_non_anchor_before_anchor_now_passes(self):
        """AUD-01: anchor at higher index than non-anchor used to fail
        because the per-input cache lookup at input 0 missed before the
        anchor at input 1 wrote the entry. The pre-pass added in the
        AUD-01 fix walks all inputs of the tx and pre-verifies anchors
        regardless of order, so this configuration now passes. Without
        the pre-pass, this would still fail under -par=1 (the per-input
        verifier processes inputs in order and input 0 hits the empty
        cache); with the pre-pass, the cache is warm before any
        per-input verifier runs."""
        self.log.info("Scenario 3: non-anchor ordered before anchor (now accepted post-AUD-01)")

        pubkey, privkey, commit = self._new_falcon()
        funded = self._fund_pq_batch([commit, commit])
        unsigned = self._build_spend(funded)

        signers = [
            self._signer_non_anchor(0, funded[0]),
            self._signer_anchor(1, funded[1], pubkey, privkey),
        ]
        signed = self.node.signrungtx(unsigned, signers, self._spent_outputs(funded))
        assert_equal(signed["complete"], True)

        accept = self.node.testmempoolaccept([signed["hex"]])[0]
        assert accept["allowed"], (
            "anchor-after-non-anchor must now pass thanks to the AUD-01 "
            "pre-pass; got reject=%s" % accept)
        # Confirm end-to-end by mining the tx — this exercises the same
        # pre-pass on the block-validation path under multi-worker -par.
        spend_txid = self.node.sendrawtransaction(signed["hex"])
        self.generate(self.node, 1)
        assert self.node.gettxout(funded[0]["txid"], 0) is None
        assert self.node.gettxout(funded[0]["txid"], 1) is None
        self.log.info("  Scenario 3: OK")

    def test_bad_signature_fails_all(self):
        """Mutate the FALCON sig — anchor verification fails, cache stays
        empty, every input UNSATISFIED."""
        self.log.info("Scenario 4: corrupted anchor signature (must reject)")

        pubkey, privkey, commit = self._new_falcon()
        funded = self._fund_pq_batch([commit, commit])
        unsigned = self._build_spend(funded)

        signed = self.node.signrungtx(
            unsigned,
            [self._signer_anchor(0, funded[0], pubkey, privkey),
             self._signer_non_anchor(1, funded[1])],
            self._spent_outputs(funded),
        )
        signed_tx = tx_from_hex(signed["hex"])
        # PQ_BATCH witness on the anchor packs PUBKEY + SIGNATURE plus the
        # MLSC proof. Flip a byte in the largest stack element — that's the
        # FALCON-512 sig (≤666 B), bigger than the 897 B pubkey only when
        # the pubkey happens to be on the stack with an enclosing length.
        # Both pubkey AND sig flips invalidate the FALCON verify, so either
        # works. Pick the largest to be deterministic.
        wit_stack = signed_tx.wit.vtxinwit[0].scriptWitness.stack
        target = max(range(len(wit_stack)), key=lambda i: len(wit_stack[i]))
        target_ba = bytearray(wit_stack[target])
        target_ba[len(target_ba) // 2] ^= 0xFF
        wit_stack[target] = bytes(target_ba)

        corrupted_hex = signed_tx.serialize().hex()
        accept = self.node.testmempoolaccept([corrupted_hex])[0]
        assert not accept["allowed"], "corrupted anchor sig must reject"
        self.log.info(f"  Scenario 4 reject reason: {accept.get('reject-reason')}")
        self.log.info("  Scenario 4: OK")

    def test_wrong_pubkey_fails_anchor(self):
        """Anchor reveals a pubkey whose SHA256 does NOT match the
        committed hash → anchor fails before sig verification."""
        self.log.info("Scenario 5: pubkey/commit mismatch (must reject)")

        pubkey_a, privkey_a, commit_a = self._new_falcon()
        pubkey_b, _privkey_b, _commit_b = self._new_falcon()  # decoy
        funded = self._fund_pq_batch([commit_a])
        unsigned = self._build_spend(funded)

        # Sign with the WRONG pubkey but the matching privkey would sign
        # over a key whose commit doesn't match — so the anchor's
        # SHA256(pubkey)==commit check fails first.
        signers = [self._signer_anchor(
            0, funded[0], pubkey_a, privkey_a, override_pubkey=pubkey_b
        )]
        signed = self.node.signrungtx(unsigned, signers, self._spent_outputs(funded))
        accept = self.node.testmempoolaccept([signed["hex"]])[0]
        assert not accept["allowed"], "wrong-pubkey anchor must reject"
        self.log.info(f"  Scenario 5 reject reason: {accept.get('reject-reason')}")
        self.log.info("  Scenario 5: OK")

    def test_mixed_commits_two_anchors(self):
        """Two distinct commits in one tx, each input is its own anchor."""
        self.log.info("Scenario 6: mixed commits, two anchors")

        pubkey_a, privkey_a, commit_a = self._new_falcon()
        pubkey_b, privkey_b, commit_b = self._new_falcon()
        funded = self._fund_pq_batch([commit_a, commit_b])
        unsigned = self._build_spend(funded)

        signers = [
            self._signer_anchor(0, funded[0], pubkey_a, privkey_a),
            self._signer_anchor(1, funded[1], pubkey_b, privkey_b),
        ]
        signed = self.node.signrungtx(unsigned, signers, self._spent_outputs(funded))
        assert_equal(signed["complete"], True)

        spend_txid = self.node.sendrawtransaction(signed["hex"])
        self.generate(self.node, 1)
        assert self.node.gettxout(funded[0]["txid"], 0) is None
        assert self.node.gettxout(funded[0]["txid"], 1) is None
        assert self.node.gettxout(spend_txid, 0) is not None
        self.log.info("  Scenario 6: OK")


if __name__ == "__main__":
    RungPQBatchTest(__file__).main()
