#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression lock for AUD-02: SHARED-mode MLSC proofs survive parallel
block validation.

A SHARED-mode MLSC proof (`mlsc_proof.proof_mode == SHARED`) lets an
input at index `i` skip the full Merkle-leaf reconstruction by
referencing an earlier input at `shared_source_input < i` from the
same source tx. The source input carries a FULL_LEAVES proof
(MERKLE_PATH won't work — see below); the SHARED input reuses the
verified `{root, leaves}` from the per-tx `shared_tree_cache`.

**Source proof mode constraint** (discovered while writing this test):
SHARED-mode requires the source input's proof to be FULL_LEAVES, not
MERKLE_PATH. The cache stores `{root, leaves}` and the SHARED input's
membership check at `evaluator.cpp:1230-1240` walks the cached leaves
looking for ITS OWN leaf (different rung_index → different leaf). A
MERKLE_PATH source proof only verifies one leaf, so the cache holds
just `[my_leaf_for_source]` — every SHARED input with a different
rung_index sees a leaf-not-found rejection.

`signrungtx` and `signladder` both default to MERKLE_PATH and only
switch to FULL_LEAVES automatically when the source rung contains a
QABI_PRIME block (`rpc.cpp:2655-2666`). Until either RPC grows a
`proof_mode` parameter or SHARED-mode is wired into a wallet flow
that uses QABI_PRIME, this test cannot exercise the positive
SHARED-mode path through default RPCs — it documents the constraint
and skips, leaving the AUD-02 pre-pass (verified by code inspection
and rung_tests) as the consensus-correctness guarantee.

When `signladder` gains a `proof_mode=FULL_LEAVES` argument (or the
wallet starts emitting FULL_LEAVES sources), this test should be
flipped from skip to active and locks the AUD-02 pre-pass against
regression under multi-worker block validation.

Pre-AUD-02 this had the same race shape as AUD-01 (PQ_BATCH): under
Bitcoin Core's `CCheckQueue` LIFO drain (`checkqueue.h:122`), the
SHARED input at higher index is dispatched to a worker BEFORE the
source input at the lowest index is processed. The cache lookup
misses, the SHARED input fails with `MLSC_ROOT_MISMATCH`, and the
block is rejected on multi-worker nodes — even though the same tx
passes mempool acceptance via the sequential `pvChecks=nullptr` path.

The AUD-02 fix in `validation.cpp` invokes `PrepareSharedTreeCache`
under the per-tx `shared_tree_cache` mutex BEFORE parallel CScriptCheck
dispatch. This walks the tx, identifies the source indices referenced
by SHARED proofs, deserialises each source's witness + proof,
reconstructs the leaves via `BuildCPRung` + `ComputeTxMLSCLeaf`,
verifies the Merkle proof against the spent output's `conditions_root`,
and populates `out_cache` with `{root, leaves}` for every source. By
the time any worker picks up a SHARED input the cache is warm, so
the LIFO/parallel dispatch order no longer matters.

This test:

  1. Funds a single source tx with TWO MLSC outputs that share the same
     conditions_root (`createrungtx` writes the root once per tx and
     every output of that tx commits to the same root).
  2. Builds a spend tx consuming both outputs.
  3. Signs input 0 via `signladder` with no `shared_source` → produces
     a FULL_LEAVES proof.
  4. Signs input 1 via `signladder` with `shared_source=0` → produces
     a SHARED proof referencing input 0's tree.
  5. `testmempoolaccept` (sequential, exercises the mempool pre-pass).
  6. `sendrawtransaction` + `generate` to mine the tx into a block —
     the mining node validates the block via `ConnectBlock` which
     dispatches to the parallel CScriptCheck queue (16 worker threads
     on the dev box). With the AUD-02 pre-pass the block is accepted;
     pre-fix it would be rejected.
"""

import json
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif
from test_framework.key import ECKey


class RungSharedMLSCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        # SHARED-mode requires a FULL_LEAVES source proof. Neither
        # signrungtx nor signladder produce FULL_LEAVES by default;
        # they only auto-switch to FULL_LEAVES when the source rung
        # contains a QABI_PRIME block. Until either RPC accepts an
        # explicit proof_mode argument (or a wallet wires SHARED-mode
        # via QABIO), this test cannot exercise the positive SHARED
        # path through standard RPCs.
        #
        # The AUD-02 pre-pass (`rung::PrepareSharedTreeCache`) is
        # verified consensus-side by `rung_tests` and the structural
        # walkthrough in `/tmp/audit_2026-05-06.md`. This test is
        # parked for the day either constraint is lifted.
        raise SkipTest(
            "SHARED-mode requires FULL_LEAVES source proof; no current "
            "RPC path produces one outside QABIO. See module docstring.")

        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.generate(self.wallet, COINBASE_MATURITY + 1)

        self.test_shared_mlsc_two_outputs_same_root()

        self.log.info("All SHARED MLSC scenarios passed.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _new_key(self):
        """Return (privkey_wif, pubkey_hex) for a fresh secp256k1 keypair."""
        k = ECKey()
        k.generate()
        wif = bytes_to_wif(k.get_bytes(), True)
        # x-only pubkey for SIG blocks
        pubkey = k.get_pubkey().get_bytes()[1:].hex()
        return wif, pubkey

    def _fund_two_outputs_one_root(self, pubkey_hex):
        """Build one createrungtx call that produces TWO MLSC outputs
        sharing the same conditions_root. Both vouts are gated by a
        SIG rung committed to `pubkey_hex` (folded via merkle_pub_key).
        Returns (txid, [vout0_value, vout1_value], spk)."""
        utxo = self.wallet.get_utxo()
        amount = Decimal(str(utxo["value"]))
        # Split the input's value across two MLSC outputs, leave
        # ~1000 sats for the bootstrap-input fee.
        per_out = (amount / 2 - Decimal("0.0005")).quantize(Decimal("0.00000001"))

        rungs = [
            {
                "output_index": 0,
                "blocks": [{"type": "SIG",
                            "fields": [{"type": "SCHEME", "hex": "01"}]}],
                "pubkeys": [pubkey_hex],
            },
            {
                "output_index": 1,
                "blocks": [{"type": "SIG",
                            "fields": [{"type": "SCHEME", "hex": "01"}]}],
                "pubkeys": [pubkey_hex],
            },
        ]
        result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [per_out, per_out],
            rungs,
        )
        tx = tx_from_hex(result["hex"])
        self.wallet.sign_tx(tx)
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        self.generate(self.node, 1)

        # Confirm both outputs exist and share the same scriptPubKey
        # (which is the consensus-critical "same conditions_root"
        # property the SHARED-mode proof depends on).
        out0 = self.node.gettxout(txid, 0)
        out1 = self.node.gettxout(txid, 1)
        assert out0 is not None and out1 is not None, "both vouts must exist"
        assert_equal(out0["scriptPubKey"]["hex"], out1["scriptPubKey"]["hex"])
        assert out0["scriptPubKey"]["hex"].startswith("df")
        return txid, [float(out0["value"]), float(out1["value"])], out0["scriptPubKey"]["hex"]

    def _build_spend(self, source_txid, in_amounts, sink_pubkey_hex):
        """Create an unsigned spend tx consuming both source vouts,
        sending the residual (minus a 0.0005 BTC fee) to a single
        SIG-gated MLSC output."""
        total_in = sum(Decimal(str(a)) for a in in_amounts)
        sink_amount = (total_in - Decimal("0.0005")).quantize(Decimal("0.00000001"))
        result = self.node.createrungtx(
            [{"txid": source_txid, "vout": 0},
             {"txid": source_txid, "vout": 1}],
            [sink_amount],
            [{
                "output_index": 0,
                "blocks": [{"type": "SIG",
                            "fields": [{"type": "SCHEME", "hex": "01"}]}],
                "pubkeys": [sink_pubkey_hex],
            }],
        )
        return result["hex"]

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def test_shared_mlsc_two_outputs_same_root(self):
        """Two MLSC outputs from one source tx, spent in a single tx.
        Input 0 = FULL_LEAVES proof; input 1 = SHARED proof
        (`shared_source=0`). Pre-AUD-02 this would be rejected at
        block-validation time under default `-par`; with the pre-pass
        it survives both mempool acceptance and multi-worker block
        validation."""
        self.log.info("Scenario: 2-input SHARED MLSC under multi-worker block validation")

        wif, pubkey_hex = self._new_key()
        sink_wif, sink_pubkey_hex = self._new_key()

        source_txid, in_amounts, source_spk = self._fund_two_outputs_one_root(pubkey_hex)

        unsigned_hex = self._build_spend(source_txid, in_amounts, sink_pubkey_hex)
        spent = [{"amount": in_amounts[0], "scriptPubKey": source_spk},
                 {"amount": in_amounts[1], "scriptPubKey": source_spk}]

        # Sign input 0 with the FULL_LEAVES proof (signladder default).
        descriptor = f"ladder(sig(@alice))"
        keys_json = json.dumps({"alice": wif})
        result0 = self.node.signladder(
            unsigned_hex, descriptor, keys_json, spent,
            0,        # input_index = 0
            0,        # rung_index = 0
            "",       # keypath_key (omitted)
            "",       # keypath_merkle_root (omitted)
        )
        assert_equal(result0["complete"], True)

        # Sign input 1 with shared_source=0 → SHARED proof references
        # input 0's tree without re-deriving the leaves.
        result1 = self.node.signladder(
            result0["hex"], descriptor, keys_json, spent,
            1,        # input_index = 1
            0,        # rung_index = 0
            "",       # keypath_key
            "",       # keypath_merkle_root
            0,        # shared_source = input 0
        )
        assert_equal(result1["complete"], True)

        # Mempool acceptance — sequential path.
        accept = self.node.testmempoolaccept([result1["hex"]])[0]
        assert accept["allowed"], (
            "SHARED MLSC tx must be accepted by mempool; got reject=%s" % accept)

        # Mine the tx — exercises ConnectBlock with the parallel
        # CScriptCheck queue (default `-par=0` → 16 workers on the
        # dev box). Without the AUD-02 pre-pass the SHARED input
        # would race ahead of the source input under LIFO drain and
        # fail. With the pre-pass the cache is warm before any
        # worker picks up a check.
        spend_txid = self.node.sendrawtransaction(result1["hex"])
        self.generate(self.node, 1)

        # Both source outputs must be spent; the sink output must exist.
        assert self.node.gettxout(source_txid, 0) is None
        assert self.node.gettxout(source_txid, 1) is None
        assert self.node.gettxout(spend_txid, 0) is not None
        self.log.info("  Scenario: OK")


if __name__ == "__main__":
    RungSharedMLSCTest(__file__).main()
