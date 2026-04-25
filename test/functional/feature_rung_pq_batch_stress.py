#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""PQ_BATCH stress / sizing test.

Funds N UTXOs sharing one FALCON-512 commit, builds a single spend tx
that consumes all of them (input 0 = anchor with full witness, inputs
1..N-1 = empty PQ_BATCH witness, all validating from the tx-local
cache), and prints the actual measured tx size in vB.

Reports for each N:
  - total tx weight (wu) and vsize (vB)
  - amortised vB per input
  - baseline cost if every input carried its own FALCON-512 sig
  - savings ratio

Not part of the standard test suite — long-running. Run directly:
  python3 test/functional/feature_rung_pq_batch_stress.py

Override input counts: --counts=10,100,500
"""

import argparse
import hashlib
import sys
import time
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.wallet import MiniWallet


FALCON512_BASELINE_VB_PER_INPUT = 433  # 41 vB base + ~392 vB witness (897+666+~4 B, ÷4 segwit)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class RungPQBatchStressTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument(
            "--counts", default="10,100,500",
            help="Comma-separated list of input counts to measure")
        parser.add_argument(
            "--modes", default="pq_batch",
            help="Comma-separated modes: pq_batch, sig_falcon")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        counts = [int(c) for c in self.options.counts.split(",")]
        modes = [m.strip() for m in self.options.modes.split(",")]
        for m in modes:
            if m not in ("pq_batch", "sig_falcon"):
                raise ValueError(f"unknown mode: {m}")

        # Need 1 wallet UTXO per fund tx, summed across all (mode, count) cells.
        cells = sum(counts) * len(modes)
        total_blocks_needed = COINBASE_MATURITY + cells + len(counts) * len(modes) + 50
        self.log.info(f"Mining {total_blocks_needed} blocks for {cells} fund UTXOs "
                      f"(modes={modes}, counts={counts})")
        self.generate(self.wallet, total_blocks_needed)

        try:
            self.node.generatepqkeypair("FALCON512")
        except Exception as e:
            if "liboqs" in str(e).lower():
                raise SkipTest("requires liboqs (FALCON support)")
            raise

        results = []
        for mode in modes:
            for n in counts:
                self.log.info(f"==== Measuring mode={mode} N={n} ====")
                if mode == "pq_batch":
                    r = self.measure_batch(n)
                elif mode == "sig_falcon":
                    r = self.measure_sig_falcon(n)
                r["mode"] = mode
                results.append(r)

        self.log.info("")
        self.log.info("=== SUMMARY ===")
        self.log.info(f"{'mode':>11} | {'N':>5} | {'tx vB':>8} | {'vB/input':>10} | "
                      f"{'savings vs baseline':>20}")
        self.log.info("-" * 70)
        for r in results:
            self.log.info(
                f"{r['mode']:>11} | {r['n']:>5} | {r['vsize']:>8} | {r['per_input']:>10.2f} | "
                f"{r['savings']:>19.2f}x"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _new_falcon(self):
        kp = self.node.generatepqkeypair("FALCON512")
        commit = sha256(bytes.fromhex(kp["pubkey"])).hex()
        return kp["pubkey"], kp["privkey"], commit

    def _pq_batch_conditions(self, commit_hex):
        return [{"blocks": [{
            "type": "PQ_BATCH",
            "fields": [{"type": "HASH256", "hex": commit_hex}],
        }]}]

    def _fund_one(self, commit):
        """Fund a single PQ_BATCH UTXO sharing the given commit. Returns
        the funded {txid, vout, amount, spk, conditions} dict. Mines a
        single block to confirm so the UTXO is spendable in subsequent
        calls."""
        utxo = self.wallet.get_utxo()
        amount_btc = (Decimal(str(utxo["value"])) - Decimal("0.001"))
        amount_btc = amount_btc.quantize(Decimal("0.00000001"))
        result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{"amount": amount_btc, "conditions": self._pq_batch_conditions(commit)}],
        )
        tx = tx_from_hex(result["hex"])
        self.wallet.sign_tx(tx)
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        return {
            "txid": txid,
            "vout": 0,
            "amount_btc": float(amount_btc),
            "amount_sats": int(amount_btc * Decimal("100000000")),
        }

    def _fund_n(self, commit, n, spk):
        """Fund n UTXOs sequentially, batching block generation to keep
        wall time down. mempool can hold all the fund txs simultaneously,
        then one batch generate() confirms them."""
        funded = []
        t0 = time.time()
        for i in range(n):
            funded.append(self._fund_one(commit))
            # Confirm in batches of 50 to bound mempool size and progress logs.
            if (i + 1) % 50 == 0 or (i + 1) == n:
                self.generate(self.node, 1)
                self.log.info(f"  funded {i+1}/{n} ({time.time()-t0:.1f}s elapsed)")
        # Each funded entry needs spk + conditions; backfill from gettxout.
        for entry in funded:
            txout = self.node.gettxout(entry["txid"], 0)
            assert txout is not None
            entry["spk"] = txout["scriptPubKey"]["hex"]
            entry["amount"] = float(txout["value"])
        return funded

    def measure_batch(self, n):
        pubkey, privkey, commit = self._new_falcon()

        # Stash the SPK/conditions once — all UTXOs share them.
        conditions = self._pq_batch_conditions(commit)
        funded = self._fund_n(commit, n, spk=None)

        total_in = sum(Decimal(str(f["amount"])) for f in funded)
        # Drain to a single sink output (cheapest valid sink: gated by the
        # same commit so we can reuse the conditions object).
        sink_amount_btc = total_in - Decimal("0.001") * n  # generous fee
        sink_amount_btc = sink_amount_btc.quantize(Decimal("0.00000001"))

        self.log.info(f"  building unsigned spend tx (n={n})...")
        unsigned = self.node.createrungtx(
            [{"txid": f["txid"], "vout": f["vout"]} for f in funded],
            [{"amount": sink_amount_btc, "conditions": conditions}],
        )["hex"]

        # input 0 = anchor, inputs 1..n-1 = non-anchor.
        signers = [{
            "input": 0,
            "blocks": [{"type": "PQ_BATCH", "scheme": "FALCON512",
                        "pq_pubkey": pubkey, "pq_privkey": privkey}],
            "conditions": conditions,
        }]
        for i in range(1, n):
            signers.append({
                "input": i,
                "blocks": [{"type": "PQ_BATCH"}],
                "conditions": conditions,
            })

        spent_outputs = [{"amount": f["amount"], "scriptPubKey": f["spk"]}
                         for f in funded]

        self.log.info(f"  signing (1 anchor + {n-1} non-anchor)...")
        t_sign = time.time()
        signed = self.node.signrungtx(unsigned, signers, spent_outputs)
        sign_secs = time.time() - t_sign
        assert signed["complete"], f"signrungtx incomplete for N={n}"

        signed_hex = signed["hex"]
        signed_bytes = len(signed_hex) // 2

        # Decode for size analysis (vsize = ceil(weight/4)).
        decoded = self.node.decoderawtransaction(signed_hex)
        vsize = decoded["vsize"]
        weight = decoded["weight"]

        # Test that the consensus path actually accepts it.
        self.log.info(f"  testmempoolaccept...")
        t_acc = time.time()
        accept = self.node.testmempoolaccept([signed_hex])[0]
        acc_secs = time.time() - t_acc

        per_input = vsize / n
        baseline = n * FALCON512_BASELINE_VB_PER_INPUT
        savings = baseline / vsize

        self.log.info(
            f"  N={n}: serialised={signed_bytes} B, weight={weight} wu, vsize={vsize} vB | "
            f"per-input {per_input:.2f} vB | sign {sign_secs:.1f}s, accept-check {acc_secs:.2f}s | "
            f"accepted={accept['allowed']}"
            + ("" if accept["allowed"] else f" reject={accept.get('reject-reason')}")
        )

        # Actually broadcast + mine to validate end-to-end (not just policy).
        if accept["allowed"]:
            spend_txid = self.node.sendrawtransaction(signed_hex)
            self.generate(self.node, 1)
            assert self.node.gettxout(funded[0]["txid"], 0) is None, \
                f"first funded UTXO should be spent (N={n})"
            assert self.node.gettxout(spend_txid, 0) is not None, \
                f"spend output should be in UTXO set (N={n})"

        return {
            "n": n,
            "vsize": vsize,
            "weight": weight,
            "per_input": per_input,
            "baseline": baseline,
            "savings": savings,
            "accepted": accept["allowed"],
            "sign_secs": sign_secs,
        }


    # ------------------------------------------------------------------
    # SIG(FALCON-512) baseline — no batching, one full FALCON sig per input
    # ------------------------------------------------------------------

    def _sig_falcon_conditions(self):
        # SIG conditions with PUBKEY folded into the Merkle leaf (merkle_pub_key);
        # only SCHEME stays in the conditions field array. Fund-time path uses
        # the PUBKEY field but the library strips it into the leaf.
        return None  # built per-key in _fund_one_sig_falcon

    def _fund_one_sig_falcon(self, pubkey_hex):
        """Fund a single SIG(FALCON-512) UTXO. The pubkey is folded into the
        Merkle leaf at fund time — conditions emit SCHEME(0x10) only."""
        utxo = self.wallet.get_utxo()
        amount_btc = (Decimal(str(utxo["value"])) - Decimal("0.001"))
        amount_btc = amount_btc.quantize(Decimal("0.00000001"))
        result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{"amount": amount_btc, "conditions": [{"blocks": [{
                "type": "SIG",
                "fields": [
                    {"type": "SCHEME", "hex": "10"},  # FALCON-512
                    {"type": "PUBKEY", "hex": pubkey_hex},
                ],
            }]}]}],
        )
        tx = tx_from_hex(result["hex"])
        self.wallet.sign_tx(tx)
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        return {
            "txid": txid,
            "vout": 0,
            "amount_btc": float(amount_btc),
        }

    def measure_sig_falcon(self, n):
        """Fund N independent SIG(FALCON-512) UTXOs each with its own keypair,
        spend them in one tx, measure size. This is the no-amortisation baseline:
        every input carries its own ~666-byte FALCON sig + ~897-byte pubkey."""
        keypairs = []
        funded = []
        t0 = time.time()
        for i in range(n):
            kp = self.node.generatepqkeypair("FALCON512")
            keypairs.append(kp)
            funded.append(self._fund_one_sig_falcon(kp["pubkey"]))
            if (i + 1) % 50 == 0 or (i + 1) == n:
                self.generate(self.node, 1)
                self.log.info(f"  funded {i+1}/{n} ({time.time()-t0:.1f}s elapsed)")
        for entry in funded:
            txout = self.node.gettxout(entry["txid"], 0)
            assert txout is not None
            entry["spk"] = txout["scriptPubKey"]["hex"]
            entry["amount"] = float(txout["value"])

        # Sink: cheapest valid MLSC output. Reuse the first keypair's pubkey
        # for the sink conditions (it's never spent, just needs to be valid).
        sink_conditions = [{"blocks": [{
            "type": "SIG",
            "fields": [
                {"type": "SCHEME", "hex": "10"},
                {"type": "PUBKEY", "hex": keypairs[0]["pubkey"]},
            ],
        }]}]
        total_in = sum(Decimal(str(f["amount"])) for f in funded)
        sink_amount_btc = (total_in - Decimal("0.001") * n).quantize(Decimal("0.00000001"))

        self.log.info(f"  building unsigned spend (n={n}, no batching)...")
        unsigned = self.node.createrungtx(
            [{"txid": f["txid"], "vout": f["vout"]} for f in funded],
            [{"amount": sink_amount_btc, "conditions": sink_conditions}],
        )["hex"]

        signers = []
        for i in range(n):
            kp = keypairs[i]
            signers.append({
                "input": i,
                "blocks": [{
                    "type": "SIG",
                    "scheme": "FALCON512",
                    "pq_pubkey": kp["pubkey"],
                    "pq_privkey": kp["privkey"],
                }],
                "conditions": [{"blocks": [{
                    "type": "SIG",
                    "fields": [
                        {"type": "SCHEME", "hex": "10"},
                        {"type": "PUBKEY", "hex": kp["pubkey"]},
                    ],
                }]}],
            })

        spent_outputs = [{"amount": f["amount"], "scriptPubKey": f["spk"]}
                         for f in funded]

        self.log.info(f"  signing ({n} independent FALCON sigs)...")
        t_sign = time.time()
        signed = self.node.signrungtx(unsigned, signers, spent_outputs)
        sign_secs = time.time() - t_sign
        assert signed["complete"], f"signrungtx incomplete for SIG(FALCON) N={n}"

        signed_hex = signed["hex"]
        decoded = self.node.decoderawtransaction(signed_hex)
        vsize = decoded["vsize"]
        weight = decoded["weight"]

        self.log.info(f"  testmempoolaccept...")
        t_acc = time.time()
        accept = self.node.testmempoolaccept([signed_hex])[0]
        acc_secs = time.time() - t_acc

        per_input = vsize / n
        # "Baseline" here is itself — savings is 1.0×; report against
        # PQ_BATCH equivalent for context.
        baseline = n * FALCON512_BASELINE_VB_PER_INPUT
        savings = baseline / vsize  # ~1.0× by construction

        self.log.info(
            f"  SIG(FALCON) N={n}: serialised={len(signed_hex)//2} B, weight={weight} wu, "
            f"vsize={vsize} vB | per-input {per_input:.2f} vB | sign {sign_secs:.1f}s, "
            f"accept-check {acc_secs:.2f}s | accepted={accept['allowed']}"
            + ("" if accept["allowed"] else f" reject={accept.get('reject-reason')}")
        )

        if accept["allowed"]:
            self.node.sendrawtransaction(signed_hex)
            self.generate(self.node, 1)

        return {
            "n": n, "vsize": vsize, "weight": weight, "per_input": per_input,
            "baseline": baseline, "savings": savings, "accepted": accept["allowed"],
            "sign_secs": sign_secs,
        }


if __name__ == "__main__":
    RungPQBatchStressTest(__file__).main()
