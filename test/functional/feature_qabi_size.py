#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""QABIO N-input batch sizing measurement.

Generalises feature_qabi.py:test_mined_batch_spend_regressions to an
arbitrary N. Reports the actual on-chain footprint of a QABI batch
spend lifecycle at N participants:

  - N priming txs (one per participant)
  - 1 batch spend tx (with qabi_block + FALCON-512 aggregated_sig)

Subclasses QABIRPCTest to inherit the priming + sighash + qabi_block
helpers. Skips the parent's run_test and runs only the sized batch.

Run: python3 test/functional/feature_qabi_size.py --counts=3,10
"""

import hashlib
from decimal import Decimal

from feature_qabi import QabiTest, rpc_hex_to_bytes
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.test_framework import SkipTest
from test_framework.wallet import MiniWallet


class QABIBatchSize(QabiTest):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def add_options(self, parser):
        parser.add_argument("--counts", default="3,10",
                            help="Comma-separated batch sizes")

    def run_test(self):
        self.node = self.nodes[0]
        counts = [int(c) for c in self.options.counts.split(",")]
        self.log.info(f"Measuring QABI batch sizes for N={counts}")

        try:
            self.node.generatepqkeypair("FALCON512")
        except Exception as e:
            if "liboqs" in str(e).lower():
                raise SkipTest("requires liboqs")
            raise

        # Mine enough wallet UTXOs: need 1 per QABI initial creation, sequential.
        # Each (initial create + priming) cycle consumes 1 wallet UTXO.
        wallet_utxos_needed = sum(counts)
        self.generate(MiniWallet(self.node), COINBASE_MATURITY + wallet_utxos_needed + 50)

        results = []
        for n in counts:
            self.log.info(f"==== Measuring QABI N={n} ====")
            results.append(self.measure_qabi_batch(n))

        self.log.info("")
        self.log.info("=== QABI batch sizing summary ===")
        self.log.info(f"{'N':>4} | {'priming total':>14} | {'spend tx':>10} | "
                      f"{'lifecycle total':>16} | {'per-input':>10}")
        self.log.info("-" * 72)
        for r in results:
            self.log.info(
                f"{r['n']:>4} | {r['priming_total']:>14} | {r['spend_vsize']:>10} | "
                f"{r['lifecycle_total']:>16} | {r['per_input']:>10.2f}"
            )

    def measure_qabi_batch(self, n):
        wallet = MiniWallet(self.node)

        # Coordinator FALCON keypair.
        kp = self.node.generatepqkeypair("FALCON512")
        coord_pubkey = kp["pubkey"]
        coord_privkey = kp["privkey"]

        # N participants, each with a unique secp256k1 owner key.
        participants = []
        for i in range(n):
            eckey = ECKey()
            eckey.generate()
            pk_bytes = eckey.get_pubkey().get_bytes()
            assert len(pk_bytes) == 33
            # auth_seed unique per participant — derive deterministically.
            seed = hashlib.sha256(f"qabi-stress-{i}".encode()).digest()
            participants.append({
                "pk_hex": pk_bytes.hex(),
                "owner_id_hex": hashlib.sha256(pk_bytes).hexdigest(),
                "auth_seed": seed.hex(),
            })

        # Build template batch tx for the conditions_root binding.
        # Consolidate to ONE output: N participants → 1 sink. Keeps
        # template_rungs at 1 rung (under MAX_RUNGS=16) and matches the
        # PQ_BATCH / SIG(FALCON) comparison topology (N inputs → 1 sink).
        z32 = "00" * 32
        sink_pk_hex = participants[0]["pk_hex"]  # any valid pubkey works as sink owner
        template_rungs = [{
            "output_index": 0,
            "blocks": [{"type": "SIG", "fields": [{"type": "SCHEME", "hex": "01"}]}],
            "pubkeys": [sink_pk_hex],
        }]
        per_input_contribution = Decimal("0.0005")
        per_input_priming_fee = Decimal("0.0001")
        per_input_post_priming = per_input_contribution - per_input_priming_fee
        sink_amount = float(per_input_post_priming * n - Decimal("0.001"))
        batch_amounts = [sink_amount]
        template = self.node.createrungtx(
            [{"txid": z32, "vout": i} for i in range(n)],
            batch_amounts,
            template_rungs,
        )
        template_conditions_root = template["conditions_root"]

        prime_expiry = 99999
        built = self.node.qabi_buildblock(
            coord_pubkey,
            prime_expiry,
            "ab" * 32,
            [{"participant_id": p["owner_id_hex"],
              "contribution": str(per_input_contribution),
              "destination_index": 0}
             for p in participants],
            template_conditions_root,
            [str(Decimal(str(sink_amount)))],
        )
        qabi_block_hex = built["qabi_block"]
        qabi_root_wire = rpc_hex_to_bytes(built["qabi_root"]).hex()
        self.log.info(f"  qabi_block built: {len(qabi_block_hex)//2} B raw")

        # Per-participant: create initial QABI UTXO, prime it, mine.
        primed = []
        priming_vsizes = []
        for i, p in enumerate(participants):
            initial = self._create_and_mine_qabi_utxo(
                wallet, p["auth_seed"], 50,
                owner_id_hex=p["owner_id_hex"],
                sig_pk_compressed_hex=p["pk_hex"],
            )
            primed_conditions_create = self._qabi_conditions_for_createrungtx(
                auth_tip_bytes_hex=initial["auth_tip_bytes_hex"],
                committed_root_hex=qabi_root_wire,
                committed_depth=10,
                committed_expiry=prime_expiry,
                owner_id_hex=p["owner_id_hex"],
                sig_pk_compressed_hex=p["pk_hex"],
            )
            primed_amount = float(initial["value_btc"] - Decimal("0.0001"))
            priming_tx = self.node.createrungtx(
                [{"txid": initial["txid"], "vout": 0}],
                [primed_amount],
                primed_conditions_create,
            )
            priming_signers = [{
                "input": 0,
                "rung": 1,
                "blocks": [{
                    "type": "QABI_PRIME",
                    "new_committed_root": qabi_root_wire,
                    "prime_depth": 10,
                    "new_committed_expiry": prime_expiry,
                    "auth_seed": p["auth_seed"],
                    "chain_length": 50,
                }],
                "conditions": initial["conditions_signrungtx"],
            }]
            spent_for_priming = [{
                "amount": str(initial["value_btc"]),
                "scriptPubKey": initial["scriptPubKey"],
            }]
            signed_priming = self.node.signrungtx(
                priming_tx["hex"], priming_signers, spent_for_priming)
            assert signed_priming["complete"]
            decoded = self.node.decoderawtransaction(signed_priming["hex"])
            priming_vsizes.append(decoded["vsize"])

            txid = self.node.sendrawtransaction(signed_priming["hex"])
            self.generate(self.node, 1)

            primed_out = self.node.gettxout(txid, 0)
            assert primed_out is not None
            primed.append({
                "txid": txid,
                "scriptPubKey": primed_out["scriptPubKey"]["hex"],
                "value_btc": Decimal(str(primed_out["value"])),
                "auth_tip_bytes_hex": initial["auth_tip_bytes_hex"],
            })
            if (i + 1) % 5 == 0 or (i + 1) == n:
                self.log.info(f"    primed {i+1}/{n}")

        priming_total = sum(priming_vsizes)
        self.log.info(f"  priming: {n} tx × ~{priming_vsizes[0]} vB = {priming_total} vB")

        # Build the batch spend tx.
        batch_tx = self.node.createrungtx(
            [{"txid": primed[i]["txid"], "vout": 0} for i in range(n)],
            batch_amounts,
            template_rungs,
            0, "",
            qabi_block_hex,
        )
        batch_unsigned = batch_tx["hex"]

        all_spent = [{"amount": str(primed[i]["value_btc"]),
                      "scriptPubKey": primed[i]["scriptPubKey"]}
                     for i in range(n)]
        all_signers = []
        for i, p in enumerate(participants):
            primed_conditions_sign = self._qabi_conditions_for_signrungtx(
                auth_tip_bytes_hex=primed[i]["auth_tip_bytes_hex"],
                committed_root_hex=qabi_root_wire,
                committed_depth=10,
                committed_expiry=prime_expiry,
                owner_id_hex=p["owner_id_hex"],
                sig_pk_compressed_hex=p["pk_hex"],
            )
            all_signers.append({
                "input": i, "rung": 2,
                "blocks": [{"type": "QABI_SPEND",
                            "auth_seed": p["auth_seed"], "chain_length": 50}],
                "conditions": primed_conditions_sign,
            })
        witnessed = self.node.signrungtx(batch_unsigned, all_signers, all_spent)
        assert witnessed["complete"]

        falcon_signed = self.node.qabi_signqabo(witnessed["hex"], coord_privkey)
        signed_hex = falcon_signed["hex"]
        decoded = self.node.decoderawtransaction(signed_hex)
        spend_vsize = decoded["vsize"]
        spend_weight = decoded["weight"]

        lifecycle_total = priming_total + spend_vsize
        per_input = lifecycle_total / n

        self.log.info(
            f"  N={n}: priming {priming_total} vB + spend {spend_vsize} vB "
            f"(weight {spend_weight} wu) = lifecycle {lifecycle_total} vB "
            f"({per_input:.2f} vB/input)"
        )

        return {
            "n": n,
            "priming_total": priming_total,
            "spend_vsize": spend_vsize,
            "spend_weight": spend_weight,
            "lifecycle_total": lifecycle_total,
            "per_input": per_input,
        }


if __name__ == "__main__":
    QABIBatchSize(__file__).main()
