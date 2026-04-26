#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end functional test for legacy P2* wrapper blocks on regtest.

Exercises the real sign → broadcast → mempool-accept → spend cycle for
the four non-recursive legacy wrappers: P2PK_LEGACY, P2PKH_LEGACY,
P2WPKH_LEGACY, P2TR_LEGACY.

Why this test exists
--------------------
The Ladder boost suite uses `MockSignatureChecker` which ignores the
sighash bytes, so a sig-verification path that routes to Core's
`BaseSignatureChecker` with bad sigversion/execdata will pass every
boost test and only fail the moment a real tx is broadcast — at which
point Core's `CheckSchnorrSignature` asserts and SIGABRTs `bitcoind`.

Commit `83f3a99a25` fixed exactly that: legacy P2* wrapper Schnorr
verify now routes through the Ladder `sig_checker` adapter (same path
`EvalSigBlock` uses) instead of Core's `BaseSignatureChecker`. This
test locks the fix by funding + spending each wrapper; if any future
refactor re-routes through Core's Schnorr check on a non-Taproot tx,
the mempool accept here fails and the daemon's assertion is caught
before merge. Without this test the regression is invisible to CI.
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


# Non-recursive legacy wrappers that route sig verify through the Ladder
# adapter. Each tuple is (block_type, condition_pubkey_only).
#
# condition_pubkey_only=True  → conditions carry PUBKEY (node auto-computes
#                               HASH160). Applies to P2PKH_LEGACY / P2WPKH_LEGACY.
# condition_pubkey_only=False → conditions carry PUBKEY directly (no auto-
#                               commit); applies to P2PK_LEGACY / P2TR_LEGACY.
LEGACY_WRAPPERS = [
    ("P2PK_LEGACY",   False),
    ("P2PKH_LEGACY",  True),
    ("P2WPKH_LEGACY", True),
    ("P2TR_LEGACY",   False),
]


class RungLegacyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.node = self.nodes[0]

        # Fund the wallet so MiniWallet has spendable UTXOs.
        self.generate(self.wallet, COINBASE_MATURITY + len(LEGACY_WRAPPERS) + 4)

        for btype, _ in LEGACY_WRAPPERS:
            self.log.info(f"--- {btype} fund+spend cycle ---")
            self.test_legacy_wrapper_roundtrip(btype)

    def test_legacy_wrapper_roundtrip(self, btype):
        """Fund an MLSC output gated by `btype`, then spend it end-to-end.

        Pre-fix (83f3a99a25^): `sendrawtransaction` during the spend step
        SIGABRTs the daemon. Post-fix: the spend is accepted and mined.
        """
        privkey = ECKey()
        # Different seed per wrapper so the wallet doesn't see reuse.
        seed_byte = {"P2PK_LEGACY": 0x11, "P2PKH_LEGACY": 0x22,
                     "P2WPKH_LEGACY": 0x33, "P2TR_LEGACY": 0x44}[btype]
        privkey.set(bytes([seed_byte]) * 31 + b'\x01', True)
        pubkey_hex = privkey.get_pubkey().get_bytes().hex()
        privkey_wif = bytes_to_wif(privkey.get_bytes(), compressed=True)

        utxo = self.wallet.get_utxo()
        fund_amount = Decimal(str(utxo["value"])) - Decimal("0.001")

        # Fund side: a single rung gated on this legacy wrapper, PUBKEY in
        # conditions. For P2PKH/P2WPKH the node will auto-HASH160 the pubkey.
        fund_blocks = [
            {"type": btype, "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]}
        ]
        fund_conditions = [{"blocks": fund_blocks}]
        create_result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [fund_amount],
            [{"output_index": 0, "blocks": fund_blocks}],
        )
        fund_tx = tx_from_hex(create_result["hex"])
        self.wallet.sign_tx(fund_tx)  # MiniWallet taproot input
        fund_txid = self.node.sendrawtransaction(fund_tx.serialize().hex())
        self.generate(self.node, 1)
        # Pull the real MLSC scriptPubKey — signrungtx uses it as the
        # spent-output script when recomputing the Ladder sighash.
        fund_txout = self.node.gettxout(fund_txid, 0)
        fund_spk_hex = fund_txout["scriptPubKey"]["hex"]
        assert fund_spk_hex.startswith("df"), \
            f"{btype}: funded output should be MLSC, got {fund_spk_hex[:4]}"
        self.log.info(f"  funded: {fund_txid[:16]}... (amount={fund_amount})")

        # Spend side: spend the MLSC output into a fresh MLSC output gated on
        # a plain SIG block (reuse MiniWallet signing is not possible for
        # MLSC inputs, so we drive signrungtx).
        dest_pubkey_hex = ECKey()
        dest_pubkey_hex.set(bytes([seed_byte]) * 31 + b'\x02', True)
        dest_pubkey_hex = dest_pubkey_hex.get_pubkey().get_bytes().hex()
        spend_amount = fund_amount - Decimal("0.001")

        spend_create = self.node.createrungtx(
            [{"txid": fund_txid, "vout": 0}],
            [spend_amount],
            [{"output_index": 0, "blocks": [{"type": "SIG", "fields": [
                {"type": "SCHEME", "hex": "01"},
                {"type": "PUBKEY", "hex": dest_pubkey_hex},
            ]}]}],
        )

        # signrungtx wants the original conditions (what was committed at fund
        # time). For P2PKH/P2WPKH the node recomputed HASH160 on the node side,
        # so conditions contain HASH160 there; but signrungtx accepts the same
        # "PUBKEY in conditions" form we used at fund time and redoes the
        # commit internally.
        signer_block = {"type": btype, "privkey": privkey_wif}
        if btype in ("P2PKH_LEGACY", "P2WPKH_LEGACY"):
            signer_block["pubkey"] = pubkey_hex

        sign_result = self.node.signrungtx(
            spend_create["hex"],
            [{"input": 0, "privkey": privkey_wif,
              "conditions": fund_conditions,
              "blocks": [signer_block]}],
            [{"amount": float(fund_amount), "scriptPubKey": fund_spk_hex}],
        )
        assert_equal(sign_result["complete"], True)
        signed_hex = sign_result["hex"]

        # The crash regression lives on this single line. Pre-fix this call
        # asserts inside Core's CheckSchnorrSignature and SIGABRTs bitcoind,
        # killing the test node and breaking every subsequent RPC. Post-fix
        # it returns a txid cleanly.
        spend_txid = self.node.sendrawtransaction(signed_hex)
        self.generate(self.node, 1)
        self.log.info(f"  spent:  {spend_txid[:16]}... (no daemon abort)")

        # Confirm the spend landed and the original output is gone.
        assert self.node.gettxout(fund_txid, 0) is None, \
            f"{btype}: original MLSC output should be spent"
        assert self.node.gettxout(spend_txid, 0) is not None, \
            f"{btype}: new MLSC output should be in the UTXO set"


if __name__ == '__main__':
    RungLegacyTest(__file__).main()
