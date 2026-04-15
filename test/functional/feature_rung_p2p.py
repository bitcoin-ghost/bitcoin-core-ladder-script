#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two-node P2P propagation tests for v4 (RUNG_TX) Ladder Script transactions.

Covers two paths that the single-node feature_rung_tx.py cannot exercise:

  - Tx-level propagation: a v4 MLSC tx broadcast on node 0 must reach
    node 1's mempool through the standard tx-relay path. Confirms
    SendMessages / GetData / TX message flow handles the TX_MLSC wire
    format end-to-end (no rejection at the deserialise boundary, no
    misclassification as orphan, no relay filtering).

  - Block-level propagation: a block containing a v4 MLSC tx mined on
    node 0 must reach node 1 via the compact block (BIP152) path. The
    HEADERS / CMPCTBLOCK / GETBLOCKTXN / BLOCKTXN reconstruction has to
    handle TX_MLSC's value-only vout layout and witness envelope without
    silently dropping the tx or rejecting the block.

A regression in either path would silently break v4 propagation for
every non-RPC user of the network — the bug would only surface in
production where nodes are exchanging blocks over the wire, not in
the single-node RPC tests."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class RungP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_v4_tx_relay_between_nodes()
        self.test_v4_block_compact_propagation()

        self.log.info("All P2P tests passed!")

    def _build_signed_v4_tx(self, pubkey_hex):
        """Build, sign, and return a serialised v4 MLSC tx hex.
        Uses a freshly-fetched MiniWallet UTXO; caller is responsible for
        ensuring the wallet has a mature coinbase available."""
        utxo = self.wallet.get_utxo()
        create_result = self.nodes[0].createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{
                "amount": Decimal(str(utxo["value"])) - Decimal("0.001"),
                "conditions": [{"blocks": [{"type": "SIG", "fields": [
                    {"type": "SCHEME", "hex": "01"},
                    {"type": "PUBKEY", "hex": pubkey_hex},
                ]}]}],
            }],
        )
        tx = tx_from_hex(create_result["hex"])
        self.wallet.sign_tx(tx)
        return tx.serialize().hex()

    def test_v4_tx_relay_between_nodes(self):
        """Broadcast a v4 MLSC tx on node 0 and verify it reaches node 1's
        mempool through standard P2P tx-relay (INV / GETDATA / TX)."""
        self.log.info("Testing v4 MLSC tx P2P relay (node 0 → node 1)...")

        # Mature coinbases on node 0 so MiniWallet has spendable UTXOs.
        self.generate(self.wallet, COINBASE_MATURITY + 5)

        signed_hex = self._build_signed_v4_tx("02" + "11" * 32)
        txid = self.nodes[0].sendrawtransaction(signed_hex)
        self.log.info(f"  Broadcast on node 0: {txid[:16]}...")

        # Wait for node 1 to see the tx in its mempool.
        self.sync_mempools()
        node1_mempool = self.nodes[1].getrawmempool()
        assert txid in node1_mempool, \
            f"v4 tx must propagate to node 1 mempool, got: {node1_mempool}"
        self.log.info(f"  Node 1 received tx: {txid[:16]}... (mempool size={len(node1_mempool)})")

        # Both nodes should have identical mempools after sync.
        assert_equal(self.nodes[0].getrawmempool(), self.nodes[1].getrawmempool())
        self.log.info("  v4 MLSC tx P2P relay: OK")

    def test_v4_block_compact_propagation(self):
        """Mine a block containing a v4 MLSC tx on node 0 and verify it
        reaches node 1 through the standard block relay path (which uses
        compact blocks / BIP152 by default for connected peers)."""
        self.log.info("Testing v4 MLSC block compact propagation (node 0 → node 1)...")

        # Build and broadcast a fresh v4 tx so we have something to mine.
        signed_hex = self._build_signed_v4_tx("02" + "22" * 32)
        txid = self.nodes[0].sendrawtransaction(signed_hex)
        self.sync_mempools()
        self.log.info(f"  Tx in both mempools: {txid[:16]}...")

        # Mine the block on node 0. After sync, node 1 must have the same tip.
        before_tip_node1 = self.nodes[1].getbestblockhash()
        new_hashes = self.generate(self.nodes[0], 1)
        new_hash = new_hashes[0]
        assert new_hash != before_tip_node1, "node 0 must produce a new tip"

        self.sync_blocks()

        node1_tip = self.nodes[1].getbestblockhash()
        assert_equal(node1_tip, new_hash)
        self.log.info(f"  Node 1 sync'd to new tip: {new_hash[:16]}...")

        # The v4 tx must be in node 1's view of the new block.
        node1_block = self.nodes[1].getblock(new_hash)
        assert txid in node1_block["tx"], \
            f"v4 tx must be in node 1's reconstructed block, got tx={node1_block['tx']}"

        # Cross-check: gettxout on both nodes returns the same MLSC UTXO.
        node0_utxo = self.nodes[0].gettxout(txid, 0)
        node1_utxo = self.nodes[1].gettxout(txid, 0)
        assert node0_utxo is not None and node1_utxo is not None
        assert_equal(node0_utxo["scriptPubKey"]["hex"],
                     node1_utxo["scriptPubKey"]["hex"])
        assert node0_utxo["scriptPubKey"]["hex"].startswith("df"), \
            "Reconstructed UTXO must carry the 0xDF MLSC prefix on both nodes"
        self.log.info(f"  UTXO consistent across nodes: "
                      f"{node0_utxo['scriptPubKey']['hex'][:16]}...")
        self.log.info("  v4 MLSC block compact propagation: OK")


if __name__ == "__main__":
    RungP2PTest(__file__).main()
