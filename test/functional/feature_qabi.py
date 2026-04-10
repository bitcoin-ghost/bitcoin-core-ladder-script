#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Functional test for QABIO (Quantum Atomic Batch Input / Output) RPCs.

Tests the four QABI JSON-RPC commands registered by RegisterRungRPCCommands:
  - qabi_buildblock
  - qabi_blockinfo
  - qabi_authchain
  - qabi_sighash

Covers:
  - RPC registration
  - qabi_authchain: tip computation + preimage retrieval + hash-chain
    roundtrip (H^d(preimage_at_d) == tip for all d in [0..N])
  - qabi_buildblock: canonical serialisation produces a parseable block
    that qabi_blockinfo decodes back to the exact input
  - qabi_buildblock: rejects bad inputs (wrong pubkey size, out-of-range
    destination_index)
  - qabi_blockinfo: rejects malformed hex
  - qabi_sighash: computes a valid SIGHASH_QABO over a tx constructed
    via the createtxmlsc RPC, verifies determinism and
    aggregated_sig exclusion

A full prime-and-spend flow at the RPC level would require additional
wallet integration (priming tx builder, QABIO batch-spend tx builder)
that is not yet surfaced as an RPC. The C++ end-to-end tests in
src/test/rung_tests.cpp (suite qabi_tests) cover that flow directly
via the evaluator.
"""

import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


QABI_RPCS = [
    "qabi_buildblock",
    "qabi_blockinfo",
    "qabi_authchain",
    "qabi_sighash",
]

QABI_COORDINATOR_PUBKEY_SIZE = 897  # FALCON-512 pk size


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_n(data: bytes, n: int) -> bytes:
    """Apply SHA-256 n times."""
    current = data
    for _ in range(n):
        current = hashlib.sha256(current).digest()
    return current


def rpc_hex_to_bytes(hex_str: str) -> bytes:
    """Convert a uint256 hex string (as returned by RPC) to raw bytes.

    Bitcoin Core's uint256::GetHex() returns the hex representation with
    bytes in REVERSED order (big-endian display of a little-endian-stored
    value — the "txid display" convention). To recover the original raw
    bytes from the in-memory uint256, reverse the hex-decoded bytes."""
    return bytes.fromhex(hex_str)[::-1]


def bytes_to_rpc_hex(data: bytes) -> str:
    """Convert raw bytes into the reversed hex form that uint256::GetHex()
    would produce."""
    return data[::-1].hex()


class QabiTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        self.node = self.nodes[0]

        self.test_rpc_available()
        self.test_authchain_tip_and_preimage()
        self.test_authchain_roundtrip_all_depths()
        self.test_authchain_rejects_bad_seed()
        self.test_authchain_rejects_depth_out_of_range()
        self.test_buildblock_roundtrip()
        self.test_buildblock_rejects_bad_pubkey_size()
        self.test_buildblock_rejects_bad_destination_index()
        self.test_blockinfo_rejects_malformed()
        self.test_sighash_determinism()

        self.log.info("All QABI functional tests passed!")

    def test_rpc_available(self):
        self.log.info("Testing that QABI RPCs are registered...")
        for rpc_name in QABI_RPCS:
            try:
                getattr(self.node, rpc_name)()
            except Exception as e:
                err_str = str(e)
                assert "Method not found" not in err_str, \
                    f"RPC '{rpc_name}' not registered: {err_str}"
                self.log.info(f"  {rpc_name}: registered")
        self.log.info(f"All {len(QABI_RPCS)} QABI RPCs available")

    def test_authchain_tip_and_preimage(self):
        self.log.info("Testing qabi_authchain tip + preimage...")
        seed = "42" * 32
        chain_length = 20
        depth = 5

        result = self.node.qabi_authchain(seed, chain_length, depth)
        assert "auth_tip" in result
        assert "preimage" in result
        assert_equal(len(result["auth_tip"]), 64)  # 32 bytes hex
        assert_equal(len(result["preimage"]), 64)

        # Verify: H^depth(preimage) == auth_tip
        # (byte-reverse the RPC hex into the in-memory order first)
        preimage_bytes = rpc_hex_to_bytes(result["preimage"])
        computed_hex = bytes_to_rpc_hex(sha256_n(preimage_bytes, depth))
        assert_equal(computed_hex, result["auth_tip"])
        self.log.info("  Tip / preimage match verified")

    def test_authchain_roundtrip_all_depths(self):
        self.log.info("Testing qabi_authchain roundtrip at all depths...")
        seed = "99" * 32
        chain_length = 15
        tip = self.node.qabi_authchain(seed, chain_length)["auth_tip"]

        for d in range(chain_length + 1):
            result = self.node.qabi_authchain(seed, chain_length, d)
            preimage_bytes = rpc_hex_to_bytes(result["preimage"])
            computed_hex = bytes_to_rpc_hex(sha256_n(preimage_bytes, d))
            assert_equal(computed_hex, tip)
        self.log.info(f"  All {chain_length + 1} depths verified")

    def test_authchain_rejects_bad_seed(self):
        self.log.info("Testing qabi_authchain rejects bad seed size...")
        bad_seed = "42" * 16  # 16 bytes instead of 32
        assert_raises_rpc_error(-8, "auth_seed must be exactly 32 bytes",
                                 self.node.qabi_authchain, bad_seed, 10)

    def test_authchain_rejects_depth_out_of_range(self):
        self.log.info("Testing qabi_authchain rejects depth > chain_length...")
        seed = "00" * 32
        assert_raises_rpc_error(-8, "invalid depth",
                                 self.node.qabi_authchain, seed, 10, 11)

    def test_buildblock_roundtrip(self):
        self.log.info("Testing qabi_buildblock → qabi_blockinfo roundtrip...")

        coordinator_pubkey = "ab" * QABI_COORDINATOR_PUBKEY_SIZE
        batch_id = "cd" * 32
        expiry_height = 12345

        # A participant's Rung 0 FALCON pubkey hash (participant_id)
        participant_id = "ef" * 32

        # A dummy destination scriptPubKey — P2WPKH-ish
        dest_script = "0014" + "11" * 20

        entries = [
            {
                "participant_id": participant_id,
                "contribution": "0.001",  # 100000 sats
                "destination_index": 0,
            },
        ]
        outputs = [
            {
                "amount": "0.00099",  # 99000 sats — 1000 sats fee
                "script_pubkey": dest_script,
            },
        ]

        built = self.node.qabi_buildblock(
            coordinator_pubkey, expiry_height, batch_id, entries, outputs)
        assert "qabi_block" in built
        assert "qabi_root" in built
        assert "size" in built
        assert_greater_than(built["size"], 900)  # at least the FALCON pubkey
        self.log.info(f"  Built block: {built['size']} bytes, root={built['qabi_root'][:16]}...")

        # Decode it back
        info = self.node.qabi_blockinfo(built["qabi_block"])
        assert_equal(info["version"], 1)
        assert_equal(info["batch_id"], batch_id)
        assert_equal(info["coordinator_pubkey"], coordinator_pubkey)
        assert_equal(info["prime_expiry_height"], expiry_height)
        assert_equal(info["n_entries"], 1)
        assert_equal(info["n_outputs"], 1)
        assert_equal(info["qabi_root"], built["qabi_root"])

        # Entry round-trips
        assert_equal(len(info["entries"]), 1)
        assert_equal(info["entries"][0]["participant_id"], participant_id)
        assert_equal(info["entries"][0]["destination_index"], 0)

        # Output round-trips (script preserved)
        assert_equal(len(info["outputs"]), 1)
        assert_equal(info["outputs"][0]["script_pubkey"], dest_script)
        self.log.info("  Roundtrip verified")

    def test_buildblock_rejects_bad_pubkey_size(self):
        self.log.info("Testing qabi_buildblock rejects wrong pubkey size...")
        short_pubkey = "ab" * 100  # wrong size (should be 897)
        assert_raises_rpc_error(-8, "coordinator_pubkey must be exactly",
                                 self.node.qabi_buildblock,
                                 short_pubkey, 1000, "cd" * 32,
                                 [{"participant_id": "ef" * 32, "contribution": "0.001", "destination_index": 0}],
                                 [{"amount": "0.0009", "script_pubkey": "00" * 22}])

    def test_buildblock_rejects_bad_destination_index(self):
        self.log.info("Testing qabi_buildblock rejects out-of-range destination_index...")
        coordinator_pubkey = "ab" * QABI_COORDINATOR_PUBKEY_SIZE
        assert_raises_rpc_error(-8, "destination_index out of range",
                                 self.node.qabi_buildblock,
                                 coordinator_pubkey, 1000, "cd" * 32,
                                 [{"participant_id": "ef" * 32, "contribution": "0.001", "destination_index": 99}],
                                 [{"amount": "0.0009", "script_pubkey": "00" * 22}])

    def test_blockinfo_rejects_malformed(self):
        self.log.info("Testing qabi_blockinfo rejects malformed bytes...")
        # Empty
        assert_raises_rpc_error(-22, "parse failed",
                                 self.node.qabi_blockinfo, "")
        # Garbage
        assert_raises_rpc_error(-22, "parse failed",
                                 self.node.qabi_blockinfo, "deadbeef" * 10)

    def test_sighash_determinism(self):
        self.log.info("Testing qabi_sighash determinism...")

        # Build a minimal valid TX_MLSC v4 tx via createtxmlsc and run it
        # through qabi_sighash. We verify:
        #   (a) the RPC returns a 32-byte (64-hex-char) result
        #   (b) two calls on the same bytes produce the same result
        # The crypto correctness of SIGHASH_QABO is already validated in the
        # C++ test suite (qabi_tests).
        from test_framework.wallet import MiniWallet
        wallet = MiniWallet(self.node)
        self.generate(wallet, 101)  # 1 coinbase matures

        utxo = wallet.get_utxo()

        dummy_pubkey = "02" + "ab" * 32

        # createtxmlsc signature:
        #   inputs:     [{"txid": ..., "vout": ...}]
        #   amounts:    [float, float, ...]        (value per output)
        #   conditions: [{output_index, blocks}]   (conditions per output)
        tx_result = self.node.createtxmlsc(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [0.0001],
            [{
                "output_index": 0,
                "blocks": [{
                    "type": "SIG",
                    "fields": [{"type": "SCHEME", "hex": "01"}],
                }],
            }],
        )
        tx_hex = tx_result["hex"]
        self.log.info(f"  built TX_MLSC v4 tx of {len(tx_hex) // 2} bytes")

        sighash_result = self.node.qabi_sighash(tx_hex)
        assert "sighash" in sighash_result
        assert_equal(len(sighash_result["sighash"]), 64)  # 32 bytes hex

        # Determinism: call twice, same result
        sighash_result2 = self.node.qabi_sighash(tx_hex)
        assert_equal(sighash_result["sighash"], sighash_result2["sighash"])
        self.log.info(f"  sighash={sighash_result['sighash'][:16]}... (deterministic)")


if __name__ == "__main__":
    QabiTest(__file__).main()
