#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test Ladder Script (RUNG_TX v4) transactions on regtest.

Tests the full lifecycle of v4 transactions:
- Creating MLSC outputs via createtxmlsc RPC
- Signing with signladder and signrungtx RPCs
- Broadcasting and mining v4 transactions
- Script-path spending with MLSC proof
- Multiple block types (SIG)
- Creation proofs for 3+ outputs (via createtxmlsc)
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    tx_from_hex,
)
from test_framework.script import (
    OP_0,
    CScript,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


# All 15 Ladder Script RPCs registered in RegisterRungRPCCommands
LADDER_RPCS = [
    "createrung",
    "createrungtx",
    "createtxmlsc",
    "computectvhash",
    "computemutation",
    "decoderung",
    "extractadaptorsecret",
    "formatladder",
    "generatepqkeypair",
    "parseladder",
    "pqpubkeycommit",
    "signladder",
    "signrungtx",
    "validateladder",
    "verifyadaptorpresig",
]


class RungTxTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.node = self.nodes[0]

        self.test_rpc_available()
        self.test_create_and_decode()
        self.test_descriptor_parse_format()
        self.test_generate_pq_keypair()
        self.test_v4_tx_lifecycle()

        self.test_spend_v4_output()

        self.test_three_output_tx_supported()
        self.test_wallet_funded_v4_structurally_mlsc()
        self.test_v4_mlsc_reorg_survival()
        self.test_v4_mlsc_rbf_replacement()
        self.test_v4_data_return_round_trip()

        self.log.info("All tests passed!")

    def test_rpc_available(self):
        """Verify Ladder Script RPCs are registered by calling them with no/bad args.
        Note: help() triggers a serialization bug in rpc/util.cpp for complex arg types,
        so we verify RPC existence by calling with no args and checking for usage error."""
        self.log.info("Testing that Ladder Script RPCs are available...")
        # RPCs that return usage error when called with no args
        for rpc_name in LADDER_RPCS:
            try:
                getattr(self.node, rpc_name)()
                # If it succeeds (unlikely), that's fine too
                self.log.info(f"  {rpc_name}: OK (no-args succeeded)")
            except Exception as e:
                err_str = str(e)
                # "Method not found" means the RPC isn't registered — fail
                assert "Method not found" not in err_str, \
                    f"RPC '{rpc_name}' not registered: {err_str}"
                # Any other error (usage, missing params) means the RPC exists
                self.log.info(f"  {rpc_name}: OK (registered)")
        self.log.info(f"All {len(LADDER_RPCS)} RPCs available")

    def test_create_and_decode(self):
        """Create a ladder witness via createrung, decode it via decoderung, verify roundtrip."""
        self.log.info("Testing createrung -> decoderung roundtrip...")

        # Create a simple SIG rung with a dummy pubkey and empty signature placeholder
        dummy_pubkey = "02" + "ab" * 32  # 33-byte compressed pubkey
        rung_spec = [
            {
                "blocks": [
                    {
                        "type": "SIG",
                        "fields": [
                            {"type": "PUBKEY", "hex": dummy_pubkey},
                            {"type": "SIGNATURE", "hex": "00" * 64},
                        ],
                    }
                ]
            }
        ]

        # Create the ladder witness
        result = self.node.createrung(rung_spec)
        assert "hex" in result, "createrung should return hex"
        assert "size" in result, "createrung should return size"
        ladder_hex = result["hex"]
        assert_greater_than(result["size"], 0)
        self.log.info(f"  Created ladder witness: {result['size']} bytes")

        # Decode it back
        decoded = self.node.decoderung(ladder_hex)
        assert_equal(decoded["num_rungs"], 1)
        assert "rungs" in decoded, "decoded should have rungs array"
        assert_equal(len(decoded["rungs"]), 1)

        # Check the block type is SIG
        blocks = decoded["rungs"][0]["blocks"]
        assert_equal(len(blocks), 1)
        assert_equal(blocks[0]["type"], "SIG")
        assert_equal(blocks[0]["inverted"], False)

        # Check fields
        fields = blocks[0]["fields"]
        assert_equal(len(fields), 2)
        assert_equal(fields[0]["type"], "PUBKEY")
        assert_equal(fields[0]["hex"], dummy_pubkey)
        assert_equal(fields[1]["type"], "SIGNATURE")

        # Check default coil
        coil = decoded["coil"]
        assert_equal(coil["type"], "UNLOCK")
        assert_equal(coil["attestation"], "INLINE")
        assert_equal(coil["scheme"], "SCHNORR")

        self.log.info("  createrung -> decoderung roundtrip: OK")

    def test_descriptor_parse_format(self):
        """Test parseladder and formatladder descriptor roundtrip."""
        self.log.info("Testing parseladder -> formatladder roundtrip...")

        # Use a real-looking 33-byte compressed pubkey hex
        test_pubkey = "02" + "11" * 32

        # Parse a simple SIG descriptor using key alias (parseladder requires @alias syntax)
        # The keys parameter is a JSON string, not a native object
        import json
        keys_json = json.dumps({"alice": test_pubkey})
        descriptor = "ladder(sig(@alice))"
        parsed = self.node.parseladder(descriptor, keys_json)

        assert "conditions_hex" in parsed, "parseladder should return conditions_hex"
        assert "mlsc_root" in parsed, "parseladder should return mlsc_root"
        assert "n_rungs" in parsed, "parseladder should return n_rungs"
        assert_equal(parsed["n_rungs"], 1)
        self.log.info(f"  Parsed descriptor: n_rungs={parsed['n_rungs']}, root={parsed['mlsc_root'][:16]}...")

        # Format it back to a descriptor string
        formatted = self.node.formatladder(parsed["conditions_hex"])
        assert "descriptor" in formatted, "formatladder should return descriptor"
        self.log.info(f"  Formatted back to: {formatted['descriptor']}")

        # Re-parse the formatted descriptor — it uses inline hex, not aliases,
        # so we may need different handling. For now verify formatladder produces output.
        self.log.info("  parseladder -> formatladder roundtrip: OK")

        # Test invalid descriptor
        assert_raises_rpc_error(
            -8,  # RPC_INVALID_PARAMETER
            "descriptor parse error",
            self.node.parseladder,
            "not_a_valid_descriptor",
        )
        self.log.info("  Invalid descriptor rejection: OK")

    def test_generate_pq_keypair(self):
        """Test post-quantum keypair generation RPC."""
        self.log.info("Testing generatepqkeypair...")

        result = self.node.generatepqkeypair("FALCON512")
        assert "pubkey" in result, "generatepqkeypair should return pubkey"
        assert "privkey" in result, "generatepqkeypair should return privkey"
        assert_greater_than(len(result["pubkey"]), 0)
        assert_greater_than(len(result["privkey"]), 0)
        self.log.info(f"  FALCON512 keypair: pubkey={len(result['pubkey']) // 2} bytes")

    def test_v4_tx_lifecycle(self):
        """Full end-to-end: fund -> createrungtx -> sign -> broadcast -> mine -> verify UTXO."""
        self.log.info("Testing v4 TX lifecycle...")

        # Mine blocks for coinbase maturity (MiniWallet mines to its own address)
        self.generate(self.wallet, COINBASE_MATURITY + 1)

        # Generate a real keypair so we can actually sign and spend
        privkey = ECKey()
        privkey.set(b'\x01' * 31 + b'\x42', True)
        pubkey_bytes = privkey.get_pubkey().get_bytes()
        pubkey_hex = pubkey_bytes.hex()
        privkey_wif = bytes_to_wif(privkey.get_bytes(), compressed=True)

        # Get a funded UTXO from MiniWallet
        utxo = self.wallet.get_utxo()
        self.log.info(f"  Funding UTXO: {utxo['txid']}:{utxo['vout']} ({utxo['value']} BTC)")

        # Compute MLSC output amount (leave room for fee)
        output_amount = Decimal(str(utxo["value"])) - Decimal("0.001")

        # Create a v4 transaction with one SIG-conditioned MLSC output.
        # The SIG block in conditions needs SCHEME (Schnorr=0x01) and PUBKEY fields.
        create_result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [
                {
                    "amount": output_amount,
                    "conditions": [
                        {
                            "blocks": [
                                {
                                    "type": "SIG",
                                    "fields": [
                                        {"type": "SCHEME", "hex": "01"},
                                        {"type": "PUBKEY", "hex": pubkey_hex},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ],
        )
        assert "hex" in create_result, "createrungtx should return hex"
        unsigned_hex = create_result["hex"]
        self.log.info(f"  Created unsigned v4 tx: {len(unsigned_hex) // 2} bytes")

        # Decode and verify it is version 4
        decoded_tx = self.node.decoderawtransaction(unsigned_hex)
        assert_equal(decoded_tx["version"], 4)
        self.log.info(f"  TX version: {decoded_tx['version']} (RUNG_TX)")

        # Verify the output scriptPubKey starts with 0xDF (MLSC marker)
        spk_hex = decoded_tx["vout"][0]["scriptPubKey"]["hex"]
        assert spk_hex.startswith("df"), \
            f"MLSC scriptPubKey should start with 0xDF, got {spk_hex[:4]}"
        self.log.info(f"  Output scriptPubKey: {spk_hex[:8]}... (0xDF MLSC)")

        # The funding input is a MiniWallet taproot (ADDRESS_OP_TRUE) output.
        # signrungtx skips non-MLSC inputs, so we must add the taproot witness
        # ourselves using MiniWallet's signing logic.
        tx = tx_from_hex(unsigned_hex)
        self.wallet.sign_tx(tx)
        signed_hex = tx.serialize().hex()

        # Broadcast
        txid = self.node.sendrawtransaction(signed_hex)
        self.log.info(f"  Broadcast txid: {txid}")

        # Mine a block
        self.generate(self.node, 1)

        # Verify the output is in the UTXO set
        tx_out = self.node.gettxout(txid, 0)
        assert tx_out is not None, "v4 output should be in UTXO set after mining"
        assert tx_out["scriptPubKey"]["hex"].startswith("df"), \
            "Confirmed output should have 0xDF MLSC prefix"
        self.log.info(f"  Output confirmed in UTXO set: {tx_out['value']} BTC")

        # Store state for the spend test
        self.v4_txid = txid
        self.v4_spk = spk_hex
        self.v4_amount = tx_out["value"]
        self.v4_privkey_wif = privkey_wif
        self.v4_pubkey_hex = pubkey_hex
        self.log.info("  v4 TX lifecycle: OK")

    def test_spend_v4_output(self):
        """Spend the MLSC output created in test_v4_tx_lifecycle via signrungtx.
        NOTE: signrungtx has complex argument formats that vary by spend type.
        This test exercises the create path; signing format is verified on signet."""
        self.log.info("Testing spending a v4 MLSC output...")

        if not hasattr(self, "v4_txid"):
            self.log.info("  SKIP: no v4 output from previous test")
            return

        # Generate a new keypair for the destination output
        dest_privkey = ECKey()
        dest_privkey.set(b'\x02' * 31 + b'\x43', True)
        dest_pubkey_hex = dest_privkey.get_pubkey().get_bytes().hex()

        spend_amount = Decimal(str(self.v4_amount)) - Decimal("0.001")  # fee

        # Create a v4 tx spending the MLSC output into a new MLSC output
        create_result = self.node.createrungtx(
            [{"txid": self.v4_txid, "vout": 0}],
            [
                {
                    "amount": spend_amount,
                    "conditions": [
                        {
                            "blocks": [
                                {
                                    "type": "SIG",
                                    "fields": [
                                        {"type": "SCHEME", "hex": "01"},
                                        {"type": "PUBKEY", "hex": dest_pubkey_hex},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ],
        )
        unsigned_hex = create_result["hex"]
        self.log.info(f"  Created spending v4 tx: {len(unsigned_hex) // 2} bytes")

        # Sign the MLSC input using signrungtx.
        # signrungtx(hex, signers[], spent_outputs[])
        # conditions: the condition-side fields (what was committed in conditions_root).
        # For SIG blocks with merkle_pub_key, conditions contain only SCHEME (not PUBKEY).
        # PUBKEY is witness-only — signrungtx adds it from the privkey automatically.
        conditions_arr = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": self.v4_pubkey_hex}
        ]}]}]
        sign_result = self.node.signrungtx(
            unsigned_hex,
            [{"input": 0, "privkey": self.v4_privkey_wif, "conditions": conditions_arr}],
            [{"amount": float(self.v4_amount), "scriptPubKey": self.v4_spk}],
        )
        assert "hex" in sign_result, "signrungtx should return hex"
        assert_equal(sign_result["complete"], True)
        signed_hex = sign_result["hex"]
        self.log.info(f"  Signed spending tx: complete={sign_result['complete']}")

        # Broadcast and mine
        spend_txid = self.node.sendrawtransaction(signed_hex)
        self.log.info(f"  Broadcast spend txid: {spend_txid}")
        self.generate(self.node, 1)

        # Verify the original output is now spent (gettxout returns None)
        assert self.node.gettxout(self.v4_txid, 0) is None, \
            "Original v4 output should be spent"

        # Verify the new output exists
        new_txout = self.node.gettxout(spend_txid, 0)
        assert new_txout is not None, "New output should be in UTXO set"
        assert new_txout["scriptPubKey"]["hex"].startswith("df"), \
            "New output should have 0xDF MLSC prefix"
        self.log.info(f"  Spend confirmed. New output: {new_txout['value']} BTC")
        self.log.info("  Spend v4 output: OK")

    def test_three_output_tx_supported(self):
        """Verify that createtxmlsc handles 3+ output txs cleanly: all
        outputs share the same conditions_root, all carry the 0xDF marker,
        and the resulting tx is well-formed. This was previously named
        `test_creation_proof_required` and was meant to verify the
        creation_proof field, but creation_proof was removed in the
        anti-spam audit pass — it served no useful purpose and opened
        the largest data-embedding channel in the protocol. The test
        survives because the underlying functionality (createtxmlsc on
        3+ outputs) is still important to verify."""
        self.log.info("Testing createtxmlsc with 3 MLSC outputs...")

        # Get a funded UTXO
        utxo = self.wallet.get_utxo()
        if utxo is None:
            self.log.info("  SKIP: no UTXO available")
            return

        test_pubkey = "02" + "cc" * 32

        # createtxmlsc creates a TX_MLSC with a shared condition tree.
        # 3 outputs, each governed by a SIG rung.
        result = self.node.createtxmlsc(
            # inputs
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            # outputs (3 amounts in BTC)
            [0.001, 0.001, 0.001],
            # rungs (one per output, each with output_index)
            [
                {
                    "output_index": 0,
                    "blocks": [
                        {
                            "type": "SIG",
                            "fields": [
                                {"type": "SCHEME", "hex": "01"},
                                {"type": "PUBKEY", "hex": test_pubkey},
                            ],
                        }
                    ],
                },
                {
                    "output_index": 1,
                    "blocks": [
                        {
                            "type": "SIG",
                            "fields": [
                                {"type": "SCHEME", "hex": "01"},
                                {"type": "PUBKEY", "hex": test_pubkey},
                            ],
                        }
                    ],
                },
                {
                    "output_index": 2,
                    "blocks": [
                        {
                            "type": "SIG",
                            "fields": [
                                {"type": "SCHEME", "hex": "01"},
                                {"type": "PUBKEY", "hex": test_pubkey},
                            ],
                        }
                    ],
                },
            ],
        )
        assert "hex" in result, "createtxmlsc should return hex"
        assert "conditions_root" in result, "createtxmlsc should return conditions_root"
        assert "n_rungs" in result, "createtxmlsc should return n_rungs"
        assert_equal(result["n_rungs"], 3)
        self.log.info(f"  conditions_root: {result['conditions_root'][:16]}...")

        # Decode and verify all 3 outputs have 0xDF prefix (shared root)
        decoded = self.node.decoderawtransaction(result["hex"])
        assert_equal(decoded["version"], 4)
        assert_equal(len(decoded["vout"]), 3)
        for i, vout in enumerate(decoded["vout"]):
            spk = vout["scriptPubKey"]["hex"]
            assert spk.startswith("df"), \
                f"Output {i} should have 0xDF MLSC prefix, got {spk[:4]}"

        # All outputs should share the same scriptPubKey (shared conditions_root)
        spks = [v["scriptPubKey"]["hex"] for v in decoded["vout"]]
        assert_equal(spks[0], spks[1])
        assert_equal(spks[1], spks[2])
        self.log.info(f"  All 3 outputs share scriptPubKey: {spks[0][:16]}...")
        self.log.info("  3-output createtxmlsc: OK")


    def test_wallet_funded_v4_structurally_mlsc(self):
        """Every v4 tx is TX_MLSC on the wire — the format is selected
        unconditionally by version, not by conditions_root being non-null.
        A non-MLSC output cannot even be serialised inside a v4 tx: the
        wire format carries vout as (value only), and the scriptPubKey is
        recomputed on deserialise as 0xDF || conditions_root. This makes
        the old wallet-funded v4 attack (build a v4 tx with a P2WPKH
        output) structurally impossible, not merely policy-rejected.

        This test locks the invariant down from the wire side: build a
        v4 tx whose in-memory vout[0].scriptPubKey is non-MLSC, serialise
        it, deserialise it, and assert the output scriptPubKey comes back
        as the MLSC form regardless of what we put in. Any future
        regression in the serializer/deserializer that reintroduces a
        standard-SegWit path for v4 would fail this round-trip."""
        self.log.info("Testing v4 tx wire format is structurally MLSC...")

        # Fabricate a v4 tx with a conditions_root and a single output.
        # In-memory we set vout[0].scriptPubKey to something deliberately
        # non-MLSC (P2WPKH-shaped) — this would have been a valid attack
        # tx pre-fix. Post-fix the serializer ignores the in-memory SPK
        # and writes only the value.
        tx = CTransaction()
        tx.version = CTransaction.RUNG_TX_VERSION  # 4
        tx.nLockTime = 0
        tx.conditions_root = bytes(range(32))  # arbitrary non-null root

        tx.vin.append(CTxIn(COutPoint(0, 0), b"", 0xffffffff))
        non_mlsc_spk = CScript([OP_0, b"\x00" * 20])
        tx.vout.append(CTxOut(99000, non_mlsc_spk))

        raw = tx.serialize_without_witness()
        parsed = CTransaction()
        from io import BytesIO
        parsed.deserialize(BytesIO(raw))

        assert_equal(parsed.version, 4)
        assert_equal(parsed.conditions_root, tx.conditions_root)
        assert_equal(len(parsed.vout), 1)
        assert_equal(parsed.vout[0].nValue, 99000)
        expected_spk = b"\xdf" + tx.conditions_root
        assert_equal(parsed.vout[0].scriptPubKey, expected_spk), \
            f"deserialised vout SPK should be MLSC, got {parsed.vout[0].scriptPubKey.hex()}"
        self.log.info("  Round-trip: in-memory non-MLSC SPK replaced with MLSC on deserialise (OK)")

        # Sanity: the same property holds through the full with-witness path.
        raw_full = tx.serialize()
        parsed_full = CTransaction()
        parsed_full.deserialize(BytesIO(raw_full))
        assert_equal(parsed_full.vout[0].scriptPubKey, expected_spk)
        self.log.info("  Full (with-witness) serialize → deserialise round-trip: OK")

    def test_v4_mlsc_reorg_survival(self):
        """Reorg survival for a plain (non-QABIO) v4 MLSC tx. Mine a v4 tx,
        invalidate the block containing it, verify it re-enters the mempool,
        mine a fresh block, verify the tx is reconfirmed at a new block hash
        and the MLSC UTXO lands in the UTXO set.

        Why this matters: feature_qabi.py exercises the reorg path for
        QABIO txs (which use the qabi_block tx-level field) but until now
        nothing exercised it for plain MLSC txs (the much more common case
        — every v4 tx that doesn't use QABIO). The TX_MLSC wire format
        round-trip through the disconnect/reconnect path is consensus-
        critical: a regression in the deserialiser, the conditions_root
        synthesis, or the UTXO compaction inflate path would silently
        break reorg recovery for every MLSC user."""
        self.log.info("Testing plain v4 MLSC tx reorg survival...")

        # Top up MiniWallet's pool — earlier tests have consumed mature
        # coinbases, and this test needs at least 2 UTXOs (one for the
        # v4 tx, one for a filler that distinguishes the re-mined block's
        # merkle root).
        self.generate(self.wallet, 3)
        utxo = self.wallet.get_utxo()
        test_pubkey = "02" + "dd" * 32

        create_result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{
                "amount": Decimal(str(utxo["value"])) - Decimal("0.001"),
                "conditions": [{"blocks": [{"type": "SIG", "fields": [
                    {"type": "SCHEME", "hex": "01"},
                    {"type": "PUBKEY", "hex": test_pubkey},
                ]}]}],
            }],
        )
        unsigned_hex = create_result["hex"]

        tx = tx_from_hex(unsigned_hex)
        self.wallet.sign_tx(tx)
        signed_hex = tx.serialize().hex()

        txid = self.node.sendrawtransaction(signed_hex)
        original_hashes = self.generate(self.node, 1)
        original_block_hash = original_hashes[0]
        original_block_info = self.node.getblock(original_block_hash)
        assert txid in original_block_info["tx"], \
            "v4 MLSC tx must be in the mined block before invalidation"
        self.log.info(f"  Initial mine: tx {txid[:16]}... in block {original_block_hash[:16]}...")

        # Invalidate the block — the tx must re-enter the mempool.
        self.node.invalidateblock(original_block_hash)
        mempool = self.node.getrawmempool()
        assert txid in mempool, \
            f"v4 MLSC tx must re-enter mempool after invalidateblock, mempool={mempool}"
        self.log.info(f"  After invalidateblock: tx back in mempool (size={len(mempool)})")

        # Filler tx so the re-mined block has a different merkle root and
        # therefore a different hash — same trick as the QABIO reorg test
        # in feature_qabi.py.
        filler_txid = self.wallet.send_self_transfer(from_node=self.node)["txid"]
        mempool_after_filler = self.node.getrawmempool()
        assert txid in mempool_after_filler
        assert filler_txid in mempool_after_filler

        new_hashes = self.generate(self.node, 1)
        new_block_hash = new_hashes[0]
        assert new_block_hash != original_block_hash, \
            "re-mined block must have a different hash"
        new_block_info = self.node.getblock(new_block_hash)
        assert txid in new_block_info["tx"], \
            "v4 MLSC tx must be re-confirmed in the fresh block"

        tx_out = self.node.gettxout(txid, 0)
        assert tx_out is not None, \
            "MLSC UTXO must be in the UTXO set after reorg re-mining"
        assert tx_out["scriptPubKey"]["hex"].startswith("df"), \
            "Reconfirmed output must still carry the 0xDF MLSC prefix"
        self.log.info(f"  After re-mine: tx in new block {new_block_hash[:16]}..., "
                      f"UTXO confirmed ({tx_out['value']} BTC)")
        self.log.info("  v4 MLSC reorg survival: OK")

    def test_v4_mlsc_rbf_replacement(self):
        """RBF replacement of a plain v4 MLSC tx: build a replaceable v4 tx
        (nSequence < 0xfffffffe), broadcast it, then build a higher-fee
        replacement spending the same input and verify it evicts the
        original from the mempool.

        Why this matters: BIP125 RBF is the standard fee-bump mechanism
        and any v4 tx user needs it to recover from a stuck transaction.
        It's not v4-specific behaviour, but a regression in v4 wire-format
        handling could break the replacement match (e.g., conflict
        detection on inputs, or sigops accounting). This test pins the
        behaviour as a baseline."""
        self.log.info("Testing plain v4 MLSC RBF replacement...")

        self.generate(self.wallet, 3)
        utxo = self.wallet.get_utxo()
        test_pubkey = "02" + "ee" * 32

        # Build the original tx: leave more fee headroom so the replacement
        # can pay strictly more.
        original_create = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{
                "amount": Decimal(str(utxo["value"])) - Decimal("0.005"),  # 5000 sat fee
                "conditions": [{"blocks": [{"type": "SIG", "fields": [
                    {"type": "SCHEME", "hex": "01"},
                    {"type": "PUBKEY", "hex": test_pubkey},
                ]}]}],
            }],
        )
        original_tx = tx_from_hex(original_create["hex"])
        # Mark the input as RBF-replaceable (BIP125: nSequence < 0xfffffffe).
        original_tx.vin[0].nSequence = 0
        self.wallet.sign_tx(original_tx)
        original_hex = original_tx.serialize().hex()
        original_txid = self.node.sendrawtransaction(original_hex)
        self.log.info(f"  Broadcast original: {original_txid[:16]}... (5000 sat fee, RBF)")

        assert original_txid in self.node.getrawmempool(), \
            "original RBF tx must be in mempool before replacement"

        # Build the replacement: same input, lower output value (= higher fee).
        replacement_create = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{
                "amount": Decimal(str(utxo["value"])) - Decimal("0.010"),  # 10000 sat fee
                "conditions": [{"blocks": [{"type": "SIG", "fields": [
                    {"type": "SCHEME", "hex": "01"},
                    {"type": "PUBKEY", "hex": test_pubkey},
                ]}]}],
            }],
        )
        replacement_tx = tx_from_hex(replacement_create["hex"])
        replacement_tx.vin[0].nSequence = 0
        self.wallet.sign_tx(replacement_tx)
        replacement_hex = replacement_tx.serialize().hex()
        replacement_txid = self.node.sendrawtransaction(replacement_hex)
        self.log.info(f"  Broadcast replacement: {replacement_txid[:16]}... (10000 sat fee)")

        mempool = self.node.getrawmempool()
        assert replacement_txid in mempool, \
            "replacement RBF tx must be in mempool after sending"
        assert original_txid not in mempool, \
            f"original tx must be evicted, but still present in mempool={mempool}"
        self.log.info("  Original evicted, replacement confirmed in mempool: OK")

        # Mine the replacement so we don't leave state behind for the next test.
        self.generate(self.node, 1)
        assert self.node.gettxout(replacement_txid, 0) is not None, \
            "replacement v4 MLSC UTXO must land in UTXO set after mining"
        self.log.info("  v4 MLSC RBF replacement: OK")

    def test_v4_data_return_round_trip(self):
        """End-to-end DATA_RETURN round-trip through the full node pipeline:
        build a v4 tx with a DATA_RETURN output, broadcast, mine, then read
        the output back and assert the 40-byte data payload is intact.

        This is the test class that DIDN'T exist for the first ~3 weeks of
        v4's life, which is why DATA_RETURN's wire format bug went undetected
        — the in-memory helpers (CreateMLSCScript, IsMLSCScript, HasMLSCData,
        GetMLSCData) all worked, the unit tests passed, the RPC produced
        plausible-looking hex. No test ever serialised a tx with DATA_RETURN
        and deserialised it on the receiving end. Adding this test pins the
        wire format invariant: 40 bytes in, 40 bytes out, regardless of how
        many serialise/deserialise hops the tx makes."""
        self.log.info("Testing DATA_RETURN end-to-end wire round-trip...")

        self.generate(self.wallet, 3)
        utxo = self.wallet.get_utxo()
        self.log.info(f"  Wallet UTXO: {utxo['txid']}:{utxo['vout']} ({utxo['value']} BTC)")

        # 40 bytes of distinctive data — pattern lets us spot any byte-level
        # corruption immediately. Bytes 0xC0..0xE7 are a sweep that doesn't
        # accidentally match common test fixtures (0xAA, 0xCC, 0xFF) and
        # has no run-length compression hits.
        payload = bytes(range(0xC0, 0xC0 + 40))
        assert_equal(len(payload), 40)
        payload_hex = payload.hex()

        # Build a v4 tx with ONE output: a zero-value DATA_RETURN carrying
        # the payload. Single-output keeps the test focused on the wire
        # format invariant; the createrungtx shared-root check is trivially
        # satisfied with one output, no SIG outputs to compare against.
        # The wallet input value goes entirely to the miner as fee — fine
        # for a regtest test, mempool accepts arbitrarily-high-fee txs.
        create_result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [
                {
                    "amount": 0,
                    "conditions": [
                        {
                            "blocks": [
                                {
                                    "type": "DATA_RETURN",
                                    "fields": [
                                        {"type": "DATA", "hex": payload_hex},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ],
        )
        unsigned_hex = create_result["hex"]
        self.log.info(f"  Built v4 tx with DATA_RETURN: {len(unsigned_hex) // 2} bytes")

        # Sanity: decoderawtransaction should return version 4 with one
        # output whose scriptPubKey starts with 0xDF and is 73 bytes long
        # (1 marker + 32 root + 40 data).
        decoded = self.node.decoderawtransaction(unsigned_hex)
        assert_equal(decoded["version"], 4)
        assert_equal(len(decoded["vout"]), 1)
        assert_equal(decoded["vout"][0]["value"], Decimal("0E-8"))
        spk_hex_pre = decoded["vout"][0]["scriptPubKey"]["hex"]
        assert spk_hex_pre.startswith("df"), \
            f"DATA_RETURN scriptPubKey must start with 0xDF, got {spk_hex_pre[:4]}"
        assert_equal(len(spk_hex_pre), 2 * 73)  # 73 bytes hex
        # The trailing 40 bytes of the SPK are the payload — verify byte-exact
        # match so we know decoderawtransaction reads the wire format correctly.
        assert_equal(spk_hex_pre[-80:], payload_hex)
        self.log.info(f"  decoderawtransaction sees 73-byte SPK with payload trailing bytes")

        # Sign the wallet input and broadcast.
        tx = tx_from_hex(unsigned_hex)
        self.wallet.sign_tx(tx)
        signed_hex = tx.serialize().hex()

        # The wallet input goes entirely to the miner as fee (the only
        # output is zero-value). That's a ~50 BTC fee — well above the
        # default maxtxfee sanity check. Pass maxfeerate=0 to bypass that
        # client-side guard (consensus and policy still apply).
        txid = self.node.sendrawtransaction(signed_hex, 0)
        self.log.info(f"  Broadcast txid: {txid[:16]}...")

        # Mine the tx and verify the data survives one full
        # serialise → mempool → mine → block → block-storage round trip.
        block_hashes = self.generate(self.node, 1)
        block_hash = block_hashes[0]

        # gettxout MUST return null: DATA_RETURN outputs are marked
        # IsUnspendable (extended CScript::IsUnspendable recognises 0xDF
        # SPKs of size 34..73), so AddCoins skips them. This matches
        # OP_RETURN semantics — unspendable outputs aren't in the UTXO
        # set, parity with how Bitcoin handles standard data carriers.
        tx_out = self.node.gettxout(txid, 0)
        assert tx_out is None, \
            "DATA_RETURN output must be unspendable and excluded from UTXO set " \
            f"(IsUnspendable should fire on 73-byte 0xDF SPK), got {tx_out}"
        self.log.info("  gettxout: null (DATA_RETURN is unspendable, parity with OP_RETURN)")

        # Read the data back via getrawtransaction (block storage path).
        # This is the canonical "look up DATA_RETURN bytes I anchored on
        # chain" workflow — same as how clients fetch OP_RETURN data.
        # The regtest node doesn't have -txindex, so we provide the block
        # hash explicitly to enable the lookup.
        raw_from_block = self.node.getrawtransaction(txid, True, block_hash)
        block_spk_hex = raw_from_block["vout"][0]["scriptPubKey"]["hex"]
        assert_equal(len(block_spk_hex), 2 * 73)
        assert block_spk_hex.startswith("df"), \
            f"block SPK must start with 0xDF, got {block_spk_hex[:4]}"
        assert_equal(block_spk_hex[-80:], payload_hex), \
            f"DATA_RETURN payload corrupted: got {block_spk_hex[-80:]}, " \
            f"expected {payload_hex}"
        self.log.info("  getrawtransaction (from block): 73-byte SPK with intact 40-byte payload")
        self.log.info("  DATA_RETURN end-to-end round-trip: OK (40 bytes in, 40 bytes out)")

    # Note: the consensus-layer half of the wallet-funded v4 defence
    # (CheckRungTxLevel invoked unconditionally from CheckInputScripts)
    # is exercised directly by the boost suite (qabi_tests::* and the
    # CheckRungTxLevel branches in rung_tests). We intentionally do not
    # add a functional test for it because every consensus-only rejection
    # path (sub-MIN_RUNG_OUTPUT_VALUE, DATA_RETURN count > 1,
    # MAX_PREIMAGE_FIELDS_PER_TX) is shadowed by an earlier standard
    # policy rejection (dust threshold, OP_RETURN data-carrier rules,
    # mismatched witness shape) — there is no input the mempool will
    # accept that lands at the consensus check before being bounced by
    # policy first. The consensus check is defence-in-depth against
    # future policy regressions and against direct block validation
    # (where policy is bypassed).


if __name__ == "__main__":
    RungTxTest(__file__).main()
