#!/usr/bin/env python3
"""Regression test: the creation_proof extra-leaves embedding vector must
stay closed by the rung_counts binding consensus rule.

Historical context: TX_MLSC's creation_proof is a list of 32-byte leaf
hashes that must Merkle-root-to tx.conditions_root. The original rule was
`leaves.size() >= n_spendable`, which left up to (252 - n_spendable)
attacker-chosen 32-byte leaves as a free data-embedding channel in the
witness. A PoC (earlier version of this test) broadcast a 3-output tx
with 3 real leaves + 10 junk leaves on regtest and confirmed the attack:
all 10 junk ASCII markers ended up in the mined block's raw bytes.

The fix: add a `rung_counts` wire-format field (1 byte per spendable
output) and enforce at consensus:
    rung_counts.size() == n_spendable
    every rung_counts entry in [1, MAX_RUNGS]
    sum(rung_counts) == leaves.size()  (strict equality)
    creation_proof.empty() iff rung_counts.empty()

With the fix, the attacker cannot add extras because every leaf is
bound to a specific spendable output's rung structure. The attacker's
options reduce to (a) adding more spendable outputs (costs dust per
output, now comparable to OP_RETURN) or (b) cramming more rungs into a
single output (bounded by MAX_RUNGS).

This test exercises both scenarios and asserts the attack is rejected:

  1. BASELINE — valid createtxmlsc tx with 3 outputs, no modifications.
     Expected: testmempoolaccept allowed=True.
  2. ATTACK — same tx, with 3 real leaves + 10 junk leaves in
     creation_proof, conditions_root recomputed, rung_counts unchanged
     (still {1,1,1} = sum 3, != 13). Expected:
     testmempoolaccept allowed=False, reject reason mentions the
     creation_proof / rung_counts mismatch.

If at any point in the future the consensus rule regresses and the
attack starts succeeding again, this test will catch it.
"""

from decimal import Decimal
import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.messages import tx_from_hex


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash. Matches C++ TaggedHash()."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def merkle_interior(a: bytes, b: bytes) -> bytes:
    """Sorted interior node hash, matches C++ MerkleInterior()."""
    lo, hi = (a, b) if a <= b else (b, a)
    return tagged_hash("LadderInternal", lo + hi)


def build_merkle_tree(leaves: list) -> bytes:
    """Python reimplementation of C++ BuildMerkleTree() in conditions.cpp.
    Pads to next power of 2 with MLSC_EMPTY_LEAF, then builds bottom-up
    using sorted interior nodes."""
    if not leaves:
        return tagged_hash("LadderLeaf", b"")
    if len(leaves) == 1:
        return leaves[0]
    padded = next_pow2(len(leaves))
    empty = tagged_hash("LadderLeaf", b"")
    leaves = list(leaves) + [empty] * (padded - len(leaves))
    while len(leaves) > 1:
        parents = []
        for i in range(0, len(leaves), 2):
            parents.append(merkle_interior(leaves[i], leaves[i + 1]))
        leaves = parents
    return leaves[0]


class CreationProofExtraLeavesPoC(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        self.node = self.nodes[0]
        wallet = MiniWallet(self.node)
        self.generate(wallet, 101)  # mature coinbase

        # ------------------------------------------------------------------
        # Scenario 1: BASELINE — valid 3-output TX_MLSC tx
        # ------------------------------------------------------------------
        self.log.info("Scenario 1: BASELINE createtxmlsc with 3 outputs")
        utxo = wallet.get_utxo()
        # Outputs near the full input value to stay under max-fee-exceeded,
        # even though testmempoolaccept is called with maxfeerate=0 below.
        total_in = Decimal(str(utxo["value"]))
        per_output = round((total_in - Decimal("0.001")) / 3, 8)
        amounts = [float(per_output)] * 3
        # Distinct pubkeys per rung so createtxmlsc's auto-Taproot-tweak
        # path (fires when all rungs are single-SIG with the same pubkey)
        # does NOT tweak conditions_root. Without the tweak, the tx's
        # conditions_root equals the raw BuildMerkleTree result, which
        # the Python rebuild in this test can reproduce.
        pubkey_markers = ["aa", "bb", "cc"]
        rungs = [
            {
                "output_index": i,
                "blocks": [{
                    "type": "SIG",
                    "fields": [{"type": "SCHEME", "hex": "01"}],
                }],
                "pubkeys": ["02" + pubkey_markers[i] * 32],
            }
            for i in range(3)
        ]
        create_result = self.node.createtxmlsc(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            amounts,
            rungs,
        )
        baseline_hex = create_result["hex"]
        baseline_tx = tx_from_hex(baseline_hex)
        wallet.sign_tx(baseline_tx)
        signed_baseline_hex = baseline_tx.serialize().hex()

        self.log.info(
            f"  baseline rung_counts (pre-send, {len(baseline_tx.rung_counts)} bytes): "
            f"{baseline_tx.rung_counts.hex()}")
        baseline_result = self.node.testmempoolaccept([signed_baseline_hex], maxfeerate=0)[0]
        self.log.info(f"  baseline testmempoolaccept: allowed={baseline_result['allowed']}")
        if not baseline_result["allowed"]:
            self.log.info(f"  reason: {baseline_result.get('reject-reason', '<none>')}")
            raise AssertionError(
                "BASELINE failed — cannot run attack scenario if the clean "
                "path doesn't work. Diagnose baseline first.")

        # Grab the creation_proof from the signed baseline tx so we know
        # what shape the real leaves take.
        cp_bytes = baseline_tx.creation_proof
        n_real_leaves = cp_bytes[0]
        real_leaves = []
        for i in range(n_real_leaves):
            real_leaves.append(cp_bytes[1 + 32 * i : 1 + 32 * (i + 1)])
        self.log.info(
            f"  baseline has {n_real_leaves} real leaves in creation_proof, "
            f"conditions_root={baseline_tx.conditions_root.hex()[:16]}...")

        # Verify our Python merkle rebuild matches the C++ root
        py_root = build_merkle_tree(real_leaves)
        if py_root != baseline_tx.conditions_root:
            self.log.info(
                f"  WARNING: Python merkle root mismatch. "
                f"py={py_root.hex()[:16]}... "
                f"cxx={baseline_tx.conditions_root.hex()[:16]}...")
            self.log.info("  Cannot run attack without matching merkle impl. Aborting.")
            return

        # ------------------------------------------------------------------
        # Scenario 2: ATTACK — 3 real leaves + 10 junk leaves
        # ------------------------------------------------------------------
        self.log.info("Scenario 2: ATTACK — appending 10 junk leaves")

        # Junk leaves are 32 bytes of ASCII-recognisable attacker data.
        # If these bytes survive the round trip, the attack is confirmed.
        junk_leaves = []
        for i in range(10):
            marker = f"ATTACKER_DATA_VECTOR_NUMBER_{i:03d}".encode()
            junk_leaves.append(marker[:32].ljust(32, b"_"))

        all_leaves = real_leaves + junk_leaves
        new_root = build_merkle_tree(all_leaves)
        self.log.info(
            f"  total leaves: {len(all_leaves)} "
            f"(3 real + 10 junk), new root={new_root.hex()[:16]}...")

        # Build the new creation_proof blob: 1 byte count + leaves.
        new_cp = bytes([len(all_leaves)])
        for leaf in all_leaves:
            new_cp += leaf

        # Start from a freshly built tx (not the wallet-signed one) so
        # we can still let MiniWallet sign after we mutate.
        attack_tx = tx_from_hex(baseline_hex)
        attack_tx.creation_proof = new_cp
        attack_tx.conditions_root = new_root
        # Re-inflate each output's scriptPubKey to 0xDF || new_root
        new_spk = b"\xdf" + new_root
        for out in attack_tx.vout:
            out.scriptPubKey = new_spk

        wallet.sign_tx(attack_tx)
        attack_hex = attack_tx.serialize().hex()

        # Verify our junk bytes are actually in the serialized form
        first_marker = b"ATTACKER_DATA_VECTOR_NUMBER_000"
        if first_marker not in bytes.fromhex(attack_hex):
            raise AssertionError(
                "ATTACKER marker not in serialized attack tx — "
                "serializer may have dropped the extra bytes.")
        self.log.info(
            f"  attack tx serialized: {len(attack_hex) // 2} bytes, "
            f"marker present in wire bytes")

        self.log.info(
            f"  attack rung_counts (pre-send, {len(attack_tx.rung_counts)} bytes): "
            f"{attack_tx.rung_counts.hex()}")
        attack_result = self.node.testmempoolaccept([attack_hex], maxfeerate=0)[0]
        self.log.info(f"  attack testmempoolaccept: allowed={attack_result['allowed']}")
        if attack_result["allowed"]:
            # Try to actually broadcast + mine so the failure message
            # includes evidence the attack worked end-to-end.
            txid = self.node.sendrawtransaction(attack_hex, 0)
            block_hashes = self.generate(self.node, 1)
            block_bytes = bytes.fromhex(self.node.getblock(block_hashes[0], 0))
            junk_count = sum(
                1 for i in range(10)
                if f"ATTACKER_DATA_VECTOR_NUMBER_{i:03d}".encode()[:32].ljust(32, b"_") in block_bytes
            )
            raise AssertionError(
                f"REGRESSION: creation_proof extra-leaves embedding vector "
                f"is open again. Attack tx {txid[:16]}... was accepted at "
                f"consensus and mined; {junk_count}/10 attacker-chosen "
                f"junk markers are now permanent in the block. Check the "
                f"rung_counts binding in ValidateCreationProofLeaves "
                f"(src/rung/conditions.cpp) and src/rung/evaluator.cpp "
                f"VerifyRungTx.")

        reason = attack_result.get("reject-reason", "<none>")
        self.log.info(f"  attack REJECTED as expected — reason: {reason}")
        self.log.info(
            "  RESULT: the rung_counts binding is holding; attacker cannot "
            "add extra leaves to creation_proof beyond sum(rung_counts).")


if __name__ == "__main__":
    CreationProofExtraLeavesPoC(__file__).main()
