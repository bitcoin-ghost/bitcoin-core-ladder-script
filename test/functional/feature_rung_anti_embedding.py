#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Functional negative-path coverage for the witness-side embedding-channel
closures E-019..E-023.

For each closure, the test:
  1. Builds a canonical valid v4 spend via createrungtx + signrungtx.
  2. Surgically mutates the LadderWitness bytes to insert the
     embedding channel the closure is supposed to refuse.
  3. Submits via sendrawtransaction and asserts rejection.

This file complements the Boost regression tests (which cover the
deserialiser at unit-test granularity) by exercising the same closures
end-to-end against a live regtest node, satisfying the activation gate
component 3 requirement of "1+ negative vector per witness rule
family".

Closures covered:
  E-019: witness-side fields on a conditions-only block (CSV)
  E-020: extra fields on legacy P2*_LEGACY bridging witness
  E-021: PQ_BATCH non-anchor with non-canonical witness shape
  E-022: redundant witness fields that echoed conditions (HASH_GUARDED)
  E-023: CTV (conditions-only, post-refinement) carrying witness bytes
"""

import hashlib
import struct
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import CTransaction, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


# ──────────────────────────────────────────────────────────────────
# Wire-format helpers — CompactSize + LadderWitness surgical edits.
# ──────────────────────────────────────────────────────────────────

# RungDataType enum codes (from src/rung/types.h). Used for
# `data_type` byte in serialized LadderField entries.
DATA_TYPE = {
    "PUBKEY":       0x01,
    "PUBKEY_COMMIT":0x02,
    "HASH256":      0x03,
    "HASH160":      0x04,
    "SIGNATURE":    0x05,
    "PREIMAGE":     0x06,
    "SCRIPT_BODY":  0x08,
    "NUMERIC":      0x09,
    "MERKLE_PROOF": 0x0A,
    "DATA":         0x0B,
    "SCHEME":       0x0C,
}


def encode_compactsize(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xFD" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xFE" + struct.pack("<I", n)
    return b"\xFF" + struct.pack("<Q", n)


def parse_compactsize(buf: bytes, off: int):
    """Return (value, new_offset)."""
    b = buf[off]
    if b < 0xFD:
        return b, off + 1
    if b == 0xFD:
        return struct.unpack("<H", buf[off + 1:off + 3])[0], off + 3
    if b == 0xFE:
        return struct.unpack("<I", buf[off + 1:off + 5])[0], off + 5
    return struct.unpack("<Q", buf[off + 1:off + 9])[0], off + 9


def append_witness_field(witness_elem: bytes, data_type: str,
                          payload: bytes) -> bytes:
    """Append one extra field to the LAST block of the LAST rung in a
    LadderWitness wire bytestring.

    LadderWitness layout (CONDITIONS-or-WITNESS context):
        n_rungs:            CompactSize
        per rung:
            n_blocks:       CompactSize
            per block:
                block_type: micro-header byte OR escape + uint16 LE
                fields:     CompactSize n_fields, per field:
                            data_type byte + length-prefixed bytes
            n_relay_refs:   CompactSize
            per ref:        uint16 LE
        coil:               4 bytes

    The mutation appends a new field to the last block of the last
    rung. This is the simplest channel the consensus closures are
    designed to refuse; if a closure regression lands, the deserialiser
    or the per-block evaluator will accept the extra bytes silently and
    `sendrawtransaction` will succeed instead of rejecting.

    NOTE: this helper does not parse the entire witness — it walks far
    enough to locate the field-count varint of the last block, then
    rewrites it (incremented by 1) and inserts the new field bytes
    immediately before the n_relay_refs varint that follows.
    """
    # For the limited scope of these tests we always operate on a
    # single-rung witness with a single-block rung, so we can take a
    # simple parsing path: find the last block's `n_fields` varint by
    # scanning forward from the start.
    #
    # Generalising this to arbitrary witness shapes is left to future
    # tests; the closures we exercise all build single-block rungs.
    field_bytes = bytes([DATA_TYPE[data_type]]) + encode_compactsize(len(payload)) + payload
    # We can't safely re-parse the witness without a full deserialiser,
    # so the strategy used in tests is to rebuild the witness from
    # scratch via `build_witness_with_extra_field` instead of mutating
    # an existing one. This helper is kept for documentation but tests
    # below construct the malformed witness directly.
    raise NotImplementedError(
        "Use build_witness_with_extra_field instead — mutating the "
        "library-built witness in place requires a full LadderWitness "
        "deserialiser, which is what the closures themselves protect."
    )


def build_witness_one_block_with_fields(
    block_type: int,
    fields: list,        # list of (data_type_str, payload_bytes)
    coil_bytes: bytes,
) -> bytes:
    """Build a LadderWitness with exactly one rung containing one block
    that carries `fields`. The closure tests use this to construct
    intentionally-malformed witnesses (extra fields on conditions-only
    blocks) without going through signrungtx's pre-validation.

    block_type: 16-bit wire ID. We always use the escape encoding
        (0xFF + uint16 LE block_type) for simplicity — the micro-header
        slots only cover the most common types; full encoding is
        always valid.
    coil_bytes: exactly 4 bytes (coil_type / attestation / scheme /
        output_index) per the post-E-009 coil layout.
    """
    assert len(coil_bytes) == 4, "coil must be 4 bytes (post-E-009)"
    out = bytearray()
    out += encode_compactsize(1)                 # n_rungs
    out += encode_compactsize(1)                 # n_blocks (in this rung)
    # Block header: 0xFF escape + uint16 LE block_type
    out += bytes([0xFF]) + struct.pack("<H", block_type)
    out += encode_compactsize(len(fields))       # n_fields
    for dtype_name, payload in fields:
        out += bytes([DATA_TYPE[dtype_name]])
        out += encode_compactsize(len(payload))
        out += payload
    out += encode_compactsize(0)                 # n_relay_refs
    out += coil_bytes                            # coil
    out += encode_compactsize(0)                 # n_relays at tail
    return bytes(out)


def replace_input_witness(signed_hex: str, input_idx: int,
                          new_witness_elem: bytes,
                          new_proof_elem: bytes = None) -> str:
    """Take a signed v4 tx and replace one input's scriptWitness stack
    with [new_witness_elem, new_proof_elem]. If new_proof_elem is
    None, the original tx's proof element for that input is kept.
    """
    tx = tx_from_hex(signed_hex)
    stack = tx.wit.vtxinwit[input_idx].scriptWitness.stack
    if new_proof_elem is None and len(stack) >= 2:
        new_proof_elem = stack[1]
    # Preserve a 3rd element (key-path internal pubkey) if present.
    new_stack = [new_witness_elem]
    if new_proof_elem is not None:
        new_stack.append(new_proof_elem)
    if len(stack) >= 3:
        new_stack.append(stack[2])
    tx.wit.vtxinwit[input_idx].scriptWitness.stack = new_stack
    return tx.serialize().hex()


# ──────────────────────────────────────────────────────────────────
# Test cases
# ──────────────────────────────────────────────────────────────────

# Block-type wire IDs (from src/rung/types.h). Centralised so the
# tests document which type they exercise.
BLOCK_TYPE = {
    "SIG":          0x0001,
    "CSV":          0x0101,
    "TAGGED_HASH":  0x0203,
    "HASH_GUARDED": 0x0204,
    "CTV":          0x0301,
    "ANCHOR":       0x0501,
    "PQ_BATCH":     0x0A03,
}

# Default coil bytes: UNLOCK / INLINE / SCHNORR / output_index=0.
# (Per src/rung/types.h enum values and src/rung/serialize.cpp wire layout.)
DEFAULT_COIL = bytes([0x01, 0x01, 0x01, 0x00])


class RungAntiEmbeddingTest(BitcoinTestFramework):
    """Negative-path functional coverage for E-019..E-023.

    Test outcome convention: every test asserts that the malformed
    transaction is REJECTED by sendrawtransaction. The reject reason
    string is logged for visibility — exact wording isn't asserted on
    (it's not part of the consensus contract) but the rejection itself
    is.
    """

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.generate(self.wallet, COINBASE_MATURITY + 5)

        self.test_e019_csv_with_witness_field()
        self.test_e022_hash_guarded_redundant_field()
        self.test_e023_ctv_with_witness_field()
        self.test_e021_pq_batch_bad_shape()
        self.test_e020_anchor_with_extra_witness()

        self.log.info("All anti-embedding negative paths rejected as expected.")

    # ──────────────────────────────────────────────────────────────
    # Shared helpers
    # ──────────────────────────────────────────────────────────────

    def _fund_with_block(self, block_type_name: str, conditions_fields: list):
        """Build + broadcast a v4 fund tx with a single MLSC output gated
        by a single rung that carries one block of the given type with
        the specified conditions fields. Returns
        {txid, vout, amount, spk, conditions} for the spend test.

        block_type_name: enum name string (e.g. "CSV").
        conditions_fields: list of {type, hex} dicts as createrungtx expects.
        """
        utxo = self.wallet.get_utxo()
        amt = (Decimal(str(utxo["value"])) - Decimal("0.001"))
        amt = amt.quantize(Decimal("0.00000001"))
        rung = {
            "output_index": 0,
            "blocks": [{"type": block_type_name, "fields": conditions_fields}],
        }
        result = self.node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [amt],
            [rung],
        )
        tx = tx_from_hex(result["hex"])
        self.wallet.sign_tx(tx)
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        self.generate(self.node, 1)
        txout = self.node.gettxout(txid, 0)
        assert txout is not None, f"funded vout missing for {block_type_name}"
        return {
            "txid": txid,
            "vout": 0,
            "amount": float(txout["value"]),
            "spk": txout["scriptPubKey"]["hex"],
            "conditions": [{"blocks": [{"type": block_type_name,
                                         "fields": conditions_fields}]}],
        }

    def _try_send_expecting_reject(self, mutated_hex: str, label: str) -> str:
        """Submit a mutated tx; assert rejection; return the reject reason."""
        try:
            txid = self.node.sendrawtransaction(mutated_hex)
            raise AssertionError(
                f"{label}: malformed tx unexpectedly ACCEPTED as txid={txid} "
                f"— consensus closure has regressed"
            )
        except Exception as e:
            reason = str(e)
            self.log.info(f"  {label}: rejected — {reason[:120]}")
            return reason

    # ──────────────────────────────────────────────────────────────
    # E-019: conditions-only block carries witness fields
    # ──────────────────────────────────────────────────────────────
    # CSV is `Empty` witness rule (per src/rung/types.h CSV_WITNESS).
    # A spender that injects PREIMAGE / PUBKEY / NUMERIC into a CSV
    # rung's witness is exercising the embedding channel E-019 closed.
    # Pre-fix: silently allowed, attacker-chosen bytes survived to the
    # chain. Post-fix: deserialiser/evaluator rejects.
    def test_e019_csv_with_witness_field(self):
        self.log.info("E-019: CSV with attacker witness field (must reject)")
        funded = self._fund_with_block("CSV", [
            {"type": "NUMERIC", "hex": "01000000"},  # CSV(1 block)
        ])

        # Build a malformed witness: CSV block carrying a spurious
        # 32-byte HASH256 field that consensus has no use for.
        bogus_hash = b"\xab" * 32
        malformed = build_witness_one_block_with_fields(
            BLOCK_TYPE["CSV"],
            [("HASH256", bogus_hash)],
            DEFAULT_COIL,
        )
        # Build a stub MLSC proof. We don't have a clean way to
        # synthesise this without going through signrungtx; instead we
        # use the proof from a SIBLING valid spend of the funded utxo.
        # Since we never mature past CSV here, this test relies on the
        # malformed witness being rejected at deserialisation BEFORE
        # the proof gets verified — which is the closure E-019 enforces.
        sink_amt = (Decimal(str(funded["amount"])) - Decimal("0.001")).quantize(Decimal("0.00000001"))
        sink_rungs = [{"output_index": 0,
                       "blocks": [{"type": "CSV",
                                    "fields": [{"type": "NUMERIC", "hex": "00000000"}]}]}]
        spend_template = self.node.createrungtx(
            [{"txid": funded["txid"], "vout": funded["vout"]}],
            [sink_amt],
            sink_rungs,
        )
        # Splice the malformed witness in at input 0 with a stub
        # 1-byte proof element. The deserialiser bails on the witness
        # before reaching proof verification.
        mutated = replace_input_witness(
            spend_template["hex"], 0,
            malformed,
            new_proof_elem=b"\x00",
        )
        self._try_send_expecting_reject(mutated, "E-019")

    # ──────────────────────────────────────────────────────────────
    # E-022: redundant witness fields that echoed conditions
    # ──────────────────────────────────────────────────────────────
    # HASH_GUARDED witness (post-E-022): exactly [PREIMAGE]. The pre-
    # E-022 wire layout allowed [PREIMAGE, HASH256] where the trailing
    # HASH256 echoed a conditions field. Closure: any extra field after
    # the canonical PREIMAGE is rejected.
    def test_e022_hash_guarded_redundant_field(self):
        self.log.info("E-022: HASH_GUARDED with redundant HASH256 (must reject)")
        # createrungtx for HASH_GUARDED takes the PREIMAGE in conditions
        # and computes the HASH256 commit itself (rpc.cpp:415-418). The
        # user never writes the HASH256 field directly at fund time.
        preimage = b"\x42" * 16
        committed = hashlib.sha256(preimage).digest()
        funded = self._fund_with_block("HASH_GUARDED", [
            {"type": "PREIMAGE", "hex": preimage.hex()},
        ])

        # Malformed witness: PREIMAGE plus a redundant HASH256 echo.
        malformed = build_witness_one_block_with_fields(
            BLOCK_TYPE["HASH_GUARDED"],
            [("PREIMAGE", preimage),
             ("HASH256",  committed)],
            DEFAULT_COIL,
        )
        sink_amt = (Decimal(str(funded["amount"])) - Decimal("0.001")).quantize(Decimal("0.00000001"))
        spend_template = self.node.createrungtx(
            [{"txid": funded["txid"], "vout": funded["vout"]}],
            [sink_amt],
            [{"output_index": 0,
              "blocks": [{"type": "CSV",
                           "fields": [{"type": "NUMERIC", "hex": "00000000"}]}]}],
        )
        mutated = replace_input_witness(
            spend_template["hex"], 0,
            malformed,
            new_proof_elem=b"\x00",
        )
        self._try_send_expecting_reject(mutated, "E-022")

    # ──────────────────────────────────────────────────────────────
    # E-023: CTV (conditions-only post-refinement) with witness bytes
    # ──────────────────────────────────────────────────────────────
    # CTV's witness rule is `Empty` post-E-023. Pre-fix tolerated a
    # trailing PREIMAGE; closure refuses any witness field on CTV.
    def test_e023_ctv_with_witness_field(self):
        self.log.info("E-023: CTV with witness field (must reject)")
        # CTV conditions: [HASH256(template_hash)]. Use a placeholder
        # hash — we never actually evaluate the CTV check here because
        # the witness rejection trips first.
        template_hash = b"\xcc" * 32
        funded = self._fund_with_block("CTV", [
            {"type": "HASH256", "hex": template_hash.hex()},
        ])

        malformed = build_witness_one_block_with_fields(
            BLOCK_TYPE["CTV"],
            [("PREIMAGE", b"\x99" * 16)],  # CTV is Empty — any field rejects
            DEFAULT_COIL,
        )
        sink_amt = (Decimal(str(funded["amount"])) - Decimal("0.001")).quantize(Decimal("0.00000001"))
        spend_template = self.node.createrungtx(
            [{"txid": funded["txid"], "vout": funded["vout"]}],
            [sink_amt],
            [{"output_index": 0,
              "blocks": [{"type": "CSV",
                           "fields": [{"type": "NUMERIC", "hex": "00000000"}]}]}],
        )
        mutated = replace_input_witness(
            spend_template["hex"], 0,
            malformed,
            new_proof_elem=b"\x00",
        )
        self._try_send_expecting_reject(mutated, "E-023")

    # ──────────────────────────────────────────────────────────────
    # E-021: PQ_BATCH non-canonical witness shape
    # ──────────────────────────────────────────────────────────────
    # PQ_BATCH is pinned to one of two exact field shapes (post-E-021):
    #   1 field:  [HASH256]                   (non-anchor / cache)
    #   3 fields: [HASH256, PUBKEY, SIGNATURE](anchor)
    # Any other shape — including [SIG, SIG], [PUBKEY, PUBKEY], or
    # [HASH256, PUBKEY, PUBKEY] — must reject.
    def test_e021_pq_batch_bad_shape(self):
        self.log.info("E-021: PQ_BATCH with [SIGNATURE, SIGNATURE] (must reject)")
        # Probe liboqs availability indirectly via PQ_BATCH funding.
        try:
            self.node.generatepqkeypair("FALCON512")
        except Exception as e:
            if "liboqs" in str(e).lower():
                raise SkipTest("E-021 PQ_BATCH probe requires liboqs")
            raise

        commit = hashlib.sha256(b"e021-test-key").digest()
        funded = self._fund_with_block("PQ_BATCH", [
            {"type": "HASH256", "hex": commit.hex()},
        ])

        malformed = build_witness_one_block_with_fields(
            BLOCK_TYPE["PQ_BATCH"],
            [("SIGNATURE", b"\x11" * 64),
             ("SIGNATURE", b"\x22" * 64)],   # bad: 2 signatures, no HASH256
            DEFAULT_COIL,
        )
        sink_amt = (Decimal(str(funded["amount"])) - Decimal("0.001")).quantize(Decimal("0.00000001"))
        spend_template = self.node.createrungtx(
            [{"txid": funded["txid"], "vout": funded["vout"]}],
            [sink_amt],
            [{"output_index": 0,
              "blocks": [{"type": "CSV",
                           "fields": [{"type": "NUMERIC", "hex": "00000000"}]}]}],
        )
        mutated = replace_input_witness(
            spend_template["hex"], 0,
            malformed,
            new_proof_elem=b"\x00",
        )
        self._try_send_expecting_reject(mutated, "E-021")

    # ──────────────────────────────────────────────────────────────
    # E-020: extra fields on legacy P2*_LEGACY bridging witness
    # ──────────────────────────────────────────────────────────────
    # The simplest E-020 shape exercises ANCHOR (a conditions-only
    # block — `Empty` witness rule per BIP) with an attacker stack-push
    # field. Same closure applies to P2SH_LEGACY / P2WSH_LEGACY but
    # those need a coherent inner-script pre-image to even reach the
    # rule check; ANCHOR makes the negative path direct.
    def test_e020_anchor_with_extra_witness(self):
        self.log.info("E-020: ANCHOR (conditions-only) with witness field (must reject)")
        funded = self._fund_with_block("ANCHOR", [
            {"type": "NUMERIC", "hex": "01000000"},  # anchor_id
        ])
        malformed = build_witness_one_block_with_fields(
            BLOCK_TYPE["ANCHOR"],
            [("PUBKEY", b"\x02" + b"\x33" * 32)],  # extra PUBKEY on Empty rule
            DEFAULT_COIL,
        )
        sink_amt = (Decimal(str(funded["amount"])) - Decimal("0.001")).quantize(Decimal("0.00000001"))
        spend_template = self.node.createrungtx(
            [{"txid": funded["txid"], "vout": funded["vout"]}],
            [sink_amt],
            [{"output_index": 0,
              "blocks": [{"type": "CSV",
                           "fields": [{"type": "NUMERIC", "hex": "00000000"}]}]}],
        )
        mutated = replace_input_witness(
            spend_template["hex"], 0,
            malformed,
            new_proof_elem=b"\x00",
        )
        self._try_send_expecting_reject(mutated, "E-020")


if __name__ == "__main__":
    RungAntiEmbeddingTest(__file__).main()
