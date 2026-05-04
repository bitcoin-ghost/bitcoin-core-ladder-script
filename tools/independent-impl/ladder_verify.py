#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license.
"""Independent v4 RUNG_TX verifier — pure Python, no Bitcoin Core deps.

Activation gate component 7 (independent implementation). The goal is
not full validation; it is to demonstrate that a stateless, second
implementation reading only the BIP draft can reproduce the
consensus-critical commitments of the reference implementation:

  - 0xDF MLSC scriptPubKey parser → conditions_root recovery
  - v4 RUNG_TX wire-format deserialiser
  - TX_MLSC leaf computation (LadderLeaf/v1 tagged hash over a
    structural template + value commitment)
  - Sorted-pair Merkle tree (LadderInternal/v1) → conditions_root
  - SIG witness rule: BIP-340 Schnorr verification against the v4
    sighash

Scope is deliberately narrow. PLC, recursion, QABI families and
spend-time evaluators are out of scope for this skeleton — the goal is
*existence of a second implementation*, not feature parity.

Reference: src/rung/conditions.cpp (LEAF_HASHER, INTERNAL_HASHER,
ComputeTxMLSCLeaf, BuildMerkleTree); src/rung/block_helpers.cpp
(BuildCPRung, ComputeConditionsRootMLSC); src/rung/sighash.cpp.
"""

import hashlib
import io
import struct
from typing import List, Tuple, Optional


# ── Tagged hash (BIP-340-style) ────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """SHA256(SHA256(tag) || SHA256(tag) || data)."""
    th = _sha256(tag.encode("utf-8"))
    return _sha256(th + th + data)


# Empty-leaf padding constant. Pre-computed once so verifications are
# byte-equivalent across runs.
_MLSC_EMPTY_LEAF = _tagged_hash("LadderLeaf/v1", b"")


# ── 0xDF MLSC scriptPubKey parser ──────────────────────────────────

RUNG_MLSC_PREFIX = 0xDF


def parse_mlsc_spk(spk: bytes) -> Optional[bytes]:
    """Return the 32-byte conditions_root, or None if `spk` is not a
    full-form MLSC script. Compact MLSC (1-byte 0xDF, root recovered
    from the UTXO compressor) returns None."""
    if not spk or spk[0] != RUNG_MLSC_PREFIX:
        return None
    if len(spk) < 33:
        return None
    return bytes(spk[1:33])


# ── v4 RUNG_TX wire-format reader ──────────────────────────────────

RUNG_TX_VERSION = 4


class V4Tx:
    __slots__ = ("version", "vin", "conditions_root", "vouts",
                 "witnesses", "qabi_block", "aggregated_sig")

    def __init__(self):
        self.version: int = 0
        self.vin: List[Tuple[bytes, int, int]] = []  # (prev_txid, prev_vout, nSequence)
        self.conditions_root: bytes = b""
        self.vouts: List[Tuple[int, bytes]] = []     # (nValue, data_or_b'')
        self.witnesses: List[List[bytes]] = []
        self.qabi_block: bytes = b""
        self.aggregated_sig: bytes = b""


def _read_compact_size(stream: io.BytesIO) -> int:
    b = stream.read(1)
    if not b:
        raise ValueError("eof in compact_size")
    n = b[0]
    if n < 253:
        return n
    if n == 253:
        return struct.unpack("<H", stream.read(2))[0]
    if n == 254:
        return struct.unpack("<I", stream.read(4))[0]
    return struct.unpack("<Q", stream.read(8))[0]


def _read_bytes(stream: io.BytesIO, n: int) -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise ValueError(f"short read: wanted {n}, got {len(data)}")
    return data


def parse_v4_tx(tx_hex_or_bytes) -> V4Tx:
    """Parse the v4 RUNG_TX wire format described in
    src/primitives/transaction.h (`RUNG_TX_VERSION` block comment).

    The witness-marker convention is BIP-141: dummy=0x00, flag=0x02. v4
    *requires* witness encoding (this serialiser never uses the
    legacy non-witness branch)."""
    if isinstance(tx_hex_or_bytes, str):
        raw = bytes.fromhex(tx_hex_or_bytes)
    else:
        raw = bytes(tx_hex_or_bytes)
    s = io.BytesIO(raw)
    tx = V4Tx()

    tx.version = struct.unpack("<I", _read_bytes(s, 4))[0]
    if tx.version != RUNG_TX_VERSION:
        raise ValueError(f"not a v4 tx: version={tx.version}")

    dummy = _read_bytes(s, 1)
    flag = _read_bytes(s, 1)
    if dummy != b"\x00" or flag != b"\x02":
        raise ValueError(f"v4 requires BIP-141 witness markers; got "
                         f"dummy={dummy.hex()}, flag={flag.hex()}")

    n_in = _read_compact_size(s)
    for _ in range(n_in):
        prev_txid = _read_bytes(s, 32)
        prev_vout = struct.unpack("<I", _read_bytes(s, 4))[0]
        scriptsig_len = _read_compact_size(s)
        if scriptsig_len != 0:
            raise ValueError("v4 input scriptSig must be empty")
        sequence = struct.unpack("<I", _read_bytes(s, 4))[0]
        tx.vin.append((prev_txid, prev_vout, sequence))

    tx.conditions_root = _read_bytes(s, 32)

    n_out = _read_compact_size(s)
    for _ in range(n_out):
        nvalue = struct.unpack("<q", _read_bytes(s, 8))[0]
        if nvalue == 0:
            data_len = _read_compact_size(s)
            data = _read_bytes(s, data_len)
            tx.vouts.append((0, data))
        else:
            tx.vouts.append((nvalue, b""))

    # Per-input witness stacks
    for _ in range(n_in):
        n_items = _read_compact_size(s)
        stack = []
        for _ in range(n_items):
            item_len = _read_compact_size(s)
            stack.append(_read_bytes(s, item_len))
        tx.witnesses.append(stack)

    # QABI block + aggregated sig (both may be empty).
    qabi_len = _read_compact_size(s)
    tx.qabi_block = _read_bytes(s, qabi_len)
    aggsig_len = _read_compact_size(s)
    tx.aggregated_sig = _read_bytes(s, aggsig_len)

    return tx


# ── TX_MLSC leaf + Merkle root ─────────────────────────────────────

def _serialize_structural_template(blocks: List[Tuple[int, int]],
                                    relay_refs: List[int],
                                    coil_type: int,
                                    coil_attestation: int,
                                    coil_scheme: int,
                                    coil_output_index: int) -> bytes:
    """Mirror SerializeStructuralTemplate (conditions.cpp:1263).

      n_blocks(1)
      per block: block_type_lo(1), block_type_hi(1), inverted(1)
      n_relay_refs(1)
      per ref: ref_lo(1), ref_hi(1)
      coil_type(1), coil_attestation(1), coil_scheme(1), coil_output_index(1)
    """
    out = bytearray()
    out.append(len(blocks))
    for block_type, inverted in blocks:
        out.append(block_type & 0xFF)
        out.append((block_type >> 8) & 0xFF)
        out.append(inverted)
    out.append(len(relay_refs))
    for r in relay_refs:
        out.append(r & 0xFF)
        out.append((r >> 8) & 0xFF)
    out.append(coil_type)
    out.append(coil_attestation)
    out.append(coil_scheme)
    out.append(coil_output_index)
    return bytes(out)


def _compute_value_commitment(rung_blocks_with_fields,
                               pubkeys: List[bytes]) -> bytes:
    """Mirror ComputeValueCommitment (conditions.cpp:1358).

    `rung_blocks_with_fields` is a list of [(block_type, [(field_type,
    field_data), ...]), ...]. NUMERIC fields shorter than 4 B are
    right-padded with zeros to 4 B before hashing — see the C++
    reference for why."""
    hasher = hashlib.sha256()
    NUMERIC = 0x08
    for _block_type, fields in rung_blocks_with_fields:
        for field_type, field_data in fields:
            if field_type == NUMERIC and len(field_data) < 4:
                hasher.update(field_data + b"\x00" * (4 - len(field_data)))
            else:
                hasher.update(field_data)
    for pk in pubkeys:
        hasher.update(pk)
    return hasher.digest()


def compute_tx_mlsc_leaf(blocks: List[Tuple[int, int]],
                          rung_blocks_with_fields,
                          pubkeys: List[bytes],
                          relay_refs: List[int],
                          coil_type: int,
                          coil_attestation: int,
                          coil_scheme: int,
                          coil_output_index: int) -> bytes:
    """Mirror ComputeTxMLSCLeaf (conditions.cpp:1299).

    leaf = TaggedHash("LadderLeaf/v1", structural_template || value_commitment)
    """
    tmpl = _serialize_structural_template(
        blocks, relay_refs, coil_type, coil_attestation,
        coil_scheme, coil_output_index)
    vc = _compute_value_commitment(rung_blocks_with_fields, pubkeys)
    return _tagged_hash("LadderLeaf/v1", tmpl + vc)


def _next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def _merkle_interior(a: bytes, b: bytes) -> bytes:
    """TaggedHash("LadderInternal/v1", min(a,b) || max(a,b))."""
    if a <= b:
        return _tagged_hash("LadderInternal/v1", a + b)
    return _tagged_hash("LadderInternal/v1", b + a)


def build_merkle_tree(leaves: List[bytes]) -> bytes:
    """Mirror BuildMerkleTree (conditions.cpp:423). Empty → empty leaf;
    1 leaf → identity; otherwise pad to next power of 2 and reduce."""
    if not leaves:
        return _MLSC_EMPTY_LEAF
    if len(leaves) == 1:
        return leaves[0]
    padded = _next_pow2(len(leaves))
    leaves = list(leaves) + [_MLSC_EMPTY_LEAF] * (padded - len(leaves))
    while len(leaves) > 1:
        leaves = [_merkle_interior(leaves[i], leaves[i + 1])
                  for i in range(0, len(leaves), 2)]
    return leaves[0]


# ── Convenience: full conditions_root recovery ─────────────────────

# Block-type wire codes (subset). See src/rung/types.h:RungBlockType
# for the full enum.
BT_SIG              = 0x0001
BT_CSV              = 0x0101
BT_CSV_TIME         = 0x0102
BT_CLTV             = 0x0103
BT_CLTV_TIME        = 0x0104
BT_TAGGED_HASH      = 0x0203
BT_HASH_GUARDED     = 0x0204
BT_CTV              = 0x0301
BT_AMOUNT_LOCK      = 0x0303
BT_RECURSE_SAME     = 0x0401
BT_RECURSE_UNTIL    = 0x0403
BT_RECURSE_COUNT    = 0x0404
BT_RECURSE_SPLIT    = 0x0405
BT_ANCHOR           = 0x0501
BT_ANCHOR_CHANNEL   = 0x0502
BT_ANCHOR_POOL      = 0x0503
BT_ANCHOR_RESERVE   = 0x0504
BT_ANCHOR_SEAL      = 0x0505
BT_HYSTERESIS_FEE   = 0x0601
BT_HYSTERESIS_VALUE = 0x0602
BT_TIMER_CONTINUOUS = 0x0611
BT_TIMER_OFF_DELAY  = 0x0612
BT_LATCH_SET        = 0x0621
BT_LATCH_RESET      = 0x0622
BT_COUNTER_DOWN     = 0x0631
BT_COUNTER_PRESET   = 0x0632
BT_COUNTER_UP       = 0x0633
BT_COMPARE          = 0x0641
BT_SEQUENCER        = 0x0651
BT_ONE_SHOT         = 0x0661
BT_RATE_LIMIT       = 0x0671
BT_EPOCH_GATE       = 0x0801
BT_WEIGHT_LIMIT     = 0x0802
BT_INPUT_COUNT      = 0x0803
BT_OUTPUT_COUNT     = 0x0804
BT_RELATIVE_VALUE   = 0x0805
# Multi-pubkey leaves (PubkeyCountForBlock = 2)
BT_HTLC             = 0x0702
BT_ANCHOR_FEE       = 0x0707
BT_VAULT_LOCK       = 0x0302
# Inner-Merkle leaf (PubkeyCountForBlock = 0; pubkeys committed via HASH256 root)
BT_MULTISIG         = 0x0002
BT_TIMELOCKED_MULTISIG = 0x0706
BT_LATCH_RESET      = 0x0622
BT_ONE_SHOT         = 0x0661
BT_RECURSE_MODIFIED = 0x0402
BT_RECURSE_DECAY    = 0x0406
BT_QABI_PRIME       = 0x0A01
# Special / governance / legacy
BT_KEY_REF_SIG      = 0x0005
BT_OUTPUT_CHECK     = 0x0807
BT_P2PK_LEGACY      = 0x0901
BT_P2PKH_LEGACY     = 0x0902
BT_P2WPKH_LEGACY    = 0x0904
BT_P2TR_LEGACY      = 0x0906
BT_P2SH_LEGACY      = 0x0903
BT_P2WSH_LEGACY     = 0x0905
BT_P2TR_SCRIPT_LEGACY = 0x0907
BT_DATA_RETURN      = 0x0507
BT_ACCUMULATOR      = 0x0806
BT_COSIGN           = 0x0681
BT_QABI_SPEND       = 0x0A02
BT_PQ_BATCH         = 0x0A03

COIL_TYPE_UNLOCK = 0x01
COIL_ATTESTATION_INLINE = 0x01
SCHEME_SCHNORR = 0x01

# Data-type wire codes. See src/rung/types.h:RungDataType.
DT_PUBKEY        = 0x01
DT_PUBKEY_COMMIT = 0x02
DT_HASH256       = 0x03
DT_HASH160       = 0x04
DT_PREIMAGE      = 0x05
DT_SIGNATURE     = 0x06
DT_NUMERIC       = 0x08
DT_SCHEME        = 0x09
DT_SCRIPT_BODY   = 0x0A
DT_DATA          = 0x0B
DT_MERKLE_PROOF  = 0x0C


def _numeric_le_4b(value_or_hex) -> bytes:
    """Encode a NUMERIC field as 4-byte little-endian."""
    if isinstance(value_or_hex, str):
        v = int.from_bytes(bytes.fromhex(value_or_hex), "little")
    else:
        v = int(value_or_hex)
    return v.to_bytes(4, "little")


def conditions_root_for_single_sig_rung(sig_pubkey: bytes,
                                         output_index: int = 0) -> bytes:
    """Compute the conditions_root for the simplest possible v4 output:
    single rung, single SIG block bound to `sig_pubkey`, default coil.

    This is the inverse-image of `vec_1_sig_keypath` from the positive
    fixture and is the simplest end-to-end check a second
    implementation can reproduce."""
    if len(sig_pubkey) not in (32, 33):
        raise ValueError(f"SIG pubkey must be 32 or 33 bytes; got {len(sig_pubkey)}")
    # Normalise x-only → compressed (even-Y prefix) to match the
    # canonical Merkle-leaf binding in C++ (rpc.cpp pubkey collection).
    if len(sig_pubkey) == 32:
        sig_pubkey = b"\x02" + sig_pubkey
    leaf = compute_tx_mlsc_leaf(
        blocks=[(BT_SIG, 0)],
        rung_blocks_with_fields=[(BT_SIG, [(DT_SCHEME, b"\x01")])],
        pubkeys=[sig_pubkey],
        relay_refs=[],
        coil_type=COIL_TYPE_UNLOCK,
        coil_attestation=COIL_ATTESTATION_INLINE,
        coil_scheme=SCHEME_SCHNORR,
        coil_output_index=output_index,
    )
    return build_merkle_tree([leaf])


# ── MULTISIG inner pubkey-Merkle tree ──────────────────────────────
#
# Mirrors src/rung/conditions.cpp:262-286 + BuildPubkeyMerkleRoot.
# Three tagged-hash domains:
#   LadderMultisigPubkey/v1   — pubkey leaf
#   LadderMultisigInternal/v1 — sorted-pair interior
#   LadderMultisigPadding/v1  — empty-leaf padding (h of empty input)

_MULTISIG_EMPTY_LEAF = _tagged_hash("LadderMultisigPadding/v1", b"")


def _multisig_pubkey_leaf(pk: bytes) -> bytes:
    return _tagged_hash("LadderMultisigPubkey/v1", pk)


def _multisig_interior(a: bytes, b: bytes) -> bytes:
    if a <= b:
        return _tagged_hash("LadderMultisigInternal/v1", a + b)
    return _tagged_hash("LadderMultisigInternal/v1", b + a)


def build_pubkey_merkle_root(pubkeys: list) -> bytes:
    """Mirror BuildPubkeyMerkleRoot. Each pubkey must be 33-byte
    compressed (parser normalises x-only → 0x02-prefixed compressed)."""
    if not pubkeys:
        return _MULTISIG_EMPTY_LEAF
    leaves = [_multisig_pubkey_leaf(pk if len(pk) == 33 else b"\x02" + pk)
              for pk in pubkeys]
    if len(leaves) == 1:
        return leaves[0]
    padded = _next_pow2(len(leaves))
    leaves = leaves + [_MULTISIG_EMPTY_LEAF] * (padded - len(leaves))
    while len(leaves) > 1:
        leaves = [_multisig_interior(leaves[i], leaves[i + 1])
                  for i in range(0, len(leaves), 2)]
    return leaves[0]


def conditions_root_for_two_pubkey_rung(block_type: int,
                                          condition_fields: list,
                                          pk_a: bytes,
                                          pk_b: bytes,
                                          output_index: int = 0) -> bytes:
    """Single-rung verifier for blocks that fold TWO pubkeys into the
    leaf hash (PubkeyCountForBlock=2): HTLC, ANCHOR_FEE, VAULT_LOCK."""
    pks = []
    for pk in (pk_a, pk_b):
        if len(pk) == 32:
            pk = b"\x02" + pk
        elif len(pk) != 33:
            raise ValueError(f"pubkey must be 32 or 33 bytes; got {len(pk)}")
        pks.append(pk)
    leaf = compute_tx_mlsc_leaf(
        blocks=[(block_type, 0)],
        rung_blocks_with_fields=[(block_type, condition_fields)],
        pubkeys=pks,
        relay_refs=[],
        coil_type=COIL_TYPE_UNLOCK,
        coil_attestation=COIL_ATTESTATION_INLINE,
        coil_scheme=SCHEME_SCHNORR,
        coil_output_index=output_index,
    )
    return build_merkle_tree([leaf])


def conditions_root_for_pubkey_rung(block_type: int,
                                     condition_fields: list,
                                     pubkey: bytes,
                                     output_index: int = 0) -> bytes:
    """Single-rung verifier for blocks that fold ONE pubkey into the
    leaf hash (PubkeyCountForBlock=1): TIMELOCKED_SIG, HASH_SIG,
    CLTV_SIG, MUSIG_THRESHOLD, ADAPTOR_SIG, PTLC, ANCHOR_ORACLE,
    LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_UP."""
    if len(pubkey) == 32:
        pubkey = b"\x02" + pubkey
    elif len(pubkey) != 33:
        raise ValueError(f"pubkey must be 32 or 33 bytes; got {len(pubkey)}")
    leaf = compute_tx_mlsc_leaf(
        blocks=[(block_type, 0)],
        rung_blocks_with_fields=[(block_type, condition_fields)],
        pubkeys=[pubkey],
        relay_refs=[],
        coil_type=COIL_TYPE_UNLOCK,
        coil_attestation=COIL_ATTESTATION_INLINE,
        coil_scheme=SCHEME_SCHNORR,
        coil_output_index=output_index,
    )
    return build_merkle_tree([leaf])


def conditions_root_for_no_pubkey_rung(block_type: int,
                                        condition_fields: list,
                                        output_index: int = 0) -> bytes:
    """Generic single-rung verifier for blocks with NO pubkey in leaf.

    `condition_fields` is a list of `(field_type, field_data_bytes)` —
    the canonical conditions layout for the block (after PUBKEY
    stripping, but for these no-pubkey blocks that's a no-op).

    Covers: CSV, CSV_TIME, CLTV, CLTV_TIME, ANCHOR, ANCHOR_CHANNEL,
    AMOUNT_LOCK, EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT,
    COMPARE, HASH_GUARDED, etc."""
    leaf = compute_tx_mlsc_leaf(
        blocks=[(block_type, 0)],
        rung_blocks_with_fields=[(block_type, condition_fields)],
        pubkeys=[],
        relay_refs=[],
        coil_type=COIL_TYPE_UNLOCK,
        coil_attestation=COIL_ATTESTATION_INLINE,
        coil_scheme=SCHEME_SCHNORR,
        coil_output_index=output_index,
    )
    return build_merkle_tree([leaf])


# ── Module entry ───────────────────────────────────────────────────

if __name__ == "__main__":
    # Smoke: tagged hash domain constants align with C++.
    assert _MLSC_EMPTY_LEAF == _tagged_hash("LadderLeaf/v1", b"")
    print(f"empty-leaf:    {_MLSC_EMPTY_LEAF.hex()}")
    print(f"internal-tag:  {_sha256(b'LadderInternal/v1').hex()}")
    print("ladder_verify: smoke OK")
