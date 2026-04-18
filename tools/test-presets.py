#!/usr/bin/env python3
"""
Automated Fund+Spend test for all Ladder Engine preset examples.
Calls the ghost-core signet RPC proxy to:
  1. Generate keypairs (replacing fake pubkeys)
  2. Generate preimages (replacing fake hashes)
  3. Build wire-format createrungtx payloads
  4. Create → Sign → Broadcast → Mine for each preset
  5. Spend the first rung of each funded output
  6. Report pass/fail per preset

Usage: python3 test-presets.py [--api URL] [--preset NAME] [--fund-only] [--spend-only TXID:VOUT]
"""

import json, os, sys, time, struct, hashlib, argparse, traceback, copy
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# Pure-Python RIPEMD-160 (OpenSSL 3.0+ disables it)
def _ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 hash, pure Python fallback when hashlib doesn't support it."""
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        pass
    # Pure Python implementation
    def _f(x, y, z, i):
        if i == 0: return x ^ y ^ z
        if i == 1: return (x & y) | (~x & z)
        if i == 2: return (x | ~y) ^ z
        if i == 3: return (x & z) | (y & ~z)
        return x ^ (y | ~z)
    def _rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    _K  = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    _KP = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    _R  = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
           7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
           3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
           1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
           4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    _RP = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
           6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
           15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
           8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
           12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    _S  = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
           7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
           11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
           11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
           9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    _SP = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
           9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
           9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
           15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
           8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    msg = bytearray(data)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len * 8)
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    MK = 0xFFFFFFFF
    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[i:i+64]))
        a, b, c, d, e = h0, h1, h2, h3, h4
        ap, bp, cp, dp, ep = h0, h1, h2, h3, h4
        for j in range(80):
            rnd = j >> 4
            t = (a + _f(b, c, d, rnd) + X[_R[j]] + _K[rnd]) & MK
            t = (_rol(t, _S[j]) + e) & MK
            a, e, d, c, b = e, d, _rol(c, 10), b, t
            rnd = j >> 4
            t = (ap + _f(bp, cp, dp, 4 - rnd) + X[_RP[j]] + _KP[rnd]) & MK
            t = (_rol(t, _SP[j]) + ep) & MK
            ap, ep, dp, cp, bp = ep, dp, _rol(cp, 10), bp, t
        t = (h1 + c + dp) & MK
        h1 = (h2 + d + ep) & MK
        h2 = (h3 + e + ap) & MK
        h3 = (h4 + a + bp) & MK
        h4 = (h0 + b + cp) & MK
        h0 = t
    return struct.pack('<5I', h0, h1, h2, h3, h4)

def hash160(data: bytes) -> bytes:
    """HASH160 = RIPEMD160(SHA256(data))"""
    return _ripemd160(hashlib.sha256(data).digest())

API = "http://localhost:8801"

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def api(endpoint, body=None, silent=False, retries=5):
    url = API + endpoint
    # Mining on signet takes ~15s/block (grind), so /mine needs long timeouts.
    # CSV spends that mine 50+ blocks can take 12+ minutes.
    mine_timeout = 900 if "/mine" in endpoint else 120
    for attempt in range(retries):
        if body is not None:
            req = Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
        else:
            req = Request(url)
        try:
            with urlopen(req, timeout=mine_timeout) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read()).get("detail", {})
                if isinstance(detail, dict):
                    detail = detail.get("rpc_error", str(detail))
            except:
                pass
            if e.code == 429 and attempt < retries - 1:
                wait = 15 * (attempt + 1)
                print(f"  Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            if not silent:
                print(f"  API ERROR {endpoint}: {e.code} — {detail}")
            raise RuntimeError(f"API {endpoint}: {e.code} — {detail}")
        except URLError as e:
            raise RuntimeError(f"API unreachable: {e.reason}")

def to_numeric_hex(val):
    n = int(val) if val else 0
    return struct.pack("<i", n).hex()

def from_numeric_hex(h):
    if not h or len(h) < 2:
        return 0
    b = bytes.fromhex(h.ljust(8, '0')[:8])
    return struct.unpack("<i", b)[0]

def sha256(data):
    return hashlib.sha256(data).digest()

def sorted_pair_hash(a_hex, b_hex):
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    if a <= b:
        combined = a + b
    else:
        combined = b + a
    return sha256(combined).hex()

def compute_ctv_hash(version, locktime, num_inputs, sequences, num_outputs, outputs_blob, input_index):
    """Compute BIP-119 CheckTemplateVerify hash (matches ComputeCTVHash in evaluator.cpp).
    SHA256(version || locktime || scriptsigs_hash || num_inputs || sequences_hash ||
           num_outputs || outputs_hash || input_index)
    All integers are 4 bytes LE except where noted.
    """
    # scriptsigs hash: SHA256 of all scriptSigs concatenated (empty for v4 RUNG_TX)
    scriptsigs_hash = sha256(b"")
    # sequences hash: SHA256 of all sequences (each 4 bytes LE)
    seq_data = b""
    for seq in sequences:
        seq_data += struct.pack("<I", seq)
    sequences_hash = sha256(seq_data)
    # outputs hash: SHA256 of all outputs (amount 8B LE + spk_len 8B LE + spk data)
    outputs_hash = sha256(outputs_blob)

    h = hashlib.sha256()
    h.update(struct.pack("<I", version))
    h.update(struct.pack("<I", locktime))
    h.update(scriptsigs_hash)
    h.update(struct.pack("<I", num_inputs))
    h.update(sequences_hash)
    h.update(struct.pack("<I", num_outputs))
    h.update(outputs_hash)
    h.update(struct.pack("<I", input_index))
    return h.hexdigest()

def serialize_ctv_output(amount_sats, script_pubkey_hex):
    """Serialize a TX output for CTV hash (amount 8B LE + spk_len 8B LE + spk data)."""
    spk = bytes.fromhex(script_pubkey_hex)
    result = struct.pack("<Q", amount_sats)
    result += struct.pack("<Q", len(spk))
    result += spk
    return result

def merkle_root(leaves):
    if not leaves:
        return "0" * 64
    if len(leaves) == 1:
        return leaves[0]
    level = list(leaves)
    while level and (len(level) & (len(level) - 1)):
        level.append(level[-1])
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(sorted_pair_hash(level[i], level[i+1]))
        level = nxt
    return level[0]

def merkle_proof(leaves, idx):
    if len(leaves) <= 1:
        return {"siblings": [], "leaf": leaves[0] if leaves else "0"*64}
    level = list(leaves)
    while level and (len(level) & (len(level) - 1)):
        level.append(level[-1])
    siblings = []
    cur = idx
    while len(level) > 1:
        sib = cur + 1 if cur % 2 == 0 else cur - 1
        siblings.append(level[sib])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(sorted_pair_hash(level[i], level[i+1]))
        level = nxt
        cur = cur // 2
    return {"siblings": siblings, "leaf": leaves[idx]}


# ═══════════════════════════════════════════════════════════════
# BLOCK TYPE FIELD DEFINITIONS
# ═══════════════════════════════════════════════════════════════

# Maps block type -> list of { name, dataType, multi?, noWire? }
BLOCK_FIELDS = {
    "SIG": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "MULTISIG": [
        {"name": "threshold", "dataType": "NUMERIC"},
        {"name": "pubkeys", "dataType": "PUBKEY", "multi": True},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "ADAPTOR_SIG": [
        {"name": "signing_key", "dataType": "PUBKEY"},
        {"name": "adaptor_point", "dataType": "PUBKEY"},
    ],
    "MUSIG_THRESHOLD": [
        {"name": "agg_pubkey", "dataType": "PUBKEY"},
        {"name": "threshold", "dataType": "NUMERIC"},
        {"name": "group_size", "dataType": "NUMERIC"},
    ],
    "KEY_REF_SIG": [
        {"name": "relay_index", "dataType": "NUMERIC"},
        {"name": "block_index", "dataType": "NUMERIC"},
    ],
    "CSV": [{"name": "blocks", "dataType": "NUMERIC"}],
    "CSV_TIME": [{"name": "seconds", "dataType": "NUMERIC"}],
    "CLTV": [{"name": "height", "dataType": "NUMERIC"}],
    "CLTV_TIME": [{"name": "timestamp", "dataType": "NUMERIC"}],
    # HASH_PREIMAGE/HASH160_PREIMAGE removed — deprecated, use HASH_SIG or HTLC
    "TAGGED_HASH": [
        {"name": "tag", "dataType": "HASH256"},
        {"name": "hash", "dataType": "HASH256"},
    ],
    "CTV": [{"name": "template_hash", "dataType": "HASH256"}],
    "VAULT_LOCK": [
        {"name": "recovery_key", "dataType": "PUBKEY"},
        {"name": "hot_key", "dataType": "PUBKEY"},
        {"name": "delay", "dataType": "NUMERIC"},
    ],
    "AMOUNT_LOCK": [
        {"name": "min", "dataType": "NUMERIC"},
        {"name": "max", "dataType": "NUMERIC"},
    ],
    "RECURSE_SAME": [{"name": "max_depth", "dataType": "NUMERIC"}],
    "RECURSE_MODIFIED": [
        {"name": "max_depth", "dataType": "NUMERIC"},
        {"name": "block_idx", "dataType": "NUMERIC"},
        {"name": "param_idx", "dataType": "NUMERIC"},
        {"name": "delta", "dataType": "NUMERIC"},
    ],
    "RECURSE_UNTIL": [{"name": "target_height", "dataType": "NUMERIC"}],
    "RECURSE_COUNT": [{"name": "remaining", "dataType": "NUMERIC"}],
    "RECURSE_SPLIT": [
        {"name": "max_splits", "dataType": "NUMERIC"},
        {"name": "min_sats", "dataType": "NUMERIC"},
    ],
    "RECURSE_DECAY": [
        {"name": "max_depth", "dataType": "NUMERIC"},
        {"name": "block_idx", "dataType": "NUMERIC"},
        {"name": "param_idx", "dataType": "NUMERIC"},
        {"name": "decay_per_step", "dataType": "NUMERIC"},
    ],
    "ANCHOR": [{"name": "anchor_id", "dataType": "NUMERIC"}],
    "ANCHOR_CHANNEL": [
        {"name": "local_key", "dataType": "PUBKEY"},
        {"name": "remote_key", "dataType": "PUBKEY"},
        {"name": "commitment_number", "dataType": "NUMERIC"},
    ],
    "ANCHOR_POOL": [
        {"name": "pool_id", "dataType": "PREIMAGE"},
        {"name": "participant_count", "dataType": "NUMERIC"},
    ],
    "ANCHOR_RESERVE": [
        {"name": "threshold_n", "dataType": "NUMERIC"},
        {"name": "threshold_m", "dataType": "NUMERIC"},
        {"name": "guardian_hash", "dataType": "PREIMAGE"},
    ],
    "ANCHOR_SEAL": [
        {"name": "asset_id", "dataType": "PREIMAGE"},
        {"name": "state_hash", "dataType": "PREIMAGE"},
    ],
    "ANCHOR_ORACLE": [
        {"name": "oracle_pk", "dataType": "PUBKEY"},
        {"name": "outcome_count", "dataType": "NUMERIC"},
    ],
    "HYSTERESIS_FEE": [
        {"name": "high_sat_vb", "dataType": "NUMERIC"},
        {"name": "low_sat_vb", "dataType": "NUMERIC"},
    ],
    "HYSTERESIS_VALUE": [
        {"name": "high_sats", "dataType": "NUMERIC"},
        {"name": "low_sats", "dataType": "NUMERIC"},
    ],
    "TIMER_CONTINUOUS": [
        {"name": "accumulated", "dataType": "NUMERIC"},
        {"name": "target", "dataType": "NUMERIC"},
    ],
    "TIMER_OFF_DELAY": [{"name": "remaining", "dataType": "NUMERIC"}],
    "LATCH_SET": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "state", "dataType": "NUMERIC"},
    ],
    "LATCH_RESET": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "state", "dataType": "NUMERIC"},
        {"name": "delay", "dataType": "NUMERIC"},
    ],
    "COUNTER_DOWN": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "count", "dataType": "NUMERIC"},
    ],
    "COUNTER_PRESET": [
        {"name": "current", "dataType": "NUMERIC"},
        {"name": "preset", "dataType": "NUMERIC"},
    ],
    "COUNTER_UP": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "current", "dataType": "NUMERIC"},
        {"name": "target", "dataType": "NUMERIC"},
    ],
    "COMPARE": [
        {"name": "operator", "dataType": "NUMERIC"},
        {"name": "value_b", "dataType": "NUMERIC"},
        {"name": "value_c", "dataType": "NUMERIC"},
    ],
    "SEQUENCER": [
        {"name": "current", "dataType": "NUMERIC"},
        {"name": "total", "dataType": "NUMERIC"},
    ],
    "ONE_SHOT": [
        {"name": "state", "dataType": "NUMERIC"},
        {"name": "commitment", "dataType": "PREIMAGE"},
    ],
    "RATE_LIMIT": [
        {"name": "max_per_block", "dataType": "NUMERIC"},
        {"name": "acc_cap", "dataType": "NUMERIC"},
        {"name": "refill_blocks", "dataType": "NUMERIC"},
    ],
    "COSIGN": [{"name": "conditions_hash", "dataType": "HASH256"}],
    "TIMELOCKED_SIG": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "blocks", "dataType": "NUMERIC"},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "HTLC": [
        {"name": "hash", "dataType": "PREIMAGE"},
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "pubkey2", "dataType": "PUBKEY"},
        {"name": "blocks", "dataType": "NUMERIC"},
    ],
    "HASH_SIG": [
        {"name": "hash", "dataType": "PREIMAGE"},
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "PTLC": [
        {"name": "signing_key", "dataType": "PUBKEY"},
        {"name": "adaptor_point", "dataType": "PUBKEY"},
        {"name": "blocks", "dataType": "NUMERIC"},
    ],
    "CLTV_SIG": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "height", "dataType": "NUMERIC"},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "TIMELOCKED_MULTISIG": [
        {"name": "threshold", "dataType": "NUMERIC"},
        {"name": "pubkeys", "dataType": "PUBKEY", "multi": True},
        {"name": "blocks", "dataType": "NUMERIC"},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "EPOCH_GATE": [
        {"name": "epoch_size", "dataType": "NUMERIC"},
        {"name": "window_size", "dataType": "NUMERIC"},
    ],
    "WEIGHT_LIMIT": [{"name": "max_weight", "dataType": "NUMERIC"}],
    "INPUT_COUNT": [
        {"name": "min", "dataType": "NUMERIC"},
        {"name": "max", "dataType": "NUMERIC"},
    ],
    "OUTPUT_COUNT": [
        {"name": "min", "dataType": "NUMERIC"},
        {"name": "max", "dataType": "NUMERIC"},
    ],
    "RELATIVE_VALUE": [
        {"name": "numerator", "dataType": "NUMERIC"},
        {"name": "denominator", "dataType": "NUMERIC"},
    ],
    "ACCUMULATOR": [
        {"name": "merkle_root", "dataType": "HASH256"},
        {"name": "merkle_leaves", "dataType": "HASH256", "multi": True, "noWire": True},
    ],
    "P2PK_LEGACY": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "P2PKH_LEGACY": [
        {"name": "pubkey", "dataType": "PUBKEY"},
    ],
    "P2SH_LEGACY": [
        {"name": "hash160", "dataType": "HASH160"},
    ],
    "P2WPKH_LEGACY": [
        {"name": "pubkey", "dataType": "PUBKEY"},
    ],
    "P2WSH_LEGACY": [
        {"name": "hash256", "dataType": "HASH256"},
    ],
    "P2TR_LEGACY": [
        {"name": "pubkey", "dataType": "PUBKEY"},
        {"name": "scheme", "dataType": "SCHEME", "optional": True},
    ],
    "P2WSH_LEGACY": [
        {"name": "script_body", "dataType": "PREIMAGE"},
    ],
    "P2TR_SCRIPT_LEGACY": [
        {"name": "script_hash", "dataType": "PREIMAGE"},
        {"name": "internal_pubkey", "dataType": "PUBKEY"},
    ],
    "QABI_PRIME": [],
    "QABI_SPEND": [
        {"name": "auth_tip", "dataType": "HASH256"},
        {"name": "committed_root", "dataType": "HASH256"},
        {"name": "committed_depth", "dataType": "NUMERIC"},
        {"name": "committed_expiry", "dataType": "NUMERIC"},
        {"name": "owner_id", "dataType": "PUBKEY_COMMIT"},
    ],
    "P2TR_SCRIPT_LEGACY": [
        {"name": "hash256", "dataType": "HASH256"},
        {"name": "pubkey_commit", "dataType": "HASH256"},
    ],
}

SCHEME_MAP = {"SCHNORR": "01", "ECDSA": "02", "FALCON512": "10", "FALCON1024": "11", "DILITHIUM3": "12", "SPHINCS_SHA": "13"}

# Block types that need keys for funding
KEY_BLOCKS = {
    "SIG": [("pubkey", False)],
    "MULTISIG": [("pubkeys", True)],
    "ADAPTOR_SIG": [("signing_key", False)],
    "MUSIG_THRESHOLD": [("agg_pubkey", False)],
    "TIMELOCKED_SIG": [("pubkey", False)],
    "HTLC": [("pubkey", False)],
    "HASH_SIG": [("pubkey", False)],
    "PTLC": [("signing_key", False)],
    "CLTV_SIG": [("pubkey", False)],
    "TIMELOCKED_MULTISIG": [("pubkeys", True)],
    "VAULT_LOCK": [("recovery_key", False), ("hot_key", False)],
    "LATCH_SET": [("pubkey", False)],
    "LATCH_RESET": [("pubkey", False)],
    "COUNTER_DOWN": [("pubkey", False)],
    "COUNTER_UP": [("pubkey", False)],
    "ANCHOR_CHANNEL": [("local_key", False), ("remote_key", False)],
    "ANCHOR_ORACLE": [("oracle_pk", False)],
    "P2PK_LEGACY": [("pubkey", False)],
    "P2PKH_LEGACY": [("pubkey", False)],
    "P2WPKH_LEGACY": [("pubkey", False)],
    "P2TR_LEGACY": [("pubkey", False)],
}

# Block types that need hash preimages
HASH_BLOCKS = {
    "TAGGED_HASH": ("hash", "tagged"),
    "HTLC": ("hash", "sha256"),
    "HASH_SIG": ("hash", "sha256"),
    "ONE_SHOT": ("commitment", "sha256"),
}

# Recursion block types
RECURSE_TYPES = {"RECURSE_SAME", "RECURSE_MODIFIED", "RECURSE_UNTIL", "RECURSE_COUNT", "RECURSE_SPLIT", "RECURSE_DECAY"}
MUTATION_TYPES = {"RECURSE_MODIFIED", "RECURSE_DECAY"}

# Timelock block types
TIMELOCK_CSV = {"CSV", "TIMELOCKED_SIG", "HTLC", "PTLC", "TIMELOCKED_MULTISIG", "VAULT_LOCK", "TIMER_OFF_DELAY", "LATCH_RESET"}
TIMELOCK_CLTV = {"CLTV", "CLTV_SIG"}
TIMELOCK_CSV_TIME = {"CSV_TIME"}
TIMELOCK_CLTV_TIME = {"CLTV_TIME"}

# Validation block types (no witness data, just constraints)
VALIDATION_TYPES = {"AMOUNT_LOCK", "HYSTERESIS_FEE", "HYSTERESIS_VALUE", "RATE_LIMIT",
                    "EPOCH_GATE", "WEIGHT_LIMIT", "INPUT_COUNT", "OUTPUT_COUNT", "RELATIVE_VALUE", "ACCUMULATOR"}


def export_block_fields(block, values):
    """Convert block values dict to wire format fields list."""
    btype = block["type"]
    field_defs = BLOCK_FIELDS.get(btype, [])
    fields = []
    for fd in field_defs:
        if fd.get("noWire"):
            continue
        val = values.get(fd["name"], "")
        if not val:
            continue
        dt = fd["dataType"]
        if dt == "NUMERIC":
            fields.append({"type": "NUMERIC", "hex": to_numeric_hex(val)})
        elif dt == "PUBKEY":
            if fd.get("multi"):
                for k in str(val).split(","):
                    k = k.strip()
                    if k:
                        fields.append({"type": "PUBKEY", "hex": k})
            else:
                fields.append({"type": "PUBKEY", "hex": str(val)})
        elif dt == "HASH256":
            fields.append({"type": "HASH256", "hex": str(val)})
        elif dt == "HASH160":
            fields.append({"type": "HASH160", "hex": str(val)})
        elif dt == "PREIMAGE":
            fields.append({"type": "PREIMAGE", "hex": str(val)})
        elif dt == "PUBKEY_COMMIT":
            fields.append({"type": "PUBKEY_COMMIT", "hex": str(val)})
        elif dt == "SCHEME":
            code = SCHEME_MAP.get(str(val), "01")
            fields.append({"type": "SCHEME", "hex": code})
    result = {"type": btype, "fields": fields}
    if block.get("inverted"):
        result["inverted"] = True
    return result


# is_compact_sig_eligible removed — COMPACT_SIG was a deprecated
# rung-encoding that stored PUBKEY_COMMIT on the rung itself, defeating
# merkle_pub_key. Deleted from the core wire format; the driver now
# emits standard SIG blocks that carry PUBKEY as a normal field.


# ═══════════════════════════════════════════════════════════════
# PRESET DEFINITIONS (mirrors EXAMPLES[] in index.html)
# ═══════════════════════════════════════════════════════════════

# Fake data placeholders (same as engine)
FAKE = {
    "pk1": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "pk2": "03f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a3928170605f4e3d2c1b0",
    "pk3": "02b4c5d6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f7081920a",
    "pk4": "03aabb112233445566778899aabbccddeeff0011223344556677889900aabbccdd",
    "pk5": "0211223344556677889900aabbccddeeff0011223344556677889900aabbccddee",
    "oracle": "02ffee112233445566778899aabbccddeeff112233445566778899aabbccddeeff",
    "hash1": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "hash2": "f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687",
    "hash3": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "hash4": "deadbeefcafebabe0123456789abcdefdeadbeefcafebabe0123456789abcdef",
}
FAKE_PQ = {
    "falcon1": "f512a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    "falcon2": "f512ff00ee11dd22cc33bb44aa5599668877f512ff00ee11dd22cc33bb44aa5599668877ff00ee11dd22cc33bb44aa5599668877ff00ee11dd22cc33bb44aa559966",
    "dilith1": "d3aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677889900aabb",
    "dilith2": "d3ff11ee22dd33cc44bb55aa66997788d3ff11ee22dd33cc44bb55aa66997788ff11ee22dd33cc44bb55aa66997788ff11ee22dd33cc44bb55aa6699778800112233",
    "falcon1024": "f1024aa1bb2cc3dd4ee5ff6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7",
    "sphincs1": "sph256aa00bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff001122334455667788",
}

PRESETS = [
    {
        "title": "2-of-3 MULTISIG VAULT",
        "rungs": [
            {"label": "SPEND", "blocks": [
                {"type": "MULTISIG", "values": {"threshold": "2", "pubkeys": f"{FAKE['pk1']}, {FAKE['pk2']}, {FAKE['pk3']}"}},
            ]},
            {"label": "RECOVER", "blocks": [
                {"type": "CSV", "values": {"blocks": "52560"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk4"]}},
            ]},
        ],
        "outputs": [{"amount": 45000}, {"amount": 5000}],
    },
    {
        "title": "ATOMIC SWAP (HTLC)",
        "rungs": [
            {"label": "CLAIM", "blocks": [
                {"type": "HASH_SIG", "values": {"hash": FAKE["hash1"], "pubkey": FAKE["pk1"]}},
            ]},
            {"label": "REFUND", "blocks": [
                {"type": "CSV", "values": {"blocks": "144"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 10000}, {"amount": 9900}],
    },
    {
        "title": "ADAPTOR SIG SWAP",
        "rungs": [
            {"label": "EXECUTE", "blocks": [
                {"type": "ADAPTOR_SIG", "values": {"signing_key": FAKE["pk1"], "adaptor_point": FAKE["hash1"][:64]}},
            ]},
            {"label": "CANCEL", "blocks": [
                {"type": "CSV", "values": {"blocks": "288"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 25000}, {"amount": 24800}],
    },
    {
        "title": "DCA COVENANT CHAIN",
        "rungs": [
            {"label": "BUY", "blocks": [
                {"type": "COUNTER_DOWN", "values": {"pubkey": FAKE["pk1"], "count": "12"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "50000", "max": "100000"}},
                {"type": "RECURSE_MODIFIED", "values": {"max_depth": "10", "block_idx": "0", "param_idx": "0", "delta": "-1"}},
            ]},
            {"label": "SWEEP", "blocks": [
                {"type": "COUNTER_DOWN", "values": {"pubkey": FAKE["pk1"], "count": "0"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
        ],
        "outputs": [{"amount": 833}, {"amount": 9166}],
    },
    {
        "title": "VAULT WITH UNVAULT + CLAWBACK",
        "rungs": [
            {"label": "UNVAULT", "blocks": [
                {"type": "VAULT_LOCK", "values": {"recovery_key": FAKE["pk3"], "hot_key": FAKE["pk1"], "delay": "10"}},
            ]},
            {"label": "CLAWBACK", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk3"]}},
            ]},
        ],
        "outputs": [{"amount": 100000}, {"amount": 99900}],
    },
    {
        "title": "RATE-LIMITED WALLET",
        "rungs": [
            {"label": "DAY_SPEND", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "RATE_LIMIT", "values": {"max_per_block": "50000", "acc_cap": "200000", "refill_blocks": "144"}},
            ]},
            {"label": "OVERRIDE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 50000}, {"amount": 50000}],
    },
    {
        "title": "DEAD MAN'S SWITCH (INHERITANCE)",
        "rungs": [
            {"label": "ALIVE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "LATCH_SET", "values": {"pubkey": FAKE["pk1"], "state": "0"}},
                {"type": "RECURSE_SAME", "values": {"max_depth": "10"}},
            ]},
            {"label": "INHERIT", "blocks": [
                {"type": "CSV", "values": {"blocks": "26000"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 250000}, {"amount": 249900}],
    },
    {
        "title": "ESCROW WITH ORACLE",
        "spend_rung": 2,  # Use SETTLE rung (no oracle/cosign needed)
        "rungs": [
            {"label": "RELEASE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ANCHOR_ORACLE", "values": {"oracle_pk": FAKE["oracle"], "outcome_count": "2"}},
                {"type": "COSIGN", "values": {"conditions_hash": FAKE["hash3"]}},
            ]},
            {"label": "DISPUTE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
                {"type": "ANCHOR_ORACLE", "values": {"oracle_pk": FAKE["oracle"], "outcome_count": "2"}},
                {"type": "COSIGN", "values": {"conditions_hash": FAKE["hash4"]}},
            ]},
            {"label": "SETTLE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 7500}, {"amount": 7500}, {"amount": 7400}],
    },
    {
        "title": "PAYMENT CHANNEL",
        "rungs": [
            {"label": "COOP", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
            {"label": "FORCE_A", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "CSV_TIME", "values": {"seconds": "86400"}},
                {"type": "CTV", "values": {"template_hash": FAKE["hash2"]}},
            ]},
            {"label": "FORCE_B", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
                {"type": "CSV_TIME", "values": {"seconds": "86400"}},
                {"type": "CTV", "values": {"template_hash": FAKE["hash3"]}},
            ]},
        ],
        "outputs": [{"amount": 30000}, {"amount": 20000}, {"amount": 20000}],
    },
    {
        "title": "SEQUENCED PAYOUT",
        "rungs": [
            {"label": "MILE", "blocks": [
                {"type": "SEQUENCER", "values": {"current": "0", "total": "5"}},
                {"type": "ANCHOR_ORACLE", "values": {"oracle_pk": FAKE["oracle"], "outcome_count": "2"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
                {"type": "AMOUNT_LOCK", "values": {"min": "100000", "max": "200000"}},
                {"type": "RECURSE_MODIFIED", "values": {"max_depth": "10", "block_idx": "0", "param_idx": "0", "delta": "1"}},
            ]},
            {"label": "CANCEL", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 2000}, {"amount": 8000}],
    },
    {
        "title": "FEE-GATED COVENANT",
        "rungs": [
            {"label": "SEND", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "HYSTERESIS_FEE", "values": {"high_sat_vb": "50", "low_sat_vb": "5"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "10000", "max": "500000"}},
            ]},
            {"label": "EMERG", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk3"]}},
            ]},
        ],
        "outputs": [{"amount": 50000}, {"amount": 30000}],
    },
    {
        "title": "ONE-SHOT TRIGGER + LATCH",
        "spend_rung": 1,  # Use EXEC rung (ONE_SHOT needs commitment handling, skip for now)
        "rungs": [
            {"label": "FIRE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ONE_SHOT", "values": {"state": "0", "commitment": FAKE["hash1"]}},
            ]},
            {"label": "EXEC", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
            {"label": "RESET", "blocks": [
                {"type": "LATCH_RESET", "values": {"pubkey": FAKE["pk3"], "state": "1", "delay": "6"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk3"]}},
            ]},
        ],
        "outputs": [{"amount": 1000}, {"amount": 5000}, {"amount": 4000}],
    },
    {
        "title": "RECURSIVE SPLIT (TREE)",
        "rungs": [
            {"label": "SPLIT", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "RECURSE_SPLIT", "values": {"max_splits": "3", "min_sats": "2000"}},
            ]},
        ],
        "outputs": [{"amount": 20000}],
    },
    {
        "title": "BLOCK-HEIGHT TIMELOCK + COMPARE",
        "rungs": [
            {"label": "SPEND", "blocks": [
                {"type": "CLTV", "values": {"height": "50"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "COMPARE", "values": {"operator": "3", "value_b": "10000", "value_c": "0"}},
            ]},
        ],
        "outputs": [{"amount": 15000}],
    },
    {
        "title": "COUNTER-UP SUBSCRIPTION",
        "rungs": [
            {"label": "PAY", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "COUNTER_UP", "values": {"pubkey": FAKE["pk2"], "current": "0", "target": "24"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "25000", "max": "25000"}},
                {"type": "RECURSE_MODIFIED", "values": {"max_depth": "10", "block_idx": "1", "param_idx": "0", "delta": "1"}},
            ]},
            {"label": "CANCEL", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
            {"label": "EXPIRE", "blocks": [
                {"type": "COUNTER_UP", "values": {"pubkey": FAKE["pk2"], "current": "24", "target": "24"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
        ],
        "outputs": [{"amount": 546}, {"amount": 6000}, {"amount": 5750}],
    },
    {
        "title": "QUANTUM-SAFE VAULT",
        "scheme": "FALCON512",
        "spend_rung": 2,  # Use HYBRID rung (has both PQ + standard SIG)
        "rungs": [
            {"label": "PQ_SPEND", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE_PQ["falcon1"], "scheme": "FALCON512"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "10000", "max": "5000000"}},
            ]},
            {"label": "PQ_RECOVER", "blocks": [
                {"type": "CSV", "values": {"blocks": "52560"}},
                {"type": "SIG", "values": {"pubkey": FAKE_PQ["dilith1"], "scheme": "DILITHIUM3"}},
            ]},
            {"label": "HYBRID", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE_PQ["falcon1"], "scheme": "FALCON512"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
        ],
        "outputs": [{"amount": 150000}, {"amount": 149900}, {"amount": 50000}],
    },
    {
        "title": "QUANTUM VAULT + CHILDREN",
        "scheme": "FALCON512",
        "rungs": [
            {"label": "PQ_SPLIT", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE_PQ["falcon1"], "scheme": "FALCON512"}},
                {"type": "RECURSE_SPLIT", "values": {"max_splits": "3", "min_sats": "10000"}},
            ]},
            {"label": "PQ_CHILD", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE_PQ["falcon1"], "scheme": "FALCON512"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "5000", "max": "1000000"}},
            ]},
            {"label": "PQ_EMERG", "blocks": [
                {"type": "MULTISIG", "values": {"threshold": "2", "pubkeys": f"{FAKE_PQ['falcon1']}, {FAKE_PQ['dilith1']}", "scheme": "FALCON512"}},
            ]},
            {"label": "SWEEP", "blocks": [
                {"type": "CSV", "values": {"blocks": "4320"}},
                {"type": "SIG", "values": {"pubkey": FAKE_PQ["dilith2"], "scheme": "DILITHIUM3"}},
            ]},
        ],
        "outputs": [{"amount": 50000}, {"amount": 50000}, {"amount": 100000}, {"amount": 99500}],
    },
    {
        "title": "MULTI-INPUT CONSOLIDATION",
        "rungs": [
            {"label": "MERGE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "AMOUNT_LOCK", "values": {"min": "100000", "max": "10000000"}},
                {"type": "CTV", "values": {"template_hash": "AUTO"}},
            ]},
        ],
        "outputs": [{"amount": 75000}],
        "ctv_auto": True,
    },
    {
        "title": "MUSIG_THRESHOLD TREASURY",
        "rungs": [
            {"label": "SPEND", "blocks": [
                {"type": "MUSIG_THRESHOLD", "values": {"agg_pubkey": FAKE["pk1"], "threshold": "3", "group_size": "5"}},
            ]},
            {"label": "RECOVER", "blocks": [
                {"type": "CSV", "values": {"blocks": "52560"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk4"]}},
            ]},
        ],
        "outputs": [{"amount": 95000}, {"amount": 5000}],
    },
    {
        "title": "PTLC PAYMENT CHANNEL",
        "rungs": [
            {"label": "COOP", "blocks": [
                {"type": "MUSIG_THRESHOLD", "values": {"agg_pubkey": FAKE["pk1"], "threshold": "2", "group_size": "2"}},
            ]},
            {"label": "FORCE", "blocks": [
                {"type": "PTLC", "values": {"signing_key": FAKE["pk2"], "adaptor_point": FAKE["hash1"][:64], "blocks": "144"}},
            ]},
        ],
        "outputs": [{"amount": 30000}, {"amount": 20000}],
    },
    {
        "title": "CLTV_SIG VESTING SCHEDULE",
        "rungs": [
            {"label": "Q1", "blocks": [
                {"type": "CLTV_SIG", "values": {"pubkey": FAKE["pk1"], "height": "30"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "250000", "max": "250000"}},
            ]},
            {"label": "Q2", "blocks": [
                {"type": "CLTV_SIG", "values": {"pubkey": FAKE["pk1"], "height": "40"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "250000", "max": "250000"}},
            ]},
            {"label": "FULL", "blocks": [
                {"type": "CLTV_SIG", "values": {"pubkey": FAKE["pk1"], "height": "50"}},
            ]},
        ],
        "outputs": [{"amount": 2500}, {"amount": 2500}, {"amount": 10000}],
    },
    {
        "title": "TIMELOCKED_MULTISIG VAULT RECOVERY",
        "rungs": [
            {"label": "HOT", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "AMOUNT_LOCK", "values": {"min": "546", "max": "1000000"}},
            ]},
            {"label": "BOARD", "blocks": [
                {"type": "TIMELOCKED_MULTISIG", "values": {"threshold": "2", "pubkeys": f"{FAKE['pk2']}, {FAKE['pk3']}, {FAKE['pk4']}", "blocks": "1008"}},
            ]},
            {"label": "COLD", "blocks": [
                {"type": "CSV", "values": {"blocks": "52560"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk5"]}},
            ]},
        ],
        "outputs": [{"amount": 5000}, {"amount": 45000}, {"amount": 50000}],
    },
    {
        "title": "HTLC COMPACT SWAP",
        "rungs": [
            {"label": "CLAIM", "blocks": [
                {"type": "HTLC", "values": {"hash": FAKE["hash1"], "pubkey": FAKE["pk1"], "pubkey2": FAKE["pk2"], "blocks": "144"}},
            ]},
            {"label": "REFUND", "blocks": [
                {"type": "TIMELOCKED_SIG", "values": {"pubkey": FAKE["pk2"], "blocks": "288"}},
            ]},
        ],
        "outputs": [{"amount": 10000}, {"amount": 9900}],
    },
    {
        "title": "HASH_SIG ATOMIC CLAIM",
        "rungs": [
            {"label": "CLAIM", "blocks": [
                {"type": "HASH_SIG", "values": {"hash": FAKE["hash2"], "pubkey": FAKE["pk1"]}},
            ]},
            {"label": "REFUND", "blocks": [
                {"type": "CSV", "values": {"blocks": "432"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 5000}, {"amount": 4900}],
    },
    {
        "title": "GOVERNANCE-GATED TREASURY",
        "spend_rung": 1,  # Use OVERRIDE rung (EPOCH_GATE window timing is unpredictable)
        "rungs": [
            {"label": "GOVERNED", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "EPOCH_GATE", "values": {"epoch_size": "2016", "window_size": "144"}},
                {"type": "INPUT_COUNT", "values": {"min": "1", "max": "3"}},
                {"type": "OUTPUT_COUNT", "values": {"min": "1", "max": "2"}},
                {"type": "WEIGHT_LIMIT", "values": {"max_weight": "400000"}},
                {"type": "RELATIVE_VALUE", "values": {"numerator": "9", "denominator": "10"}},
            ]},
            {"label": "OVERRIDE", "blocks": [
                {"type": "MULTISIG", "values": {"threshold": "3", "pubkeys": f"{FAKE['pk1']}, {FAKE['pk2']}, {FAKE['pk3']}, {FAKE['pk4']}"}},
            ]},
        ],
        "outputs": [{"amount": 90000}, {"amount": 9500}],
    },
    {
        "title": "ACCUMULATOR ALLOWLIST",
        "rungs": [
            {"label": "SEND", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ACCUMULATOR", "values": {"merkle_root": "", "merkle_leaves": f"{FAKE['hash1']}, {FAKE['hash2']}, {FAKE['hash3']}"}},
                {"type": "AMOUNT_LOCK", "values": {"min": "10000", "max": "5000000"}},
            ]},
            {"label": "ADMIN", "blocks": [
                {"type": "MULTISIG", "values": {"threshold": "2", "pubkeys": f"{FAKE['pk2']}, {FAKE['pk3']}, {FAKE['pk4']}"}},
            ]},
        ],
        "outputs": [{"amount": 25000}, {"amount": 70000}],
    },
    {
        "title": "CLTV_TIME CALENDAR LOCK",
        "rungs": [
            {"label": "UNLOCK", "blocks": [
                {"type": "CLTV_TIME", "values": {"timestamp": "1"}},
                {"type": "HASH_SIG", "values": {"hash": FAKE["hash1"], "pubkey": FAKE["pk1"]}},
            ]},
            {"label": "CANCEL", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk3"]}},
            ]},
        ],
        "outputs": [{"amount": 30000}, {"amount": 29800}],
    },
    {
        "title": "TIMER WATCHDOG",
        "rungs": [
            {"label": "ACTIVE", "blocks": [
                {"type": "TIMER_CONTINUOUS", "values": {"accumulated": "0", "target": "144"}, "inverted": True},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "RECURSE_MODIFIED", "values": {"max_depth": "200", "block_idx": "0", "param_idx": "0", "delta": "1"}},
            ]},
            {"label": "HELD", "blocks": [
                {"type": "TIMER_OFF_DELAY", "values": {"remaining": "72"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
            {"label": "EMERG", "blocks": [
                {"type": "CSV", "values": {"blocks": "1008"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 500000}, {"amount": 7000}, {"amount": 5000}],
        "spend_loop": 5,  # full pattern is 144 — keep test fast; the loop logic is identical
    },
    {
        "title": "PRESET COUNTER BOARD VOTE",
        "rungs": [
            {"label": "APPROVE", "blocks": [
                {"type": "COUNTER_PRESET", "values": {"current": "0", "preset": "3"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "HYSTERESIS_VALUE", "values": {"high_sats": "5000000", "low_sats": "100000"}},
                {"type": "RECURSE_MODIFIED", "values": {"max_depth": "10", "block_idx": "0", "param_idx": "0", "delta": "1"}},
            ]},
            {"label": "EXECUTE", "blocks": [
                {"type": "COUNTER_PRESET", "values": {"current": "3", "preset": "3"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
            {"label": "CANCEL", "blocks": [
                {"type": "MULTISIG", "values": {"threshold": "3", "pubkeys": f"{FAKE['pk1']}, {FAKE['pk2']}, {FAKE['pk3']}, {FAKE['pk4']}"}},
            ]},
        ],
        "outputs": [{"amount": 150000}, {"amount": 5000}, {"amount": 50000}],
    },
    {
        "title": "ANCHORED CHANNEL + RECURSE_UNTIL",
        "rungs": [
            {"label": "COOP", "blocks": [
                {"type": "MUSIG_THRESHOLD", "values": {"agg_pubkey": FAKE["pk1"], "threshold": "2", "group_size": "2"}},
                {"type": "ANCHOR_CHANNEL", "values": {"local_key": FAKE["pk1"], "remote_key": FAKE["pk2"], "commitment_number": "1"}},
            ]},
            {"label": "UPDATE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
                {"type": "ANCHOR_CHANNEL", "values": {"local_key": FAKE["pk2"], "remote_key": FAKE["pk3"], "commitment_number": "1"}},
                {"type": "RECURSE_UNTIL", "values": {"target_height": "950000"}},
            ]},
            {"label": "EXPIRE", "blocks": [
                {"type": "CLTV", "values": {"height": "950000"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk3"]}},
            ]},
        ],
        "outputs": [{"amount": 30000}, {"amount": 20000}, {"amount": 50000}],
    },
    # --- Recurse variants ---
    {
        "title": "RECURSE_COUNT COUNTDOWN",
        "rungs": [
            {"label": "COUNTDOWN", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "RECURSE_COUNT", "values": {"remaining": "5"}},
            ]},
        ],
        "outputs": [{"amount": 20000}],
    },
    {
        "title": "RECURSE_DECAY DIMINISHING RETURNS",
        "rungs": [
            {"label": "DECAY", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "AMOUNT_LOCK", "values": {"min": "10000", "max": "5000000"}},
                {"type": "RECURSE_DECAY", "values": {"max_depth": "10", "block_idx": "1", "param_idx": "0", "decay_per_step": "1000"}},
            ]},
        ],
        "outputs": [{"amount": 50000}],
    },
    # --- KEY_REF_SIG ---
    {
        "title": "KEY_REF_SIG RELAY KEY",
        "rungs": [
            {"label": "VERIFY", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "KEY_REF_SIG", "values": {"relay_index": "0", "block_index": "0"}},
            ]},
            {"label": "DIRECT", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
        ],
        "spend_rung": 1,
        "outputs": [{"amount": 10000}, {"amount": 9800}],
    },
    # --- Legacy wrappers ---
    {
        "title": "LEGACY P2PKH + RECOVERY",
        "rungs": [
            {"label": "SPEND", "blocks": [
                {"type": "P2PKH_LEGACY", "values": {"pubkey": FAKE["pk1"]}},
            ]},
            {"label": "RECOVER", "blocks": [
                {"type": "CSV", "values": {"blocks": "52560"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 15000}, {"amount": 14800}],
    },
    {
        "title": "LEGACY P2SH MULTISIG VAULT",
        "rungs": [
            {"label": "HOT", "blocks": [
                {"type": "P2WPKH_LEGACY", "values": {"pubkey": FAKE["pk1"]}},
            ]},
            {"label": "COLD", "blocks": [
                {"type": "CLTV", "values": {"height": "50"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk3"]}},
            ]},
        ],
        "outputs": [{"amount": 10000}, {"amount": 9800}],
    },
    {
        "title": "LEGACY P2WSH MULTISIG",
        "rungs": [
            {"label": "SPEND", "blocks": [
                {"type": "P2WSH_LEGACY", "values": {"script_body": "010100010000"}},
            ]},
            {"label": "FALLBACK", "blocks": [
                {"type": "CSV", "values": {"blocks": "52560"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
            ]},
        ],
        "outputs": [{"amount": 10000}, {"amount": 9800}],
    },
    {
        "title": "P2TR TAPROOT MIGRATION",
        "rungs": [
            {"label": "KEY", "blocks": [
                {"type": "P2TR_LEGACY", "values": {"pubkey": FAKE["pk1"]}},
            ]},
            {"label": "SCRIPT", "blocks": [
                {"type": "P2TR_SCRIPT_LEGACY", "values": {"script_hash": "010100010000", "internal_pubkey": FAKE["pk2"]}},
            ]},
            {"label": "RECOVERY", "blocks": [
                {"type": "CSV", "values": {"blocks": "52560"}},
                {"type": "SIG", "values": {"pubkey": FAKE["pk3"]}},
            ]},
        ],
        "outputs": [{"amount": 20000}, {"amount": 19800}, {"amount": 19500}],
    },
    # --- Anchor blocks (validation-only, always SATISFIED with correct fields) ---
    {
        "title": "ANCHOR TAG",
        "rungs": [
            {"label": "TAG", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ANCHOR", "values": {"anchor_id": "42"}},
            ]},
        ],
        "outputs": [{"amount": 10000}],
    },
    {
        "title": "ANCHOR POOL (VTXO)",
        "rungs": [
            {"label": "POOL", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ANCHOR_POOL", "values": {"pool_id": FAKE["hash1"], "participant_count": "5"}},
            ]},
        ],
        "outputs": [{"amount": 10000}],
    },
    {
        "title": "ANCHOR RESERVE",
        "rungs": [
            {"label": "RESERVE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ANCHOR_RESERVE", "values": {"threshold_n": "3", "threshold_m": "5", "guardian_hash": FAKE["hash2"]}},
            ]},
        ],
        "outputs": [{"amount": 10000}],
    },
    {
        "title": "ANCHOR SEAL",
        "rungs": [
            {"label": "SEAL", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ANCHOR_SEAL", "values": {"asset_id": FAKE["hash1"], "state_hash": FAKE["hash2"]}},
            ]},
        ],
        "outputs": [{"amount": 10000}],
    },
    {
        "title": "ANCHOR ORACLE",
        "rungs": [
            {"label": "ATTEST", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
                {"type": "ANCHOR_ORACLE", "values": {"oracle_pk": FAKE["oracle"], "outcome_count": "2"}},
            ]},
        ],
        "outputs": [{"amount": 10000}],
    },
    # --- QABIO presets ---
    {
        "title": "QABIO UTXO --FRESH (unprimed)",
        "spend_rung": 0,
        "rungs": [
            {"label": "ESCAPE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
            {"label": "PRIME", "blocks": [
                {"type": "QABI_PRIME", "values": {}},
            ]},
            {"label": "SPEND", "blocks": [
                {"type": "QABI_SPEND", "values": {
                    "auth_tip": FAKE["hash3"],
                    "committed_root": "0" * 64,
                    "committed_depth": "0",
                    "committed_expiry": "0",
                    "owner_id": FAKE["hash4"],
                }},
            ]},
        ],
        "outputs": [{"amount": 50000}, {"amount": 49800}, {"amount": 49500}],
    },
    {
        "title": "QABIO UTXO --PRIMED",
        "spend_rung": 0,
        "rungs": [
            {"label": "ESCAPE", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
            {"label": "RE_PRIME", "blocks": [
                {"type": "QABI_PRIME", "values": {}},
            ]},
            {"label": "SPEND", "blocks": [
                {"type": "QABI_SPEND", "values": {
                    "auth_tip": FAKE["hash3"],
                    "committed_root": FAKE["hash1"],
                    "committed_depth": "10",
                    "committed_expiry": "500",
                    "owner_id": FAKE["hash4"],
                }},
            ]},
        ],
        "outputs": [{"amount": 50000}, {"amount": 49800}, {"amount": 49500}],
    },
    {
        "title": "QABIO COORDINATOR BAILS --ESCAPE",
        "rungs": [
            {"label": "SIG_ONLY", "blocks": [
                {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
            ]},
        ],
        "outputs": [{"amount": 49950}],
    },
    {
        "title": "QABIO BATCH PAYOUT --COORDINATOR VIEW",
        "qabio_batch": True,
    },
]

# Compact SIG presets — single SIG rungs use compact wire encoding
PRESETS.append({
    "title": "SINGLE SIG (COMPACT)",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
        ]},
    ],
    "outputs": [{"amount": 10000}],
})

PRESETS.append({
    "title": "DUAL SIG (COMPACT)",
    "rungs": [
        {"label": "HOT", "blocks": [
            {"type": "SIG", "values": {"pubkey": FAKE["pk1"]}},
        ]},
        {"label": "COLD", "blocks": [
            {"type": "SIG", "values": {"pubkey": FAKE["pk2"]}},
        ]},
    ],
    "outputs": [{"amount": 10000}, {"amount": 10000}],
})

# Also add PQ single-sig presets for Dilithium3 and SPHINCS testing
PRESETS.append({
    "title": "SINGLE SIG (DILITHIUM3)",
    "scheme": "DILITHIUM3",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "SIG", "values": {"pubkey": FAKE_PQ["dilith1"], "scheme": "DILITHIUM3"}},
        ]},
    ],
    "outputs": [{"amount": 20000}],
})

PRESETS.append({
    "title": "SINGLE SIG (FALCON512)",
    "scheme": "FALCON512",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "SIG", "values": {"pubkey": FAKE_PQ["falcon1"], "scheme": "FALCON512"}},
        ]},
    ],
    "outputs": [{"amount": 20000}],
})

PRESETS.append({
    "title": "SINGLE SIG (FALCON1024)",
    "scheme": "FALCON1024",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "SIG", "values": {"pubkey": FAKE_PQ["falcon1024"], "scheme": "FALCON1024"}},
        ]},
    ],
    "outputs": [{"amount": 20000}],
})

PRESETS.append({
    "title": "SINGLE SIG (SPHINCS+)",
    "scheme": "SPHINCS_SHA",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "SIG", "values": {"pubkey": FAKE_PQ["sphincs1"], "scheme": "SPHINCS_SHA"}},
        ]},
    ],
    "outputs": [{"amount": 20000}],
})

# Legacy block presets — wrap classic Bitcoin script types as typed Ladder blocks
PRESETS.append({
    "title": "P2PK Legacy",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "P2PK_LEGACY", "values": {"pubkey": FAKE["pk1"]}},
        ]},
    ],
    "outputs": [{"amount": 10000}],
})

PRESETS.append({
    "title": "P2PKH Legacy",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "P2PKH_LEGACY", "values": {"pubkey": FAKE["pk1"]}},
        ]},
    ],
    "outputs": [{"amount": 10000}],
})

PRESETS.append({
    "title": "P2WPKH Legacy",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "P2WPKH_LEGACY", "values": {"pubkey": FAKE["pk1"]}},
        ]},
    ],
    "outputs": [{"amount": 10000}],
})

PRESETS.append({
    "title": "P2TR Legacy",
    "rungs": [
        {"label": "SPEND", "blocks": [
            {"type": "P2TR_LEGACY", "values": {"pubkey": FAKE["pk1"]}},
        ]},
    ],
    "outputs": [{"amount": 10000}],
})


# ═══════════════════════════════════════════════════════════════
# FUND FLOW
# ═══════════════════════════════════════════════════════════════

def fund_preset(preset, verbose=True):
    """Fund a preset: generate keys, build TX, create, sign, broadcast, mine."""
    title = preset["title"]
    scheme = preset.get("scheme", "SCHNORR")
    is_pq = scheme not in ("SCHNORR", "ECDSA")
    rungs = copy.deepcopy(preset["rungs"])
    outputs = copy.deepcopy(preset["outputs"])

    log = lambda msg: print(f"  {msg}") if verbose else None

    # 1. Collect all fake pubkeys that need replacement
    all_pubkeys = set()
    pubkey_locations = []  # (ri, bi, field_name, multi)
    hash_locations = []    # (ri, bi, field_name, hash_type)
    accumulator_locations = []  # (ri, bi) for ACCUMULATOR blocks

    for ri, rung in enumerate(rungs):
        for bi, block in enumerate(rung["blocks"]):
            btype = block["type"]
            vals = block.get("values", {})

            # Collect pubkey fields
            if btype in KEY_BLOCKS:
                for field, multi in KEY_BLOCKS[btype]:
                    val = vals.get(field, "")
                    if val:
                        if multi:
                            keys = [k.strip() for k in val.split(",") if k.strip()]
                            for k in keys:
                                all_pubkeys.add(k)
                        else:
                            all_pubkeys.add(val)
                        pubkey_locations.append((ri, bi, field, multi))

            # Collect hash fields
            if btype in HASH_BLOCKS:
                hfield, htype = HASH_BLOCKS[btype]
                if vals.get(hfield):
                    hash_locations.append((ri, bi, hfield, htype))

            # ACCUMULATOR merkle_leaves
            if btype == "ACCUMULATOR" and vals.get("merkle_leaves"):
                accumulator_locations.append((ri, bi))

    # 2. Generate keypairs
    keypair_count = max(len(all_pubkeys), 1)
    log(f"Generating {keypair_count} keypair(s) ({scheme})...")
    keypairs = []
    for _ in range(keypair_count):
        if is_pq:
            kp = api("/api/ladder/pq/keypair", {"scheme": scheme})
        else:
            kp = api("/api/ladder/wallet/keypair")
        keypairs.append(kp)

    # Standard wallet key for input signing
    wallet_key = api("/api/ladder/wallet/keypair") if is_pq else keypairs[0]

    # 3. Map old pubkeys to new
    old_to_new = {}
    old_keys = list(all_pubkeys)
    for i, old_key in enumerate(old_keys):
        kp = keypairs[i % len(keypairs)]
        old_to_new[old_key] = kp["pubkey"]

    # 4. Generate preimages for hash blocks
    preimages_generated = []
    hash_replacements = {}  # "ri:bi" -> {preimage, hash}
    for ri, bi, hfield, htype in hash_locations:
        pi = api("/api/ladder/preimage", silent=True)
        if pi:
            new_hash = pi["hash160"] if htype == "hash160" else pi["sha256"]
            hash_replacements[f"{ri}:{bi}"] = {"preimage": pi["preimage"], "hash": new_hash}
            preimages_generated.append({"preimage": pi["preimage"], "hash": new_hash, "type": htype, "ri": ri, "bi": bi})

    # 5. Apply replacements to rungs
    for ri, rung in enumerate(rungs):
        for bi, block in enumerate(rung["blocks"]):
            vals = block.get("values", {})
            btype = block["type"]

            # Replace pubkeys
            if btype in KEY_BLOCKS:
                for field, multi in KEY_BLOCKS[btype]:
                    val = vals.get(field, "")
                    if not val:
                        continue
                    if multi:
                        new_keys = [old_to_new.get(k.strip(), k.strip()) for k in val.split(",") if k.strip()]
                        vals[field] = ", ".join(new_keys)
                    else:
                        vals[field] = old_to_new.get(val, val)
                    if scheme != "SCHNORR":
                        vals["scheme"] = scheme

            # Replace hashes. The wire format now carries PREIMAGE for
            # hash-locking blocks (HTLC/HASH_SIG/ONE_SHOT) — the node
            # computes the SHA256 commitment internally — so the value
            # substituted here is the preimage, not the hash.
            hr = hash_replacements.get(f"{ri}:{bi}")
            if hr:
                if "hash" in vals:
                    vals["hash"] = hr["preimage"]
                if "commitment" in vals:
                    vals["commitment"] = hr["preimage"]

            block["values"] = vals

    # 6. Compute ACCUMULATOR merkle roots
    for ri, bi in accumulator_locations:
        block = rungs[ri]["blocks"][bi]
        vals = block["values"]
        leaves_str = vals.get("merkle_leaves", "")
        # Replace fake hashes in leaves with... we keep them as-is since they're arbitrary
        leaves = [s.strip() for s in leaves_str.split(",") if s.strip()]
        if leaves:
            root = merkle_root(leaves)
            vals["merkle_root"] = root
            log(f"ACCUMULATOR root computed: {root[:16]}...")

    ctv_outputs_map = {}

    # 7. Fee calculation
    pq_witness = {"FALCON512": 900, "FALCON1024": 1800, "DILITHIUM3": 3300, "SPHINCS_SHA": 50000}
    witness_bytes = pq_witness.get(scheme, 0)
    num_blocks = sum(len(r["blocks"]) for r in rungs)
    base_fee = 200 + 150 * (len(outputs) + 1) + 100 * num_blocks
    fee_sats = max(1000, base_fee + (witness_bytes + 3) // 4)
    spend_fee_est = max(1000, (witness_bytes + 3) // 4 + 500)

    # 8. Enforce output minimums (AMOUNT_LOCK, RECURSE_SPLIT)
    for oi, out in enumerate(outputs):
        min_required = spend_fee_est + 546
        # Check all rungs assigned to this output (assume 1:1 for presets)
        if oi < len(rungs):
            rung = rungs[oi]
            for block in rung["blocks"]:
                if block["type"] == "RECURSE_SPLIT":
                    min_sats = int(block["values"].get("min_sats", 546))
                    min_required = max(min_required, min_sats * 2 + spend_fee_est)
                if block["type"] == "AMOUNT_LOCK":
                    lock_min = int(block["values"].get("min", 0))
                    if lock_min > 0:
                        min_required = max(min_required, lock_min + spend_fee_est)
        if out["amount"] < min_required:
            log(f"Bumping output {oi} from {out['amount']} to {min_required}")
            out["amount"] = min_required

    # 8b. CTV auto-compute: generate template hash from finalized spend outputs
    if preset.get("ctv_auto"):
        ctv_dest_key = api("/api/ladder/wallet/keypair")
        ctv_send_sats = outputs[0]["amount"] - spend_fee_est
        # Build the CTV spend output as a SIG condition
        ctv_spend_output = {
            "amount": ctv_send_sats / 1e8,
            "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": ctv_dest_key["pubkey"]}]}]}],
        }
        # Create a dummy TX to get the scriptPubKey serialization
        dummy_input = {"txid": "0" * 64, "vout": 0, "sequence": 0xfffffffe}
        dummy_create = api("/api/ladder/create", {"inputs": [dummy_input], "outputs": [ctv_spend_output]}, silent=True)
        if dummy_create and "hex" in dummy_create:
            dummy_decoded = api("/api/ladder/decode-tx", {"hex": dummy_create["hex"]}, silent=True)
            if dummy_decoded and "vout" in dummy_decoded:
                spk_hex = dummy_decoded["vout"][0]["scriptPubKey"]["hex"]
                outputs_blob = serialize_ctv_output(ctv_send_sats, spk_hex)
                ctv_hash = compute_ctv_hash(
                    version=4, locktime=0, num_inputs=1,
                    sequences=[0xfffffffe], num_outputs=1,
                    outputs_blob=outputs_blob, input_index=0
                )
                for rung in rungs:
                    for block in rung["blocks"]:
                        if block["type"] == "CTV" and block["values"].get("template_hash") == "AUTO":
                            block["values"]["template_hash"] = ctv_hash
                            log(f"CTV template hash computed: {ctv_hash[:16]}...")
                for ri, rung in enumerate(rungs):
                    for bi, block in enumerate(rung["blocks"]):
                        if block["type"] == "CTV":
                            ctv_outputs_map[f"{ri}:{bi}"] = {"outputs": [ctv_spend_output]}

    total_output_sats = sum(o["amount"] for o in outputs)
    need_sats = total_output_sats + fee_sats

    # 9. Fetch UTXOs and select
    log(f"Need {need_sats} sats (outputs: {total_output_sats}, fee: {fee_sats})...")
    utxos = api("/api/ladder/wallet/utxos")
    confirmed = sorted([u for u in utxos if u.get("confirmations", 0) > 0], key=lambda u: -u["amount"])
    if not confirmed:
        raise RuntimeError("No confirmed UTXOs available")

    selected = []
    selected_total = 0
    for u in confirmed:
        selected.append(u)
        selected_total += round(u["amount"] * 1e8)
        if selected_total >= need_sats:
            break

    if selected_total < need_sats:
        raise RuntimeError(f"Insufficient funds: have {selected_total}, need {need_sats}")

    log(f"Selected {len(selected)} UTXO(s): {selected_total} sats")

    # 10. Generate addresses for outputs
    for out in outputs:
        addr = api("/api/ladder/wallet/address")
        out["address"] = addr["address"]

    # 11. Change output
    change_sats = selected_total - total_output_sats - fee_sats
    change_rung = None
    if change_sats >= 546:
        change_addr = api("/api/ladder/wallet/address")
        outputs.append({"address": change_addr["address"], "amount": change_sats})
        change_rung = {
            "label": "Change",
            "blocks": [{"type": "SIG", "values": {"pubkey": wallet_key["pubkey"], "scheme": scheme}}],
        }
        log(f"Change output: {change_sats} sats")

    # 12. Build wire-format conditions for outputs.
    # Each rung maps to an output at the same index; if more rungs than
    # outputs, extras share the last real output. The change output (if
    # present) gets a single SIG rung against the wallet key.
    #
    # Note on the previous COMPACT_SIG branch: the on-chain encoding
    # `{compact_type: COMPACT_SIG, pubkey_commit: ..., scheme: ...}` was
    # the historical "single SIG output stores the pubkey commit on the
    # rung" format. The wire format dropped it (commit notes in core:
    # COMPACT_SIG defeated merkle_pub_key by storing PUBKEY_COMMIT on the
    # rung itself). All conditions now use the standard `{blocks: [...]}`
    # shape with the pubkey carried as a normal SIG block field.
    wire_outputs = []
    num_real_outputs = len(outputs) - (1 if change_rung else 0)
    for oi in range(len(outputs)):
        conditions = []
        if oi < num_real_outputs:
            # Find all rungs that map to this output
            # Simple mapping: rung i → output i (if i < num_real_outputs), else → last real output
            assigned_rungs = []
            for ri, rung in enumerate(rungs):
                target_oi = ri if ri < num_real_outputs else num_real_outputs - 1
                if target_oi == oi:
                    assigned_rungs.append(rung)

            for rung in assigned_rungs:
                blocks_wire = [export_block_fields(b, b["values"]) for b in rung["blocks"]]
                conditions.append({"blocks": blocks_wire})
        else:
            # Change output — a single SIG rung against the wallet key.
            change_block = {"type": "SIG", "values": {"pubkey": wallet_key["pubkey"], "scheme": scheme}}
            conditions.append({"blocks": [export_block_fields(change_block, change_block["values"])]})

        if not conditions:
            continue  # skip outputs with no conditions

        wire_out = {
            "amount": outputs[oi]["amount"] / 1e8,  # sats → BTC for API
            "conditions": conditions,
            "coil": {"type": "UNLOCK", "attestation": "INLINE", "scheme": scheme},
        }
        wire_outputs.append(wire_out)

    # Build inputs
    wire_inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in selected]

    # 13. Create TX. Route on output count:
    #   - 1 output  → /api/ladder/create (createrungtx) — still the
    #     simplest path; the shared-root requirement is trivially
    #     satisfied with a single output.
    #   - N outputs → /api/ladder/createtxmlsc — TX_MLSC requires all
    #     outputs to share one conditions_root; createtxmlsc builds the
    #     shared Merkle commitment across N rung layouts. createrungtx
    #     rejects multi-output mixed-root inputs explicitly.
    #
    # createtxmlsc's input shape: outputs is a flat list of amounts;
    # rungs is a flat list of {output_index, blocks} entries.
    log("Creating transaction...")
    if len(wire_outputs) == 1:
        create_payload = {"inputs": wire_inputs, "outputs": wire_outputs}
        create_endpoint = "/api/ladder/create"
    else:
        amounts = [out["amount"] for out in wire_outputs]
        rungs_flat = []
        for oi, out in enumerate(wire_outputs):
            for cond in out["conditions"]:
                rungs_flat.append({"output_index": oi, "blocks": cond["blocks"]})
        create_payload = {"inputs": wire_inputs, "outputs": amounts, "rungs": rungs_flat}
        create_endpoint = "/api/ladder/createtxmlsc"
    create_result = api(create_endpoint, create_payload)
    if not create_result or "hex" not in create_result:
        raise RuntimeError("Failed to create TX")
    log(f"Created via {create_endpoint}: {len(create_result['hex'])//2} bytes")

    # 14. Sign TX. Funding txs spend wallet-owned P2WPKH UTXOs, not
    # MLSC inputs. signrungtx in core only signs MLSC inputs (it skips
    # non-MLSC inputs entirely with a "wallet must sign separately"
    # comment), so signing the funding tx via signrungtx leaves the
    # P2WPKH input unsigned and broadcast fails with "Witness program
    # hash mismatch". Route to signrawtransactionwithwallet via the
    # proxy's no-signers branch — that's the correct path for
    # wallet-owned bootstrap inputs.
    log("Signing (wallet-owned P2WPKH inputs)...")
    sign_result = api("/api/ladder/sign", {"hex": create_result["hex"]})
    if not sign_result or "hex" not in sign_result:
        raise RuntimeError("Failed to sign TX")
    if not sign_result.get("complete", True):
        errors = sign_result.get("errors", [])
        raise RuntimeError(f"Funding tx not fully signed: {errors}")

    # 15. Decode signed TX for docs
    fund_decoded = api("/api/ladder/decode-tx", {"hex": sign_result["hex"]}, silent=True)

    # 16. Broadcast
    log("Broadcasting...")
    bc_result = api("/api/ladder/broadcast", {"hex": sign_result["hex"]})
    if not bc_result or "txid" not in bc_result:
        raise RuntimeError("Failed to broadcast")
    txid = bc_result["txid"]
    log(f"Broadcast! TXID: {txid}")

    # 17. Mine
    api("/api/ladder/mine", {"blocks": 1}, silent=True)
    log("Mined 1 block")

    # Build record for spend
    condition_keys = []
    for kp in keypairs:
        condition_keys.append({"pubkey": kp["pubkey"], "privkey": kp["privkey"]})

    # Build rung snapshot with real pubkeys. Mirror exactly the rungs
    # committed to the fund-time tree so spend-time leaf reconstruction
    # produces the same Merkle root. That includes the change-output
    # rung (a single SIG against wallet_key) when one exists.
    rung_snapshot = []
    for ri, rung in enumerate(rungs):
        snapshot_blocks = []
        for bi, block in enumerate(rung["blocks"]):
            snap = {"type": block["type"], "values": dict(block["values"])}
            if block.get("inverted"):
                snap["inverted"] = True
            snapshot_blocks.append(snap)
        oi = ri if ri < num_real_outputs else num_real_outputs - 1
        rung_snapshot.append({
            "label": rung["label"],
            "vout": oi,
            "blocks": snapshot_blocks,
            "coilType": "UNLOCK",
        })
    if change_rung is not None:
        # Change output sits at the last vout. Its committed rung is a
        # single SIG block against wallet_key with the active scheme.
        rung_snapshot.append({
            "label": "CHANGE",
            "vout": len(outputs) - 1,
            "blocks": [{
                "type": "SIG",
                "values": {"pubkey": wallet_key["pubkey"], "scheme": scheme},
            }],
            "coilType": "UNLOCK",
        })

    record = {
        "txid": txid,
        "vout": 0,
        "scheme": scheme,
        "amount": outputs[0]["amount"],
        "walletKey": wallet_key,
        "conditionKeys": condition_keys,
        "preimages": preimages_generated,
        "rungs": rung_snapshot,
        "ctvOutputsMap": ctv_outputs_map,
    }

    return {"txid": txid, "record": record, "outputs": outputs, "fund_decoded": fund_decoded}


# ═══════════════════════════════════════════════════════════════
# SPEND FLOW
# ═══════════════════════════════════════════════════════════════

def spend_preset(record, spend_rung_idx=0, verbose=True, dry_run=False):
    """Spend the first rung of a funded preset. If dry_run=True, sign but don't broadcast."""
    log = lambda msg: print(f"  {msg}") if verbose else None

    rec = record
    txid = rec["txid"]
    scheme = rec.get("scheme", "SCHNORR")
    is_pq = scheme not in ("SCHNORR", "ECDSA")

    all_rungs = rec.get("rungs", [])
    if not all_rungs:
        raise RuntimeError("No rungs in record")

    # Select target rung by absolute index, then determine vout from that rung
    abs_idx = min(spend_rung_idx, len(all_rungs) - 1)
    target_rung = all_rungs[abs_idx]
    vout = target_rung.get("vout", rec.get("vout", 0))

    # Find all rungs that share this vout (for multi-condition outputs)
    vout_rungs = [r for r in all_rungs if r.get("vout") == vout]
    rung_idx = vout_rungs.index(target_rung) if target_rung in vout_rungs else 0

    rung_blocks = target_rung.get("blocks", [])
    log(f"Spending rung: {target_rung.get('label', '?')} ({', '.join(b['type'] for b in rung_blocks)})")

    # Build key lookup
    key_by_pubkey = {}
    for k in rec.get("conditionKeys", []):
        if k.get("pubkey"):
            key_by_pubkey[k["pubkey"]] = k

    preimages = rec.get("preimages", [])
    preimage_idx = 0

    # Build signer blocks
    signer_blocks = []
    csv_blocks = 0
    csv_time_seconds = 0
    tx_locktime = 0
    input_sequence = 0xfffffffe

    # Track recursion/mutation blocks
    recurse_blocks = []
    mutation_blocks = []
    split_block = None
    has_ctv = False

    for b in rung_blocks:
        btype = b["type"]
        vals = b.get("values", {})

        # Classify for output building
        if btype in RECURSE_TYPES:
            recurse_blocks.append(b)
            if btype in MUTATION_TYPES:
                mutation_blocks.append(b)
            if btype == "RECURSE_SPLIT":
                split_block = b

        if btype == "CTV":
            has_ctv = True

        # Build signer entry. PQ-ness is per-block (the SIG's own scheme),
        # not per-preset — HYBRID rungs mix PQ + classical SIG blocks.
        if btype == "SIG":
            pk = vals.get("pubkey", "")
            key = key_by_pubkey.get(pk)
            block_scheme = vals.get("scheme", scheme)
            block_is_pq = block_scheme not in ("SCHNORR", "ECDSA")
            if key:
                entry = {"type": "SIG"}
                if block_is_pq:
                    entry["pq_privkey"] = key["privkey"]
                    entry["pq_pubkey"] = key["pubkey"]
                    entry["scheme"] = block_scheme
                else:
                    entry["privkey"] = key["privkey"]
                    if block_scheme and block_scheme != "SCHNORR":
                        entry["scheme"] = block_scheme
                signer_blocks.append(entry)
            else:
                signer_blocks.append({"type": "SIG"})

        elif btype == "MULTISIG":
            threshold = int(vals.get("threshold", 2))
            pks = [k.strip() for k in vals.get("pubkeys", "").split(",") if k.strip()]
            # Witness needs ALL N pubkeys (merkle_pub_key folds them into
            # the leaf at fund time); only M privkeys are needed to sign.
            all_pubkeys = []
            privkeys = []
            for i, pk in enumerate(pks):
                key = key_by_pubkey.get(pk)
                all_pubkeys.append(pk)
                if i < threshold and key:
                    privkeys.append(key["privkey"])
            if is_pq:
                signer_blocks.append({"type": "MULTISIG", "pq_privkeys": privkeys, "pq_pubkeys": all_pubkeys, "scheme": vals.get("scheme", scheme)})
            else:
                signer_blocks.append({"type": "MULTISIG", "privkeys": privkeys, "pubkeys": all_pubkeys})

        elif btype == "TIMELOCKED_MULTISIG":
            threshold = int(vals.get("threshold", 2))
            pks = [k.strip() for k in vals.get("pubkeys", "").split(",") if k.strip()]
            all_pubkeys = []
            privkeys = []
            for i, pk in enumerate(pks):
                key = key_by_pubkey.get(pk)
                all_pubkeys.append(pk)
                if i < threshold and key:
                    privkeys.append(key["privkey"])
            csv_blocks = int(vals.get("blocks", 0))
            input_sequence = csv_blocks
            if is_pq:
                signer_blocks.append({"type": "TIMELOCKED_MULTISIG", "pq_privkeys": privkeys, "pq_pubkeys": all_pubkeys, "scheme": vals.get("scheme", scheme)})
            else:
                signer_blocks.append({"type": "TIMELOCKED_MULTISIG", "privkeys": privkeys, "pubkeys": all_pubkeys})

        elif btype == "ADAPTOR_SIG":
            pk = vals.get("signing_key", "")
            adaptor_point = vals.get("adaptor_point", "")
            key = key_by_pubkey.get(pk)
            if key:
                # ADAPTOR_SIG folds 2 pubkeys (signing_key + adaptor_point).
                # Witness must include both; signing key emitted by the
                # signing path, adaptor_point appended via the `pubkeys`
                # array (not `adaptor_point` — the consensus extractor only
                # walks PUBKEY fields in positional order).
                signer_blocks.append({"type": "ADAPTOR_SIG", "privkey": key["privkey"], "pubkeys": [adaptor_point]})

        elif btype == "MUSIG_THRESHOLD":
            pk = vals.get("agg_pubkey", "")
            key = key_by_pubkey.get(pk)
            if key:
                signer_blocks.append({
                    "type": "MUSIG_THRESHOLD",
                    "privkey": key["privkey"],
                    "threshold": int(vals.get("threshold", 2)),
                    "group_size": int(vals.get("group_size", 2)),
                })

        elif btype == "TIMELOCKED_SIG":
            pk = vals.get("pubkey", "")
            key = key_by_pubkey.get(pk)
            csv_blocks = int(vals.get("blocks", 0))
            input_sequence = csv_blocks
            if key:
                entry = {"type": "TIMELOCKED_SIG"}
                if is_pq:
                    entry["pq_privkey"] = key["privkey"]
                    entry["pq_pubkey"] = key["pubkey"]
                    entry["scheme"] = vals.get("scheme", scheme)
                else:
                    entry["privkey"] = key["privkey"]
                signer_blocks.append(entry)

        elif btype == "CLTV_SIG":
            pk = vals.get("pubkey", "")
            key = key_by_pubkey.get(pk)
            tx_locktime = int(vals.get("height", 0))
            if key:
                entry = {"type": "CLTV_SIG"}
                if is_pq:
                    entry["pq_privkey"] = key["privkey"]
                    entry["pq_pubkey"] = key["pubkey"]
                    entry["scheme"] = vals.get("scheme", scheme)
                else:
                    entry["privkey"] = key["privkey"]
                signer_blocks.append(entry)

        elif btype == "HTLC":
            pk = vals.get("pubkey", "")
            pk2 = vals.get("pubkey2", "")
            key = key_by_pubkey.get(pk)
            preimage = None
            if preimage_idx < len(preimages):
                preimage = preimages[preimage_idx]["preimage"]
                preimage_idx += 1
            csv_blocks = int(vals.get("blocks", 0))
            input_sequence = csv_blocks
            if key and preimage:
                # HTLC has 2 pubkeys folded into the Merkle leaf
                # (PubkeyCountForBlock returns 2). Witness emits the signing
                # pubkey then SIGNATURE then the second pubkey then PREIMAGE
                # then NUMERIC — keep both pubkeys consistent with fund-time.
                signer_blocks.append({"type": "HTLC", "privkey": key["privkey"], "preimage": preimage, "pubkeys": [pk2]})

        elif btype == "HASH_SIG":
            pk = vals.get("pubkey", "")
            key = key_by_pubkey.get(pk)
            preimage = None
            if preimage_idx < len(preimages):
                preimage = preimages[preimage_idx]["preimage"]
                preimage_idx += 1
            if key and preimage:
                entry = {"type": "HASH_SIG", "preimage": preimage}
                if is_pq:
                    entry["pq_privkey"] = key["privkey"]
                    entry["pq_pubkey"] = key["pubkey"]
                    entry["scheme"] = vals.get("scheme", scheme)
                else:
                    entry["privkey"] = key["privkey"]
                signer_blocks.append(entry)

        elif btype == "PTLC":
            pk = vals.get("signing_key", "")
            key = key_by_pubkey.get(pk)
            csv_blocks = int(vals.get("blocks", 0))
            input_sequence = csv_blocks
            if key:
                signer_blocks.append({"type": "PTLC", "privkey": key["privkey"], "adaptor_point": vals.get("adaptor_point", "")})

        elif btype == "TAGGED_HASH":
            preimage = None
            if preimage_idx < len(preimages):
                preimage = preimages[preimage_idx]["preimage"]
                preimage_idx += 1
            if preimage:
                signer_blocks.append({"type": "TAGGED_HASH", "preimage": preimage})
            else:
                signer_blocks.append({"type": "TAGGED_HASH"})

        elif btype == "ANCHOR_CHANNEL":
            # Witness must include both local + remote pubkeys (KEY_BLOCKS
            # has 2 entries) so the leaf's pubkey-fold reproduces fund-time
            # value_commitment.
            local_pk = vals.get("local_key", "")
            remote_pk = vals.get("remote_key", "")
            signer_blocks.append({"type": "ANCHOR_CHANNEL", "pubkeys": [local_pk, remote_pk]})

        elif btype == "ANCHOR_ORACLE":
            oracle_pk = vals.get("oracle_pk", "")
            signer_blocks.append({"type": "ANCHOR_ORACLE", "pubkeys": [oracle_pk]})

        elif btype == "VAULT_LOCK":
            hot_pk_hex = vals.get("hot_key", "")
            recovery_pk_hex = vals.get("recovery_key", "")
            hot_key = key_by_pubkey.get(hot_pk_hex)
            # Use hot key path (has CSV delay).
            # Witness must include BOTH pubkeys (recovery + hot) so the
            # leaf's value_commitment matches what was committed at fund
            # time (merkle_pub_key folds all key-block pubkeys in order).
            if hot_key:
                delay = int(vals.get("delay", 144))
                csv_blocks = delay
                input_sequence = delay
                entry = {"type": "VAULT_LOCK", "pubkeys": [recovery_pk_hex, hot_pk_hex]}
                if is_pq:
                    entry["pq_privkey"] = hot_key["privkey"]
                    entry["pq_pubkey"] = hot_key["pubkey"]
                    entry["scheme"] = scheme
                else:
                    entry["privkey"] = hot_key["privkey"]
                signer_blocks.append(entry)

        elif btype == "ACCUMULATOR":
            leaves = [s.strip() for s in vals.get("merkle_leaves", "").split(",") if s.strip()]
            if leaves:
                proof = merkle_proof(leaves, 0)
                signer_blocks.append({"type": "ACCUMULATOR", "proof": proof["siblings"], "leaf": proof["leaf"]})
            else:
                signer_blocks.append({"type": "ACCUMULATOR"})

        elif btype == "CSV":
            csv_blocks = int(vals.get("blocks", 0))
            input_sequence = csv_blocks
            signer_blocks.append({"type": "CSV"})

        elif btype == "CSV_TIME":
            seconds = int(vals.get("seconds", 0))
            csv_time_seconds = seconds
            input_sequence = ((seconds + 511) // 512) | 0x400000
            signer_blocks.append({"type": "CSV_TIME"})

        elif btype == "CLTV":
            tx_locktime = int(vals.get("height", 0))
            signer_blocks.append({"type": "CLTV"})

        elif btype == "CLTV_TIME":
            tx_locktime = int(vals.get("timestamp", 0))
            signer_blocks.append({"type": "CLTV_TIME"})

        elif btype == "LATCH_SET":
            # The witness must include the conditioning PUBKEY so consensus
            # ExtractBlockPubkeys reproduces the fund-time merkle_pub_key
            # fold (LATCH_SET has 1 KEY_BLOCKS entry).
            pk = vals.get("pubkey", "")
            signer_blocks.append({"type": "LATCH_SET", "pubkeys": [pk]} if pk else {"type": "LATCH_SET"})

        elif btype == "LATCH_RESET":
            pk = vals.get("pubkey", "")
            key = key_by_pubkey.get(pk)
            delay = int(vals.get("delay", 6))
            csv_blocks = delay
            input_sequence = delay
            entry = {"type": "LATCH_RESET", "pubkeys": [pk]} if pk else {"type": "LATCH_RESET"}
            if key:
                if is_pq:
                    entry["pq_privkey"] = key["privkey"]
                    entry["pq_pubkey"] = key["pubkey"]
                    entry["scheme"] = scheme
                else:
                    entry["privkey"] = key["privkey"]
            signer_blocks.append(entry)

        elif btype == "COUNTER_DOWN":
            pk = vals.get("pubkey", "")
            signer_blocks.append({"type": "COUNTER_DOWN", "pubkeys": [pk]} if pk else {"type": "COUNTER_DOWN"})

        elif btype == "COUNTER_UP":
            pk = vals.get("pubkey", "")
            signer_blocks.append({"type": "COUNTER_UP", "pubkeys": [pk]} if pk else {"type": "COUNTER_UP"})

        elif btype in ("P2PK_LEGACY", "P2TR_LEGACY"):
            pk = vals.get("pubkey", "")
            key = key_by_pubkey.get(pk)
            if key:
                entry = {"type": btype, "privkey": key["privkey"]}
                s = vals.get("scheme", scheme)
                if s and s != "SCHNORR":
                    entry["scheme"] = s
                signer_blocks.append(entry)
            else:
                signer_blocks.append({"type": btype})

        elif btype in ("P2PKH_LEGACY", "P2WPKH_LEGACY"):
            pk = vals.get("pubkey", "")
            key = key_by_pubkey.get(pk)
            if key:
                signer_blocks.append({"type": btype, "privkey": key["privkey"], "pubkey": key["pubkey"]})
            else:
                signer_blocks.append({"type": btype})

        elif btype in ("P2WSH_LEGACY", "P2TR_SCRIPT_LEGACY"):
            # Inner conditions serialised as SCRIPT_BODY. The outer
            # witness also carries PUBKEY + SIGNATURE for the inner SIG
            # block (EvalInnerConditions merges them).
            script_body = vals.get("script_body") or vals.get("script_hash", "")
            entry = {"type": btype, "preimage": script_body}
            # Find a key to sign with (first available keypair)
            if rec.get("conditionKeys"):
                k = rec["conditionKeys"][0]
                entry["privkey"] = k["privkey"]
            signer_blocks.append(entry)

        elif btype in ("ANCHOR", "ANCHOR_POOL", "ANCHOR_SEAL", "ANCHOR_RESERVE"):
            # Hash-bound anchors: VerifyHashPreimageBinding requires the
            # witness to include the original PREIMAGE that was hashed
            # into HASH256 at fund time. Collect all PREIMAGE-typed fields
            # from the values dict.
            preimage_fields = []
            for fd in BLOCK_FIELDS.get(btype, []):
                if fd["dataType"] == "PREIMAGE":
                    v = vals.get(fd["name"], "")
                    if v:
                        preimage_fields.append(v)
            if preimage_fields:
                signer_blocks.append({"type": btype, "preimages": preimage_fields})
            else:
                signer_blocks.append({"type": btype})

        else:
            # All other types: no witness data needed (COMPARE, SEQUENCER, AMOUNT_LOCK, etc.)
            signer_blocks.append({"type": btype})

    # Fallback if no signers found
    if not signer_blocks and rec.get("conditionKeys"):
        key = rec["conditionKeys"][0]
        if is_pq:
            signer_blocks.append({"type": "SIG", "pq_privkey": key["privkey"], "pq_pubkey": key["pubkey"], "scheme": scheme})
        else:
            signer_blocks.append({"type": "SIG", "privkey": key["privkey"]})

    # 1. Look up UTXO
    log(f"Looking up UTXO {txid[:16]}:{vout}...")
    tx_data = api(f"/api/ladder/tx/{txid}", silent=True)
    if not tx_data:
        raise RuntimeError("Transaction not found on chain")
    utxo_output = tx_data["vout"][vout]
    utxo_amount_sats = round(utxo_output["value"] * 1e8)
    log(f"Found UTXO: {utxo_amount_sats} sats")

    # 2. Fee calculation
    pq_witness_map = {"FALCON512": 900, "FALCON1024": 1800, "DILITHIUM3": 3300, "SPHINCS_SHA": 50000}
    witness_overhead = pq_witness_map.get(scheme, 0)
    fee_sats = max(1000, 500 + (witness_overhead + 3) // 4)
    send_sats = utxo_amount_sats - fee_sats
    if send_sats < 546:
        raise RuntimeError(f"UTXO too small: {utxo_amount_sats} sats, fee {fee_sats}")

    # 3. Get destination address
    dest = api("/api/ladder/wallet/address", silent=True)
    dest_addr = dest["address"]

    # 4. Build outputs
    wallet_key = rec.get("walletKey") or api("/api/ladder/wallet/keypair", silent=True)
    fresh_sig_output = {
        "amount": send_sats / 1e8,
        "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": wallet_key["pubkey"]}]}]}],
    }

    if has_ctv:
        # CTV outputs from stored template
        ctv_map = rec.get("ctvOutputsMap", {})
        ctv_key = None
        for k in ctv_map:
            if k.split(":")[0] == str(rung_idx):
                ctv_key = k
                break
        if ctv_key and ctv_map[ctv_key]:
            create_outputs = ctv_map[ctv_key]["outputs"]
            log(f"CTV: {len(create_outputs)} template output(s)")
        else:
            create_outputs = [fresh_sig_output]
    elif recurse_blocks:
        # Check exhaustion
        exhausted = False
        for rb in recurse_blocks:
            if rb["type"] == "RECURSE_SPLIT" and int(rb["values"].get("max_splits", 0)) <= 0:
                exhausted = True
            if rb["type"] == "RECURSE_UNTIL":
                st = api("/api/ladder/status", silent=True)
                if st and st.get("blocks", 0) >= int(rb["values"].get("target_height", 0)):
                    exhausted = True

        if exhausted:
            create_outputs = [fresh_sig_output]
        else:
            # Build carry-forward conditions. The recurse covenant rule
            # depends on the block type:
            #   RECURSE_SAME / RECURSE_UNTIL — identity: spend output's MLSC
            #     root must equal the spent UTXO's root, so the carry tree
            #     must be the FULL original tree (all_rungs unchanged).
            #   RECURSE_MODIFIED / RECURSE_SPLIT / RECURSE_COUNT / RECURSE_DECAY —
            #     leaf-centric: ComputeExpectedRoot in MERKLE_PATH mode stores
            #     just the revealed leaf, so expected_root collapses to the
            #     single mutated leaf. Carry tree = just the target rung.
            identity_recurse = any(
                rb["type"] in ("RECURSE_SAME", "RECURSE_UNTIL") for rb in recurse_blocks
            )
            def build_carry_conditions():
                conds = []
                source_rungs = all_rungs if identity_recurse else [target_rung]
                for r in source_rungs:
                    blocks_wire = []
                    for block in r.get("blocks", []):
                        blocks_wire.append(export_block_fields(block, block["values"]))
                    conds.append({"blocks": blocks_wire, "output_index": r.get("vout", 0)})

                # Apply RECURSE_SPLIT/RECURSE_COUNT decrements
                for cond in conds:
                    for blk in cond["blocks"]:
                        if blk["type"] in ("RECURSE_SPLIT", "RECURSE_COUNT"):
                            for f in blk["fields"]:
                                if f["type"] == "NUMERIC":
                                    f["hex"] = to_numeric_hex(str(max(0, from_numeric_hex(f["hex"]) - 1)))
                                    break

                # Apply mutations. PUBKEY is folded into the Merkle leaf at
                # parse time and stripped from block.fields, so the consensus
                # mutation walker (VerifyMutatedLeaves) counts only the
                # remaining condition fields. Match that semantics here —
                # IsConditionDataType in conditions.cpp returns false for
                # PUBKEY/SIGNATURE/PREIMAGE.
                is_condition_field = lambda t: t in ("HASH256", "HASH160", "NUMERIC", "SCHEME", "DATA")
                for mb in mutation_blocks:
                    block_idx = int(mb["values"].get("block_idx", 0))
                    param_idx = int(mb["values"].get("param_idx", 0))
                    raw_delta = int(mb["values"].get("delta") or mb["values"].get("decay_per_step") or 1)
                    delta = -raw_delta if mb["type"] == "RECURSE_DECAY" else raw_delta
                    if conds and conds[0]["blocks"] and block_idx < len(conds[0]["blocks"]):
                        target_block = conds[0]["blocks"][block_idx]
                        cond_count = 0
                        for fi, f in enumerate(target_block["fields"]):
                            if is_condition_field(f["type"]):
                                if cond_count == param_idx:
                                    if f["type"] != "NUMERIC":
                                        log(f"Mutation error: param_idx={param_idx} targets {f['type']}")
                                        break
                                    old_val = from_numeric_hex(f["hex"])
                                    new_val = old_val + delta
                                    f["hex"] = to_numeric_hex(str(new_val))
                                    log(f"Mutation [{block_idx},{param_idx}]: {old_val} → {new_val}")
                                    break
                                cond_count += 1

                return conds

            # Check for RATE_LIMIT block — requires vout[0] = small payment, vout[1] = carry-forward
            rate_limit_block = None
            for b in rung_blocks:
                if b["type"] == "RATE_LIMIT":
                    rate_limit_block = b
                    break

            if split_block:
                min_sats = int(split_block["values"].get("min_sats", 546))
                half = send_sats // 2
                if half < min_sats:
                    raise RuntimeError(f"RECURSE_SPLIT: half ({half}) < min_sats ({min_sats})")
                create_outputs = [
                    {"amount": half / 1e8, "conditions": build_carry_conditions(), "_isCarryForward": True},
                    {"amount": (send_sats - half) / 1e8, "conditions": build_carry_conditions(), "_isCarryForward": True},
                ]
                log(f"RECURSE_SPLIT: {half} + {send_sats - half}")
            elif rate_limit_block:
                max_per = int(rate_limit_block["values"].get("max_per_block", 0))
                payment_sats = min(max_per, send_sats - 546 - 1000)  # leave room for carry-forward + fee
                carry_sats = send_sats - payment_sats
                create_outputs = [
                    fresh_sig_output | {"amount": payment_sats / 1e8},
                    {"amount": carry_sats / 1e8, "conditions": build_carry_conditions(), "_isCarryForward": True},
                ]
                log(f"RATE_LIMIT: payment {payment_sats}, carry-forward {carry_sats}")
            else:
                if identity_recurse:
                    # RECURSE_SAME / RECURSE_UNTIL must reproduce the original
                    # tree exactly so the spend's MLSC root equals the input's
                    # frozen root. createtxmlsc requires output_index < N
                    # outputs, so pad amounts to cover every original
                    # output_index. The first output keeps the bulk of the
                    # value; padding outputs get dust each.
                    carry = build_carry_conditions()
                    max_oi = max((c.get("output_index", 0) for c in carry), default=0)
                    n_outputs = max_oi + 1
                    # Use a generous per-output minimum — non-standard SPKs
                    # (0xDF MLSC) have stricter dust thresholds than the
                    # vanilla 546-sat baseline, and mempool flat-out
                    # rejects "tx with dust output must be 0-fee".
                    pad_min = 3000
                    if send_sats < pad_min * n_outputs:
                        raise RuntimeError(f"identity recurse: {send_sats} sats too small for {n_outputs} outputs of {pad_min}")
                    pad_amounts = [pad_min] * n_outputs
                    pad_amounts[0] = send_sats - pad_min * (n_outputs - 1)
                    create_outputs = [
                        {"amount": amt / 1e8, "conditions": carry, "_isCarryForward": True}
                        for amt in pad_amounts
                    ]
                    log(f"Identity carry: {n_outputs} outputs (main {pad_amounts[0]}, dust×{n_outputs-1})")
                else:
                    create_outputs = [
                        {"amount": send_sats / 1e8, "conditions": build_carry_conditions(), "_isCarryForward": True},
                    ]
                    log(f"Carry-forward: {', '.join(b['type'] for b in recurse_blocks)}")
    else:
        create_outputs = [fresh_sig_output]

    # 5. Create spend TX. Same routing logic as the funding tx: 1
    # output uses createrungtx (legacy single-output path is fine);
    # multi-output (RECURSE_SPLIT, RATE_LIMIT carry-forward) needs
    # createtxmlsc because all outputs share one conditions_root.
    spend_inputs = [{"txid": txid, "vout": vout, "sequence": input_sequence}]

    log(f"Creating spend TX ({send_sats} sats after {fee_sats} fee)...")
    is_carry_forward_split = (
        len(create_outputs) > 1 and all(out.get("_isCarryForward") for out in create_outputs)
    )
    if len(create_outputs) == 1:
        create_payload = {"inputs": spend_inputs, "outputs": create_outputs}
        if tx_locktime > 0:
            create_payload["locktime"] = tx_locktime
        create_result = api("/api/ladder/create", create_payload, silent=True)
    elif is_carry_forward_split:
        # RECURSE_SPLIT/RATE_LIMIT etc.: all spend outputs share the same
        # mutated conditions tree (the recurse covenant requires every
        # output to be MLSC with the new expected_root). Use the conditions
        # from the first output and let each rung keep its original
        # output_index so leaves match what the verifier reconstructs.
        amounts = [out["amount"] for out in create_outputs]
        shared = create_outputs[0]["conditions"]
        rungs_flat = [
            {"output_index": cond.get("output_index", 0), "blocks": cond["blocks"]}
            for cond in shared
        ]
        create_payload = {"inputs": spend_inputs, "outputs": amounts, "rungs": rungs_flat}
        if tx_locktime > 0:
            create_payload["locktime"] = tx_locktime
        create_result = api("/api/ladder/createtxmlsc", create_payload, silent=True)
    else:
        amounts = [out["amount"] for out in create_outputs]
        rungs_flat = []
        for oi, out in enumerate(create_outputs):
            for cond in out["conditions"]:
                rungs_flat.append({"output_index": oi, "blocks": cond["blocks"]})
        create_payload = {"inputs": spend_inputs, "outputs": amounts, "rungs": rungs_flat}
        if tx_locktime > 0:
            create_payload["locktime"] = tx_locktime
        create_result = api("/api/ladder/createtxmlsc", create_payload, silent=True)
    if not create_result or "hex" not in create_result:
        raise RuntimeError("Failed to create spending TX")
    log(f"Created: {len(create_result['hex'])//2} bytes")

    # 6. Mine timelocks
    if csv_time_seconds > 0:
        log(f"CSV_TIME: mining 6 blocks for MTP advance...")
        api("/api/ladder/mine", {"blocks": 6}, silent=True)
    elif csv_blocks > 1:
        remaining = csv_blocks
        log(f"CSV: mining {remaining} blocks...")
        while remaining > 0:
            batch = min(remaining, 50)
            api("/api/ladder/mine", {"blocks": batch}, silent=True)
            remaining -= batch
        log(f"CSV satisfied ({csv_blocks} blocks)")

    # 7. Sign. signrungtx requires the full conditions tree alongside
    # the witness-side `blocks` so it can verify the spent UTXO's
    # conditions_root matches what we're claiming to satisfy. Build the
    # conditions array from ALL rungs in the original tree (across all
    # outputs) — the merkle path siblings need leaves for other-output
    # rungs too. Each rung carries its original output_index so spend-time
    # leaf reconstruction matches fund-time commitment.
    spend_conditions = [
        {
            "blocks": [export_block_fields(b, b["values"]) for b in r.get("blocks", [])],
            "output_index": r.get("vout", 0),
        }
        for r in all_rungs
    ]
    target_rung_global = all_rungs.index(target_rung)
    signer_entry = {"input": 0, "blocks": signer_blocks, "conditions": spend_conditions}
    if len(spend_conditions) > 1:
        signer_entry["rung"] = target_rung_global
        log(f"Passing rung={target_rung_global} (of {len(spend_conditions)} total leaves)")

    sign_payload = {
        "hex": create_result["hex"],
        "signers": [signer_entry],
        "spent_outputs": [{"amount": utxo_output["value"], "scriptPubKey": utxo_output["scriptPubKey"].get("hex", "")}],
    }
    log(f"Signing with {len(signer_blocks)} block(s)...")
    sign_result = api("/api/ladder/sign", sign_payload, silent=True)
    if not sign_result or "hex" not in sign_result:
        raise RuntimeError("Signing failed")

    # 8. Decode signed spend TX for docs (non-fatal — large PQ witnesses may exceed decode limit)
    spend_decoded = None
    try:
        spend_decoded = api("/api/ladder/decode-tx", {"hex": sign_result["hex"]}, silent=True)
    except Exception:
        log(f"decode-tx skipped (TX too large: {len(sign_result['hex'])//2} bytes)")

    # 9. Broadcast (or dry run)
    if dry_run:
        log(f"DRY RUN — signed TX: {len(sign_result['hex'])//2} bytes")
        log(f"Signed hex: {sign_result['hex'][:80]}...{sign_result['hex'][-40:]}")
        log(f"(broadcast skipped — timelock not satisfiable on regtest)")
        return {"txid": "dry_run", "amount": send_sats, "signed_hex": sign_result["hex"], "spend_decoded": spend_decoded}

    log("Broadcasting...")
    bc_result = api("/api/ladder/broadcast", {"hex": sign_result["hex"]})
    if not bc_result or "txid" not in bc_result:
        raise RuntimeError("Broadcast failed")
    spend_txid = bc_result["txid"]
    log(f"Spent! TXID: {spend_txid}")

    # 10. Mine confirmation
    api("/api/ladder/mine", {"blocks": 1}, silent=True)
    log("Confirmed")

    return {"txid": spend_txid, "amount": send_sats, "spend_decoded": spend_decoded}


# ═══════════════════════════════════════════════════════════════
# QABIO BATCH PAYOUT — standalone end-to-end flow
# ═══════════════════════════════════════════════════════════════

def run_qabio_batch(verbose=True):
    log = lambda msg: print(f"  {msg}") if verbose else None

    coord = api("/api/ladder/pq/keypair", {"scheme": "FALCON512"})
    log(f"Coordinator: {len(coord['pubkey'])//2}B FALCON-512")

    participants = []
    for i in range(3):
        ac = api("/api/ladder/qabi/authchain", {
            "auth_seed": f"{'%02x' % i}" * 32, "chain_length": 10, "depth": 0,
        })
        participants.append({"participant_id": ac["auth_tip"], "chain": ac})

    utxos = api("/api/ladder/wallet/utxos")
    big = [u for u in utxos if u.get("amount", 0) > 0.1]
    if len(big) < 3:
        api("/api/ladder/mine", {"blocks": 5})
        utxos = api("/api/ladder/wallet/utxos")
        big = [u for u in utxos if u.get("amount", 0) > 0.1]

    keys, fund_txids = [], []
    for i in range(3):
        kp = api("/api/ladder/wallet/keypair")
        keys.append(kp)
        out = {"amount": 0.001,
               "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": kp["pubkey"]}]}]}]}
        res = api("/api/ladder/create", {"inputs": [{"txid": big[i]["txid"], "vout": big[i]["vout"]}], "outputs": [out]})
        signed = api("/api/ladder/sign", {"hex": res["hex"]})
        bc = api("/api/ladder/broadcast", {"hex": signed["hex"]})
        fund_txids.append(bc["txid"])
    api("/api/ladder/mine", {"blocks": 1})
    log(f"Funded 3 UTXOs")

    spent_outputs = []
    for txid in fund_txids:
        tx = api(f"/api/ladder/tx/{txid}")
        spent_outputs.append({"amount": 0.001, "scriptPubKey": tx["vout"][0]["scriptPubKey"]["hex"]})

    dest_key = api("/api/ladder/wallet/keypair")
    dest_rung = {"output_index": 0, "blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_key["pubkey"]}]}]}
    dummy = api("/api/ladder/createtxmlsc", {"inputs": [{"txid": "0"*64, "vout": 0}], "outputs": [0.001], "rungs": [dest_rung]})
    outputs_root = dummy["conditions_root"]

    total, entries = 0, []
    for i in range(3):
        contrib = 99500
        entries.append({"participant_id": participants[i]["participant_id"],
                        "contribution": contrib / 1e8, "destination_index": 0})
        total += contrib

    height = api("/api/ladder/status")["blocks"]
    qabi = api("/api/ladder/qabi/buildblock", {
        "coordinator_pubkey": coord["pubkey"], "prime_expiry_height": height + 100,
        "batch_id": "cc" * 32, "entries": entries,
        "outputs_conditions_root": outputs_root, "output_values": [total / 1e8],
    })
    log(f"QABI block: {len(qabi['qabi_block'])//2} bytes")

    batch_tx = api("/api/ladder/createtxmlsc", {
        "inputs": [{"txid": t, "vout": 0} for t in fund_txids],
        "outputs": [total / 1e8], "rungs": [dest_rung], "qabi_block": qabi["qabi_block"],
    })

    hex_tx = batch_tx["hex"]
    for i in range(3):
        input_cond = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": keys[i]["pubkey"]}]}]}]
        sign_res = api("/api/ladder/sign", {
            "hex": hex_tx,
            "signers": [{"input": i, "privkey": keys[i]["privkey"], "conditions": input_cond}],
            "spent_outputs": spent_outputs,
        })
        hex_tx = sign_res["hex"]

    qabo = api("/api/ladder/qabi/signqabo", {"hex": hex_tx, "privkey": coord["privkey"]})
    log(f"QABO signed: {len(qabo['hex'])//2} bytes")

    bc2 = api("/api/ladder/broadcast", {"hex": qabo["hex"]})
    api("/api/ladder/mine", {"blocks": 1})
    return {"txid": bc2["txid"]}


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Test all Ladder Engine presets")
    parser.add_argument("--api", default="http://localhost:8801", help="API proxy URL")
    parser.add_argument("--preset", help="Run only this preset (by title substring)")
    parser.add_argument("--fund-only", action="store_true", help="Only fund, don't spend")
    parser.add_argument("--list", action="store_true", help="List all presets")
    args = parser.parse_args()

    global API
    API = args.api

    if args.list:
        for i, p in enumerate(PRESETS):
            skip = " [SKIP: " + p.get("skip_reason", "") + "]" if p.get("skip_reason") else ""
            print(f"  {i+1:2d}. {p['title']}{skip}")
        return

    # Check proxy
    print("Checking proxy...")
    try:
        st = api("/api/ladder/status")
        print(f"Proxy online. Chain height: {st.get('blocks', '?')}")
    except:
        print("ERROR: Proxy not reachable at " + API)
        sys.exit(1)

    # Ensure wallet has funds
    print("Checking wallet...")
    try:
        balance = api("/api/ladder/wallet/balance")
        balance_sats = round(balance.get("balance", 0) * 1e8)
        print(f"Wallet balance: {balance_sats:,} sats")
        if balance_sats < 100000:
            print("Low balance — mining 10 blocks for coinbase...")
            api("/api/ladder/mine", {"blocks": 10})
            # Wait for maturity
            api("/api/ladder/mine", {"blocks": 100})
            balance = api("/api/ladder/wallet/balance")
            balance_sats = round(balance.get("balance", 0) * 1e8)
            print(f"Balance after mining: {balance_sats:,} sats")
    except Exception as e:
        print(f"WARNING: Could not check balance: {e}")

    results = []
    presets_to_test = PRESETS
    if args.preset:
        presets_to_test = [p for p in PRESETS if args.preset.lower() in p["title"].lower()]
        if not presets_to_test:
            print(f"No preset matching '{args.preset}'")
            sys.exit(1)

    for i, preset in enumerate(presets_to_test):
        title = preset["title"]
        skip = preset.get("skip_reason")
        print(f"\n{'='*60}")
        print(f"[{i+1}/{len(presets_to_test)}] {title}")
        print(f"{'='*60}")

        if skip:
            print(f"  SKIPPED: {skip}")
            results.append({"title": title, "status": "SKIPPED", "reason": skip})
            continue

        fund_result = None
        spend_result = None

        # Small delay between presets to avoid rate limiting
        if i > 0:
            time.sleep(2)

        try:
            # QABIO BATCH PAYOUT — standalone flow (coordinator creates + signs)
            if preset.get("qabio_batch"):
                print("  --- QABIO BATCH (fund 3 + batch + QABO sign) ---")
                spend_result = run_qabio_batch(verbose=True)
                results.append({"title": title, "status": "PASS", "txid": spend_result["txid"],
                                "spend_decoded": spend_result.get("spend_decoded")})
                print(f"  Batch TXID: {spend_result['txid'][:16]}...")
                print(f"  Confirmed")
                continue

            # Fund
            print("  --- FUND ---")
            fund_result = fund_preset(preset)
            results.append({"title": title, "status": "FUND_OK", "txid": fund_result["txid"],
                            "fund_decoded": fund_result.get("fund_decoded")})

            if args.fund_only:
                continue

            # Spend
            dry_run = preset.get("dry_run_spend")
            if dry_run:
                print(f"  --- SPEND (DRY RUN: {dry_run}) ---")
            else:
                print("  --- SPEND ---")
            spend_rung = preset.get("spend_rung", 0)
            loop_count = preset.get("spend_loop", 1)

            if loop_count > 1:
                # Recursive spend loop (e.g. TIMER WATCHDOG: 144 iterations)
                record = fund_result["record"]
                first_spend_decoded = None
                for iteration in range(loop_count):
                    spend_result = spend_preset(record, spend_rung_idx=spend_rung, verbose=(iteration < 3 or iteration == loop_count - 1))
                    if iteration == 0:
                        first_spend_decoded = spend_result.get("spend_decoded")
                    if iteration < 3 or iteration == loop_count - 1 or (iteration + 1) % 50 == 0:
                        print(f"  Loop {iteration + 1}/{loop_count}: txid={spend_result['txid'][:16]}...")
                    # Build updated record for next iteration. The carry tree
                    # produced by RECURSE_MODIFIED is single-leaf (just the
                    # mutated target rung), so subsequent iterations spend a
                    # UTXO whose conditions tree has only that one rung at
                    # output_index 0. Reduce the snapshot to match.
                    record = dict(record)
                    record["txid"] = spend_result["txid"]
                    record["vout"] = 0
                    record["amount"] = spend_result["amount"]
                    new_rungs = [dict(record["rungs"][spend_rung])]
                    new_rungs[0]["vout"] = 0
                    new_rungs[0]["blocks"] = [dict(b, values=dict(b.get("values", {}))) for b in new_rungs[0]["blocks"]]
                    record["rungs"] = new_rungs
                    spend_rung = 0
                    # Apply mutations to rung block values (post-fold NUMERIC
                    # indexing — match the consensus VerifyMutatedLeaves walker).
                    rung_data = record["rungs"][spend_rung]
                    for b in rung_data.get("blocks", []):
                        if b["type"] in MUTATION_TYPES:
                            vals = b.get("values", {})
                            blk_idx = int(vals.get("block_idx", 0))
                            param_idx = int(vals.get("param_idx", 0))
                            delta = int(vals.get("delta") or vals.get("decay_per_step") or 1)
                            if b["type"] == "RECURSE_DECAY":
                                delta = -delta
                            target_block = rung_data["blocks"][blk_idx]
                            cond_count = 0
                            for fd_name, fd_val in target_block.get("values", {}).items():
                                fd_defs = BLOCK_FIELDS.get(target_block["type"], [])
                                for fd in fd_defs:
                                    if fd["name"] == fd_name and fd["dataType"] == "NUMERIC" and not fd.get("noWire"):
                                        if cond_count == param_idx:
                                            old_val = int(fd_val)
                                            target_block["values"][fd_name] = str(old_val + delta)
                                        cond_count += 1
                                        break
                print(f"  Completed {loop_count} recursive spends")
                spend_result["spend_decoded"] = first_spend_decoded
            else:
                spend_result = spend_preset(fund_result["record"], spend_rung_idx=spend_rung, dry_run=bool(dry_run))

            if dry_run:
                results[-1]["status"] = "DRY_RUN"
                results[-1]["note"] = dry_run
                results[-1]["spend_decoded"] = spend_result.get("spend_decoded")
            else:
                results[-1]["status"] = "PASS"
                results[-1]["spend_txid"] = spend_result["txid"]
                results[-1]["spend_decoded"] = spend_result.get("spend_decoded")

        except Exception as e:
            error_msg = str(e)
            print(f"  FAILED: {error_msg}")
            if fund_result:
                results[-1]["status"] = "SPEND_FAIL"
                results[-1]["error"] = error_msg
            else:
                results.append({"title": title, "status": "FUND_FAIL", "error": error_msg})

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")

    passed = [r for r in results if r["status"] == "PASS"]
    dry_runs = [r for r in results if r["status"] == "DRY_RUN"]
    fund_ok = [r for r in results if r["status"] == "FUND_OK"]
    skipped = [r for r in results if r["status"] == "SKIPPED"]
    fund_fail = [r for r in results if r["status"] == "FUND_FAIL"]
    spend_fail = [r for r in results if r["status"] == "SPEND_FAIL"]

    print(f"\nPASSED:     {len(passed)}/{len(results)}")
    if dry_runs:
        print(f"DRY RUN:    {len(dry_runs)} (fund + sign OK, broadcast skipped)")
    if fund_ok:
        print(f"FUND ONLY:  {len(fund_ok)}")
    print(f"SKIPPED:    {len(skipped)}")
    print(f"FUND FAIL:  {len(fund_fail)}")
    print(f"SPEND FAIL: {len(spend_fail)}")

    if passed:
        print("\nPassed:")
        for r in passed:
            print(f"  + {r['title']}")
            print(f"    fund: {r['txid'][:16]}...")
            print(f"    spend: {r.get('spend_txid', r.get('txid', '?'))[:16]}...")

    if dry_runs:
        print("\nDry Run (fund + sign OK, broadcast skipped):")
        for r in dry_runs:
            print(f"  ~ {r['title']}")
            print(f"    fund: {r['txid'][:16]}...")
            print(f"    note: {r['note']}")

    if fund_fail:
        print("\nFund Failures:")
        for r in fund_fail:
            print(f"  X {r['title']}: {r['error']}")

    if spend_fail:
        print("\nSpend Failures:")
        for r in spend_fail:
            print(f"  X {r['title']}: {r['error']}")
            print(f"    fund txid: {r.get('txid', '?')[:16]}...")

    if skipped:
        print("\nSkipped:")
        for r in skipped:
            print(f"  ~ {r['title']}: {r['reason']}")

    # Write summary results (no decoded TX data) and full results
    # (with decoded TX JSON for doc generation) next to this script.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    summary_path = os.path.join(script_dir, "test-results.json")
    summary = []
    for r in results:
        s = {k: v for k, v in r.items() if k not in ("fund_decoded", "spend_decoded")}
        summary.append(s)
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to: {summary_path}")

    full_path = os.path.join(script_dir, "test-results-full.json")
    with open(full_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Full results saved to: {full_path}")

    return len(fund_fail) + len(spend_fail)


if __name__ == "__main__":
    sys.exit(main())
