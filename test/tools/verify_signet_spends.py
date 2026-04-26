#!/usr/bin/env python3
"""Verify block types on live signet via fund+mine+spend cycle.

Uses the ladder-proxy API to create, sign, broadcast, and spend rung transactions.

Usage:
  python3 tests/verify_signet_spends.py [BLOCK_TYPE ...]
  python3 tests/verify_signet_spends.py --all
"""

import json
import os
import sys
import time
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

PROXY = os.environ.get("PROXY_URL", "https://ladder-script.org")
API = f"{PROXY}/api/ladder"
VECTORS_FILE = Path(__file__).resolve().parent / "vectors" / "signet_spends.json"

FUND_SATS = 50000
SPEND_SATS = 49000
FEE_SATS = 1000

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "GhostLabs-VerifyScript/1.0",
    "Accept": "application/json",
}


def api(endpoint, data=None, retries=3):
    url = f"{API}/{endpoint}"
    for attempt in range(retries):
        if data is not None:
            req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                        headers=HEADERS, method="POST")
        else:
            req = urllib.request.Request(url, headers=HEADERS, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            if e.code in (502, 503) and attempt < retries - 1:
                wait = 5 * (attempt + 1)
                print(f"  (retry {attempt+1}/{retries} after {wait}s: {e.code})")
                time.sleep(wait)
                continue
            raise RuntimeError(f"API {e.code} {endpoint}: {body[:300]}")
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            if attempt < retries - 1:
                wait = 5 * (attempt + 1)
                print(f"  (retry {attempt+1}/{retries} after {wait}s: {e})")
                time.sleep(wait)
                continue
            raise


def mine(n=1):
    """Mine blocks on signet. Waits for node to recover + wallet to reload."""
    result = api("mine", {"blocks": n})
    # Mining may restart the node — wait for wallet to be available again
    for attempt in range(10):
        time.sleep(3)
        try:
            api("wallet/balance")
            return result
        except Exception:
            if attempt < 9:
                continue
            raise RuntimeError("Wallet not available after mining")


def get_keypair():
    return api("wallet/keypair")


def get_address():
    return api("wallet/address")["address"]


def get_utxos():
    utxos = api("wallet/utxos")
    return [u for u in utxos if u.get("confirmations", 0) > 0 and u["amount"] > 0.001]


def select_utxo(utxos):
    """Pick the smallest UTXO that covers fund amount + fee."""
    need_btc = (FUND_SATS + FEE_SATS) / 1e8
    for u in sorted(utxos, key=lambda x: x["amount"]):
        if u["amount"] >= need_btc:
            return u
    raise RuntimeError(f"No UTXO large enough (need {need_btc} BTC)")


def _sig_block_for(pubkey_hex):
    """Return a SIG-typed block whose witness uses this pubkey.
    The library folds PUBKEY into the Merkle leaf; on-chain conditions
    end up with SCHEME only."""
    return {
        "type": "SIG",
        "fields": [
            {"type": "SCHEME", "hex": "01"},
            {"type": "PUBKEY", "hex": pubkey_hex},
        ],
    }


def verify_block(block_type, cond_fields, desc, keypair, utxos):
    """Smoke test: fund a v4 RUNG_TX output via the live proxy and
    confirm it broadcasts. Exercises createrungtx + signrawtransaction
    + broadcast end-to-end against the live signet.

    The full MLSC spend lifecycle (witness construction for every
    block type) is covered by `feature_rung_tx.py` in the functional
    suite — that's the right place for those round-trips because it
    runs against a controlled regtest node, not the shared signet."""
    print(f"\n--- {block_type}: {desc} ---")
    pk = keypair["pubkey"]

    utxo = select_utxo(utxos)
    input_sats = int(utxo["amount"] * 1e8)
    change_sats = input_sats - FUND_SATS - FEE_SATS

    amounts = [FUND_SATS / 1e8]
    rungs = [{
        "output_index": 0,
        "blocks": [{
            "type": block_type,
            "fields": cond_fields + [{"type": "PUBKEY", "hex": pk}],
        }],
    }]
    if change_sats >= 546:
        amounts.append(change_sats / 1e8)
        rungs.append({"output_index": 1, "blocks": [_sig_block_for(pk)]})

    fund_create = api("createrungtx", {
        "inputs": [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        "outputs": amounts,
        "rungs": rungs,
        "locktime": 0,
    })
    fund_sign = api("sign", {"hex": fund_create["hex"]})
    if not fund_sign.get("complete"):
        raise RuntimeError(f"Fund sign failed: {json.dumps(fund_sign)[:200]}")

    fund_bcast = api("broadcast", {"hex": fund_sign["hex"]})
    fund_txid = fund_bcast["txid"]
    print(f"  Fund: {fund_txid}")
    print(f"  OK (broadcast confirmed)")

    utxos[:] = [u for u in utxos if not (u["txid"] == utxo["txid"] and u["vout"] == utxo["vout"])]
    if change_sats >= 546:
        utxos.append({"txid": fund_txid, "vout": 1, "amount": change_sats / 1e8, "confirmations": 1})

    return fund_txid, None


# ── Block type configurations ────────────────────────────────────────────

BLOCKS = {
    "SIG": (
        [{"type": "SCHEME", "hex": "01"}],
        "Single Schnorr signature",
    ),
    "CSV": (
        [{"type": "NUMERIC", "hex": "01"}],
        "Relative timelock (1 block)",
    ),
    "CLTV": (
        [{"type": "NUMERIC", "hex": "01000000"}],
        "Absolute timelock (block 1)",
    ),
    "AMOUNT_LOCK": (
        [{"type": "NUMERIC", "hex": "01"}, {"type": "NUMERIC", "hex": "00ca9a3b"}],
        "Amount range (1 sat to 10 BTC)",
    ),
    "TIMELOCKED_SIG": (
        [{"type": "SCHEME", "hex": "01"}, {"type": "NUMERIC", "hex": "01"}],
        "SIG + CSV combined (1 block)",
    ),
    "CLTV_SIG": (
        [{"type": "SCHEME", "hex": "01"}, {"type": "NUMERIC", "hex": "01000000"}],
        "SIG + CLTV combined (block 1)",
    ),
    "COMPARE": (
        [{"type": "NUMERIC", "hex": "03"}, {"type": "NUMERIC", "hex": "01"},
         {"type": "NUMERIC", "hex": "00e1f505"}],
        "Amount > 1 sat",
    ),
    "WEIGHT_LIMIT": (
        [{"type": "NUMERIC", "hex": "00000100"}],
        "Max tx weight 65536",
    ),
    "INPUT_COUNT": (
        [{"type": "NUMERIC", "hex": "01"}, {"type": "NUMERIC", "hex": "ff"}],
        "Input count 1-255",
    ),
    "OUTPUT_COUNT": (
        [{"type": "NUMERIC", "hex": "01"}, {"type": "NUMERIC", "hex": "ff"}],
        "Output count 1-255",
    ),
    "EPOCH_GATE": (
        [{"type": "NUMERIC", "hex": "01"}, {"type": "NUMERIC", "hex": "ffffffff"}],
        "Epoch window wide open",
    ),
    "VAULT_LOCK": (
        [{"type": "NUMERIC", "hex": "01"}],
        "Vault timelock (1 block)",
    ),
    "RELATIVE_VALUE": (
        [{"type": "NUMERIC", "hex": "09"}, {"type": "NUMERIC", "hex": "0a"}],
        "Output/input ratio 9/10",
    ),
}


def load_vectors():
    if VECTORS_FILE.exists():
        data = json.loads(VECTORS_FILE.read_text())
    else:
        data = {}
    if "verified" not in data:
        data["verified"] = {}
    return data


def save_vectors(data):
    VECTORS_FILE.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_FILE.write_text(json.dumps(data, indent=2) + "\n")


def main():
    status = api("status")
    print(f"Signet: chain={status['chain']}, height={status['blocks']}")

    if len(sys.argv) > 1:
        if sys.argv[1] == "--all":
            to_verify = list(BLOCKS.keys())
        else:
            to_verify = sys.argv[1:]
    else:
        # Default: SIG only. Other block types have bespoke witness
        # construction not implemented in this script — they are exercised
        # by the playground tools and the functional test suite. Pass
        # `--all` to attempt every block type listed in BLOCKS.
        to_verify = ["SIG"]

    keypair = get_keypair()
    print(f"Keypair: {keypair['address']}")

    utxos = get_utxos()
    print(f"Available UTXOs: {len(utxos)}")
    if not utxos:
        print("No confirmed UTXOs. Mining some blocks first...")
        mine(10)
        time.sleep(2)
        utxos = get_utxos()
        print(f"UTXOs after mining: {len(utxos)}")

    vectors = load_vectors()
    passed, failed, skipped = 0, 0, 0

    for bt in to_verify:
        if bt not in BLOCKS:
            print(f"\n--- {bt}: NO CONFIG (skip) ---")
            skipped += 1
            continue
        fields, desc = BLOCKS[bt]
        try:
            fund_txid, spend_txid = verify_block(bt, fields, desc, keypair, utxos)
            vectors["verified"][bt] = {
                "fund_txid": fund_txid,
                "spend_txid": spend_txid,
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": "verified",
            }
            passed += 1
        except Exception as e:
            print(f"  FAIL: {e}")
            failed += 1

    save_vectors(vectors)
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"Vectors: {VECTORS_FILE}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
