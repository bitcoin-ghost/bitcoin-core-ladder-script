#!/usr/bin/env python3
"""QABIO escape-after-prime lifecycle driver for a live signet node.

Proves the SIG escape rung is actually spendable after priming —
the "coordinator bails" safety test. Walks:

  1. generate a real secp256k1 keypair (pure-Python)
  2. create + mine a 3-rung QABI UTXO with SIG bound to that key
  3. prime it via QABI_PRIME (as the participant would do before
     the batch window)
  4. sweep the primed UTXO via the SIG escape rung using signrungtx
     with the participant's private key
  5. verify the fresh 1-rung SIG-only MLSC UTXO lands on chain
     under participant control

Reuses the same JSON-RPC bypass machinery as signet_lifecycle.py.

Env vars (all optional):
  QABIO_RPC_URL  default http://127.0.0.1:38332/
  QABIO_RPC_USER default ladderrpc
  QABIO_RPC_PASS default ladder_signet_rpc_2026
  QABIO_WALLET   default ladder

Requires the test_framework sources to be importable (for the
pure-Python ECKey / bytes_to_wif helpers).
"""
import json, os, sys, urllib.request, urllib.error, base64

# Pure-Python keypair helpers from the repo's functional test framework.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "test", "functional"))
from test_framework.key import ECKey  # type: ignore
from test_framework.wallet_util import bytes_to_wif  # type: ignore

RPC_URL  = os.environ.get("QABIO_RPC_URL",  "http://127.0.0.1:38332/")
RPC_USER = os.environ.get("QABIO_RPC_USER", "ladderrpc")
RPC_PASS = os.environ.get("QABIO_RPC_PASS", "ladder_signet_rpc_2026")
WALLET   = os.environ.get("QABIO_WALLET",   "ladder")

AUTH_SEED        = "f2" * 32
CHAIN_LENGTH     = 50
PRIME_DEPTH      = 10
NEW_COMMITTED    = "aa" * 32
NEW_EXPIRY       = 1000
OWNER_ID         = "c5" * 32


def _post(url, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))


def rpc(method, *params, wallet=False):
    url = RPC_URL + ("wallet/" + WALLET if wallet else "")
    payload = {"jsonrpc": "1.0", "id": "qabio_escape",
               "method": method, "params": list(params)}
    res = _post(url, payload)
    if res.get("error"):
        raise RuntimeError(f"RPC {method} failed: {res['error']}")
    return res["result"]


def u32_le_hex(v: int) -> str:
    return v.to_bytes(4, "little").hex()


def bytes_reverse_hex(h: str) -> str:
    return bytes.fromhex(h)[::-1].hex()


def conditions_createtxmlsc(auth_tip_hex, committed_root_hex, committed_depth,
                            committed_expiry, owner_id_hex,
                            sig_pk_compressed_hex):
    return [
        {"output_index": 0,
         "blocks": [{"type": "SIG",
                     "fields": [{"type": "SCHEME", "hex": "01"}]}],
         "pubkeys": [sig_pk_compressed_hex]},
        {"output_index": 0,
         "blocks": [{"type": "QABI_PRIME", "fields": []}]},
        {"output_index": 0,
         "blocks": [{"type": "QABI_SPEND",
                     "fields": [
                         {"type": "HASH256", "hex": auth_tip_hex},
                         {"type": "HASH256", "hex": committed_root_hex},
                         {"type": "NUMERIC", "hex": u32_le_hex(committed_depth)},
                         {"type": "NUMERIC", "hex": u32_le_hex(committed_expiry)},
                         {"type": "PUBKEY_COMMIT", "hex": owner_id_hex},
                     ]}]},
    ]


def conditions_signrungtx(auth_tip_hex, committed_root_hex, committed_depth,
                          committed_expiry, owner_id_hex,
                          sig_pk_compressed_hex):
    return [
        {"blocks": [{"type": "SIG",
                     "fields": [
                         {"type": "SCHEME", "hex": "01"},
                         {"type": "PUBKEY", "hex": sig_pk_compressed_hex},
                     ]}]},
        {"blocks": [{"type": "QABI_PRIME", "fields": []}]},
        {"blocks": [{"type": "QABI_SPEND",
                     "fields": [
                         {"type": "HASH256", "hex": auth_tip_hex},
                         {"type": "HASH256", "hex": committed_root_hex},
                         {"type": "NUMERIC", "hex": u32_le_hex(committed_depth)},
                         {"type": "NUMERIC", "hex": u32_le_hex(committed_expiry)},
                         {"type": "PUBKEY_COMMIT", "hex": owner_id_hex},
                     ]}]},
    ]


def main():
    # Step 0: generate the participant's escape keypair.
    eckey = ECKey()
    eckey.generate()
    privkey_bytes = eckey.get_bytes()
    privkey_wif = bytes_to_wif(privkey_bytes, compressed=True)
    pubkey_bytes = eckey.get_pubkey().get_bytes()
    assert len(pubkey_bytes) == 33
    pubkey_hex = pubkey_bytes.hex()
    print(f"[0] escape keypair: pubkey={pubkey_hex[:16]}...")

    # Step 1: create + mine the QABI UTXO.
    height = rpc("getblockcount")
    print(f"[1a] tip height={height}")
    unspent = rpc("listunspent", 100, wallet=True)
    if not unspent:
        print("ERROR: no mature UTXOs available", file=sys.stderr)
        sys.exit(1)
    utxo = unspent[0]
    print(f"[1b] funding UTXO: {utxo['txid']}:{utxo['vout']} "
          f"({utxo['amount']} BTC)")

    chain_info = rpc("qabi_authchain", AUTH_SEED, CHAIN_LENGTH)
    auth_tip_mem = bytes_reverse_hex(chain_info["auth_tip"])

    initial_conditions_create = conditions_createtxmlsc(
        auth_tip_mem, "00" * 32, 0, 0, OWNER_ID, pubkey_hex)
    fee = 0.001
    create_amount = round(float(utxo["amount"]) - fee, 8)
    creation_template = rpc(
        "createtxmlsc",
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [create_amount],
        initial_conditions_create,
    )
    initial_spk = creation_template["scriptPubKey"]
    signed_hex = rpc("signrawtransactionwithwallet",
                     creation_template["hex"], wallet=True)["hex"]
    creation_txid = rpc("sendrawtransaction", signed_hex)
    mine_addr = rpc("getnewaddress", wallet=True)
    rpc("generatetoaddress", 1, mine_addr, 100_000_000, wallet=True)
    tx_out = rpc("gettxout", creation_txid, 0)
    qabi_value = tx_out["value"]
    qabi_spk = tx_out["scriptPubKey"]["hex"]
    print(f"[1c] QABI UTXO mined: {creation_txid}:0 value={qabi_value}")

    # Step 2: prime it.
    primed_conditions_create = conditions_createtxmlsc(
        auth_tip_mem, NEW_COMMITTED, PRIME_DEPTH, NEW_EXPIRY, OWNER_ID, pubkey_hex)
    primed_amount = round(float(qabi_value) - fee, 8)
    priming_template = rpc(
        "createtxmlsc",
        [{"txid": creation_txid, "vout": 0}],
        [primed_amount],
        primed_conditions_create,
    )
    priming_hex = priming_template["hex"]
    primed_spk_predicted = priming_template["scriptPubKey"]

    initial_conditions_sign = conditions_signrungtx(
        auth_tip_mem, "00" * 32, 0, 0, OWNER_ID, pubkey_hex)
    signed_priming = rpc("signrungtx", priming_hex, [{
        "input": 0,
        "rung": 1,
        "blocks": [{
            "type": "QABI_PRIME",
            "new_committed_root": NEW_COMMITTED,
            "prime_depth": PRIME_DEPTH,
            "new_committed_expiry": NEW_EXPIRY,
            "auth_seed": AUTH_SEED,
            "chain_length": CHAIN_LENGTH,
        }],
        "conditions": initial_conditions_sign,
    }], [{"amount": str(qabi_value), "scriptPubKey": qabi_spk}])
    if not signed_priming.get("complete"):
        print(f"ERROR: priming sign incomplete: {signed_priming}", file=sys.stderr)
        sys.exit(1)
    priming_txid = rpc("sendrawtransaction", signed_priming["hex"])
    rpc("generatetoaddress", 1, mine_addr, 100_000_000, wallet=True)
    primed_out = rpc("gettxout", priming_txid, 0)
    assert primed_out["scriptPubKey"]["hex"] == primed_spk_predicted
    primed_value = primed_out["value"]
    primed_chain_spk = primed_out["scriptPubKey"]["hex"]
    print(f"[2] primed: {priming_txid}:0 value={primed_value} "
          f"spk={primed_chain_spk[:18]}...")

    # Step 3: coordinator bailed. Build the escape tx: simple 1-rung
    # [SIG(participant_key)] MLSC output.
    escape_conditions = [{
        "output_index": 0,
        "blocks": [{"type": "SIG",
                    "fields": [{"type": "SCHEME", "hex": "01"}]}],
        "pubkeys": [pubkey_hex],
    }]
    escape_amount = round(float(primed_value) - fee, 8)
    escape_template = rpc(
        "createtxmlsc",
        [{"txid": priming_txid, "vout": 0}],
        [escape_amount],
        escape_conditions,
    )
    assert escape_template["n_rungs"] == 1
    escape_target_spk = escape_template["scriptPubKey"]
    print(f"[3] escape skeleton built, target spk={escape_target_spk[:18]}...")

    # Step 4: sign the SIG rung of the primed UTXO.
    primed_conditions_sign = conditions_signrungtx(
        auth_tip_mem, NEW_COMMITTED, PRIME_DEPTH, NEW_EXPIRY, OWNER_ID, pubkey_hex)
    signed_escape = rpc("signrungtx", escape_template["hex"], [{
        "input": 0,
        "rung": 0,
        "blocks": [{"type": "SIG", "privkey": privkey_wif}],
        "conditions": primed_conditions_sign,
    }], [{"amount": str(primed_value), "scriptPubKey": primed_chain_spk}])
    if not signed_escape.get("complete"):
        print(f"ERROR: escape sign incomplete: {signed_escape}", file=sys.stderr)
        sys.exit(1)
    print(f"[4] SIG escape witness built: "
          f"{len(signed_escape['hex']) // 2} bytes")

    # Step 5: broadcast + mine.
    escape_txid = rpc("sendrawtransaction", signed_escape["hex"])
    rpc("generatetoaddress", 1, mine_addr, 100_000_000, wallet=True)
    print(f"[5] escape tx mined: {escape_txid}")

    # Step 6: verify.
    primed_still = rpc("gettxout", priming_txid, 0)
    if primed_still is not None:
        print(f"ERROR: primed UTXO still present: {primed_still}",
              file=sys.stderr)
        sys.exit(1)
    escape_out = rpc("gettxout", escape_txid, 0)
    assert escape_out["scriptPubKey"]["hex"] == escape_target_spk

    print()
    print("=" * 60)
    print("QABIO ESCAPE-AFTER-PRIME ON LIVE SIGNET: SUCCESS")
    print("=" * 60)
    print(f"Creation tx: {creation_txid}")
    print(f"Priming tx:  {priming_txid}")
    print(f"Escape tx:   {escape_txid}")
    print(f"Recovered:   {escape_out['value']} BTC at "
          f"{escape_target_spk[:18]}...")
    print(f"Chain tip:   {rpc('getblockcount')}")


if __name__ == "__main__":
    main()
