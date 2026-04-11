#!/usr/bin/env python3
"""QABIO mined priming lifecycle driver for a live signet node.

Drives the full happy-path QABIO priming lifecycle end-to-end against
a running bitcoind: picks a mature coinbase UTXO from the wallet,
builds the 3-rung [SIG_escape, QABI_PRIME, QABI_SPEND] conditions
tree, broadcasts the creation tx, mines it in, builds the priming
tx, signs it with the QABI_PRIME witness via signrungtx, broadcasts,
mines it in, and verifies the covenant mutation landed on chain.

Intended as a production-readiness smoke test for any fresh QABIO
signet deployment and as a reference for how the pieces fit together
at the RPC level. Bypasses bitcoin-cli to avoid arg-type conversion
surprises and hits JSON-RPC over HTTP directly.

Env vars (all optional):
  QABIO_RPC_URL  default http://127.0.0.1:38332/
  QABIO_RPC_USER default ladderrpc
  QABIO_RPC_PASS default ladder_signet_rpc_2026
  QABIO_WALLET   default ladder

Exits 0 on full lifecycle success, non-zero on any step failure.
"""
import json, os, sys, urllib.request, urllib.error, base64

RPC_URL  = os.environ.get("QABIO_RPC_URL",  "http://127.0.0.1:38332/")
RPC_USER = os.environ.get("QABIO_RPC_USER", "ladderrpc")
RPC_PASS = os.environ.get("QABIO_RPC_PASS", "ladder_signet_rpc_2026")
WALLET   = os.environ.get("QABIO_WALLET",   "ladder")

# Test parameters
AUTH_SEED        = "b1" * 32
CHAIN_LENGTH     = 50
PRIME_DEPTH      = 10
NEW_COMMITTED    = "77" * 32
NEW_EXPIRY       = 500
OWNER_ID         = "c5" * 32
SIG_PK_XONLY     = "00" * 32


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
    payload = {"jsonrpc": "1.0", "id": "qabio_signet",
               "method": method, "params": list(params)}
    res = _post(url, payload)
    if res.get("error"):
        err = res["error"]
        raise RuntimeError(f"RPC {method} failed: {err}")
    return res["result"]


def u32_le_hex(v: int) -> str:
    return v.to_bytes(4, "little").hex()


def bytes_reverse_hex(h: str) -> str:
    return bytes.fromhex(h)[::-1].hex()


def conditions_createtxmlsc(auth_tip_hex, committed_root_hex, committed_depth,
                            committed_expiry, owner_id_hex):
    return [
        {
            "output_index": 0,
            "blocks": [{"type": "SIG",
                        "fields": [{"type": "SCHEME", "hex": "01"}]}],
            "pubkeys": [SIG_PK_XONLY],
        },
        {
            "output_index": 0,
            "blocks": [{"type": "QABI_PRIME", "fields": []}],
        },
        {
            "output_index": 0,
            "blocks": [{
                "type": "QABI_SPEND",
                "fields": [
                    {"type": "HASH256", "hex": auth_tip_hex},
                    {"type": "HASH256", "hex": committed_root_hex},
                    {"type": "NUMERIC", "hex": u32_le_hex(committed_depth)},
                    {"type": "NUMERIC", "hex": u32_le_hex(committed_expiry)},
                    {"type": "PUBKEY_COMMIT", "hex": owner_id_hex},
                ],
            }],
        },
    ]


def conditions_signrungtx(auth_tip_hex, committed_root_hex, committed_depth,
                          committed_expiry, owner_id_hex):
    return [
        {"blocks": [{"type": "SIG",
                     "fields": [
                         {"type": "SCHEME", "hex": "01"},
                         {"type": "PUBKEY", "hex": "02" + SIG_PK_XONLY},
                     ]}]},
        {"blocks": [{"type": "QABI_PRIME", "fields": []}]},
        {"blocks": [{
            "type": "QABI_SPEND",
            "fields": [
                {"type": "HASH256", "hex": auth_tip_hex},
                {"type": "HASH256", "hex": committed_root_hex},
                {"type": "NUMERIC", "hex": u32_le_hex(committed_depth)},
                {"type": "NUMERIC", "hex": u32_le_hex(committed_expiry)},
                {"type": "PUBKEY_COMMIT", "hex": owner_id_hex},
            ],
        }]},
    ]


def main():
    height = rpc("getblockcount")
    print(f"[0] chain tip height = {height}")

    unspent = rpc("listunspent", 100, wallet=True)
    if not unspent:
        print("ERROR: no mature UTXOs available", file=sys.stderr)
        sys.exit(1)
    utxo = unspent[0]
    print(f"[1] funding UTXO: {utxo['txid']}:{utxo['vout']} "
          f"({utxo['amount']} BTC)")

    chain_info = rpc("qabi_authchain", AUTH_SEED, CHAIN_LENGTH)
    auth_tip_rpc_hex = chain_info["auth_tip"]
    auth_tip_mem = bytes_reverse_hex(auth_tip_rpc_hex)
    print(f"[2] chain_length={CHAIN_LENGTH} auth_tip={auth_tip_rpc_hex}")

    initial_conditions_create = conditions_createtxmlsc(
        auth_tip_hex=auth_tip_mem,
        committed_root_hex="00" * 32,
        committed_depth=0,
        committed_expiry=0,
        owner_id_hex=OWNER_ID,
    )

    fee = 0.001
    create_amount = float(utxo["amount"]) - fee
    creation_template = rpc(
        "createtxmlsc",
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        [create_amount],
        initial_conditions_create,
    )
    print(f"[3] createtxmlsc: "
          f"n_rungs={creation_template['n_rungs']}, "
          f"cond_root={creation_template['conditions_root'][:16]}..., "
          f"spk={creation_template['scriptPubKey'][:18]}...")
    initial_spk = creation_template["scriptPubKey"]
    unsigned_hex = creation_template["hex"]

    signed = rpc("signrawtransactionwithwallet", unsigned_hex, wallet=True)
    if not signed.get("complete"):
        print(f"ERROR: wallet signing incomplete: {signed}", file=sys.stderr)
        sys.exit(1)
    signed_hex = signed["hex"]
    print(f"[4] wallet signed: {len(signed_hex) // 2} bytes")

    creation_txid = rpc("sendrawtransaction", signed_hex)
    print(f"[5] creation tx broadcast: {creation_txid}")

    mine_addr = rpc("getnewaddress", wallet=True)
    hashes = rpc("generatetoaddress", 1, mine_addr, 100_000_000, wallet=True)
    print(f"[6] mined block: {hashes[0]}")

    tx_out = rpc("gettxout", creation_txid, 0)
    print(f"[7] QABI UTXO in chainstate: "
          f"value={tx_out['value']} "
          f"spk={tx_out['scriptPubKey']['hex'][:18]}...")
    qabi_value = tx_out["value"]
    qabi_spk   = tx_out["scriptPubKey"]["hex"]

    primed_conditions_create = conditions_createtxmlsc(
        auth_tip_hex=auth_tip_mem,
        committed_root_hex=NEW_COMMITTED,
        committed_depth=PRIME_DEPTH,
        committed_expiry=NEW_EXPIRY,
        owner_id_hex=OWNER_ID,
    )
    primed_amount = float(qabi_value) - fee
    priming_template = rpc(
        "createtxmlsc",
        [{"txid": creation_txid, "vout": 0}],
        [primed_amount],
        primed_conditions_create,
    )
    priming_hex = priming_template["hex"]
    primed_spk  = priming_template["scriptPubKey"]
    print(f"[8] priming skeleton: {len(priming_hex) // 2} bytes, "
          f"primed spk={primed_spk[:18]}... "
          f"(differs from initial: {primed_spk != initial_spk})")

    initial_conditions_sign = conditions_signrungtx(
        auth_tip_hex=auth_tip_mem,
        committed_root_hex="00" * 32,
        committed_depth=0,
        committed_expiry=0,
        owner_id_hex=OWNER_ID,
    )
    spent_outputs = [{"amount": str(qabi_value), "scriptPubKey": qabi_spk}]
    signers = [{
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
    }]
    signed_priming = rpc("signrungtx", priming_hex, signers, spent_outputs)
    if not signed_priming.get("complete"):
        print(f"ERROR: signrungtx incomplete: {signed_priming}",
              file=sys.stderr)
        sys.exit(1)
    signed_priming_hex = signed_priming["hex"]
    print(f"[9] QABI_PRIME witness built: "
          f"{len(signed_priming_hex) // 2} bytes")

    priming_txid = rpc("sendrawtransaction", signed_priming_hex)
    print(f"[10] priming tx broadcast: {priming_txid}")

    hashes = rpc("generatetoaddress", 1, mine_addr, 100_000_000, wallet=True)
    print(f"[11] mined block: {hashes[0]}")

    old = rpc("gettxout", creation_txid, 0)
    if old is not None:
        print(f"ERROR: original UTXO still present: {old}", file=sys.stderr)
        sys.exit(1)
    primed_out = rpc("gettxout", priming_txid, 0)
    primed_chain_spk = primed_out["scriptPubKey"]["hex"]
    print(f"[12] primed UTXO on chain: "
          f"value={primed_out['value']} "
          f"spk={primed_chain_spk[:18]}...")
    assert primed_chain_spk == primed_spk, \
        f"on-chain primed spk != predicted"
    assert primed_chain_spk != initial_spk, \
        "primed spk must differ from initial"

    print()
    print("=" * 60)
    print("QABIO MINED PRIMING LIFECYCLE ON LIVE SIGNET: SUCCESS")
    print("=" * 60)
    print(f"Creation tx: {creation_txid}")
    print(f"Priming tx:  {priming_txid}")
    print(f"Chain tip:   {rpc('getblockcount')}")


if __name__ == "__main__":
    main()
