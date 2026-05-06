"""Battery 9: KEY_REF_SIG + COSIGN + RECURSE_SPLIT.

The remaining 7 untested types need specific harness extensions:
- KEY_REF_SIG: createrungtx accepts `relays` as 7th positional arg;
  signrungtx accepts `relay_blocks` in the signer spec. Build a
  conditions tree with the SIG inside a relay, the rung referencing
  it via relay_refs.
- COSIGN: 2-input scenario where input 0 is a vanilla SIG UTXO and
  input 1's COSIGN block targets SHA256(input 0's scriptPubKey).
- RECURSE_SPLIT: single-hop split — fund with RECURSE_SPLIT,
  spend by re-encumbering the SAME conditions on 2 child outputs.

P2SH/P2WSH/P2TR_SCRIPT_LEGACY and RECURSE_MODIFIED/DECAY need RPC
surface extensions (inner-conditions serialisation that preserves
PUBKEY fields, mutation-target scaffolding) — left for a follow-up.
"""
import sys, re, hashlib
sys.path.insert(0, "/tmp")
src3 = open("/tmp/v4_trials3.py").read()
src3 = re.sub(r'^if __name__ == "__main__":.*?(?=^(?:def |# |import |$))', "", src3,
              flags=re.MULTILINE | re.DOTALL)
exec(src3, globals())


def t64_key_ref_sig():
    # KEY_REF_SIG_CONDITIONS = [NUMERIC(relay_index), NUMERIC(block_index)].
    # The actual SIG block (with the pubkey) lives in the conditions-side
    # `relays` array; the rung references it via `relay_refs` and the
    # spend witness only carries SIGNATURE — pubkey is resolved from
    # the relay block at evaluation time.
    name = "64. KEY_REF_SIG (relay-bound)"
    pk = derive("t64-keyref"); pkh = pk.get_pubkey().get_bytes().hex()
    u, uerr = get_or_make_small_utxo(name)
    if not u: results.append((name, "SKIP", uerr or "no UTXO")); return
    fund_amt = round(u["amount"] - 0.001, 8)
    rungs = [{
        "output_index": 0,
        "blocks": [{"type": "KEY_REF_SIG", "fields": [
            {"type": "NUMERIC", "hex": "00000000"},   # relay_index = 0
            {"type": "NUMERIC", "hex": "00000000"}]}],   # block_index = 0
        "relay_refs": [0]
    }]
    relays = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "01"},
        {"type": "PUBKEY", "hex": pkh}]}]}]
    fr, err = ok(rpc("createrungtx",
        [[{"txid": u["txid"], "vout": u["vout"]}], [fund_amt], rungs,
         0, "", "", relays]), "fund")
    if not fr: results.append((name, "FAIL", err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet", [fr["hex"]], WALLET), "fund-sign")
    if not fs or not fs.get("complete"):
        results.append((name, "FAIL", f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction", [fs["hex"]]), "send-fund")
    if not fund_txid: results.append((name, "FAIL", err)); return
    mine(1)
    spend_amt = round(fund_amt - 0.001, 8)
    sweep_pk = pk_hex(f"sweep-{name}")
    sweep_rungs = [{"output_index": 0, "blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "01"}, {"type": "PUBKEY", "hex": sweep_pk}]}]}]
    su, err = ok(rpc("createrungtx",
        [[{"txid": fund_txid, "vout": 0}], [spend_amt], sweep_rungs]),
        "spend-build")
    if not su: results.append((name, "FAIL", err)); return
    spent_outs = [{"amount": fund_amt, "scriptPubKey": fr["scriptPubKey"]}]
    signer = {
        "input": 0,
        "blocks": [{"type": "KEY_REF_SIG",
                    "privkey": bytes_to_wif(pk.get_bytes(), True)}],
        "conditions": [{
            "blocks": [{"type": "KEY_REF_SIG", "fields": [
                {"type": "NUMERIC", "hex": "00000000"},
                {"type": "NUMERIC", "hex": "00000000"}]}],
            "relay_refs": [0]
        }],
        "relays": relays,
        # Relay's SIG block also signs (BuildWitnessBlock calls
        # SignSingleKey for relay blocks, which requires privkey).
        "relay_blocks": [{"blocks": [{"type": "SIG",
                                       "privkey": bytes_to_wif(pk.get_bytes(), True)}]}]
    }
    ss, err = ok(rpc("signrungtx", [su["hex"], [signer], spent_outs]), "signrungtx")
    if not ss or not ss.get("complete"):
        results.append((name, "FAIL", f"sign-spend {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction", [ss["hex"]]), "send-spend")
    if not spend_txid: results.append((name, "FAIL", err)); return
    mine(1)
    results.append((name, "OK", f"fund={fund_txid[:10]} spend={spend_txid[:10]}"))


def t65_cosign():
    # COSIGN evaluator (plc.cpp:356) walks ctx.tx's other inputs and
    # checks that any of their spent_outputs[i].scriptPubKey hashes to
    # the committed HASH256. For a self-referential 2-input trial:
    # 1. Fund UTXO_A with vanilla SIG conditions; record SPK_A.
    # 2. Fund UTXO_B with [SIG(bob), COSIGN(SHA256(SPK_A))].
    # 3. Spend BOTH in one tx — UTXO_B's COSIGN finds UTXO_A in the
    #    input set. UTXO_A is satisfied independently by its own SIG.
    name = "65. COSIGN (2-input cross-ref)"
    alice = derive("t65-alice"); alice_h = alice.get_pubkey().get_bytes().hex()
    bob   = derive("t65-bob");   bob_h   = bob.get_pubkey().get_bytes().hex()
    alice_wif = bytes_to_wif(alice.get_bytes(), True)
    bob_wif   = bytes_to_wif(bob.get_bytes(), True)

    # Fund UTXO_A (vanilla SIG)
    uA, uAerr = get_or_make_small_utxo(name + "-A")
    if not uA: results.append((name, "SKIP", uAerr or "no UTXO_A")); return
    fund_amtA = round(uA["amount"] - 0.001, 8)
    rungsA = [{"output_index": 0, "blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "01"}, {"type": "PUBKEY", "hex": alice_h}]}]}]
    frA, err = ok(rpc("createrungtx",
        [[{"txid": uA["txid"], "vout": uA["vout"]}], [fund_amtA], rungsA]),
        "fund-A")
    if not frA: results.append((name, "FAIL", f"fund-A: {err}")); return
    fsA, err = ok(rpc("signrawtransactionwithwallet", [frA["hex"]], WALLET), "fund-A-sign")
    if not fsA or not fsA.get("complete"):
        results.append((name, "FAIL", f"fund-A-sign: {err}")); return
    fund_A_txid, err = ok(rpc("sendrawtransaction", [fsA["hex"]]), "send-A")
    if not fund_A_txid: results.append((name, "FAIL", f"send-A: {err}")); return
    mine(1)
    spk_A = frA["scriptPubKey"]   # 0xDF || conditions_root_A

    # Compute COSIGN target: SHA256(spk_A bytes)
    spk_A_bytes = bytes.fromhex(spk_A)
    cosign_target = hashlib.sha256(spk_A_bytes).hexdigest()

    # Fund UTXO_B with [SIG(bob), COSIGN(target)]
    uB, uBerr = get_or_make_small_utxo(name + "-B")
    if not uB: results.append((name, "SKIP", uBerr or "no UTXO_B")); return
    fund_amtB = round(uB["amount"] - 0.001, 8)
    rungsB = [{"output_index": 0, "blocks": [
        {"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "01"}, {"type": "PUBKEY", "hex": bob_h}]},
        {"type": "COSIGN", "fields": [
            {"type": "HASH256", "hex": cosign_target}]}]}]
    frB, err = ok(rpc("createrungtx",
        [[{"txid": uB["txid"], "vout": uB["vout"]}], [fund_amtB], rungsB]),
        "fund-B")
    if not frB: results.append((name, "FAIL", f"fund-B: {err}")); return
    fsB, err = ok(rpc("signrawtransactionwithwallet", [frB["hex"]], WALLET), "fund-B-sign")
    if not fsB or not fsB.get("complete"):
        results.append((name, "FAIL", f"fund-B-sign: {err}")); return
    fund_B_txid, err = ok(rpc("sendrawtransaction", [fsB["hex"]]), "send-B")
    if not fund_B_txid: results.append((name, "FAIL", f"send-B: {err}")); return
    mine(1)
    spk_B = frB["scriptPubKey"]

    # Spend both A and B in one tx
    spend_amt = round((fund_amtA + fund_amtB) - 0.002, 8)
    sweep_pk = pk_hex(f"sweep-{name}")
    sweep_rungs = [{"output_index": 0, "blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "01"}, {"type": "PUBKEY", "hex": sweep_pk}]}]}]
    su, err = ok(rpc("createrungtx",
        [[{"txid": fund_A_txid, "vout": 0}, {"txid": fund_B_txid, "vout": 0}],
         [spend_amt], sweep_rungs]), "spend-build")
    if not su: results.append((name, "FAIL", err)); return

    spent_outs = [
        {"amount": fund_amtA, "scriptPubKey": spk_A},
        {"amount": fund_amtB, "scriptPubKey": spk_B},
    ]
    signers = [
        {"input": 0,
         "blocks": [{"type": "SIG", "privkey": alice_wif}],
         "conditions": [{"blocks": [{"type": "SIG", "fields": [
             {"type": "SCHEME", "hex": "01"}, {"type": "PUBKEY", "hex": alice_h}]}]}]},
        {"input": 1,
         "blocks": [{"type": "SIG", "privkey": bob_wif}, {"type": "COSIGN"}],
         "conditions": [{"blocks": [
             {"type": "SIG", "fields": [
                 {"type": "SCHEME", "hex": "01"}, {"type": "PUBKEY", "hex": bob_h}]},
             {"type": "COSIGN", "fields": [
                 {"type": "HASH256", "hex": cosign_target}]}]}]},
    ]
    ss, err = ok(rpc("signrungtx", [su["hex"], signers, spent_outs]), "signrungtx")
    if not ss or not ss.get("complete"):
        results.append((name, "FAIL", f"sign-spend: {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction", [ss["hex"]]), "send-spend")
    if not spend_txid: results.append((name, "FAIL", err)); return
    mine(1)
    results.append((name, "OK",
        f"A={fund_A_txid[:8]} B={fund_B_txid[:8]} spend={spend_txid[:8]}"))


def t66_recurse_split():
    # RECURSE_SPLIT lets the UTXO split into multiple re-encumbered
    # outputs. Single-hop trial: fund with [RECURSE_SPLIT(max=2,
    # min_sats=10000)], spend by producing 2 outputs each carrying
    # the SAME conditions tree. The evaluator checks that each
    # output re-encumbers and respects the min_sats floor.
    name = "66. RECURSE_SPLIT (2-way, single hop)"
    rungs = [{"output_index": 0, "blocks": [{"type": "RECURSE_SPLIT", "fields": [
        {"type": "NUMERIC", "hex": (2).to_bytes(4, 'little').hex()},      # max_splits=2
        {"type": "NUMERIC", "hex": (10_000).to_bytes(4, 'little').hex()}]}]}]    # min_sats=10000

    u, uerr = get_or_make_small_utxo(name)
    if not u: results.append((name, "SKIP", uerr or "no UTXO")); return
    fund_amt = round(u["amount"] - 0.001, 8)
    fr, err = ok(rpc("createrungtx",
        [[{"txid": u["txid"], "vout": u["vout"]}], [fund_amt], rungs]), "fund")
    if not fr: results.append((name, "FAIL", err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet", [fr["hex"]], WALLET), "fund-sign")
    if not fs or not fs.get("complete"):
        results.append((name, "FAIL", f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction", [fs["hex"]]), "send-fund")
    if not fund_txid: results.append((name, "FAIL", err)); return
    mine(1)

    # Spend: build 2 child outputs each re-encumbering the SAME conditions
    # but with max_splits decremented (per eval — the rung leaf with
    # max_splits-1 is what the verifier expects for the next-hop root).
    half = round((fund_amt - 0.001) / 2, 8)
    child_rungs = [
        {"output_index": 0, "blocks": [{"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": (1).to_bytes(4, 'little').hex()},   # max=2-1
            {"type": "NUMERIC", "hex": (10_000).to_bytes(4, 'little').hex()}]}]},
        {"output_index": 1, "blocks": [{"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": (1).to_bytes(4, 'little').hex()},   # max=2-1
            {"type": "NUMERIC", "hex": (10_000).to_bytes(4, 'little').hex()}]}]},
    ]
    su, err = ok(rpc("createrungtx",
        [[{"txid": fund_txid, "vout": 0}], [half, half], child_rungs]),
        "spend-build")
    if not su: results.append((name, "FAIL", err)); return
    spent_outs = [{"amount": fund_amt, "scriptPubKey": fr["scriptPubKey"]}]
    signer = {"input": 0,
              "blocks": [{"type": "RECURSE_SPLIT"}],
              "conditions": [{"blocks": [{"type": "RECURSE_SPLIT", "fields": [
                  {"type": "NUMERIC", "hex": (2).to_bytes(4, 'little').hex()},
                  {"type": "NUMERIC", "hex": (10_000).to_bytes(4, 'little').hex()}]}]}]}
    ss, err = ok(rpc("signrungtx", [su["hex"], [signer], spent_outs]), "signrungtx")
    if not ss or not ss.get("complete"):
        results.append((name, "FAIL", f"sign-spend: {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction", [ss["hex"]]), "send-spend")
    if not spend_txid: results.append((name, "FAIL", err)); return
    mine(1)
    results.append((name, "OK", f"fund={fund_txid[:10]} spend={spend_txid[:10]}"))


if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    results.clear()
    for fn in (t64_key_ref_sig, t65_cosign, t66_recurse_split):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))
    print()
    for name, status, detail in results:
        marker = "OK " if status == "OK" else status[:3].upper()
        print(f"  [{marker}] {name:<48} {detail[:140]}")
    print(f"\nchain height (end): {rpc('getblockcount')['result']}")
