"""Battery 6: CTV, ACCUMULATOR, RECURSE_UNTIL, RECURSE_COUNT.

Adds the consensus-significant block types that need slightly more
test infrastructure:
- CTV: compute the BIP-119 template hash of the spend tx via the
  `computectvhash` RPC, commit that hash in the fund's conditions.
- ACCUMULATOR: build a 1-element accumulator (depth=0, no proof
  needed since the leaf IS the root).
- RECURSE_UNTIL: requires the spend tx's nLockTime >= until_height.
- RECURSE_COUNT: chain-style; spend re-encumbers with count-1 OR (when
  count==0) terminates with arbitrary output.
"""
import sys, re, hashlib
sys.path.insert(0, "/tmp")
src3 = open("/tmp/v4_trials3.py").read()
src3 = re.sub(r'^if __name__ == "__main__":.*?(?=^(?:def |# |import |$))', "", src3,
              flags=re.MULTILINE | re.DOTALL)
exec(src3, globals())


def t57_ctv():
    # CTV (BIP-119) commits to the template hash of the spending tx.
    # 1. Build a draft spend tx (no signatures needed for CTV — the
    #    hash covers structure).
    # 2. Call computectvhash to get the canonical template hash.
    # 3. Fund with HASH256 = that hash.
    # 4. The actual spend re-uses the exact draft so the live template
    #    hash matches.
    name = "57. CTV (BIP-119 template)"
    u, uerr = get_or_make_small_utxo(name)
    if not u: results.append((name, "SKIP", uerr or "no UTXO")); return
    fund_amt = round(u["amount"] - 0.001, 8)
    spend_amt = round(fund_amt - 0.001, 8)
    sweep_pk = pk_hex(f"sweep-{name}")
    sweep_rungs = [{"output_index":0,"blocks":[{"type":"SIG","fields":[
        {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":sweep_pk}]}]}]
    # We don't yet have the fund txid, but CTV's template hash doesn't
    # depend on input prevouts — only on outputs/sequences/counts. Build
    # the spend draft with a placeholder prevout, compute the template
    # hash; then construct the fund tx with that hash; then the real
    # spend uses the same outputs so the template hash matches.
    placeholder_prev = {"txid":"00"*32,"vout":0}
    su_draft, err = ok(rpc("createrungtx",
        [[placeholder_prev],[spend_amt],sweep_rungs]),"draft-spend")
    if not su_draft: results.append((name,"FAIL",err)); return
    ctv_r = rpc("computectvhash", [su_draft["hex"], 0])
    if ctv_r.get("error"):
        results.append((name,"FAIL",f"computectvhash: {ctv_r['error']}")); return
    template_hash = ctv_r["result"]["hash"]
    # Fund with CTV(template_hash) — `HASH256` is allowed in CTV
    # conditions (whitelist exception in createrungtx — see rpc.cpp:347).
    fund_rungs = [{"output_index":0,"blocks":[{"type":"CTV","fields":[
        {"type":"HASH256","hex":template_hash}]}]}]
    fr, err = ok(rpc("createrungtx",
        [[{"txid":u["txid"],"vout":u["vout"]}],[fund_amt],fund_rungs]),"fund")
    if not fr: results.append((name,"FAIL",err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet",[fr["hex"]],WALLET),"fund-sign")
    if not fs or not fs.get("complete"):
        results.append((name,"FAIL",f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction",[fs["hex"]]),"send-fund")
    if not fund_txid: results.append((name,"FAIL",err)); return
    mine(1)
    # Real spend: same outputs as draft, but real prevout. CTV template
    # hash is computed over outputs/sequences/counts so the prev change
    # doesn't shift the hash.
    real_prev = {"txid":fund_txid,"vout":0}
    su, err = ok(rpc("createrungtx",
        [[real_prev],[spend_amt],sweep_rungs]),"spend-build")
    if not su: results.append((name,"FAIL",err)); return
    spent_outs = [{"amount":fund_amt,"scriptPubKey":fr["scriptPubKey"]}]
    signer = {"input":0,"blocks":[{"type":"CTV"}],
              "conditions":[{"blocks":[{"type":"CTV","fields":[
                  {"type":"HASH256","hex":template_hash}]}]}]}
    ss, err = ok(rpc("signrungtx",[su["hex"],[signer],spent_outs]),"sign-spend")
    if not ss or not ss.get("complete"):
        results.append((name,"FAIL",f"sign-spend {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction",[ss["hex"]]),"send-spend")
    if not spend_txid: results.append((name,"FAIL",err)); return
    mine(1)
    results.append((name,"OK",f"fund={fund_txid[:10]} spend={spend_txid[:10]}"))


def t58_accumulator():
    # ACCUMULATOR conditions: HASH256(set_root). Witness:
    # NUMERIC(element_id) + MERKLE_PROOF(siblings).
    # 1-element set: the leaf IS the root, depth=0, empty proof.
    # leaf = TaggedHash("LadderAccumulatorLeaf/v1", element_id_LE).
    # set_root = leaf (since there's only 1 element).
    import hashlib
    eid_bytes = (3).to_bytes(4, 'little')   # element_id=3
    tag_hash = hashlib.sha256(b"LadderAccumulatorLeaf/v1").digest()
    leaf = hashlib.sha256(tag_hash + tag_hash + eid_bytes).digest()
    fund = [{"output_index":0,"blocks":[{"type":"ACCUMULATOR","fields":[
        {"type":"HASH256","hex":leaf.hex()}]}]}]
    spender = [{"type":"ACCUMULATOR","element_id":3,"proof":[]}]
    conds = [{"blocks":[{"type":"ACCUMULATOR","fields":[
        {"type":"HASH256","hex":leaf.hex()}]}]}]
    trial("58. ACCUMULATOR (1-elem set, eid=3)", fund, spender, conds)


def t59_recurse_until():
    # RECURSE_UNTIL: until_height field; spend valid only when
    # tx.nLockTime >= until_height OR the output re-encumbers with the
    # same conditions. Simplest path: re-encumber (mirror RECURSE_SAME).
    name = "59. RECURSE_UNTIL chain (re-encumber)"
    rungs = [{"output_index":0,"blocks":[{"type":"RECURSE_UNTIL","fields":[
        {"type":"NUMERIC","hex":"00000000"}]}]}]   # until_height=0
    u, uerr = get_or_make_small_utxo(name)
    if not u: results.append((name,"SKIP",uerr or "no UTXO")); return
    fund_amt = round(u["amount"] - 0.001, 8)
    fr, err = ok(rpc("createrungtx",
        [[{"txid":u["txid"],"vout":u["vout"]}],[fund_amt],rungs]),"fund")
    if not fr: results.append((name,"FAIL",err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet",[fr["hex"]],WALLET),"fund-sign")
    if not fs or not fs.get("complete"):
        results.append((name,"FAIL",f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction",[fs["hex"]]),"send-fund")
    if not fund_txid: results.append((name,"FAIL",err)); return
    mine(1)
    spend_amt = round(fund_amt - 0.001, 8)
    su, err = ok(rpc("createrungtx",
        [[{"txid":fund_txid,"vout":0}],[spend_amt],rungs]),"spend-build")
    if not su: results.append((name,"FAIL",err)); return
    spent_outs = [{"amount":fund_amt,"scriptPubKey":fr["scriptPubKey"]}]
    signer = {"input":0,"blocks":[{"type":"RECURSE_UNTIL"}],
              "conditions":[{"blocks":[{"type":"RECURSE_UNTIL","fields":[
                  {"type":"NUMERIC","hex":"00000000"}]}]}]}
    ss, err = ok(rpc("signrungtx",[su["hex"],[signer],spent_outs]),"sign-spend")
    if not ss or not ss.get("complete"):
        results.append((name,"FAIL",f"sign-spend {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction",[ss["hex"]]),"send-spend")
    if not spend_txid: results.append((name,"FAIL",err)); return
    mine(1)
    results.append((name,"OK",f"fund={fund_txid[:10]} spend={spend_txid[:10]}"))


def t60_recurse_count():
    # RECURSE_COUNT: like RECURSE_SAME but the conditions carry a
    # NUMERIC(count) that must decrement by 1 each hop. count==0 means
    # the covenant terminates (any output allowed).
    # Test the count==0 termination path: fund with count=0, spend to
    # arbitrary SIG output (no need to re-encumber).
    name = "60. RECURSE_COUNT (count=0 terminator)"
    fund_rungs = [{"output_index":0,"blocks":[{"type":"RECURSE_COUNT","fields":[
        {"type":"NUMERIC","hex":"00000000"}]}]}]   # count=0 → terminate
    u, uerr = get_or_make_small_utxo(name)
    if not u: results.append((name,"SKIP",uerr or "no UTXO")); return
    fund_amt = round(u["amount"] - 0.001, 8)
    fr, err = ok(rpc("createrungtx",
        [[{"txid":u["txid"],"vout":u["vout"]}],[fund_amt],fund_rungs]),"fund")
    if not fr: results.append((name,"FAIL",err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet",[fr["hex"]],WALLET),"fund-sign")
    if not fs or not fs.get("complete"):
        results.append((name,"FAIL",f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction",[fs["hex"]]),"send-fund")
    if not fund_txid: results.append((name,"FAIL",err)); return
    mine(1)
    spend_amt = round(fund_amt - 0.001, 8)
    sweep_pk = pk_hex(f"sweep-{name}")
    sweep_rungs = [{"output_index":0,"blocks":[{"type":"SIG","fields":[
        {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":sweep_pk}]}]}]
    su, err = ok(rpc("createrungtx",
        [[{"txid":fund_txid,"vout":0}],[spend_amt],sweep_rungs]),"spend-build")
    if not su: results.append((name,"FAIL",err)); return
    spent_outs = [{"amount":fund_amt,"scriptPubKey":fr["scriptPubKey"]}]
    signer = {"input":0,"blocks":[{"type":"RECURSE_COUNT"}],
              "conditions":[{"blocks":[{"type":"RECURSE_COUNT","fields":[
                  {"type":"NUMERIC","hex":"00000000"}]}]}]}
    ss, err = ok(rpc("signrungtx",[su["hex"],[signer],spent_outs]),"sign-spend")
    if not ss or not ss.get("complete"):
        results.append((name,"FAIL",f"sign-spend {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction",[ss["hex"]]),"send-spend")
    if not spend_txid: results.append((name,"FAIL",err)); return
    mine(1)
    results.append((name,"OK",f"fund={fund_txid[:10]} spend={spend_txid[:10]}"))


if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    results.clear()
    for fn in (t57_ctv, t58_accumulator, t59_recurse_until, t60_recurse_count):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))
    print()
    for name, status, detail in results:
        marker = "OK " if status == "OK" else status[:3].upper()
        print(f"  [{marker}] {name:<48} {detail[:140]}")
    print(f"\nchain height (end): {rpc('getblockcount')['result']}")
