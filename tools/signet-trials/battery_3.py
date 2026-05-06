"""Battery 3: harder block shapes (HTLC, VAULT_LOCK, multisig+csv, legacy wrappers)."""
import sys
sys.path.insert(0, "/tmp")
exec(open("/tmp/v4_trials3.py").read().split("if __name__")[0])

results.clear()  # fresh batch

def t26_htlc_claim():
    recv = derive("t26-recv"); recv_h = recv.get_pubkey().get_bytes().hex()
    send = derive("t26-send"); send_h = send.get_pubkey().get_bytes().hex()
    pre = b"\x42" * 32
    fund = [{"output_index":0,"blocks":[{"type":"HTLC","fields":[
        {"type":"PREIMAGE","hex":pre.hex()},
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":recv_h},
        {"type":"PUBKEY","hex":send_h}]}]}]
    spender = [{"type":"HTLC","path":0,"pubkeys":[recv_h,send_h],
                "privkey":bytes_to_wif(recv.get_bytes(),True),
                "preimage":pre.hex()}]
    conds = [{"blocks":[{"type":"HTLC","fields":[
        {"type":"PREIMAGE","hex":pre.hex()},
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":recv_h},
        {"type":"PUBKEY","hex":send_h}]}]}]
    trial("26. HTLC claim (preimage + recv sig)", fund, spender, conds)

def t27_htlc_refund():
    recv = derive("t27-recv"); recv_h = recv.get_pubkey().get_bytes().hex()
    send = derive("t27-send"); send_h = send.get_pubkey().get_bytes().hex()
    pre = b"\x99" * 32
    fund = [{"output_index":0,"blocks":[{"type":"HTLC","fields":[
        {"type":"PREIMAGE","hex":pre.hex()},
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":recv_h},
        {"type":"PUBKEY","hex":send_h}]}]}]
    spender = [{"type":"HTLC","path":1,"pubkeys":[recv_h,send_h],
                "privkey":bytes_to_wif(send.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"HTLC","fields":[
        {"type":"PREIMAGE","hex":pre.hex()},
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":recv_h},
        {"type":"PUBKEY","hex":send_h}]}]}]
    trial("27. HTLC refund (sender sig + CSV elapsed)", fund, spender, conds,
          spend_input_extra={"sequence": 2}, mine_after_fund=3)

def t28_vault_lock_hot():
    rec = derive("t28-rec"); rec_h = rec.get_pubkey().get_bytes().hex()
    hot = derive("t28-hot"); hot_h = hot.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"VAULT_LOCK","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"PUBKEY","hex":rec_h},
        {"type":"PUBKEY","hex":hot_h}]}]}]
    spender = [{"type":"VAULT_LOCK","pubkeys":[rec_h,hot_h],
                "privkey":bytes_to_wif(hot.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"VAULT_LOCK","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"PUBKEY","hex":rec_h},
        {"type":"PUBKEY","hex":hot_h}]}]}]
    trial("28. VAULT_LOCK hot path", fund, spender, conds,
          spend_input_extra={"sequence": 2}, mine_after_fund=3)

def t29_timelocked_multisig():
    pks = [derive(f"t29-{c}") for c in "ABC"]
    pks_h = [k.get_pubkey().get_bytes().hex() for k in pks]
    wifs = [bytes_to_wif(k.get_bytes(),True) for k in pks]
    fund = [{"output_index":0,"blocks":[{"type":"TIMELOCKED_MULTISIG","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pks_h[0]},
        {"type":"PUBKEY","hex":pks_h[1]},
        {"type":"PUBKEY","hex":pks_h[2]}]}]}]
    spender = [{"type":"TIMELOCKED_MULTISIG","privkeys":[wifs[0],wifs[1]],"pubkeys":pks_h}]
    conds = [{"blocks":[{"type":"TIMELOCKED_MULTISIG","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pks_h[0]},
        {"type":"PUBKEY","hex":pks_h[1]},
        {"type":"PUBKEY","hex":pks_h[2]}]}]}]
    trial("29. TIMELOCKED_MULTISIG 2-of-3 + CSV=2", fund, spender, conds,
          spend_input_extra={"sequence": 2}, mine_after_fund=3)

def t30_p2pk_legacy():
    pk = derive("t30-p2pk"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"P2PK_LEGACY","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"P2PK_LEGACY","privkey":bytes_to_wif(pk.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"P2PK_LEGACY","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("30. P2PK_LEGACY", fund, spender, conds)

def t31_p2pkh_legacy():
    pk = derive("t31-p2pkh"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"P2PKH_LEGACY","fields":[
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"P2PKH_LEGACY","privkey":bytes_to_wif(pk.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"P2PKH_LEGACY","fields":[
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("31. P2PKH_LEGACY", fund, spender, conds)

def t32_p2wpkh_legacy():
    pk = derive("t32-p2wpkh"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"P2WPKH_LEGACY","fields":[
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"P2WPKH_LEGACY","privkey":bytes_to_wif(pk.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"P2WPKH_LEGACY","fields":[
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("32. P2WPKH_LEGACY", fund, spender, conds)

def t33_p2tr_legacy():
    pk = derive("t33-p2tr"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"P2TR_LEGACY","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"P2TR_LEGACY","privkey":bytes_to_wif(pk.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"P2TR_LEGACY","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("33. P2TR_LEGACY", fund, spender, conds)

def t34_anchor_fee():
    pk1 = derive("t34-A"); pk1_h = pk1.get_pubkey().get_bytes().hex()
    pk2 = derive("t34-B"); pk2_h = pk2.get_pubkey().get_bytes().hex()
    # Widened from the original (min=1000, max=100000, weight=400) which
    # double-failed: trial fee≈100k sat / vsize≈196 vB → fee_rate≈510 sat/vB
    # < min(1000), and weight≈784 WU > max(400). Realistic for a 1-in/1-out
    # MLSC script-path spend with 4-field ANCHOR_FEE witness:
    # min=10 sat/vB, max=10000 sat/vB, max_weight=2000 WU.
    fund = [{"output_index":0,"blocks":[{"type":"ANCHOR_FEE","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"NUMERIC","hex":(10).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(10_000).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(2_000).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(12345).to_bytes(4,'little').hex()},
        {"type":"PUBKEY","hex":pk1_h},
        {"type":"PUBKEY","hex":pk2_h}]}]}]
    # ANCHOR_FEE is 2-of-2: both keys must sign.
    spender = [{"type":"ANCHOR_FEE",
                "privkeys":[bytes_to_wif(pk1.get_bytes(),True),
                             bytes_to_wif(pk2.get_bytes(),True)],
                "pubkeys":[pk1_h, pk2_h]}]
    conds = [{"blocks":[{"type":"ANCHOR_FEE","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"NUMERIC","hex":(10).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(10_000).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(2_000).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(12345).to_bytes(4,'little').hex()},
        {"type":"PUBKEY","hex":pk1_h},
        {"type":"PUBKEY","hex":pk2_h}]}]}]
    trial("34. ANCHOR_FEE 2-of-2", fund, spender, conds)

def t35_recurse_chain():
    # RECURSE_SAME chain: spend re-encumbers the SAME conditions.
    # Use the harness directly because the sweep_rungs need to mirror fund.
    rungs = [{"output_index":0,"blocks":[{"type":"RECURSE_SAME","fields":[
        {"type":"NUMERIC","hex":"05000000"}]}]}]
    u, uerr = get_or_make_small_utxo("35")
    if not u: results.append(("35. RECURSE_SAME proper chain", "SKIP", uerr or "no UTXO")); return
    fund_amt = round(u["amount"] - 0.001, 8)
    fr, err = ok(rpc("createrungtx",
        [[{"txid":u["txid"],"vout":u["vout"]}],[fund_amt],rungs]),"fund")
    if not fr: results.append(("35. RECURSE_SAME proper chain","FAIL",err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet",[fr["hex"]],WALLET),"fund-sign")
    if not fs or not fs.get("complete"):
        results.append(("35. RECURSE_SAME proper chain","FAIL",f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction",[fs["hex"]]),"send-fund")
    if not fund_txid: results.append(("35. RECURSE_SAME proper chain","FAIL",err)); return
    mine(1)
    # Spend: re-encumber the SAME conditions (RECURSE_SAME requires this)
    spend_amt = round(fund_amt - 0.001, 8)
    su, err = ok(rpc("createrungtx",
        [[{"txid":fund_txid,"vout":0}],[spend_amt],rungs]),"spend-build")
    if not su: results.append(("35. RECURSE_SAME proper chain","FAIL",err)); return
    spent_outs = [{"amount":fund_amt,"scriptPubKey":fr["scriptPubKey"]}]
    signer = {"input":0,"blocks":[{"type":"RECURSE_SAME"}],
               "conditions":[{"blocks":[{"type":"RECURSE_SAME","fields":[
                   {"type":"NUMERIC","hex":"05000000"}]}]}]}
    ss, err = ok(rpc("signrungtx",[su["hex"],[signer],spent_outs]),"sign-spend")
    if not ss or not ss.get("complete"):
        results.append(("35. RECURSE_SAME proper chain","FAIL",f"sign-spend {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction",[ss["hex"]]),"send-spend")
    if not spend_txid: results.append(("35. RECURSE_SAME proper chain","FAIL",err)); return
    mine(1)
    results.append(("35. RECURSE_SAME proper chain","OK",f"fund={fund_txid[:10]} spend={spend_txid[:10]}"))

def t36_multi_output_fund():
    """Single fund tx with TWO MLSC outputs (different rungs)."""
    pk1 = derive("t36-out0"); pk1_h = pk1.get_pubkey().get_bytes().hex()
    pk2 = derive("t36-out1"); pk2_h = pk2.get_pubkey().get_bytes().hex()
    rungs = [
        {"output_index":0,"blocks":[{"type":"SIG","fields":[
            {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pk1_h}]}]},
        {"output_index":1,"blocks":[{"type":"SIG","fields":[
            {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pk2_h}]}]}]
    u, uerr = get_or_make_small_utxo("36")
    if not u: results.append(("36. multi-output fund","SKIP",uerr or "no UTXO")); return
    each = round((u["amount"] - 0.001) / 2, 8)
    fr, err = ok(rpc("createrungtx",
        [[{"txid":u["txid"],"vout":u["vout"]}],[each, each],rungs]),"fund")
    if not fr: results.append(("36. multi-output fund","FAIL",err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet",[fr["hex"]],WALLET),"fund-sign")
    if not fs or not fs.get("complete"):
        results.append(("36. multi-output fund","FAIL",f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction",[fs["hex"]]),"send-fund")
    if not fund_txid: results.append(("36. multi-output fund","FAIL",err)); return
    mine(1)
    results.append(("36. multi-output fund (2 MLSC outs)","OK",f"fund={fund_txid[:10]}"))

if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    for fn in (t26_htlc_claim, t27_htlc_refund, t28_vault_lock_hot,
               t29_timelocked_multisig, t30_p2pk_legacy, t31_p2pkh_legacy,
               t32_p2wpkh_legacy, t33_p2tr_legacy, t34_anchor_fee,
               t35_recurse_chain, t36_multi_output_fund):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:120]))
    print()
    for name, status, detail in results:
        marker = "✓" if status == "OK" else ("‼" if status=="EXC" else "✗")
        print(f"  {marker} {name:<48} {status:<5} {detail[:90]}")
    print()
    ok_count = sum(1 for _, s, _ in results if s == "OK")
    print(f"summary: {ok_count}/{len(results)} OK")
    print(f"chain height (end): {rpc('getblockcount')['result']}")
