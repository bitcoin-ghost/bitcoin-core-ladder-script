#!/usr/bin/env python3
"""v0.23 signet tx-trial battery."""
import hashlib, json, sys, base64
from urllib import request as urlreq, error as urlerr

URL = "http://127.0.0.1:38332/"
AUTH = base64.b64encode(b"ladderrpc:ladder_signet_rpc_2026").decode()
WALLET = "ladder"
MINE_ADDR = "tb1q6u0d2d32syczatw57m0evwqztjrfsypt30zqnl"

sys.path.insert(0, "/home/defenwycke/dev/projects/bitcoin-core-ladder/test/functional")
from test_framework.key import ECKey
from test_framework.wallet_util import bytes_to_wif

def rpc(method, params=None, wallet=None):
    body = json.dumps({"jsonrpc":"1.0","id":"x","method":method,"params":params if params is not None else []}).encode()
    url = URL + (f"wallet/{wallet}" if wallet else "")
    req = urlreq.Request(url, data=body, headers={"Content-Type":"application/json","Authorization":f"Basic {AUTH}"})
    try:
        with urlreq.urlopen(req, timeout=60) as r: return json.loads(r.read())
    except urlerr.HTTPError as e: return json.loads(e.read())

def ok(r, label):
    if r.get("error") is not None: return None, f"{r['error']}"
    return r["result"], None

def derive(seed):
    h = hashlib.sha256(seed.encode()).digest()
    if h == b"\x00"*32: h = b"\x01"*32
    k = ECKey(); k.set(h, True); return k

def pk_hex(seed): return derive(seed).get_pubkey().get_bytes().hex()

def mine(n=1):
    # Named-params with high maxtries; positional form is buggy on this build.
    return rpc("generatetoaddress", {"nblocks": n, "address": MINE_ADDR, "maxtries": 100_000_000})

def get_utxo():
    r = rpc("listunspent", [1], WALLET)
    return r["result"][0] if r["result"] else None

results = []

SMALL_TRIAL_BTC = 1.0  # per-trial fund amount, returns ~49 BTC change to wallet

def get_or_make_small_utxo(label):
    """Send SMALL_TRIAL_BTC to a fresh wallet address, mine 1 confirm,
    return the new UTXO. Each trial gets its own small UTXO so the
    50-BTC coinbases stay reusable as wallet change."""
    addr_r = rpc("getnewaddress", wallet=WALLET)
    if addr_r.get("error"): return None, f"getnewaddress: {addr_r['error']}"
    addr = addr_r["result"]
    sr = rpc("sendtoaddress", [addr, SMALL_TRIAL_BTC], wallet=WALLET)
    if sr.get("error"): return None, f"sendtoaddress: {sr['error']}"
    mine(1)
    listr = rpc("listunspent", [1, 9999999, [addr]], wallet=WALLET)
    utxos = listr["result"] if listr.get("result") else []
    if not utxos: return None, f"small UTXO not found at {addr}"
    return utxos[0], None

def trial(name, fund_rungs, spender_blocks, conditions_arr, *,
          spend_input_extra=None, mine_after_fund=1, expect_fail=False):
    """spend_input_extra: e.g. {"sequence": 2} for CSV.
    expect_fail=True: flip OK/FAIL — the trial PASSES if the spend is
    rejected at any step (sign, send, or send-fund). Used for trials
    that are deliberate negatives."""
    def record(status, detail):
        if expect_fail:
            # Invert: a real "FAIL" becomes "PASS_NEG"; a real "OK" becomes
            # "UNEXPECTED_OK" because the trial was meant to be rejected.
            if status == "FAIL":
                results.append((name, "PASS_NEG", detail))
            elif status == "OK":
                results.append((name, "UNEXPECTED_OK", detail))
            else:
                results.append((name, status, detail))
        else:
            results.append((name, status, detail))

    # v0.24: use a small per-trial wallet UTXO (~1 BTC) instead of the
    # first listunspent (which is a 50-BTC coinbase). Sendtoaddress
    # creates a small UTXO and returns the rest as change, so the
    # wallet stays reusable across the whole 36-trial battery without
    # needing to re-mine 1800+ BTC of coinbases.
    u, err = get_or_make_small_utxo(name)
    if not u: record("SKIP", err or "no UTXO"); return
    fund_amt = round(u["amount"] - 0.001, 8)
    fr, err = ok(rpc("createrungtx",
        [[{"txid":u["txid"],"vout":u["vout"]}], [fund_amt], fund_rungs]), "fund")
    if not fr: record("FAIL", err); return
    fs, err = ok(rpc("signrawtransactionwithwallet", [fr["hex"]], WALLET), "fund-sign")
    if not fs or not fs.get("complete"):
        record("FAIL", f"fund-sign {err}"); return
    fund_txid, err = ok(rpc("sendrawtransaction", [fs["hex"]]), "send-fund")
    if not fund_txid: record("FAIL", err); return
    mr = mine(mine_after_fund)
    if not mr.get("result"):
        record("FAIL", f"mine-after-fund: {mr}"); return

    spend_amt = round(fund_amt - 0.001, 8)
    sweep_pk = pk_hex(f"sweep-{name}")
    sweep_rungs = [{"output_index":0,"blocks":[{"type":"SIG","fields":[
        {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":sweep_pk}]}]}]
    spend_input = {"txid": fund_txid, "vout": 0}
    if spend_input_extra: spend_input.update(spend_input_extra)
    su, err = ok(rpc("createrungtx",
        [[spend_input], [spend_amt], sweep_rungs]), "spend-build")
    if not su: record("FAIL", err); return
    spent_outs = [{"amount": fund_amt, "scriptPubKey": fr["scriptPubKey"]}]
    signer = {"input":0, "blocks": spender_blocks, "conditions": conditions_arr}
    ss, err = ok(rpc("signrungtx", [su["hex"], [signer], spent_outs]), "signrungtx")
    if not ss or not ss.get("complete"):
        record("FAIL", f"sign-spend {err}"); return
    spend_txid, err = ok(rpc("sendrawtransaction", [ss["hex"]]), "send-spend")
    if not spend_txid: record("FAIL", err); return
    mine(1)
    record("OK", f"fund={fund_txid[:10]} spend={spend_txid[:10]}")

# ─── Trials ────────────────────────────────────────────────────────

def t01_sig():
    pk = derive("t01-sig"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"SIG","fields":[
        {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"SIG","privkey":bytes_to_wif(pk.get_bytes(), True)}]
    conds = [{"blocks":[{"type":"SIG","fields":[
        {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkh}]}]}]
    trial("01. SIG single-rung", fund, spender, conds)

def t02_csv():
    fund = [{"output_index":0,"blocks":[{"type":"CSV","fields":[
        {"type":"NUMERIC","hex":"02000000"}]}]}]
    spender = [{"type":"CSV"}]
    conds = [{"blocks":[{"type":"CSV","fields":[
        {"type":"NUMERIC","hex":"02000000"}]}]}]
    trial("02. CSV (Empty, csv=2)", fund, spender, conds,
          spend_input_extra={"sequence": 2}, mine_after_fund=3)

def t03_cltv_height0():
    fund = [{"output_index":0,"blocks":[{"type":"CLTV","fields":[
        {"type":"NUMERIC","hex":"00000000"}]}]}]
    spender = [{"type":"CLTV"}]
    conds = [{"blocks":[{"type":"CLTV","fields":[
        {"type":"NUMERIC","hex":"00000000"}]}]}]
    trial("03. CLTV (height=0)", fund, spender, conds)

def t04_anchor():
    fund = [{"output_index":0,"blocks":[{"type":"ANCHOR","fields":[
        {"type":"NUMERIC","hex":"0a000000"}]}]}]
    spender = [{"type":"ANCHOR"}]
    conds = [{"blocks":[{"type":"ANCHOR","fields":[
        {"type":"NUMERIC","hex":"0a000000"}]}]}]
    trial("04. ANCHOR marker=10", fund, spender, conds)

def t05_amount_lock():
    # AMOUNT_LOCK NUMERIC fields are capped at 4 B (uint32 max ≈ 42.95
    # BTC), so a band around the now-default ~1 BTC small trial UTXO
    # easily fits. Spend amount is ~0.999 BTC = 99_900_000 sat.
    fund = [{"output_index":0,"blocks":[{"type":"AMOUNT_LOCK","fields":[
        {"type":"NUMERIC","hex":(50_000_000).to_bytes(4,'little').hex()},   # 0.5 BTC
        {"type":"NUMERIC","hex":(150_000_000).to_bytes(4,'little').hex()}]}]}]  # 1.5 BTC
    spender = [{"type":"AMOUNT_LOCK"}]
    conds = [{"blocks":[{"type":"AMOUNT_LOCK","fields":[
        {"type":"NUMERIC","hex":(50_000_000).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(150_000_000).to_bytes(4,'little').hex()}]}]}]
    trial("05. AMOUNT_LOCK 0.5-1.5 BTC", fund, spender, conds)

def t06_hash_guarded():
    pre = b"trial-6-preimage"
    fund = [{"output_index":0,"blocks":[{"type":"HASH_GUARDED","fields":[
        {"type":"PREIMAGE","hex":pre.hex()}]}]}]
    spender = [{"type":"HASH_GUARDED","preimage":pre.hex()}]
    # F24-corrected: pass PREIMAGE on conditions side too; the auto-derive
    # produces the same HASH256 as the fund-time conversion.
    conds = [{"blocks":[{"type":"HASH_GUARDED","fields":[
        {"type":"PREIMAGE","hex":pre.hex()}]}]}]
    trial("06. HASH_GUARDED preimage", fund, spender, conds)

def t07_weight_limit():
    fund = [{"output_index":0,"blocks":[{"type":"WEIGHT_LIMIT","fields":[
        {"type":"NUMERIC","hex":"a0860100"}]}]}]
    spender = [{"type":"WEIGHT_LIMIT"}]
    conds = [{"blocks":[{"type":"WEIGHT_LIMIT","fields":[
        {"type":"NUMERIC","hex":"a0860100"}]}]}]
    trial("07. WEIGHT_LIMIT 100k wu", fund, spender, conds)

def t08_anchor_channel():
    fund = [{"output_index":0,"blocks":[{"type":"ANCHOR_CHANNEL","fields":[
        {"type":"NUMERIC","hex":"01000000"}]}]}]
    spender = [{"type":"ANCHOR_CHANNEL"}]
    conds = [{"blocks":[{"type":"ANCHOR_CHANNEL","fields":[
        {"type":"NUMERIC","hex":"01000000"}]}]}]
    trial("08. ANCHOR_CHANNEL marker", fund, spender, conds)

def t09_compound_sig_csv():
    pk = derive("t09-sig"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[
        {"type":"SIG","fields":[{"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkh}]},
        {"type":"CSV","fields":[{"type":"NUMERIC","hex":"02000000"}]}]}]
    spender = [
        {"type":"SIG","privkey":bytes_to_wif(pk.get_bytes(), True)},
        {"type":"CSV"}]
    conds = [{"blocks":[
        {"type":"SIG","fields":[{"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkh}]},
        {"type":"CSV","fields":[{"type":"NUMERIC","hex":"02000000"}]}]}]
    trial("09. AND(SIG, CSV=2)", fund, spender, conds,
          spend_input_extra={"sequence": 2}, mine_after_fund=3)

def t10_or_two_sigs():
    pkA = derive("t10-A"); pkA_h = pkA.get_pubkey().get_bytes().hex()
    pkB = derive("t10-B"); pkB_h = pkB.get_pubkey().get_bytes().hex()
    fund = [
        {"output_index":0,"blocks":[{"type":"SIG","fields":[
            {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkA_h}]}]},
        {"output_index":0,"blocks":[{"type":"SIG","fields":[
            {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkB_h}]}]}]
    # Spend rung 0 (the A path).
    spender = [{"type":"SIG","privkey":bytes_to_wif(pkA.get_bytes(), True)}]
    conds = [
        {"blocks":[{"type":"SIG","fields":[
            {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkA_h}]}]},
        {"blocks":[{"type":"SIG","fields":[
            {"type":"SCHEME","hex":"01"},{"type":"PUBKEY","hex":pkB_h}]}]}]
    trial("10. OR(SIG_A, SIG_B), spend A", fund, spender, conds)

if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    for fn in (t01_sig, t02_csv, t03_cltv_height0, t04_anchor, t05_amount_lock,
               t06_hash_guarded, t07_weight_limit, t08_anchor_channel,
               t09_compound_sig_csv, t10_or_two_sigs):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:120]))
    print()
    for name, status, detail in results:
        marker = "✓" if status == "OK" else "✗"
        print(f"  {marker} {name:<48} {status:<5} {detail}")
    print()
    ok_count = sum(1 for _, s, _ in results if s == "OK")
    print(f"summary: {ok_count}/{len(results)} OK")
    print(f"chain height (end): {rpc('getblockcount')['result']}")

# ─── Additional trials ────────────────────────────────────────────

def t11_hash_sig():
    pk = derive("t11-sig"); pkh = pk.get_pubkey().get_bytes().hex()
    pre = b"trial-11-preimage"
    fund = [{"output_index":0,"blocks":[{"type":"HASH_SIG","fields":[
        {"type":"PREIMAGE","hex":pre.hex()},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"HASH_SIG","privkey":bytes_to_wif(pk.get_bytes(), True),
                "preimage": pre.hex()}]
    conds = [{"blocks":[{"type":"HASH_SIG","fields":[
        {"type":"PREIMAGE","hex":pre.hex()},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("11. HASH_SIG (preimage + sig)", fund, spender, conds)

def t12_timelocked_sig():
    pk = derive("t12-sig"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"TIMELOCKED_SIG","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"TIMELOCKED_SIG","privkey":bytes_to_wif(pk.get_bytes(), True)}]
    conds = [{"blocks":[{"type":"TIMELOCKED_SIG","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("12. TIMELOCKED_SIG (SIG + csv=2)", fund, spender, conds,
          spend_input_extra={"sequence": 2}, mine_after_fund=3)

def t13_cltv_sig():
    pk = derive("t13-sig"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"CLTV_SIG","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"CLTV_SIG","privkey":bytes_to_wif(pk.get_bytes(), True)}]
    conds = [{"blocks":[{"type":"CLTV_SIG","fields":[
        {"type":"SCHEME","hex":"01"},
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("13. CLTV_SIG (SIG + cltv=0)", fund, spender, conds)

def t14_multisig_2of3():
    pk1 = derive("t14-A"); pk2 = derive("t14-B"); pk3 = derive("t14-C")
    pks_hex = [k.get_pubkey().get_bytes().hex() for k in (pk1,pk2,pk3)]
    fund = [{"output_index":0,"blocks":[{"type":"MULTISIG","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pks_hex[0]},
        {"type":"PUBKEY","hex":pks_hex[1]},
        {"type":"PUBKEY","hex":pks_hex[2]}]}]}]
    spender = [{"type":"MULTISIG",
                "privkeys":[bytes_to_wif(pk1.get_bytes(),True), bytes_to_wif(pk2.get_bytes(),True)],
                "pubkeys": pks_hex}]
    conds = [{"blocks":[{"type":"MULTISIG","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"SCHEME","hex":"01"},
        {"type":"PUBKEY","hex":pks_hex[0]},
        {"type":"PUBKEY","hex":pks_hex[1]},
        {"type":"PUBKEY","hex":pks_hex[2]}]}]}]
    trial("14. MULTISIG 2-of-3", fund, spender, conds)

def t15_input_count():
    fund = [{"output_index":0,"blocks":[{"type":"INPUT_COUNT","fields":[
        {"type":"NUMERIC","hex":"01000000"},   # min=1
        {"type":"NUMERIC","hex":"0a000000"}]}]}]  # max=10
    spender = [{"type":"INPUT_COUNT"}]
    conds = [{"blocks":[{"type":"INPUT_COUNT","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"0a000000"}]}]}]
    trial("15. INPUT_COUNT [1, 10]", fund, spender, conds)

def t16_output_count():
    fund = [{"output_index":0,"blocks":[{"type":"OUTPUT_COUNT","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"0a000000"}]}]}]
    spender = [{"type":"OUTPUT_COUNT"}]
    conds = [{"blocks":[{"type":"OUTPUT_COUNT","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"0a000000"}]}]}]
    trial("16. OUTPUT_COUNT [1, 10]", fund, spender, conds)

def t17_epoch_gate():
    # EPOCH_GATE is `block_height % epoch_size < window_size`, NOT the
    # height-band the previous trial config implied. Fields are
    # (epoch_size, window_size); evaluator rejects epoch_size=0 with
    # ERROR. Use (epoch_size=1, window_size=1) → position=0 < 1 →
    # always SATISFIED regardless of block height.
    fund = [{"output_index":0,"blocks":[{"type":"EPOCH_GATE","fields":[
        {"type":"NUMERIC","hex":"01000000"},  # epoch_size=1
        {"type":"NUMERIC","hex":"01000000"}]}]}]  # window_size=1
    spender = [{"type":"EPOCH_GATE"}]
    conds = [{"blocks":[{"type":"EPOCH_GATE","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"01000000"}]}]}]
    trial("17. EPOCH_GATE epoch=1 window=1", fund, spender, conds)

def t18_tagged_hash():
    # Evaluator at hash.cpp:47 computes
    # `SHA256(tag_hash || tag_hash || preimage) == expected_hash`.
    # The previous fixed-value config (aa*32, bb*32, no real preimage)
    # could never satisfy. Pre-compute the expected_hash from a real
    # preimage and pass the matching preimage in the spender witness.
    tag_hash = hashlib.sha256(b"trial-18-tag").digest()  # 32 B
    pre = b"trial-18-preimage" + b"\x00" * (32 - len(b"trial-18-preimage"))  # pad to 32
    expected = hashlib.sha256(tag_hash + tag_hash + pre).digest()
    fund = [{"output_index":0,"blocks":[{"type":"TAGGED_HASH","fields":[
        {"type":"HASH256","hex":tag_hash.hex()},
        {"type":"HASH256","hex":expected.hex()}]}]}]
    spender = [{"type":"TAGGED_HASH","preimage":pre.hex()}]
    conds = [{"blocks":[{"type":"TAGGED_HASH","fields":[
        {"type":"HASH256","hex":tag_hash.hex()},
        {"type":"HASH256","hex":expected.hex()}]}]}]
    trial("18. TAGGED_HASH (real preimage)", fund, spender, conds)

def t19_relative_value():
    fund = [{"output_index":0,"blocks":[{"type":"RELATIVE_VALUE","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"02000000"}]}]}]   # 1/2 ratio
    spender = [{"type":"RELATIVE_VALUE"}]
    conds = [{"blocks":[{"type":"RELATIVE_VALUE","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"02000000"}]}]}]
    trial("19. RELATIVE_VALUE 1/2", fund, spender, conds)

def t20_anchor_pool():
    # ANCHOR_POOL evaluator (anchor.cpp:181) requires
    # SHA256(witness_PREIMAGE) == conditions_HASH256. The fund-time
    # PREIMAGE auto-derives the HASH256 commitment; the spender must
    # supply the matching preimage in the witness.
    pre = "cc" * 32
    fund = [{"output_index":0,"blocks":[{"type":"ANCHOR_POOL","fields":[
        {"type":"PREIMAGE","hex":pre},   # auto -> HASH256 at fund time
        {"type":"NUMERIC","hex":"05000000"}]}]}]   # participant_count=5
    spender = [{"type":"ANCHOR_POOL","preimage":pre}]
    conds = [{"blocks":[{"type":"ANCHOR_POOL","fields":[
        {"type":"PREIMAGE","hex":pre},
        {"type":"NUMERIC","hex":"05000000"}]}]}]
    trial("20. ANCHOR_POOL (vtxo marker)", fund, spender, conds)

def t21_recurse_same():
    # RECURSE_SAME is a re-encumbrance covenant. The spend output MUST
    # reproduce the same conditions. Our sweep_rungs is a SIG, not
    # RECURSE_SAME, so the spend is structurally rejected at consensus.
    # The trial is a deliberate negative — passes if the rejection
    # fires.
    fund = [{"output_index":0,"blocks":[{"type":"RECURSE_SAME","fields":[
        {"type":"NUMERIC","hex":"05000000"}]}]}]    # max_depth=5
    spender = [{"type":"RECURSE_SAME"}]
    conds = [{"blocks":[{"type":"RECURSE_SAME","fields":[
        {"type":"NUMERIC","hex":"05000000"}]}]}]
    trial("21. RECURSE_SAME negative (sweep to non-RECURSE)",
          fund, spender, conds, expect_fail=True)

def t22_data_return():
    # DATA_RETURN outputs are consensus-unspendable by design (the
    # evaluator returns ERROR for any spend attempt). Deliberate
    # negative — passes if the spend is rejected.
    payload = b"trial-22-data-return-payload"
    fund = [{"output_index":0,"blocks":[{"type":"DATA_RETURN","fields":[
        {"type":"DATA","hex":payload.hex()}]}]}]
    spender = [{"type":"DATA_RETURN"}]
    conds = [{"blocks":[{"type":"DATA_RETURN","fields":[
        {"type":"DATA","hex":payload.hex()}]}]}]
    trial("22. DATA_RETURN negative (unspendable by design)",
          fund, spender, conds, expect_fail=True)

def t23_ptlc():
    pk = derive("t23-ptlc"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"PTLC","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"PTLC","privkey":bytes_to_wif(pk.get_bytes(), True)}]
    conds = [{"blocks":[{"type":"PTLC","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("23. PTLC (point-locked, csv=2)", fund, spender, conds,
          spend_input_extra={"sequence": 2}, mine_after_fund=3)

def t24_anchor_seal():
    # ANCHOR_SEAL needs SHA256(preimage_i)==HASH256_i for both pairs.
    # Spender provides both preimages via _preimage / _preimage2 keys
    # (signrungtx multi-hash convention at rpc.cpp:3858-3866).
    pre1 = "a1" * 32
    pre2 = "a2" * 32
    fund = [{"output_index":0,"blocks":[{"type":"ANCHOR_SEAL","fields":[
        {"type":"PREIMAGE","hex":pre1},
        {"type":"PREIMAGE","hex":pre2}]}]}]
    spender = [{"type":"ANCHOR_SEAL","preimages":[pre1,pre2]}]
    conds = [{"blocks":[{"type":"ANCHOR_SEAL","fields":[
        {"type":"PREIMAGE","hex":pre1},
        {"type":"PREIMAGE","hex":pre2}]}]}]
    trial("24. ANCHOR_SEAL (paired commit)", fund, spender, conds)

def t25_compare():
    # COMPARE evaluator (plc.cpp:255) checks `ctx.input_amount` against
    # value_b using the named operator. The CONDITIONS layout requires
    # exactly 3 NUMERIC fields (op, value_b, value_c) per
    # `COMPARE_CONDITIONS = {3, ...}` (types.h:1186); value_c is only
    # consulted by op=IN_RANGE (0x07). Use op=GTE (0x05) with value_b=1
    # → input_amount >= 1 → always SATISFIED. value_c=0 (ignored).
    fund = [{"output_index":0,"blocks":[{"type":"COMPARE","fields":[
        {"type":"NUMERIC","hex":"05000000"},   # op = 5 (GTE)
        {"type":"NUMERIC","hex":"01000000"},   # value_b = 1 sat
        {"type":"NUMERIC","hex":"00000000"}]}]}]   # value_c = 0 (unused)
    spender = [{"type":"COMPARE"}]
    conds = [{"blocks":[{"type":"COMPARE","fields":[
        {"type":"NUMERIC","hex":"05000000"},
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"00000000"}]}]}]
    trial("25. COMPARE gte(input, 1 sat)", fund, spender, conds)

# Override the runner block from above to call the extras
import sys as _sys
_sys.argv = ["t"]
if __name__ == "__main__":
    print("\n=== Extended battery (trials 11-25) ===")
    for fn in (t11_hash_sig, t12_timelocked_sig, t13_cltv_sig, t14_multisig_2of3,
               t15_input_count, t16_output_count, t17_epoch_gate, t18_tagged_hash,
               t19_relative_value, t20_anchor_pool, t21_recurse_same, t22_data_return,
               t23_ptlc, t24_anchor_seal, t25_compare):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:120]))
    print()
    for name, status, detail in results[10:]:
        marker = "✓" if status == "OK" else ("✗" if status != "EXC" else "‼")
        print(f"  {marker} {name:<48} {status:<5} {detail}")
    print()
    new_ok = sum(1 for _, s, _ in results[10:] if s == "OK")
    print(f"new battery: {new_ok}/{len(results)-10} OK")
    total_ok = sum(1 for _, s, _ in results if s == "OK")
    print(f"cumulative: {total_ok}/{len(results)} OK across both batteries")
