"""Battery 4: previously untested block types.

Coverage gap from block_type_testing.md after batteries 1-3:
- PQ schemes (FALCON-512, FALCON-1024, Dilithium3, SPHINCS+) for SIG
- ANCHOR_RESERVE, ANCHOR_ORACLE
- ONE_SHOT
- COSIGN (cross-input dependency — 2 funded inputs)
- KEY_REF_SIG (relay-based pubkey reference)
- P2SH_LEGACY, P2WSH_LEGACY, P2TR_SCRIPT_LEGACY (inner script bodies)
- RECURSE_MODIFIED, RECURSE_DECAY, RECURSE_COUNT, RECURSE_SPLIT (mutations)
"""
import sys, re, hashlib
sys.path.insert(0, "/tmp")

# Reuse the harness from v4_trials3 + v4_trials4 (they define rpc/derive/
# mine/get_or_make_small_utxo/trial/results etc).
src3 = open("/tmp/v4_trials3.py").read()
src3 = re.sub(r'^if __name__ == "__main__":.*?(?=^(?:def |# |import |$))', "", src3,
              flags=re.MULTILINE | re.DOTALL)
exec(src3, globals())
src4 = open("/tmp/v4_trials4.py").read()
src4 = src4.replace('exec(open("/tmp/v4_trials3.py").read().split("if __name__")[0])', "")
src4 = src4.replace('results.clear()  # fresh batch', "")
src4 = re.split(r'^if __name__', src4, maxsplit=1, flags=re.MULTILINE)[0]
exec(src4, globals())

# ─── Trials 37+ ────────────────────────────────────────────────────────

def _sig_pq(name, scheme_name, scheme_byte_hex):
    """Generic SIG-with-PQ-scheme trial.
    Calls generatepqkeypair to get a pubkey/privkey pair, then signs the
    fund/spend using the PQ scheme via signrungtx's pq_privkey path."""
    kp_r = rpc("generatepqkeypair", [scheme_name])
    if kp_r.get("error"):
        results.append((name, "SKIP", f"generatepqkeypair: {kp_r['error']}"))
        return
    kp = kp_r["result"]
    pq_pubkey = kp["pubkey"]
    pq_privkey = kp["privkey"]
    fund = [{"output_index":0,"blocks":[{"type":"SIG","fields":[
        {"type":"SCHEME","hex":scheme_byte_hex},
        {"type":"PUBKEY","hex":pq_pubkey}]}]}]
    spender = [{"type":"SIG",
                "scheme": scheme_name,
                "pq_privkey": pq_privkey,
                "pq_pubkey": pq_pubkey}]
    conds = [{"blocks":[{"type":"SIG","fields":[
        {"type":"SCHEME","hex":scheme_byte_hex},
        {"type":"PUBKEY","hex":pq_pubkey}]}]}]
    trial(name, fund, spender, conds)

def t37_sig_falcon512():    _sig_pq("37. SIG (FALCON512)", "FALCON512", "10")
def t38_sig_falcon1024():   _sig_pq("38. SIG (FALCON1024)", "FALCON1024", "11")
def t39_sig_dilithium3():   _sig_pq("39. SIG (DILITHIUM3)", "DILITHIUM3", "12")
def t40_sig_sphincs_sha():  _sig_pq("40. SIG (SPHINCS_SHA)", "SPHINCS_SHA", "13")

def t41_anchor_reserve():
    # ANCHOR_RESERVE conditions: NUMERIC(threshold_n) + NUMERIC(threshold_m)
    # + HASH256(guardian_set_hash). Witness: PREIMAGE binding the HASH256.
    pre = "33" * 32
    fund = [{"output_index":0,"blocks":[{"type":"ANCHOR_RESERVE","fields":[
        {"type":"NUMERIC","hex":"02000000"},   # threshold_n=2
        {"type":"NUMERIC","hex":"03000000"},   # threshold_m=3
        {"type":"PREIMAGE","hex":pre}]}]}]      # auto -> HASH256
    spender = [{"type":"ANCHOR_RESERVE","preimage":pre}]
    conds = [{"blocks":[{"type":"ANCHOR_RESERVE","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"NUMERIC","hex":"03000000"},
        {"type":"PREIMAGE","hex":pre}]}]}]
    trial("41. ANCHOR_RESERVE 2-of-3", fund, spender, conds)

def t42_anchor_oracle():
    # ANCHOR_ORACLE conditions: NUMERIC(outcome_count); witness reveals the
    # oracle PUBKEY (folded into Merkle leaf at fund time via merkle_pub_key).
    oracle = derive("t42-oracle")
    oracle_h = oracle.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"ANCHOR_ORACLE","fields":[
        {"type":"NUMERIC","hex":"02000000"},   # outcome_count=2
        {"type":"PUBKEY","hex":oracle_h}]}]}]
    spender = [{"type":"ANCHOR_ORACLE","pubkey":oracle_h}]
    conds = [{"blocks":[{"type":"ANCHOR_ORACLE","fields":[
        {"type":"NUMERIC","hex":"02000000"},
        {"type":"PUBKEY","hex":oracle_h}]}]}]
    trial("42. ANCHOR_ORACLE outcomes=2", fund, spender, conds)

def t43_one_shot():
    # ONE_SHOT_CONDITIONS = {NUMERIC(state), HASH256(commitment)} — only 2
    # fields, no pubkey consumed. The descriptor `one_shot(@pk, N, hex)`
    # pushes a pubkey into rung_pks but the registry sets pubkey_count=0
    # so the evaluator doesn't read it back; the trial builds conditions
    # directly via JSON so we just omit PUBKEY entirely. Witness only
    # needs the PREIMAGE that hashes to the conditions HASH256.
    commit_pre = "77" * 32
    fund = [{"output_index":0,"blocks":[{"type":"ONE_SHOT","fields":[
        {"type":"NUMERIC","hex":"00000000"},   # state=0 (unfired → SATISFIED)
        {"type":"PREIMAGE","hex":commit_pre}]}]}]   # auto -> HASH256
    spender = [{"type":"ONE_SHOT","preimage":commit_pre}]
    conds = [{"blocks":[{"type":"ONE_SHOT","fields":[
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"PREIMAGE","hex":commit_pre}]}]}]
    trial("43. ONE_SHOT state=0 (unfired)", fund, spender, conds)

if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    results.clear()
    for fn in (t37_sig_falcon512, t38_sig_falcon1024, t39_sig_dilithium3,
               t40_sig_sphincs_sha, t41_anchor_reserve, t42_anchor_oracle,
               t43_one_shot):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))
    print()
    for name, status, detail in results:
        marker = "OK " if status == "OK" else status[:3].upper()
        print(f"  [{marker}] {name:<48} {detail[:120]}")
    print(f"\nchain height (end): {rpc('getblockcount')['result']}")
