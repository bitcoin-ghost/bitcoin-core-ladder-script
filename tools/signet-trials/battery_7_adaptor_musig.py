"""Battery 7: ADAPTOR_SIG, MUSIG_THRESHOLD.

Both are Schnorr-only signing variants. ADAPTOR_SIG can be tested with
a plain Schnorr sig (no adaptor secret) — the eval just verifies the
signature like SIG. MUSIG_THRESHOLD verifies a single aggregate
Schnorr sig — a single-key trial passes since the aggregate of one
key IS that key.
"""
import sys, re
sys.path.insert(0, "/tmp")
src3 = open("/tmp/v4_trials3.py").read()
src3 = re.sub(r'^if __name__ == "__main__":.*?(?=^(?:def |# |import |$))', "", src3,
              flags=re.MULTILINE | re.DOTALL)
exec(src3, globals())


def t61_adaptor_sig():
    # ADAPTOR_SIG_CONDITIONS = nullptr (no conditions fields). Pubkey is
    # folded into Merkle leaf via merkle_pub_key (pubkey_count=1). Witness:
    # PUBKEY + SIGNATURE. signrungtx supports plain Schnorr (no adaptor
    # secret) which produces a normal Schnorr sig — useful for testing.
    pk = derive("t61-adapt"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"ADAPTOR_SIG","fields":[
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"ADAPTOR_SIG","privkey":bytes_to_wif(pk.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"ADAPTOR_SIG","fields":[
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("61. ADAPTOR_SIG (plain Schnorr)", fund, spender, conds)


def t62_musig_threshold():
    # MUSIG_THRESHOLD_CONDITIONS = [NUMERIC(M), NUMERIC(N)]. Pubkey is
    # folded into Merkle leaf via merkle_pub_key (pubkey_count=1). A
    # single-key MuSig (M=1, N=1) is the aggregate of one key — equal
    # to that key — so signrungtx's SignSingleKey path produces a
    # verifying Schnorr sig.
    pk = derive("t62-musig"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"MUSIG_THRESHOLD","fields":[
        {"type":"NUMERIC","hex":"01000000"},  # M=1
        {"type":"NUMERIC","hex":"01000000"},  # N=1
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"MUSIG_THRESHOLD","privkey":bytes_to_wif(pk.get_bytes(),True)}]
    conds = [{"blocks":[{"type":"MUSIG_THRESHOLD","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("62. MUSIG_THRESHOLD (1-of-1)", fund, spender, conds)


if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    results.clear()
    for fn in (t61_adaptor_sig, t62_musig_threshold):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))
    print()
    for name, status, detail in results:
        marker = "OK " if status == "OK" else status[:3].upper()
        print(f"  [{marker}] {name:<48} {detail[:140]}")
    print(f"\nchain height (end): {rpc('getblockcount')['result']}")
