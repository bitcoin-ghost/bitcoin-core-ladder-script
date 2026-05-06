"""Battery 8: OUTPUT_CHECK."""
import sys, re
sys.path.insert(0, "/tmp")
src3 = open("/tmp/v4_trials3.py").read()
src3 = re.sub(r'^if __name__ == "__main__":.*?(?=^(?:def |# |import |$))', "", src3,
              flags=re.MULTILINE | re.DOTALL)
exec(src3, globals())


def t63_output_check():
    # OUTPUT_CHECK_CONDITIONS = [NUMERIC(output_index),
    # NUMERIC(min_sats), NUMERIC(max_sats), HASH256(script_hash)].
    # script_hash = 32 zero bytes → script check is skipped (per
    # governance.cpp:291). Bound output 0 value in a wide band that
    # any 0.999-BTC spend satisfies.
    fund = [{"output_index":0,"blocks":[{"type":"OUTPUT_CHECK","fields":[
        {"type":"NUMERIC","hex":"00000000"},   # output_index = 0
        {"type":"NUMERIC","hex":(1).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(2_000_000_000).to_bytes(4,'little').hex()},
        {"type":"HASH256","hex":"00"*32}]}]}]
    spender = [{"type":"OUTPUT_CHECK"}]
    conds = [{"blocks":[{"type":"OUTPUT_CHECK","fields":[
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"NUMERIC","hex":(1).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(2_000_000_000).to_bytes(4,'little').hex()},
        {"type":"HASH256","hex":"00"*32}]}]}]
    trial("63. OUTPUT_CHECK [out0, 1..2B sats]", fund, spender, conds)


if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    results.clear()
    try: t63_output_check()
    except Exception as e: results.append(("t63_output_check", "EXC", str(e)[:200]))
    print()
    for name, status, detail in results:
        marker = "OK " if status == "OK" else status[:3].upper()
        print(f"  [{marker}] {name:<48} {detail[:140]}")
    print(f"\nchain height (end): {rpc('getblockcount')['result']}")
