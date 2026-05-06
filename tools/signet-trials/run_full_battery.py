"""Re-run the full battery (all 36 trials) to see which 8 still fail post T34 fix."""
import sys, re
sys.path.insert(0, "/tmp")

src3 = open("/tmp/v4_trials3.py").read()
# Strip BOTH `if __name__` blocks but keep the trial defs that sit between
# them, plus the t11-t25 defs that come after the first runner block.
src3 = re.sub(
    r'^if __name__ == "__main__":.*?(?=^(?:def |# ─|import|$))',
    "",
    src3,
    flags=re.MULTILINE | re.DOTALL,
)
exec(src3, globals())

src4 = open("/tmp/v4_trials4.py").read()
src4 = src4.replace('exec(open("/tmp/v4_trials3.py").read().split("if __name__")[0])', "")
src4 = src4.replace('results.clear()  # fresh batch', "")
src4 = re.split(r'^if __name__', src4, maxsplit=1, flags=re.MULTILINE)[0]
exec(src4, globals())

print(f"chain height (start): {rpc('getblockcount')['result']}")
bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
print(f"wallet trusted: {bal['trusted']} BTC")
print()

results.clear()

# Battery 1 (trials 1-10)
for fn in (t01_sig, t02_csv, t03_cltv_height0, t04_anchor, t05_amount_lock,
           t06_hash_guarded, t07_weight_limit, t08_anchor_channel,
           t09_compound_sig_csv, t10_or_two_sigs):
    try: fn()
    except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))

# Battery 2 (trials 11-25)
for fn in (t11_hash_sig, t12_timelocked_sig, t13_cltv_sig, t14_multisig_2of3,
           t15_input_count, t16_output_count, t17_epoch_gate, t18_tagged_hash,
           t19_relative_value, t20_anchor_pool, t21_recurse_same, t22_data_return,
           t23_ptlc, t24_anchor_seal, t25_compare):
    try: fn()
    except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))

# Battery 3 (trials 26-36)
for fn in (t26_htlc_claim, t27_htlc_refund, t28_vault_lock_hot,
           t29_timelocked_multisig, t30_p2pk_legacy, t31_p2pkh_legacy,
           t32_p2wpkh_legacy, t33_p2tr_legacy, t34_anchor_fee,
           t35_recurse_chain, t36_multi_output_fund):
    try: fn()
    except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))

print()
for name, status, detail in results:
    marker = "OK " if status == "OK" else ("EXC" if status == "EXC" else status[:3].upper())
    print(f"  [{marker}] {name:<48} {detail[:120]}")

ok_count = sum(1 for _, s, _ in results if s == "OK")
fail_count = sum(1 for _, s, _ in results if s != "OK")
print(f"\nsummary: {ok_count}/{len(results)} OK, {fail_count} fails")
print(f"chain height (end): {rpc('getblockcount')['result']}")
