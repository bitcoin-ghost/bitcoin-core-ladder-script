"""Battery 5: easy state-machine + timelock-variant blocks.

Adds CSV_TIME, CLTV_TIME, HYSTERESIS_FEE/VALUE, TIMER_CONTINUOUS/OFF_DELAY,
LATCH_SET/RESET, COUNTER_DOWN/PRESET/UP, SEQUENCER, RATE_LIMIT — block
types that have only NUMERIC fields and don't need inner conditions,
relays, mutation targets, or cross-input wiring.
"""
import sys, re
sys.path.insert(0, "/tmp")
src3 = open("/tmp/v4_trials3.py").read()
src3 = re.sub(r'^if __name__ == "__main__":.*?(?=^(?:def |# |import |$))', "", src3,
              flags=re.MULTILINE | re.DOTALL)
exec(src3, globals())

# ─── Trials 44+ ────────────────────────────────────────────────────────

def t44_csv_time():
    # CSV_TIME uses BIP-68 time-bit (1<<22) in nSequence. The minimum
    # delta is 1 unit = 512 sec — the signet's MTP doesn't advance that
    # fast inside a back-to-back mining run (each block ~1 sec timestamp
    # apart by default), so the relative timelock can't elapse in real
    # time within a battery run. Use a 0-unit value (bit 22 set, value=0)
    # which satisfies trivially.
    fund = [{"output_index":0,"blocks":[{"type":"CSV_TIME","fields":[
        {"type":"NUMERIC","hex":(0x00400000).to_bytes(4,'little').hex()}]}]}]   # bit 22 + 0 units
    spender = [{"type":"CSV_TIME"}]
    conds = [{"blocks":[{"type":"CSV_TIME","fields":[
        {"type":"NUMERIC","hex":(0x00400000).to_bytes(4,'little').hex()}]}]}]
    trial("44. CSV_TIME (time-bit, 0 units)", fund, spender, conds,
          spend_input_extra={"sequence": 0x00400000})

def t45_cltv_time():
    # CLTV_TIME: NUMERIC(MTP_seconds), tx.nLockTime >= value. Use 0 so
    # any tx satisfies it.
    fund = [{"output_index":0,"blocks":[{"type":"CLTV_TIME","fields":[
        {"type":"NUMERIC","hex":"00000000"}]}]}]
    spender = [{"type":"CLTV_TIME"}]
    conds = [{"blocks":[{"type":"CLTV_TIME","fields":[
        {"type":"NUMERIC","hex":"00000000"}]}]}]
    trial("45. CLTV_TIME (mtp=0)", fund, spender, conds)

def _two_numeric(name, btype, a, b, sequence_extra=None):
    a_hex = a.to_bytes(4,'little').hex()
    b_hex = b.to_bytes(4,'little').hex()
    fund = [{"output_index":0,"blocks":[{"type":btype,"fields":[
        {"type":"NUMERIC","hex":a_hex},
        {"type":"NUMERIC","hex":b_hex}]}]}]
    spender = [{"type":btype}]
    conds = [{"blocks":[{"type":btype,"fields":[
        {"type":"NUMERIC","hex":a_hex},
        {"type":"NUMERIC","hex":b_hex}]}]}]
    extra = {"sequence": sequence_extra} if sequence_extra is not None else None
    trial(name, fund, spender, conds, spend_input_extra=extra)

def t46_hysteresis_fee():
    # HYSTERESIS_FEE conditions: NUMERIC(high_sat_vb), NUMERIC(low_sat_vb)
    # — wide band that any tx fee_rate hits.
    _two_numeric("46. HYSTERESIS_FEE [low=1, high=10000]", "HYSTERESIS_FEE", 10_000, 1)

def t47_hysteresis_value():
    _two_numeric("47. HYSTERESIS_VALUE [low=1, high=2B]", "HYSTERESIS_VALUE", 2_000_000_000, 1)

def t48_timer_continuous():
    # TIMER_CONTINUOUS: [accumulated, target]. Eval likely passes when
    # accumulated >= target. Use accumulated=10, target=1.
    _two_numeric("48. TIMER_CONTINUOUS (accum=10>=target=1)", "TIMER_CONTINUOUS", 10, 1)

def t49_timer_off_delay():
    # TIMER_OFF_DELAY eval: SATISFIED iff `remaining > 0` (still in
    # hold-off window). Use remaining=5.
    fund = [{"output_index":0,"blocks":[{"type":"TIMER_OFF_DELAY","fields":[
        {"type":"NUMERIC","hex":"05000000"}]}]}]
    spender = [{"type":"TIMER_OFF_DELAY"}]
    conds = [{"blocks":[{"type":"TIMER_OFF_DELAY","fields":[
        {"type":"NUMERIC","hex":"05000000"}]}]}]
    trial("49. TIMER_OFF_DELAY (remaining=5)", fund, spender, conds)

def t50_latch_set():
    # LATCH_SET conditions: NUMERIC(state). state=0 → SATISFIED (can set);
    # state=1 → UNSATISFIED (already set). Pubkey is committed via merkle_pub_key
    # — descriptor takes @pk but registry has pubkey_count=1 (key-consuming).
    pk = derive("t50-latch"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"LATCH_SET","fields":[
        {"type":"NUMERIC","hex":"00000000"},  # state=0
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"LATCH_SET","pubkey":pkh}]
    conds = [{"blocks":[{"type":"LATCH_SET","fields":[
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("50. LATCH_SET (state=0)", fund, spender, conds)

def t51_latch_reset():
    # LATCH_RESET eval (plc.cpp:184): SATISFIED iff `state >= 1 AND
    # delay == 0`. Pubkey committed via merkle_pub_key.
    pk = derive("t51-latch"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"LATCH_RESET","fields":[
        {"type":"NUMERIC","hex":"01000000"},  # state=1 (set)
        {"type":"NUMERIC","hex":"00000000"},  # delay=0 (matured)
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"LATCH_RESET","pubkey":pkh}]
    conds = [{"blocks":[{"type":"LATCH_RESET","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"00000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("51. LATCH_RESET (state=1, delay=0)", fund, spender, conds)

def t52_counter_down():
    pk = derive("t52-cdwn"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"COUNTER_DOWN","fields":[
        {"type":"NUMERIC","hex":"05000000"},  # count=5 (>0 → SATISFIED)
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"COUNTER_DOWN","pubkey":pkh}]
    conds = [{"blocks":[{"type":"COUNTER_DOWN","fields":[
        {"type":"NUMERIC","hex":"05000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("52. COUNTER_DOWN (count=5)", fund, spender, conds)

def t53_counter_preset():
    # COUNTER_PRESET registry: key_consuming=false, pubkey_count=0 — no
    # pubkey is consumed unlike COUNTER_DOWN/UP. Just (current, preset).
    fund = [{"output_index":0,"blocks":[{"type":"COUNTER_PRESET","fields":[
        {"type":"NUMERIC","hex":"01000000"},  # current=1
        {"type":"NUMERIC","hex":"05000000"}]}]}]   # preset=5 (current<preset)
    spender = [{"type":"COUNTER_PRESET"}]
    conds = [{"blocks":[{"type":"COUNTER_PRESET","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"05000000"}]}]}]
    trial("53. COUNTER_PRESET (1<5)", fund, spender, conds)

def t54_counter_up():
    pk = derive("t54-cup"); pkh = pk.get_pubkey().get_bytes().hex()
    fund = [{"output_index":0,"blocks":[{"type":"COUNTER_UP","fields":[
        {"type":"NUMERIC","hex":"01000000"},  # current=1
        {"type":"NUMERIC","hex":"05000000"},  # target=5
        {"type":"PUBKEY","hex":pkh}]}]}]
    spender = [{"type":"COUNTER_UP","pubkey":pkh}]
    conds = [{"blocks":[{"type":"COUNTER_UP","fields":[
        {"type":"NUMERIC","hex":"01000000"},
        {"type":"NUMERIC","hex":"05000000"},
        {"type":"PUBKEY","hex":pkh}]}]}]
    trial("54. COUNTER_UP (current=1, target=5)", fund, spender, conds)

def t55_sequencer():
    # SEQUENCER conditions: [current_step, total_steps]. Eval SATISFIED if
    # 0 <= current < total. Use (current=0, total=3).
    _two_numeric("55. SEQUENCER (step=0/3)", "SEQUENCER", 0, 3)

def t56_rate_limit():
    # RATE_LIMIT conditions: [max_per_block, accumulation_cap, refill_blocks].
    # Eval likely passes if output_amount <= max_per_block. Use very wide
    # max so any spend within a 1-BTC trial UTXO satisfies.
    fund = [{"output_index":0,"blocks":[{"type":"RATE_LIMIT","fields":[
        {"type":"NUMERIC","hex":(2_000_000_000).to_bytes(4,'little').hex()},  # max_per_block
        {"type":"NUMERIC","hex":(2_000_000_000).to_bytes(4,'little').hex()},  # accumulation_cap
        {"type":"NUMERIC","hex":(144).to_bytes(4,'little').hex()}]}]}]        # refill_blocks
    spender = [{"type":"RATE_LIMIT"}]
    conds = [{"blocks":[{"type":"RATE_LIMIT","fields":[
        {"type":"NUMERIC","hex":(2_000_000_000).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(2_000_000_000).to_bytes(4,'little').hex()},
        {"type":"NUMERIC","hex":(144).to_bytes(4,'little').hex()}]}]}]
    trial("56. RATE_LIMIT (max=20 BTC)", fund, spender, conds)


if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    results.clear()
    for fn in (t44_csv_time, t45_cltv_time, t46_hysteresis_fee, t47_hysteresis_value,
               t48_timer_continuous, t49_timer_off_delay, t50_latch_set,
               t51_latch_reset, t52_counter_down, t53_counter_preset,
               t54_counter_up, t55_sequencer, t56_rate_limit):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))
    print()
    for name, status, detail in results:
        marker = "OK " if status == "OK" else status[:3].upper()
        print(f"  [{marker}] {name:<48} {detail[:120]}")
    print(f"\nchain height (end): {rpc('getblockcount')['result']}")
