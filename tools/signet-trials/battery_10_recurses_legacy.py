"""Battery 10: RECURSE_MODIFIED + RECURSE_DECAY + legacy wrappers.

The remaining 5 untested block types via the same patterns RECURSE_SPLIT
used: a single-rung spend whose conditions tree matches the eval's
mutated parent computation (manual construction — no need for the
mutation_targets RPC infrastructure).

Legacy wrappers use serialiseconditions to build the inner script
body (P2PKH_LEGACY auto-converts PUBKEY → HASH160 inside the inner
block at parse time), then the outer block commits to SHA256/RIPEMD160
of those bytes via a PREIMAGE field that createrungtx auto-converts
to the right hash type.
"""
import sys, re, hashlib
sys.path.insert(0, "/tmp")
src3 = open("/tmp/v4_trials3.py").read()
src3 = re.sub(r'^if __name__ == "__main__":.*?(?=^(?:def |# |import |$))', "", src3,
              flags=re.MULTILINE | re.DOTALL)
exec(src3, globals())


def _recurse_chain_with_mutation(name, btype, parent_amount_lo, parent_amount_hi,
                                  child_amount_lo, child_amount_hi,
                                  mutation_block_idx, mutation_param_idx, mutation_delta):
    """Build a 1-rung [RECURSE_*, AMOUNT_LOCK] covenant chain.

    Parent has AMOUNT_LOCK[lo_p, hi_p] and the recurse block carries
    the mutation. Spend re-encumbers with AMOUNT_LOCK[lo_c, hi_c]
    where lo_c = lo_p ± delta. Single-rung pattern: spend tx has 1
    output (no need to split for non-SPLIT recurses)."""
    parent_rungs = [{"output_index": 0, "blocks": [
        {"type": btype, "fields": [
            {"type": "NUMERIC", "hex": (10).to_bytes(4, 'little').hex()},  # depth
            {"type": "NUMERIC", "hex": mutation_block_idx.to_bytes(4, 'little').hex()},
            {"type": "NUMERIC", "hex": mutation_param_idx.to_bytes(4, 'little').hex()},
            {"type": "NUMERIC", "hex": mutation_delta.to_bytes(4, 'little', signed=True).hex()}]},
        {"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": parent_amount_lo.to_bytes(4, 'little').hex()},
            {"type": "NUMERIC", "hex": parent_amount_hi.to_bytes(4, 'little').hex()}]}]}]
    child_rungs = [{"output_index": 0, "blocks": [
        {"type": btype, "fields": [
            {"type": "NUMERIC", "hex": (10).to_bytes(4, 'little').hex()},
            {"type": "NUMERIC", "hex": mutation_block_idx.to_bytes(4, 'little').hex()},
            {"type": "NUMERIC", "hex": mutation_param_idx.to_bytes(4, 'little').hex()},
            {"type": "NUMERIC", "hex": mutation_delta.to_bytes(4, 'little', signed=True).hex()}]},
        {"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": child_amount_lo.to_bytes(4, 'little').hex()},
            {"type": "NUMERIC", "hex": child_amount_hi.to_bytes(4, 'little').hex()}]}]}]

    u, uerr = get_or_make_small_utxo(name)
    if not u: results.append((name, "SKIP", uerr or "no UTXO")); return
    fund_amt = round(u["amount"] - 0.001, 8)
    fr, err = ok(rpc("createrungtx",
        [[{"txid": u["txid"], "vout": u["vout"]}], [fund_amt], parent_rungs]), "fund")
    if not fr: results.append((name, "FAIL", err)); return
    fs, err = ok(rpc("signrawtransactionwithwallet", [fr["hex"]], WALLET), "fund-sign")
    if not fs or not fs.get("complete"):
        results.append((name, "FAIL", f"fund-sign {err}")); return
    fund_txid, err = ok(rpc("sendrawtransaction", [fs["hex"]]), "send-fund")
    if not fund_txid: results.append((name, "FAIL", err)); return
    mine(1)
    spend_amt = round(fund_amt - 0.001, 8)
    su, err = ok(rpc("createrungtx",
        [[{"txid": fund_txid, "vout": 0}], [spend_amt], child_rungs]),
        "spend-build")
    if not su: results.append((name, "FAIL", err)); return
    spent_outs = [{"amount": fund_amt, "scriptPubKey": fr["scriptPubKey"]}]
    signer = {"input": 0,
              "blocks": [{"type": btype}, {"type": "AMOUNT_LOCK"}],
              "conditions": parent_rungs}
    ss, err = ok(rpc("signrungtx", [su["hex"], [signer], spent_outs]), "signrungtx")
    if not ss or not ss.get("complete"):
        results.append((name, "FAIL", f"sign-spend: {err}")); return
    spend_txid, err = ok(rpc("sendrawtransaction", [ss["hex"]]), "send-spend")
    if not spend_txid: results.append((name, "FAIL", err)); return
    mine(1)
    results.append((name, "OK", f"fund={fund_txid[:10]} spend={spend_txid[:10]}"))


def t67_recurse_modified():
    # AMOUNT_LOCK eval (covenant.cpp:215) checks
    # `min_sats <= ctx.output_amount <= max_sats`. The harness's
    # 1-BTC small UTXO yields a spend output of ~0.998 BTC =
    # 99_800_000 sat, so the band must span that. Use
    # [10_000_000, 200_000_000] = [0.1 BTC, 2 BTC].
    # RECURSE_MODIFIED mutates AMOUNT_LOCK block (idx 1) param 0
    # (min_sats) by +1 each hop.
    _recurse_chain_with_mutation(
        "67. RECURSE_MODIFIED (AMOUNT_LOCK min += 1)", "RECURSE_MODIFIED",
        parent_amount_lo=10_000_000, parent_amount_hi=200_000_000,
        child_amount_lo=10_000_001, child_amount_hi=200_000_000,
        mutation_block_idx=1, mutation_param_idx=0, mutation_delta=1)


def t68_recurse_decay():
    # RECURSE_DECAY: eval negates delta, so encoded delta=+1 produces
    # mutation -1. Same AMOUNT_LOCK band as T67 to fit the trial UTXO.
    _recurse_chain_with_mutation(
        "68. RECURSE_DECAY (AMOUNT_LOCK min -= 1)", "RECURSE_DECAY",
        parent_amount_lo=10_000_000, parent_amount_hi=200_000_000,
        child_amount_lo=9_999_999, child_amount_hi=200_000_000,
        mutation_block_idx=1, mutation_param_idx=0, mutation_delta=1)


def _legacy_wrapper(name, outer_type, needs_internal_pubkey=False):
    """P2WSH_LEGACY / P2SH_LEGACY / P2TR_SCRIPT_LEGACY share the
    same trial shape — outer commits to a hash of the inner script
    body, spend reveals the inner body + the pubkey/sig that
    satisfy it.

    Inner conditions = 1 rung with 1 P2PKH_LEGACY block (which
    auto-converts PUBKEY → HASH160 at conditions-parse time).
    `serialiseconditions` produces the inner bytes; the outer's
    PREIMAGE field auto-converts to the right outer-hash type
    (HASH160 for P2SH_LEGACY, HASH256 for P2WSH/P2TR_SCRIPT).

    `needs_internal_pubkey=True` for P2TR_SCRIPT_LEGACY: the
    registry has pubkey_count=1 — the internal Taproot key is
    folded into the Merkle leaf via merkle_pub_key. Pass an extra
    PUBKEY to fund/spend so the leaf reconstruction matches at
    consensus time."""
    pk = derive(f"t-legacy-{outer_type}")
    pkh = pk.get_pubkey().get_bytes().hex()
    wif = bytes_to_wif(pk.get_bytes(), True)

    inner_spec = [{"blocks": [{"type": "P2PKH_LEGACY", "fields": [
        {"type": "PUBKEY", "hex": pkh}]}]}]
    sr = rpc("serialiseconditions", [inner_spec])
    if sr.get("error"):
        results.append((name, "FAIL", f"serialiseconditions: {sr['error']}"))
        return
    inner_hex = sr["result"]["hex"]

    outer_fields = [{"type": "PREIMAGE", "hex": inner_hex}]
    if needs_internal_pubkey:
        # P2TR_SCRIPT_LEGACY (registry pubkey_count=1): the witness
        # PUBKEY field plays double duty — at consensus
        # `ExtractBlockPubkeys` (evaluator.cpp:572) reads it as the
        # merkle_pub_key for OUTER-leaf reconstruction, while
        # `EvalInnerConditions` also forwards it to the inner
        # P2PKH_LEGACY block as the spender's pubkey. The two keys
        # must therefore be the SAME pubkey at fund and spend time.
        outer_fields.append({"type": "PUBKEY", "hex": pkh})

    fund_rungs = [{"output_index": 0, "blocks": [{"type": outer_type,
                                                  "fields": outer_fields}]}]
    spender = [{"type": outer_type, "preimage": inner_hex, "privkey": wif}]
    conds = [{"blocks": [{"type": outer_type, "fields": outer_fields}]}]
    trial(name, fund_rungs, spender, conds)


def t69_p2wsh_legacy():
    _legacy_wrapper("69. P2WSH_LEGACY (inner P2PKH_LEGACY)", "P2WSH_LEGACY")


def t70_p2sh_legacy():
    _legacy_wrapper("70. P2SH_LEGACY (inner P2PKH_LEGACY)", "P2SH_LEGACY")


def t71_p2tr_script_legacy():
    _legacy_wrapper("71. P2TR_SCRIPT_LEGACY (inner P2PKH_LEGACY)",
                    "P2TR_SCRIPT_LEGACY", needs_internal_pubkey=True)


if __name__ == "__main__":
    print(f"chain height (start): {rpc('getblockcount')['result']}")
    bal = rpc("getbalances", wallet=WALLET)["result"]["mine"]
    print(f"wallet trusted: {bal['trusted']} BTC")
    print()
    results.clear()
    for fn in (t67_recurse_modified, t68_recurse_decay,
               t69_p2wsh_legacy, t70_p2sh_legacy, t71_p2tr_script_legacy):
        try: fn()
        except Exception as e: results.append((fn.__name__, "EXC", str(e)[:200]))
    print()
    for name, status, detail in results:
        marker = "OK " if status == "OK" else status[:3].upper()
        print(f"  [{marker}] {name:<48} {detail[:140]}")
    print(f"\nchain height (end): {rpc('getblockcount')['result']}")
