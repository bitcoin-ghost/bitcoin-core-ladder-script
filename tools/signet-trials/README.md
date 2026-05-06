# Signet trial battery

End-to-end fund + spend trials against the Ladder Script signet
(`85.9.213.194`, RPC port 38332). Each trial:

1. Splits a small ~1 BTC UTXO out of the wallet's coinbase pool.
2. Funds an MLSC output gated on the block type under test.
3. Mines 1+ blocks for confirmation.
4. Builds a spend tx, signs it via `signrungtx`, broadcasts via
   `sendrawtransaction`.
5. Records OK / FAIL / SKIP / PASS_NEG / EXC.

## Coverage as of 2026-05-06

**71 trials passing end-to-end** (69 OK + 2 PASS_NEG for deliberate
negatives) covering **all 62 active block types in this trial
battery + 3 via playgrounds = 65/65 active block types** confirmed
on the live Ladder Script signet.

Batteries 9-10 closed every previously-untested type:
- KEY_REF_SIG (relay structure with `relays` + `relay_blocks`)
- COSIGN (2-input cross-reference; input 1's COSIGN targets
  SHA256(input 0 SPK))
- RECURSE_SPLIT (single-rung spend with mutated max_splits;
  shared output SPK)
- RECURSE_MODIFIED / RECURSE_DECAY (2-block rung
  `[RECURSE_*, AMOUNT_LOCK]`; mutation targets AMOUNT_LOCK
  param 0)
- P2WSH_LEGACY / P2SH_LEGACY (inner script body via
  `serialiseconditions` auto-converting PUBKEY → HASH160
  inside P2PKH_LEGACY)
- P2TR_SCRIPT_LEGACY (registry pubkey_count=1 — the witness
  PUBKEY plays double duty as merkle_pub_key for OUTER leaf
  reconstruction AND as the inner P2PKH spender pubkey, so the
  trial uses the same pubkey for both)

QABI/PQ_BATCH (3 types) are covered by their dedicated playgrounds
(`tools/qabio-playground/`, `tools/pq-batch-playground/`).

## Files

| File | Trials | Block types |
|------|-------:|-------------|
| `battery_1_2.py` | T01..T25 | base sig/timelock/hash/covenant/anchor/governance |
| `battery_3.py` | T26..T36 | compound (HTLC, VAULT_LOCK, TIMELOCKED_MULTISIG, ANCHOR_FEE), legacy P2PK/P2PKH/P2WPKH/P2TR, RECURSE_SAME chain, multi-output |
| `battery_4_pq_anchors.py` | T37..T43 | SIG with PQ schemes (FALCON-512, FALCON-1024, Dilithium3, SPHINCS+), ANCHOR_RESERVE, ANCHOR_ORACLE, ONE_SHOT |
| `battery_5_plc.py` | T44..T56 | CSV_TIME, CLTV_TIME, HYSTERESIS_FEE/VALUE, TIMER_*, LATCH_*, COUNTER_*, SEQUENCER, RATE_LIMIT |
| `battery_6_ctv_accum_recurse.py` | T57..T60 | CTV (BIP-119), ACCUMULATOR, RECURSE_UNTIL, RECURSE_COUNT |
| `battery_7_adaptor_musig.py` | T61..T62 | ADAPTOR_SIG (plain Schnorr), MUSIG_THRESHOLD (1-of-1) |
| `battery_8_output_check.py` | T63 | OUTPUT_CHECK |
| `battery_9_keyref_cosign_split.py` | T64..T66 | KEY_REF_SIG (relay), COSIGN (2-input), RECURSE_SPLIT (single-rung spend with mutated max_splits) |
| `battery_10_recurses_legacy.py` | T67..T71 | RECURSE_MODIFIED, RECURSE_DECAY, P2WSH_LEGACY, P2SH_LEGACY, P2TR_SCRIPT_LEGACY |
| `run_full_battery.py` | T01..T36 | runner that re-executes batteries 1+2+3 in sequence |

## Running

Requires the SSH tunnel `ssh -fN -L 38332:127.0.0.1:38332 ladder-script`
and a wallet named `ladder` with mature trusted UTXOs. Each trial
costs ~1 BTC plus a few sats in fees (the rest comes back as wallet
change).

```bash
# Top up the wallet — mine 50 to a wallet address, then 100 empty
# blocks for coinbase maturity:
python3 tools/signet-trials/_topup.py   # not yet shipped — manual for now

# Run the full 36-trial battery:
python3 tools/signet-trials/run_full_battery.py

# Run individual extension batteries:
python3 tools/signet-trials/battery_4_pq_anchors.py
python3 tools/signet-trials/battery_5_plc.py
# ... etc
```

## Trial-config gotchas (recorded as comments in each file)

- `AMOUNT_LOCK` NUMERIC fields are 4-byte (uint32 max ~42.95 BTC), so
  bands and trial UTXOs must fit. T05 uses a 1-BTC small UTXO.
- `EPOCH_GATE` rejects `epoch_size <= 0` — use `epoch_size=1, window=1`
  for trivial-pass.
- `TAGGED_HASH` requires SHA256(tag||tag||preimage) == expected_hash —
  the trial pre-computes this exactly.
- `ANCHOR_POOL`, `ANCHOR_RESERVE`, `ANCHOR_SEAL` need PREIMAGE in the
  spend witness via `preimage` / `preimages` keys.
- `COMPARE` conditions layout requires 3 NUMERICs (op, value_b,
  value_c); value_c is a placeholder for ops other than IN_RANGE.
- `LATCH_RESET` SATISFIED iff `state >= 1 AND delay == 0`.
- `TIMER_OFF_DELAY` SATISFIED iff `remaining > 0`.
- `COUNTER_PRESET` is NOT key-consuming (registry pubkey_count=0)
  unlike COUNTER_DOWN/UP — don't pass a PUBKEY.
- `ANCHOR_FEE` fee_rate band and max_weight must fit a real spend
  shape (a 1-BTC trial spend is ~196 vB / 784 WU at 510 sat/vB).
- `ONE_SHOT` registry pubkey_count=0 — descriptor's @pk arg isn't
  consumed; trial must omit PUBKEY from conditions.
- `MUSIG_THRESHOLD_CONDITIONS` is `[NUMERIC(M), NUMERIC(N)]` — not
  SCHEME+PUBKEY.
- `ADAPTOR_SIG_CONDITIONS` is empty (nullptr); pubkey is folded via
  merkle_pub_key only.
- `CSV_TIME` BIP-68 minimum is 1 unit (512 sec) which doesn't elapse
  inside a back-to-back-mined battery — use bit-22-only (value=0)
  for trivial-pass.

## All 65 block types now covered end-to-end

The previously-untested types closed in batteries 9-10:

- **KEY_REF_SIG** (T64): `createrungtx` 7th positional arg accepts
  `relays`; `signrungtx` signer-spec accepts `relay_blocks` array.
  The relay's SIG block needs `privkey` for `BuildWitnessBlock`'s
  `SignSingleKey` path even though it's the pubkey-commitment side.
- **COSIGN** (T65): two-input scenario — input 0 is a vanilla SIG
  UTXO, input 1's COSIGN block targets
  `SHA256(input 0's scriptPubKey)`. Each input's signer spec is a
  separate entry in `signrungtx`'s signers array.
- **RECURSE_SPLIT** (T66): single-rung spend with mutated
  max_splits. All v4 outputs share the same `tx.conditions_root`,
  so a single rung at output_index=0 + N output values produces N
  outputs with identical SPK that all match the eval's
  `expected_root`.
- **RECURSE_MODIFIED / RECURSE_DECAY** (T67/T68): 2-block rung
  `[RECURSE_*, AMOUNT_LOCK]`. The mutation targets AMOUNT_LOCK
  param 0 (min_sats); spend re-encumbers with min_sats ± 1. The
  trial-config gotcha here: the spend output's value must lie
  inside the AMOUNT_LOCK band — a 1-BTC trial UTXO yields a
  ~0.998-BTC spend output, so the band [10M, 200M] sat is what
  fits. (Earlier attempts with band [100M, 200M] failed not for
  RECURSE_MODIFIED reasons but because AMOUNT_LOCK rejected the
  output value.)
- **P2WSH_LEGACY / P2SH_LEGACY** (T69/T70): outer commits to
  SHA256/RIPEMD160 of the inner script body. Inner = 1
  P2PKH_LEGACY block — `serialiseconditions` auto-converts the
  inner PUBKEY → HASH160 inside the parser (rpc.cpp:384-390), so
  the resulting bytes deserialise cleanly under
  SerializationContext::CONDITIONS at spend time.
- **P2TR_SCRIPT_LEGACY** (T71): registry pubkey_count=1 means
  the internal Taproot key is folded into the OUTER leaf via
  merkle_pub_key. At consensus, `ExtractBlockPubkeys`
  (`evaluator.cpp:572`) reads the witness PUBKEY field as the
  merkle_pub_key. But `EvalInnerConditions`
  (`blocks/legacy.cpp:88-95`) ALSO forwards that same PUBKEY to
  the inner block's witness fields, where the inner P2PKH eval
  uses it as the spender's pubkey. So the witness PUBKEY plays
  double duty — the trial uses the SAME pubkey for both the
  internal Taproot key and the inner P2PKH key, which is the
  pattern the wire format requires.

This pattern (single witness PUBKEY = both merkle_pub_key fold +
inner script's signer key) isn't documented anywhere obvious; it
fell out of debugging the leaf-root mismatch via
`computesighash` / a manual fund→spend root comparison (see
`/tmp/debug_p2tr_script.py`).
