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

**65 trials passing end-to-end** (63 OK + 2 PASS_NEG for deliberate
negatives) covering **57 of 65 active block types directly + 3 via
playgrounds = 60/65**. Battery 9 added KEY_REF_SIG (relay structure)
and COSIGN (2-input cross-reference). The remaining 5 untested
(RECURSE_MODIFIED / RECURSE_DECAY / RECURSE_SPLIT,
P2SH/P2WSH/P2TR_SCRIPT_LEGACY) need RPC-surface extensions that
aren't in scope for the trial battery — see "Untested types" below.
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
| `battery_9_keyref_cosign_split.py` | T64..T66 | KEY_REF_SIG (relay), COSIGN (2-input), RECURSE_SPLIT (currently FAIL — needs coil/leaf engineering) |
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

## Untested types (need scaffolding extensions)

Closed in battery 9:
- **KEY_REF_SIG**: now passing (T64). `createrungtx` 7th positional
  arg accepts `relays`; `signrungtx` signer-spec accepts
  `relay_blocks` array. The relay's SIG block needs `privkey` for
  `BuildWitnessBlock`'s `SignSingleKey` path even though it's the
  pubkey-commitment side.
- **COSIGN**: now passing (T65). Two-input scenario: input 0 is a
  vanilla SIG UTXO, input 1's COSIGN block targets
  `SHA256(input 0's scriptPubKey)`. Each input's signer spec is
  passed as a separate entry in `signrungtx`'s signers array.

Still untested via this harness:
- **RECURSE_SPLIT** (T66): the spend's child outputs must
  re-encumber with the mutated rung's MLSC root (max_splits
  decremented by 1), but the child root computation needs to align
  with the eval's `BuildCPRung` + `ComputeTxMLSCLeaf` path
  (specifically the input's coil bytes must propagate to the
  child's leaf). T66 currently fails consensus
  (`mempool-script-verify-flag-failed`); needs a follow-up that
  computes the expected output root via `parseladder` /
  `serialiseconditions` rather than building the child rungs by
  hand.
- **RECURSE_MODIFIED / RECURSE_DECAY**: similar to RECURSE_SPLIT
  but with per-mutation `MutationSpec` parameters. The
  `signrungtx` `mutation_targets` infrastructure (rpc.cpp:2533+)
  exists but the trial harness doesn't yet drive it.
- **P2SH / P2WSH / P2TR_SCRIPT_LEGACY**: need a serialised inner
  LadderWitness with PUBKEY fields preserved (the existing
  `serialiseconditions` RPC folds PUBKEY into rung_pks under
  `conditions_only=true`, which is wrong for legacy-wrapper inner
  bodies — the inner SIG block needs the pubkey in its fields so
  the script body's HASH256 commits to it). A dedicated RPC or
  flag is needed.

All five remaining items are covered by C++ boost tests in
`src/test/rung_tests.cpp` already; the gap is just live-signet
end-to-end coverage via the trial battery.
