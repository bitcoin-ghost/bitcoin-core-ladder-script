# Remote v4 RUNG_TX mutation fuzzer

Black-box mutation fuzzer for v4 transactions over JSON-RPC. Targets a
running `bitcoind` and submits ~5–7 mutation strategies plus
audit-driven fixed cases to either `sendrawtransaction` or
`decoderawtransaction`. The node MUST cleanly reject every mutation;
acceptance, timeout, internal-error leak, or empty-error-message all
flag as anomalies.

## Why

The Stage 3 audit found 7 consensus / policy bugs by reading code.
Anything the audit missed lives in interaction effects between modules
or in mutation patterns the human eye doesn't generate. This fuzzer
is the third leg of the same stool: code review → vector regression
→ adversarial mutation against a live node carrying real chainstate.

`feature_rung_fuzz.py` already exercises the parser RPCs
(`qabi_blockinfo`, `decoderung`, `parseladder`) on a fresh regtest
node. This tool complements it by exercising the **full submission
path** (mempool acceptance, script verify, conditions-root recovery,
parallel CCheckQueue, synthetic-entry interaction) against an
**accumulated chainstate** — exactly the surface that local in-process
tests can't reach.

## Modes

- **`sendrawtransaction`** (default): submits each mutated tx through
  the mempool acceptance path. Most random mutations reject early at
  `tx decode failed`, but a meaningful minority reach the v4
  deserialiser, MLSC proof verifier, and tx-level checks.

- **`--decode-only`**: targets `decoderawtransaction`. Exercises the
  v4 deserialiser + `TxToUniv` (where audit fix F11 lived). Doesn't
  need matching chainstate, so successful decodes happen frequently
  and exercise the JSON-output schema path.

- **`--audit-pass`**: also runs hand-crafted cases that target the
  Stage 3 audit fixes (F14 banned hash_type bytes, F17 oversize
  padding past `MAX_STANDARD_TX_WEIGHT`).

## Targets

### Local regtest (smoke)

```sh
build/bin/bitcoind -regtest -daemon -rpcuser=fuzz -rpcpassword=fuzz \
    -datadir=/tmp/fuzz-rt -port=29445 -rpcport=29446 -listen=0
sleep 2
BITCOIN_RPC_URL='http://fuzz:fuzz@127.0.0.1:29446' \
    python3 tools/remote-fuzz/fuzz_v4_remote.py --iterations 500 --audit-pass
```

### Ladder-script signet (the real target)

The signet node binds RPC to localhost, so use an SSH tunnel:

```sh
ssh -N -f -L 38332:127.0.0.1:38332 ladder-script
BITCOIN_RPC_URL='http://ladderrpc:ladder_signet_rpc_2026@127.0.0.1:38332' \
    python3 tools/remote-fuzz/fuzz_v4_remote.py --iterations 5000 \
        --audit-pass --signet
```

Throughput against the signet over the SSH tunnel is ~12 it/s
(network-bound, not CPU-bound). 5000 iterations ≈ 7 minutes.

## Output

The report aggregates rejection categories so you can spot drift:

```
top rejection categories:
   1411  code=-22, head='tx decode failed'
    271  code=-25, head='bad-txns-inputs-missingorspent'
      6  code=-26, head='non-final'
      4  code=-26, head='bad-txns-vout-toolarge'
```

If `STATUS: ANOMALIES` appears, the per-anomaly log has the strategy
name, reason category, and first 32 bytes of the offending tx for
reproduction. Reproducing one anomaly:

```sh
python3 tools/remote-fuzz/fuzz_v4_remote.py \
    --iterations 5000 --rng-seed <SEED_FROM_FAILED_RUN>
```

The PRNG is fully seeded; runs with the same `--rng-seed`,
`--seed-tx-hex`, and iteration count produce byte-identical mutations.

## What clean rejection looks like

Across the live signet at v0.22 (height 112), one full pass:

- 1000 sendrawtransaction iterations → 100 % cleanly rejected, 0
  anomalies, 0 acceptances
- 2000 decoderawtransaction iterations → 100 % cleanly handled (a
  mix of valid decodes and structural rejections, no F11-style
  schema mismatches, no internal-error leaks)
- All audit-driven fixed cases (F14, F17) reject as expected

This is what the BIP draft cites as "fuzzed against the live signet";
re-running this tool periodically against the same signet is the way
to keep that claim honest.

## Limitations

- Single-threaded, sequential RPC. Throughput is bound by RPC roundtrip
  latency, not by node CPU. Parallel submission would push it harder
  but also drown out anomaly signal.
- Mutations are bytewise; they don't generate semantically-valid v4
  txs that exercise the *successful* spend path. For success-path
  coverage, use the committed positive vectors via
  `feature_rung_tx_spend_vectors.py`.
- Doesn't currently send malformed P2P `tx` messages — the same
  surface as `sendrawtransaction` reaches them, so no new code paths
  exercised, but a P2P-level harness would catch peer-management
  bugs that an RPC harness can't.
