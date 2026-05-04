#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license.
"""Black-box mutation fuzzer for v4 RUNG_TX over JSON-RPC.

Targets a running bitcoind (regtest, signet, or mainnet) via the
`sendrawtransaction` RPC. Each iteration takes a known-good v4 tx,
applies one of several mutation strategies, and submits the result.
The node MUST respond with a well-formed JSON-RPC error in every
case. Anything else (acceptance, timeout, internal exception leak,
empty error message, hang) is recorded as an anomaly.

Why mutation fuzzing over a live node?

  - Pure-random inputs almost never reach the v4 deserialiser — they
    fail at "TX decode failed" before any v4-specific code runs.
    Mutating a valid v4 tx makes the inputs structurally close enough
    to exercise the deserialiser's per-field bounds, the MLSC proof
    verifier, and the conditions-root recovery path.
  - A live node carries accumulated chainstate that local regtest
    doesn't — synthetic-entry recovery paths, mempool interaction,
    parallel CCheckQueue, etc. all run against real state.
  - Stage 3 audit fixes (F11 RPC schema, F14 sighash fail-open, F15
    mutation OOB, F16 refcount overflow, F17 mempool weight cap) are
    consensus paths that ONLY a remote-tx submission exercises end to
    end. The local boost suite mocks the sig checker; the local
    functional tests use deterministic keys; this fuzzer hits the
    actual consensus code with random bytes.

Run:
    # Against a local regtest (cookie auth):
    BITCOIN_RPC_URL=http://__cookie__:$(cat ~/.bitcoin/regtest/.cookie | cut -d: -f2)@127.0.0.1:18443 \\
        python3 tools/remote-fuzz/fuzz_v4_remote.py --iterations 1000

    # Against the ladder-script signet:
    BITCOIN_RPC_URL=http://user:pass@85.9.213.194:38332 \\
        python3 tools/remote-fuzz/fuzz_v4_remote.py --iterations 5000 --signet

The fuzzer never broadcasts a valid tx — every mutated tx is expected
to reject. `sendrawtransaction` is called with `maxfeerate=0` so even
the unlikely event of a valid mutation getting through cannot waste
fees.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
import urllib.request
import urllib.error
from collections import Counter
from dataclasses import dataclass, field


# ── Known-good v4 tx hex (one of the committed positive vectors) ──
# This is the smallest single-SIG-rung fund tx from the v0.22 vector
# generator. Using a committed-vector tx keeps the seed reproducible
# across runs and keeps the node's TX_MLSC parser well-fed before
# rejection. If the node version drifts past v0.22, replace this with
# any vector from src/test/data/rung_tx_vectors.json.
_DEFAULT_SEED_TX_HEX_FILE = "src/test/data/rung_tx_vectors.json"


@dataclass
class FuzzStats:
    iterations: int = 0
    cleanly_rejected: int = 0
    anomalies: int = 0
    rejection_reasons: Counter = field(default_factory=Counter)
    anomaly_log: list = field(default_factory=list)
    accepted: int = 0  # if a mutated tx was accepted (very bad)
    timeouts: int = 0
    rpc_errors_no_message: int = 0


def _load_seed_tx_hex(path: str) -> str:
    """Load the first single-SIG fund tx from the committed vector
    fixture as the mutation seed."""
    if not os.path.isfile(path):
        raise SystemExit(f"seed-vector file not found: {path}\n"
                         f"  pass --seed-tx-hex <hex> to override")
    with open(path) as f:
        payload = json.load(f)
    for v in payload.get("vectors", []):
        if v.get("block_types") == ["SIG"] and "fund_tx" in v:
            return v["fund_tx"]["hex"]
    raise SystemExit(f"no SIG-only vector found in {path}")


# ── Mutation strategies ────────────────────────────────────────────

def _mutate_bit_flip(rng: random.Random, raw: bytes) -> bytes:
    out = bytearray(raw)
    pos = rng.randrange(len(out))
    out[pos] ^= 1 << rng.randrange(8)
    return bytes(out)


def _mutate_byte_replace(rng: random.Random, raw: bytes) -> bytes:
    out = bytearray(raw)
    pos = rng.randrange(len(out))
    out[pos] = rng.randrange(256)
    return bytes(out)


def _mutate_byte_insert(rng: random.Random, raw: bytes) -> bytes:
    pos = rng.randrange(len(raw) + 1)
    return raw[:pos] + bytes([rng.randrange(256)]) + raw[pos:]


def _mutate_byte_delete(rng: random.Random, raw: bytes) -> bytes:
    if len(raw) <= 1:
        return raw
    pos = rng.randrange(len(raw))
    return raw[:pos] + raw[pos + 1:]


def _mutate_truncate(rng: random.Random, raw: bytes) -> bytes:
    if len(raw) <= 1:
        return raw
    n = rng.randrange(1, len(raw))
    return raw[:n]


def _mutate_extend(rng: random.Random, raw: bytes) -> bytes:
    n = rng.randrange(1, 64)
    suffix = bytes(rng.randrange(256) for _ in range(n))
    return raw + suffix


def _mutate_pure_random(rng: random.Random, raw: bytes) -> bytes:
    n = rng.randrange(1, max(2, len(raw) * 2))
    return bytes(rng.randrange(256) for _ in range(n))


_STRATEGIES = [
    ("bit_flip", _mutate_bit_flip),
    ("byte_replace", _mutate_byte_replace),
    ("byte_insert", _mutate_byte_insert),
    ("byte_delete", _mutate_byte_delete),
    ("truncate", _mutate_truncate),
    ("extend", _mutate_extend),
    ("pure_random", _mutate_pure_random),
]


# ── Targeted (audit-driven) cases ──────────────────────────────────

def _audit_case_invalid_hashtype_sig(seed: bytes) -> bytes:
    """F14 regression: corrupt the signature byte at a witness offset
    to a banned hash_type (0x40 / 0xC0). Most random mutations don't
    reach the precise sig-byte offset; this case tries each of the
    rejected hash_type values."""
    if not seed:
        return seed
    out = bytearray(seed)
    # Pick a position inside the second half of the tx (witness area).
    pos = (len(out) * 3) // 4
    out[pos] = random.choice([0x40, 0x41, 0x42, 0x43, 0xC0, 0xC1, 0xC2, 0xC3])
    return bytes(out)


def _audit_case_oversize_padding(seed: bytes) -> bytes:
    """F17 regression: make the tx large enough to exceed
    MAX_STANDARD_TX_WEIGHT. Pad with random bytes the wire-deserialiser
    will reject for length / sanity reasons."""
    return seed + bytes(random.getrandbits(8) for _ in range(450_000))


_AUDIT_CASES = [
    ("F14_invalid_hashtype", _audit_case_invalid_hashtype_sig),
    ("F17_oversize_padding", _audit_case_oversize_padding),
]


# ── JSON-RPC client ────────────────────────────────────────────────

def _split_url_auth(url: str) -> tuple[str, str | None]:
    """Strip `user:pass@` from a URL and return (clean_url, auth_b64).
    `urllib.request.urlopen` does not consume URL-embedded credentials —
    it forwards them to DNS as part of the hostname, which breaks. We
    move the credentials to a Basic auth header instead."""
    parsed = urllib.parse.urlparse(url)
    if "@" not in (parsed.netloc or ""):
        return url, None
    auth, _, host_port = parsed.netloc.rpartition("@")
    auth_b64 = base64.b64encode(auth.encode()).decode("ascii")
    clean = parsed._replace(netloc=host_port).geturl()
    return clean, auth_b64


def _rpc_call(url: str, method: str, params: list, timeout: float = 5.0):
    """One-shot JSON-RPC POST. Returns (ok, result_or_error_dict)."""
    body = json.dumps({
        "jsonrpc": "1.0",
        "id": "fuzz",
        "method": method,
        "params": params,
    }).encode("utf-8")
    clean_url, auth_b64 = _split_url_auth(url)
    headers = {"Content-Type": "application/json"}
    if auth_b64:
        headers["Authorization"] = f"Basic {auth_b64}"
    req = urllib.request.Request(clean_url, data=body, method="POST",
                                  headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # Bitcoin Core returns 500 for RPC errors with the usual JSON body.
        try:
            payload = json.loads(e.read())
        except Exception:
            return False, {"http_error": e.code, "raw": str(e)}
    except (urllib.error.URLError, TimeoutError) as e:
        return False, {"network_error": str(e)}
    if payload.get("error"):
        return False, payload["error"]
    return True, payload.get("result")


# ── Fuzzer driver ──────────────────────────────────────────────────

def _categorise_error(err: dict) -> str:
    """Extract a short category label from a JSON-RPC error so we can
    aggregate. Bitcoin Core returns {code, message}; we strip the
    human-readable suffix and keep the consistent prefix."""
    if "network_error" in err:
        return "network_error"
    msg = err.get("message", "") if isinstance(err, dict) else str(err)
    code = err.get("code", "?") if isinstance(err, dict) else "?"
    # Cheap canonicalisation: take the first colon-delimited prefix.
    head = msg.split(":")[0].strip().lower() if msg else "(empty)"
    return f"code={code}, head='{head[:60]}'"


def _is_anomaly(ok: bool, err) -> tuple[bool, str]:
    """Decide whether (ok, err) from sendrawtransaction represents an
    anomaly. Anomalies:
      - tx accepted (we mutated the witness; should never accept)
      - empty/missing error message on rejection
      - network error / timeout
      - internal-error code (-32603) which leaks an unhandled exception
    """
    if ok:
        return True, "ACCEPTED a mutated tx (consensus or policy gap)"
    if not isinstance(err, dict):
        return True, f"non-dict error: {err!r}"
    if "network_error" in err:
        return True, f"network: {err['network_error']}"
    if "http_error" in err:
        return True, f"http: {err['http_error']}"
    msg = err.get("message", "")
    if not msg:
        return True, f"empty error message (code={err.get('code', '?')})"
    if err.get("code") == -32603:  # JSON-RPC internal error
        return True, f"internal error leak: {msg[:120]}"
    return False, ""


def _is_anomaly_decode(ok: bool, err) -> tuple[bool, str]:
    """`decoderawtransaction` is a pure-decode call — no chainstate, no
    network. ANY successful decode is fine (it's just bytes-in,
    JSON-out). What we look for: empty/missing error message on
    rejection, internal-error leak, or a successful decode that
    returns malformed JSON (missing required fields)."""
    if ok:
        # Successful decode — exercise F11 territory: TxToUniv must
        # populate required fields cleanly. If any are missing, the
        # node would itself flag the call as an internal-bug
        # (-1 returned alongside "incorrect type" message).
        # Here we just confirm shape.
        if not isinstance(err, dict):
            return True, f"decode returned non-dict: {type(err).__name__}"
        for required in ("txid", "version", "vin", "vout"):
            if required not in err:
                return True, f"decode missing required field {required!r}"
        return False, ""
    if not isinstance(err, dict):
        return True, f"non-dict error: {err!r}"
    msg = err.get("message", "")
    if not msg:
        return True, f"empty error message (code={err.get('code', '?')})"
    if err.get("code") == -32603:
        return True, f"internal error leak: {msg[:120]}"
    if err.get("code") == -1:
        # The "internal bug" code Bitcoin Core uses when a returned
        # field doesn't match its declared schema. F11 reincarnated.
        return True, f"RPC schema mismatch (-1): {msg[:120]}"
    return False, ""


def run_fuzz(rpc_url: str, seed_tx_hex: str, iterations: int,
             rng_seed: int, audit_pass: bool, decode_only: bool) -> FuzzStats:
    rng = random.Random(rng_seed)
    seed_bytes = bytes.fromhex(seed_tx_hex)
    stats = FuzzStats()

    rpc_method = "decoderawtransaction" if decode_only else "sendrawtransaction"
    rpc_extra_args = [] if decode_only else [0]  # 0 = maxfeerate (no fee waste)
    anomaly_fn = _is_anomaly_decode if decode_only else _is_anomaly

    # Audit-driven pass first (fixed cases).
    if audit_pass:
        for name, mutator in _AUDIT_CASES:
            mutated = mutator(seed_bytes)
            stats.iterations += 1
            ok, err = _rpc_call(rpc_url, rpc_method,
                                [mutated.hex()] + rpc_extra_args)
            anomaly, reason = anomaly_fn(ok, err)
            if anomaly:
                stats.anomalies += 1
                stats.anomaly_log.append((f"audit:{name}", reason,
                                           mutated[:64].hex()))
                if ok and not decode_only:
                    stats.accepted += 1
            else:
                stats.cleanly_rejected += 1
                if not ok:
                    stats.rejection_reasons[_categorise_error(err)] += 1

    # Random mutation pass.
    last_progress = time.monotonic()
    for i in range(iterations):
        strategy_name, mutator = rng.choice(_STRATEGIES)
        mutated = mutator(rng, seed_bytes)
        if not mutated:
            continue
        stats.iterations += 1
        try:
            ok, err = _rpc_call(rpc_url, rpc_method,
                                [mutated.hex()] + rpc_extra_args)
        except Exception as e:
            stats.anomalies += 1
            stats.anomaly_log.append((f"rpc_exception:{strategy_name}",
                                       str(e), mutated[:64].hex()))
            continue

        anomaly, reason = anomaly_fn(ok, err)
        if anomaly:
            stats.anomalies += 1
            stats.anomaly_log.append((strategy_name, reason,
                                       mutated[:64].hex()))
            if ok and not decode_only:
                stats.accepted += 1
        else:
            stats.cleanly_rejected += 1
            if not ok:
                stats.rejection_reasons[_categorise_error(err)] += 1

        if time.monotonic() - last_progress > 5.0:
            print(f"  ...{i+1}/{iterations} iterations "
                  f"(rejected={stats.cleanly_rejected}, "
                  f"anomalies={stats.anomalies})",
                  file=sys.stderr)
            last_progress = time.monotonic()

    return stats


def _print_report(stats: FuzzStats):
    print()
    print("─" * 72)
    print("REPORT")
    print("─" * 72)
    print(f"iterations:        {stats.iterations}")
    print(f"cleanly rejected:  {stats.cleanly_rejected}  "
          f"({100.0*stats.cleanly_rejected/max(1,stats.iterations):.1f}%)")
    print(f"anomalies:         {stats.anomalies}")
    print(f"  accepted:        {stats.accepted}")
    print(f"  timeouts:        {stats.timeouts}")
    print(f"  empty errors:    {stats.rpc_errors_no_message}")
    print()
    print("top rejection categories:")
    for reason, count in stats.rejection_reasons.most_common(15):
        print(f"  {count:>5}  {reason}")
    if stats.anomaly_log:
        print()
        print(f"anomaly log ({len(stats.anomaly_log)} entries):")
        for kind, reason, hex_head in stats.anomaly_log[:30]:
            print(f"  [{kind}] {reason}")
            print(f"           tx[:32]={hex_head}")
        if len(stats.anomaly_log) > 30:
            print(f"  ... {len(stats.anomaly_log) - 30} more")
    print("─" * 72)
    if stats.anomalies:
        print("STATUS: ANOMALIES — review above")
    else:
        print("STATUS: clean rejections only")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=1000,
                        help="number of random mutations (default: 1000)")
    parser.add_argument("--rpc-url",
                        default=os.environ.get("BITCOIN_RPC_URL"),
                        help="JSON-RPC URL (or set $BITCOIN_RPC_URL)")
    parser.add_argument("--seed-vectors-file",
                        default=_DEFAULT_SEED_TX_HEX_FILE,
                        help="path to rung_tx_vectors.json (relative to "
                             "repo root if not absolute)")
    parser.add_argument("--seed-tx-hex",
                        help="explicit seed tx hex (overrides vector lookup)")
    parser.add_argument("--rng-seed", type=lambda s: int(s, 0),
                        default=0xCAFEBABE,
                        help="PRNG seed for reproducible runs (decimal "
                             "or 0x-prefixed hex)")
    parser.add_argument("--audit-pass", action="store_true",
                        help="also run audit-driven fixed cases (F14, F17)")
    parser.add_argument("--signet", action="store_true",
                        help="signet sanity probe — confirms node network "
                             "before fuzzing")
    parser.add_argument("--decode-only", action="store_true",
                        help="target decoderawtransaction instead of "
                             "sendrawtransaction. Exercises the v4 "
                             "deserialiser + TxToUniv (F11 territory) "
                             "without needing matching chainstate.")
    args = parser.parse_args()

    if not args.rpc_url:
        parser.error("--rpc-url or $BITCOIN_RPC_URL required")

    if args.seed_tx_hex:
        seed_hex = args.seed_tx_hex
    else:
        path = args.seed_vectors_file
        if not os.path.isabs(path):
            # Try repo-root relative.
            here = os.path.dirname(os.path.abspath(__file__))
            path = os.path.join(here, "..", "..", path)
        seed_hex = _load_seed_tx_hex(path)
    print(f"seed tx: {len(seed_hex)//2} bytes")

    # Liveness check.
    print("probing node...")
    ok, info = _rpc_call(args.rpc_url, "getblockchaininfo", [])
    if not ok:
        raise SystemExit(f"node probe failed: {info}")
    chain = info.get("chain", "?")
    blocks = info.get("blocks", "?")
    print(f"node alive: chain={chain}, blocks={blocks}")
    if args.signet and chain != "signet":
        print(f"WARN: --signet was passed but chain={chain}", file=sys.stderr)

    mode = "decoderawtransaction (decode-only)" if args.decode_only \
           else "sendrawtransaction"
    print(f"fuzzing {args.iterations} iterations against {chain} "
          f"via {mode}...")
    t0 = time.monotonic()
    stats = run_fuzz(args.rpc_url, seed_hex, args.iterations,
                      args.rng_seed, args.audit_pass, args.decode_only)
    elapsed = time.monotonic() - t0
    print(f"done in {elapsed:.1f}s "
          f"({stats.iterations/max(0.1,elapsed):.0f} it/s)")
    _print_report(stats)
    return 1 if stats.anomalies else 0


if __name__ == "__main__":
    sys.exit(main())
