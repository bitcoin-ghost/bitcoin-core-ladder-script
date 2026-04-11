"""QABI endpoints for ladder_proxy.py.

These are the JSON-RPC wrappers the web engine uses to drive the
full QABIO lifecycle from a browser or a client script. They are
intended to be included from ladder_proxy.py (append to the file
or import as a module) — the file is standalone-valid Python and
does not execute anything on import.

Endpoints
---------

    POST /api/ladder/qabi/authchain
        body:  {auth_seed: hex, chain_length: int, depth?: int}
        returns: {auth_tip: hex, preimage?: hex}

    POST /api/ladder/qabi/buildblock
        body: {
            coordinator_pubkey: hex (897 bytes, FALCON-512),
            prime_expiry_height: int,
            batch_id: hex (32 bytes),
            entries: [{participant_id, contribution, destination_index}, ...],
            outputs: [{amount, script_pubkey}, ...]
        }
        returns: {qabi_block: hex, qabi_root: hex, size: int}

    POST /api/ladder/qabi/blockinfo
        body:  {qabi_block: hex}
        returns: decoded block contents

    POST /api/ladder/qabi/sighash
        body:  {hex: full tx hex}
        returns: {sighash: hex}

    POST /api/ladder/qabi/signqabo
        body:  {hex: tx hex, privkey: FALCON-512 privkey hex}
        returns: {hex: signed tx hex, sighash: hex, sig_size: int}

    GET  /api/ladder/qabi/info
        returns: {
            scheme, pubkey_size, sig_size, block_max_soft,
            block_max_hard, standard_relay_max_N,
            single_block_max_N
        }

Each endpoint is a thin wrapper over the corresponding ladder
bitcoind JSON-RPC (`qabi_authchain`, `qabi_buildblock`, ...) and
enforces request size limits / minimal input validation so the
engine can surface usage errors directly. Wrapping is needed
because the engine's frontend cannot call bitcoind RPC directly
— it has to go through the proxy which handles auth + CORS.

To wire this into ladder_proxy.py, either:

    1. cat contrib/qabi/ladder_proxy_qabi_endpoints.py >> ladder_proxy.py
       and `systemctl restart ladder-proxy`, or

    2. from ladder_proxy_qabi_endpoints import register_qabi_endpoints
       register_qabi_endpoints(app, rpc_call)
"""

# The symbols `app`, `rpc_call`, `HTTPException`, `json` must be in
# scope when this file is sourced into ladder_proxy.py. They match
# the existing endpoint conventions (see create_txmlsc etc.).

from fastapi import HTTPException  # noqa: F401 — same import ladder_proxy already has
import json                          # noqa: F401

# Request size guardrails (matching ladder_proxy's existing limits).
_QABI_MAX_JSON = 262_144      # 256 KB
_QABI_MAX_HEX  = 524_288      # 512 KB hex ≈ 256 KB binary


def _parse_json_body(body: bytes, max_size: int = _QABI_MAX_JSON):
    if len(body) > max_size:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")
    if not isinstance(data, dict):
        raise HTTPException(400, "Request must be a JSON object.")
    return data


def _require_str(d, key, name=None, max_len=_QABI_MAX_HEX):
    v = d.get(key)
    if not isinstance(v, str):
        raise HTTPException(400, f"Missing or invalid '{key}' string.")
    if len(v) > max_len:
        raise HTTPException(400, f"{name or key} too large.")
    return v


def _require_int(d, key, min_val=None, max_val=None):
    v = d.get(key)
    if not isinstance(v, int) or isinstance(v, bool):
        raise HTTPException(400, f"Missing or invalid '{key}' integer.")
    if min_val is not None and v < min_val:
        raise HTTPException(400, f"'{key}' below minimum.")
    if max_val is not None and v > max_val:
        raise HTTPException(400, f"'{key}' above maximum.")
    return v


def register_qabi_endpoints(app, rpc_call):
    """Attach the QABI endpoints to the given FastAPI app.
    Pass `rpc_call` from ladder_proxy.py so we reuse the existing
    httpx client + RPC auth handling.
    """

    @app.post("/api/ladder/qabi/authchain")
    async def qabi_authchain(request):
        body = await request.body()
        data = _parse_json_body(body)
        auth_seed = _require_str(data, "auth_seed", max_len=64)
        chain_length = _require_int(data, "chain_length",
                                     min_val=1, max_val=200_000)
        params = [auth_seed, chain_length]
        if "depth" in data:
            depth = _require_int(data, "depth",
                                  min_val=0, max_val=chain_length)
            params.append(depth)
        return await rpc_call("qabi_authchain", params)

    @app.post("/api/ladder/qabi/buildblock")
    async def qabi_buildblock(request):
        body = await request.body()
        data = _parse_json_body(body)
        coord_pk    = _require_str(data, "coordinator_pubkey", max_len=1800)
        expiry      = _require_int(data, "prime_expiry_height", min_val=0)
        batch_id    = _require_str(data, "batch_id", max_len=64)
        entries     = data.get("entries")
        outputs     = data.get("outputs")
        if not isinstance(entries, list) or len(entries) == 0:
            raise HTTPException(400, "Missing or invalid 'entries' array.")
        if not isinstance(outputs, list) or len(outputs) == 0:
            raise HTTPException(400, "Missing or invalid 'outputs' array.")
        params = [coord_pk, expiry, batch_id, entries, outputs]
        return await rpc_call("qabi_buildblock", params)

    @app.post("/api/ladder/qabi/blockinfo")
    async def qabi_blockinfo(request):
        body = await request.body()
        data = _parse_json_body(body)
        qabi_block = _require_str(data, "qabi_block")
        return await rpc_call("qabi_blockinfo", [qabi_block])

    @app.post("/api/ladder/qabi/sighash")
    async def qabi_sighash(request):
        body = await request.body()
        data = _parse_json_body(body)
        hex_tx = _require_str(data, "hex")
        return await rpc_call("qabi_sighash", [hex_tx])

    @app.post("/api/ladder/qabi/signqabo")
    async def qabi_signqabo(request):
        body = await request.body()
        data = _parse_json_body(body)
        hex_tx  = _require_str(data, "hex")
        privkey = _require_str(data, "privkey", max_len=8192)
        return await rpc_call("qabi_signqabo", [hex_tx, privkey])

    @app.get("/api/ladder/qabi/info")
    async def qabi_info():
        """Static QABIO configuration info for the web engine UI.

        All values match the consensus constants in src/rung/qabi.h;
        hardcoded here so the frontend can render scheme + limits
        without a round-trip through bitcoind for what is fixed
        metadata. If the constants in qabi.h change, bump this to
        match (or read them via a dedicated RPC in a future revision).
        """
        return {
            "scheme": "FALCON-512",
            "pubkey_size": 897,
            "sig_size": 666,
            "block_max_soft": 65_536,
            "block_max_hard": 262_144,
            # Empirical ceilings from qabi_tests/qabi_tx_size_sweep
            # (commit 9258bb1989, measured on v1 QABIBlock format).
            "standard_relay_max_N": 618,
            "single_block_max_N": 3500,
            "bytes_per_input": 432,
            "vbytes_per_input": 162,
        }
