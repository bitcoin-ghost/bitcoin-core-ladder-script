"""
Ladder Script Signet Proxy

Thin FastAPI service that wraps bitcoin-core-ladder RPC commands for the Ladder Script
Builder. Runs on the same VM as bitcoind, proxying browser requests to localhost
RPC with rate limiting and input validation.

Endpoints:
  POST /api/ladder/create        - createrungtx (build v4 tx, legacy)
  POST /api/ladder/createtxmlsc  - createtxmlsc (build v4 TX_MLSC tx)
  POST /api/ladder/sign          - signrungtx (sign with wallet keys, legacy)
  POST /api/ladder/signladder    - signladder (sign with auto-lookup)
  POST /api/ladder/broadcast     - sendrawtransaction (push to signet)
  POST /api/ladder/decode        - decoderung (decode ladder hex)
  POST /api/ladder/validate      - validateladder (validate structure)
  POST /api/ladder/parse         - parseladder (descriptor to conditions)
  POST /api/ladder/format        - formatladder (conditions to descriptor)
  POST /api/ladder/computemutation - computemutation (recursive covenant roots)
  GET  /api/ladder/tx/{txid}     - getrawtransaction (lookup tx)
  POST /api/ladder/faucet        - fund a test address from faucet wallet
  GET  /api/ladder/status        - proxy health + chain info
"""

import hashlib
import hmac as hmac_mod
import json
import os
import sqlite3
import struct
import time
from collections import defaultdict
from contextlib import asynccontextmanager

import coincurve
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# --- Config ---

RPC_BASE = os.environ.get("RPC_URL", "http://127.0.0.1:38332")
RPC_URL = RPC_BASE
RPC_WALLET_URL = RPC_BASE + "/wallet/" + os.environ.get("RPC_WALLET", "ladder")
RPC_USER = os.environ.get("RPC_USER", "ladderrpc")
RPC_PASS = os.environ.get("RPC_PASS", "ladder_signet_rpc_2026")
FAUCET_AMOUNT = float(os.environ.get("FAUCET_AMOUNT", "0.001"))
FAUCET_COOLDOWN = int(os.environ.get("FAUCET_COOLDOWN", "300"))  # seconds per IP
RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "120"))  # requests per minute
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS", "https://ladder-script.org,https://www.ladder-script.org,http://localhost:8080,http://127.0.0.1:8080"
).split(",")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8340"))
ANALYTICS_DB = os.environ.get("ANALYTICS_DB", os.path.join(os.path.dirname(__file__), "analytics.db"))

# --- Rate limiter ---

_rate_buckets: dict[str, list[float]] = defaultdict(list)
_faucet_last: dict[str, float] = {}


def _check_rate_limit(ip: str) -> None:
    now = time.time()
    bucket = _rate_buckets[ip]
    # Prune entries older than 60s
    _rate_buckets[ip] = [t for t in bucket if now - t < 60]
    if len(_rate_buckets[ip]) >= RATE_LIMIT_RPM:
        raise HTTPException(429, "Rate limit exceeded. Try again in a minute.")
    _rate_buckets[ip].append(now)


def _check_faucet_cooldown(ip: str) -> None:
    now = time.time()
    last = _faucet_last.get(ip, 0)
    remaining = int(FAUCET_COOLDOWN - (now - last))
    if remaining > 0:
        raise HTTPException(429, f"Faucet cooldown: {remaining}s remaining.")


# --- RPC client ---

_http_client: httpx.AsyncClient | None = None


def _init_analytics_db():
    conn = sqlite3.connect(ANALYTICS_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        page TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        ts REAL NOT NULL,
        referrer TEXT DEFAULT '',
        ua TEXT DEFAULT ''
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS broadcasts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        txid TEXT NOT NULL,
        ts REAL NOT NULL,
        ip_hash TEXT NOT NULL,
        tx_size INTEGER DEFAULT 0
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_visits_ts ON visits(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_broadcasts_ts ON broadcasts(ts)")
    conn.commit()
    conn.close()


def _hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client
    _init_analytics_db()
    _http_client = httpx.AsyncClient(timeout=900.0)
    yield
    await _http_client.aclose()


WALLET_METHODS = {
    "getbalance", "getbalances", "getwalletinfo", "getnewaddress",
    "listunspent", "sendtoaddress", "sendmany",
    "signrawtransactionwithwallet",
    "signrungtx", "signladder", "createrungtx", "createtxmlsc",
    "validateaddress", "generatetoaddress",
    "getaddressinfo", "listdescriptors",
}


# --- BIP32 key derivation (for descriptor wallets that lack dumpprivkey) ---

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_master_privkey: bytes | None = None
_master_chaincode: bytes | None = None


def _b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58_ALPHABET.index(c)
    result = []
    while n > 0:
        n, r = divmod(n, 256)
        result.insert(0, r)
    pad = len(s) - len(s.lstrip('1'))
    return bytes(pad) + bytes(result)


def _b58decode_check(s: str) -> bytes:
    data = _b58decode(s)
    payload, checksum = data[:-4], data[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("Bad base58 checksum")
    return payload


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = _B58_ALPHABET[r] + result
    for b in data:
        if b == 0:
            result = '1' + result
        else:
            break
    return result


def _parse_xprv(xprv_str: str) -> tuple[bytes, bytes]:
    data = _b58decode_check(xprv_str)
    chain_code = data[13:45]
    privkey = data[46:78]
    return privkey, chain_code


def _derive_child(privkey: bytes, chain_code: bytes, index: int, hardened: bool = False) -> tuple[bytes, bytes]:
    if hardened:
        index += 0x80000000
        data = b'\x00' + privkey + struct.pack('>I', index)
    else:
        pubkey = coincurve.PublicKey.from_secret(privkey).format(compressed=True)
        data = pubkey + struct.pack('>I', index)
    I = hmac_mod.new(chain_code, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    child_int = (int.from_bytes(IL, 'big') + int.from_bytes(privkey, 'big')) % _SECP256K1_N
    return child_int.to_bytes(32, 'big'), IR


def _derive_path(privkey: bytes, chain_code: bytes, path: str) -> bytes:
    """Derive a child private key from a BIP32 path like m/84'/1'/0'/0/22."""
    parts = path.strip().lstrip('m').lstrip('/').split('/')
    for part in parts:
        hardened = part.endswith("'") or part.endswith("h")
        idx = int(part.rstrip("'h"))
        privkey, chain_code = _derive_child(privkey, chain_code, idx, hardened)
    return privkey


def _privkey_to_wif(privkey: bytes, testnet: bool = True) -> str:
    prefix = b'\xef' if testnet else b'\x80'
    payload = prefix + privkey + b'\x01'  # compressed
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _b58encode(payload + checksum)


async def _ensure_master_key():
    """Fetch and cache the master xprv from the wallet's descriptors."""
    global _master_privkey, _master_chaincode
    if _master_privkey is not None:
        return
    descriptors = await rpc_call("listdescriptors", [True])
    # Find the wpkh descriptor (bech32 = m/84'/1'/0')
    for desc in descriptors.get("descriptors", []):
        desc_str = desc.get("desc", "")
        if desc_str.startswith("wpkh(tprv") and not desc.get("internal", False):
            # Extract xprv from wpkh(tprv.../*)
            xprv = desc_str.split("wpkh(")[1].split("/")[0]
            _master_privkey, _master_chaincode = _parse_xprv(xprv)
            return
    raise HTTPException(500, "Could not find wpkh descriptor with private key.")


async def rpc_call(method: str, params=None):
    if params is None:
        params = []
    payload = {
        "jsonrpc": "1.0",
        "id": "ladder-proxy",
        "method": method,
        "params": params,
    }
    url = RPC_WALLET_URL if method in WALLET_METHODS else RPC_URL
    try:
        resp = await _http_client.post(
            url,
            json=payload,
            auth=(RPC_USER, RPC_PASS),
            headers={"Content-Type": "application/json"},
        )
    except httpx.ConnectError:
        raise HTTPException(503, "Ladder node unavailable.")
    except httpx.TimeoutException:
        raise HTTPException(504, "Ladder node timeout.")

    if resp.status_code == 401:
        raise HTTPException(503, "RPC authentication failed.")
    if resp.status_code not in (200, 404, 500):
        raise HTTPException(502, f"RPC error: HTTP {resp.status_code}")

    data = resp.json()
    if data.get("error"):
        err = data["error"]
        raise HTTPException(
            400, {"rpc_error": err.get("message", str(err)), "code": err.get("code")}
        )
    return data.get("result")


# --- Validation helpers ---

MAX_JSON_SIZE = 262_144  # 256KB max request body (PQ witnesses up to ~50KB)
MAX_HEX_SIZE = 262_144   # 256KB max hex string (SPHINCS+ signed TX ~100KB hex)


def _validate_hex(value: str, name: str, max_len: int = MAX_HEX_SIZE) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, f"{name} must be a string.")
    value = value.strip()
    if len(value) > max_len:
        raise HTTPException(400, f"{name} too large (max {max_len} chars).")
    if not all(c in "0123456789abcdefABCDEF" for c in value):
        raise HTTPException(400, f"{name} must be valid hex.")
    return value


def _validate_txid(txid: str) -> str:
    txid = _validate_hex(txid, "txid", 64)
    if len(txid) != 64:
        raise HTTPException(400, "txid must be 64 hex characters.")
    return txid


# --- App ---

app = FastAPI(title="Ladder Script Proxy", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=3600,
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.method != "OPTIONS":
        ip = request.headers.get("X-Real-IP", request.client.host)
        try:
            _check_rate_limit(ip)
        except HTTPException as exc:
            # Must include CORS headers on 429 responses — otherwise the browser
            # treats the missing Access-Control-Allow-Origin as a network error
            # ("Failed to fetch") instead of showing the actual 429 status.
            origin = request.headers.get("origin", "")
            headers = {}
            if origin in ALLOWED_ORIGINS:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                headers["Access-Control-Allow-Headers"] = "Content-Type"
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=headers,
            )
    return await call_next(request)


# --- Endpoints ---


@app.get("/api/ladder/status")
async def status():
    """Proxy health + chain info."""
    info = await rpc_call("getblockchaininfo")
    return {
        "status": "ok",
        "chain": info.get("chain"),
        "blocks": info.get("blocks"),
        "bestblockhash": info.get("bestblockhash"),
    }


@app.post("/api/ladder/create")
async def create_rungtx(request: Request):
    """Build a v4 ladder transaction from JSON spec."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    if not isinstance(data, dict):
        raise HTTPException(400, "Request must be a JSON object.")

    inputs = data.get("inputs", [])
    outputs = data.get("outputs", [])
    locktime = data.get("locktime", 0)
    relays = data.get("relays")

    params = [inputs, outputs, locktime]
    if relays:
        params.append(relays)

    result = await rpc_call("createrungtx", params)
    # RPC returns {"hex": "..."} — unwrap if needed
    if isinstance(result, dict) and "hex" in result:
        return {"hex": result["hex"]}
    return {"hex": result}


@app.post("/api/ladder/sign")
async def sign_rungtx(request: Request):
    """Sign a v4 ladder transaction.
    - If 'signers' and 'spent_outputs' are provided → signrungtx (MLSC inputs).
    - Otherwise → signrawtransactionwithwallet (wallet P2WPKH inputs)."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    tx_hex = data.get("hex", "")
    tx_hex = _validate_hex(tx_hex, "hex")
    if not tx_hex:
        raise HTTPException(400, "Missing 'hex' field.")

    signers = data.get("signers")
    spent_outputs = data.get("spent_outputs")

    if signers and spent_outputs:
        # MLSC input signing via signrungtx(hex, signers[], spent_outputs[])
        result = await rpc_call("signrungtx", [tx_hex, signers, spent_outputs])
    else:
        # Wallet-owned inputs (funding txs) via signrawtransactionwithwallet
        result = await rpc_call("signrawtransactionwithwallet", [tx_hex])
    return result


@app.post("/api/ladder/createtxmlsc")
async def create_txmlsc(request: Request):
    """Build a v4 TX_MLSC transaction from JSON spec (new RPC).
    RPC: createtxmlsc(inputs, outputs, rungs, locktime, internal_pubkey, qabi_block)
      inputs:      [{txid, vout, sequence?}, ...]
      outputs:     [amount_btc, ...]  — array of BTC amounts (one per output)
      rungs:       [{output_index, blocks: [{type, fields: [{type, hex}]}]}, ...]
      locktime:    uint32 (optional, default 0)
      internal_pubkey: optional hex string for explicit key-path tweak
      qabi_block:  optional hex blob produced by qabi_buildblock, embedded in
                   the resulting tx's QABI extension
    """
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    if not isinstance(data, dict):
        raise HTTPException(400, "Request must be a JSON object.")

    inputs = data.get("inputs", [])
    outputs = data.get("outputs", [])
    rungs = data.get("rungs", [])
    locktime = data.get("locktime", 0)

    params = [inputs, outputs, rungs, locktime]
    # qabi_block sits at positional index 5 (after internal_pubkey). When a
    # caller supplies qabi_block without internal_pubkey we still have to
    # pass an empty string placeholder so the positional slot lines up.
    internal_pubkey = data.get("internal_pubkey")
    qabi_block = data.get("qabi_block")
    if internal_pubkey or qabi_block:
        params.append(internal_pubkey or "")
    if qabi_block:
        params.append(qabi_block)

    result = await rpc_call("createtxmlsc", params)
    return result


@app.post("/api/ladder/signladder")
async def sign_ladder(request: Request):
    """Sign a v4 transaction using descriptor notation (new RPC).
    RPC: signladder(hex, descriptor, keys, spent_outputs, input_index,
                    rung_index, keypath_key, keypath_merkle_root, shared_source)
      hex:            unsigned v4 transaction hex
      descriptor:     ladder descriptor string, e.g. "ladder(sig(@alice))"
      keys:           JSON string mapping aliases to WIF privkeys
      spent_outputs:  [{amount, scriptPubKey}, ...]
      input_index:    which input to sign (default 0)
      rung_index:     which rung to reveal (default 0)
      keypath_key:    WIF for key-path spending (optional)
      keypath_merkle_root: 32-byte hex for key-path with tree (optional)
    """
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    tx_hex = data.get("hex", "")
    tx_hex = _validate_hex(tx_hex, "hex")
    if not tx_hex:
        raise HTTPException(400, "Missing 'hex' field.")

    descriptor = data.get("descriptor", "")
    if not descriptor:
        raise HTTPException(400, "Missing 'descriptor' field.")

    keys = data.get("keys", "{}")
    if isinstance(keys, dict):
        keys = json.dumps(keys)

    spent_outputs = data.get("spent_outputs", [])
    if not spent_outputs:
        raise HTTPException(400, "Missing 'spent_outputs' field.")

    input_index = data.get("input_index", 0)
    rung_index = data.get("rung_index", 0)

    params = [tx_hex, descriptor, keys, spent_outputs, input_index, rung_index]

    # Optional key-path params
    keypath_key = data.get("keypath_key")
    keypath_merkle_root = data.get("keypath_merkle_root")
    shared_source = data.get("shared_source")

    if keypath_key:
        params.append(keypath_key)
        params.append(keypath_merkle_root or "")
    elif shared_source is not None:
        params.extend(["", ""])  # skip keypath params
        params.append(shared_source)

    result = await rpc_call("signladder", params)
    return result


@app.post("/api/ladder/broadcast")
async def broadcast(request: Request):
    """Broadcast a signed transaction to signet."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    tx_hex = data.get("hex", "")
    tx_hex = _validate_hex(tx_hex, "hex")
    if not tx_hex:
        raise HTTPException(400, "Missing 'hex' field.")

    # maxfeerate=0 disables fee-rate check — this is signet/regtest, not mainnet
    txid = await rpc_call("sendrawtransaction", [tx_hex, 0])

    # Record broadcast for telemetry
    try:
        ip = request.headers.get("X-Real-IP", request.client.host)
        conn = sqlite3.connect(ANALYTICS_DB)
        conn.execute(
            "INSERT INTO broadcasts (txid, ts, ip_hash, tx_size) VALUES (?, ?, ?, ?)",
            (txid, time.time(), _hash_ip(ip), len(tx_hex) // 2),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # telemetry must never block broadcasts

    return {"txid": txid}


@app.post("/api/ladder/decode")
async def decode(request: Request):
    """Decode a ladder witness or conditions hex string."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    hex_str = data.get("hex", "")
    hex_str = _validate_hex(hex_str, "hex")
    if not hex_str:
        raise HTTPException(400, "Missing 'hex' field.")

    result = await rpc_call("decoderung", [hex_str])
    return result


@app.post("/api/ladder/validate")
async def validate(request: Request):
    """Validate a ladder structure."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    hex_str = data.get("hex", "")
    hex_str = _validate_hex(hex_str, "hex")
    if not hex_str:
        raise HTTPException(400, "Missing 'hex' field.")

    result = await rpc_call("validateladder", [hex_str])
    return result


@app.post("/api/ladder/parse")
async def parse_ladder(request: Request):
    """Parse descriptor string to conditions."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    descriptor = data.get("descriptor", "")
    if not descriptor:
        raise HTTPException(400, "Missing 'descriptor' field.")

    keys = data.get("keys", {})
    result = await rpc_call("parseladder", [descriptor, keys])
    return result


@app.post("/api/ladder/format")
async def format_ladder(request: Request):
    """Format conditions as descriptor string."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    hex_str = data.get("hex", "")
    hex_str = _validate_hex(hex_str, "hex")
    if not hex_str:
        raise HTTPException(400, "Missing 'hex' field.")

    keys = data.get("keys", {})
    result = await rpc_call("formatladder", [hex_str, keys])
    return result


@app.post("/api/ladder/computemutation")
async def compute_mutation(request: Request):
    """Compute mutated conditions root for recursive covenants."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    result = await rpc_call("computemutation", [data])
    return result


@app.get("/api/ladder/tx/{txid}")
async def get_tx(txid: str):
    """Look up a transaction by txid. Adds is_qabio flag for QABIO batch txs."""
    txid = _validate_txid(txid)
    result = await rpc_call("getrawtransaction", [txid, True])
    # Detect QABIO: v4 tx with a non-empty aggregated_sig (666 bytes).
    # The raw hex encodes qabi_block + aggregated_sig after the witness
    # stacks. A FALCON-512 sig is exactly 666 bytes (1332 hex chars).
    result["is_qabio"] = False
    if result.get("version") == 4 and result.get("hex"):
        raw = result["hex"]
        # Quick heuristic: QABIO txs have 666-byte agg sig at the end
        # (before the 8-char locktime). Check the compact_size prefix.
        # aggregated_sig sits right before locktime (last 8 hex chars).
        # Its compact_size prefix for 666 bytes is fd9a02 (3 bytes = 6 hex).
        if "fd9a02" in raw[-1400:]:
            result["is_qabio"] = True
    return result


@app.post("/api/ladder/faucet")
async def faucet(request: Request):
    """Send test sats to an address from the faucet wallet."""
    ip = request.headers.get("X-Real-IP", request.client.host)
    _check_faucet_cooldown(ip)

    body = await request.body()
    if len(body) > 4096:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    address = data.get("address", "").strip()
    if not address or not isinstance(address, str):
        raise HTTPException(400, "Missing 'address' field.")
    if len(address) > 128:
        raise HTTPException(400, "Address too long.")

    # Validate address via RPC
    addr_info = await rpc_call("validateaddress", [address])
    if not addr_info.get("isvalid"):
        raise HTTPException(400, "Invalid signet address.")

    txid = await rpc_call("sendtoaddress", [address, FAUCET_AMOUNT])
    _faucet_last[ip] = time.time()
    return {"txid": txid, "amount": FAUCET_AMOUNT}


@app.post("/api/ladder/playground/fund-batch")
async def playground_fund_batch(request: Request):
    """Fund N participant addresses in a single sendmany tx.

    Used by the QABIO playground to bypass the per-IP faucet cooldown
    when setting up multi-participant scenarios. Mines 1 block before
    returning so the resulting UTXOs are immediately spendable.

    Request:  {"addresses": [str, ...], "amount_btc": float (optional)}
    Response: {"txid": str, "block_hash": str,
               "outputs": [{"address": str, "vout": int, "amount_btc": float}, ...]}
    """
    body = await request.body()
    if len(body) > 16384:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    addresses = data.get("addresses", [])
    if not isinstance(addresses, list) or not addresses:
        raise HTTPException(400, "addresses must be a non-empty list.")
    if len(addresses) > 32:
        raise HTTPException(400, "Max 32 addresses per batch.")
    for a in addresses:
        if not isinstance(a, str) or len(a) > 128:
            raise HTTPException(400, "Invalid address entry.")

    try:
        amount_btc = float(data.get("amount_btc", FAUCET_AMOUNT))
    except (TypeError, ValueError):
        raise HTTPException(400, "amount_btc must be numeric.")
    if amount_btc <= 0 or amount_btc > 1.0:
        raise HTTPException(400, "amount_btc out of range.")

    amount_map = {a: amount_btc for a in addresses}
    txid = await rpc_call("sendmany", ["", amount_map])

    # Mine one block so the outputs are immediately available as inputs.
    # Matches the /api/ladder/mine handler: needs a large maxtries for the
    # signet challenge. Any exception here leaves block_hash=None and the
    # caller can retry by calling /api/ladder/mine separately.
    try:
        mine_addr = await rpc_call("getnewaddress", ["", "bech32"])
        block_hashes = await rpc_call("generatetoaddress", [1, mine_addr, 100_000_000])
        block_hash = block_hashes[0] if block_hashes else None
    except Exception:
        block_hash = None

    # Resolve per-address vout by decoding the tx.
    raw = await rpc_call("getrawtransaction", [txid, True])
    outputs = []
    for addr in addresses:
        vout_match = None
        amt_match = None
        for v in raw.get("vout", []):
            spk = v.get("scriptPubKey", {}) or {}
            if spk.get("address") == addr or addr in (spk.get("addresses") or []):
                vout_match = v["n"]
                amt_match = float(v["value"])
                break
        outputs.append({
            "address": addr,
            "vout": vout_match,
            "amount_btc": amt_match,
        })

    return {"txid": txid, "block_hash": block_hash, "outputs": outputs}


# --- Wallet & chain info endpoints ---


@app.get("/api/ladder/wallet/balance")
async def wallet_balance():
    """Get wallet balance info."""
    balance = await rpc_call("getbalance")
    balances = await rpc_call("getbalances")
    unconfirmed = balances.get("mine", {}).get("untrusted_pending", 0) if balances else 0
    info = await rpc_call("getwalletinfo")
    return {
        "balance": balance,
        "unconfirmed_balance": unconfirmed,
        "txcount": info.get("txcount"),
    }


@app.get("/api/ladder/wallet/address")
async def wallet_address():
    """Generate a new bech32 receiving address."""
    address = await rpc_call("getnewaddress", ["", "bech32"])
    return {"address": address}


@app.get("/api/ladder/wallet/keypair")
async def wallet_keypair():
    """Generate a new address and return its pubkey + privkey (descriptor wallet)."""
    await _ensure_master_key()
    address = await rpc_call("getnewaddress", ["", "bech32"])
    info = await rpc_call("getaddressinfo", [address])
    pubkey = info.get("pubkey", "")
    hdkeypath = info.get("hdkeypath", "")
    if not hdkeypath:
        raise HTTPException(500, "Address has no HD key path.")
    child_privkey = _derive_path(_master_privkey, _master_chaincode, hdkeypath)
    # Verify derivation matches
    derived_pub = coincurve.PublicKey.from_secret(child_privkey).format(compressed=True).hex()
    if derived_pub != pubkey:
        raise HTTPException(500, f"Key derivation mismatch: got {derived_pub}, expected {pubkey}")
    wif = _privkey_to_wif(child_privkey)
    return {"address": address, "pubkey": pubkey, "privkey": wif}


@app.get("/api/ladder/wallet/utxos")
async def wallet_utxos():
    """List unspent transaction outputs."""
    result = await rpc_call("listunspent", [0, 9999999])
    return result


@app.post("/api/ladder/decode-tx")
async def decode_tx(request: Request):
    """Decode a raw transaction hex string."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    hex_str = data.get("hex", "")
    hex_str = _validate_hex(hex_str, "hex")
    if not hex_str:
        raise HTTPException(400, "Missing 'hex' field.")

    result = await rpc_call("decoderawtransaction", [hex_str])
    return result


@app.get("/api/ladder/mempool")
async def mempool():
    """Get mempool info."""
    info = await rpc_call("getmempoolinfo")
    return {
        "size": info.get("size"),
        "bytes": info.get("bytes"),
        "usage": info.get("usage"),
        "maxmempool": info.get("maxmempool"),
        "mempoolminfee": info.get("mempoolminfee"),
    }


@app.get("/api/ladder/mempool/txs")
async def mempool_txs():
    """Get mempool transactions with decoded details."""
    txids = await rpc_call("getrawmempool")
    if not isinstance(txids, list):
        return {"txs": []}
    txs = []
    for txid in txids[:50]:  # limit to 50 txs
        try:
            raw = await rpc_call("getrawtransaction", [txid, True])
            tx_entry = {
                "txid": txid,
                "version": raw.get("version"),
                "size": raw.get("size"),
                "vsize": raw.get("vsize"),
                "weight": raw.get("weight"),
                "vin_count": len(raw.get("vin", [])),
                "vout_count": len(raw.get("vout", [])),
                "vout": [],
            }
            for vout in raw.get("vout", []):
                tx_entry["vout"].append({
                    "value": vout.get("value"),
                    "n": vout.get("n"),
                    "type": vout.get("scriptPubKey", {}).get("type", "unknown"),
                    "hex": vout.get("scriptPubKey", {}).get("hex", "")[:20],
                })
            # Check if it's a v4 RUNG_TX
            if raw.get("version") == 4:
                tx_entry["is_ladder"] = True
                # Try to get conditions_root from scriptPubKey
                for vout in raw.get("vout", []):
                    spk = vout.get("scriptPubKey", {}).get("hex", "")
                    if spk.startswith("df") and len(spk) >= 66:
                        tx_entry["conditions_root"] = spk[2:66]
                        break
            txs.append(tx_entry)
        except Exception:
            txs.append({"txid": txid, "error": "decode failed"})
    return {"count": len(txids), "txs": txs}


@app.get("/api/ladder/blocks/recent")
async def blocks_recent():
    """Get the 5 most recent blocks."""
    height = await rpc_call("getblockcount")
    blocks = []
    for h in range(height, max(height - 5, -1), -1):
        block_hash = await rpc_call("getblockhash", [h])
        block = await rpc_call("getblock", [block_hash, 1])
        blocks.append({
            "height": block.get("height"),
            "hash": block.get("hash"),
            "time": block.get("time"),
            "tx_count": len(block.get("tx", [])),
            "size": block.get("size"),
            "txids": block.get("tx", []),
        })
    return blocks


@app.post("/api/ladder/pq/keypair")
async def pq_keypair(request: Request):
    """Generate a post-quantum keypair for the specified scheme."""
    body = await request.body()
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}

    scheme = data.get("scheme", "FALCON512")
    valid_schemes = {"FALCON512", "FALCON1024", "DILITHIUM3", "SPHINCS_SHA"}
    if scheme not in valid_schemes:
        raise HTTPException(400, f"Invalid PQ scheme. Use one of: {', '.join(sorted(valid_schemes))}")

    result = await rpc_call("generatepqkeypair", [scheme])
    # Compute pubkey_commit (SHA-256 of raw pubkey bytes)
    pubkey_hex = result.get("pubkey", "")
    if pubkey_hex:
        commit = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()
        result["pubkey_commit"] = commit
    return result


def _ripemd160(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160 (OpenSSL 3.x disabled legacy hashes)."""
    # Constants
    _f = [lambda x, y, z: x ^ y ^ z, lambda x, y, z: (x & y) | (~x & z),
          lambda x, y, z: (x | ~y) ^ z, lambda x, y, z: (x & z) | (y & ~z),
          lambda x, y, z: x ^ (y | ~z)]
    _K1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    _K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    _R1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
           3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
           4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    _R2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
           15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
           12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    _S1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
           11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
           9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    _S2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
           9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
           8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    M = 0xFFFFFFFF
    rl = lambda v, n: ((v << n) | (v >> (32 - n))) & M
    msg = bytearray(data)
    l = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', l)
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16L', msg[i:i+64]))
        a1, b1, c1, d1, e1 = h0, h1, h2, h3, h4
        a2, b2, c2, d2, e2 = h0, h1, h2, h3, h4
        for j in range(80):
            rnd = j >> 4
            t = (a1 + _f[rnd](b1, c1, d1) + X[_R1[j]] + _K1[rnd]) & M
            t = (rl(t, _S1[j]) + e1) & M
            a1, e1, d1, c1, b1 = e1, d1, rl(c1, 10), b1, t
            t = (a2 + _f[4 - rnd](b2, c2, d2) + X[_R2[j]] + _K2[rnd]) & M
            t = (rl(t, _S2[j]) + e2) & M
            a2, e2, d2, c2, b2 = e2, d2, rl(c2, 10), b2, t
        t = (h1 + c1 + d2) & M
        h1 = (h2 + d1 + e2) & M
        h2 = (h3 + e1 + a2) & M
        h3 = (h4 + a1 + b2) & M
        h4 = (h0 + b1 + c2) & M
        h0 = t
    return struct.pack('<5L', h0, h1, h2, h3, h4)


@app.get("/api/ladder/preimage")
async def generate_preimage():
    """Generate a random 32-byte preimage and return its SHA256 and HASH160 hashes."""
    preimage = os.urandom(32)
    sha256_hash = hashlib.sha256(preimage).digest()
    hash160 = _ripemd160(sha256_hash)
    return {
        "preimage": preimage.hex(),
        "sha256": sha256_hash.hex(),
        "hash160": hash160.hex(),
    }


@app.post("/api/ladder/ctv-hash")
async def compute_ctv_hash(request: Request):
    """Compute BIP-119 CTV template hash for a v4 RUNG_TX spending transaction."""
    body = await request.body()
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")

    hex_str = data.get("hex", "")
    input_index = int(data.get("input_index", 0))

    if not hex_str or not all(c in "0123456789abcdefABCDEF" for c in hex_str):
        raise HTTPException(400, "Invalid hex")

    result = await rpc_call("computectvhash", [hex_str, input_index])
    return result


@app.post("/api/ladder/mine")
async def mine_blocks(request: Request):
    """Mine blocks on regtest (for local testing only)."""
    body = await request.body()
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}

    n_blocks = min(int(data.get("blocks", 1)), 200)  # cap at 200 for CSV satisfaction
    address = data.get("address", "")

    if not address:
        address = await rpc_call("getnewaddress", ["", "bech32"])

    hashes = []
    for _ in range(n_blocks):
        batch = await rpc_call("generatetoaddress", [1, address, 100_000_000])
        if not batch:
            break
        hashes.extend(batch)
    result = hashes
    return {"blocks_mined": len(result), "hashes": result}


# --- Analytics endpoints ---


@app.post("/api/ladder/analytics/visit")
async def record_visit(request: Request):
    """Record a page visit for telemetry."""
    body = await request.body()
    if len(body) > 4096:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    page = str(data.get("page", "/"))[:200]
    referrer = str(data.get("referrer", ""))[:500]
    ip = request.headers.get("X-Real-IP", request.client.host)
    ua = str(request.headers.get("User-Agent", ""))[:300]

    conn = sqlite3.connect(ANALYTICS_DB)
    conn.execute(
        "INSERT INTO visits (page, ip_hash, ts, referrer, ua) VALUES (?, ?, ?, ?, ?)",
        (page, _hash_ip(ip), time.time(), referrer, ua),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/ladder/analytics/stats")
async def analytics_stats():
    """Return aggregated visit and broadcast statistics."""
    conn = sqlite3.connect(ANALYTICS_DB)
    now = time.time()
    day_ago = now - 86400
    week_ago = now - 604800

    # Per-page totals (all time)
    pages = conn.execute(
        "SELECT page, COUNT(*) as views, COUNT(DISTINCT ip_hash) as uniques "
        "FROM visits GROUP BY page ORDER BY views DESC"
    ).fetchall()

    # Per-page today
    pages_today = conn.execute(
        "SELECT page, COUNT(*) as views, COUNT(DISTINCT ip_hash) as uniques "
        "FROM visits WHERE ts > ? GROUP BY page ORDER BY views DESC",
        (day_ago,),
    ).fetchall()

    # Totals
    total = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT ip_hash) FROM visits"
    ).fetchone()
    total_today = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT ip_hash) FROM visits WHERE ts > ?",
        (day_ago,),
    ).fetchone()
    total_week = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT ip_hash) FROM visits WHERE ts > ?",
        (week_ago,),
    ).fetchone()

    # Recent visits (last 30)
    recent = conn.execute(
        "SELECT page, ip_hash, ts, referrer FROM visits ORDER BY ts DESC LIMIT 30"
    ).fetchall()

    # Broadcast stats
    bc_total = conn.execute("SELECT COUNT(*) FROM broadcasts").fetchone()[0]
    bc_today = conn.execute(
        "SELECT COUNT(*) FROM broadcasts WHERE ts > ?", (day_ago,)
    ).fetchone()[0]
    bc_week = conn.execute(
        "SELECT COUNT(*) FROM broadcasts WHERE ts > ?", (week_ago,)
    ).fetchone()[0]
    bc_recent = conn.execute(
        "SELECT txid, ts, tx_size FROM broadcasts ORDER BY ts DESC LIMIT 20"
    ).fetchall()

    conn.close()

    return {
        "pages": [{"page": p, "views": v, "uniques": u} for p, v, u in pages],
        "pages_today": [{"page": p, "views": v, "uniques": u} for p, v, u in pages_today],
        "total_views": total[0],
        "total_uniques": total[1],
        "today_views": total_today[0],
        "today_uniques": total_today[1],
        "week_views": total_week[0],
        "week_uniques": total_week[1],
        "recent_visits": [
            {"page": p, "ip_hash": h, "ts": t, "referrer": r}
            for p, h, t, r in recent
        ],
        "broadcasts": {
            "total": bc_total,
            "today": bc_today,
            "week": bc_week,
            "recent": [
                {"txid": tx, "ts": t, "size": s}
                for tx, t, s in bc_recent
            ],
        },
    }




# ============================================================================
# QABI endpoints — added for QABIO live testing. See
# contrib/qabi/ladder_proxy_qabi_endpoints.py in bitcoin-core-ladder for the
# canonical upstream copy (version-controlled in the main repo).
# ============================================================================

_QABI_MAX_JSON = 262_144      # 256 KB
_QABI_MAX_HEX  = 524_288      # 512 KB hex ≈ 256 KB binary


def _qabi_parse_json(body: bytes, max_size: int = _QABI_MAX_JSON):
    if len(body) > max_size:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")
    if not isinstance(data, dict):
        raise HTTPException(400, "Request must be a JSON object.")
    return data


def _qabi_require_str(d, key, name=None, max_len=_QABI_MAX_HEX):
    v = d.get(key)
    if not isinstance(v, str):
        raise HTTPException(400, f"Missing or invalid '{key}' string.")
    if len(v) > max_len:
        raise HTTPException(400, f"{name or key} too large.")
    return v


def _qabi_require_int(d, key, min_val=None, max_val=None):
    v = d.get(key)
    if not isinstance(v, int) or isinstance(v, bool):
        raise HTTPException(400, f"Missing or invalid '{key}' integer.")
    if min_val is not None and v < min_val:
        raise HTTPException(400, f"'{key}' below minimum.")
    if max_val is not None and v > max_val:
        raise HTTPException(400, f"'{key}' above maximum.")
    return v


@app.post("/api/ladder/qabi/authchain")
async def qabi_authchain_ep(request: Request):
    body = await request.body()
    data = _qabi_parse_json(body)
    auth_seed = _qabi_require_str(data, "auth_seed", max_len=64)
    chain_length = _qabi_require_int(data, "chain_length",
                                      min_val=1, max_val=200_000)
    params = [auth_seed, chain_length]
    if "depth" in data:
        depth = _qabi_require_int(data, "depth",
                                   min_val=0, max_val=chain_length)
        params.append(depth)
    return await rpc_call("qabi_authchain", params)


@app.post("/api/ladder/qabi/buildblock")
async def qabi_buildblock_ep(request: Request):
    body = await request.body()
    data = _qabi_parse_json(body)
    coord_pk    = _qabi_require_str(data, "coordinator_pubkey", max_len=1800)
    expiry      = _qabi_require_int(data, "prime_expiry_height", min_val=0)
    batch_id    = _qabi_require_str(data, "batch_id", max_len=64)
    entries     = data.get("entries")
    # RPC signature: qabi_buildblock(coord, expiry, batch_id, entries,
    #   outputs_conditions_root, output_values)
    # Accept either split fields or legacy "outputs" array of root strings.
    ocr = data.get("outputs_conditions_root")
    ov  = data.get("output_values")
    outputs = data.get("outputs")
    if not isinstance(entries, list) or len(entries) == 0:
        raise HTTPException(400, "Missing or invalid 'entries' array.")
    if ocr and ov:
        params = [coord_pk, expiry, batch_id, entries, ocr, ov]
    elif isinstance(outputs, list) and len(outputs) > 0:
        params = [coord_pk, expiry, batch_id, entries, outputs[0],
                  [e["contribution"] for e in entries]]
    else:
        raise HTTPException(400, "Missing outputs_conditions_root + output_values (or legacy 'outputs').")
    return await rpc_call("qabi_buildblock", params)


@app.post("/api/ladder/qabi/blockinfo")
async def qabi_blockinfo_ep(request: Request):
    body = await request.body()
    data = _qabi_parse_json(body)
    qabi_block = _qabi_require_str(data, "qabi_block")
    return await rpc_call("qabi_blockinfo", [qabi_block])


@app.post("/api/ladder/qabi/sighash")
async def qabi_sighash_ep(request: Request):
    body = await request.body()
    data = _qabi_parse_json(body)
    hex_tx = _qabi_require_str(data, "hex")
    return await rpc_call("qabi_sighash", [hex_tx])


@app.post("/api/ladder/qabi/signqabo")
async def qabi_signqabo_ep(request: Request):
    body = await request.body()
    data = _qabi_parse_json(body)
    hex_tx  = _qabi_require_str(data, "hex")
    privkey = _qabi_require_str(data, "privkey", max_len=8192)
    return await rpc_call("qabi_signqabo", [hex_tx, privkey])


@app.get("/api/ladder/qabi/info")
async def qabi_info_ep():
    return {
        "scheme": "FALCON-512",
        "pubkey_size": 897,
        "sig_size": 666,
        "block_max_soft": 65_536,
        "block_max_hard": 262_144,
        "standard_relay_max_N": 618,
        "single_block_max_N": 3500,
        "bytes_per_input": 432,
        "vbytes_per_input": 162,
    }


# --- Entry point ---

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT)
