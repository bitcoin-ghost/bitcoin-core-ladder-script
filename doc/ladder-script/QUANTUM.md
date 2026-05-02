# Quantum Resistance in Ladder Script

How RUNG_TX transactions protect against quantum computers, what's safe,
what isn't, and how to migrate.

## The Threat

No quantum computer capable of breaking elliptic curve cryptography exists
today. However, advances in quantum computing may make this possible in the
future. Shor's algorithm, if run on a sufficiently powerful quantum computer,
could theoretically derive an elliptic curve private key from a public key.

If that day comes, Bitcoin transactions that expose public keys would be
vulnerable in two ways:

1. **On-chain in the output** (P2PK, Taproot key-path) — the pubkey sits in the
   UTXO set. An attacker could crack it at leisure before you spend.
2. **In the witness at spend time** (P2PKH, P2WPKH, P2WSH) — the pubkey is
   revealed when you broadcast the spending transaction. An attacker would need
   to crack it before the transaction confirms.

Address reuse makes (2) worse: once you spend from an address, the pubkey is
known, and any other UTXOs at the same address are vulnerable.

## How Ladder Script Protects Against Quantum

### Script-path + PQ scheme: SAFE

When you use a post-quantum signature scheme (FALCON-512, FALCON-1024,
Dilithium3, or SPHINCS+) with script-path spending:

- The `conditions_root` on-chain is a **Merkle hash**, not a public key.
  A quantum attacker cannot derive anything useful from it.
- The PQ public key is folded into the Merkle leaf via `merkle_pub_key` —
  it's hashed, never stored in conditions. It does not appear on-chain
  until you spend.
- At spend time, the PQ pubkey is revealed in the witness alongside a PQ
  signature. The PQ signature scheme is designed to resist quantum attack —
  a quantum computer cannot forge the signature or derive the private key.
- The spending transaction enters the mempool and confirms. Even if a
  quantum attacker sees the revealed PQ pubkey, they cannot forge a
  competing spend.

**This is fully quantum-safe.** The pubkey is hidden until spend time,
and the signature scheme resists quantum attack.

### Key-path: NOT quantum-safe

Key-path spending treats the `conditions_root` as an x-only EC public key.
This key sits on-chain in the UTXO set. A quantum attacker can:

1. Read the EC pubkey from the UTXO
2. Derive the private key using Shor's algorithm
3. Forge a Schnorr signature and steal the funds

Key-path is Schnorr-only by design (64-byte signature, `SignatureHashLadderKeyPath`).
PQ signatures cannot be used with key-path — they are too large and use a
different verification path.

**Key-path is not quantum-safe.** This is the same vulnerability as Taproot
key-path outputs in Bitcoin today.

### Auto-tweak behaviour

When `createrungtx` detects a single-SIG rung, it automatically tweaks the
output to enable key-path spending:
`conditions_root = internal_pubkey + H("LadderTweak/v1", pubkey || merkle_root) × G`

For PQ schemes, the pubkey is larger than 32 bytes (e.g. 897 bytes for
FALCON-512). The tweak function requires exactly 32 bytes and rejects PQ
keys — the auto-tweak **falls back** to using the raw Merkle root
as the conditions_root. This means:

- **PQ outputs are never auto-tweaked.** The conditions_root is always a
  hash, never an EC pubkey.
- **Key-path spending is automatically disabled** for PQ outputs.
- **No code change is needed** to get quantum protection — just set the
  scheme to a PQ scheme and the system does the right thing.

## Supported PQ Schemes

| Scheme | Code | Pubkey | Signature (max) | Security Level |
|--------|------|--------|-----------------|----------------|
| FALCON-512 | `0x10` | 897 B | variable, up to 666 B | 128-bit PQ |
| FALCON-1024 | `0x11` | 1,793 B | variable, up to 1,280 B | 256-bit PQ |
| Dilithium3 | `0x12` | 1,952 B | 3,293 B (fixed) | 192-bit PQ |
| SPHINCS+-SHA2-256f | `0x13` | 64 B | 49,216 B (fixed) | 256-bit PQ |

FALCON signatures are variable-length up to the per-scheme maximum
(the upper bound is enforced by `signrungtx` and the evaluator);
Dilithium3 and SPHINCS+ are fixed-length. All schemes are verified
via liboqs, which is a **hard build dependency** — `find_package(liboqs
REQUIRED)` in `src/rung/CMakeLists.txt` — to keep every node on the
same consensus rules. A node built without liboqs would fail to link.

Set the SCHEME field to any PQ code and the same SIG block handles
verification. Works with SIG, MULTISIG, TIMELOCKED_SIG, CLTV_SIG,
TIMELOCKED_MULTISIG, and KEY_REF_SIG.

## Address Reuse

Address reuse is dangerous regardless of signature scheme:

- If you spend from a script-path output, the pubkey is revealed in that
  transaction's witness.
- If you have other UTXOs with the same `conditions_root`, they share the
  same Merkle tree and the same pubkeys.
- For **EC schemes** (Schnorr, ECDSA): the revealed EC pubkey is vulnerable
  to quantum attack on the remaining UTXOs. This is the dangerous case.
- For **PQ schemes**: the revealed PQ pubkey does NOT compromise the
  remaining UTXOs. A quantum attacker who sees a FALCON-512 pubkey still
  cannot derive the private key — that is the entire point of post-quantum
  cryptography. The remaining outputs are still fully protected. The only
  cost is privacy (the revealed pubkey links the outputs).

**This means batch PQ outputs are safe to spend incrementally.** Create 100
outputs sharing one PQ-protected conditions root. Spend them one at a time.
Each spend reveals the PQ pubkey in the witness, but the other 99 outputs
remain quantum-safe because the PQ scheme resists key recovery.

For EC schemes, avoid address reuse. For PQ schemes, address reuse is
cryptographically safe — only a privacy consideration.

## Migration Path

The migration from classical to post-quantum is straightforward:

1. **Today (no quantum threat):** use key-path spending (110 vB, cheapest).
   The EC pubkey is on-chain but quantum computers don't exist yet.

2. **Transition (quantum threat emerging):** switch new outputs to
   script-path with a PQ scheme. Existing key-path UTXOs should be swept
   to PQ outputs before quantum computers can crack them. Use a two-rung
   ladder: rung 0 with Schnorr (cheap, pre-quantum), rung 1 with FALCON-512
   (quantum-safe fallback).

3. **Post-quantum (quantum computers operational):** all outputs use PQ
   schemes. Key-path spending is abandoned. Script-path overhead at the
   per-scheme upper bound: FALCON-512 ~666 B sig + 897 B pubkey;
   FALCON-1024 ~1,280 B + 1,793 B; Dilithium3 3,293 B + 1,952 B;
   SPHINCS+-SHA2-256f 49,216 B + 64 B.

No consensus change is needed for any of these transitions. The SCHEME
field routes to the correct verifier at evaluation time. All 6 schemes
(2 classical + 4 PQ) coexist in the same transaction format.

## Hybrid Approach (Recommended)

A two-rung ladder gives you the best of both worlds:

```
ladder(or(
  sig(@classical_key),
  sig(@pq_key, falcon512)
))
```

- **Rung 0:** Schnorr signature. Cheap (110 vB key-path or 124 vB script-path).
  Use this while quantum computers don't exist.
- **Rung 1:** FALCON-512 signature. Quantum-safe. Larger witness
  (variable, up to 666 B sig + 897 B pubkey) but protects against
  quantum attack.

If quantum computers become a threat, stop using rung 0 and spend via rung 1.
The output is protected from day one — the PQ key is committed in the Merkle
tree at creation time, hidden behind its leaf hash. An attacker who cracks the
EC key from rung 0 cannot access the PQ key from rung 1 (it's a different
Merkle leaf with different conditions).

This hybrid approach means you don't need to predict when quantum computers
will arrive. Create outputs with both paths today. Spend via the cheap
classical path until it's no longer safe, then switch to the PQ path.

## Batch Quantum Protection

A RUNG_TX shares one `conditions_root` across all outputs. This means a single
PQ-protected condition tree covers every output in the transaction:

```
ladder(output(0, sig(@pq_key, falcon512)),
       output(1, sig(@pq_key, falcon512)),
       output(2, sig(@pq_key, falcon512)))
```

100 outputs, one Merkle tree, one PQ pubkey commitment. The PQ pubkey (897 bytes
for FALCON-512) is hashed into the Merkle leaf once — not stored per output. Each
output is just 8 bytes on the wire. The UTXO cost is ~8 bytes per output regardless
of the signature scheme.

When spending, each input reveals the PQ pubkey and provides a PQ signature in the
witness. But the creation cost is flat: one tree, one creation proof, one root.

This is unique to Ladder Script. In legacy Bitcoin, each output carries its own
scriptPubKey and would need its own PQ commitment. In a RUNG_TX, the shared root
amortises the PQ overhead across all outputs — making batch PQ payments practical
even with large PQ pubkeys.

Combined with the hybrid approach, you can batch-create 100 outputs that are each
spendable via cheap Schnorr today or quantum-safe FALCON-512 in the future, all
from one compact transaction.
