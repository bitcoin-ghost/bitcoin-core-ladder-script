# Independent v4 RUNG_TX verifier (Python)

A pure-Python, zero-dependency, stateless re-implementation of the
consensus-critical v4 RUNG_TX commitments. The goal is **existence**, not
feature parity — to demonstrate that a second implementer reading only the
BIP draft and the wire-format documentation can reproduce the same
byte-level conditions root that the reference C++ implementation
produces.

## Scope

| Subsystem                                   | Status    |
| ------------------------------------------- | --------- |
| 0xDF MLSC `scriptPubKey` parser             | Done      |
| v4 wire-format reader                       | Done      |
| TX_MLSC leaf hash (`LadderLeaf/v1`)         | Done      |
| Merkle tree (`LadderInternal/v1`)           | Done      |
| No-pubkey single-rung leaf                  | Done      |
| Single-pubkey single-rung leaf              | Done      |
| Sig family (SIG, ADAPTOR_SIG, MUSIG_THRESHOLD) | Done   |
| Timelock family (CSV, CLTV, _TIME)          | Done      |
| Compound sig (TIMELOCKED_SIG, HASH_SIG, CLTV_SIG) | Done |
| Anchor family (ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE) | Done |
| Covenant family (AMOUNT_LOCK, CTV)          | Done      |
| Hash family (TAGGED_HASH, HASH_GUARDED)     | Done      |
| Recursion family (RECURSE_SAME, _UNTIL, _COUNT, _SPLIT) | Done |
| PLC family (TIMER_*, COUNTER_*, LATCH_SET, HYSTERESIS_*, RATE_LIMIT, SEQUENCER, COMPARE) | Done |
| Governance (WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, EPOCH_GATE, RELATIVE_VALUE) | Done |
| PTLC                                        | Done      |
| MULTISIG inner-Merkle                       | Done      |
| TIMELOCKED_MULTISIG inner-Merkle            | Done      |
| Two-pubkey leaf (HTLC, ANCHOR_FEE, VAULT_LOCK) | Done   |
| Legacy P2PK / P2PKH / P2WPKH / P2TR         | Done      |
| OUTPUT_CHECK, KEY_REF_SIG                   | Done      |
| RECURSE_MODIFIED / RECURSE_DECAY headers    | Done      |
| QABI_PRIME header                           | Done      |
| BIP-341 key-path tweak                      | TODO      |
| Sighash computation                         | TODO      |
| Schnorr signature verification              | TODO      |
| Legacy P2SH / P2WSH / P2TR_SCRIPT (script-bearing) | TODO |
| ACCUMULATOR, COSIGN, DATA_RETURN+SIG, OUTPUT_CHECK compound | TODO |
| QABI_SPEND, PQ_BATCH                        | TODO      |

Coverage as of 2026-05-04: **60 / 68** committed positive vectors
verified byte-for-byte against the reference C++ implementation, across
**45 distinct block types** including HTLC, MULTISIG (with inner
pubkey-Merkle), TIMELOCKED_MULTISIG, ANCHOR_FEE, VAULT_LOCK, and
P2PK/P2PKH/P2WPKH/P2TR legacy wrappers. Anything still in TODO or
Out-of-scope is left for follow-on iterations.

## Layout

```
tools/independent-impl/
├── README.md                            (this file)
├── ladder_verify.py                     ~280 lines, no deps
└── tests/
    └── test_against_vectors.py          consumes the committed JSON fixtures
```

## Running

```sh
python3 tools/independent-impl/ladder_verify.py            # smoke
python3 tools/independent-impl/tests/test_against_vectors.py
```

The test consumes `src/test/data/rung_tx_vectors.json` directly, so it
inherits all 68 committed positive vectors automatically. Vectors whose
block shapes the verifier doesn't yet support are reported as
out-of-scope (not failures); supported shapes must reproduce the
committed `merkle_root` byte-for-byte.

## Endianness

`uint256::GetHex()` in Bitcoin Core returns reversed bytes (txid
convention). The verifier works in wire order throughout and the test
helper `_u256_from_rpc_hex()` undoes the reversal when comparing
against JSON fields.

## Reference points in the C++ tree

| Concept                  | File                                |
| ------------------------ | ----------------------------------- |
| Tagged hash domains      | `src/rung/conditions.cpp:225-251`   |
| Structural template      | `src/rung/conditions.cpp:1263`      |
| Value commitment         | `src/rung/conditions.cpp:1358`      |
| Leaf hash                | `src/rung/conditions.cpp:1299`      |
| Merkle tree              | `src/rung/conditions.cpp:423`       |
| Sorted-pair interior     | `src/rung/conditions.cpp:398`       |
| Block-type enum          | `src/rung/types.h:130-185`          |
| Data-type enum           | `src/rung/types.h:580-`             |
| Conditions-root entry    | `src/rung/block_helpers.cpp:404`    |
| BIP-341 tweak            | `src/rung/conditions.cpp:677`       |
| v4 wire format           | `src/primitives/transaction.h:218`  |

## Why this matters

Activation gate component 7 ("independent implementation") is the
empirical evidence that a reviewer doesn't have to take the reference
implementation's word for the spec. If two implementations written from
the same documentation produce the same bytes, the documentation is
actually a specification.

Adding a SECOND independent implementation in a different language
(Rust would be the natural next step) would strengthen this further,
but a single second implementation already moves the gate from "no
evidence" to "minimal evidence".
