# Ladder Script

Ladder Script replaces Bitcoin Script with 62 typed function blocks. Instead of
an untyped stack machine, every spending condition is a named block with declared
fields. Blocks are grouped into rungs (AND — all must pass) and ladders (OR —
first satisfied rung wins). Every byte in a transaction belongs to one of 11 typed
fields with enforced size constraints.

A version 4 transaction (`RUNG_TX`) carries a single shared Merkle root covering
all outputs. Each output is 8 bytes on the wire (value only). The full spending
conditions are committed in the Merkle tree and revealed only at spend time — the
unrevealed paths stay private. This is Merkelised Ladder Script Conditions (MLSC).

Based on Bitcoin Core v30.0.

## Why Use It

**Smallest transactions in Bitcoin.** A key-path payment is 119 vB — cheaper than
P2WPKH (143 vB), P2TR (157 vB), and P2PKH (226 vB). Script-path is 140 vB, still
beating every legacy type. Full lifecycle (create + spend) is 6% cheaper than P2WPKH.

**Smallest UTXO footprint ever.** Each output costs ~8 bytes in the UTXO set versus
~29 for P2WPKH and ~41 for P2TR. A 100-output batch payment is 914 vB — 71% cheaper
than P2WPKH. The MLSC scriptPubKey compresses to a single byte; the conditions root
is stored once per transaction via a synthetic UTXO entry.

**Inscriptions are structurally impossible.** Every byte must belong to a typed field.
There is no contiguous data block in a RUNG_TX. The total user-chosen arbitrary data
surface is 112 bytes per transaction, flat, regardless of how many outputs you create.
Fail-closed deserialisation rejects unknown types, unknown fields, and trailing bytes.

**Privacy by default.** When you spend via one rung, only that rung's conditions are
revealed. Every other spending path stays hidden behind its Merkle leaf hash. An observer
sees how many paths exist but not what they contain.

**Post-quantum ready.** Swap the SCHEME field to FALCON-512, FALCON-1024, Dilithium3,
or SPHINCS+ and the same transaction structure works with quantum-resistant signatures.
No new opcodes, no new transaction format — just a different scheme byte.

**Native covenants and state machines.** CTV template verification, recursive covenants
(RECURSE_SAME, RECURSE_MODIFIED, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY,
RECURSE_UNTIL), vaults with clawback (VAULT_LOCK), rate limiters, latches, counters,
sequencers, and cross-input constraints (COSIGN) — all as single typed blocks, not
fragile opcode sequences.

**ANYPREVOUT for payment channels.** BIP-118 analogue sighash flags (0x40, 0xC0) enable
LN-Symmetry/eltoo-style channels where the latest state simply replaces any older state.

**Half-aggregated Schnorr signatures.** The AGGREGATE attestation mode collects each
input's R-value in the witness and verifies a single shared s-value at the transaction
level, reducing multi-input transaction size.

## How It Works

A **ladder** is a set of spending paths. Each path is a **rung** of one or more
**blocks**. A SIG block checks a signature. A CSV block checks a relative timelock.
An HTLC block checks a hash preimage + timelock + signature in one block. You combine
them with AND logic within a rung, and OR logic across rungs.

Public keys are folded into the Merkle leaf hash (`merkle_pub_key`) rather than stored
in the on-chain conditions. This eliminates the writable surface that inscriptions exploit
in Taproot. Key-consuming blocks are never invertible — you cannot embed arbitrary data
by providing a garbage pubkey and inverting the result.

Transactions with 3 or more spendable outputs include a creation proof in the witness,
binding each output to the shared condition tree and preventing UTXO spam.
