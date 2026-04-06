# Ladder Script Possibilities

What Ladder Script enables that Bitcoin Script cannot. Each example uses actual block types
from the 62 active types. All patterns compose freely within the AND/OR rung/ladder model.

## Vaults with Clawback

A vault that allows hot-key spending after a delay, with cold-key clawback at any time.

**Block types:** VAULT_LOCK (0x0302), SIG (0x0001)

Rung 0: `VAULT_LOCK` with hot-key and cold-key pubkeys, plus a delay parameter. The hot
key can spend after the delay; the cold key can claw back immediately.

Rung 1: `SIG` with the cold key for emergency recovery.

In Bitcoin Script, vaults require pre-signed transactions or CTV. Ladder Script makes vaults
a single native block type with built-in clawback.

## Rate-Limited Wallets

A wallet that limits spending to N satoshis per block period, with a refill mechanism.

**Block types:** RATE_LIMIT (0x0671), SIG (0x0001), RECURSE_SAME (0x0401)

A rung combines `SIG` (authorisation), `RATE_LIMIT` (spending cap), and `RECURSE_SAME`
(re-encumber the change output with the same conditions). The RATE_LIMIT block tracks
accumulated spending and enforces the cap. RECURSE_SAME ensures the rate limit persists
across transactions.

## Covenant Chains

Outputs that constrain the spending transaction to create specific successor outputs.

**Block types:** CTV (0x0301), RECURSE_MODIFIED (0x0402), RECURSE_COUNT (0x0404)

CTV commits to a template hash (BIP-119) that fixes the spending transaction's outputs.
RECURSE_MODIFIED allows a single mutation per hop (e.g., decrementing a counter).
RECURSE_COUNT creates a countdown that terminates after N hops. These compose into chains
of constrained transactions with deterministic state progression.

## ANYPREVOUT Channels (LN-Symmetry / Eltoo)

Payment channels where either party can close with the latest state, without penalty
transactions.

**Block types:** SIG (0x0001) with ANYPREVOUT sighash (0x40)

ANYPREVOUT allows signatures to rebind to any prevout with matching amounts and conditions.
This enables the LN-Symmetry (eltoo) protocol: each new state is signed with ANYPREVOUT,
and the latest state can always replace an older one without needing a justice transaction.

## OUTPUT_CHECK Governance

DAO-style spending rules where outputs must meet specific value and script constraints.

**Block types:** OUTPUT_CHECK (0x0807), MULTISIG (0x0002), EPOCH_GATE (0x0801)

OUTPUT_CHECK enforces that a specific output index has a value within bounds and a script
matching a committed hash. Combined with MULTISIG for authorisation and EPOCH_GATE for
periodic voting windows, this creates on-chain governance where funds can only move to
approved destinations in approved amounts during approved periods.

## Post-Quantum Safe Migration

Migrate existing funds to PQ-safe spending conditions in preparation for potential future
advances in quantum computing.

**Block types:** SIG (0x0001) with SPHINCS_SHA scheme (0x13), TIMELOCKED_SIG (0x0701)

Rung 0: `SIG` with a SPHINCS+ key (49KB signatures, but quantum-safe). Immediate spending.

Rung 1: `TIMELOCKED_SIG` with a Schnorr key and a CSV delay. Fallback if PQ key is lost.

The SCHEME field allows Schnorr and PQ signatures to coexist in the same ladder. Wallets
can migrate incrementally by creating new outputs with PQ-safe rungs while keeping a
Schnorr fallback.

## Recursive Covenants

Outputs that re-encumber themselves with modified conditions, creating state machines.

**Block types:** RECURSE_SAME (0x0401), RECURSE_MODIFIED (0x0402), RECURSE_UNTIL (0x0403),
RECURSE_SPLIT (0x0405), RECURSE_DECAY (0x0406)

RECURSE_SAME creates outputs with identical conditions. RECURSE_MODIFIED allows one
parameter to change per hop. RECURSE_UNTIL terminates at a block height. RECURSE_SPLIT
divides value across multiple outputs. RECURSE_DECAY reduces a parameter over time.

These enable congestion control trees (RECURSE_SPLIT), time-bounded subscriptions
(RECURSE_UNTIL), and decaying multisig thresholds (RECURSE_DECAY + RECURSE_MODIFIED).

## Cross-Input Dependencies (COSIGN)

Require multiple inputs in the same transaction to be spent together.

**Block types:** COSIGN (0x0681), SIG (0x0001)

COSIGN requires another input with matching conditions (identified by HASH256). This
enables atomic multi-UTXO operations: both inputs must be spent in the same transaction
or neither can be spent. Unlike Bitcoin Script's SIGHASH_ALL (which only commits to
outputs), COSIGN creates an explicit cross-input dependency at the conditions level.

## Stateful PLC Logic

Industrial control patterns for Bitcoin: timers, counters, latches, and sequencers.

**Block types:** COUNTER_UP (0x0633), LATCH_SET (0x0621), SEQUENCER (0x0651),
TIMER_CONTINUOUS (0x0611), COMPARE (0x0641), RECURSE_SAME (0x0401)

A COUNTER_UP block incremented by a designated key, combined with RECURSE_SAME to persist
state. When the counter reaches the target, COMPARE enables the next step. LATCH_SET
provides irreversible state activation. SEQUENCER enforces ordered multi-step workflows.
TIMER_CONTINUOUS requires a minimum number of consecutive blocks between steps.

These patterns enable escrow release after N approvals, multi-phase contract execution,
and time-delayed state transitions, all as native block types rather than simulated through
Script opcodes.

## Atomic Swaps and HTLCs

Hash-locked payments for cross-chain atomic swaps and Lightning Network.

**Block types:** HTLC (0x0702), PTLC (0x0704), HASH_SIG (0x0703)

HTLC combines hash verification, timelock, and signature in a single block. PTLC uses
adaptor signatures instead of hash preimages (point-locked contracts). HASH_SIG provides
hash-locked signatures without a timelock. In Bitcoin Script, each of these requires
multi-opcode templates. In Ladder Script, they are single blocks with typed fields.

## Accumulator-Based Access Control

Dynamically managed allowlists and blocklists using Merkle accumulators.

**Block types:** ACCUMULATOR (0x0806), SIG (0x0001)

ACCUMULATOR verifies set membership via a Merkle proof against a committed root. Combined
with inversion (`!ACCUMULATOR`), it becomes a blocklist. The Merkle root can be updated
via RECURSE_MODIFIED, enabling dynamic addition and removal of authorised parties without
recreating the output. Capped at 10 HASH256 fields (root + 8 proof nodes + leaf).
