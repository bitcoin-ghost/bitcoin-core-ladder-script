// Copyright (c) 2026 The Ladder Script developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_QABI_H
#define BITCOIN_RUNG_QABI_H

// QABIO (BIP-YYYY) is a separable soft-fork extension to Ladder Script.
// All types and functions declared in this header are gated on the
// ENABLE_QABIO compile-time flag. When the flag is off, this header
// expands to an empty translation unit and any caller that tries to
// reference a QABIO symbol is caught by the compiler. Every QABIO call
// site in the rest of the codebase must therefore be wrapped in its
// own `#ifdef ENABLE_QABIO` guard. See src/rung/CMakeLists.txt for the
// option definition.
#ifdef ENABLE_QABIO

#include <primitives/transaction.h>
#include <rung/types.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rung {

//! Current QABIBlock wire format version.
static constexpr uint8_t QABI_BLOCK_VERSION_CURRENT = 0x01;

//! Exact size of a FALCON-512 public key (bytes).
static constexpr size_t QABI_COORDINATOR_PUBKEY_SIZE = 897;

//! Exact size of a FALCON-512 signature (bytes).
static constexpr size_t QABI_AGGREGATED_SIG_MAX = 666;

//! Soft cap on the serialised QABIBlock size (standard relay).
//! 64 KB supports ~400-participant batches with standard destinations.
static constexpr size_t QABI_BLOCK_MAX_SOFT = 65536;

//! Hard cap on the serialised QABIBlock size (consensus).
//! 256 KB supports ~1600-participant batches; beyond this a future
//! block version with Merkle-committed entries will be required.
static constexpr size_t QABI_BLOCK_MAX_HARD = 262144;

//! Default length of a UTXO's auth hash chain.
//! 20,000 depths supports ~10,000 clean batches per UTXO.
static constexpr uint32_t QABI_AUTH_CHAIN_DEFAULT_LENGTH = 20000;

/** One entry in a QABIBlock — a single participant's contribution. */
struct QABIEntry
{
    //! SHA256 of the participant's Rung 0 FALCON public key (stable identity).
    uint256 participant_id;

    //! How much this participant contributes to the batch (sats).
    int64_t contribution{0};

    //! Index into QABIBlock::outputs for this participant's destination.
    uint32_t destination_index{0};
};

/** Tx-level structured data describing a QABIO batch. Carried in
 *  tx.qabi_block (serialised). QABI_ROOT = SHA256(canonical_serialise(block)).
 *
 *  Output binding (post-dedup design):
 *  ----------------------------------
 *  Participants do NOT commit to per-output scriptPubKeys. They commit to a
 *  single shared `outputs_conditions_root` and a vector of per-output values.
 *  At spend time the QABI_SPEND evaluator enforces:
 *
 *    (a) tx.conditions_root == parsed.outputs_conditions_root
 *        — pins the spend tx's conditions tree to the participants' agreed root;
 *          any v4 MLSC tx has tx.vout[i].scriptPubKey = 0xDF + tx.conditions_root,
 *          so binding tx.conditions_root structurally pins every destination SPK.
 *
 *    (b) tx.vout.size() == output_values.size()
 *
 *    (c) tx.vout[i].nValue == output_values[i] for all i.
 *
 *  Replaces the previous `std::vector<CTxOut> outputs` field, which carried
 *  a redundant 33-byte scriptPubKey per output. The combined check (a)+(c)
 *  is strictly equivalent to the old bit-exact CTxOut comparison for any
 *  on-the-wire v4 MLSC tx (where SPK is structurally `0xDF + conditions_root`),
 *  while removing 34 wire bytes per output and eliminating the per-output SPK
 *  field entirely. */
struct QABIBlock
{
    //! Wire format version (currently QABI_BLOCK_VERSION_CURRENT = 0x01).
    uint8_t version{QABI_BLOCK_VERSION_CURRENT};

    //! Unique identifier for this batch attempt (32 random bytes).
    uint256 batch_id;

    //! Coordinator's FALCON-512 public key (exactly QABI_COORDINATOR_PUBKEY_SIZE bytes).
    std::vector<uint8_t> coordinator_pubkey;

    //! Max block height at which QABI_SPEND may fire on any primed input bound to this block.
    uint32_t prime_expiry_height{0};

    //! Conditions tree root that the spend tx MUST use as its tx.conditions_root.
    //! Pins the destination SPKs structurally (every v4 MLSC output has SPK =
    //! 0xDF + tx.conditions_root). See QABIBlock docstring for the full check chain.
    uint256 outputs_conditions_root;

    //! Participant list. Each entry is one primed UTXO's committed contribution.
    std::vector<QABIEntry> entries;

    //! Per-output values (sats). Indexed by QABIEntry::destination_index.
    //! The destination scriptPubKey is implicit: every v4 MLSC output uses
    //! 0xDF + outputs_conditions_root.
    std::vector<int64_t> output_values;
};

/** Canonical serialiser. Produces the exact bytes used in tx.qabi_block
 *  and hashed by ComputeQABIRoot. Deterministic: identical input produces
 *  identical output across all implementations. */
std::vector<uint8_t> SerializeQABIBlock(const QABIBlock& block);

/** Strict deserialiser with full field validation. Returns nullopt on any
 *  malformed data, oversized field, unknown version, out-of-range destination
 *  index, size-cap violation, or mismatched field sizes. Writes an error
 *  description to `error_out` on failure. */
std::optional<QABIBlock> ParseQABIBlock(const std::vector<uint8_t>& bytes,
                                         std::string& error_out);

/** Compute QABI_ROOT = SHA256(canonical_serialise(bytes)). For v1 this is
 *  a flat hash of the serialised bytes — not a Merkle root. Future block
 *  versions may use a Merkle-committed structure. */
uint256 ComputeQABIRoot(const std::vector<uint8_t>& serialised_block_bytes);

/** Convenience: serialise then hash. Equivalent to
 *  ComputeQABIRoot(SerializeQABIBlock(block)). */
uint256 ComputeQABIRoot(const QABIBlock& block);

/* ---------------- Wallet / builder helpers ---------------- */

/** Compute the public tip of a UTXO's auth hash chain.
 *  auth_tip = H^chain_length(auth_seed), where H is SHA-256.
 *  This is the value committed into the UTXO's QABI_SPEND block at creation. */
uint256 ComputeAuthChainTip(std::span<const uint8_t> auth_seed, uint32_t chain_length);

/** Compute the preimage at a given depth along the auth chain.
 *  Depth d means: owner reveals a value P such that H^d(P) == auth_tip.
 *  Depth 0 is the tip itself (useless — public). Depth chain_length is the
 *  seed (maximum reveal). The returned value goes into the witness stack of
 *  priming or QABIO txs.
 *
 *  Returns false if depth > chain_length. */
bool ComputeAuthChainPreimageAt(std::span<const uint8_t> auth_seed,
                                 uint32_t chain_length,
                                 uint32_t depth,
                                 uint256& preimage_out);

/** Build a QABI_PRIME RungBlock with the 4 witness-only fields in the exact
 *  order expected by the evaluator and the QABI_PRIME_WITNESS implicit layout:
 *    [0] HASH256  new_committed_root
 *    [1] NUMERIC  prime_depth
 *    [2] NUMERIC  new_committed_expiry
 *    [3] PREIMAGE prime_preimage
 */
RungBlock BuildQABIPrimeBlock(const uint256& new_committed_root,
                               int64_t prime_depth,
                               uint32_t new_committed_expiry,
                               std::span<const uint8_t> prime_preimage);

/** Build a QABI_SPEND RungBlock with the 6 fields in the exact order expected
 *  by the evaluator and the QABI_SPEND_WITNESS implicit layout:
 *    [0] HASH256       auth_tip
 *    [1] HASH256       committed_root
 *    [2] NUMERIC       committed_depth
 *    [3] NUMERIC       committed_expiry
 *    [4] PUBKEY_COMMIT owner_id
 *    [5] PREIMAGE      spend_preimage
 */
RungBlock BuildQABISpendBlock(const uint256& auth_tip,
                               const uint256& committed_root,
                               int64_t committed_depth,
                               uint32_t committed_expiry,
                               const uint256& owner_id,
                               std::span<const uint8_t> spend_preimage);

/** Serialise a single-block LadderWitness (one rung, one block) to raw bytes
 *  suitable for placement in CTxIn::scriptWitness::stack. Used for both
 *  priming tx witnesses (block type QABI_PRIME) and QABIO tx witnesses
 *  (block type QABI_SPEND). */
std::vector<uint8_t> SerializeSingleBlockWitness(const RungBlock& block);

/* ---------------- Sighash ---------------- */

/** Compute SIGHASH_QABO — the sighash used for the coordinator's FALCON QABO
 *  signature on a QABIO batch tx.
 *
 *  Covered:
 *    - tx.version
 *    - tx.vin (prevout hash, prevout index, nSequence — in order)
 *    - tx.vout (value, scriptPubKey — in order)
 *    - tx.conditions_root
 *    - tx.qabi_block (the tx-level QABIBlock bytes, with length prefix)
 *    - tx.nLockTime
 *
 *  Covered (Phase 18 update):
 *    - per-input scriptWitness.stack contents (stack element count and
 *      bytes of every element). Closes byte-level witness malleability:
 *      a third party cannot modify LadderWitness framing, spend preimages,
 *      Merkle proofs, or extra stack padding without invalidating the
 *      coordinator's FALCON signature.
 *
 *  Excluded (and why):
 *    - tx.aggregated_sig: chicken-and-egg — the sig signs the hash, the hash
 *      cannot depend on the sig.
 *
 *  The same sighash is produced for every input in the tx — the coordinator
 *  signs once, every primed input's QABI_SPEND evaluator verifies against
 *  the same hash. */
uint256 ComputeSighashQABO(const CTransaction& tx);

} // namespace rung

#endif // ENABLE_QABIO

#endif // BITCOIN_RUNG_QABI_H
