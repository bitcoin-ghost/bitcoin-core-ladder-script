// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_QABI_H
#define BITCOIN_RUNG_QABI_H

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
 *  tx.qabi_block (serialised). QABI_ROOT = SHA256(canonical_serialise(block)). */
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

    //! Participant list. Each entry is one primed UTXO's committed contribution.
    std::vector<QABIEntry> entries;

    //! Destination output list. QABI_SPEND enforces tx.vout bit-exact equal to this list
    //! (full output set match — closes the coordinator-skim hole).
    std::vector<CTxOut> outputs;
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
 *  Excluded (and why):
 *    - tx.aggregated_sig: chicken-and-egg — the sig signs the hash, the hash
 *      cannot depend on the sig.
 *    - tx.creation_proof: not consensus-relevant for the batch authorisation;
 *      it proves output structure, which is already bound via tx.vout.
 *    - per-input witness stacks (including spend preimages): deliberately
 *      excluded. Each QABI_SPEND input's witness is independently validated
 *      by its own evaluator against the UTXO's committed auth_tip. An
 *      attacker cannot substitute a forged preimage (they don't hold
 *      auth_seed), so witness malleation is prevented at the eval layer
 *      rather than at the sighash layer. This matches the "sighash covers
 *      only intent, per-input checks cover authorisation" pattern.
 *
 *  The same sighash is produced for every input in the tx — the coordinator
 *  signs once, every primed input's QABI_SPEND evaluator verifies against
 *  the same hash. */
uint256 ComputeSighashQABO(const CTransaction& tx);

} // namespace rung

#endif // BITCOIN_RUNG_QABI_H
