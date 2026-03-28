// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/sighash.h>
#include <rung/serialize.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

namespace rung {

const HashWriter HASHER_LADDERSIGHASH{TaggedHash("LadderSighash")};
const HashWriter HASHER_LADDERKEYPATH{TaggedHash("LadderKeyPathSighash")};

/** Compute the conditions commitment for sighash.
 *  For MLSC outputs: use conditions_root directly (already commits to all data via Merkle tree).
 *  For legacy 0xC1 outputs: SHA256 of serialized conditions (original behavior). */
static uint256 HashRungConditions(const RungConditions& conditions)
{
    // MLSC: conditions_root is the commitment — use it directly
    if (conditions.conditions_root.has_value()) {
        return *conditions.conditions_root;
    }

    // Legacy: hash the serialized conditions
    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    auto bytes = SerializeLadderWitness(ladder, SerializationContext::CONDITIONS);

    HashWriter ss{};
    ss.write(MakeByteSpan(bytes));
    return ss.GetSHA256();
}

template <class T>
bool SignatureHashLadder(const PrecomputedTransactionData& cache,
                         const T& tx,
                         unsigned int nIn,
                         uint8_t hash_type,
                         const RungConditions& conditions,
                         uint256& hash_out)
{
    assert(nIn < tx.vin.size());

    // Validate hash_type: BIP341 base range + ANYPREVOUT (0x40) + ANYPREVOUTANYSCRIPT (0xC0)
    // Valid: {0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}
    const bool valid_hash_type =
        (hash_type <= 0x03) ||                                    // DEFAULT/ALL/NONE/SINGLE
        (hash_type >= 0x40 && hash_type <= 0x43) ||               // ANYPREVOUT variants
        (hash_type >= 0x81 && hash_type <= 0x83) ||               // ANYONECANPAY variants
        (hash_type >= 0xC0 && hash_type <= 0xC3);                 // ANYPREVOUTANYSCRIPT variants
    if (!valid_hash_type) {
        return false;
    }

    const bool anyprevout = (hash_type & LADDER_SIGHASH_ANYPREVOUT) != 0;
    const bool anyprevoutanyscript = (hash_type & LADDER_SIGHASH_ANYPREVOUTANYSCRIPT) == LADDER_SIGHASH_ANYPREVOUTANYSCRIPT;

    // Require ladder caches to be initialized
    if (!cache.m_ladder_ready || !cache.m_spent_outputs_ready) {
        return false;
    }

    const uint8_t base_hash_type = hash_type & 0x03; // strip APO/ACP flags
    const uint8_t output_type = (hash_type == SIGHASH_DEFAULT || base_hash_type == 0) ? SIGHASH_ALL : base_hash_type;
    const uint8_t input_type = hash_type & SIGHASH_INPUT_MASK;

    HashWriter ss{HASHER_LADDERSIGHASH};

    // Epoch
    static constexpr uint8_t EPOCH = 0;
    ss << EPOCH;

    // Hash type
    ss << hash_type;

    // Transaction level data
    ss << tx.version;
    ss << tx.nLockTime;

    if (input_type != SIGHASH_ANYONECANPAY) {
        if (!anyprevout) {
            ss << cache.m_prevouts_single_hash;
        }
        ss << cache.m_spent_amounts_single_hash;
        ss << cache.m_sequences_single_hash;
    }
    if (output_type == SIGHASH_ALL) {
        ss << cache.m_outputs_single_hash;
    }

    // Spend type: always 0 for ladder (no annex, no extensions)
    static constexpr uint8_t SPEND_TYPE = 0;
    ss << SPEND_TYPE;

    // Input-specific data
    if (input_type == SIGHASH_ANYONECANPAY) {
        if (!anyprevout) {
            ss << tx.vin[nIn].prevout;
        }
        ss << cache.m_spent_outputs[nIn];
        ss << tx.vin[nIn].nSequence;
    } else {
        ss << nIn;
    }

    // Output for SIGHASH_SINGLE
    if (output_type == SIGHASH_SINGLE) {
        if (nIn >= tx.vout.size()) return false;
        HashWriter sha_single_output{};
        sha_single_output << tx.vout[nIn];
        ss << sha_single_output.GetSHA256();
    }

    // Conditions hash — commit to the locking conditions from the spent output
    // ANYPREVOUTANYSCRIPT: skip conditions commitment (allows rebinding across scripts)
    if (!anyprevoutanyscript) {
        ss << HashRungConditions(conditions);
    }

    hash_out = ss.GetSHA256();
    return true;
}

template <class T>
bool SignatureHashLadderKeyPath(const PrecomputedTransactionData& cache,
                                const T& tx,
                                unsigned int nIn,
                                uint8_t hash_type,
                                uint256& hash_out)
{
    assert(nIn < tx.vin.size());

    // Key-path only supports standard sighash types (no ANYPREVOUT)
    if (hash_type > 0x03 && hash_type != 0x81 && hash_type != 0x82 && hash_type != 0x83) {
        return false;
    }

    if (!cache.m_ladder_ready || !cache.m_spent_outputs_ready) {
        return false;
    }

    const uint8_t output_type = (hash_type == SIGHASH_DEFAULT || (hash_type & 0x03) == 0) ? SIGHASH_ALL : (hash_type & 0x03);
    const uint8_t input_type = hash_type & SIGHASH_INPUT_MASK;

    HashWriter ss{HASHER_LADDERKEYPATH};

    // Epoch
    static constexpr uint8_t EPOCH = 0;
    ss << EPOCH;

    // Hash type
    ss << hash_type;

    // Transaction level data
    ss << tx.version;
    ss << tx.nLockTime;

    if (input_type != SIGHASH_ANYONECANPAY) {
        ss << cache.m_prevouts_single_hash;
        ss << cache.m_spent_amounts_single_hash;
        ss << cache.m_sequences_single_hash;
    }
    if (output_type == SIGHASH_ALL) {
        ss << cache.m_outputs_single_hash;
    }

    // Spend type: 0x00 for key-path (no conditions, no annex)
    static constexpr uint8_t SPEND_TYPE_KEYPATH = 0x00;
    ss << SPEND_TYPE_KEYPATH;

    // Input-specific data
    if (input_type == SIGHASH_ANYONECANPAY) {
        ss << tx.vin[nIn].prevout;
        ss << cache.m_spent_outputs[nIn];
        ss << tx.vin[nIn].nSequence;
    } else {
        ss << nIn;
    }

    // Output for SIGHASH_SINGLE
    if (output_type == SIGHASH_SINGLE) {
        if (nIn >= tx.vout.size()) return false;
        HashWriter sha_single_output{};
        sha_single_output << tx.vout[nIn];
        ss << sha_single_output.GetSHA256();
    }

    // NO conditions hash for key-path — conditions are not revealed

    hash_out = ss.GetSHA256();
    return true;
}

// Explicit template instantiations
template bool SignatureHashLadder<CTransaction>(
    const PrecomputedTransactionData& cache,
    const CTransaction& tx,
    unsigned int nIn,
    uint8_t hash_type,
    const RungConditions& conditions,
    uint256& hash_out);

template bool SignatureHashLadder<CMutableTransaction>(
    const PrecomputedTransactionData& cache,
    const CMutableTransaction& tx,
    unsigned int nIn,
    uint8_t hash_type,
    const RungConditions& conditions,
    uint256& hash_out);

template bool SignatureHashLadderKeyPath<CTransaction>(
    const PrecomputedTransactionData& cache,
    const CTransaction& tx,
    unsigned int nIn,
    uint8_t hash_type,
    uint256& hash_out);

template bool SignatureHashLadderKeyPath<CMutableTransaction>(
    const PrecomputedTransactionData& cache,
    const CMutableTransaction& tx,
    unsigned int nIn,
    uint8_t hash_type,
    uint256& hash_out);

} // namespace rung
