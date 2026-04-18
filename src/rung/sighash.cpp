// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/sighash.h>
#include <rung/api.h>
#include <rung/serialize.h>

#include <hash.h>
#include <uint256.h>

#include <cstdint>
#include <cstring>
#include <span>

namespace rung {

// Sighash type constants (bit-compatible with Bitcoin Core's SIGHASH_* — duplicated
// here so sighash.cpp does not need to include <script/interpreter.h>).
constexpr uint8_t LADDER_SIGHASH_DEFAULT       = 0x00;
constexpr uint8_t LADDER_SIGHASH_ALL           = 0x01;
constexpr uint8_t LADDER_SIGHASH_NONE          = 0x02;
constexpr uint8_t LADDER_SIGHASH_SINGLE        = 0x03;
constexpr uint8_t LADDER_SIGHASH_ANYONECANPAY  = 0x80;
constexpr uint8_t LADDER_SIGHASH_INPUT_MASK    = 0x80;

const HashWriter HASHER_LADDERSIGHASH{TaggedHash("LadderSighash/v1")};
const HashWriter HASHER_LADDERKEYPATH{TaggedHash("LadderKeyPathSighash/v1")};

// ------------------------------------------------------------
// Byte-level serialisation helpers (library-internal).
//
// These produce EXACTLY the same bytes Bitcoin Core's << operator would
// write for the equivalent types (int32, uint32, uint64, COutPoint,
// CTxOut, CompactSize). Consensus equivalence depends on this.
// ------------------------------------------------------------

static void WriteBytes(HashWriter& ss, const uint8_t* data, size_t size) {
    ss.write(std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), size});
}

static void WriteU8(HashWriter& ss, uint8_t v) {
    WriteBytes(ss, &v, 1);
}

static void WriteU32LE(HashWriter& ss, uint32_t v) {
    uint8_t buf[4] = {
        static_cast<uint8_t>(v),
        static_cast<uint8_t>(v >> 8),
        static_cast<uint8_t>(v >> 16),
        static_cast<uint8_t>(v >> 24),
    };
    WriteBytes(ss, buf, 4);
}

static void WriteS32LE(HashWriter& ss, int32_t v) {
    WriteU32LE(ss, static_cast<uint32_t>(v));
}

static void WriteU64LE(HashWriter& ss, uint64_t v) {
    uint8_t buf[8];
    for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>(v >> (8 * i));
    WriteBytes(ss, buf, 8);
}

static void WriteS64LE(HashWriter& ss, int64_t v) {
    WriteU64LE(ss, static_cast<uint64_t>(v));
}

static void WriteCompactSize(HashWriter& ss, uint64_t n) {
    if (n < 253) {
        WriteU8(ss, static_cast<uint8_t>(n));
    } else if (n <= 0xFFFF) {
        WriteU8(ss, 253);
        uint8_t buf[2] = { static_cast<uint8_t>(n), static_cast<uint8_t>(n >> 8) };
        WriteBytes(ss, buf, 2);
    } else if (n <= 0xFFFFFFFFULL) {
        WriteU8(ss, 254);
        WriteU32LE(ss, static_cast<uint32_t>(n));
    } else {
        WriteU8(ss, 255);
        WriteU64LE(ss, n);
    }
}

static void WriteLadderOutPoint(HashWriter& ss, const api::LadderOutPoint& op) {
    WriteBytes(ss, op.txid, 32);
    WriteU32LE(ss, op.n);
}

static void WriteLadderOutput(HashWriter& ss, const api::LadderOutputView& out) {
    WriteS64LE(ss, out.value);
    WriteCompactSize(ss, out.script_pub_key.size);
    WriteBytes(ss, out.script_pub_key.data, out.script_pub_key.size);
}

static void WriteU256(HashWriter& ss, const uint256& h) {
    WriteBytes(ss, h.data(), 32);
}

/** Compute the conditions commitment used inside the sighash.
 *  MLSC outputs already carry a conditions_root that commits to every
 *  field of the locking tree — use it directly. The fallback SHA256 of
 *  the serialised rungs is defensive: in-memory RungConditions built
 *  via a non-MLSC path should never hit production (consensus rejects
 *  non-MLSC v4 outputs), but unit tests construct them directly. */
static uint256 HashRungConditions(const RungConditions& conditions)
{
    if (conditions.conditions_root.has_value()) {
        return *conditions.conditions_root;
    }

    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    auto bytes = SerializeLadderWitness(ladder, SerializationContext::CONDITIONS);

    HashWriter ss{};
    WriteBytes(ss, bytes.data(), bytes.size());
    return ss.GetSHA256();
}

namespace api {

bool SignatureHashLadder(const LadderPrecomputedTxData& cache,
                         const LadderTxView& tx,
                         unsigned int nIn,
                         uint8_t hash_type,
                         const RungConditions& conditions,
                         uint256& hash_out)
{
    if (nIn >= tx.input_count) return false;

    // Valid: {0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}
    // 0x80 (ANYONECANPAY + SIGHASH_DEFAULT) is excluded, matching BIP341.
    const bool valid_hash_type =
        (hash_type <= 0x03) ||
        (hash_type >= 0x40 && hash_type <= 0x43) ||
        (hash_type >= 0x81 && hash_type <= 0x83) ||
        (hash_type >= 0xC0 && hash_type <= 0xC3);
    if (!valid_hash_type) return false;

    const bool anyprevout = (hash_type & LADDER_SIGHASH_ANYPREVOUT) != 0;
    const bool anyprevoutanyscript = (hash_type & LADDER_SIGHASH_ANYPREVOUTANYSCRIPT) == LADDER_SIGHASH_ANYPREVOUTANYSCRIPT;

    if (!cache.ladder_ready) return false;

    const uint8_t base_hash_type = hash_type & 0x03;
    const uint8_t output_type = (hash_type == LADDER_SIGHASH_DEFAULT || base_hash_type == 0) ? LADDER_SIGHASH_ALL : base_hash_type;
    const uint8_t input_type = hash_type & LADDER_SIGHASH_INPUT_MASK;

    HashWriter ss{HASHER_LADDERSIGHASH};

    WriteU8(ss, 0);                                 // epoch
    WriteU8(ss, hash_type);                         // hash type
    WriteS32LE(ss, tx.version);                     // tx.version
    WriteU32LE(ss, tx.lock_time);                   // tx.locktime

    if (input_type != LADDER_SIGHASH_ANYONECANPAY) {
        if (!anyprevout) {
            WriteBytes(ss, cache.hash_prevouts_sha256, 32);
        }
        WriteBytes(ss, cache.hash_spent_amounts_sha256, 32);
        WriteBytes(ss, cache.hash_sequences_sha256, 32);
    }
    if (output_type == LADDER_SIGHASH_ALL) {
        WriteBytes(ss, cache.hash_outputs_sha256, 32);
    }

    WriteU8(ss, 0);                                 // spend_type (no annex)

    if (input_type == LADDER_SIGHASH_ANYONECANPAY) {
        if (!cache.spent_outputs || nIn >= cache.spent_output_count) return false;
        if (!anyprevout) {
            WriteLadderOutPoint(ss, tx.inputs[nIn].prevout);
        }
        WriteLadderOutput(ss, cache.spent_outputs[nIn]);
        WriteU32LE(ss, tx.inputs[nIn].sequence);
    } else {
        WriteU32LE(ss, nIn);
    }

    if (output_type == LADDER_SIGHASH_SINGLE) {
        if (nIn >= tx.output_count) return false;
        HashWriter sha_single_output{};
        WriteLadderOutput(sha_single_output, tx.outputs[nIn]);
        uint256 single_hash = sha_single_output.GetSHA256();
        WriteU256(ss, single_hash);
    }

    if (!anyprevoutanyscript) {
        uint256 conditions_hash = HashRungConditions(conditions);
        WriteU256(ss, conditions_hash);
    }

    hash_out = ss.GetSHA256();
    return true;
}

bool SignatureHashLadderKeyPath(const LadderPrecomputedTxData& cache,
                                const LadderTxView& tx,
                                unsigned int nIn,
                                uint8_t hash_type,
                                uint256& hash_out)
{
    if (nIn >= tx.input_count) return false;

    // Key-path supports standard sighash types only (no ANYPREVOUT).
    if (hash_type > 0x03 && hash_type != 0x81 && hash_type != 0x82 && hash_type != 0x83) return false;

    if (!cache.ladder_ready) return false;

    const uint8_t output_type = (hash_type == LADDER_SIGHASH_DEFAULT || (hash_type & 0x03) == 0) ? LADDER_SIGHASH_ALL : static_cast<uint8_t>(hash_type & 0x03);
    const uint8_t input_type = hash_type & LADDER_SIGHASH_INPUT_MASK;

    HashWriter ss{HASHER_LADDERKEYPATH};

    WriteU8(ss, 0);
    WriteU8(ss, hash_type);
    WriteS32LE(ss, tx.version);
    WriteU32LE(ss, tx.lock_time);

    if (input_type != LADDER_SIGHASH_ANYONECANPAY) {
        WriteBytes(ss, cache.hash_prevouts_sha256, 32);
        WriteBytes(ss, cache.hash_spent_amounts_sha256, 32);
        WriteBytes(ss, cache.hash_sequences_sha256, 32);
    }
    if (output_type == LADDER_SIGHASH_ALL) {
        WriteBytes(ss, cache.hash_outputs_sha256, 32);
    }

    WriteU8(ss, 0);                                 // spend_type key-path

    if (input_type == LADDER_SIGHASH_ANYONECANPAY) {
        if (!cache.spent_outputs || nIn >= cache.spent_output_count) return false;
        WriteLadderOutPoint(ss, tx.inputs[nIn].prevout);
        WriteLadderOutput(ss, cache.spent_outputs[nIn]);
        WriteU32LE(ss, tx.inputs[nIn].sequence);
    } else {
        WriteU32LE(ss, nIn);
    }

    if (output_type == LADDER_SIGHASH_SINGLE) {
        if (nIn >= tx.output_count) return false;
        HashWriter sha_single_output{};
        WriteLadderOutput(sha_single_output, tx.outputs[nIn]);
        uint256 single_hash = sha_single_output.GetSHA256();
        WriteU256(ss, single_hash);
    }

    // NO conditions hash for key-path — conditions are not revealed

    hash_out = ss.GetSHA256();
    return true;
}

}  // namespace api

} // namespace rung
