// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// ============================================================================
// REVIEWER BLOCK — Ladder signature hash
// ============================================================================
//
// PURPOSE
//   Compute the digest that Ladder-native signatures commit to. Two variants:
//     SignatureHashLadder         — script-path, TaggedHash("LadderSighash/v1")
//     SignatureHashLadderKeyPath  — key-path, TaggedHash("LadderKeyPathSighash/v1")
//
// LOAD-BEARING INVARIANTS
//   1. Tagged-hash domain strings are versioned (/v1). Must match whatever
//      the wallet/signer library uses exactly.
//   2. Allowed hash_type set: {0x00..0x03, 0x40..0x43, 0x81..0x83, 0xC0..0xC3}.
//      Anything outside is rejected — no SIGHASH_FORKID, no undefined bits.
//   3. For MLSC inputs the conditions_root is hashed AS-IS (no
//      re-serialisation). The root is a 32-byte field already; re-hashing
//      would only add cost.
//   4. Key-path sighash (LadderKeyPathSighash/v1) deliberately does NOT
//      commit to conditions. The x-only tweak already binds them via
//      CheckLadderTweakRaw; including them again would create a
//      cross-protocol signing-oracle risk.
//   5. ANYPREVOUTANYSCRIPT (0xC0..0xC3) skips both prevout and conditions —
//      preserves pre-signed template-reuse patterns.
//
// OPTIONAL / REMOVABLE
//   - ANYPREVOUT variants (0x40..0x43, 0xC0..0xC3) enable channel-style
//     patterns (eltoo-like). A minimum-viable BIP can ship with 0x00..0x03
//     and 0x81..0x83 only.
// ============================================================================

#include <rung/sighash.h>
#include <rung/api.h>
#include <rung/serialize.h>
#include <rung/write_helpers.h>

#include <hash.h>
#include <uint256.h>

#include <cstdint>
#include <cstring>

namespace rung {

using namespace wire;

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

static void WriteU256(HashWriter& ss, const uint256& h) {
    wire::WriteBytes(ss, h.data(), 32);
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

/** v0.10 (F-6): bind tx.qabi_block and tx.aggregated_sig into the sighash so
 *  signatures lock them down as defence-in-depth. Pre-v0.10, those fields
 *  were not in the sighash; their authenticity relied on the QABI input's
 *  internal SHA256 commitment plus the v0.9 T-1/T-2 gate. Pinning them here
 *  removes any future cache-shape change from re-opening a malleation
 *  window. Empty fields hash to a sentinel zero so a tx that legitimately
 *  carries no QABI fields produces a stable sighash. */
static uint256 HashQABISection(const rung::api::LadderTxView& tx)
{
    HashWriter qss{};
    if (tx.qabi_block_size > 0 && tx.qabi_block) {
        WriteBytes(qss, tx.qabi_block, tx.qabi_block_size);
    }
    if (tx.aggregated_sig_size > 0 && tx.aggregated_sig) {
        WriteBytes(qss, tx.aggregated_sig, tx.aggregated_sig_size);
    }
    return qss.GetSHA256();
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

    // v0.10 (F-6): bind QABI tx-level fields.
    WriteU256(ss, HashQABISection(tx));

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

    // v0.10 (F-6): bind QABI tx-level fields here too.
    WriteU256(ss, HashQABISection(tx));

    hash_out = ss.GetSHA256();
    return true;
}

}  // namespace api

} // namespace rung
