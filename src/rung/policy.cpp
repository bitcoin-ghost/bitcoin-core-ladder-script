// Copyright (c) 2026 The Bitcoin Core developers
// Copyright (c) 2026 defenwycke
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/policy.h>
#include <rung/api.h>
#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/types.h>
#ifdef ENABLE_QABIO
#include <rung/qabi.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <string>

namespace rung {
using namespace api;  // Bring libladder public API (span-based) into file scope

bool IsBaseBlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::MUSIG_THRESHOLD:
    case RungBlockType::KEY_REF_SIG:
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    case RungBlockType::TAGGED_HASH:
    // Compound family (collapsed multi-block patterns)
    case RungBlockType::TIMELOCKED_SIG:
    case RungBlockType::HTLC:
    case RungBlockType::HASH_SIG:
    case RungBlockType::PTLC:
    case RungBlockType::CLTV_SIG:
    case RungBlockType::TIMELOCKED_MULTISIG:
    // Legacy family (wrapped Bitcoin transaction types)
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2SH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY:
    case RungBlockType::P2WSH_LEGACY:
    case RungBlockType::P2TR_LEGACY:
    case RungBlockType::P2TR_SCRIPT_LEGACY:
    // Utility family
    case RungBlockType::DATA_RETURN:
        return true;
    default:
        return false;
    }
}

bool IsCovenantBlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::CTV:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::AMOUNT_LOCK:
    case RungBlockType::ANCHOR:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_FEE:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_RESERVE:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::ANCHOR_ORACLE:
    // Governance family (transaction-level constraints)
    case RungBlockType::EPOCH_GATE:
    case RungBlockType::WEIGHT_LIMIT:
    case RungBlockType::INPUT_COUNT:
    case RungBlockType::OUTPUT_COUNT:
    case RungBlockType::RELATIVE_VALUE:
    case RungBlockType::ACCUMULATOR:
    case RungBlockType::OUTPUT_CHECK:
        return true;
    default:
        return false;
    }
}

bool IsStatefulBlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::RECURSE_SAME:
    case RungBlockType::RECURSE_MODIFIED:
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_COUNT:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    case RungBlockType::HYSTERESIS_FEE:
    case RungBlockType::HYSTERESIS_VALUE:
    case RungBlockType::TIMER_CONTINUOUS:
    case RungBlockType::TIMER_OFF_DELAY:
    case RungBlockType::LATCH_SET:
    case RungBlockType::LATCH_RESET:
    case RungBlockType::COUNTER_DOWN:
    case RungBlockType::COUNTER_PRESET:
    case RungBlockType::COUNTER_UP:
    case RungBlockType::COMPARE:
    case RungBlockType::SEQUENCER:
    case RungBlockType::ONE_SHOT:
    case RungBlockType::RATE_LIMIT:
    case RungBlockType::COSIGN:
        return true;
    default:
        return false;
    }
}

namespace api {

bool IsStandardRungTx(const LadderTxView& tx, std::string& reason)
{
    // All structural validation is enforced at consensus in DeserializeLadderWitness
    // (serialize.cpp) and ValidateRungOutputs (evaluator.cpp). Policy only needs to
    // verify the witness deserializes — rejecting garbage early before consensus
    // spends CPU on Merkle proof verification and block evaluation.

    // Note: per-input witness deserialization is NOT checked here.
    // V4 txs can have mixed inputs (standard P2WPKH bootstrap + MLSC ladder).
    // Standard P2WPKH witnesses have 2 stack elements (sig + pubkey), same as
    // ladder witnesses (LadderWitness + MLSCProof), so they cannot be
    // distinguished without access to spent outputs.
    // Full witness validation is done at consensus level in VerifyRungTx,
    // which has access to spent outputs and only validates MLSC inputs.

    // Output validation is consensus (ValidateRungOutputs in VerifyRungTx).
    // Run it here too for early mempool rejection.
    for (size_t i = 0; i < tx.output_count; ++i) {
        const auto& spk = tx.outputs[i].script_pub_key;
        if (!IsMLSCScript(spk.as_span())) {
            reason = "rung-non-mlsc-output";
            return false;
        }
    }

#ifdef ENABLE_QABIO
    // QABIO soft cap on tx.qabi_block: consensus allows up to QABI_BLOCK_MAX_HARD
    // (256 KB) but standard relay caps at QABI_BLOCK_MAX_SOFT (64 KB) to bound
    // mempool memory and propagation cost. Non-QABIO v4 txs have an empty
    // qabi_block so this check is a no-op for them.
    if (tx.qabi_block_size > QABI_BLOCK_MAX_SOFT) {
        reason = "qabi-block-soft-cap";
        return false;
    }
#endif

    return true;
}

}  // namespace api

// ============================================================================
// QABI Replace-By-Depth (RBD) mempool policy (BIP-YYYY)
// ============================================================================
//
// Gated on ENABLE_QABIO. When the extension is disabled the three
// public helpers (ExtractQABIPrimeDepth, IsQABIPrimingTx,
// IsValidRBDReplacement) are compiled as always-return-false stubs at
// the bottom of this section, so call sites in validation.cpp don't
// need conditional compilation — they just see "no tx ever looks like
// a priming tx" and the RBD path is never taken.
#ifdef ENABLE_QABIO

/** Read a little-endian NUMERIC field value (local to policy.cpp to avoid
 *  reaching into evaluator.cpp's statics). */
static bool PolicyReadNumeric(const RungField& f, int64_t& out)
{
    if (f.type != RungDataType::NUMERIC) return false;
    if (f.data.empty() || f.data.size() > 8) return false;
    uint64_t val = 0;
    for (size_t i = 0; i < f.data.size(); ++i) {
        val |= static_cast<uint64_t>(f.data[i]) << (8 * i);
    }
    out = static_cast<int64_t>(val);
    return true;
}

/** Scan a LadderWitness for the first QABI_PRIME block and return its
 *  prime_depth. Returns false if no QABI_PRIME block is present or the
 *  prime_depth field is missing/malformed.
 *
 *  QABI_PRIME's witness has exactly four fields, in order:
 *    [0] HASH256   new_committed_root
 *    [1] NUMERIC   prime_depth        ← what we want
 *    [2] NUMERIC   new_committed_expiry
 *    [3] PREIMAGE  prime_preimage
 *  See `EvalQABIPrimeBlock` in src/rung/blocks/qabi.cpp for the
 *  consensus-side schema. Index by position so a future field-order
 *  change at the consensus layer surfaces here as a wrong-type
 *  assertion rather than silently reading the wrong NUMERIC. */
static bool FindPrimeDepthInLadder(const LadderWitness& ladder, int64_t& depth_out)
{
    for (const auto& rung : ladder.rungs) {
        for (const auto& block : rung.blocks) {
            if (block.type != RungBlockType::QABI_PRIME) continue;
            if (block.fields.size() != 4) return false;
            if (block.fields[1].type != RungDataType::NUMERIC) return false;
            return PolicyReadNumeric(block.fields[1], depth_out);
        }
    }
    return false;
}

namespace api {

bool ExtractQABIPrimeDepth(const LadderTxView& tx,
                            uint32_t input_index,
                            int64_t& depth_out)
{
    if (input_index >= tx.input_count) return false;
    const auto& witness = tx.inputs[input_index].witness;
    if (witness.count == 0) return false;

    const auto& first = witness.elements[0];
    std::vector<uint8_t> buf(first.data, first.data + first.size);

    LadderWitness ladder;
    std::string err;
    if (!DeserializeLadderWitness(buf, ladder, err)) return false;

    return FindPrimeDepthInLadder(ladder, depth_out);
}

bool IsQABIPrimingTx(const LadderTxView& tx)
{
    for (uint32_t i = 0; i < tx.input_count; ++i) {
        int64_t dummy;
        if (ExtractQABIPrimeDepth(tx, i, dummy)) {
            return true;
        }
    }
    return false;
}

bool IsValidRBDReplacement(const LadderTxView& new_tx,
                            const LadderTxView& old_tx,
                            std::string& reason)
{
    // Both must be priming txs.
    if (!IsQABIPrimingTx(new_tx)) {
        reason = "rbd-new-not-priming";
        return false;
    }
    if (!IsQABIPrimingTx(old_tx)) {
        reason = "rbd-old-not-priming";
        return false;
    }

    // Collect (prevout-as-36-bytes → prime_depth) for each priming input of
    // the old tx. The map key is an opaque 36-byte blob (32-byte txid + 4-byte
    // vout LE) built at the boundary so the library never sees COutPoint.
    struct PrimeKey {
        std::array<uint8_t, 36> bytes;
        bool operator<(const PrimeKey& o) const {
            return std::memcmp(bytes.data(), o.bytes.data(), 36) < 0;
        }
    };
    auto make_key = [](const LadderOutPoint& op) {
        PrimeKey k{};
        std::memcpy(k.bytes.data(), op.txid, 32);
        // Little-endian vout encoding; order is arbitrary as long as it's
        // consistent between new_tx and old_tx comparison.
        for (size_t i = 0; i < 4; ++i) {
            k.bytes[32 + i] = static_cast<uint8_t>((op.n >> (8 * i)) & 0xff);
        }
        return k;
    };

    struct PrimeEntry {
        uint32_t input_idx;
        int64_t depth;
    };
    std::map<PrimeKey, PrimeEntry> old_primes;
    for (uint32_t i = 0; i < old_tx.input_count; ++i) {
        int64_t d;
        if (ExtractQABIPrimeDepth(old_tx, i, d)) {
            old_primes.emplace(make_key(old_tx.inputs[i].prevout), PrimeEntry{i, d});
        }
    }
    if (old_primes.empty()) {
        reason = "rbd-old-has-no-primings";
        return false;
    }

    // For every QABI_PRIME input in new_tx that shares a prevout with old_tx,
    // require new_tx.depth ≥ old_tx.depth + MIN_RBD_DEPTH_GAP. The gap
    // prevents the legitimate owner from free-flooding the mempool with
    // depth+1, depth+2, ... replacements: each RBD step now requires
    // committing a meaningful jump in the auth chain.
    bool found_shared = false;
    for (uint32_t i = 0; i < new_tx.input_count; ++i) {
        int64_t new_depth;
        if (!ExtractQABIPrimeDepth(new_tx, i, new_depth)) continue;

        auto it = old_primes.find(make_key(new_tx.inputs[i].prevout));
        if (it == old_primes.end()) continue;

        found_shared = true;
        if (new_depth < it->second.depth + MIN_RBD_DEPTH_GAP) {
            reason = "rbd-depth-gap-too-small";
            return false;
        }
    }

    if (!found_shared) {
        reason = "rbd-no-shared-primed-inputs";
        return false;
    }

    return true;
}

}  // namespace api

#else // !ENABLE_QABIO

namespace api {

// Always-false stubs so validation.cpp RBD checks collapse cleanly when
// the extension is disabled. No priming tx ever exists from this node's
// point of view; RBD replacements are never accepted.
bool ExtractQABIPrimeDepth(const LadderTxView& /*tx*/,
                            uint32_t /*input_index*/,
                            int64_t& /*depth_out*/) { return false; }

bool IsQABIPrimingTx(const LadderTxView& /*tx*/) { return false; }

bool IsValidRBDReplacement(const LadderTxView& /*new_tx*/,
                            const LadderTxView& /*old_tx*/,
                            std::string& reason)
{
    reason = "rbd-qabio-disabled";
    return false;
}

}  // namespace api

#endif // ENABLE_QABIO

} // namespace rung
